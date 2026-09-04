"""Prompt construction, offline validation, and the live LLM call."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from _env import load_env
from decode import ESTABLISHMENT_CAUSES
from run import OracleError, evaluate_witnesses, validate_oracle

HERE = Path(__file__).resolve().parent
DSL_PATH = HERE / "DSL.md"
SPEC_PATH = HERE / "spec" / "33501_6_12_3.json"
ORACLE_PATH = HERE / "oracle.json"
ALL_ORACLES = HERE / "all_oracles"

LEAK_TOKENS = (
    "paging",
    "reuse",
    "repeat",
    "distinct",
    "relink",
    "track",
    "guti reuse",
    "violation",
    "starhub",
    "singtel",
    "non-compliance",
)

_DATASHEET = """## Instrument datasheet

A capture is a sequence of records in observation order. Each record is one uplink message
seen on the air interface, decoded into these fields:

    seq                  1-based position of the record within the capture
    ts                   arrival time, in seconds
    message_is           the message type, or null if the PDU did not decode
    id_type              the identity type carried by the message, or null
    ue_identity_tmsi     the identity carried by the message, as a 39-character binary
                         string, or null
    establishment_cause  the establishment cause carried by the message, or null

`establishment_cause` takes exactly one of these 16 values (TS 38.331, ASN.1 order):
{causes}.

The instrument decodes uplink messages only. Nothing sent by the network is available to it.
"""

_TASK = """## Task

Below are a grammar and a passage of specification text. Consider each normative sentence in
the passage on its own. If the grammar can express that sentence as an oracle over the records
the datasheet describes, emit one oracle object for it; if it cannot, emit nothing for it.

Return a JSON array of oracle objects and nothing else. Return [] for any sentence you cannot
express in this grammar -- including the case where that is every sentence.

Compose only from the closed vocabularies. Do not invent field names, observation primitives,
or predicate forms.
"""


def load_spec(path: Path = SPEC_PATH) -> dict:
    return json.loads(Path(path).read_text())


def spec_sha256(spec: dict) -> str:
    return hashlib.sha256("\n".join(spec["paragraphs"]).encode("utf-8")).hexdigest()


def prompt_sections(spec_path: Path = SPEC_PATH) -> list[tuple[str, str, bool]]:
    """(name, text, authored). Only `authored` sections are scanned by the leak test."""
    spec = load_spec(spec_path)
    clause = "## Specification text -- {}\n\n{}\n".format(
        spec["title"], "\n\n".join(spec["paragraphs"])
    )
    return [
        ("task", _TASK, True),
        ("datasheet", _DATASHEET.format(causes=", ".join(ESTABLISHMENT_CAUSES)), True),
        ("grammar", DSL_PATH.read_text(), False),
        ("clause", clause, False),
    ]


def build_prompt(spec_path: Path = SPEC_PATH) -> str:
    return "\n\n".join(text.strip() for _, text, _ in prompt_sections(spec_path)) + "\n"


def authored_text(spec_path: Path = SPEC_PATH) -> str:
    return "\n\n".join(text for _, text, authored in prompt_sections(spec_path) if authored)


# offline validation


def validate_file(path: Path) -> list[dict]:
    raw = json.loads(path.read_text())
    oracles = raw if isinstance(raw, list) else [raw]
    report = []
    for oracle in oracles:
        try:
            validate_oracle(oracle)
        except OracleError as exc:
            report.append({"id": oracle.get("id"), "ok": False, "error": str(exc)})
            continue
        witnesses = evaluate_witnesses(oracle)
        report.append(
            {
                "id": oracle["id"],
                "ok": all(w["ok"] for w in witnesses),
                "authored_by": oracle.get("authored_by", "unknown"),
                "witness_verdicts": witnesses,
            }
        )
    return report


# live: OpenRouter


def extract_json_array(text: str) -> list:
    """First balanced top-level JSON array in the reply, ignoring prose around it."""
    depth, start, in_string, escaped = 0, None, False, False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "[":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0 and start is not None:
                return json.loads(text[start : i + 1])
    raise ValueError("no balanced JSON array in reply")


def call_live(prompt: str, model: str | None = None) -> tuple[str, str]:
    """Returns (model, raw_reply)."""
    from openai import OpenAI

    load_env(HERE / ".env")
    load_env(HERE.parent / ".env")
    load_env(".env")
    model = model or os.environ.get("SPECIFIER_MODEL", "anthropic/claude-opus-5")
    client = OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )
    reply = client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )
    return model, reply.choices[0].message.content or ""


def run_live(persist: bool) -> dict:
    prompt = build_prompt()
    model, raw_reply = call_live(prompt)
    try:
        candidates = extract_json_array(raw_reply)
    except ValueError:
        candidates = []

    validation, accepted = [], []
    for oracle in candidates:
        try:
            validate_oracle(oracle)
        except OracleError as exc:
            validation.append({"id": oracle.get("id"), "ok": False, "error": str(exc)})
            continue
        witnesses = evaluate_witnesses(oracle)
        ok = all(w["ok"] for w in witnesses)
        validation.append({"id": oracle["id"], "ok": ok, "witness_verdicts": witnesses})
        if ok:
            oracle = {**oracle, "authored_by": f"model:{model}"}
            accepted.append(oracle)

    record = {
        "run_id": str(uuid.uuid4()),
        "utc": datetime.now(timezone.utc).isoformat(),
        "provider": "openrouter",
        "model": model,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "spec_anchor": load_spec()["id"],
        "raw_reply": raw_reply,
        "candidates": candidates,
        "validation": validation,
        "accepted": accepted,
    }
    ALL_ORACLES.mkdir(parents=True, exist_ok=True)
    stamp = record["utc"].replace(":", "").replace("+0000", "Z")
    (ALL_ORACLES / f"{stamp}-{record['run_id']}.json").write_text(json.dumps(record, indent=2))

    if persist and accepted:
        ORACLE_PATH.write_text(json.dumps(accepted[0] if len(accepted) == 1 else accepted, indent=2))
    return record


def main() -> None:
    ap = argparse.ArgumentParser(description="build the prompt; validate or elicit oracles")
    ap.add_argument("--live", action="store_true", help="call the model (network)")
    ap.add_argument("--persist", action="store_true", help="with --live, copy accepted to oracle.json")
    ap.add_argument("--print-prompt", action="store_true")
    args = ap.parse_args()

    if args.persist and not args.live:
        ap.error("--persist requires --live")
    if args.print_prompt:
        print(build_prompt())
        return
    if args.live:
        record = run_live(args.persist)
        print(json.dumps({k: v for k, v in record.items() if k != "raw_reply"}, indent=2))
        return

    report = validate_file(ORACLE_PATH)
    print(json.dumps({"mode": "offline", "oracle_file": str(ORACLE_PATH), "report": report}, indent=2))
    sys.exit(0 if all(r["ok"] for r in report) else 1)


if __name__ == "__main__":
    main()
