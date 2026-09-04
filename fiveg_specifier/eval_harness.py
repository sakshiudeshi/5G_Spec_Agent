"""Candidate oracle + eval case -> report. The ground truth lives in the case, not the oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from decode import load_capture
from run import OracleError, evaluate, evaluate_witnesses, validate_oracle, witness_records
from specify import load_spec

HERE = Path(__file__).resolve().parent
EVAL_DATA = HERE / "evals" / "data"
ORACLE_PATH = HERE / "oracle.json"

STATUSES = ("ok", "fail", "skip", "error")

# A counter never repeats and is wholly predictable, so no predicate that only forbids
# repetition can encode unpredictable generation.
COUNTER_PROBE = {
    "name": "sequential-counter",
    "applies_when": "unpredictable identifier generation",
    "primitive": "ue_identity_tmsi",
    "values": [format(i, "039b") for i in (1, 2, 3, 4)],
    "forbidden": "pass",
}

# Labels hold under one clause and one matcher, so a case owns them; the harness does not.
EVAL_CASES = {
    # A new 5G-GUTI on every paging-triggered reconnection. TS 33.501 6.12.3.
    "guti-reuse-mt-access": {
        "captures": (
            # 205 mt-Access, 21 distinct: the same TMSI returns after paging.
            (
                "starhub",
                EVAL_DATA / "starhub-xiaomi11-ntu-sutd.pcap",
                "0bd01276d33133a974ca9d00807db063f73fb26e62615c5ac069ac5f22f3ec8c",
                "violate",
            ),
            # 93 mt-Access, 93 distinct. Its mo-Data repeats are permitted by 6.12.3 NOTE 1.
            (
                "singtel",
                EVAL_DATA / "singtel-xiaomi11-ntu.txt",
                "3c09b7d55b7d697361b2219a634bac411b3ab869da6d11d269bc21c0a390418d",
                "pass",
            ),
        ),
        "probes": (COUNTER_PROBE,),
    },
}

DEFAULT_CASE = "guti-reuse-mt-access"


def _entry(case: str, expected: str, got: str, status: str) -> dict:
    return {"case": case, "expected": expected, "got": got, "status": status}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_eval(oracle: dict, case: dict) -> list[dict]:
    """One entry per eval case. A malformed oracle or capture is an `error`, not a raise."""
    try:
        if not isinstance(oracle, dict):
            raise OracleError("oracle must be a JSON object")
        spec = validate_oracle(oracle)
        rule = oracle["nl_rule"]
        if not isinstance(rule, str):
            raise OracleError(f"nl_rule must be a string, got {type(rule).__name__}")
    except OracleError as exc:
        return [_entry("schema", "valid", str(exc), "error")]

    report = [_entry("schema", "valid", "valid", "ok")]
    primitive = oracle["observe"][spec["variable"]]

    witnesses = evaluate_witnesses(oracle)
    if not witnesses:
        report.append(_entry("witness_round_trip", "round-trip", "none declared", "skip"))
    else:
        got = ",".join(f"{w['witness'].removeprefix('witness_')}={w['got']}" for w in witnesses)
        ok = all(w["ok"] for w in witnesses)
        report.append(_entry("witness_round_trip", "round-trip", got, "ok" if ok else "fail"))

    spec_text = load_spec()
    anchored = any(rule.strip() in paragraph for paragraph in spec_text["paragraphs"])
    report.append(
        _entry(
            "rule_anchored_in_spec",
            f"in {spec_text['id']}",
            "verbatim" if anchored else "not in the clause",
            "ok" if anchored else "fail",
        )
    )

    for name, path, sha256, expected in case["captures"]:
        label = f"capture:{name}"
        try:
            digest = _sha256(path)
        except OSError as exc:
            report.append(_entry(label, expected, f"unreadable: {exc}", "error"))
            continue
        if digest != sha256:
            report.append(_entry(label, expected, f"sha256 mismatch: {path}", "error"))
            continue
        verdict = evaluate(oracle, load_capture(path))["verdict"]
        report.append(_entry(label, expected, verdict, "ok" if verdict == expected else "fail"))

    for probe in case["probes"]:
        label = f"probe:{probe['name']}"
        expected = f"not {probe['forbidden']}"
        if probe["applies_when"] not in rule.lower():
            report.append(_entry(label, expected, "rule not claimed", "skip"))
            continue
        if primitive != probe["primitive"]:
            report.append(_entry(label, expected, f"{probe['primitive']} not observed", "skip"))
            continue
        verdict = evaluate(oracle, witness_records(oracle, probe["values"]))["verdict"]
        status = "fail" if verdict == probe["forbidden"] else "ok"
        report.append(_entry(label, expected, verdict, status))

    return report


def failed(report: list[dict]) -> list[dict]:
    return [e for e in report if e["status"] in ("fail", "error")]


def render(oracle_id: str, case_name: str, report: list[dict]) -> str:
    marks = {"ok": "ok", "fail": "FAIL", "skip": "skip", "error": "ERROR"}
    width_case = max(len(e["case"]) for e in report)
    width_expected = max(len(e["expected"]) for e in report)
    lines = [f"oracle {oracle_id}   case {case_name}", ""]
    for e in report:
        status = marks[e["status"]]
        if e["status"] != "ok":
            status += f" ({e['got']})"
        lines.append(f"{e['case']:<{width_case}}  {e['expected']:<{width_expected}}  {status}")
    bad, skipped = failed(report), [e for e in report if e["status"] == "skip"]
    lines.append("")
    if bad:
        lines.append(f"EVAL FAILED: {len(bad)} of {len(report)} cases")
    else:
        tail = f" ({len(skipped)} skipped)" if skipped else ""
        lines.append(f"EVAL PASSED: {len(report)} cases{tail}")
    return "\n".join(lines)


def load_oracles(path: Path) -> list:
    raw = json.loads(path.read_text())
    return raw if isinstance(raw, list) else [raw]


def main() -> None:
    ap = argparse.ArgumentParser(description="run a candidate oracle against an eval case")
    ap.add_argument("--oracle", default=str(ORACLE_PATH))
    ap.add_argument("--case", default=DEFAULT_CASE, choices=sorted(EVAL_CASES))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    case = EVAL_CASES[args.case]
    reports = []
    for oracle in load_oracles(Path(args.oracle)):
        report = run_eval(oracle, case)
        oracle_id = oracle.get("id", "?") if isinstance(oracle, dict) else "?"
        reports.append({"oracle": oracle_id, "report": report})

    ok = not any(failed(r["report"]) for r in reports)
    if args.json:
        print(json.dumps(
            {"case": args.case, "oracle_file": args.oracle, "ok": ok, "reports": reports}, indent=2
        ))
    else:
        print("\n\n".join(render(r["oracle"], args.case, r["report"]) for r in reports))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
