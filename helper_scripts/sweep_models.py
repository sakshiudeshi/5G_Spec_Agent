#!/usr/bin/env python3
"""Run the specifier prompt across several models and score each reply against an eval case.

Every reply goes through the same path as `eval_harness.py --live`, so a row here means
exactly what a RUN PASSED/FAILED banner means there. Each sweep directory gets the full
run records, a `summary.json` of table rows, and a `manifest.json` holding the high-level
sweep info plus the oracle objects every run produced -- that manifest is what the
dashboard reads.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "fiveg_specifier"

MODELS = [
    "openai/gpt-6-sol",
    "openai/gpt-6-luna",
    "openai/gpt-6-astra",
    "anthropic/claude-opus-5.5",
    # "openai/gpt-5.6-sol",
    # "openai/gpt-5.6-terra",
    # "anthropic/claude-fable-5.1",
    # "anthropic/claude-opus-5",
    # "anthropic/claude-sonnet-5",
    # "moonshotai/kimi-k3",
    # "z-ai/glm-5.3-flash",
    # "google/gemini-3.8-flash",
]


def summarize(record: dict) -> dict:
    run_report = {e["case"]: e["status"] for e in record.get("run_report", [])}
    oracles = record.get("oracles", [])
    per_oracle_fails = [
        e["case"]
        for o in oracles
        for e in o["report"]
        if e["status"] in ("fail", "error")
    ]
    return {
        "ok": record["ok"],
        # `message.content or ""` turns a None content into "", which otherwise scores
        # exactly like a deliberate []. An empty reply is a broken call, not an abstention.
        "empty_reply": not record.get("raw_reply", "").strip(),
        "n": len(oracles),
        "ids": ",".join(o["oracle"] for o in oracles) or "-",
        "count": run_report.get("count", "-"),
        "required": next((v for k, v in run_report.items() if k.startswith("required:")), "-"),
        "forbidden": next((v for k, v in run_report.items() if k.startswith("forbidden:")), "-"),
        "oracle_fails": ",".join(sorted(set(per_oracle_fails))) or "-",
    }


def run_status(row: dict) -> str:
    """One word for what became of this call, for the dashboard to group on."""
    if row.get("error"):
        return "error"
    if row.get("empty_reply"):
        return "empty"
    if row.get("ok"):
        return "pass"
    return "abstain" if row.get("n") == 0 else "fail"


def fingerprint(o: dict) -> str:
    """Delegate to the harness's own notion of oracle identity, so the dashboard and the
    `distinct_oracles` check can never disagree about what counts as the same check."""
    from run import fingerprint as canonical  # repo is already on sys.path
    try:
        return canonical(o)
    except Exception:  # malformed oracles are a schema error, not a duplicate
        return json.dumps({"unparsed": o.get("id")}, sort_keys=True)


def oracle_details(record: dict, extract) -> list[dict]:
    """The oracle objects a run produced, each merged with its own check report.

    `_record` builds its per-oracle list from `extract_oracles(raw_reply)` in order, so
    the parsed objects and the reports line up by index.
    """
    parsed = extract(record.get("raw_reply", ""))
    out, first_seen = [], {}
    for i, scored in enumerate(record.get("oracles", [])):
        obj = parsed[i] if i < len(parsed) and isinstance(parsed[i], dict) else {}
        fp = fingerprint(obj)
        out.append({
            "id": scored["oracle"],
            "fingerprint": fp,
            # an oracle that executes identically to an earlier one in the same reply:
            # a second name (and a second claimed sentence) over one check
            "duplicate_of": first_seen.get(fp),
            "nl_rule": obj.get("nl_rule"),
            "spec_anchor": obj.get("spec_anchor"),
            "matcher": obj.get("matcher"),
            "observe": obj.get("observe"),
            "predicate": obj.get("predicate"),
            "witness_pass": obj.get("witness_pass"),
            "witness_violate": obj.get("witness_violate"),
            "checks": scored["report"],
            # the object exactly as the model emitted it, for the dashboard to show verbatim
            "json": obj,
        })
        first_seen.setdefault(fp, scored["oracle"])
    return out


# manifest


def manifest_from_dir(out_dir: Path, extract, meta: dict) -> dict:
    """Read a sweep directory back and build its manifest.

    Fresh sweeps and `--rebuild-manifests` both come through here, so a rebuilt manifest
    is byte-identical to the one the sweep would have written.
    """
    runs = []
    for path in sorted(out_dir.glob("*.json")):
        if path.name in ("manifest.json", "summary.json"):
            continue
        blob = json.loads(path.read_text())
        if path.name.endswith("-ERROR.json"):
            runs.append({
                "model": blob["model"], "rep": blob["rep"], "status": "error",
                "ok": False, "error": blob["error"], "record": path.name, "oracles": [],
            })
            continue
        row = {"model": blob["model"], "rep": _rep_of(path), **summarize(blob)}
        oracles = oracle_details(blob, extract)
        runs.append({
            **row,
            "status": run_status(row),
            "record": path.name,
            "run_id": blob.get("run_id"),
            "utc": blob.get("utc"),
            "prompt_sha256": blob.get("prompt_sha256"),
            "raw_reply": blob.get("raw_reply", ""),
            "run_report": blob.get("run_report", []),
            "oracles": oracles,
            "distinct_checks": len({o["fingerprint"] for o in oracles}),
            "duplicates": sum(1 for o in oracles if o["duplicate_of"]),
        })

    runs.sort(key=lambda r: (r["model"], r["rep"]))
    models = sorted({r["model"] for r in runs})
    by_model = []
    for model in models:
        got = [r for r in runs if r["model"] == model]
        valid = [r for r in got if r["status"] not in ("error", "empty")]
        by_model.append({
            "model": model,
            "calls": len(got),
            "valid": len(valid),
            "passed": sum(1 for r in got if r["status"] == "pass"),
            "abstained": sum(1 for r in got if r["status"] == "abstain"),
            "failed": sum(1 for r in got if r["status"] == "fail"),
            "dup_runs": sum(1 for r in got if r.get("duplicates")),
            "empty": sum(1 for r in got if r["status"] == "empty"),
            "errors": sum(1 for r in got if r["status"] == "error"),
        })

    def tally(status: str) -> int:
        return sum(1 for r in runs if r["status"] == status)

    prompts = sorted({r["prompt_sha256"] for r in runs if r.get("prompt_sha256")})
    return {
        "sweep": out_dir.name,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        **meta,
        # every run shares one prompt; more than one hash means the sweep is not comparable
        "prompt_sha256": prompts[0] if len(prompts) == 1 else prompts,
        "models": models,
        "totals": {
            "calls": len(runs),
            "valid": sum(1 for r in runs if r["status"] not in ("error", "empty")),
            "passed": tally("pass"),
            "failed": tally("fail"),
            "abstained": tally("abstain"),
            "empty": tally("empty"),
            "errors": tally("error"),
            "dup_runs": sum(1 for r in runs if r.get("duplicates")),
        },
        "by_model": by_model,
        "runs": runs,
    }


def _rep_of(path: Path) -> int:
    stem = path.stem.rsplit("-rep", 1)
    return int(stem[1]) if len(stem) == 2 and stem[1].isdigit() else 0


def write_index(root: Path) -> Path:
    """List every sweep that has a manifest, newest first, for the dashboard picker."""
    entries = []
    for manifest in sorted(root.glob("sweep-*/manifest.json")):
        m = json.loads(manifest.read_text())
        entries.append({
            "sweep": m["sweep"], "case": m.get("case"), "utc": m.get("started_utc"),
            "models": len(m.get("models", [])), "totals": m.get("totals", {}),
        })
    entries.sort(key=lambda e: e["sweep"], reverse=True)
    path = root / "sweeps.json"
    path.write_text(json.dumps(entries, indent=2))
    return path


def one_run(eval_harness, case_name, case, model, rep, out_dir) -> dict:
    row = {"model": model, "rep": rep}
    try:
        record = eval_harness.run_live(case_name, case, model)
    except Exception as exc:  # a model can be unavailable, rate-limited, or renamed
        row.update(ok=False, error=f"{type(exc).__name__}: {exc}")
        (out_dir / f"{model.replace('/', '_')}-rep{rep}-ERROR.json").write_text(json.dumps(
            {"model": model, "rep": rep, "error": row["error"],
             "traceback": traceback.format_exc()}, indent=2))
        return row
    path = out_dir / f"{model.replace('/', '_')}-rep{rep}.json"
    path.write_text(json.dumps(record, indent=2))
    row.update(summarize(record), record=str(path))
    return row


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=REPO, help="path to fiveg_specifier/")
    ap.add_argument("--case", default="guti-reuse-mt-access")
    ap.add_argument("--models", nargs="*", default=MODELS)
    ap.add_argument("--reps", type=int, default=3, help="runs per model; temperature=0 is not determinism")
    ap.add_argument("--jobs", type=int, default=4, help="concurrent calls")
    ap.add_argument("--out", type=Path, default=None, help="directory for run records")
    ap.add_argument("--rebuild-manifests", action="store_true",
                    help="rebuild manifest.json for existing sweep dirs; makes no model calls")
    args = ap.parse_args()

    sys.path.insert(0, str(args.repo))
    import eval_harness

    if args.rebuild_manifests:
        for out_dir in sorted(HERE.glob("sweep-*")):
            if not out_dir.is_dir():
                continue
            manifest = manifest_from_dir(out_dir, eval_harness.extract_oracles,
                                         {"case": args.case, "started_utc": None, "reps": None})
            (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
            t = manifest["totals"]
            print(f"{out_dir.name}  {t['passed']}/{t['valid']} passed  "
                  f"({t['calls']} calls, {t['empty']} empty, {t['errors']} errors)")
        print(f"\nindex -> {write_index(HERE)}")
        return

    cases = eval_harness.load_cases()
    if args.case not in cases:
        ap.error(f"unknown case {args.case!r}; declared: {sorted(cases)}")
    case = cases[args.case]

    started = datetime.now(timezone.utc)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out or HERE / f"sweep-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # a leading `~` is not OpenRouter syntax; strip it so the id resolves
    models = [m.lstrip("~") for m in args.models]
    jobs = [(m, r) for m in models for r in range(1, args.reps + 1)]
    print(f"case {args.case}   {len(models)} models x {args.reps} reps = {len(jobs)} calls")
    print(f"records -> {out_dir}\n")

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(
            lambda j: one_run(eval_harness, args.case, case, j[0], j[1], out_dir), jobs
        ))

    width = max(len(r["model"]) for r in rows)
    header = f"{'model':<{width}}  rep  n  count     required  forbidden  oracle fails"
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda r: (r["model"], r["rep"])):
        mark = "PASS" if row.get("ok") else "FAIL"
        if "error" in row:
            print(f"{row['model']:<{width}}  {row['rep']:>3}  {mark}  {row['error'][:60]}")
            continue
        if row.get("empty_reply"):
            print(f"{row['model']:<{width}}  {row['rep']:>3}  -  EMPTY REPLY (no content returned)")
            continue
        print(
            f"{row['model']:<{width}}  {row['rep']:>3}  {row['n']:>1}  "
            f"{row['count']:<8}  {row['required']:<8}  {row['forbidden']:<9}  "
            f"{row['oracle_fails']}   [{mark}] {row['ids']}"
        )

    print()
    for model in models:
        got = [r for r in rows if r["model"] == model]
        print(f"{model:<{width}}  {sum(1 for r in got if r.get('ok'))}/{len(got)} passed")

    (out_dir / "summary.json").write_text(json.dumps(rows, indent=2))
    manifest = manifest_from_dir(out_dir, eval_harness.extract_oracles, {
        "case": args.case,
        "spec": str(case["spec"].relative_to(args.repo.resolve())),
        "started_utc": started.isoformat(),
        "reps": args.reps,
    })
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nsummary  -> {out_dir / 'summary.json'}")
    print(f"manifest -> {out_dir / 'manifest.json'}")
    print(f"index    -> {write_index(HERE)}")


if __name__ == "__main__":
    main()
