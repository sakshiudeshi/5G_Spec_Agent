"""Spec clause -> model -> oracles -> report. The cases are declared in evals/cases.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import specify
from decode import load_capture
from run import VERDICTS, OracleError, evaluate, evaluate_witnesses, validate_oracle, witness_records

HERE = Path(__file__).resolve().parent
EVALS = HERE / "evals"
CASES_PATH = EVALS / "cases.json"
RUNS = EVALS / "runs"

STATUSES = ("ok", "fail", "skip", "error")

CASE_KEYS = frozenset({"name", "spec", "note", "expect", "captures", "probes", "candidates", "replays"})
CAPTURE_KEYS = frozenset({"name", "file", "sha256", "expect", "note"})
PROBE_KEYS = frozenset({"name", "applies_when", "primitive", "forbidden", "values", "note"})
SHAPE_KEYS = frozenset({"name", "note", "matcher_includes", "predicate_relation", "observes", "nl_rule_includes"})
SHAPE_CRITERIA = SHAPE_KEYS - {"name", "note"}
CANDIDATE_KEYS = frozenset({"oracle", "expect_failures", "note"})


class EvalError(ValueError):
    """The case file is malformed. Not a property of any oracle."""


# case file


def _check_keys(obj: dict, allowed: frozenset[str], required: tuple[str, ...], where: str) -> None:
    if not isinstance(obj, dict):
        raise EvalError(f"{where}: expected an object")
    for key in required:
        if key not in obj:
            raise EvalError(f"{where}: missing {key!r}")
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise EvalError(f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _load_case(raw: dict) -> dict:
    _check_keys(raw, CASE_KEYS, ("name", "spec", "expect", "captures", "probes"), "case")
    name = raw["name"]
    case = dict(raw)
    case["spec"] = HERE / raw["spec"]

    captures = []
    for capture in raw["captures"]:
        where = f"case {name!r}: capture"
        _check_keys(capture, CAPTURE_KEYS, ("name", "file", "sha256", "expect"), where)
        if capture["expect"] not in VERDICTS:
            raise EvalError(f"{where} {capture['name']!r}: expect must be one of {list(VERDICTS)}")
        if len(capture["sha256"]) != 64:
            raise EvalError(f"{where} {capture['name']!r}: sha256 must be 64 hex characters")
        captures.append({**capture, "file": HERE / capture["file"]})
    if len({c["name"] for c in captures}) != len(captures):
        raise EvalError(f"case {name!r}: duplicate capture name")
    case["captures"] = captures

    for probe in raw["probes"]:
        where = f"case {name!r}: probe"
        _check_keys(probe, PROBE_KEYS, ("name", "applies_when", "primitive", "forbidden", "values"), where)
        if probe["forbidden"] not in VERDICTS:
            raise EvalError(f"{where} {probe['name']!r}: forbidden must be one of {list(VERDICTS)}")
        if probe["primitive"] == "ue_identity_tmsi":
            bad = [v for v in probe["values"] if len(v) != 39 or set(v) - set("01")]
            if bad:
                raise EvalError(f"{where} {probe['name']!r}: not a 39-bit binary string: {bad[0]!r}")

    expect = raw["expect"]
    _check_keys(expect, frozenset({"count", "required", "forbidden"}), ("count",), f"case {name!r}: expect")
    count = expect["count"]
    _check_keys(count, frozenset({"min", "max"}), ("min", "max"), f"case {name!r}: expect.count")
    if not 0 <= count["min"] <= count["max"]:
        raise EvalError(f"case {name!r}: expect.count needs 0 <= min <= max")
    for key in ("required", "forbidden"):
        for shape in expect.get(key, []):
            where = f"case {name!r}: expect.{key}"
            _check_keys(shape, SHAPE_KEYS, ("name",), where)
            if not set(shape) & SHAPE_CRITERIA:
                raise EvalError(f"{where} {shape['name']!r}: states no criterion")
    case["expect"] = {"count": count, "required": expect.get("required", []),
                      "forbidden": expect.get("forbidden", [])}

    candidates = []
    for candidate in raw.get("candidates", []):
        where = f"case {name!r}: candidate"
        _check_keys(candidate, CANDIDATE_KEYS, ("oracle", "expect_failures"), where)
        candidates.append({**candidate, "path": HERE / candidate["oracle"]})
    case["candidates"] = candidates
    case["replays"] = [HERE / p for p in raw.get("replays", [])]
    return case


def load_cases(path: Path = CASES_PATH) -> dict[str, dict]:
    """name -> case, with every declared path resolved."""
    raw = json.loads(Path(path).read_text())
    if "cases" not in raw:
        raise EvalError(f"{path}: no 'cases' array")
    cases: dict[str, dict] = {}
    for entry in raw["cases"]:
        case = _load_case(entry)
        if case["name"] in cases:
            raise EvalError(f"duplicate case {case['name']!r}")
        cases[case["name"]] = case
    if not cases:
        raise EvalError(f"{path}: no cases declared")
    return cases


# one oracle against one case


def _entry(case: str, expected: str, got: str, status: str) -> dict:
    return {"case": case, "expected": expected, "got": got, "status": status}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_eval(oracle: dict, case: dict) -> list[dict]:
    """One entry per check. A malformed oracle or capture is an `error`, not a raise."""
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

    clause = specify.load_spec(case["spec"])
    anchored = any(rule.strip() in paragraph for paragraph in clause["paragraphs"])
    report.append(_entry("rule_anchored_in_spec", f"in {clause['id']}",
                         "verbatim" if anchored else "not in the clause",
                         "ok" if anchored else "fail"))

    for capture in case["captures"]:
        label, path, expected = f"capture:{capture['name']}", capture["file"], capture["expect"]
        try:
            digest = _sha256(path)
        except OSError as exc:
            report.append(_entry(label, expected, f"unreadable: {exc}", "error"))
            continue
        if digest != capture["sha256"]:
            report.append(_entry(label, expected, f"sha256 mismatch: {path}", "error"))
            continue
        verdict = evaluate(oracle, load_capture(path))["verdict"]
        report.append(_entry(label, expected, verdict, "ok" if verdict == expected else "fail"))

    for probe in case["probes"]:
        label, expected = f"probe:{probe['name']}", f"not {probe['forbidden']}"
        if probe["applies_when"] not in rule.lower():
            report.append(_entry(label, expected, "rule not claimed", "skip"))
            continue
        if primitive != probe["primitive"]:
            report.append(_entry(label, expected, f"{probe['primitive']} not observed", "skip"))
            continue
        verdict = evaluate(oracle, witness_records(oracle, probe["values"]))["verdict"]
        report.append(_entry(label, expected, verdict, "fail" if verdict == probe["forbidden"] else "ok"))

    return report


def failed(report: list[dict]) -> list[dict]:
    return [e for e in report if e["status"] in ("fail", "error")]


# a reply against one case


def shape_matches(oracle: dict, shape: dict) -> bool:
    """Only the criteria the shape states are checked."""
    try:
        spec = validate_oracle(oracle)
    except (OracleError, AttributeError, TypeError):
        return False
    matcher = oracle.get("matcher", {})
    if any(matcher.get(k) != v for k, v in shape.get("matcher_includes", {}).items()):
        return False
    if "predicate_relation" in shape and spec["relation"] != shape["predicate_relation"]:
        return False
    if "observes" in shape and oracle["observe"][spec["variable"]] != shape["observes"]:
        return False
    if "nl_rule_includes" in shape:
        rule = oracle.get("nl_rule")
        if not isinstance(rule, str) or shape["nl_rule_includes"].lower() not in rule.lower():
            return False
    return True


def _first_match(oracles: list[dict], shape: dict) -> str | None:
    for oracle in oracles:
        if shape_matches(oracle, shape):
            return oracle.get("id", "?")
    return None


def _oracle_id(oracle) -> str:
    return oracle.get("id", "?") if isinstance(oracle, dict) else "?"


def run_case(case: dict, oracles: list) -> tuple[list[dict], list[dict]]:
    """(per-oracle reports, run-level report) for one reply's worth of oracles."""
    per_oracle = [{"oracle": _oracle_id(o), "report": run_eval(o, case)} for o in oracles]
    valid = [o for o, r in zip(oracles, per_oracle) if r["report"][0]["status"] == "ok"]

    expect = case["expect"]
    low, high = expect["count"]["min"], expect["count"]["max"]
    run_report = [_entry("count", f"{low}..{high}", str(len(valid)),
                         "ok" if low <= len(valid) <= high else "fail")]
    for shape in expect["required"]:
        hit = _first_match(valid, shape)
        run_report.append(_entry(f"required:{shape['name']}", "one oracle matches",
                                 hit or "no match", "ok" if hit else "fail"))
    for shape in expect["forbidden"]:
        hit = _first_match(valid, shape)
        run_report.append(_entry(f"forbidden:{shape['name']}", "no oracle matches",
                                 hit or "absent", "fail" if hit else "ok"))
    return per_oracle, run_report


def _record(case_name: str, case: dict, source: str, oracles: list, **extra) -> dict:
    per_oracle, run_report = run_case(case, oracles)
    ok = not failed(run_report) and not any(failed(r["report"]) for r in per_oracle)
    return {
        "run_id": str(uuid.uuid4()),
        "utc": datetime.now(timezone.utc).isoformat(),
        "case": case_name,
        "source": source,
        "spec": str(case["spec"].relative_to(HERE)),
        **extra,
        "oracles": per_oracle,
        "run_report": run_report,
        "ok": ok,
    }


# the loop


def extract_oracles(raw_reply: str) -> list:
    try:
        return specify.extract_json_array(raw_reply)
    except ValueError:
        return []


def run_live(case_name: str, case: dict, model: str | None = None) -> dict:
    """Call the model on this case's clause, then eval whatever comes back."""
    prompt = specify.build_prompt(case["spec"])
    model, raw_reply = specify.call_live(prompt, model)
    return _record(case_name, case, "live", extract_oracles(raw_reply), model=model,
                   prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                   raw_reply=raw_reply)


def run_replay(case_name: str, case: dict, path: Path) -> dict:
    """Re-eval a stored reply through the same parse path, with no network."""
    stored = json.loads(Path(path).read_text())
    raw_reply = stored["raw_reply"]
    return _record(case_name, case, "replay", extract_oracles(raw_reply),
                   model=stored.get("model"), prompt_sha256=stored.get("prompt_sha256"),
                   replay_of=str(path), raw_reply=raw_reply)


def run_oracle_file(case_name: str, case: dict, path: Path) -> dict:
    raw = json.loads(Path(path).read_text())
    oracles = raw if isinstance(raw, list) else [raw]
    return _record(case_name, case, "oracle", oracles, oracle_file=str(path))


def run_candidates(case_name: str, case: dict) -> dict:
    """The declared static oracles, each against the failures the case says it should have."""
    per_oracle = []
    for candidate in case["candidates"]:
        oracle = json.loads(candidate["path"].read_text())
        report = run_eval(oracle, case)
        declared = sorted(candidate["expect_failures"])
        got = sorted(e["case"] for e in failed(report))
        report = report + [_entry("declared_failures", ", ".join(declared) or "none",
                                  ", ".join(got) or "none", "ok" if got == declared else "fail")]
        per_oracle.append({"oracle": _oracle_id(oracle), "report": report,
                           "oracle_file": candidate["oracle"]})
    return {
        "run_id": str(uuid.uuid4()),
        "utc": datetime.now(timezone.utc).isoformat(),
        "case": case_name,
        "source": "candidates",
        "spec": str(case["spec"].relative_to(HERE)),
        "oracles": per_oracle,
        "run_report": [],
        "ok": all(e["status"] == "ok" for r in per_oracle for e in r["report"][-1:]),
    }


# report


def _table(report: list[dict], indent: str = "  ") -> list[str]:
    marks = {"ok": "ok", "fail": "FAIL", "skip": "skip", "error": "ERROR"}
    width_case = max(len(e["case"]) for e in report)
    width_expected = max(len(e["expected"]) for e in report)
    lines = []
    for e in report:
        status = marks[e["status"]]
        if e["status"] != "ok":
            status += f" ({e['got']})"
        lines.append(f"{indent}{e['case']:<{width_case}}  {e['expected']:<{width_expected}}  {status}")
    return lines


def render(record: dict) -> str:
    head = [f"run {record['run_id']}   case {record['case']}"]
    detail = [f"source {record['source']}", f"spec {record['spec']}"]
    if record.get("model"):
        detail.append(f"model {record['model']}")
    detail.append(f"oracles {len(record['oracles'])}")
    head.append("   ".join(detail))

    lines = head + [""]
    for entry in record["oracles"]:
        title = entry["oracle"]
        if entry.get("oracle_file"):
            title += f"   {entry['oracle_file']}"
        lines.append(title)
        lines += _table(entry["report"])
        lines.append("")
    if record["run_report"]:
        lines += _table(record["run_report"], indent="")
        lines.append("")

    entries = [e for r in record["oracles"] for e in r["report"]] + record["run_report"]
    bad = failed(entries)
    total = len(entries)
    if record["ok"]:
        skipped = sum(1 for e in entries if e["status"] == "skip")
        lines.append(f"RUN PASSED: {total} checks" + (f" ({skipped} skipped)" if skipped else ""))
    else:
        lines.append(f"RUN FAILED: {len(bad)} of {total} checks")
    return "\n".join(lines)


def main() -> None:
    cases = load_cases()
    ap = argparse.ArgumentParser(description="run a spec clause through a model and eval the oracles")
    ap.add_argument("--case", choices=sorted(cases), default=None)
    ap.add_argument("--live", action="store_true", help="call the model (network)")
    ap.add_argument("--model", default=None, help="with --live; default $SPECIFIER_MODEL")
    ap.add_argument("--replay", help="re-eval a stored run record, no network")
    ap.add_argument("--oracle", help="eval an oracle file as if it were a reply")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if sum(bool(x) for x in (args.live, args.replay, args.oracle)) > 1:
        ap.error("--live, --replay and --oracle are alternatives")
    if args.model and not args.live:
        ap.error("--model requires --live")
    if args.case is None:
        if len(cases) > 1:
            ap.error(f"--case is required; declared: {sorted(cases)}")
        args.case = next(iter(cases))
    case = cases[args.case]

    if args.live:
        record = run_live(args.case, case, args.model)
        RUNS.mkdir(parents=True, exist_ok=True)
        stamp = record["utc"].replace(":", "").replace("+0000", "Z")
        path = RUNS / f"{stamp}-{record['run_id']}.json"
        path.write_text(json.dumps(record, indent=2))
        record["saved_to"] = str(path)
    elif args.replay:
        record = run_replay(args.case, case, Path(args.replay))
    elif args.oracle:
        record = run_oracle_file(args.case, case, Path(args.oracle))
    else:
        record = run_candidates(args.case, case)

    print(json.dumps(record, indent=2) if args.json else render(record))
    if record.get("saved_to"):
        print(f"\nsaved to {record['saved_to']}")
    sys.exit(0 if record["ok"] else 1)


if __name__ == "__main__":
    main()
