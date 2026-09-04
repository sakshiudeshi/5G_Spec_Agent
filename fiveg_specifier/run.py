"""Oracle + capture -> verdict, reason, evidence.

Two error axes, deliberately different:

  * the byte axis is total   -- an undecodable PDU becomes `inconclusive`, never a
    false `violate`;
  * the authoring axis is loud -- an invented `observe` primitive or `matcher` key
    raises OracleError. Silently ignoring a misspelled matcher key would widen the
    oracle to all traffic and make it fire on a compliant network.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from decode import ESTABLISHMENT_CAUSES, Record, load_capture

# --- the three closed vocabularies -----------------------------------------

MATCHER_KEYS: dict[str, frozenset[str]] = {
    "message_is": frozenset({"rrc_setup_request"}),
    "id_type": frozenset({"tmsi", "random"}),
    "establishment_cause": frozenset(ESTABLISHMENT_CAUSES),
}

OBSERVE_PRIMITIVES = frozenset({"ue_identity_tmsi", "establishment_cause", "id_type"})

# --- the three predicate forms, matched by regex, no parser ----------------

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_PREDICATE_FORMS = (
    ("distinct", re.compile(rf"^distinct\(\s*({_NAME})\s*\)$")),
    ("constant", re.compile(rf"^constant\(\s*({_NAME})\s*\)$")),
    ("equals", re.compile(rf'^({_NAME})\s*==\s*"([^"]*)"$')),
)

VERDICTS = ("pass", "violate", "inconclusive")


class OracleError(ValueError):
    """The oracle is malformed. Not a property of the capture."""


def validate_oracle(oracle: dict) -> dict:
    """Check the oracle against the closed vocabularies. Returns the parsed predicate."""
    if not isinstance(oracle, dict):
        raise OracleError("oracle must be a JSON object")
    for field in ("id", "nl_rule", "spec_anchor", "observe", "predicate"):
        if field not in oracle:
            raise OracleError(f"oracle {oracle.get('id', '?')!r}: missing field {field!r}")

    matcher = oracle.get("matcher", {})
    if not isinstance(matcher, dict):
        raise OracleError("matcher must be an object")
    for key, value in matcher.items():
        if key not in MATCHER_KEYS:
            raise OracleError(f"unknown matcher key {key!r}; allowed: {sorted(MATCHER_KEYS)}")
        if value not in MATCHER_KEYS[key]:
            raise OracleError(f"matcher {key}={value!r} outside its closed domain")

    observe = oracle["observe"]
    if not isinstance(observe, dict) or not observe:
        raise OracleError("observe must be a non-empty object")
    for name, primitive in observe.items():
        if not re.fullmatch(_NAME, name):
            raise OracleError(f"illegal observe name {name!r}")
        if primitive not in OBSERVE_PRIMITIVES:
            raise OracleError(
                f"unknown observe primitive {primitive!r}; allowed: {sorted(OBSERVE_PRIMITIVES)}"
            )

    predicate = oracle["predicate"]
    if not isinstance(predicate, str):
        raise OracleError("predicate must be a string")
    for relation, pattern in _PREDICATE_FORMS:
        m = pattern.match(predicate.strip())
        if m:
            variable = m.group(1)
            if variable not in observe:
                raise OracleError(f"predicate uses unbound name {variable!r}")
            literal = m.group(2) if relation == "equals" else None
            return {"relation": relation, "variable": variable, "literal": literal}
    raise OracleError(
        f"predicate {predicate!r} is outside the three forms: "
        "distinct(V), constant(V), V == \"literal\""
    )


def matches(record: Record, matcher: dict) -> bool:
    """All matcher keys AND-ed; an omitted key means don't care."""
    return all(getattr(record, key) == value for key, value in matcher.items())


def evaluate(oracle: dict, records: list[Record]) -> dict:
    spec = validate_oracle(oracle)
    relation, variable, literal = spec["relation"], spec["variable"], spec["literal"]
    observe = oracle["observe"]
    primitive = observe[variable]

    matched = [r for r in records if matches(r, oracle.get("matcher", {}))]
    if not matched:
        return _verdict("inconclusive", "matcher-never-met", {"matched": 0})

    seen: dict[str, tuple[int, float]] = {}
    violation: dict | None = None
    undecodable: int | None = None
    observed = 0

    for r in matched:
        if any(getattr(r, p) is None for p in observe.values()):
            undecodable = r.seq
            break
        observed += 1
        value = getattr(r, primitive)

        if relation == "distinct":
            if value in seen:
                first_seq, first_ts = seen[value]
                if violation is None:
                    violation = {
                        "value": value,
                        "first_seq": first_seq,
                        "first_ts": first_ts,
                        "repeat_seq": r.seq,
                        "repeat_ts": r.ts,
                        "gap_s": round(r.ts - first_ts, 6),
                    }
            else:
                seen[value] = (r.seq, r.ts)
        elif relation == "constant":
            if seen and value not in seen:
                first_value, (first_seq, first_ts) = next(iter(seen.items()))
                if violation is None:
                    violation = {
                        "value": value,
                        "expected": first_value,
                        "first_seq": first_seq,
                        "first_ts": first_ts,
                        "mismatch_seq": r.seq,
                        "mismatch_ts": r.ts,
                    }
            elif not seen:
                seen[value] = (r.seq, r.ts)
        else:  # equals
            seen.setdefault(value, (r.seq, r.ts))
            if value != literal and violation is None:
                violation = {
                    "value": value,
                    "expected": literal,
                    "mismatch_seq": r.seq,
                    "mismatch_ts": r.ts,
                }

    evidence = {
        "matched": len(matched),
        "observed": observed,
        "distinct": len(seen),
        "repeats": observed - len(seen),
    }
    # `violate` is irrevocable: a break in a finite prefix decides the verdict, whatever
    # follows it in the capture.
    if violation is not None:
        evidence["first_violation"] = violation
        return _verdict("violate", None, evidence)
    if undecodable is not None:
        evidence["undecodable_at_seq"] = undecodable
        return _verdict("inconclusive", "undecodable-pdu", evidence)
    # One observation makes every relation trivially true; calling that `pass` would be
    # agreement that was never tested.
    if observed < 2:
        return _verdict("inconclusive", f"under-observed:{observed}", evidence)
    return _verdict("pass", None, evidence)


def _verdict(verdict: str, reason: str | None, evidence: dict) -> dict:
    return {"verdict": verdict, "reason": reason, "evidence": evidence}


def witness_records(oracle: dict, values: list[str]) -> list[Record]:
    """Synthesise the minimal record sequence that carries `values` past the matcher."""
    spec = validate_oracle(oracle)
    matcher = oracle.get("matcher", {})
    primitive = oracle["observe"][spec["variable"]]
    defaults = {
        "message_is": "rrc_setup_request",
        "id_type": "tmsi",
        "ue_identity_tmsi": "0" * 39,
        "establishment_cause": ESTABLISHMENT_CAUSES[0],
    }
    records = []
    for i, value in enumerate(values, start=1):
        fields = dict(defaults)
        fields.update(matcher)
        fields[primitive] = value
        records.append(Record(seq=i, ts=float(i), **fields))
    return records


def evaluate_witnesses(oracle: dict) -> list[dict]:
    out = []
    for key, expected in (("witness_pass", "pass"), ("witness_violate", "violate")):
        values = oracle.get(key)
        if values is None:
            continue
        result = evaluate(oracle, witness_records(oracle, values))
        out.append({"witness": key, "expected": expected, "got": result["verdict"],
                    "ok": result["verdict"] == expected})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="run an oracle over a capture")
    ap.add_argument("--oracle", default=str(Path(__file__).parent / "oracle.json"))
    ap.add_argument("--capture", required=True)
    args = ap.parse_args()
    oracle = json.loads(Path(args.oracle).read_text())
    result = evaluate(oracle, load_capture(args.capture))
    print(json.dumps({"oracle": oracle["id"], "capture": args.capture, **result}, indent=2))


if __name__ == "__main__":
    main()
