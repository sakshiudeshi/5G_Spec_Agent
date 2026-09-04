import copy
import json
from pathlib import Path

import pytest

import decode
import eval_harness
import specify

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_ORACLE = ROOT / "fiveg_specifier" / "golden_oracle.json"
CANDIDATE = ROOT / "fiveg_specifier" / "evals" / "candidates" / "TMSI-UNPRED-01.json"

CASE = eval_harness.EVAL_CASES[eval_harness.DEFAULT_CASE]


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN_ORACLE.read_text())


@pytest.fixture(scope="module")
def candidate():
    return json.loads(CANDIDATE.read_text())


def _by_case(report):
    return {e["case"]: e for e in report}


def test_golden_oracle_passes_every_case(golden):
    report = eval_harness.run_eval(golden, CASE)
    assert eval_harness.failed(report) == []
    got = _by_case(report)
    assert got["capture:starhub"]["got"] == "violate"
    assert got["capture:singtel"]["got"] == "pass"
    # distinct(tmsi) does express re-assignment, so the unpredictability probe does not apply.
    assert got["probe:sequential-counter"]["status"] == "skip"


def test_model_oracle_fails_the_capture_and_the_probe(candidate):
    report = eval_harness.run_eval(candidate, CASE)
    assert {e["case"] for e in eval_harness.failed(report)} == {
        "capture:singtel",
        "probe:sequential-counter",
    }
    got = _by_case(report)
    assert got["capture:singtel"]["got"] == "violate", "accuses a network 6.12.3 NOTE 1 permits"
    assert got["probe:sequential-counter"]["got"] == "pass", "a counter is not unpredictable"
    assert got["capture:starhub"]["status"] == "ok"


def test_existing_gate_accepts_what_the_eval_rejects(candidate):
    report = specify.validate_file(CANDIDATE)
    assert all(r["ok"] for r in report)
    assert eval_harness.failed(eval_harness.run_eval(candidate, CASE))


def test_model_rule_is_a_real_sentence_of_the_clause(candidate):
    got = _by_case(eval_harness.run_eval(candidate, CASE))
    assert got["rule_anchored_in_spec"]["status"] == "ok"


def test_eval_captures_are_pinned():
    for name, path, sha256, _expected in CASE["captures"]:
        assert eval_harness._sha256(path) == sha256, f"{name} capture moved"
    counts = {}
    for name, path, _sha256, _expected in CASE["captures"]:
        records = decode.load_capture(path)
        counts[name] = sum(
            1
            for r in records
            if r.message_is == "rrc_setup_request"
            and r.id_type == "tmsi"
            and r.establishment_cause == "mt-Access"
        )
    assert counts == {"starhub": 205, "singtel": 93}


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda o: o.update({"nl_rule": 42}), id="nl_rule-not-a-string"),
        pytest.param(lambda o: o["matcher"].update({"establishmentCause": "mt-Access"}), id="matcher-key"),
        pytest.param(lambda o: o.pop("predicate"), id="missing-predicate"),
    ],
)
def test_malformed_oracle_is_an_error_not_a_crash(golden, mutate):
    broken = copy.deepcopy(golden)
    mutate(broken)
    report = eval_harness.run_eval(broken, CASE)
    assert [(e["case"], e["status"]) for e in report] == [("schema", "error")]


def test_missing_capture_is_an_error_not_a_crash(golden):
    ghost = eval_harness.EVAL_DATA / "no-such-capture.pcap"
    case = {**CASE, "captures": (("ghost", ghost, "0" * 64, "pass"),)}
    entry = _by_case(eval_harness.run_eval(golden, case))["capture:ghost"]
    assert entry["status"] == "error"
    assert ghost.name in entry["got"]


def test_render_reports_the_failing_summary(candidate):
    report = eval_harness.run_eval(candidate, CASE)
    text = eval_harness.render(candidate["id"], eval_harness.DEFAULT_CASE, report)
    assert text.startswith("oracle TMSI-UNPRED-01   case guti-reuse-mt-access")
    assert "EVAL FAILED: 2 of 6 cases" in text
    assert "FAIL (violate)" in text and "FAIL (pass)" in text


def test_render_reports_the_passing_summary(golden):
    report = eval_harness.run_eval(golden, CASE)
    text = eval_harness.render(golden["id"], eval_harness.DEFAULT_CASE, report)
    assert "EVAL PASSED: 6 cases (1 skipped)" in text
    assert "FAIL" not in text


def test_load_oracles_takes_one_object_or_an_array(tmp_path, golden):
    single = tmp_path / "one.json"
    single.write_text(json.dumps(golden))
    many = tmp_path / "many.json"
    many.write_text(json.dumps([golden, golden]))
    assert eval_harness.load_oracles(single) == [golden]
    assert len(eval_harness.load_oracles(many)) == 2
