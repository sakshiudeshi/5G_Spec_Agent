import copy
import hashlib
import json
import uuid
from pathlib import Path

import pytest

import decode
import eval_harness
import run
import specify

ROOT = Path(__file__).resolve().parents[2]
FIVEG = ROOT / "fiveg_specifier"
GOLDEN_ORACLE = FIVEG / "golden_oracle.json"
CANDIDATE = FIVEG / "evals" / "candidates" / "TMSI-UNPRED-01.json"
REPLAY = FIVEG / "evals" / "replays" / "2026-09-04-claude-opus-5.json"

CASE_NAME = "guti-reuse-mt-access"


@pytest.fixture(scope="module")
def case():
    return eval_harness.load_cases()[CASE_NAME]


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN_ORACLE.read_text())


@pytest.fixture(scope="module")
def candidate():
    return json.loads(CANDIDATE.read_text())


def _by_case(report):
    return {e["case"]: e for e in report}


# the case file


def test_cases_file_declares_resolvable_paths(case):
    assert case["spec"].exists()
    for capture in case["captures"]:
        assert capture["file"].exists(), capture["name"]
    for candidate in case["candidates"]:
        assert candidate["path"].exists(), candidate["oracle"]
    for replay in case["replays"]:
        assert replay.exists(), replay


def _raw_case(**over):
    case = {
        "name": "t",
        "spec": "spec/x.json",
        "expect": {"count": {"min": 0, "max": 1}},
        "captures": [{"name": "c", "file": "f", "sha256": "0" * 64, "expect": "pass"}],
        "probes": [],
    }
    case.update(over)
    return {"cases": [case]}


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(_raw_case(captures=[{"name": "c", "file": "f", "sha256": "0" * 64, "expect": "maybe"}]), id="verdict-not-in-domain"),
        pytest.param(_raw_case(captures=[{"name": "c", "file": "f", "sha256": "abc", "expect": "pass"}]), id="short-sha256"),
        pytest.param(_raw_case(captures=[{"name": "c", "file": "f", "sha256": "0" * 64, "expect": "pass", "labels": []}]), id="unknown-capture-key"),
        pytest.param(_raw_case(expect={"count": {"min": 2, "max": 1}}), id="count-min-over-max"),
        pytest.param(_raw_case(expect={"count": {"min": 0, "max": 1}, "required": [{"name": "n"}]}), id="shape-states-no-criterion"),
        pytest.param(_raw_case(probes=[{"name": "p", "applies_when": "x", "primitive": "ue_identity_tmsi", "forbidden": "pass", "values": ["01"]}]), id="probe-value-not-39-bit"),
        pytest.param({"cases": [_raw_case()["cases"][0], _raw_case()["cases"][0]]}, id="duplicate-case-name"),
        pytest.param({"note": "no cases key"}, id="no-cases-array"),
    ],
)
def test_malformed_case_file_is_rejected(tmp_path, raw):
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(eval_harness.EvalError):
        eval_harness.load_cases(path)


# one oracle against the case


def test_golden_oracle_passes_every_check(golden, case):
    report = eval_harness.run_eval(golden, case)
    assert eval_harness.failed(report) == []
    got = _by_case(report)
    assert got["capture:starhub"]["got"] == "violate"
    assert got["capture:singtel"]["got"] == "pass"
    # distinct(tmsi) does express re-assignment, so the unpredictability probe does not apply.
    assert got["probe:sequential-counter"]["status"] == "skip"


def test_model_oracle_fails_the_capture_and_the_probe(candidate, case):
    report = eval_harness.run_eval(candidate, case)
    assert {e["case"] for e in eval_harness.failed(report)} == {
        "capture:singtel",
        "probe:sequential-counter",
    }
    got = _by_case(report)
    assert got["capture:singtel"]["got"] == "violate", "accuses a network 6.12.3 NOTE 1 permits"
    assert got["probe:sequential-counter"]["got"] == "pass", "a counter is not unpredictable"
    assert got["capture:starhub"]["status"] == "ok"
    assert got["rule_anchored_in_spec"]["status"] == "ok", "the sentence is real, the encoding is not"


def test_existing_gate_accepts_what_the_eval_rejects(candidate, case):
    assert all(r["ok"] for r in specify.validate_file(CANDIDATE))
    assert eval_harness.failed(eval_harness.run_eval(candidate, case))


def test_eval_captures_are_pinned(case):
    counts = {}
    for capture in case["captures"]:
        assert eval_harness._sha256(capture["file"]) == capture["sha256"], capture["name"]
        counts[capture["name"]] = sum(
            1
            for r in decode.load_capture(capture["file"])
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
def test_malformed_oracle_is_an_error_not_a_crash(golden, case, mutate):
    broken = copy.deepcopy(golden)
    mutate(broken)
    report = eval_harness.run_eval(broken, case)
    assert [(e["case"], e["status"]) for e in report] == [("schema", "error")]


def test_missing_capture_is_an_error_not_a_crash(golden, case):
    ghost = FIVEG / "evals" / "data" / "no-such-capture.pcap"
    broken = {**case, "captures": [{"name": "ghost", "file": ghost, "sha256": "0" * 64, "expect": "pass"}]}
    entry = _by_case(eval_harness.run_eval(golden, broken))["capture:ghost"]
    assert entry["status"] == "error"
    assert ghost.name in entry["got"]


# expectations on the emitted oracles


def test_required_shape_matches_the_golden_only(golden, candidate, case):
    shape = case["expect"]["required"][0]
    assert eval_harness.shape_matches(golden, shape)
    assert not eval_harness.shape_matches(candidate, shape), "its matcher omits establishment_cause"


def test_forbidden_shape_matches_the_model_only(golden, candidate, case):
    shape = case["expect"]["forbidden"][0]
    assert eval_harness.shape_matches(candidate, shape)
    assert not eval_harness.shape_matches(golden, shape)


def test_shape_ignores_the_observe_binding_name(golden, case):
    renamed = copy.deepcopy(golden)
    renamed["observe"] = {"v": renamed["observe"].pop("tmsi")}
    renamed["predicate"] = "distinct(v)"
    assert eval_harness.shape_matches(renamed, case["expect"]["required"][0])


def test_count_bounds_the_valid_oracles(golden, case):
    for oracles, expected in (([], "fail"), ([golden], "ok"), ([golden, golden], "fail")):
        _per_oracle, run_report = eval_harness.run_case(case, oracles)
        assert _by_case(run_report)["count"]["status"] == expected, oracles


def test_run_case_scores_the_golden_reply(golden, case):
    per_oracle, run_report = eval_harness.run_case(case, [golden])
    assert eval_harness.failed(run_report) == []
    assert eval_harness.failed(per_oracle[0]["report"]) == []


# the loop


def test_replay_of_the_recorded_reply_fails_the_run(case):
    record = eval_harness.run_replay(CASE_NAME, case, REPLAY)
    assert record["source"] == "replay"
    assert record["model"] == "anthropic/claude-opus-5"
    assert [o["oracle"] for o in record["oracles"]] == ["TMSI-UNPRED-01"]
    run = _by_case(record["run_report"])
    assert run["count"]["status"] == "ok", "one oracle, as the case expects"
    assert run["required:mt-access-guti-reuse"]["status"] == "fail"
    assert run["forbidden:unpredictability-as-distinctness"]["got"] == "TMSI-UNPRED-01"
    assert record["ok"] is False


def test_run_live_drives_the_whole_loop(monkeypatch, case):
    reply = json.loads(REPLAY.read_text())["raw_reply"]
    seen = {}

    def fake_call_live(prompt, model=None):
        seen["prompt"] = prompt
        return ("stub/model", reply)

    monkeypatch.setattr(specify, "call_live", fake_call_live)
    record = eval_harness.run_live(CASE_NAME, case, "stub/model")

    clause = specify.load_spec(case["spec"])
    for paragraph in clause["paragraphs"]:
        assert paragraph in seen["prompt"], "the case's clause reached the model"
    assert record["prompt_sha256"] == hashlib.sha256(seen["prompt"].encode("utf-8")).hexdigest()
    assert record["source"] == "live" and record["model"] == "stub/model"
    assert uuid.UUID(record["run_id"]).version == 4
    assert record["raw_reply"] == reply
    assert [o["oracle"] for o in record["oracles"]] == ["TMSI-UNPRED-01"]
    assert record["ok"] is False


def test_unparseable_reply_is_zero_oracles(monkeypatch, case):
    monkeypatch.setattr(specify, "call_live", lambda prompt, model=None: ("stub/model", "I refuse."))
    record = eval_harness.run_live(CASE_NAME, case, "stub/model")
    assert record["oracles"] == []
    assert _by_case(record["run_report"])["count"]["got"] == "0"
    assert record["ok"] is False, "the clause does hold an expressible sentence"


def test_candidates_lane_matches_the_declared_failures(case):
    record = eval_harness.run_candidates(CASE_NAME, case)
    assert record["ok"] is True
    declared = {r["oracle"]: r["report"][-1] for r in record["oracles"]}
    assert declared["NR-GUTI-01"]["got"] == "none"
    assert declared["TMSI-UNPRED-01"]["got"] == "capture:singtel, probe:sequential-counter"


def test_oracle_file_lane_reads_one_object_or_an_array(tmp_path, golden, case):
    many = tmp_path / "many.json"
    many.write_text(json.dumps([golden, golden]))
    single = eval_harness.run_oracle_file(CASE_NAME, case, GOLDEN_ORACLE)
    pair = eval_harness.run_oracle_file(CASE_NAME, case, many)
    assert single["ok"] is True and len(single["oracles"]) == 1
    assert len(pair["oracles"]) == 2
    assert _by_case(pair["run_report"])["count"]["status"] == "fail", "two oracles, expected 1..1"


# duplicate oracles: one check wearing two names


def test_fingerprint_ignores_the_bound_name(golden):
    renamed = copy.deepcopy(golden)
    renamed["observe"] = {"other": golden["observe"]["tmsi"]}
    renamed["predicate"] = "distinct(other)"
    assert run.fingerprint(renamed) == run.fingerprint(golden)


def test_fingerprint_separates_the_matcher(golden):
    narrower = copy.deepcopy(golden)
    narrower["matcher"] = {**golden["matcher"], "id_type": "tmsi"}
    assert run.fingerprint(narrower) != run.fingerprint(golden)


def test_fingerprint_separates_an_unused_observe_binding(golden):
    """An extra binding is not inert -- it can decide `undecodable-pdu`."""
    extra = copy.deepcopy(golden)
    extra["observe"] = {**golden["observe"], "cause": "establishment_cause"}
    assert run.fingerprint(extra) != run.fingerprint(golden)


def test_one_oracle_is_all_distinct(golden, case):
    _per_oracle, run_report = eval_harness.run_case(case, [golden])
    assert _by_case(run_report)["distinct_oracles"]["status"] == "ok"


def test_renaming_an_oracle_does_not_make_it_a_second_check(golden, case):
    """The glm/fable failure mode: same matcher, observe and predicate, a new id and rule."""
    twin = copy.deepcopy(golden)
    twin["id"] = "NR-GUTI-02"
    twin["nl_rule"] = (
        "This new 5G-GUTI shall be sent before the current NAS signalling connection is "
        "released or the N1 NAS signalling connection is suspended."
    )
    entry = _by_case(eval_harness.run_case(case, [golden, twin])[1])["distinct_oracles"]
    assert entry["status"] == "fail"
    assert entry["got"] == "NR-GUTI-02 = NR-GUTI-01"


def test_two_genuinely_different_checks_are_distinct(golden, case):
    """opus's second oracle: a real second check, caught by count rather than by this one."""
    other = copy.deepcopy(golden)
    other["id"] = "GUTI-REG-02"
    other["matcher"] = {**golden["matcher"], "establishment_cause": "mo-Signalling"}
    assert _by_case(eval_harness.run_case(case, [golden, other])[1])["distinct_oracles"]["status"] == "ok"


def test_duplicates_are_counted_among_valid_oracles_only(golden, case):
    """A malformed twin never reaches the check; it is already a schema error."""
    broken = copy.deepcopy(golden)
    broken["id"], broken["predicate"] = "BROKEN-01", "sometimes(tmsi)"
    run_report = eval_harness.run_case(case, [golden, broken])[1]
    assert _by_case(run_report)["distinct_oracles"]["status"] == "ok"


# report


def test_render_reports_the_failing_run(case):
    text = eval_harness.render(eval_harness.run_replay(CASE_NAME, case, REPLAY))
    assert f"case {CASE_NAME}" in text
    assert "TMSI-UNPRED-01" in text
    assert "FAIL (violate)" in text and "FAIL (pass)" in text
    assert "RUN FAILED: 4 of 10 checks" in text


def test_render_reports_the_passing_run(golden, case):
    text = eval_harness.render(eval_harness.run_oracle_file(CASE_NAME, case, GOLDEN_ORACLE))
    assert "RUN PASSED: 10 checks (1 skipped)" in text
    assert "FAIL" not in text


def _main(monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["eval_harness.py", *argv])
    with pytest.raises(SystemExit) as exit:
        eval_harness.main()
    return exit.value.code


def test_cli_candidates_lane_is_the_default(monkeypatch, capsys):
    assert _main(monkeypatch) == 0
    out = capsys.readouterr().out
    assert "source candidates" in out and "RUN PASSED" in out


def test_cli_replay_exits_nonzero(monkeypatch, capsys):
    assert _main(monkeypatch, "--replay", str(REPLAY)) == 1
    assert "RUN FAILED" in capsys.readouterr().out


def test_cli_json_lane_emits_the_record(monkeypatch, capsys):
    assert _main(monkeypatch, "--oracle", str(CANDIDATE), "--json") == 1
    record = json.loads(capsys.readouterr().out)
    assert record["source"] == "oracle" and record["ok"] is False
    assert uuid.UUID(record["run_id"]).version == 4


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(("--model", "x"), id="model-without-live"),
        pytest.param(("--live", "--replay", "r"), id="live-with-replay"),
        pytest.param(("--case", "no-such-case"), id="unknown-case"),
    ],
)
def test_cli_rejects_bad_invocations(monkeypatch, argv):
    assert _main(monkeypatch, *argv) == 2
