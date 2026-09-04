import copy
import hashlib
import json
from pathlib import Path

import pytest

import decode
import run
import specify

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "guti_reuse_report" / "report_data"
STARHUB = DATA / "starhub-xiaomi11-ntu-sutd.pcap"
SINGTEL = DATA / "singtel-xiaomi11-ntu.txt"


@pytest.fixture(scope="module")
def oracle():
    return json.loads((ROOT / "fiveg_specifier" / "oracle.json").read_text())


@pytest.fixture(scope="module")
def starhub():
    return decode.load_capture(STARHUB)


@pytest.fixture(scope="module")
def singtel():
    return decode.load_capture(SINGTEL)


def _causes(records):
    counts = {}
    for r in records:
        if r.message_is == "rrc_setup_request" and r.id_type == "tmsi":
            counts[r.establishment_cause] = counts.get(r.establishment_cause, 0) + 1
    return counts


# 1. pcap decode
def test_pcap_decode(starhub):
    assert len(starhub) == 612
    assert _causes(starhub) == {"mo-Data": 352, "mt-Access": 205, "mo-Signalling": 36}
    assert sum(_causes(starhub).values()) == 593


# 2. txt decode
def test_txt_decode(singtel):
    assert _causes(singtel) == {"mt-Access": 93, "mo-Data": 32, "mo-Signalling": 1}
    assert sum(_causes(singtel).values()) == 126


# 3. golden verdicts
def test_starhub_violates(oracle, starhub):
    result = run.evaluate(oracle, starhub)
    assert result["verdict"] == "violate"
    ev = result["evidence"]
    assert (ev["matched"], ev["distinct"], ev["repeats"]) == (205, 21, 184)
    first = ev["first_violation"]
    assert first["value"] == "101010111000000101111111010110011011111"
    assert (first["first_seq"], first["repeat_seq"]) == (217, 252)
    assert first["gap_s"] == pytest.approx(42.238, abs=1e-3)


def test_singtel_passes(oracle, singtel):
    result = run.evaluate(oracle, singtel)
    assert result["verdict"] == "pass"
    assert result["evidence"]["matched"] == 93
    assert result["evidence"]["distinct"] == 93


# 4. the establishment_cause matcher key is load-bearing
def test_matcher_key_is_load_bearing(oracle, singtel):
    widened = copy.deepcopy(oracle)
    del widened["matcher"]["establishment_cause"]
    result = run.evaluate(widened, singtel)
    assert result["verdict"] == "violate", "without the cause key the oracle accuses a compliant network"
    assert result["evidence"]["matched"] == 126


# 5. witness round-trip
def test_witness_round_trip(oracle):
    verdicts = run.evaluate_witnesses(oracle)
    assert [(w["witness"], w["got"]) for w in verdicts] == [
        ("witness_pass", "pass"),
        ("witness_violate", "violate"),
    ]


# 6. the authoring axis fails loudly
@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda o: o["observe"].update({"tmsi": "ue_identity_guti"}), id="observe"),
        pytest.param(lambda o: o["matcher"].update({"establishmentCause": "mt-Access"}), id="matcher-key"),
        pytest.param(lambda o: o["matcher"].update({"establishment_cause": "mt-access"}), id="matcher-value"),
        pytest.param(lambda o: o.update({"predicate": "unique(tmsi)"}), id="predicate-form"),
        pytest.param(lambda o: o.update({"predicate": "distinct(guti)"}), id="unbound-name"),
    ],
)
def test_validator_rejects(oracle, mutate):
    broken = copy.deepcopy(oracle)
    mutate(broken)
    with pytest.raises(run.OracleError):
        run.evaluate(broken, [])


# undecodable input is inconclusive, never a false violate
def test_undecodable_is_inconclusive(oracle):
    truncated = decode.decode_ul_ccch(b"\x09\xd9\x1c")
    assert truncated == (None, None, None, None)
    widened = copy.deepcopy(oracle)
    widened["matcher"] = {}
    records = [decode.Record(1, 0.0, *truncated)]
    result = run.evaluate(widened, records)
    assert result["verdict"] == "inconclusive"
    assert result["reason"] == "undecodable-pdu"


def test_single_observation_is_not_pass(oracle):
    records = run.witness_records(oracle, ["0" * 39])
    result = run.evaluate(oracle, records)
    assert result["verdict"] == "inconclusive"
    assert result["reason"] == "under-observed:1"


def test_matcher_never_met(oracle, singtel):
    narrowed = copy.deepcopy(oracle)
    narrowed["matcher"]["establishment_cause"] = "spare1"
    result = run.evaluate(narrowed, singtel)
    assert (result["verdict"], result["reason"]) == ("inconclusive", "matcher-never-met")


# 7. the prompt does not carry the answer
BANNED = (
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


def test_leak_token_list_not_weakened():
    assert set(BANNED) <= set(specify.LEAK_TOKENS)


def test_prompt_no_leak():
    authored = specify.authored_text().lower()
    leaked = [t for t in BANNED if t in authored]
    assert leaked == [], f"authored prompt region leaks: {leaked}"


def test_prompt_keeps_the_whole_cause_domain():
    prompt = specify.build_prompt()
    missing = [c for c in decode.ESTABLISHMENT_CAUSES if c not in prompt]
    assert missing == [], f"cause domain narrowed, missing: {missing}"
    assert len(decode.ESTABLISHMENT_CAUSES) == 16


def test_prompt_contains_the_clause_and_grammar():
    prompt = specify.build_prompt()
    spec = specify.load_spec()
    for paragraph in spec["paragraphs"]:
        assert paragraph in prompt
    assert "distinct(V)" in prompt  # the grammar, a verbatim section, may say it


# 8. the clause text cannot drift silently
def test_spec_pinned():
    spec = specify.load_spec()
    assert specify.spec_sha256(spec) == spec["sha256"]


def test_extract_json_array():
    reply = 'Here you go:\n```json\n[{"id": "X", "s": "a [bracket] in a string"}]\n```\nDone.'
    assert specify.extract_json_array(reply) == [{"id": "X", "s": "a [bracket] in a string"}]


def test_offline_validation_report():
    report = specify.validate_file(ROOT / "fiveg_specifier" / "oracle.json")
    assert report and all(r["ok"] for r in report)
    assert report[0]["authored_by"] == "human"
