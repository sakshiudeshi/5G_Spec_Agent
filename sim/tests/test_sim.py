import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

import run_scenario
from decode import load_capture
from rls_to_capture import RLS_PORT, convert

SIM = Path(__file__).resolve().parents[1]
FAULTS = SIM / "open5gs" / "faults"
SCENARIOS = sorted((SIM / "scenarios").glob("*.json"))
E2E = os.environ.get("FIVEG_SIM_E2E") == "1"


def _scenario(path: Path) -> dict:
    return json.loads(path.read_text())


def _patch(name: str) -> str:
    return (FAULTS / f"{name}.patch").read_text()


# scenarios and fault patches


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_scenario_shape(path):
    s = _scenario(path)
    assert set(s) == {"id", "description", "culprit", "fault", "workload", "ground_truth"}
    fault = s["fault"]
    assert fault is None or (set(fault) <= {"name", "params"} and "name" in fault)
    paragraphs = json.loads((SIM.parent / s["ground_truth"]["spec"]).read_text())["paragraphs"]
    assert all(0 <= i < len(paragraphs) for i in s["ground_truth"]["violated_paragraphs"])


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_a_fault_scenario_violates_something_and_a_clean_one_nothing(path):
    s = _scenario(path)
    assert bool(s["fault"]) == bool(s["ground_truth"]["violated_paragraphs"])
    assert bool(s["fault"]) == bool(s["culprit"])


@pytest.mark.parametrize("path", [p for p in SCENARIOS if _scenario(p)["fault"]], ids=lambda p: p.stem)
def test_scenario_fault_has_a_patch_that_reads_its_params(path):
    fault = _scenario(path)["fault"]
    patch = _patch(fault["name"])
    for param in fault.get("params", {}):
        assert f'getenv("FIVEG_FAULT_{param.upper()}")' in patch


@pytest.mark.parametrize("patch", sorted(FAULTS.glob("*.patch")), ids=lambda p: p.stem)
def test_patch_logs_its_fault_marker(patch):
    # run_scenario refuses a run whose core log lacks this line.
    assert f'"[FAULT] {patch.stem}' in patch.read_text()


@pytest.mark.parametrize("patch", sorted(FAULTS.glob("*.patch")), ids=lambda p: p.stem)
def test_patch_is_self_contained(patch):
    text = patch.read_text()
    assert "/dev/null" not in text, "patches edit stock files; no shared new sources"
    other = {p.stem for p in FAULTS.glob("*.patch")} - {patch.stem}
    assert not any(name in text for name in other)


@pytest.mark.parametrize("patch", sorted(FAULTS.glob("*.patch")), ids=lambda p: p.stem)
def test_every_patch_has_a_scenario(patch):
    names = {(_scenario(p)["fault"] or {}).get("name") for p in SCENARIOS}
    assert patch.stem in names


# verdict logic


@pytest.mark.parametrize("all_ok, uncovered, status", [
    (True, [], "PASS"),
    (True, [7], "NO ORACLE"),
    (False, [], "FAIL"),
    (False, [7], "FAIL"),
])
def test_overall_status(all_ok, uncovered, status):
    assert run_scenario.overall_status(all_ok, uncovered) == status
    assert run_scenario.EXIT_CODES[status] == {"PASS": 0, "FAIL": 1, "NO ORACLE": 2}[status]


def test_uncovered_paragraphs():
    truth = {"violated_paragraphs": [3, 7]}
    violated = ["The AMF shall send a new 5G-GUTI.", "5G-TMSI generation should be unpredictable."]
    oracle = {"nl_rule": "The AMF shall send a new 5G-GUTI."}
    assert run_scenario.uncovered_paragraphs([oracle], truth, violated) == [7]
    assert run_scenario.uncovered_paragraphs([], truth, violated) == [3, 7]


# runner plumbing, docker mocked


class Recorder:
    def __init__(self, logs=""):
        self.calls, self.logs = [], logs

    def dc(self, *args, env=None, check=True):
        env_file = (env or {}).get("FAULT_ENV_FILE")
        self.calls.append((args, env, Path(env_file).read_text() if env_file else None))
        return {"logs": self.logs, "exec": "inet 10.45.0.2/16"}.get(args[0], "")


def test_start_passes_params_as_env_and_the_image_tag(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(run_scenario, "dc", rec.dc)
    monkeypatch.setattr(run_scenario, "HERE", Path("/nonexistent"))
    run_scenario.start("amf.guti.sequential_tmsi", {"run_length": 3})
    (args, env, env_text), = [c for c in rec.calls if c[0][0] == "up"]
    assert env["CORE_TAG"] == "amf.guti.sequential_tmsi"
    assert env_text == "FIVEG_FAULT_RUN_LENGTH=3\n"


def test_build_core_applies_one_patch_or_none(monkeypatch):
    seen = []
    monkeypatch.setattr(run_scenario.subprocess, "run",
                        lambda cmd, **kw: seen.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""))
    assert run_scenario.build_core(None) == "stock"
    assert run_scenario.build_core("amf.x") == "amf.x"
    stock, faulted = seen
    assert "stock" in stock and not any(a.startswith("FAULT=") for a in stock)
    assert ["--target", "faulted", "--build-arg", "FAULT=amf.x"] == faulted[4:8]
    assert faulted[faulted.index("-t") + 1] == "fiveg-sim/open5gs:amf.x"


def _main(monkeypatch, scenario, status="PASS", keep_up=False, raises=None):
    rec, removed = Recorder(), []

    def fake_run(*a, **kw):
        if raises:
            raise raises
        return status

    monkeypatch.setattr(run_scenario, "dc", rec.dc)
    monkeypatch.setattr(run_scenario, "build_core", lambda name: name or "stock")
    monkeypatch.setattr(run_scenario, "run", fake_run)
    monkeypatch.setattr(run_scenario.subprocess, "run",
                        lambda cmd, **kw: removed.append(cmd[-1]) if cmd[1:3] == ["image", "rm"] else None)
    monkeypatch.setattr("sys.argv", ["run_scenario.py", str(SIM / "scenarios" / scenario)]
                        + (["--keep-up"] if keep_up else []))
    with pytest.raises(SystemExit) as exc:
        run_scenario.main()
    return exc.value.code, removed, [c[0][0] for c in rec.calls]


@pytest.mark.parametrize("status", ["PASS", "FAIL", "NO ORACLE"])
def test_fault_image_is_removed_after_the_run(monkeypatch, status):
    code, removed, dc_calls = _main(monkeypatch, "tmsi_sequential_allocation.json", status)
    assert code == run_scenario.EXIT_CODES[status]
    assert removed == ["fiveg-sim/open5gs:amf.guti.sequential_tmsi"]
    assert dc_calls == ["down"]


def test_fault_image_is_removed_when_the_run_aborts(monkeypatch):
    code, removed, _ = _main(monkeypatch, "tmsi_reuse_after_paging.json", raises=SystemExit("boom"))
    assert code == "boom"
    assert removed == ["fiveg-sim/open5gs:amf.paging.skip_guti_realloc"]


def test_stock_image_is_kept(monkeypatch):
    _, removed, dc_calls = _main(monkeypatch, "baseline.json")
    assert removed == [] and dc_calls == ["down"]


def test_keep_up_keeps_stack_and_image(monkeypatch):
    _, removed, dc_calls = _main(monkeypatch, "tmsi_sequential_allocation.json", keep_up=True)
    assert removed == [] and dc_calls == []


def test_run_refuses_a_fault_the_workload_never_reached(monkeypatch):
    rec = Recorder(logs="core up\n")
    monkeypatch.setattr(run_scenario, "dc", rec.dc)
    monkeypatch.setattr(run_scenario, "start", lambda *a: None)
    monkeypatch.setattr(run_scenario, "run_workload", lambda w: None)
    with pytest.raises(SystemExit, match="amf.x never reached"):
        run_scenario.run(None, {"workload": {}}, "amf.x", "amf.x", {}, [], {}, "t")


# capture conversion


def _rrc_setup_request(tmsi39: str, cause: int) -> bytes:
    # UL-CCCH c1.rrcSetupRequest: ue-Identity ng-5G-S-TMSI-Part1, establishmentCause, spare (TS 38.331)
    bits = "0" + "00" + "0" + tmsi39 + format(cause, "04b") + "0"
    return int(bits, 2).to_bytes(6, "big")


def _rls_pcap(path: Path, rrc: bytes, channel: int = 5) -> None:
    rls = (bytes([0x03, 3, 2, 1, 6]) + bytes(8) + bytes([1]) + bytes(4)
           + struct.pack("!II", channel, len(rrc)) + rrc)
    udp = struct.pack("!HHHH", 1234, RLS_PORT, 8 + len(rls), 0) + rls
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([10, 100, 200, 30]), bytes([10, 100, 200, 20])) + udp
    frame = bytes(12) + b"\x08\x00" + ip
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


def test_rls_rrc_setup_request_reaches_the_oracle_decoder(tmp_path):
    tmsi = "000000011000000000000000000010101111001"
    _rls_pcap(tmp_path / "gnb.pcap", _rrc_setup_request(tmsi, cause=2))
    written = convert(tmp_path / "gnb.pcap", tmp_path / "rrc.pcap")
    assert [name for _, name, _ in written] == ["UL-CCCH"]
    (record,) = load_capture(tmp_path / "rrc.pcap")
    assert (record.id_type, record.ue_identity_tmsi, record.establishment_cause) == ("tmsi", tmsi, "mt-Access")


def test_non_rls_traffic_is_dropped(tmp_path):
    _rls_pcap(tmp_path / "gnb.pcap", b"", channel=5)
    data = bytearray((tmp_path / "gnb.pcap").read_bytes())
    struct.pack_into("!H", data, 24 + 16 + 14 + 20 + 2, 38412)
    (tmp_path / "gnb.pcap").write_bytes(bytes(data))
    assert convert(tmp_path / "gnb.pcap", tmp_path / "rrc.pcap") == []


# amf.guti.sequential_tmsi generator, compiled from the patch


_STUB = """
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#define ogs_assert assert
#define ogs_min(x, y) (((x) < (y)) ? (x) : (y))
#define ogs_random32() ((uint32_t)rand())
#define ogs_warn(...) (printf(__VA_ARGS__), printf("\\n"))
typedef uint32_t amf_m_tmsi_t;
static struct { int size; amf_m_tmsi_t *array; } m_tmsi_pool;
"""

_MAIN = """
int main(void) {
    m_tmsi_pool.size = 2048;
    m_tmsi_pool.array = calloc(2048, sizeof(amf_m_tmsi_t));
    m_tmsi_sequential_runs_generate();
    for (int i = 0; i < 2048; i++) printf("%u\\n", m_tmsi_pool.array[i]);
}
"""


@pytest.fixture(scope="module")
def generator(tmp_path_factory):
    if not shutil.which("cc"):
        pytest.skip("no C compiler")
    added = "\n".join(l[1:] for l in _patch("amf.guti.sequential_tmsi").splitlines()
                      if l.startswith("+") and not l.startswith("+++"))
    body = re.search(r"static void m_tmsi_sequential_runs_generate\(void\)\n\{.*?\n\}\n", added, re.S)
    d = tmp_path_factory.mktemp("gen")
    (d / "gen.c").write_text(_STUB + body.group(0) + _MAIN)
    subprocess.run(["cc", "-o", str(d / "gen"), str(d / "gen.c")], check=True)

    def run(run_length=None):
        env = {k: v for k, v in os.environ.items() if k != "FIVEG_FAULT_RUN_LENGTH"}
        if run_length is not None:
            env["FIVEG_FAULT_RUN_LENGTH"] = run_length
        out = subprocess.run([str(d / "gen")], env=env, capture_output=True, text=True, check=True)
        marker, *ids = out.stdout.splitlines()
        return marker, [int(i) for i in ids]
    return run


def _runs(ids):
    runs = [[ids[0]]]
    for prev, cur in zip(ids, ids[1:]):
        runs[-1].append(cur) if cur == prev + 1 else runs.append([cur])
    return runs


@pytest.mark.parametrize("run_length, expected", [(None, 100), ("3", 3), ("0", 100), ("junk", 100)])
def test_generator_reads_run_length(generator, run_length, expected):
    marker, ids = generator(run_length)
    assert marker == f"[FAULT] amf.guti.sequential_tmsi: M-TMSI pool in runs of {expected}"
    assert sorted(ids) == list(range(1, 2049))
    # Each run starts on a run boundary; adjacent shuffled runs may merge into a longer one.
    for run in _runs(ids):
        assert (run[0] - 1) % expected == 0
        assert len(run) % expected == 0 or run[-1] == 2048


# end to end, needs docker: FIVEG_SIM_E2E=1 pytest sim/tests


@pytest.mark.skipif(not E2E, reason="set FIVEG_SIM_E2E=1 to run scenarios in docker")
@pytest.mark.parametrize("scenario, code", [
    ("baseline.json", 0),
    ("tmsi_reuse_after_paging.json", 0),
    ("tmsi_sequential_allocation.json", 2),
])
def test_scenario_end_to_end(scenario, code):
    out = subprocess.run(["python3", "run_scenario.py", f"scenarios/{scenario}", "--no-trace"],
                         cwd=SIM, capture_output=True, text=True)
    assert out.returncode == code, out.stdout + out.stderr
    fault = (_scenario(SIM / "scenarios" / scenario)["fault"] or {}).get("name")
    images = subprocess.run(["docker", "image", "ls", "-q", f"fiveg-sim/open5gs:{fault}"],
                            capture_output=True, text=True).stdout
    assert not fault or images.strip() == ""
