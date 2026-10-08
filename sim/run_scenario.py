"""Scenario -> simulated 5G run -> capture -> every oracle -> verdicts checked against ground truth.

A scenario (scenarios/*.json) names the faults to switch on, the workload to drive, and the
spec paragraphs the faulted system violates. An oracle whose `nl_rule` lies in violated text must
return `violate`; every other oracle must not.

    python3 run_scenario.py scenarios/tmsi_reuse_after_paging.json
    python3 run_scenario.py scenarios/baseline.json --oracles ../fiveg_specifier/all_oracles
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPECIFIER = HERE.parent / "fiveg_specifier"
sys.path.insert(0, str(SPECIFIER))

from decode import load_capture  # noqa: E402
from run import OracleError, evaluate, validate_oracle  # noqa: E402
from rls_to_capture import convert  # noqa: E402

GNB = "UERANSIM-gnb-999-70-1"
UE_IP, DN_GW = "10.45.0.2", "10.45.0.1"
DEFAULT_ORACLES = [SPECIFIER / "golden_oracle.json", SPECIFIER / "oracle.json"]
TRACE_FILTER = "(nr-rrc && !nr-rrc.MIB_element && !nr-rrc.SIB1_element) || ngap || icmp"


def log(msg: str) -> None:
    print(msg, flush=True)


def dc(*args: str, env: dict | None = None, check: bool = True) -> str:
    out = subprocess.run(
        ["docker", "compose", *args], cwd=HERE, env={**os.environ, **(env or {})},
        capture_output=True, text=True,
    )
    if check and out.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)}\n{out.stdout}{out.stderr}")
    return out.stdout


# workload


def start(faults: list[str]) -> None:
    dc("down", "--remove-orphans", check=False)
    (HERE / "captures" / "gnb.pcap").unlink(missing_ok=True)
    dc("up", "-d", "--wait", env={"FIVEG_SIM_FAULTS": ",".join(faults)})
    for _ in range(30):
        if "inet " in dc("exec", "-T", "ue", "ip", "-4", "addr", "show", "uesimtun0", check=False):
            return
        time.sleep(1)
    raise RuntimeError("UE never got a PDU session (uesimtun0 has no address)")


def ping(service: str, *args: str) -> bool:
    return " 0% packet loss" in dc("exec", "-T", service, "ping", *args, check=False)


def paging_cycle() -> bool:
    """gNB releases the UE to idle; downlink data then makes the AMF page it."""
    ue_list = dc("exec", "-T", "gnb", "nr-cli", GNB, "-e", "ue-list")
    ue_id = re.search(r"ue-id: (\d+)", ue_list).group(1)
    dc("exec", "-T", "gnb", "nr-cli", GNB, "-e", f"ue-release {ue_id}")
    time.sleep(2)
    ok = ping("core", "-c", "1", "-W", "3", UE_IP)
    time.sleep(1)
    return ok


def run_workload(workload: dict) -> None:
    log(f"  uplink ping over PDU session: {'ok' if ping('ue', '-I', 'uesimtun0', '-c', '2', DN_GW) else 'FAILED'}")
    for i in range(1, workload.get("paging_cycles", 0) + 1):
        log(f"  paging cycle {i}: {'ok' if paging_cycle() else 'FAILED'}")
    time.sleep(1)


# oracles


def load_oracles(paths: list[Path]) -> list[tuple[str, dict]]:
    """Oracle files, lists of oracles, or specify.py run records (their `accepted` oracles)."""
    files = [f for p in paths for f in (sorted(p.glob("*.json")) if p.is_dir() else [p])]
    oracles = []
    for f in files:
        raw = json.loads(f.read_text())
        source = os.path.relpath(f.resolve(), HERE.parent)
        if isinstance(raw, dict) and "accepted" in raw:
            source += f" ({raw.get('model', '?')})"
            raw = raw["accepted"]
        for oracle in raw if isinstance(raw, list) else [raw]:
            oracles.append((source, oracle))
    return oracles


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def expected_verdict(oracle: dict, violated: list[str]) -> str:
    rule = _norm(oracle.get("nl_rule", ""))
    hit = rule and any(rule in _norm(v) or _norm(v) in rule for v in violated)
    return "violate" if hit else "not violate"


def judge(expected: str, got: str) -> bool:
    return got == "violate" if expected == "violate" else got != "violate"


# main


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenario", type=Path)
    ap.add_argument("--oracles", type=Path, nargs="+", default=DEFAULT_ORACLES,
                    help="oracle files or directories (default: golden_oracle.json, oracle.json)")
    ap.add_argument("--no-trace", action="store_true", help="skip the message ladder")
    ap.add_argument("--keep-up", action="store_true", help="leave the stack running afterwards")
    args = ap.parse_args()

    scenario = json.loads(args.scenario.read_text())
    faults = scenario.get("faults", [])
    truth = scenario["ground_truth"]
    paragraphs = json.loads((HERE.parent / truth["spec"]).read_text())["paragraphs"]
    violated = [paragraphs[i] for i in truth["violated_paragraphs"]]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    log(f"== scenario {scenario['id']}: faults {faults or 'none'}")
    start(faults)
    run_workload(scenario.get("workload", {}))
    # The core reads FIVEG_SIM_FAULTS at the first hook it reaches, so this also shows the
    # workload drove the system through the faulted code path.
    core_log = dc("logs", "core", "--no-log-prefix", "--no-color")
    unexercised = [f for f in faults if f"[FAULT] enabled: {f}" not in core_log]
    if unexercised:
        dc("down", check=False)
        sys.exit(f"fault(s) {unexercised} never reached: workload missed the hook, "
                 "or the core image predates the patch (docker compose build core)")

    out_dir = HERE / "runs" / f"{stamp}-{scenario['id']}"
    out_dir.mkdir(parents=True)
    raw_pcap, rrc_pcap = out_dir / "gnb.pcap", out_dir / "rrc.pcap"
    raw_pcap.write_bytes((HERE / "captures" / "gnb.pcap").read_bytes())
    (out_dir / "core.log").write_text(core_log)

    if not args.no_trace:
        log("\n== message trace (air = NR RRC over RLS, N2 = NGAP)")
        fields = dc("exec", "-T", "gnb", "tshark", "-r", "/captures/gnb.pcap",
                    "-o", "nas-5gs.null_decipher:TRUE", "-Y", TRACE_FILTER, "-T", "fields",
                    "-E", "separator=/t", "-e", "frame.time_relative", "-e", "ip.src",
                    "-e", "ip.dst", "-e", "_ws.col.Info", check=False)
        subprocess.run([sys.executable, str(HERE / "trace.py")], input=fields, text=True)

    convert(raw_pcap, rrc_pcap)
    log("\n== RRCSetupRequest records the oracles see")
    for r in load_capture(rrc_pcap):
        log(f"  {r.seq:>4}  {r.id_type or '-':7}  {r.ue_identity_tmsi or '-':39}  {r.establishment_cause}")

    log(f"\n== oracles vs ground truth ({len(violated)} violated rule(s))")
    results, checked, all_ok = [], [], True
    for source, oracle in load_oracles(args.oracles):
        try:
            validate_oracle(oracle)
        except OracleError as exc:
            results.append({"source": source, "id": oracle.get("id"), "error": str(exc)})
            log(f"  SKIP  {oracle.get('id')}: invalid oracle ({exc})")
            continue
        checked.append((source, oracle))
        verdict = evaluate(oracle, load_capture(rrc_pcap))
        expected = expected_verdict(oracle, violated)
        ok = judge(expected, verdict["verdict"])
        all_ok &= ok
        results.append({"source": source, "id": oracle["id"], "expected": expected, "ok": ok, **verdict})
        got = verdict["verdict"] + (f" ({verdict['reason']})" if verdict["reason"] else "")
        log(f"  {'OK  ' if ok else 'FAIL'}  {oracle['id']:<24} expected {expected:<12} got {got:<30} {source}")

    # A violated paragraph no oracle targets leaves the fault undetectable, which is not a pass.
    uncovered = [i for i, text in zip(truth["violated_paragraphs"], violated)
                 if not any(expected_verdict(o, [text]) == "violate" for _, o in checked)]
    for i in uncovered:
        log(f"  NONE  paragraph {i}: no oracle targets it")
    status = "FAIL" if not all_ok else "NO ORACLE" if uncovered else "PASS"

    report = {"scenario": scenario, "run": out_dir.name, "status": status, "ok": all_ok,
              "uncovered_paragraphs": uncovered, "oracles": results}
    (out_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    log(f"\n{status}: run saved to {out_dir.relative_to(HERE)}/")
    if not args.keep_up:
        dc("down", check=False)
    sys.exit({"PASS": 0, "FAIL": 1, "NO ORACLE": 2}[status])


if __name__ == "__main__":
    main()
