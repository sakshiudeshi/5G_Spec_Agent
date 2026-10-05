# Simulated 5G SA environment

Open5GS 5G core + UERANSIM gNB and UE in Docker, captured at the gNB, and piped into
`fiveg_specifier/run.py` unchanged. arm64 and amd64: both images build from source/PPA.

```
 UE (nr-ue)  --RLS/UDP 4997-->  gNB (nr-gnb)  --NGAP/SCTP 38412-->  core (Open5GS AMF, SMF, UPF, ...)
 10.100.200.30  "air"            10.100.200.20   --GTP-U/UDP 2152-->  10.100.200.10     mongo .5
                                   tcpdump -> captures/gnb.pcap
```

## Running a scenario

```sh
python3 run_scenario.py scenarios/baseline.json                   # first run builds images (~15 min)
python3 run_scenario.py scenarios/tmsi_reuse_after_paging.json
python3 run_scenario.py scenarios/tmsi_reuse_after_paging.json \
    --oracles ../fiveg_specifier/golden_oracle.json ../fiveg_specifier/all_oracles
```

A scenario (`scenarios/*.json`) is a fault list, a workload, and ground truth: the spec
paragraphs the faulted system violates. The runner starts a fresh stack with those faults, drives
the workload (register, ping, then `paging_cycles` x: gNB releases the UE, core pings it, AMF
pages), and runs every oracle over the capture. An oracle whose `nl_rule` lies in a violated
paragraph must return `violate`; every other oracle must not. Exit code 1 on any mismatch.

`--oracles` takes oracle files, lists of oracles, or `specify.py` run records (their `accepted`
oracles), so model-written oracles go straight from `all_oracles/` into a scenario.

Each run lands in `runs/<utc>-<scenario>/`: `gnb.pcap`, `rrc.pcap` (oracle input), `core.log`,
`report.json`.

## Faults

Open5GS is built from source at v2.8.0 with `open5gs/fault-hooks.patch`. The patch adds
`src/amf/fault.{c,h}` and one call site per fault. The core reads the comma-separated
`FIVEG_SIM_FAULTS` (set by the runner from the scenario) when it first reaches a hook; with it
unset, the core is stock Open5GS. The runner refuses a run whose faults never logged
`[FAULT] enabled`, i.e. the workload never reached the hook.

| fault | effect | violates |
|---|---|---|
| `amf.paging.skip_guti_realloc` | no Configuration Update Command with a new 5G-GUTI after a paging-triggered Service Request | TS 33.501 6.12.3 para 4, TS 24.501 5.3.3 c |

Adding one: define the name in `fault.h`, guard the behaviour with `amf_fault_active(...)`,
regenerate the patch from an Open5GS checkout (`git diff v2.8.0 > sim/open5gs/fault-hooks.patch`),
`docker compose build core`, then write a scenario.

## How the capture reaches the oracle

UERANSIM has no PHY/MAC/RLC. Its air interface is RLS: UDP datagrams carrying one UPER RRC PDU
plus its logical channel. The UL-CCCH RRCSetupRequest is the same 6-octet encoding a real UE
sends, so `rls_to_capture.py` re-frames each RRC PDU as rlc-nr over UDP (the format
`decode.read_pcap` already reads) and nothing in `fiveg_specifier/` changes.

`runs/*/gnb.pcap` opens in Wireshark with UERANSIM's `tools/rls-wireshark-dissector.lua`
(the gNB image has it installed for tshark). NAS is readable because Open5GS picks NEA0.

## Caveats

- A fault's ground truth is the scenario author's claim, not something the runner checks:
  it only checks that the hook ran.
- The UE container has IPv6 disabled: router solicitations on `uesimtun0` otherwise wake the
  idle UE as `mo-Data` before the page arrives.
- Captures are clean by construction: one UE, no loss, no ciphering of NAS.

## Files

| path | what |
|---|---|
| `docker-compose.yml` | mongo, core, gnb, ue on 10.100.200.0/24 |
| `docker/` | image builds; `open5gs-entrypoint.sh` moves NGAP/GTP-U off loopback |
| `open5gs/fault-hooks.patch` | the AMF fault hooks, applied at image build |
| `config/` | gNB and UE configs, subscriber seed for mongo |
| `scenarios/` | faults + workload + ground truth |
| `run_scenario.py` | scenario -> run -> oracle verdicts vs ground truth |
| `trace.py` | tshark fields -> ladder |
| `rls_to_capture.py` | gNB pcap -> oracle-ready pcap |
