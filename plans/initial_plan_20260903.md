# `5g_specifier` — a minimal DSL for 5G-GUTI reuse oracles

## Context

`guti_reuse_report/` documents that StarHub reuses the 5G-TMSI after paging-triggered
reconnections — a hard **3GPP TS 33.501 §6.12.3 violation**. We want that finding to be
**mechanically re-derivable**: give an LLM the clause text and a grammar, get back a small
declarative JSON object, run it over a capture with deterministic code, get `pass` / `violate`.

This is a **proof of concept**: one oracle, one page of grammar, ~350 lines. 

**This plan is self-contained.** Everything needed is written below. 

### Verified during planning

Numbers below were produced by reading the capture files directly and are the acceptance targets.

| capture | matched `mt-Access` | distinct | repeats | verdict |
|---|---|---|---|---|
| `starhub-xiaomi11-ntu-sutd.pcap` | 205 | 21 | 184 | **violate** (first repeat seq 217 → 252, +42.238 s) |
| `singtel-xiaomi11-ntu.txt` | 93 | 93 | 0 | **pass** |

Singtel under `mo-Data`: 32 requests, 21 distinct, **11 repeats** — reuse that §6.12.3 NOTE 1
explicitly permits. So the `establishment_cause` matcher key is load-bearing: remove it and the
oracle falsely accuses the compliant network. **That contrast pair is the deliverable.**

---

## Rules for the implementer

1. **Run no code except `pytest`.** No decoder runs, no runner runs, no ad-hoc scripts, no REPL
   checks. Correctness is demonstrated by tests over the real capture files, nothing else.
2. **Make no live LLM call.** `specify.py --live` must be *implemented*, never *executed*. Default
   behaviour (no `--live`) is offline: re-validate the checked-in oracle and exit.
3. Everything ships in one new folder, `5g_specifier/`, plus a one-line `pytest.ini` edit.

---

## The DSL

An **oracle** is one flat JSON object — the RTSP oracle's shape, with `predicate` extended from a
per-message comparison to a relation folded over a matched *sequence*, because GUTI reuse is not
visible in any single message.

```json
{
  "id": "NR-GUTI-01",
  "nl_rule": "Upon receiving Service Request message sent by the UE in response to a Paging message, the AMF shall send a new 5G-GUTI to the UE.",
  "spec_anchor": "3GPP TS 33.501 clause 6.12.3",
  "matcher":   { "message_is": "rrc_setup_request", "establishment_cause": "mt-Access" },
  "observe":   { "tmsi": "ue_identity_tmsi" },
  "predicate": "distinct(tmsi)",
  "witness_pass":    ["<39-bit string A>", "<39-bit string B>"],
  "witness_violate": ["<39-bit string A>", "<39-bit string A>"]
}
```

Three **closed vocabularies** — the model composes from fixed lists and cannot invent a name:

1. **`matcher` keys** (AND-ed; an omitted key means "don't care")
   - `message_is` ∈ {`rrc_setup_request`}
   - `id_type` ∈ {`tmsi`, `random`}
   - `establishment_cause` ∈ the 16 TS 38.331 values, ASN.1 order:
     `emergency`, `highPriorityAccess`, `mt-Access`, `mo-Signalling`, `mo-Data`, `mo-VoiceCall`,
     `mo-VideoCall`, `mo-SMS`, `mps-PriorityAccess`, `mcs-PriorityAccess`,
     `spare6`…`spare1`
2. **`observe` primitives** — `ue_identity_tmsi` (39-char binary string), `establishment_cause`
   (string), `id_type` (string). Bound to names the predicate uses.
3. **`predicate` forms** — exactly three, matched by **regex, no parser**:
   - `distinct(V)` — V never repeats across matched messages
   - `constant(V)` — V never changes across matched messages
   - `V == "literal"` — holds on every matched message

**Verdicts** (3): `pass`, `violate`, `inconclusive`, plus a `reason` string
(`matcher-never-met`, `under-observed:1`, `undecodable-pdu`). Fewer than two observations is
`inconclusive`, never `pass` — with one value both relations are trivially true, and `pass` would be
agreement that was never tested. `violate` is irrevocable, so every verdict is decided by a finite
prefix of the capture.

**Two error axes.** The byte axis is *total*: a truncated or non-6-octet PDU yields `None` fields,
never an exception, so undecidable input becomes `inconclusive` and never a false `violate`. The
authoring axis fails *loudly*: an unknown `observe` primitive or `matcher` key raises. An invented
name is a broken oracle, not an ambiguous capture — and silently ignoring a misspelled matcher key
would widen the oracle to all traffic and fire on a compliant network.

---

## Leakage control

§6.12.3 obliges the **AMF** to *send* a new GUTI — downlink. The captures are uplink RRC only. The
bridge from obligation to observable is:

> The 5G-S-TMSI a UE presents in `RRCSetupRequest` is the one the network last assigned it. Had a
> new GUTI been delivered, the next request would carry a different value. `establishmentCause =
> mt-Access` is the uplink marker of "responding to a Paging message".

**This hypothesis must not appear in the prompt.** The split the prompt builder enforces:

- **Permitted — the instrument's datasheet.** Record shape, field names, and the *complete*
  16-value cause domain in ASN.1 order, unannotated. Describing what the sensor can see is not
  telling the model the answer.
- **Prohibited — the answer.** Singling out `mt-Access`; the words *paging*, *reuse*, *repeat*,
  *distinct*, *relink*, *track*, *GUTI reuse*, *violation*, *StarHub*, *Singtel*, *non-compliance*;
  any pointer to which clause sentence to use.

Enforced mechanically by `test_prompt_no_leak.py`: render the prompt, assert it contains no banned
token (case-insensitive), and assert every one of the 16 cause values appears — so the domain cannot
be quietly narrowed to the answer. Discipline is not the control; the test is.

**Expected outcome, recorded not hidden.** A leak-free prompt may return `[]`, or an oracle with the
wrong matcher. That is a measurement, which is why every run is archived (below). `oracle.json`
therefore holds a **human-authored** oracle by default; `specify.py` never overwrites it silently —
`--persist` is required, and the run record says whether the oracle came from a model or a human.

---

## Files

```
5g_specifier/
  DSL.md                      the one-page grammar above — the artefact pasted to the LLM
  spec/33501_6_12_3.json      pinned verbatim clause text
  decode.py       ~110 lines  capture file -> [Record]
  run.py          ~90  lines  oracle + capture -> verdict, reason, evidence
  specify.py      ~80  lines  prompt build; offline validate; --live OpenRouter call
  _env.py         ~20  lines  read .env into os.environ, no dependency
  oracle.json                 the current oracle (human-authored to start)
  all_oracles/                one JSON per specify.py run, never overwritten
  tests/test_5g_specifier.py  ~90 lines
```

`pytest.ini`: change `testpaths` to `5g_specifier/tests`.

### `spec/33501_6_12_3.json`

Hand-transcribe §6.12.3 from `guti_reuse_report/3gpp-ts-33.501.pdf` (the clause is titled
"Subscription temporary identifier"). Shape:

```json
{ "id": "33501-6.12.3", "title": "6.12.3 Subscription temporary identifier",
  "source_file": "guti_reuse_report/3gpp-ts-33.501.pdf",
  "sha256": "<of the joined paragraphs>",
  "paragraphs": ["…", "…"] }
```

Whitespace-normalised only; elide the page-break "ETSI" footer and running header, alter nothing
else. The obligations to capture include the initial/mobility-registration sentence, the
periodic-registration *should*, the Service-Request-after-Paging *shall* with its
"before the connection is released or suspended" refinement, the RRC-resume equivalent, NOTE 1,
NOTE 2, and the "unpredictable identifier generation" sentence. A test pins the `sha256` so the text
cannot drift silently; eyeball it once against the PDF.

### `decode.py`

Both capture formats collapse to one record type, so `run.py` never sees a pcap:

```python
@dataclass(frozen=True)
class Record:
    seq: int; ts: float
    message_is: str | None           # "rrc_setup_request"
    id_type: str | None              # "tmsi" | "random"
    ue_identity_tmsi: str | None     # 39-char binary string
    establishment_cause: str | None  # TS 38.331 name
```

**pcap adapter** — verified against the StarHub file:

- Classic little-endian pcap, magic `0xa1b2c3d4` (also accept `0xa1b23c4d`, nanosecond),
  **linktype 101 = raw IP** — records are bare IP datagrams, no Ethernet header.
- Keep IPv4/UDP. The payload of interest starts with the ASCII magic `rlc-nr` (Wireshark's
  RLC-NR UDP framing).
- After the 6-byte magic come two bytes (`rlcMode`, `snLength`), then tag/value pairs:
  `0x02` direction (1 byte), `0x03` ueid (2 bytes), `0x04` bearerType (1 byte),
  `0x05` bearerId (1 byte), `0x01` payload-to-end-of-packet.
- Keep frames with `direction == 0` (uplink) **and** `bearerType == 1` (CCCH). Their payload is the
  UL-CCCH PDU.

**txt adapter** — verified against the Singtel SCAT log: find a line containing
`rrcSetupRequest(Up)`; the timestamp is the text before the first `;`; the **next** line is
`          HEX: 0x…` and its hex is the PDU. Sequence numbers are 1-based over matches.

**UL-CCCH decode** — exactly 6 octets, constant bit offsets, no ASN.1 library and no tshark:

```
bits 0-2    "000"  = c1.rrcSetupRequest       (anything else -> message_is = None)
bit  3      0 = ng-5G-S-TMSI-Part1 ("tmsi"), 1 = randomValue ("random")
bits 4-42   the 39-bit identity, as a binary string
bits 43-46  establishmentCause, index into the 16-name tuple
bit  47     spare
```

A payload that is not exactly 6 octets yields a record with all decoded fields `None`.

CLI: `python 5g_specifier/decode.py --capture <path>` prints per-cause counts. (Written, not run —
its output is asserted by tests instead.)

> **Naming constraint.** `5g_specifier` starts with a digit, so it is not a legal Python module
> name — `import 5g_specifier` and `python -m 5g_specifier.decode` are syntax errors. Keep the
> folder name as asked, but make the files **flat scripts, not a package**: no `__init__.py`, plain
> `import decode` / `import run` between them, invoked as `python 5g_specifier/run.py …`.
> `tests/conftest.py` puts `5g_specifier/` on `sys.path` so the tests import them the same way.

### `run.py`

```
load oracle -> validate against the three closed vocabularies and the three predicate forms
filter records by matcher -> observe -> fold the relation -> verdict, reason, evidence
```

Evidence on `violate`: matched count, distinct count, repeat count, and the first repeat as
`(value, first_seq, first_ts, repeat_seq, repeat_ts, gap_s)`.

### `specify.py`

- `build_prompt()` → `DSL.md` + the pinned clause paragraphs + the instrument datasheet +
  *"return a JSON array of oracle objects; return `[]` for any sentence you cannot express in this
  grammar."* Must pass the no-leak test.
- Offline (default): validate `oracle.json` against the vocabularies, run its own
  `witness_pass` / `witness_violate` through `run.py`'s fold, print the result, exit. No network.
- `--live`: `OpenAI(api_key=os.environ["OPENROUTER_API_KEY"],
  base_url="https://openrouter.ai/api/v1")`, `temperature=0`, model from `SPECIFIER_MODEL`
  (default `anthropic/claude-sonnet-5`) — matching the keys already in `.env`. Pull the first
  balanced JSON array out of the reply by bracket-depth scan, ignoring any prose around it.
- **Every `--live` run writes** `all_oracles/<UTC-ISO-timestamp>-<uuid4>.json`, never overwriting:

  ```json
  { "run_id": "<uuid4>", "utc": "...", "provider": "openrouter", "model": "...",
    "prompt_sha256": "...", "spec_anchor": "33501-6.12.3", "raw_reply": "...",
    "candidates": [ ... ], "validation": [ {"id": "...", "ok": true, "witness_verdicts": [...]} ],
    "accepted": [ ... ] }
  ```
- `--persist` (requires `--live`) additionally copies the accepted oracles to `oracle.json`.
  Without it `oracle.json` is untouched.

### `_env.py`

Read `./.env` line by line; skip blanks and `#` comments; split on the first `=`; strip a trailing
`# comment`, whitespace and surrounding quotes; `os.environ.setdefault`. No `python-dotenv`.

---

## Tests — the only thing that runs

use the venv I have created using `uv venv`

`.venv/bin/python -m pytest`

1. **pcap decode** over `guti_reuse_report/report_data/starhub-xiaomi11-ntu-sutd.pcap`:
   612 uplink-CCCH frames, 593 `rrc_setup_request` + `tmsi`, causes
   `mo-Data` 352 / `mt-Access` 205 / `mo-Signalling` 36.
2. **txt decode** over `guti_reuse_report/report_data/singtel-xiaomi11-ntu.txt`:
   126 `rrc_setup_request` + `tmsi`, causes `mt-Access` 93 / `mo-Data` 32 / `mo-Signalling` 1.
3. **Golden verdicts** — StarHub → `violate`, matched 205, distinct 21, repeats 184, first repeat
   value `101010111000000101111111010110011011111` at seq 217 → 252.
   Singtel → `pass`, matched 93, distinct 93.
4. **The matcher key is load-bearing** — take the oracle, delete
   `"establishment_cause": "mt-Access"`, run against Singtel, assert it flips to `violate`. This is
   the test that proves the oracle discriminates rather than always firing.
5. **Witness round-trip** — `witness_pass` → `pass`, `witness_violate` → `violate`.
6. **Validator rejects** an unknown `observe` primitive, an unknown `matcher` key, and a predicate
   outside the three forms — each raises, not `inconclusive`.
7. **`test_prompt_no_leak`** — rendered prompt contains no banned token; contains all 16 cause names.
8. **`test_spec_pinned`** — `sha256` of the joined clause paragraphs matches the stored value.

## Deliberately out of scope

Singtel's static-bit / counter-bit predictability. It is a *should* (§6.12.3's final sentence, and
NIST CSWP 36C), needs a justified threshold, and does not reduce to `distinct` / `constant`. Adding
`static_bits(V) <= N` later is one more predicate form; the closed-vocabulary design leaves room.
