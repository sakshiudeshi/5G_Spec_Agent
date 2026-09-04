# Oracle DSL v1

An **oracle** is one flat JSON object. It names a normative sentence, says which messages it
is about, says what to look at in those messages, and states a relation that must hold over
the whole matched sequence.

```json
{
  "id": "SHORT-ID-01",
  "nl_rule": "the single normative sentence, quoted",
  "spec_anchor": "3GPP TS 33.501 clause X.YY.Z",
  "matcher":   { "message_is": "rrc_setup_request", "id_type": "tmsi" },
  "observe":   { "v": "ue_identity_tmsi" },
  "predicate": "distinct(v)",
  "witness_pass":    ["...", "..."],
  "witness_violate": ["...", "..."]
}
```

## Fields

| field | meaning |
|---|---|
| `id` | short identifier you choose |
| `nl_rule` | the one sentence of specification text this oracle encodes, quoted verbatim |
| `spec_anchor` | where that sentence lives |
| `matcher` | which records this oracle applies to; keys are AND-ed; an omitted key means "don't care" |
| `observe` | binds names to observation primitives; the predicate may only use names bound here |
| `predicate` | the relation that must hold over the matched sequence, in order |
| `witness_pass` | a short list of observed values that must yield `pass` |
| `witness_violate` | a short list of observed values that must yield `violate` |

## Closed vocabularies

You may only compose from these lists. A name that is not on a list is a broken oracle, not a
new feature; the validator rejects it.

### 1. `matcher` keys

- `message_is` — one of: `rrc_setup_request`
- `id_type` — one of: `tmsi`, `random`
- `establishment_cause` — one of: `emergency`, `highPriorityAccess`, `mt-Access`,
  `mo-Signalling`, `mo-Data`, `mo-VoiceCall`, `mo-VideoCall`, `mo-SMS`, `mps-PriorityAccess`,
  `mcs-PriorityAccess`, `spare6`, `spare5`, `spare4`, `spare3`, `spare2`, `spare1`

### 2. `observe` primitives

- `ue_identity_tmsi` — the UE identity carried in the record, as a 39-character binary string
- `establishment_cause` — the establishment cause of the record, as a string
- `id_type` — the identity type of the record, as a string

### 3. `predicate` forms

Exactly three forms. `V` is a name bound in `observe`.

- `distinct(V)` — the value of `V` never recurs across the matched sequence
- `constant(V)` — the value of `V` never changes across the matched sequence
- `V == "literal"` — the value of `V` equals the given literal on every matched record

## Verdicts

- `pass` — the relation held over at least two observations
- `violate` — the relation was broken; irrevocable, decided by a finite prefix of the capture
- `inconclusive` — nothing was decided, with a `reason`:
  - `matcher-never-met` — no record matched
  - `under-observed:N` — fewer than two observations (N of them); with one value every
    relation is trivially true, so this is never reported as `pass`
  - `undecodable-pdu` — a matched record carried no value for an observed primitive

## Leakage control

Clause 6.12.3 obliges the AMF to *send* a new 5G-GUTI — downlink. The captures are uplink RRC
only. The bridge from that obligation to something observable is the finding under test, so it
must not appear in the prompt.

`specify.py` splits the prompt in two:

- **Verbatim** — the grammar above and the pinned clause paragraphs. These are the inputs. The
  clause necessarily contains its own vocabulary; quoting it is not a hint.
- **Authored** — the instrument datasheet and the task instructions. This is prose we write,
  and it is where a hint would hide. `authored_text()` returns exactly this region.

The datasheet gives the complete 16-value establishment-cause domain in ASN.1 order,
unannotated. Describing what the instrument can see is not telling the model the answer;
singling out one value would be.

Three tests hold this: `test_prompt_no_leak` (no banned token in the authored region),
`test_leak_token_list_not_weakened` (the banned list cannot be quietly shortened), and
`test_prompt_keeps_the_whole_cause_domain` (all 16 values survive in the rendered prompt).

A leak-free prompt may return `[]`, or an oracle with the wrong matcher. That is a
measurement, not a failure, which is why every `--live` run is archived to `all_oracles/` and
`oracle.json` is overwritten only under `--persist`.
