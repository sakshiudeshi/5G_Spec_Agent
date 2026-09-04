---
name: tight-comments
description: Comment style for this repo - keep comments short, about the code as it stands, and never a substitute for a test. Load before writing or editing any comment, docstring, or code-adjacent prose in this repo.
---

# Tight comments

One line unless a second earns its place. Say what the code is, not what it used to be.

## No history

A comment describes the code as it stands now. It never records what changed, what it used
to do, why it was moved, what a previous version got wrong, or what a bug once was. Git holds
that. A reader opening the file today should not have to page through decisions that are
already settled.

Cut these on sight:

- "previously X, now Y", "used to be", "was renamed from", "moved here from"
- "fixed a bug where...", "this used to break when..."
- "note: changed in response to..."
- justifications for a decision already visible in the code

## An invariant is a test, not a comment

Never write a comment to protect an invariant. Assume the reader will break it. Prose does
not stop them; a failing test does.

If you catch yourself writing "don't change this because...", "must stay in sync with...",
"keep this ordering...", or "this has to match..." - stop and write the assertion instead.
If it cannot be tested, it is not an invariant, it is a wish.

```python
# BAD
# These must stay in ASN.1 order - the index is the wire encoding.
ESTABLISHMENT_CAUSES = (...)

# GOOD
ESTABLISHMENT_CAUSES = (...)   # TS 38.331

def test_cause_indices_match_the_wire():
    assert ESTABLISHMENT_CAUSES.index("mt-Access") == 2
```

## No restating the code

If the line below says it, the comment does not. Names and types carry meaning; let them.

```python
# BAD                                    # GOOD
# increment the counter                  (nothing)
n += 1                                   n += 1

# The tests read golden_oracle.json,     # The tests read golden_oracle.json
# never oracle.json, because oracle.json
# is what --persist overwrites, so
# pinning the suite to it would mean a
# live run could turn the tests red.
```

## What is worth a comment

Only what a test cannot say:

- a pointer to the external authority a value comes from - a spec clause, an RFC, a datasheet
- a unit or encoding not visible in the signature
- a genuine non-obvious constraint of the wire format or the domain

Even then: one line.

## Docstrings

One line for what the thing does. Add more only for a real contract - what it returns on
failure, what it raises. No changelog, no rationale essay, no worked example unless the API
is genuinely hard to call.

## Applies to

Comments, docstrings, module headers, and test comments alike. When editing an existing
comment, trim it to this standard rather than extending it.
