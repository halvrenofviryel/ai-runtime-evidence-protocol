# CDE-12 — Control-Delivery Evidence

An instrument for reporting what a system can and cannot **record** about a control decision and its
fate, and a dataset applying it to ten systems.

It is **not part of the AIREP specification.** It measures record formats and deployments generally,
including AIREP itself, and lives beside `spec/` rather than inside it for that reason: a format
evaluated by criteria defined in its own specification would not be evaluated at all.

## Start here

| | |
|---|---|
| [`CDE-12.md`](./CDE-12.md) | The instrument. Twelve criteria, five verdicts, evidence tiers, ordered decision rules |
| [`dataset/`](./dataset/) | Ten systems scored, one row per (system, criterion), with a validator |
| [`CRITERIA.md`](./CRITERIA.md) | The original pre-registration and its changelog |
| [`PINS.md`](./PINS.md) | The revision each system was read at, fixed before reading |

```
python3 cde12/dataset/validate_dataset.py
```

## The question it asks

Governance systems record that a decision was **made**. Whether the resulting control instruction
**arrived** at the component that enforces it is a different fact — and an instruction correctly
issued, correctly signed and never delivered leaves a record indistinguishable from one nobody sent.

Twelve criteria separate what a record establishes from what a reader has to assume.

## Score your own system

Read `CDE-12.md`, score every criterion, run the validator, open a PR or an issue.

- **Score every criterion**, not a favourable subset — a partial submission is a selection effect.
- Use `not tested` freely. It is a claim about the rater, not about the system, and it is the honest
  answer more often than it looks.
- Scoring a system you built is expected: say so in the `rater` column and score it last. That is the
  constraint the authors applied to themselves.

## What the current data shows about its authors

Two rows describe this project: **AIREP as a format** and **the Phionyx control plane as a
deployment using it**. They score differently — the format expresses things the deployment does not
record. That gap is the instrument's subtlest output and it is disclosed rather than smoothed over,
along with two biases that favour the authors, in [`dataset/README.md`](./dataset/README.md).

Exactly one criterion in the dataset is met by a system whose authors did not write this instrument,
and several of ours are not met at all. If that ever inverts without the reason being visible in the
tiers, the instrument has stopped working.

## Status

**v0.1, single rater, no second-rater agreement yet.** Released early so it can be corrected by
people who know these systems better than we do. Corrections are applied and credited.
