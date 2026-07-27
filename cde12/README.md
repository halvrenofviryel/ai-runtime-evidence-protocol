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
| [`CRITERIA.md`](./CRITERIA.md) | The original protocol, retained as the historical artifact, and its changelog |
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

## Cite the instrument

If you **apply these criteria** to a system, cite the instrument. It is versioned separately from the
data, because criteria and measurements are corrected on different schedules and for different
reasons.

> Abak, A. T. (2026). *CDE-12 — Control-Delivery Evidence* (Version 0.2).

Machine-readable metadata: [`CITATION.cff`](./CITATION.cff).

## Cite the dataset

If you **use, correct or extend the measurements**, cite the dataset instead. A reader who took a
number from a cell is relying on the reading, not on the criteria.

> Abak, A. T. (2026). *CDE-12 dataset — control-delivery evidence across ten systems* (Version 0.1).

Machine-readable metadata: [`dataset/CITATION.cff`](./dataset/CITATION.cff).

## Status

**Instrument v0.2. Dataset v0.1, single rater, no second-rater agreement yet.** Released early so it
can be corrected by people who know these systems better than we do. Corrections are applied and
credited.

**v0.2 corrected the criterion this instrument exists for, and the correction cost us both of our own
`supported` cells on it.** C12 as first written asked whether a system can record *that an expected
instruction did not arrive*. No single party can observe that: a receiver cannot know what it never
received, and an issuer's silence is indistinguishable from a lost acknowledgement. C12 now measures
the non-arrival **observation** and requires it to be classified rather than free-text. Exactly two
cells moved, both ours, both downward. No other cell moved — a stricter criterion cannot promote
anything. The reasoning is in the [changelog](./CDE-12.md#10-changelog).
