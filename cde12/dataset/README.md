# CDE-12 dataset

One row per (system, criterion). The instrument is [`../CDE-12.md`](../CDE-12.md); this is its
output, released as data rather than summarised in prose, because the assembled reading is the
expensive part and re-doing it is waste.

```
python3 validate_dataset.py            # check the rules the machine can check
```

## Schema

| Column | Meaning |
|---|---|
| `system` | Identifier. A repository path, a specification name, or an RFC number |
| `revision` | Commit or specification version, **fixed before reading**. A release tag is not a substitute for a commit |
| `criterion` | `C1_…` through `C12_…`, exactly as named in CDE-12 §5 |
| `verdict` | `supported` · `partial` · `not demonstrated` · `out of scope` · `not tested` |
| `tier` | `T0`–`T4` evidence tier. Empty for `not tested`, which is a claim about the rater |
| `evidence_ref` | File path, section, or URL where the evidence sits |
| `quote` | The supporting text, verbatim. `(absent)` where the finding *is* the absence |
| `rater` | Rater identifier. Not a name — raters are identified so agreement can be computed |
| `date` | When the reading was made |
| `note` | Why this verdict. **Required for `partial`**, where the gap must be named |

## Reading this dataset without misusing it

**Do not sum the columns.** There is no total and no ranking. The systems have different purposes and
a score across these criteria would assert a comparability the instrument does not establish. A row
reading `out of scope` is not a failure; it is a project having drawn its own boundary and said so.

**`not tested` is about us, not about the system.** Four rows currently carry it. They mean the
reading was too shallow to say, and reading them as deficiencies would be a mistake this dataset goes
out of its way to prevent.

**Depth is unequal and visible.** Some systems were read across specification, source and tests;
others at documentation level only. The `tier` column exposes this per cell rather than hiding it
behind a uniform-looking table.

**Five `supported` cells in the current dataset, four of them ours** — and that distribution is a
fact about reading depth, not about quality. See the biases below before drawing any conclusion from
it.

## Capability is not practice — read the two authors' rows together

The dataset carries **two rows for the same project**, and the difference between them is the most
useful thing in it:

| | `supported` | `partial` | `not demonstrated` | `not tested` |
|---|---:|---:|---:|---:|
| `airep` — the **format** | 3 | 5 | 4 | 0 |
| `phionyx-control-plane` — a **deployment** using it | 1 | 5 | 5 | 1 |

Same authors, same week, same instrument. The format can express things the deployment does not
record. C9 is the clearest case: `applied` / `refused` / `no_effect` are distinct values in the
schema and the running control plane emits none of them.

**A schema field is a capability. A record is a practice.** An evaluation that scores only formats
measures what is expressible; one that scores only deployments measures one operator's habits.
Scoring both, and reporting the gap, is what the instrument is for.

This is not hypothetical for us. On 2026-07-26 the delivery-evidence mechanism scored `supported`
as a format while the deployment using it was writing nothing at all, because its evidence sink was
mounted read-only and failing silently. **The format row would have been true and the system would
still have been blind.**

Anyone submitting rows for a system they build should consider doing the same: score what your
format can express and what your deployment actually writes, as separate rows.

## Two biases in the current data, disclosed rather than defended

Found by looking at our own rows after adding them. Both flatter us and neither is fixed by the
instrument's existing safeguards.

### 1. We executed our own system and only read everyone else's

All four of AIREP's `supported` cells sit at **T4** — executed by the rater, output retained. The
single `supported` cell belonging to anyone else sits at **T1**, specification text.

That is not a difference in the systems. It is a difference in access: running our own code costs
nothing and running someone else's costs installation, dependencies and time. **A dataset where the
authors' system is measured at a higher evidence tier than everyone else's is biased in the authors'
favour, and rating ourselves last does not correct it.**

Two honest mitigations, and the second is the real one:

- Read the tier column, not just the verdict. A `supported` at T4 and a `not tested` at no tier are
  claims of very different strength, and several of the latter would likely become `supported` if
  someone with access ran them.
- **Submissions from maintainers fix this properly.** A project scoring itself at T4 lands on the
  same footing we gave ourselves. That is the strongest reason to send rows.

### 2. We score well on exactly what we built the format for

AIREP's three `supported` cells are C7, C8 and C9 — offline verification, delivery acknowledgement
and enforcement outcome. Those are the properties `control_delivery` was designed around.

**A format scoring well on what it was designed for is close to a tautology and should not be read as
a result.** The informative cells are the other nine: AIREP fails C3 where Microsoft's twelve named
runtime-error reasons succeed, and fails C1, C4 and C10 outright.

**C12 was the fourth, and we lost it.** Until CDE-12 v0.2 both of our rows read `supported` on the
negative record — the criterion the instrument exists for. The v0.1 wording asked whether a system
could record *that an instruction did not arrive*, which no single party can observe. Corrected to
measure the non-arrival **observation**, and to require it be classified rather than free-text, both
cells fall to `partial`: `failure.reason` is an unconstrained string. The change moved two cells and
both were ours. See the CDE-12 changelog.

If a future version of this dataset shows us leading on criteria we did *not* design for, that would
mean something. This one does not, and says so.

## Submitting rows

Corrections and additions are wanted, including — especially — from maintainers of the systems
scored here.

**To correct a row about your project.** Open an issue or PR with the row, the evidence reference, and
the quote. If a cell is wrong, saying so with a pointer is enough; the burden of proof is on the
dataset, not on you. Corrections are applied and credited.

**To add a system.** Score every criterion, not a favourable subset — a partial submission is a
selection effect. Use `not tested` freely rather than guessing; it is the honest answer more often
than it looks. Then run `validate_dataset.py`, which catches the rule violations a machine can catch.
It found two in the authors' own first submission.

**Self-rating.** If you are scoring a system you built, say so in the `rater` column and score it
last. The authors' own system is rated under the same constraint.

## What the validator cannot check

Whether a quote actually supports its verdict. Whether a reading was deep enough for the tier it
claims. Whether the rater was honest.

Those need a second rater, which is why CDE-12 §7 requires one for any published application, with
disagreements published rather than reconciled privately. **A disagreement usually means a criterion
is loose — that is information about the instrument, and it is more useful than agreement.**

## Provenance

Every row here was produced by a single rater (`R1`) and **has not been through second-rater
agreement.** Treat it accordingly: it is a first pass, released early so it can be corrected by
people who know these systems better than we do.
