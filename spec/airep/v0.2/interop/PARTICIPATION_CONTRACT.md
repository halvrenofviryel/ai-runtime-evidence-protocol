# AIREP v0.2 — External interoperability participation contract

> **Status: DRAFT for maintainer review.** Nothing here is normative yet, and no external party
> has been approached. This document exists so that "independent implementation" means a
> specific, checkable thing before anyone starts work, rather than being argued about
> afterwards.

## 1. Why this document exists

[AD-15](../../v0.2-design/ARCHITECTURE_DECISIONS.md) withholds the word *stable* from v0.2
until three things are observed: a producer implementation **not written by this repository's
maintainers**; the cross-implementation corpus passing under that implementation as well as
both reference verifiers; and the SCITT (AD-10) and AuthZEN (AD-11) cases exercised end to end.
AD-15 closes with the sentence that governs this whole document: *absence of prior failure is
not capability evidence; the gate demands observed results.*

Everything the project has measured so far is **same-project** evidence. Two verifiers were
authored separately, compared by a separately written comparator, and reproduced from a clean
checkout — but all of it inside one repository under one maintainer. That is a real property
and it is not independence. This contract is about obtaining the thing it is not.

## 2. What a participant implements

**A producer.** The participant writes software that *emits* AIREP v0.2 artifacts. This is the
half of the protocol with no implementation anywhere today — both existing implementations are
verifiers. A second verifier is welcome but does **not** satisfy AD-15 clause (1).

The producer must cover all four artifact families (decision, control, execution, effect),
because AD-03 reconciliation cannot be exercised from a subset.

**Independently, and starting from a fixed point.** Work begins from the tagged, archived
release — `v0.2.0-alpha.1`, DOI [10.5281/zenodo.22101986](https://doi.org/10.5281/zenodo.22101986)
— not from a moving `main`. The participant may read this project's specification, schemas and
reference verifiers; that is what a public specification is for. What they must not do is
reuse this project's implementation code inside their producer, because a producer assembled
from our verifier's helpers would be measuring our code against itself.

## 3. What the participant delivers

| # | Deliverable | Why it is required |
|---|---|---|
| D1 | The producer implementation, with its dependency and runtime basis pinned | Without a pinned basis, a later failure to reproduce cannot be attributed |
| D2 | Artifacts it emits for the shared interop corpus, all four families | The measurement surface |
| D3 | A statement of what was read and what was reused, at file granularity | Distinguishes "read the spec" from "reused the implementation" |
| D4 | Their own verification or reproduction path, however partial, and its results | An implementer who can only emit but never check has not exercised the protocol |
| D5 | Every divergence found, including ones they believe are their own bugs | The divergences a participant suppresses are the most informative ones |

D5 is not a formality. Our own first official parity run **failed**, and preserving that
failure is why the later passing run means anything. A participant who reports only successes
gives us less evidence than one who reports failures.

## 4. The shared interop corpus

Not yet built; it is the next work package after this contract is accepted. Per AD-15 it must
include AD-03 reconciliation cases and **at least one deliberately broken case per artifact
type**, so that a participant's implementation is shown capable of rejecting, not only of
accepting.

Expected values will be derived from cited normative clauses without executing any
implementation, as the C1 corpus was — otherwise the corpus measures agreement with our code
rather than agreement with the specification.

## 5. What counts toward AD-15, and what does not

**Counts:**

- a producer written outside this project that emits conformant artifacts across all four families;
- that producer's output passing the shared interop corpus under both reference verifiers **and** under the participant's own checking path;
- SCITT seal → register → receipt → subsequent-anchor exercised end to end at least once (AD-10);
- an AuthZEN authorization decision bound to AIREP Control/Decision evidence, end to end (AD-11);
- a documented reconciliation when implementations disagree — including the case where **we** turn out to be wrong.

**Does not count:**

- another verifier, however independent — clause (1) is specifically about a producer;
- an implementation that vendors or ports this project's verifier code;
- a passing run with no negative cases, since a checker never shown to fail is not evidence;
- our own re-measurement of a participant's artifacts as a substitute for their own checking path;
- informal agreement that "it interoperates" without the corpus results behind it.

## 6. What the maintainer commits to

Specification defects found by a participant are **specification defects**, closed by ruling and
recorded — not closed by asking the participant to match our implementation. Where our
implementation and the specification disagree, the specification governs.

Divergence outputs are preserved as measured, and no expected value is adjusted to make a
disagreement disappear. Where a participant's reading is defensible and ours was ambiguous, the
ambiguity is the finding.

## 7. Boundary of any resulting claim

Satisfying this contract would let the project state that an independent producer exists and
that cross-implementation interoperability has been observed on a defined corpus.

It would **not** establish semantic correctness of the protocol, third-party audit or
certification, the truth or completeness of any real-world evidence an AIREP record refers to,
or fitness for any regulatory purpose. Those remain outside what this project measures, and the
language for them stays outside its documentation.

## 8. Open questions for the maintainer

1. **Participant sourcing.** Approaching individuals versus publishing an open call — this
   affects whether the corpus must be self-explanatory to a stranger.
2. **Corpus size.** AD-15 sets a floor, not a target. C1's 60 cases took a full phase; an
   interop corpus that large may deter participation.
3. **Reciprocity.** Whether the project offers review or co-authorship, and how that interacts
   with the independence being claimed.
4. **Failure disposition.** If a participant starts and abandons, whether partial results are
   published — publishing them is more honest and may discourage participation.
5. **Sequencing.** Whether SCITT and AuthZEN proceed in parallel with producer recruitment, or
   after, given they are maintainer-side work that does not depend on a participant.
