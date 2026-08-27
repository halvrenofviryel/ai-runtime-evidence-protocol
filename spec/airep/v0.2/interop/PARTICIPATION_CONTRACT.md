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

### Ruling AD15-IR-1 — what a qualifying external implementation is

AD-15 clause (2) asks the corpus to pass "under both reference verifiers **and the independent
implementation**". A producer is not normally a verifier of foreign artifacts, so that phrase
had no operational meaning. It is closed here, before any participant is approached:

> **A qualifying external implementation = an external producer *plus* a participant-owned
> evaluation/reproduction path.**

- an independent **verifier alone does not** satisfy clause (1);
- an external **producer** satisfies clause (1);
- the **participant-owned evaluation path inside that producer package** is what makes clause
  (2)'s "passes under … the independent implementation" operational.

The evaluation path need **not** be a complete, general-purpose third class verifier. It must be
able to run the corpus assertions assigned to the participant lane, machine-observably.

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
| D3 | A **code-provenance manifest** (see below) | Distinguishes "read the specification" from "reused the implementation" in a way that is actually auditable |
| D4 | A **participant-owned evaluation path** meeting the minimum sufficiency below, and its results | Operationalises AD-15 clause (2); an implementer who can emit but never check has not exercised the protocol |
| D5 | Every divergence found, including ones they believe are their own bugs | The divergences a participant suppresses are the most informative ones |

#### D3 — code-provenance manifest

Recording which files a person *read* is a browsing diary, not provenance, and cannot be
audited. What is auditable is what ended up **inside** the producer. The manifest states:

- the base: `v0.2.0-alpha.1` and its DOI;
- **AIREP executable/source code copied, ported or adapted into the producer: must be `none`**;
- normative schemas and test fixtures copied unchanged: **permitted**, listed if used;
- the reference verifiers **and the two reference interop evaluators** invoked as an external
  process or test oracle: **permitted**; imported, vendored, ported or adapted into the producer
  or into the participant's own qualifying evaluation path: **not permitted**
  (`AD15-IR-2`, `INTEROP_REFERENCE_EVALUATOR_CONTRACT.md` §9). Reading them is permitted;
  reusing them means our reconciliation logic gets measured twice rather than two
  implementations once;
- general-purpose JCS, Ed25519 and JSON-Schema libraries: **permitted**, with dependency and
  version recorded.

Specifically excluded from the producer: this project's `jcs.py`, its verifier hash/preimage
helpers, and any AIREP-specific verification logic. **Reading is free; reuse of AIREP-specific
implementation is not.**

#### D4 — minimum sufficiency of the evaluation path

Not "however partial". The path must, at minimum:

- run the participant lane of the shared corpus;
- **generate** the positive cases assigned to it;
- **demonstrate the expected rejection/failure outcome** on the negative cases assigned to it.

**Independence of the qualifying outcome (normative).** D3 permits invoking the reference
verifiers as an external process or test oracle. Without the following restriction, a
participant could satisfy D4 with a thin wrapper around those verifiers — and the project would
then claim the corpus "passed under the independent implementation" when the independent
evaluation was in fact our own code:

> **For AD-15 qualification, the participant-owned evaluation path MUST NOT derive its
> qualifying pass/fail outcomes solely from either AIREP reference verifier or from any wrapper
> around them. Reference verifiers may be invoked separately as diagnostic or cross-check
> oracles, but their outputs do not constitute the participant lane's qualifying result. The
> participant lane's qualifying assertions must be computed by participant-authored logic
> independent of the reference-verifier implementation code.**

A participant evaluation path need not implement the full AIREP class-verifier surface; it only
needs independent participant-authored logic sufficient to evaluate the assertions assigned to
the participant lane.

It need not cover the reference lane.

D5 is not a formality. Our own first official parity run **failed**, and preserving that
failure is why the later passing run means anything. A participant who reports only successes
gives us less evidence than one who reports failures.

## 4. The shared interop corpus

Not yet built; it is the next work package after this contract is accepted. Per AD-15 it must
include AD-03 reconciliation cases and **at least one deliberately broken case per artifact
type**, so that a participant's implementation is shown capable of rejecting, not only of
accepting.

**Size: 12 mandatory scenarios for the first round.** C1's 60 cases are the right depth for
same-project work and the wrong barrier for a first external participant. The mandatory core is:

| Group | Count | Scenarios |
|---|---|---|
| Positive family baseline | 4 | one each: Decision, Control, Execution, Effect |
| Deliberately broken | 4 | one per artifact family |
| Reconciliation (AD-03) | 4 | clean Decision→Control→Execution→Effect path; authorized-vs-executed action digest mismatch; broken/unresolved cross-artifact reference; an Effect claiming `independent` where the authentication/independence condition is not met |

This meets AD-15's floor directly — broken-per-type and AD-03 reconciliation are both named in
it — while keeping the cost of participation low. Further stress vectors are an **optional
extension**, never a precondition for qualifying.

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
- a participant evaluation path whose qualifying outcomes come from the reference verifiers or a wrapper around them, rather than from participant-authored logic;
- informal agreement that "it interoperates" without the corpus results behind it.

## 6. What the maintainer commits to

Specification defects found by a participant are **specification defects**, closed by ruling and
recorded — not closed by asking the participant to match our implementation. Where our
implementation and the specification disagree, the specification governs.

**If the specification is ambiguous, neither implementation governs until the ambiguity is
resolved by an explicit ruling.** "The specification governs" applies where the specification is
determinate; it must not be used to settle a case where the text admits two reasonable readings.
Our own R-1 and R-10 were exactly that situation, and both were closed by ruling rather than by
declaring one implementation correct.

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

## 8. Decided (maintainer, 2026-08-26)

**Participant sourcing — targeted recruitment *and* a public call.** Not an open call alone:
approach 3–5 real candidates directly, and open a public participation call once this contract
and the corpus are ready. A qualifying participant works under **their own** public
repository/account/organisation. An implementation under another account belonging to the
maintainer, or one the maintainer effectively directs, does **not** count as independent.

**Reciprocity — review yes, implementation help bounded.** Before the first official
measurement the maintainer may answer specification questions, issue public clarifications or
rulings, and explain corpus usage — but may **not** supply code patches, pair-program, or hand
over an implementation recipe. Remediation review is available after the first raw run is
preserved. Acknowledgement is natural; **co-authorship is not promised in advance** and is
decided separately, later, only if there is genuine scholarly contribution. Paying a participant
does not by itself break independence but **must be disclosed**; the maintainer writing the code
or directing the implementation does break it.

**Abandonment — two-phase, opt-in before anything becomes evidence.**

| Phase | Status of the work |
|---|---|
| Exploratory | Private, non-evidence. If the participant stops, **no named failure is published.** |
| Official measurement | Entered by explicit participant opt-in. From then the raw run is immutable evidence. |

If a participant stops after an official run, the result is preserved and reported as
**INCOMPLETE / NON-QUALIFYING** — never presented as a "failed third-party implementation".
Publication and identity terms are agreed before the official phase begins, not after. This
keeps failure preservation intact without making recruitment punitive.

**SCITT and AuthZEN — run in parallel, not after.** There is no technical reason to wait: AD-15
requires them independently of the external producer, and serialising them lengthens the path to
stable for nothing. Three workstreams share the `v0.2.0-alpha.1` target but keep separate
branches, worktrees and evidence:

| | Workstream |
|---|---|
| **W1** | External producer / interop corpus |
| **W2** | SCITT PoC — seal → register → receipt → subsequent anchor |
| **W3** | AuthZEN E2E — external authorization decision → digest/reference → AIREP Decision/Control evidence |
