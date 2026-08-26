# AIREP v0.2 — Interop corpus contract (W1)

> **Status: DRAFT for maintainer review. No corpus bytes exist.** This contract fixes the
> scenario set, lane roles, expected-outcome model, provenance rules and run-preservation
> mechanics *before* any fixture is generated. Corpus bytes remain on hold until it is accepted.
>
> Governed by [`PARTICIPATION_CONTRACT.md`](./PARTICIPATION_CONTRACT.md), including ruling
> AD15-IR-1 and the requirement that a participant lane's qualifying outcomes come from
> participant-authored logic rather than from either reference verifier or a wrapper around one.

## 1. Scenario set — 12 mandatory

| ID | Group | Scenario |
|---|---|---|
| `IOP-P-DEC` | positive baseline | clean Decision artifact |
| `IOP-P-CTL` | positive baseline | clean Control artifact |
| `IOP-P-EXE` | positive baseline | clean Execution artifact |
| `IOP-P-EFF` | positive baseline | clean Effect artifact |
| `IOP-B-DEC` | broken | deliberately broken Decision |
| `IOP-B-CTL` | broken | deliberately broken Control |
| `IOP-B-EXE` | broken | deliberately broken Execution |
| `IOP-B-EFF` | broken | deliberately broken Effect |
| `IOP-R-CLEAN` | reconciliation | clean Decision → Control → Execution → Effect path |
| `IOP-R-TOCTOU` | reconciliation | authorized-vs-executed action digest mismatch |
| `IOP-R-XREF` | reconciliation | broken / unresolved cross-artifact reference |
| `IOP-R-INDEP` | reconciliation | Effect asserting `independent` where the authentication/independence condition is not met |

Optional stress vectors may be added later; they are never a precondition for qualifying.

## 2. Lanes — both lanes cover all 12

All three evaluation surfaces evaluate **every** scenario. A split corpus would leave a scenario
measured on one side only, and invites the objection that a given broken case was never actually
run by the external implementation. AD-15's "passes under both reference verifiers **and** the
independent implementation" reads most defensibly as the same surface measured by all three.

**Covering all 12 does not mean the participant does twice the work.** Generation and evaluation
are separate roles, and the participant producer is never asked to emit invalid or dishonest
artifacts:

| Scenario group | Participant producer | Participant evaluation path | Python ref | Node ref |
|---|---|---|---|---|
| 4 positive family baselines | **generate** | evaluate all 4 | evaluate all 4 | evaluate all 4 |
| 4 broken-per-family | no invalid generation required | **reject/detect all 4** | reject/detect all 4 | reject/detect all 4 |
| `IOP-R-CLEAN` | **generate the four-artifact path** | reconcile PASS | reconcile PASS | reconcile PASS |
| `IOP-R-TOCTOU` | no malformed generation required | detect mismatch | detect | detect |
| `IOP-R-XREF` | no malformed generation required | detect unresolved/broken reference | detect | detect |
| `IOP-R-INDEP` | no dishonest generation required | withhold/downgrade independence as specified | same semantic result | same semantic result |

So the producer carries **five generation obligations** — four family baselines plus the clean
linked path — while the evaluation path must produce a machine-observable result on all twelve.

Negative and reconciliation-negative vectors are supplied by the shared corpus, or derived from
participant-generated positives by deterministic transformations defined in this contract, so
that a participant never has to build a dishonest emitter to be measured on dishonest input.

## 3. Expected outcomes — two levels

Requiring a participant to emit this project's exact reason codes would bind the independent
implementation to our verifier's API, which is the opposite of what AD-15 is for. Each scenario
therefore carries expectations at two levels:

**Level 1 — normative semantic expectation.** Vocabulary-neutral, and the only level that
qualifies:

`ACCEPT` · `REJECT` · `RECONCILIATION_MISMATCH` · `INDEPENDENCE_NOT_ESTABLISHED`

**Level 2 — lane-native evidence.** For the Python and Node reference lanes: the exact verdict,
class and reason sets already pinned by the class-verifier contract. For the participant lane:
**their own raw result format**, whatever it is.

A **neutral reconciliation layer** then measures whether each lane's raw result satisfies the
scenario's Level-1 expectation. Emitting our reason strings is explicitly **not** a qualification
requirement. A participant may map their outcomes to the Level-1 vocabulary; they need not adopt
our internal vocabulary to do so.

The mapping from a participant's raw results to Level 1 is declared by the participant and
recorded before the official run, so it cannot be adjusted after seeing the outcome.

## 4. Provenance rules

Carried from the participation contract and applying to every corpus artifact:

- expected values are **derived from cited normative clauses without executing any
  implementation** — an expectation computed by running code makes the test measure agreement
  with that code rather than with the specification;
- fixtures are built deterministically; two builds produce byte-identical output;
- a manifest records every file digest plus an aggregate, under a rule that names its sort key;
- the participant's code-provenance manifest (D3) is recorded alongside the run.

## 5. Run preservation

The distinction that made our own parity history usable, carried to third-party work:

| Phase | Status |
|---|---|
| **Exploratory** | Private, **not evidence**. A participant may run, fail and iterate freely. If they stop here, no named failure is published. |
| **Official** | Entered by explicit participant opt-in, with publication and identity terms agreed first. |

Once official:

- the **first raw run is immutable**, whether it passes or fails;
- a remediation run **never overwrites** it — Run 1 and Run 2 are kept separately, exactly as
  the class-verifier parity runs were;
- if a participant stops after an official run, the result is preserved and reported
  **INCOMPLETE / NON-QUALIFYING**, never as a "failed third-party implementation";
- a divergence is closed by ruling where the specification is ambiguous, and neither
  implementation governs until that ruling exists.

## 6. What a clean run would and would not establish

**Would:** an external producer exists; the same 12-scenario surface was evaluated by three
independent evaluation paths; the participant's qualifying outcomes came from participant-authored
logic; negative cases were rejected rather than merely absent.

**Would not:** semantic correctness of the protocol; third-party audit or certification;
completeness of the scenario set beyond its 12 mandatory members; truth of any real-world
evidence; nor, on its own, satisfaction of AD-15 — clauses (3) for SCITT (AD-10) and AuthZEN
(AD-11) are separate workstreams W2 and W3.

## 7. Open for maintainer decision

1. Whether the deterministic transformations that derive negative vectors from participant
   positives are specified here or in the corpus builder, given the builder is ours and the
   transformation must not encode our verifier's assumptions.
2. Whether the participant's Level-1 mapping is reviewed by the maintainer before the official
   run — reviewing it risks steering the implementation; not reviewing it risks a mapping that
   quietly redefines a scenario.
