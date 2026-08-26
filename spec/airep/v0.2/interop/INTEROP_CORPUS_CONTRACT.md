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

Negative and reconciliation-negative vectors are supplied by the shared corpus, or derived by
deterministic transformations **defined in this contract**, so that a participant never has to
build a dishonest emitter to be measured on dishonest input.

### 2.1 Where transformations are defined

Transformations are specified **here, not in the builder**. The builder applies this contract
mechanically and carries no expected-outcome or verifier-semantic knowledge; otherwise the
corpus would encode our verifier's assumptions and then measure implementations against them.

Each transformation states, at minimum:

`source scenario` → `exact mutation` → `preserved fields` → `targeted predicate` →
`Level-1 expectation` → `normative clause`

### 2.2 Causal isolation — single target per fixture (normative)

**Reconciliation-negative fixtures MUST NOT be produced by field-mutating a participant's signed
positive artifact.** Mutating a sealed artifact invalidates its hash or signature, so evaluation
stops at integrity long before it reaches the reconciliation predicate — and the fixture then
measures integrity failure while claiming to measure reconciliation.

`IOP-R-TOCTOU`, `IOP-R-XREF` and `IOP-R-INDEP` are therefore **shared fixtures whose internal
integrity and cryptography are valid**, with only the targeted reconciliation predicate broken.
Corpus-owned test keys are used so such fixtures can be sealed correctly.

> **Single-target rule.** A fixture MUST NOT create an independent failure that would be reached
> before its targeted failure. The only exception is a fixture whose target *is* integrity.

This applies to the four broken-per-family cases too: each targets one predicate, and its
Level-1 expectation is only meaningful if nothing else fails first.

### 2.3 The transformations (normative)

Each row is the complete specification the builder applies. The builder adds nothing.

**Broken-per-family — each breaks exactly one predicate, in a different family, so no two share
a failure mode.**

| ID | Source | Exact mutation | Preserved | Targeted predicate | Level 1 | Clause |
|---|---|---|---|---|---|---|
| `IOP-B-DEC` | `IOP-P-DEC` | flip one byte of a hashed member **after** `integrity.current` is computed | schema shape; signature over the *original* preimage | `integrity.current` recomputation | `REJECT` | INTEGRITY §2 |
| `IOP-B-CTL` | `IOP-P-CTL` | add one unknown member to a closed sub-object | hash and signature recomputed over the mutated bytes, so integrity is **valid** | schema closure | `REJECT` | contract §0/§2; AD-07 |
| `IOP-B-EXE` | `IOP-P-EXE` | re-sign with a key not in the trust store, leaving the suite label unchanged | schema shape; `integrity.current` correct | record-signature verification | `REJECT` | INTEGRITY §3, §3.2 |
| `IOP-B-EFF` | `IOP-P-EFF` | set `integrity.previous` to a digest that is not the predecessor's `current` | own hash and signature valid | chain linkage | `REJECT` | INTEGRITY §2, §5 |

`IOP-B-CTL` deliberately recomputes hash and signature over the mutated bytes: without that the
fixture would fail at integrity and never reach the closure predicate, which is the single-target
rule in §2.2.

**Reconciliation-negative — all three are internally valid. Hash, signature and chain linkage are
correct and sealed with corpus-owned test keys; only the reconciliation predicate is broken.**

| ID | Source | Exact mutation | Preserved | Targeted predicate | Level 1 | Clause |
|---|---|---|---|---|---|---|
| `IOP-R-TOCTOU` | `IOP-R-CLEAN` | build the Execution over a different action payload, so `executed_action_digest` ≠ the Control's `authorized_action_digest` | **all four artifacts individually valid and correctly sealed**; chain intact | authorized-vs-executed digest equality | `RECONCILIATION_MISMATCH` | AD-03; AD-06 |
| `IOP-R-XREF` | `IOP-R-CLEAN` | point the Effect's `decision_ref` at a `record_id` absent from the bundle | **all artifacts individually valid and correctly sealed** | cross-artifact reference resolution | `RECONCILIATION_MISMATCH` | AD-03 |
| `IOP-R-INDEP` | `IOP-R-CLEAN` | Effect asserts `observer_relationship: independent` while the referenced Execution's producer binding is the **same identity/key** as the Effect's | **all artifacts individually valid and correctly sealed**; the wire label is present and well-formed | independence condition for an `independent` claim | `INDEPENDENCE_NOT_ESTABLISHED` | CONFORMANCE_CLASS_DESIGN §7 (AD-03 scoping); AD-09 |

The `IOP-R-*` rows are the reason §2.2 exists. Each is a *semantically* broken bundle made of
*cryptographically sound* artifacts — which is the only way the reconciliation predicate is ever
reached.

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

### 3.1 Mapping review — bounded, and frozen before the run

The mapping from a participant's raw results to Level 1 is declared by the participant and
**reviewed by the maintainer before the official run**, strictly as an *outcome mapping*:

| Reviewed for | Not reviewed for |
|---|---|
| completeness — every scenario has a mapping | anything about how the producer or evaluator is built |
| non-circularity — the mapping does not read our reason codes to decide | implementation quality, structure or approach |
| semantic correspondence — each scenario's mapping matches its Level-1 meaning | whether their result "looks right" |

The maintainer gives **no producer or evaluator implementation advice** during this review; that
would be the steering the participation contract forbids before the first official measurement.

The accepted mapping's **bytes and digest are frozen before the first official run**. This closes
both failure modes at once: a mapping adjusted after seeing the outcome, and a review that
quietly becomes implementation guidance.

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
evaluation paths, **including one externally authored participant path — the two reference paths
remain same-project evidence**; the participant's qualifying outcomes came from participant-authored
logic; negative cases were rejected rather than merely absent.

**Would not:** semantic correctness of the protocol; third-party audit or certification;
completeness of the scenario set beyond its 12 mandatory members; truth of any real-world
evidence; nor, on its own, satisfaction of AD-15 — clauses (3) for SCITT (AD-10) and AuthZEN
(AD-11) are separate workstreams W2 and W3.

## 7. Decided

Both questions previously open here are closed and folded into the sections above:

- **where transformations are defined** — in this contract (§2.1–§2.3), never in the builder, so
  the corpus cannot encode our verifier's assumptions;
- **whether the participant's Level-1 mapping is reviewed** — yes, bounded to completeness,
  non-circularity and semantic correspondence, with no implementation advice, and frozen by
  digest before the first official run (§3.1).
