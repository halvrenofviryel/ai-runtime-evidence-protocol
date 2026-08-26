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

Every mutation below is stated as a **JSON Pointer (RFC 6901) into the source artifact plus an
exact replacement or addition value**, or as a **deterministic derivation from a literal byte
string**. No row leaves a choice to the builder: two builders applying these rows to the same
baseline produce byte-identical fixtures, signatures included: Ed25519 is deterministic and both the
seed and the preimage are pinned.

**Corpus test-key identities (closed).** Five identities. The binding store shipped with the
corpus resolves exactly the **first four**; `iop-key-untrusted-01` is deliberately absent.

Key material is pinned, not just named, so the fixtures are byte-reproducible end to end. Ed25519
signing is deterministic (RFC 8032), so a fixed seed and a fixed preimage give a fixed signature.

**Seed derivation (normative):** `seed = SHA-256(<key identity as ASCII>)`, taken as the 32-byte
Ed25519 private seed. Both the seed and the resulting public key are pinned below; a builder that
derives a different public key has made an error and must stop.

| Key identity | Wire `subject.producer` token | In binding store | Seed (hex) | Ed25519 public key (hex) |
|---|---|---|---|---|
| `iop-key-decider-01` | `iop-producer-decider` | yes | `08f77d3458b09ccb381bbdc70c6d5b7457c4efcfeb7ae7673af3c391ee125ffe` | `e1030b1c4e4b093dc2db452792f18a0b056d47678ca53d7f7bb99678579446e8` |
| `iop-key-controller-01` | `iop-producer-controller` | yes | `683cfd5742d282207f391471bf7377dc78ac3cab024a3e089f1c81ff1e219ccd` | `616d2d532aa119ee406bb4ed75197ead6db9075ff620ad6e7dd8debc5037d425` |
| `iop-key-executor-01` | `iop-producer-executor` | yes | `a141b597840a2eb005da39cd7df3802c7d1c600fa26ef444d475c3504d9f5d89` | `0f406e8865d87a15e2bfa91714375ded05d60afbebb9568db041b8b6b910dd9a` |
| `iop-key-observer-01` | `iop-producer-observer` | **yes** | `2a36bf2f2f120d13fdbe863b849b481727355e812f396842b86725dd64e2bc2b` | `14d68d08422890e0c78245bf295e9233df552228ffff23a3d56053a510ae8a7f` |
| `iop-key-untrusted-01` | *(never appears on the wire)* | **no** | `6b0f646f140bdec734a3afaf7dd57efdac8a1b8c1a29c2307f47f2b08a3252a2` | `18c9e95426261596dbf096f0f7dc6feb4c69681fb577bdd91f0d262e1e80faef` |

> **TEST KEYS ONLY.** These private seeds are published deliberately so the corpus is
> reproducible. They MUST NOT be used for anything else, ever.

**Binding store requirements (normative).** The `--bindings` file shipped with the corpus MUST
contain a `producer` binding for **all four** resolvable identities above — including
`iop-key-observer-01`. Without the observer binding, a clean Effect cannot reach the Authenticated
surface at all, and the reconciliation-negative fixtures could not be what they claim to be:
individually valid artifacts whose *only* defect is the reconciliation predicate. Each binding
carries `role: "producer"`, `suite: "ed25519"`, `trusted: true`, the pinned `public_key_hex` above,
and a distinct `subject_identity` per identity — except as pinned for `IOP-R-INDEP` below.
`producer_bindings` maps each wire token in column 2 to its binding id.

"Re-seal" below means: recompute `integrity.current` per INTEGRITY §2 over the mutated bytes, then
re-sign per INTEGRITY §3 with the artifact's own key identity from the table above. "Do not
re-seal" means both `integrity.current` and `integrity.signature` are carried over from the source
artifact unchanged.

**Broken-per-family — each breaks exactly one predicate, in a different family, so no two share
a failure mode.**

| ID | Source | Exact mutation | Preserved | Targeted predicate | Level 1 | Clause |
|---|---|---|---|---|---|---|
| `IOP-B-DEC` | `IOP-P-DEC` | at `/claim/assertion`, replace the value with the exact literal `"IOP-B-DEC mutated assertion"`. **Do not re-seal.** | schema shape; `integrity.current` and `integrity.signature` as computed over the *source* bytes | `integrity.current` recomputation (stage 1) | `REJECT` | INTEGRITY §2 |
| `IOP-B-CTL` | `IOP-P-CTL` | add member `"iop_unknown"` with the exact value `true` at `/authority/iop_unknown`. **Re-seal.** | integrity valid over the mutated bytes | schema closure — `/authority` is `additionalProperties: false` (stage 0) | `REJECT` | contract §0/§2; AD-07 |
| `IOP-B-EXE` | `IOP-P-EXE` | re-sign with key identity `iop-key-untrusted-01`, leaving `signature.alg` byte-identical to the source. Do not recompute `integrity.current` — `integrity.signature` is outside the hash preimage (INTEGRITY §2), so it is unchanged and still correct. | schema shape; `integrity.current` correct | record-signature verification (stage 4) | `REJECT` | INTEGRITY §3, §3.2 |
| `IOP-B-EFF` | `IOP-P-EFF` | at `/observer_relationship`, replace the value with the exact literal string `"external"`. **Re-seal.** | integrity valid over the mutated bytes; every other member unchanged | accepted-family schema validation — `/observer_relationship` is a closed enum of `same_executor` / `independent` / `unknown` (stage 0) | `REJECT` | `effect.schema.json` `/observer_relationship`; contract §3 stage 0 |

`IOP-B-CTL` and `IOP-B-EFF` deliberately re-seal: without that the fixture would fail at integrity
and never reach its targeted predicate, which is the single-target rule in §2.2.

**Why `IOP-B-EFF` targets the schema and not chain linkage.** An earlier draft of this contract
broke `integrity.previous` and named "chain linkage" as the predicate. That predicate is **not on
the reference verifier surface**: the frozen class-verifier contract's evaluation order (§3,
stages 0–11) contains no predecessor resolution and no `previous`-to-`current` equality gate, and
§8 places reference resolution explicitly out of scope. `integrity.previous` is inside the hash
preimage (INTEGRITY §2 rule 1), so a re-sealed artifact carrying a wrong `previous` is
*internally* valid and both reference lanes would return `ACCEPT` — making the scenario
unmeasurable under the "both reference verifiers cover all 12" commitment in §2. The v0.1
conformance verifier does perform sequence linkage (`spec/airep/v0.1/conformance/verify.py`), which
is where the assumption came from; it is a v0.1 property, not a v0.2 one. INTEGRITY §5 was also
miscited: §5 binds `airep_version` and `artifact_type`, not chain position.

**Reconciliation-negative — all three are internally valid. Hash and signature are correct and
sealed with corpus-owned test keys, and the bundle is built with correct chain linkage (a
construction property; per the note above, no v0.2 reference verifier measures it). Only the
reconciliation predicate is broken.**

| ID | Source | Exact mutation | Preserved | Targeted predicate | Level 1 | Clause |
|---|---|---|---|---|---|---|
| `IOP-R-TOCTOU` | `IOP-R-CLEAN` | at the Execution's `/executed_action_digest`, set the value to `"sha256:" || lowercase-hex(SHA-256(B))` where `B` is the exact UTF-8 bytes of `IOP-R-TOCTOU divergent action payload` with no trailing newline. The Control's `/authorized_action_digest` is unchanged. **Re-seal the Execution.** | **all four artifacts individually valid and correctly sealed**; chain intact | authorized-vs-executed digest equality | `RECONCILIATION_MISMATCH` | AD-03; AD-06 |
| `IOP-R-XREF` | `IOP-R-CLEAN` | at the Effect's **`/decision_ref/record_id`**, set the value to the exact literal `"iop-absent-decision-0000"`, which is the `record_id` of no artifact in the bundle. `/decision_ref` stays an object and `/decision_ref/chain_id`, if present, is left unchanged. **Re-seal the Effect.** | **all artifacts individually valid and correctly sealed** | cross-artifact reference resolution | `RECONCILIATION_MISMATCH` | AD-03 |
| `IOP-R-INDEP` | `IOP-R-CLEAN` | leave `/observer_relationship` at `"independent"`; set the Effect's **`/subject/producer`** to the exact literal `"iop-producer-executor"` (the Execution's wire token, replacing `"iop-producer-observer"`); **re-seal the Effect under `iop-key-executor-01`**. Both changes are required — see the note below. | **all artifacts individually valid and correctly sealed**; the wire label is present and well-formed | independence condition for an `independent` claim | `INDEPENDENCE_NOT_ESTABLISHED` | CONFORMANCE_CLASS_DESIGN §7 (AD-03 scoping); AD-09 |

**Why `IOP-R-XREF` targets `/decision_ref/record_id` and not `/decision_ref`.** `decision_ref` is
`common.schema.json` `$defs/artifact_ref` — an **object** with `additionalProperties: false` and a
required `record_id`. Replacing the whole member with a bare string is a stage-0 type failure, so
the fixture would be rejected as malformed and cross-reference reconciliation would never be
reached. The mutation has to leave a *well-formed* reference that simply resolves to nothing.

**Why `IOP-R-INDEP` moves the producer token as well as the key.** Producer binding resolution
(stage 2) looks the artifact up in `producer_bindings` by the exact string `subject.producer`, and
stage 4 verifies the record signature under the **binding-derived** key. Re-signing with the
executor key while leaving `subject.producer` as the observer token would resolve the *observer*
binding, verify an executor signature against the *observer* public key, and fail at stage 4 as
`authenticated_failures` — a signature failure, not an independence failure, and stage 8 would
never run because it requires an accepted producer binding.

Moving the token as well makes both artifacts resolve to the **same** binding, so each is
**independently Authenticated** and the only thing left broken is the independence condition: the
Effect claims `independent` while sharing the referenced Execution's identity *and* key. That is
the targeted predicate, reached for the right reason. For this fixture the binding store's
`subject_identity` for the executor binding is shared by both artifacts by construction — which is
precisely the "same identity" condition §1.2/§3 tests.

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

**`REJECT` is a verdict about the artifact, not about the process.** A scenario counts as `REJECT`
when the lane reaches a definitive negative determination on the targeted predicate — including
when the lane completes normally and leaves the artifact at a lower tier. Under the frozen class
contract an Authenticated-tier definitive failure (for example `IOP-B-EXE`: an accepted producer
binding with an invalid record signature) yields a **completed verdict, `class = AIREP-Core`, and
a populated `authenticated_failures` channel**. That is a `REJECT` for Level-1 purposes. It is
**not** required to be a parse-level or process-level rejection, and a non-zero process exit is
neither required nor sufficient. The distinction between *withheld* and *failure* in the frozen
contract §4 is what separates a `REJECT` from an inconclusive result: a **withheld** channel is
never a `REJECT`.

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
