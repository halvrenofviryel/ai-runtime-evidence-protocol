# AIREP × EMILIA — proposed mapping contract
## Revision 0.3 · post-EMILIA case review · 10 September 2026

**Status: PROPOSED / NOT FROZEN / NOT RUN.**

This revision incorporates Iman Schrock's EMILIA-side review of the five-case sheet. It is binding only as a **proposed experiment contract pending mutual confirmation**. It does not change AIREP, EMILIA, the five-case scope, or the reviewed `AIREP_EMILIA_INTEROP_CASE_SHEET_v0.2.md`.

### Fixed references

- AIREP: `v0.2.0-beta.1`, commit `8a6c01ecce457aa94330c0ed7219e4c56ebfe771`
- EMILIA repository snapshot reviewed by Iman: commit `b1275b08f91939a2330aee26a03d0a6bfda375d6`
- Reviewed case sheet: `AIREP_EMILIA_INTEROP_CASE_SHEET_v0.2.md`
- Original contributed fixture: `freeze-after-provider-entry-with-multiple-required-targets`
- Original fixture SHA-256: `2d8faa1b64b8a73fd0bf81b21889bbf726cbfb324af099b700499627af84203a`

The EMILIA commit above is the reviewed source pin for these mapping decisions. It is **not yet a mutually approved frozen experiment baseline**. Iman explicitly characterized his response as EMILIA-side case review, not freeze approval or an interoperability result.

---

## 1. Experiment-binding decisions incorporated from EMILIA review

These are experiment-level mapping rules, not new protocol requirements.

### M-01 — Preserve original parent and target identity

For Case 1:

1. Keep the original parent operation/instruction identity intact.
2. Keep both required targets, EP-A and EP-B, intact.
3. Evidence confirming EP-A MUST NOT establish EP-B.
4. One confirmed target out of two MUST NOT establish parent completion.
5. A separate per-target obligation ledger MAY be used to preserve the source facts.
6. That ledger MUST NOT be presented as target coverage computed by stock AIREP `reconcile()`.
7. The adapter MUST NOT create synthetic target-specific instruction identities merely to make AIREP core appear to have native per-target reconciliation.
8. AIREP's stock `receiver_receipt=SATISFIED` result for a Decision+instruction group is scoped only to the admitted records in that group and MUST NOT be projected into complete target coverage.

### M-02 — Provider entry/custody is not action-ran evidence

Across Cases 1, 3, 4 and 5:

1. Provider entry, `INVOKING` custody, reservation, or consumed authority alone MUST NOT establish AIREP `execution_event=executed`.
2. The adapter MAY emit `executed` only when an accepted executor-side source establishes that the exact scoped action ran under the agreed action identity/projection.
3. The executor report, provider commitment/outcome, and later business-effect observation MUST remain distinct evidence axes.
4. Case 4 is intentionally allowed to establish action execution while leaving Effect evidence missing.
5. A missing Effect remains missing evidence. It is not evidence that no effect occurred and does not reverse a valid action-ran report.
6. Provider commitment alone MUST NOT be used as a generic substitute for an executor report unless both parties explicitly agree that the selected native artifact directly establishes the AIREP action-ran predicate at the chosen action granularity. No blanket equivalence is approved by this revision.

### M-03 — Suppression requires positive, action-bound refusal evidence

For Cases 1 and 2:

1. AIREP `execution_event=suppressed` MAY be emitted only from an explicit refusal/prevention observation.
2. That observation MUST be bound to the same exact action and to the same Decision/instruction context used by the AIREP Execution artifact.
3. Absence of an Execution record MUST NOT be converted into suppression.
4. Absence of provider entry alone MUST NOT be converted into suppression without corresponding positive refusal/prevention evidence.
5. Reservation released before provider entry MUST remain distinct from authority already consumed after provider entry.
6. The mandatory `executed_action_digest` on a suppressed Execution MUST bind the exact attempted action under an agreed byte/projection rule; the adapter MUST NOT copy the authorized digest merely to fill the field.

### M-04 — Preserve effect observer, method and window

For Case 5, and any Effect emitted in the experiment:

1. Preserve who observed the effect.
2. Preserve how the effect was observed.
3. Preserve the observation window or timestamp scope.
4. Preserve the exact Execution/Decision binding.
5. An executor observing its own result is not an independent observer.
6. A bound AIREP Effect can establish that an Effect report is present and properly linked; that alone MUST NOT be described as proof that the intended business outcome occurred.
7. `observer_relationship=independent` MAY be claimed only when AIREP's accepted identity/key/policy/authentication prerequisites establish it.
8. A same-executor observation is valid evidence within its declared scope; it MUST NOT be silently upgraded or discarded.

### M-05 — Missing evidence remains distinct from positive non-occurrence evidence

- Missing receiver evidence ≠ delivery failure.
- Missing Execution ≠ suppression/non-execution.
- Missing Effect ≠ no effect.
- A positive scoped negative observation, such as “O2 did not cross EP-A during window W,” is evidence of that scoped predicate and MUST remain distinct from mere absence.
- A scoped negative observation MUST NOT be generalized into global non-occurrence or complete mediation.

---

## 2. Pinned EMILIA kernel behavior: preserve, do not repair in projection

Iman reported reproducing the following behavior at EMILIA commit `b1275b08f91939a2330aee26a03d0a6bfda375d6`:

| Provider outcome | Effect relation | Semantic state retained by kernel | Reconciliation | Actual reason label at pinned commit |
|---|---|---|---|---|
| `COMMITTED` | `NOT_OBSERVED` | unresolved / non-terminal | required | `provider_committed_effect_observed` |
| `COMMITTED` | `INDETERMINATE` | unresolved / non-terminal | required | `provider_committed_effect_observed` |

The state/reconciliation axes remain conservative, but the `reason` label is inconsistent with those axes.

### K-01 — Raw source preservation
Retain the actual native EMILIA result exactly as produced, including the incorrect reason label, with raw/canonical captured bytes and SHA-256.

### K-02 — No silent source correction
The adapter/projection MUST NOT rewrite the native EMILIA reason to a semantically cleaner value and present that rewritten value as the source result.

### K-03 — No semantic amplification from the bad label
`provider_committed_effect_observed` MUST NOT be used to infer an observed effect when the structured native axis is `NOT_OBSERVED` or `INDETERMINATE`.

### K-04 — Interpretation is separate metadata
The interop report MAY record `source_reason_inconsistent_with_structured_axes_at_pinned_emilia_commit` as experiment metadata. This does not mutate the native result.

### K-05 — Future EMILIA fix is a new pin
A later EMILIA fix requires a separately pinned rerun; results from `b1275b08f91939a2330aee26a03d0a6bfda375d6` remain immutable historical experiment evidence.

Machine-readable form: `KERNEL_BEHAVIOR_PIN_v0.3.json`.

---

## 3. Case-by-case consequences

### Case 1 — original multi-target freeze race
- Preserve the original parent and EP-A/EP-B identities.
- Retain the external obligation ledger as 2 expected / 1 confirmed / 1 unconfirmed.
- Do not present that ledger as stock AIREP target reconciliation.
- EP-A may support a scoped Control only after all mandatory Control fields and source bindings are agreed.
- EP-B stays unconfirmed; do not manufacture `delivery_failed`.
- O1 crossed provider entry before freeze; this alone does not prove action-ran or effect, and the later freeze cannot retroactively suppress/reverse it.
- O2 may support `suppressed` only from exact action-bound refusal evidence.
- The O2 negative boundary observation remains scoped, not global.

### Case 2 — reserved, then frozen before provider entry
- Authorization/reservation remain prior facts.
- Serialized freeze refusal is separate from advisory state checking.
- `suppressed` requires explicit same-action refusal evidence and correct Decision/instruction binding.
- `not_entered` plus reservation release does not describe post-entry consumed custody.
- Do not emit an Effect merely to represent missing effect evidence.

### Case 3 — provider entry/custody with indeterminate provider outcome
- Entry/custody alone is insufficient for `executed`.
- A separate accepted executor report may establish `executed` even while provider/effect outcome remains unresolved.
- Preserve provider and effect uncertainty separately.
- `UNREPRESENTABLE_IN_SCOPE` remains a per-fact option after lawful carriers are considered; it is not preassigned.
- No fabricated Effect to carry uncertainty.

### Case 4 — action ran, Effect evidence missing
- The selected source MUST include an accepted executor report for the exact action.
- `executed` may be emitted from that source.
- Effect evidence remains absent/MISSING when no adequate post-state observation exists.
- Provider `COMMITTED` remains a distinct axis.
- If the source contains the pinned bad reason label, preserve it raw and do not interpret it as effect observation.

### Case 5 — provider commitment plus divergent observed state
- Execution requires its own action-ran evidence.
- Provider commitment remains distinct.
- AIREP Effect may carry the actual observed state when correctly bound to Execution/Decision.
- Preserve observer identity, method and window.
- Retain native `DIVERGED` through agreed source reference/experiment ledger; do not invent an AIREP core `DIVERGED` enum.
- `effect_evidence=SATISFIED` means a bound Effect report exists, not that the requested business outcome succeeded.

---

## 4. Minimum source-to-field accounting

Before any adapter run, every emitted mandatory AIREP field MUST have an agreed source.

| AIREP field/group | Binding discipline |
|---|---|
| `airep_version`, `artifact_type` | Use wire `0.2` and the actual family. Package/document revisions are not wire versions. |
| `record_id`, `chain_id`, `sequence` | Adapter identities may differ from native IDs. Preserve native↔adapter correspondence separately; adapter order does not create native causality. |
| `subject.producer`, timestamp, principal | Identify the actual AIREP reporting producer/signer. Keep native observer/issuer separate from adapter identity. |
| `scope.covers`, `scope.does_not_cover` | State exact action, target/boundary, source, synthetic limits, missing axes and retained-only native facts. Scope cannot repair a false core event. |
| Decision fields | Require real governed-input bytes, governance assertion/basis, directive and output. Do not create a Decision solely to make downstream references resolve. |
| Control identity fields | Bind the actual governing Decision and instruction bytes. Preserve freeze-control identity separately from protected business-action identity. |
| `authorized_action_digest` | Bind what the control side authorized under an agreed projection; never substitute `instruction_digest`. |
| `control_event`, `boundary_side` | `dispatched` requires issuer observation; `received` receiver observation; `delivery_failed` explicit failure evidence. |
| `authority.writable_by_controlled_system` | Required source-backed declaration. Do not default it or treat it as proof of trustworthiness. |
| Execution identity fields | Preserve real Decision/instruction linkage; a synthetic resolving reference is not evidence of correct causal binding. |
| `executed_action_digest`, `execution_event` | Bind the exact attempted/ran action. `executed` requires action-ran evidence; `suppressed` positive action-bound refusal; `failed` explicit failed-execution semantics. |
| Effect references | Bind the exact Execution and same Decision. Never fabricate an Execution so an Effect can be emitted. |
| `observed_state` | Preserve what was actually observed; optional digest binds bytes, not truth. |
| `observer_relationship` | Preserve declared and effective relationship separately; same-executor is not independent. |
| Optional `evidence[]` | Reference exact native bytes/results with truthful resolvability and content hash. A native reference does not mean AIREP semantically verified it. |
| `profiles` | Existing extension surface. No new profile is part of this baseline. |
| AIREP integrity/signature | Follow pinned AIREP construction. Adapter signature authenticates the new AIREP report, not the native EMILIA source identity or truth. |

---

## 5. Adapter ownership proposal

**Proposal only; not an assignment.**

Preferred independence split:

- **Adapter implementation:** EMILIA side, or another implementer who is not an AIREP first-party producer author, implementing from the pinned AIREP specification.
- **Phionyx/AIREP side:** maintain the AIREP acceptance contract; provide the pinned spec/schemas; run/preserve reference verification and reconciliation; maintain the frozen input/output/hash ledger; review non-amplification against this mapping contract.
- **Independence disclosure:** record author, AIREP producer-code exposure/reuse, copied code, libraries, AI assistance, and contact with expected outputs.

Not importing the first-party producer is necessary for the proposed independence claim but not sufficient by itself. No adapter implementer is recorded until both sides agree.

---

## 6. What remains open before freeze

1. Exact native EMILIA artifact/capture selected for each case, including bytes/digests.
2. Exact executor evidence and action granularity used for `executed`.
3. Exact attempted-action preimage/projection and linkage used for `suppressed`.
4. Exact source for Control `authority.writable_by_controlled_system`.
5. Exact observer identity, method, window and trust inputs for emitted Effects.
6. Final byte/projection rules for every AIREP digest field.
7. Mutually approved adapter implementer and independence disclosure.
8. Fixed toolchains, commands, signing/operator inputs, output naming and retention layout.
9. Mutual acceptance of this mapping revision and source pins.
10. Recipient integrity check of the refreshed package, if desired.

Until these are resolved, the package is **NOT FROZEN**.

---

## 7. Freeze/run rule

Freeze only after both sides approve mapping/source pins and adapter ownership. At freeze, hash the accepted mapping contract, manifest, case descriptors, native inputs and trust/operator inputs; preserve all native raw outputs, adapter outputs, verifier/reconciler outputs and exit codes; do not rewrite negative, missing, indeterminate or upstream-bug outputs.

A completed run is a **bounded interoperability experiment**, not certification, deployment, adoption, complete mediation, general protocol equivalence, or by itself satisfaction of AIREP stable-release independence gates.

---

## 8. Provenance

`IMAN_REVIEW_DISPOSITION_v0.3.md` records the EMILIA-side review incorporation.  
`KERNEL_BEHAVIOR_PIN_v0.3.json` records the reviewer-reproduced kernel behavior.  
`SOURCE_LOCK.json` retains the GitHub source audit.  
The five v0.2 case descriptors and original fixture remain unchanged reviewed inputs.
