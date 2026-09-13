# AIREP × EMILIA — proposed interoperability case sheet
## Review revision 0.2 · 10 September 2026

**Phionyx first-party provisional case sheet. Not frozen; no adapter assigned; no interoperability run performed; no interoperability result is claimed.** This supersedes document revision 0.1, not either protocol. The five primary questions are unchanged. Machine-readable counterparts are in `AIREP_EMILIA_INTEROP_MANIFEST_v0.2.json` and `inputs/`.

### 1. Fixed reference and proposed source baseline

| Item | Reference | Status |
|---|---|---|
| AIREP | `v0.2.0-beta.1`, commit `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` | Exact published implementation target; wire version `0.2` |
| EMILIA | commit `b1275b08f91939a2330aee26a03d0a6bfda375d6` | Public upstream repository snapshot inspected by Phionyx; subject to source-selection review before any future measurement |
| Source audit | first-party source-audit records, retained privately | Name the actual documents, implementation functions and tests inspected; not a fresh build/test claim |

The AIREP specification incorporates its accepted schema design; the latter explicitly distinguishes an action having run from its material success. The release tag was checked separately from historical prepublication wording in repository documents. This sheet does not assert an overall EMILIA package version or equate an IETF draft revision with a repository implementation. [A-SPEC] [A-DESIGN] [A-STAGES]

### 2. Question and reporting boundary

**Can the selected EMILIA evidence support honest AIREP records while preserving the original claims, omissions, uncertainty, target scope and observation provenance?** Record the answer for each fact, not by matching similarly named status values.

The baseline permits ordinary beta fields, accurate `scope`, descriptions and hashed `evidence[]` references. An experiment sidecar retains native facts that the stock AIREP tools do not interpret. A new profile is *not* required for this first proposal; profiles are an existing AIREP extension mechanism, not prohibited by the protocol. Any new mapping profile needs separate agreement and must not change core meanings. A native byte reference preserves evidence availability; it does not mean AIREP has verified or semantically interpreted that evidence. Do not invent a Decision/Execution just to obtain a container for an otherwise unsupported state. [A-COMMON] [A-SPEC] [A-VERIFY]

Use these **experiment-only**, per-fact dispositions after review: `CORE_TYPED`, `CORE_DESCRIPTIVE`, `SOURCE_REFERENCE_ONLY`, `UNREPRESENTABLE_IN_SCOPE`, or `INSUFFICIENT_EVIDENCE`. A missing typed field is not automatically an unrepresentable fact. An unrepresentable finding must name the scoped carriers considered and the residual loss. No measured disposition is pre-filled in this package.

### 3. Rules that apply to all five cases

**No stage promotion.** Authorization/reservation does not establish delivery, provider entry or action execution. Equally, an unknown provider/effect outcome does not establish that the action did not run. AIREP `executed` reports that the exact scoped action ran, not that its desired effect happened. Native evidence must establish the actual event at a defined action granularity before selecting `executed`, `failed` or `suppressed`. Custody words alone are insufficient. [A-DESIGN] [A-EXECUTION] [E-KERNEL]

**Keep the objects separate.** A freeze instruction, a protected business operation, provider entry and an observed post-state are not the same object. Preserve instruction IDs and decision/Execution references. AIREP’s Control `authorized_action_digest` and Execution `executed_action_digest` must refer to the corresponding action under an explicit byte/projection rule; they are not aliases for `instruction_digest`. No synthetic receipt, action digest, control-side authority declaration or missing Decision may be silently supplied. [A-SPEC] [A-CONTROL] [A-EXECUTION]

**Keep absence and observation separate.** Missing receipt is not non-delivery; missing Effect is not no-effect. Positive scoped negative observations, such as an audit finding that O2 did not cross a particular boundary during a specified window, must also be preserved. They do not imply global non-occurrence or complete mediation. The original fixture contains such an O2 observation.

**Keep native trust and adapter signing separate.** AIREP authentication identifies the accepted signer of its report; it does not transplant a native issuer’s signature or verify a source observation. Disclose the original observer, native verifier and trust inputs, adapter signer, and declared/effective observer relationship. `same_executor` is permissible evidence without independent corroboration. Distinct test keys or a fixture’s independence declaration do not establish independent observation. [A-SPEC] [A-TESTS]

**Keep the result axes separate.** Native statuses, AIREP family validity/class/profile findings, reconciliation predicates, business outcome and mapping fidelity remain separately visible. In this beta, `failed` and `suppressed` produce `execution_outcome=FAILURE`. An otherwise correlated lifecycle remains `INCOMPLETE` because stock target coverage is not evaluated. Neither is automatically an adapter defect; exit zero means evaluation completed, not acceptance. [A-RECON-CODE] [A-TESTS] [A-VERIFY]

Field-by-field binding requirements are in `MAPPING_CONTRACT.md`; they do not supply missing native events or trust inputs.

### 4. Concrete inputs and what still needs native review

`inputs/original/agent-control-delivery-freeze-race.v1.json` is the recovered original **6,212-byte file**, unchanged, with SHA-256:

`2d8faa1b64b8a73fd0bf81b21889bbf726cbfb324af099b700499627af84203a`

Its original ID is `freeze-after-provider-entry-with-multiple-required-targets`. Its historical related-work references and expected results are retained. The exact instruction-string digest was also recomputed successfully. O1/O2 action preimages are not in that file; their digests remain source declarations, not newly recomputed action bindings.

The five `inputs/AEI-EMILIA-00N.v0.2.json` files are **proposed scenario descriptors**, not native EMILIA records or AIREP artifacts. Their new adapted IDs end in `-review-v0.2`. Cases 2–5 contain proposed fixed timelines and separate action/instruction byte files in `preimages/`. These use a small synthetic `test.record.set` operation. SHA-256 binds the exact UTF-8 file bytes, including the final newline; it is not asserted to equal an EMILIA CAID or `capabilityActionDigest`. No CAID registration or native verification success is invented. Case 5 includes proposed requested/observed state values, explicitly not measurements.

This makes the scenario inputs reviewable now. The exact native capture, source verification, mapping prerequisites and the selected EMILIA revision remain pre-run gates, not hidden defaults. Normalized AEB input fields such as `native_verification: VERIFIED` are upstream-test findings, not independently executed native signature verification. The Gate reference demo’s in-memory state and synthetic control verifier are also identified explicitly. [E-KERNEL] [E-AEB-TESTS] [E-FREEZE-DEMO]

### 5. Five proposed cases

#### AEI-EMILIA-001 — original multi-target freeze race

**Source/input.** Use the unchanged contributed fixture plus its separately identified review sidecar. Source instruction `ctrl-freeze-42` has required targets EP-A and EP-B. EP-A receipt/enforcement is present; EP-B is unconfirmed. O1 crossed entry before freeze and has unknown effect at cutoff. O2 was refused after freeze; a scoped audit observation says O2 did not enter EP-A during its window.

**Permitted handling.** Retain all six fact IDs in the case descriptor. A qualifying EP-A receiver observation can support a Control receipt only once every required field and its source binding are supplied. The O2 refusal can be considered for `suppressed`, subject to an honest attempted-action digest and proper Decision/instruction relationship. Retain the O2 audit predicate as a scoped control-effect fact, not a business-effect assertion. Keep freeze execution and protected-operation execution in separate contexts; do not use one merely to fill the other’s references.

**Critical boundary.** Stock `reconcile()` groups Controls/Executions by resolved Decision identity plus instruction ID, **not target**. Its single group receipt cannot certify EP-B. It has no target-inventory input and unconditionally returns `intended_target_coverage=NOT_EVALUATED`. The experiment therefore retains the original external obligation ledger: 2 expected, 1 confirmed, 1 unconfirmed, parent not fully confirmed. That ledger is not advertised as stock AIREP target reconciliation. No unapproved ID splitting or reminting may hide the limitation. [A-RECON-CODE] [A-CONTROL]

**Forbidden.** EP-A ⇒ EP-B; target-set closure ⇒ complete deployment mediation; later freeze ⇒ O1 blocked/reversed/no-effect; O2’s scoped observation ⇒ every path closed; fixture-declared independence ⇒ authenticated independent observer.

**Review needed.** Native target/parent representation strategy; source-bound missing family fields; separation of the control and business-action contexts. Existing portable signed freeze events must not be assumed: the inspected EMILIA implementation explicitly names that gap. [E-FREEZE-NOTE]

#### AEI-EMILIA-002 — reserved, then frozen before provider entry

**Source/input.** The proposed local timeline follows the reference ordering in `scenario.mts`: reserve, freeze in the same owning domain, refuse old reservation at provider entry, optionally restore without reviving it. The adapted bytes use a mock record update, not the demo’s robot action. [E-FREEZE-DEMO] [E-FREEZE-TESTS]

**Permitted handling.** Preserve authorization/reservation as prior facts; accept a Control only for its separately observed boundary event. Consider `suppressed` only from the explicit scoped refusal and reviewed action binding. Preserve the source’s `not_entered` and `released` reservation result. Known pre-entry refusal is different from consumed custody after entry with an unknown outcome. An advisory status check is not a serialized freeze. [E-ENTRY] [E-FREEZE-NOTE]

**Forbidden.** Reserved ⇒ executed; not-entered ⇒ unknown post-entry custody; no supplied Effect ⇒ global no-effect. A correct `suppressed` record may give AIREP `execution_outcome=FAILURE`; preserve it without marking the adapter incorrect solely for that reason.

**Review needed.** The exact refusal observation, owner/domain/epoch binding, Decision/instruction fields and the appropriate attempted-action meaning for mandatory `executed_action_digest`. The reference schema/tests permit suppression, but do not by themselves establish the native mapping for this new case. [A-EXECUTION] [A-TESTS]

#### AEI-EMILIA-003 — entry/custody with indeterminate outcome

**Source/input.** Proposed action, source-bound entry/custody finding, provider timeout/unknown outcome, no sufficient effect observation, no-blind-retry and reconciliation requirement. Relevant AEB vector anchors are `timeout_after_dispatch`, `provider_unknown_effect_unknown` and `blind_retry_refused`. They are normalized findings, not a captured end-to-end run. [E-KERNEL] [E-AEB-TESTS]

**Permitted handling.** First determine what the native evidence proves about the exact scoped action. When it establishes only reservation, dispatch or custody, do not assert action-ran. When a separate accepted executor observation establishes that the exact action ran, AIREP `executed` can be faithful **even while the provider/effect outcome remains indeterminate**. Preserve those uncertainties and replay/reconciliation obligations separately through legitimate source references/sidecar facts. AIREP does not thereby enforce the EMILIA obligations.

**Forbidden.** Unknown effect ⇒ action did not run; `INVOKING` alone ⇒ action ran; unknown outcome ⇒ guessed `failed`; receipt-signing ⇒ actual execution; no typed custody field ⇒ whole protocol cannot preserve the evidence. Do not manufacture an Effect to carry “unknown” as though it were an observed world state.

**Review needed.** Agree action granularity and exact executor-source evidence before selecting a family event. `UNREPRESENTABLE_IN_SCOPE` remains an available per-fact result, but is **not preassigned** to this case. No new primary case is added by identifying these conditional outcomes. [A-DESIGN] [A-COMMON]

#### AEI-EMILIA-004 — action ran, effect not observed

**Source/input.** A source-bound executor report of the scoped action, optional distinct provider commitment finding, and deliberate absence of adequate post-state observation. Do not substitute an isolated `COMMITTED` flag for the executor report/action binding.

**Permitted handling.** Emit `executed` only when its own prerequisites are met. The missing Effect stays absent; stock reconciliation should name `effect_evidence=MISSING` for that admitted Execution. This is missing evidence, not failure to execute and not proof of no effect. [A-RECON-CODE] [A-TESTS]

**Native nuance.** The inspected AEB kernel allows provider `COMMITTED` with effect `NOT_OBSERVED`, but does not classify that pair as fully terminal. The provider and effect axes must not be flattened. Its generic reason-selection branch also merits scrutiny for that pair; `MAPPING_CONTRACT_v0.3.md` section 2 records the exact static observation, cited to public source, without claiming a reproduced runtime defect. A reason string is never a substitute for an observation. [E-KERNEL]

**Forbidden.** Execution ⇒ observed effect; missing Effect ⇒ no effect; a misleading reason label ⇒ observation success; `INCOMPLETE` ⇒ unfaithful mapping.

#### AEI-EMILIA-005 — commitment with divergent observed state

**Source/input.** Separate execution/provider evidence and a later source-bound post-state observation, with method, window and comparison basis. Proposed byte files set the requested test value to `requested` and observed value to `different`. The upstream anchor `provider_committed_effect_diverged` verifies that EMILIA preserves distinct provider/effect axes. [E-AEB-TESTS]

**Permitted handling.** A properly bound Execution and Effect can preserve the reported action and actual observed state. A description and hashed native evidence can retain the divergence assertion even though AIREP has no core `DIVERGED` enum. The stock reconciler checks binding/presence and observer treatment, not whether requested and observed business states match. Report separately whether divergence was merely retained or actually recomputed under a defined comparison rule. [A-EFFECT] [A-RECON-CODE]

**Forbidden.** Commitment ⇒ requested effect; bound Effect `SATISFIED` ⇒ business success; adapter signature ⇒ native source identity; same-executor observation ⇒ independent corroboration. No novel enum or fabricated observer is needed to report an actual divergent observation.

**Review needed.** The native post-state artifact, comparison basis, observer identity/trust, and faithful adapter attribution. A same-executor observation is acceptable within its declared limits; independence is not imposed as a universal prerequisite. [A-SPEC] [A-TESTS]

### 6. Assessment, independence and freeze

Every required fact must have a source pointer, disposition, output reference or explicit non-emission reason. No empty-output “pass” and no silent dropping of custody, target or effect facts. A valid cryptographic artifact does not prove a faithful mapping. Preserve all raw reference findings; negative/unknown outcomes may be the correct case result. A case can yield `SEMANTIC_GAP` or `INSUFFICIENT_EVIDENCE` without being rewritten into success. A complete semantic-gap report with no independently emitted validated artifacts does **not** establish producer interoperability.

These are **expected-aware** cases. Adapter authorship, code exposure/reuse, general-purpose dependencies and AI assistance must be disclosed. Not importing the reference producer is necessary to the proposed independence claim, not sufficient proof. Reference Python/Node parity is not a new non-maintainer consumer. Adapter selection follows source-selection review; no implementer is selected here. This limited exercise does not by itself satisfy the stable requirements for same-candidate producers, a qualifying non-maintainer consumer and broader normative/adversarial coverage. [A-STAGES]

Any future measured experiment would require a separately defined and independently recorded input/acceptance basis: settled native commit/source selection; completed byte/projection and family-field mappings; recorded per-fact expectations, observation/trust inputs and target handling; then a recorded implementer, toolchains and output contract. Custody all final native bytes and hashes against the final document digest. A changed meaning or input produces a new revision; hashing a proposal does not make it approved.

**Open requirement:** settle or amend R1–R7 in the manifest, especially target representation (R3), the action-ran boundary (R4), suppression binding (R5) and observer attribution (R6). R8 implementation planning follows that step.


[A-SPEC]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/SPEC.md
[A-DESIGN]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/schema-design/ARTIFACT_SCHEMA_DESIGN.md
[A-COMMON]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/schemas/common.schema.json
[A-CONTROL]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/schemas/control.schema.json
[A-EXECUTION]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/schemas/execution.schema.json
[A-EFFECT]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/schemas/effect.schema.json
[A-PRODUCER]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/tools/airep_v02/producer.py
[A-RECON-CODE]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/tools/airep_v02/reconcile.py
[A-RECON-DOC]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/RECONCILIATION.md
[A-TESTS]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/tests/v02/test_beta.py
[A-VERIFY]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/VERIFICATION.md
[A-STAGES]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/RELEASE_STAGES.md
[A-INTEGRITY]: https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/INTEGRITY.md
[E-README]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/README.md
[E-AEB-DOC]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/docs/conformance/AEB-1-CONSEQUENCE-ADMISSION.md
[E-KERNEL]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/packages/verify/src/aeb-consequence-conformance.ts
[E-AEB-TESTS]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/packages/verify/aeb-consequence-conformance.test.ts
[E-AEB-VECTORS]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/conformance/vectors/aeb-consequence-conformance.v1.json
[E-ENTRY]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/packages/gate/src/provider-entry.ts
[E-STORE]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/packages/gate/src/admission-store.ts
[E-FREEZE-NOTE]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/docs/security/CONSEQUENCE-ENTRY-HARDENING-2026-08-03.md
[E-FREEZE-DEMO]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/examples/supply-chain-authority-v1/scenario.mts
[E-FREEZE-TESTS]: https://github.com/emiliaprotocol/emilia-protocol/blob/b1275b08f91939a2330aee26a03d0a6bfda375d6/examples/supply-chain-authority-v1/scenario.test.mts
