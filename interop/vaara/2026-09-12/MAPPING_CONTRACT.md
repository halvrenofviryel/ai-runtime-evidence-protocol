# Vaara × AIREP — Source-Pinned Mapping Contract

**ID:** `VAARA-AIREP-MAP` · **Revision:** `0.1.1-freeze-candidate` · **Date:** 13 September 2026  
**Status:** PROPOSED FREEZE CANDIDATE. Review feedback incorporated. Source identities are pinned. Not mutually frozen. Not run.  
**Prepared on the Phionyx side for review.** This is a proposed experimental contract, not a joint result, certification, legal agreement, or new protocol version.

## 1. Question, deliverable and evidence class

Can the selected Vaara records be represented using the pinned AIREP v0.2 semantics without strengthening their claims, suppressing their negative findings, or manufacturing missing provenance?

The deliverable is a per-case, per-family mapping report with the original source identities, native findings, target-field provenance and any qualifying AIREP artifacts. A valid result may be a partial mapping or an explicit no-map. Merely preserving JSON in a container is not a native-lifecycle mapping. An adapter-authored assessment of a source record is a new assessment, not the original governance decision or execution.

This pass is **`OPEN_EXPECTED`** over existing public fixtures. It is **not expected-blind**: the fixtures and their published expectations are already public, so withholding expected values would not establish a blind evaluation. `OPEN_EXPECTED` states what is true about the exposure and is not a stronger evidence class than that. It is separate from the reciprocal AIREP verifier exercise. It measures neither live agent behavior nor real-world delivery, execution or effect. The Phionyx-authored adapter is not a non-maintainer AIREP producer.

## 2. Exact source and target bases

The machine-readable companion [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) is part of this review package.

| Component | Pinned identity |
|---|---|
| Vaara repository | `vaaraio/vaara` |
| Vaara commit | `d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317` |
| Corpus | `conformance/sep2828`, version `1.0.0`; manifest label `SEP-2828` |
| Full upstream corpus digest | `sha256:0baa437da95d6ffb6bda3185d657385b7738c79daba77819acc0c6280ac0ed7a` |
| Selected native suites | `record_conformance_v0` and `record_set_v0` |
| Related work | `draft-sirkkavaara-vaara-receipt` (Work in Progress); informative only, not a measured run input |
| Proposed AIREP target | `v0.2.0-beta.1`, wire version `0.2` |
| AIREP commit | `8a6c01ecce457aa94330c0ed7219e4c56ebfe771` |
| AIREP annotated tag object | `dff7b4eeb14d57525855ae2c1af54d8f38bc9ec8` |

The Vaara corpus digest covers the full upstream manifest file list, not this seven-file subset. Do not claim full-manifest verification from checking the subset. Git blob IDs and SHA-256 file digests are different identities and are labelled separately. The AIREP tag is unsigned; pinning it does not independently authenticate its author.

For native reproduction, the exact committed checkers and their public expectations are the observational baseline. They are not proof of the whole draft's conformance. The draft describes related protocol semantics; an apparent mismatch with the selected checker surface is a named scope difference, not permission to change either source silently.

AIREP validity is determined by the pinned `SPEC.md` and its incorporated byte-authoritative integrity, input-admission, schema, class, profile and reconciliation rules. The fixture adapter cannot change those rules. An informative-reference documentation commit is recorded separately and does not retag or replace the beta measurement basis.

AIREP's active specification cites the Vaara draft by its revision-independent Internet-Draft name and Datatracker document URL, because the draft is Work in Progress. That bibliography choice is informative and makes no draft revision a measured input here. This experiment's behavior and source basis are the pinned Vaara repository commit and the selected corpus. [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) retains, byte-exact, the exact draft revision recorded when the package was prepared; that record is historical provenance and is not restated as the current revision. If a specific revision's text is later used as semantic evidence, that exact revision is pinned, hashed and recorded separately in the report that uses it.

## 3. Selected units — seven source files, five cases

Source IDs and exact SHA-256 digests are in the companion manifest. No additional Vaara fixture or feature work is requested for this pass.

| Case | Sources | What is exercised |
|---|---|---|
| VAM-01 | S1 `decision_a.json`, S2 `decision_b.json`, S3 `outcome_a.json`, all from `record_set_v0/sets/decision_without_outcome/` | Preserve the complete three-record set: a completed call A and an `escalate` decision on call B without an outcome in this supplied set. |
| VAM-02 | S4 `conforming_refused_no_commitment.json` | Preserve an explicit `refused` outcome and the absence of a result commitment; do not infer a blocking Decision that is not supplied. |
| VAM-03 | S5 `conforming_executed_projection.json` | Preserve reported `executed`, `completedAt`, result projection and projection digest; do not turn the commitment into a state observation. |
| VAM-04 | S6 `neg_digest_mismatch.json` | Preserve failed result-projection self-consistency; do not silently replace the recorded digest with the recomputed value. |
| VAM-05 | S7 `neg_malformed_backlink_digest.json` | Preserve rejection of `attestationDigest: "deadbeef"` as malformed. This is not an evaluated mismatch against a supplied predecessor. |

VAM-01 is indivisible for the measured native set run. The pinned set checker evaluates its decision/outcome pairing findings only when conforming decisions **and** outcomes are present. Removing the completed call changes the case. Its published expectation combines `conforms: true` with the `decision_without_outcome` advisory on `decision_b.json`; both must remain visible.

Source IDs are local to these case boundaries. A matching test nonce or repeated digest in another fixture does not authorize a cross-case join. Each record is also identified by its source path and exact-file digest; filenames alone never establish semantic identity.

No selected source supplies Control delivery observations or an Effect state observation. Absence is a representational limit of this selection, not a new positive test or a claim that the underlying event did not occur.

**Reviewed basis for this candidate.** Upstream maintainer review feedback confirms the five measurement units exactly as listed. VAM-01 remains the complete three-record unit — `decision_a`, `decision_b` and `outcome_a` as one unit — with the `escalate` decision's absent outcome visible inside the set rather than removed from it. VAM-04 and VAM-05 remain distinct negative units: they fail at different layers, and merging them would hide which one moved.

## 4. Rules preserving the strength of claims

The following are experimental acceptance rules, not additions to the AIREP wire format.

**R1 — Keep source and projection distinct.** Preserve original bytes, original signature fields, source paths and file digests. Every projected claim links to the specific source and field(s) supporting it. Adapter IDs, capture metadata and signatures are explicitly adapter-authored. They cannot impersonate a Vaara actor, clock, observer or historical chain.

**R2 — Do not promote stages.** A decision is not dispatch or receipt evidence. Receipt is not execution evidence. A reported execution and its result commitment are not state-observation evidence. A `block` decision, missing outcome and explicit `refused` outcome are distinct. Retain the actual source status rather than normalizing all non-successes into a single value.

**R3 — Do not promote trust.** The selected native checkers inspect structure and certain digest relations; they do not cryptographically verify source signatures against accepted keys. A native `conforms: true` result is not source authentication. Source signature verification remains `NOT_EVALUATED` in this pass. A fresh AIREP signature authenticates the projection under its own accepted binding, not the source's authorship or real-world truth.

**R4 — Preserve negative and unevaluated information.** Native required failures, advisories, missing counterpart records, unresolved references and unperformed checks are separately reported. A malformed or self-inconsistent record is retained as rejected evidence, not repaired or silently discarded. The mapper may explain a defect but cannot present repaired bytes as the original source.

**R5 — Distinguish digest meanings.** Exact-file SHA-256, JCS object digest, attestation digest, decision digest, result-projection digest, instruction digest and executed-action digest are not interchangeable. Recompute `projectionDigest` over the projection's UTF-8 bytes for the native self-consistency check. Do not replace it with the digest of a parsed-and-reformatted JSON object. A present, well-formed backlink is not a verified backlink when the predecessor and applicable verification inputs are not supplied.

**R6 — No invented completeness.** A missing outcome means absent from the supplied set. `escalate` does not establish a completed human decision. A complete pair does not establish complete history. New AIREP chain sequence numbers describe the adapter's emission, not Vaara's historical completeness. No tail-truncation, witness or all-target coverage claim is added in this first pass.

**Reviewed basis for this candidate.** R3 is carried forward substantively unchanged. A native `conforms: true` establishes neither source signature authentication nor a source key claim, and does not show that the source bytes are bound to an accepted key. Source signature verification remains `NOT_EVALUATED` in this pass.

## 5. Field-level projection policy

A mapping report records each candidate target field as `SOURCE_VALUE`, `DERIVED_BY_DECLARED_RULE`, `ADAPTER_METADATA`, or `UNSUPPORTED_FROM_SELECTION`, with source pointers and a rule identifier where applicable. These are report categories, not AIREP enums. Satisfying the JSON schema is necessary for an emitted artifact, but is not sufficient for semantic acceptance.

| Native element | Allowed treatment | Forbidden substitution |
|---|---|---|
| `decisionDerived.decision = allow` | Candidate vocabulary correspondence to Decision `directive.verb = release`, only as a report of the source decision and subject to full-family checks. | Inferring a delivered instruction or a completed execution. |
| `decisionDerived.decision = escalate` | Candidate correspondence to `escalate_to_human`; preserve source vocabulary and its stated scope. | Inventing a resolved human verdict or an outcome. |
| Original policy, claim basis, input/output evidence | Carry only supported values; identify absent provenance explicitly. A schema-permitted empty collection does not create information. | Using the adapter's mapping policy as the policy that made the original decision. |
| `outcomeDerived.status` | Preserve verbatim in the source report. `executed` and `refused` are potential correspondences to `executed` and `suppressed`, not automatic artifact-emission permission. | Treating a source label alone as all of an AIREP Execution's required bindings. |
| `backLink.attestationDigest` and `attestationNonce` | Use the exact pair as the native call-correlation key; state whether its predecessor is present and actually verified. | Treating an attestation commitment as an instruction or executed-action digest without an accepted rule. |
| `outcomeDerived.decisionDigest` where present | Preserve as a source commitment. Any new recomputation against a supplied Decision is reported separately from the native checker's result. | Claiming the native set checker cryptographically verified this edge when it did not. |
| `resultCommitment.projection` / `projectionDigest` | Preserve exact projection text and the native digest check. The result is a source-reported commitment. | Reusing it as `executed_action_digest`, or interpreting `deleted: true` as an observed post-action state. |
| `receiptAsserted`, `issuerAsserted`, native timestamps | Preserve as source assertions with their original status. | Claiming independently authenticated source identity or independently established event time. |
| New IDs, chain, capture timestamp, Ed25519 signature | Generate only as labelled adapter metadata under AIREP's actual construction rules. | Pretending these existed in Vaara's original lifecycle. |

**Per-family sufficiency gate.** Before emission, the report must resolve all required fields and their meaning, not merely their types:

- **Decision:** identify the governed input and digest/projection basis, the source decision assertion and basis, directive and policy-basis representation, output commitment and required evidence. These fixtures' minimal decision records do not, merely by carrying `allow` or `escalate`, supply all of that provenance.
- **Control:** no dispatch/receipt source evidence is supplied. Do not emit Control in this selection, including `delivery_failed` inferred from silence.
- **Execution:** identify the Decision reference, instruction identity and digest, executed-action digest and explicit outcome. The supplied result digest and backlink cannot fill missing instruction/action commitments by shape alone. Rejected source records cannot supply accepted execution facts.
- **Effect:** no state-observation evidence is supplied. Do not emit Effect, including one with an invented `same_executor` or `unknown` observer relationship.

For unsupported required semantics, emit a report entry, not a malformed artifact or a placeholder digest. Partial payloads are not described as conforming AIREP records. The review may therefore conclude that this selection supports no complete native-lifecycle AIREP artifacts. That result is reportable and must not be disguised as producer interoperability. A new AIREP Decision about *admitting a source record* would be a different, adapter-authored governance event and is outside this first-pass native-lifecycle mapping claim.

Any concrete derivation beyond the rules above needs a versioned rule in the contract and reviewer disposition before the measured run. A proof-of-representability check may occur during review, labelled development; it is not retrospectively the measured run.

**Reviewed basis for this candidate.** The field-sufficiency and no-fabrication rules above are carried forward unchanged. No Control or Effect artifact is emitted without source evidence; a result digest never substitutes for an instruction or executed-action digest; a partial mapping or an explicit no-map remains a valid outcome. Successful AIREP artifact emission is not a goal of this pass.

## 6. Separate outputs and comparison dimensions

Retain (a) native checker results, (b) field-sufficiency and mapping reports, and (c) AIREP verifier/reconciler outputs for any artifacts actually emitted. A native advisory does not become an AIREP failure merely by renaming; a target result does not overwrite the native one.

For each family in each case, use these mapping-report dispositions:

| Disposition | Meaning |
|---|---|
| `EMITTED` | A complete target artifact is supported and actually produced; link its exact bytes and checks. |
| `PARTIAL_NO_ARTIFACT` | Some meaningful source fields correspond, but required target semantics are unsupported; no family artifact is emitted. |
| `NO_MAP` | This family has no supported representation from these inputs under the frozen rules. |
| `REJECTED_SOURCE` | Relevant source fails applicable admission checks; retain its defect and source identity. |
| `NOT_EVALUATED` | The mapping has not been evaluated, or a named prerequisite prevents evaluation. |

Comparison is a different axis: `NOT_COMPARED`, `AGREE`, or `DISAGREE`. Both sides may agree on `NO_MAP`; that does not become a full mapping. Agreement on a coarse disposition does not conceal disagreement on supporting fields or reasons.

The [REPORT_TEMPLATE.json](REPORT_TEMPLATE.json) has five unmeasured rows. Preserve source signature-check state, native failures and advisories, per-field provenance, per-family dispositions, output digests and disagreements. A detailed machine schema can be fixed with the implementation; it is not claimed as delivered here.

## 7. Acceptance procedure and freeze

1. Review this revision and its source manifest. Resolve field sufficiency, exact derivation rules and the case grouping. Record changes in a new revision; do not silently edit a version already cited in correspondence. Upstream maintainer review feedback on sections 3 to 5 and on the five-unit grouping has been incorporated into this revision, which is offered as a freeze candidate.
2. Exact mutual freeze still requires both sides to accept this candidate's exact identities and digests. [FREEZE_CANDIDATE.json](FREEZE_CANDIDATE.json) states the proposed identities; on both sides' explicit acceptance, record the accepted contract and manifest file digests together in an acceptance record. Neither this candidate nor its transport checksum records acceptance on behalf of the upstream maintainer.
3. Only after candidate freeze, and before the measured run, pin adapter code, dependency versions, commands, any declared projection rules, target-verifier inputs and test-key policy. Do not insert private keys or credentials into the public report.
4. Verify selected source bytes at the pin. Reproduce the public native surface with an exact seven-file selection wrapper calling the pinned checker functions. Preserve the three-record set. A run of the complete upstream runner, if also made, is a separate full-corpus baseline, not five extra mapping results.
5. Capture native results and adapter outputs without altering sources or public expectations. Evaluate only target artifacts actually emitted. Freeze raw first-run output digests before adjudication.
6. Compare against the open expectations and agreed mapping rules. Publish disagreements, implementation failures, source limits and unperformed checks. Corrections produce a new run identity; preserve the first result. The first run is preserved as recorded and is not repaired to reach an expected result.

Transport/run failures, semantic mapping limitations and mismatches are distinct. An adapter test passes only when it reports the required boundaries correctly and any emitted artifacts satisfy the relevant AIREP checks. A correctly preserved `INCOMPLETE` reconciliation result is not automatically a failed mapping test. No global lifecycle success is inferred from a command exiting zero.

## 8. Attribution, publication and exclusions

The Vaara draft is an informative reference in AIREP's active specification, independently of whether the experiment finds a full mapping. Two citation needs are distinct. In the **active specification**, the draft is cited by its revision-independent Internet-Draft name and Datatracker document URL, because it is Work in Progress; that generic citation does not change the beta experiment basis. In a **measured report**, if an exact Internet-Draft revision is actually used as semantic evidence, that exact revision is separately pinned, hashed and recorded in the report alongside the source commits. Do not turn the reference into a normative dependency or a claim of historical priority, equivalence, endorsement or completed interoperability.

Use `interop/vaara/2026-09-12/` in the AIREP repository as the proposed review location. Publish this contract, the source manifest and later accepted reports with truthful status labels. Link upstream Vaara files by their pinned identities rather than copying them into this package. Any later redistribution of upstream material retains its applicable terms; this draft grants no rights in other parties' material.

Do not publish private email text, private enclosures, credentials, or imply Henri's approval or joint authorship without permission. A public draft PR is an invitation to review, not evidence of acceptance. Do not create a successful `EXTERNAL_EVIDENCE.md` entry or rewrite a frozen release from this planning package.

The reciprocal AIREP verifier run is separate: the existing *Independent-Verifier Corpus v0.2* is alpha.1-based. A beta measurement requires an explicitly beta-based package and implementation provenance. Neither this mapping exercise nor that future run is pre-counted as closing the full stable gate.

Excluded from this pass: live provider integration, new Vaara fixtures, source-key authentication, positive Effect observations, delivery witnesses, completeness/sealing extensions, held-out blind tests, performance benchmarks, and production interoperability claims.

## 9. Current status and review decision requested

The selected source identities and applicable source code have been inspected. This preparation has **not** run the full corpus, verified source signatures, implemented the adapter, emitted AIREP artifacts, or measured interoperability. Earlier selected-file probes are not a substitute for the run record defined above.

Upstream maintainer review feedback has been incorporated into this candidate. The reviewed technical scope is sections 3 to 5, the five-unit grouping, and the mapping/verifier handoff scope relevant to this mapping contract. The reciprocal AIREP verifier package's 60 class cases, its 117 schema fixtures and its 11 example variants are outside this mapping-contract review. No interoperability measurement has occurred, and this review establishes no interoperability result. No additional Vaara implementation work is a prerequisite for reviewing this contract.

Remaining decision: mutual freeze is pending acceptance of this candidate's exact identity — the contract and source-manifest digests recorded in [FREEZE_CANDIDATE.json](FREEZE_CANDIDATE.json), together with the pull request head commit. After that acceptance, the next step is the adapter implementation and its frozen run plan—not a new high-level collaboration proposal.

## Source references

- [Vaara pinned corpus manifest](https://github.com/vaaraio/vaara/blob/d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317/conformance/sep2828/MANIFEST.json).
- [Vaara pinned single-record checker](https://github.com/vaaraio/vaara/blob/d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317/conformance/sep2828/record_conformance_v0/_check_independent.py) and [set checker](https://github.com/vaaraio/vaara/blob/d44b8b0de4f5f3e4e5c0248ad1e6fbbc3972b317/conformance/sep2828/record_set_v0/_check_independent.py).
- [Vaara Receipt](https://datatracker.ietf.org/doc/draft-sirkkavaara-vaara-receipt/), H. Sirkkavaara, Internet-Draft `draft-sirkkavaara-vaara-receipt`, Work in Progress; informative only, not a measured run input.
- [AIREP pinned specification](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/SPEC.md), its incorporated sources, and [reconciliation contract](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/RECONCILIATION.md).
- [AIREP release stages](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/spec/airep/v0.2/RELEASE_STAGES.md) and [alpha-based corpus revision README](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/blob/8a6c01ecce457aa94330c0ed7219e4c56ebfe771/interop/independent-verifier-corpus/v0.2/README.md).
