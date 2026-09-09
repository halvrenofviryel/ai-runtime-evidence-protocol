# AIREP v0.2 specification

**Implementation target: `v0.2.0-beta.1`. Wire version: `0.2`.** This is a
usable experimental beta, not stable interoperability certification. v0.1
remains frozen, supported, and independently verifiable under its existing
rules. A v0.1 artifact MUST NOT be relabelled as v0.2.

This is the normative entry point. MUST, MUST NOT, SHOULD and MAY are BCP 14
requirements. Read this document, then the [producer quickstart](QUICKSTART.md),
[verifier interface](VERIFICATION.md), and [worked lifecycle](../../../examples/v02/README.md).

## 1. Authority and implementation basis

The following contracts are incorporated, not copied or superseded. If a
summary here conflicts with a byte-level rule, the byte-authoritative source
governs; an implementation MUST NOT invent an alternate construction.

| Concern | Normative owner |
|---|---|
| Domain tags, JCS body subtraction, SHA-256, pure Ed25519 preimages, witness claim | [INTEGRITY.md](INTEGRITY.md), **byte-authoritative and frozen**, SHA-256 `2fca9a02ebd8b22807f51742278d7ddfc101e25ca6fd4fa844d6c6a537e98c11` |
| Raw artifact input and binary64 model | [JSON_INPUT_ADMISSIBILITY.md](JSON_INPUT_ADMISSIBILITY.md), AD-17 |
| Core and family structures, required fields, enums and closure | [accepted schema design](schema-design/ARTIFACT_SCHEMA_DESIGN.md) and the five [schemas](schemas/) |
| Assurance semantics, revocation, independence, withholding | [CONFORMANCE_CLASSES.md](CONFORMANCE_CLASSES.md) |
| Profile evaluation | [N-01/N-01b/N-01c](profile-validation/N-01_PROFILE_VALIDATION_DECISION.md) |
| Reference measurement envelope, inputs and reasons | [r3 contract](class-verification/contract-r3/CLASS_VERIFIER_CONTRACT_R3.md) and its explicit r1 incorporations; [source digests](class-verification/contract-r3/SOURCE_BASIS.json) |
| Beta lifecycle reconciliation | [RECONCILIATION.md](RECONCILIATION.md) |

The [architecture decisions](../v0.2-design/ARCHITECTURE_DECISIONS.md) provide
design provenance. Earlier design vocabulary such as `decision_id` or
`action_digest` is conceptual: implementers MUST use the accepted schema's
`decision_ref`, `authorized_action_digest` and `executed_action_digest` fields.
Earlier optional-suite sketches do not extend INTEGRITY's closed suite registry.
Contract revisions are measurement revisions, never wire versions.

## 2. Artifact families

Each artifact reports exactly its family stage. Higher assurance does not
promote one stage into another or prove that the reported event occurred.

| `artifact_type` | Meaning | Required family fields |
|---|---|---|
| `decision` | A governance decision on input and policy | `input`, `claim`, `directive`, `output`, `evidence` |
| `control` | A boundary-side report about an instruction | `decision_ref`, `instruction_id`, `instruction_digest`, `authorized_action_digest`, `control_event`, `boundary_side`, `authority` |
| `execution` | An executor's report about an attempted action | `decision_ref`, `instruction_id`, `instruction_digest`, `executed_action_digest`, `execution_event` |
| `effect` | An observation of state following a referenced execution | `decision_ref`, `execution_ref`, `observer_relationship`, `observed_state` |

Decision `claim` contains an assertion and nonempty basis array; `directive.verb`
is `release`, `block`, `defer`, `redact`, `escalate_to_human`, or `kill` and
`policy_basis` is required. A decision is neither a delivery receipt nor proof
of a correct authorization decision.

Control `control_event` is `dispatched`, `received`, or `delivery_failed`;
`boundary_side` is `issuer` or `receiver`. Dispatch requires an issuer report;
receipt requires a receiver report. `authority.writable_by_controlled_system`
is required and expresses a producer declaration about the boundary, not
verified authority. `issuer_id` is optional.

Execution `execution_event` is `executed`, `failed`, or `suppressed`; these
MUST remain distinct. Effect `observer_relationship` is `same_executor`,
`independent`, or `unknown`; `observed_state.description` is required and
`state_digest` is optional. Effect reports need not come from an independent
observer. An executor's own observation is evidence without independent
corroboration. There is no automatic inference from absence to non-occurrence.

## 3. Common core and identity

Every family MUST carry:

| Member | Requirement |
|---|---|
| `airep_version` | Exactly `"0.2"`, regardless of package SemVer |
| `artifact_type` | Exactly its family schema constant |
| `chain_id` | Globally collision-resistant identity chosen at chain genesis |
| `record_id` | Globally collision-resistant record identity, separate from position |
| `sequence` | Monotonic chain ordering; non-negative safe integer ≤ 2^53−1 |
| `subject` | `producer` string and UTC `timestamp_utc`; optional `runtime`, `principal` |
| `scope` | Both `covers` and `does_not_cover` string arrays |
| `integrity` | `previous`, `current`, and `signature` |

Subject timestamp syntax, optional principal fields and `established_by` values
are fixed by [common.schema.json](schemas/common.schema.json). A timestamp
matching a structural pattern is not an independently established signing time.
When principal is present, `established_by` is required. No assertion of a
principal or producer inside a record can replace verifier-accepted key binding.

Identifiers and sequence are inside the signed/hashed content. Distinct roles
MAY emit into distinct chains. Cross-artifact references carry `record_id` and
optionally `chain_id`; a bare sequence MUST NOT resolve a cross-artifact edge.
The reference producer uses UUID4 by default and sequences 0, 1, 2, …; fixed
`demo.*` identities and public keys in fixtures are test data, not production IDs.

## 4. Digests and correlation

Digests use the accepted `sha256:` plus 64 lowercase hexadecimal form.

* Decision `input` MUST include `input_ref` and `input_digest`. Without
  `digest_projection`, the digest binds full governed-input bytes. If present,
  `digest_projection` identifies the declared namespaced projection rule;
  unavailable rules leave provenance unevaluated, never assumed.
* Decision `output` MUST include `result_ref` and `result_digest`.
* Every supplied `evidence[]` item MUST include `type`, `ref`, `resolvable`, and
  `content_hash`, whether `resolvable` is true or false.
* Control and Execution MUST bind the same instruction using `decision_ref`,
  `instruction_id` and `instruction_digest`. Control states the authorized action
  digest; Execution states the executed action digest. The TOCTOU comparison is
  their equality, not the equality of either with the instruction digest.
* Effect MUST reference the specific Execution and its Decision. Co-location,
  filenames, list order and timestamps cannot substitute for explicit references.

Application bytes and projection semantics MUST be explicit. The reference
library exposes `digest_bytes(bytes)` and an explicit `digest_json(value)` for
applications choosing JCS-encoded JSON. They are different operations: a JSON
file with whitespace need not hash like its JCS representation. The worked
example hashes exact instruction file bytes and JCS action/state values.
Digest agreement does not establish that the declared input, execution, or
state was actually observed. The beta reconciler does not fetch referenced URIs.

## 5. Closed core and profile extension

Core objects are closed exactly as the accepted schemas specify. Implementers
MUST NOT add vendor fields to the core or supply defaults that alter hashed
content. `profiles` is the only extension point: keys are namespaced IDs matching
the accepted grammar; values are objects owned by the named profile.

Unknown profiles remain carried and integrity-bound. Without a usable basis for
the exact identifier, profile evaluation MUST be `NOT_EVALUATED`, with null
basis digest. A profile asserting a higher class cannot grant it.

The r3 operator registry binds exact self-contained Draft 2020-12 schema bytes
by SHA-256. No network loading, alternate dialect selection, implicit plugins
or undeclared external references are allowed. `format` remains annotation-only.
An unusable supplied basis invalidates the run; a valid basis rejecting a payload
produces profile `FAIL`, not a class downgrade. [VERIFICATION.md](VERIFICATION.md)
defines the runnable surface and the separate evidence identities.

## 6. Integrity, signatures and chains

Implementers MUST implement [INTEGRITY.md §§1–5](INTEGRITY.md) exactly. That file
alone owns the preimage bytes, LF separators, closed domain-tag and suite
registries, signed witness claim, and no-search/no-fallback rules. This document
does not duplicate its formulas.

The required suite is **pure Ed25519**, signing the frozen record-signature
preimage directly. No Ed25519ph or alternative v0.1 preimage is permitted.
The verifier selects suite and public key from accepted operator bindings;
unauthenticated `signature.alg` MUST NOT select cryptographic behaviour. A
changed informative label can generate a caveat but not a different suite.

`integrity.previous` binds the previous artifact's `integrity.current`; genesis
uses the schema-design zero digest. A producer MUST preserve chain identity
and increasing sequence and MUST NOT reuse record identity for different bytes.
A partial chain is not a proved complete chain. Link reconciliation and witness
head anchoring are separate checks with separately bounded claims.

## 7. Assurance classes and negative semantics

[CONFORMANCE_CLASSES.md](CONFORMANCE_CLASSES.md) is the normative class text,
already consolidated from accepted decisions before this beta implementation.

| Class | Exactly what it adds |
|---|---|
| AIREP-Core | Schema validity and internal tagged-hash consistency; neither provenance nor freshness |
| AIREP-Authenticated | Authorship under a verifier-accepted key binding and current revocation policy |
| AIREP-Witnessed | Authenticated chain head plus independent signed head anchoring, freshness and non-truncation **relative to that anchor** |

No class provides truth assurance. A self-declared key cannot independently
establish Authenticated. Missing/malformed operator prerequisites are WITHHELD,
not passed. Revoked producer binding caps the result at Core; revoked witness
binding prevents Witnessed. No backdated record timestamp restores a revoked key.

Witness independence requires distinct accepted identities, different resolved
public keys, and explicit verifier policy accepting the relation. Its signed
`witnessed_at` is checked against operator `now` and window using the frozen
inclusive predicate; unsigned freshness fields confer nothing. Witnesses are
optional for producing or authenticating artifacts. No beta-generated file
constitutes an externally independent witness merely because it uses another key.

FAILURE, WITHHELD and CAVEAT retain their adopted meanings and separate channels.
Profile `NOT_EVALUATED`, reconciliation MISSING/NOT_EVALUATED/INDETERMINATE and
explicit failures MUST NOT be collapsed into success. No receipt does not prove
non-delivery; no Execution does not prove non-execution; no Effect does not prove
no effect. No lifecycle reconciliation result is a fourth assurance class.

## 8. Producer, verifier and reconciliation conformance

A conforming producer MUST construct all required fields, use admissible JSON,
bind real declared digests, compute the frozen integrity material, sign with
Ed25519, maintain identity/ordering/linkage and produce schema-valid artifacts.
It MUST NOT fabricate success from missing observations. The reference API
validates an emission before advancing its cursor; its CLI refuses file overwrite.
Caller-supplied reports, keys, identifiers and external byte capture remain the
caller's responsibility. A cursor is single-writer, not a concurrent ledger.

A conforming beta verifier MUST enforce AD-17 before parser collapse, then
evaluate the accepted Core and class gates. The r3 result includes every profile
identifier, its evaluation state/basis digest, and the registry-file digest.
The [beta adapters](../../../tools/airep_v02/) preserve historical r1 engines
for reproduction while applying the new admission/profile surface. They also
enforce that observer independence resolves an actual, uniquely identified
Execution. This closes a demonstrated implementation defect; it does not create
a new class rule. No historical measurement is rescored.

A beta reconciler MUST implement [RECONCILIATION.md](RECONCILIATION.md), retaining
per-record assurance and named facts, missing evidence, contradictions and
unevaluated prerequisites. It MUST assess each instruction and each Execution's
Effect coverage independently; multiple-target coverage needs an explicit target
inventory. The shipped tool leaves that total-coverage check NOT_EVALUATED.

Conformance includes frozen integrity vectors and negatives, both schema engines,
historical class expectations, producer→verifier round trips across all four
families, domain/version/key/tamper failures, and the lifecycle negative corpus.
The [readiness evidence](BETA_READINESS.md) links commands and observed results.
Same-author Python/Node beta adapter agreement is regression evidence, not
independent interoperability or a proof of semantic correctness.

## 9. Scope and release stages

This beta supplies first-party production, verification, a complete runnable
lifecycle, profile-basis evaluation, reconciliation and implementation docs.
It does not certify truth, deployment security, authority correctness, complete
real-world histories, independent observation, or cross-deployment interoperability.

One qualified external v0.2 consumer/verifier result exists against the earlier
r1/handoff basis (17 AGREE / 1 DISAGREE; not expected-blind); see
[EXTERNAL_EVIDENCE.md](../../../EXTERNAL_EVIDENCE.md). Emek's v0.1.2 producer
result remains a separate version and evidence class. No same-version
third-party v0.2 producer→consumer result exists. Neither is promoted by this beta.

Independent v0.2 producer/consumer interoperability, external-standard E2E
exercises, wire-freeze RC discipline, production HSM/KMS, hardware attestation,
migration tooling and expanded companion profiles remain outside this beta.
[RELEASE_STAGES.md](RELEASE_STAGES.md) preserves the stable independence gate and
records the correction to AD-01's earlier migration-tooling sequencing.
