# AIREP v0.2 — Architecture Decisions

> Status: **Design.** Each decision below is marked `Adopted (process)`, `Proposed`, or `Open`.
> `Proposed` means the design position is written down for review and is not yet binding on any
> schema or implementation. Nothing here changes v0.1, which is frozen (see
> [`README.md`](./README.md)).
>
> External documents are cited with their verified status as of 2026-08-22. Internet-Drafts are
> work in progress, may change or expire, and are not standards; they are cited as landscape
> evidence, never as dependencies.

## The landscape facts these decisions respond to

Verified against primary sources on 2026-08-22:

- **RFC 9943** (June 2026, Proposed Standard) defines the SCITT architecture: signed statements
  registered with transparency services, append-only logs, verifiable receipts.
- **draft-noa-scitt-ai-agent-receipt-01** (2026-08-15, individual submission, not an IETF product)
  profiles SCITT for signed, offline-verifiable AI-agent action receipts.
- **OpenID AuthZEN Authorization API 1.0** (published 2026-08-20, Standards Track) standardises
  the PDP/PEP authorization decision interface.
- **draft-mcguinness-mission-runtime-evidence** (2026-08-22, individual submission) separates
  Decision Evidence, Execution Evidence, Refusal Records, and Mission Receipts, and states that
  auditors MUST NOT treat decision evidence alone as evidence of action.
- **NIST AI Agent Standards Initiative** (announced 2026-02-17) is driving standards work on agent
  identity, authorization, and secure interoperability.

Consequence: a generic "signed AI decision receipt" is no longer a defensible distinguishing
contribution — several efforts now produce one. What remains structurally unoccupied, and what
AIREP's existing `control_delivery` work already models, is the **decision-to-effect assurance
gap**: evidence that a governance decision was delivered to its enforcement point, executed, and
had its intended observable effect — with each step recorded as separate, correlatable,
independently verifiable evidence. The decisions below narrow AIREP onto that gap.

---

## AD-01 — v0.1 freeze and staged v0.2 release line

**Status: Adopted (process).**

v0.1 is frozen: documentation-correctness and security fixes only; no wire, schema, or
conformance-semantics change. v0.2 proceeds through explicit stages: `design` (this directory) →
`alpha` (schema + verifiers + migration tooling) → **interoperability gate** (≥2 producers, a
cross-implementation corpus, external-standard mappings exercised) → **independence gate**
(genuinely third-party production or reproduction) → `stable`. No stage is skipped, and the
"stable" label is not used before both gates pass.

**Consequence:** breaking design work happens here instead of as incremental v0.1 patches, so
published v0.1 chains and citations stay stable.

## AD-02 — Thesis: composition, not reinvention

**Status: Proposed.**

AIREP v0.2 is a vendor-neutral evidence interchange protocol for cryptographically binding AI
runtime governance decisions to control delivery, execution, and observed effects, composing with
external identity, authorization, telemetry, and transparency standards.

Explicit **non-goals**, each owned by an adjacent layer:

| Concern | Owned by | AIREP's relationship |
|---|---|---|
| Authorization decisions | OAuth 2.x, OpenID AuthZEN | Record and reference them (AD-11) |
| Agent identity / delegation | OAuth delegation work, NIST agent-identity work | Reference, with `established_by` provenance |
| Agent communication / execution transport | MCP, A2A | Correlate via profile mappings (AD-12) |
| Telemetry | OpenTelemetry | Correlate via `trace_id` (AD-12) |
| Transparency / inclusion / append-only logging | SCITT (RFC 9943) | Project into and cite receipts from (AD-10) |

**Consequence:** v0.2 removes or re-scopes anything in v0.1 that duplicates an adjacent layer, and
adds nothing that does. Growth of the profile catalogue is not a goal; precision of the core is.

## AD-03 — Separate the record family: decision, control, execution, effect

**Status: Proposed.** The central structural change of v0.2.

v0.1 has one core record ("one AI runtime governance decision") and pushes the
`issued → delivered → acknowledged → enforced → observed` lifecycle into the `control_delivery`
profile of decision-shaped records. But an enforcement point acknowledging receipt is not a
governance decision, and an observer reporting a state change is not a governance decision.
Forcing those events into decision semantics manufactures artificial `claim` / `directive` /
`output` content — a semantic defect, not a style issue.

v0.2 defines a small **family of evidence artifacts**:

| Artifact | Question it answers | Typical producer |
|---|---|---|
| **Decision Receipt** (core) | Who decided what, under which authority, on which input and policy? | The governing runtime |
| **Control Evidence** | Was the control instruction dispatched, and did the enforcement point receive it? | Both sides of the boundary |
| **Execution Evidence** | Was the authorized action actually executed, with which parameters? | The executing component |
| **Effect Evidence** | Was the intended material/system effect independently observed? | An observer distinct from the executor |

Correlation is by explicit keys, not by co-location in one record: `decision_id`,
`instruction_id`, `action_digest`, `principal` reference, `trace_id`, and `chain_id` (AD-05).
Equality of the **authorized** parameter digest and the **executed** parameter digest is the
TOCTOU check this structure exists to make mechanical.

This separation now has independent convergent design elsewhere
(draft-mcguinness-mission-runtime-evidence, cited above), which we read as evidence the cut is
correct — not as a claim of priority in either direction. AIREP's distinct contribution remains
the **two-sided boundary evidence** (`control_delivery`'s receiver-side records,
`authority.writable_by_controlled_system`, `delivery_failed` as a positive fact) and the
**reconciliation** across all four artifacts (AD-15's interop corpus must include
reconciliation cases).

**Consequence:** the v0.1 single-record shape becomes the Decision Receipt; lifecycle events move
out of `profiles` into first-class sibling artifacts. Wire-breaking; see `BREAKING_CHANGES.md`.

## AD-04 — One canonicalization, one hash domain

**Status: Proposed.** Resolves v0.1 open items 1–2 (STATUS.md).

v0.2 admits exactly one byte-level rule: **RFC 8785 (JCS)** canonicalization, hash computed over
the record **in place** (with `integrity.current` and `integrity.signature` removed,
`integrity.previous` and `chain_id` retained) — no wrapper object, no `ensure_ascii` /
`allow_nan` variance, no sorted-key `json.dumps` alternative. Producers that cannot emit JCS
cannot claim v0.2 conformance. Reference producers are aligned in the alpha stage, and the
conformance kit's existing cross-language JCS battery (`jcs.py` ↔ `verify.mjs`) becomes the
normative fixture set.

**Consequence:** every v0.2 hash differs from its v0.1 counterpart by construction. This is the
single largest reason v0.2 is a version bump and not a patch.

## AD-05 — Chain identity: `chain_id` and `record_id`

**Status: Proposed.**

v0.1 binds records to their predecessor (`previous`) but a chain has no signed name and a record
has no stable identifier; the threat model acknowledges the resulting relative-binding limits.
v0.2 requires on every artifact:

- `chain_id` — globally unique, chosen at chain genesis, **inside the signed/hashed content**;
- `record_id` — unique within the chain (chain_id + monotonic index, or UUID), also signed.

Cross-artifact correlation keys (AD-03) reference `record_id`s, so "the execution evidence for
decision X" is a resolvable link, not a text convention.

**Consequence:** required-field addition inside the hash domain — wire-breaking.

## AD-06 — Mandatory digests: input, result, evidence

**Status: Proposed.**

v0.1 requires `input.input_ref` and `output.result_ref` (references) but no digests, and
`evidence[].content_hash` is required only for `resolvable: false` entries at the Verified class.
A reference without a digest binds the record to a *name*, not to *bytes*.

v0.2: `input` carries a required digest of the governed input; `output` carries a required
`result_digest`; every `evidence[]` entry carries `content_hash` to earn the authenticated class
(AD-09), resolvable or not. Where the input is unbounded or privacy-constrained, the digest is
over a declared, named projection — and the projection rule itself is named in the record.

**Consequence:** required-field additions — wire-breaking.

## AD-07 — Close the core; extend only through namespaced profiles

**Status: Proposed.** Resolves v0.1 open item 4.

v0.1 closes the top level (`additionalProperties: false`) but every core sub-object —
`subject`, `input`, `claim`, `output`, `evidence[]`, `directive`, `scope`, `integrity`,
`integrity.signature` — is `additionalProperties: true`, so the block-level neutrality test proves
less than it appears to. v0.2 closes **all** core sub-objects. Extension happens in exactly one
place: `profiles`, keyed by a namespaced identifier (`<org>.<profile>` or a registered short
name). The neutrality test then proves field-level mechanical neutrality, not block-level only.

**Consequence:** any producer currently stowing vendor fields inside core sub-objects breaks —
intentionally. Wire-breaking.

## AD-08 — Asymmetric signature baseline

**Status: Proposed.**

v0.1 leaves `integrity.signature.alg` open and the Verified class explicitly admits
`HMAC-SHA256`. A symmetric MAC cannot establish authorship to a third party — any holder of the
key, including the verifier, can forge it — so a MAC-signed record cannot support portable
third-party assurance, which is AIREP's whole use case.

v0.2: the interchange baseline is an asymmetric signature; **Ed25519 is mandatory to implement**,
others (e.g. ECDSA P-256) optional. MAC-based integrity is relegated to an explicitly named
deployment-internal profile that can never earn the portable authenticated class. Key
representation and trust references align with the `key_trust` profile, and identity provenance
(`established_by`) carries over from v0.1's `subject.principal` design.

**Consequence:** class-semantics change; records signed with HMAC lose the authenticated class
under v0.2 rules. Assurance-breaking (not hash-breaking).

## AD-09 — Assurance-class vocabulary: retire "Trusted"

**Status: Proposed; final names Open (maintainer decision).**

AIREP's own threat model states that even the top class cannot stop a malicious producer writing a
false claim — the classes assure provenance, integrity, and freshness, never truth. The name
"Trusted" invites exactly the over-reading the threat model warns against, and a regulator or
procurement document citing "AIREP-Trusted" would likely read it as more than it is.

v0.2 renames the ladder to say what is actually established. Working candidate:

| v0.1 name | v0.2 candidate | Establishes |
|---|---|---|
| AIREP-Core | **Core** | Well-formed, hash-chained, untampered |
| AIREP-Verified | **Authenticated** | Authorship cryptographically established against a named key |
| AIREP-Trusted | **Witnessed** (alt: Externally Anchored) | Current, untruncated head, vouched by an independent witness / transparency log |

Whatever names are chosen, the normative text binds each to the sentence: *"provenance, integrity,
and freshness assurance only; not truth assurance."* The v0.1 fail-closed machinery
(`TRUSTED_NOT_IMPLEMENTED`, strict-mode gates, withheld-reason lists) carries over unchanged in
substance — an unevaluated prerequisite is never a satisfied one.

## AD-10 — Transparency via SCITT binding, not a homegrown stack

**Status: Proposed.**

v0.1's `chain_witness` profile is a local, offline head-witness mechanism. It stays — it serves
the network-free case. But AIREP does not grow it toward a transparency service: RFC 9943 defines
that layer. v0.2 adds a **SCITT binding profile**: an AIREP artifact (or chain head) is projected
to a signed statement, registered with a transparency service, and the returned receipt is
recorded as evidence in the AIREP chain. The alpha stage includes a proof-of-concept registration
and receipt verification against at least one SCITT implementation. Adjacent work
(draft-noa-scitt-ai-agent-receipt) suggests AIREP artifacts should be registrable with at most a
thin mapping; the PoC tests that.

**What SCITT does not give us** — and where AIREP remains necessary: a SCITT receipt proves a
statement was registered at a time; it does not prove the control was delivered, executed, or had
effect. Registration composes with, and does not replace, AD-03's evidence family.

## AD-11 — Authorization is referenced, never defined

**Status: Proposed.**

AIREP v0.2 defines an **authorization reference profile**: a Decision Receipt can carry a
reference to (and digest of) an external authorization decision — an AuthZEN Authorization API 1.0
decision, an OAuth token/delegation evidence artifact — including the PDP identity and the
decision's own identifier. AIREP records *that* an authorization decision was obtained and *binds
its bytes*; it never restates or reinterprets authorization semantics. The v0.1 `subject.principal`
block (with `established_by`) remains the identity-provenance anchor.

## AD-12 — MCP / A2A / OTel mappings are informative profiles

**Status: Proposed.**

Mappings for MCP (tool-call context), A2A (inter-agent task context), and OpenTelemetry
(`trace_id`/span correlation) are shipped as **informative profiles** with worked examples. None
becomes a dependency: an AIREP producer with no MCP, A2A, or OTel presence remains fully
conformant. Each mapping names the version of the external spec it was written against and is
re-checked, not assumed, when that spec revs.

## AD-13 — Regulatory crosswalk discipline

**Status: Proposed** (already partially practiced in v0.1).

Every regulatory or framework crosswalk (`eu_ai_act_log`, `nist_ai_rmf`, `owasp_threat`, and any
successor) carries three mandatory header fields: **source version/date**, **status**
(informative/indicative — never normative until validated against the primary text by a named
review), and an explicit **"what this does not cover"** list. The strings "compliant",
"compliance-ready", or equivalents do not appear. This is the documentation-ceiling rule already
used elsewhere in this repository, applied uniformly.

## AD-14 — Verifier parity is a release gate

**Status: Proposed.**

v0.1's two verifiers agree on structure, hashes, signatures, and class/withheld-reason sets, but
`verify.mjs` runs no profile-schema validation, so identical bytes can exit 0 under one verifier
and 1 under the other — a documented, real parity gap. For v0.2, at every stage from alpha
onward: both verifiers MUST produce the **same conformance verdict, the same class, the same
reason sets, and the same exit code** for every record in the shared corpus, including
profile-schema validation. Parity is enforced by CI over the corpus; a check implemented in one
verifier and not the other is a release blocker, not a footnote.

## AD-15 — Independence gate before "stable"

**Status: Adopted (process).**

v0.2 is not called stable until: (1) at least one producer implementation exists that was not
written by this repository's maintainers; (2) the cross-implementation corpus — including AD-03
reconciliation cases and at least one deliberately broken case per artifact type — passes under
both reference verifiers and the independent implementation; (3) the SCITT PoC (AD-10) and the
AuthZEN reference case (AD-11) have been exercised end-to-end at least once. Absence of prior
failure is not capability evidence; the gate demands observed results.

---

## Decision index

| AD | Title | Status | Wire-breaking |
|---|---|---|---|
| 01 | v0.1 freeze, staged release line | Adopted (process) | — |
| 02 | Composition thesis, non-goals | Proposed | — |
| 03 | Decision/control/execution/effect artifact family | Proposed | **Yes** |
| 04 | Single JCS canonicalization + in-place hash domain | Proposed | **Yes** |
| 05 | `chain_id` + `record_id` | Proposed | **Yes** |
| 06 | Mandatory input/result/evidence digests | Proposed | **Yes** |
| 07 | Core sub-object closure | Proposed | **Yes** |
| 08 | Asymmetric signature baseline | Proposed | Assurance-breaking |
| 09 | Retire "Trusted" naming | Proposed / names Open | Vocabulary |
| 10 | SCITT binding profile | Proposed | Additive |
| 11 | Authorization reference profile | Proposed | Additive |
| 12 | MCP/A2A/OTel informative profiles | Proposed | Additive |
| 13 | Crosswalk discipline | Proposed | — |
| 14 | Verifier parity gate | Proposed | — |
| 15 | Independence gate | Adopted (process) | — |
