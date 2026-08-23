# AIREP v0.2 — Artifact Schema Design Contract (Stage 1)

> **Status: DESIGN CONTRACT for maintainer review — no JSON Schema exists yet.** This document
> fixes the common wire shape of the four v0.2 artifact families before any `.schema.json` is
> written, so the four schemas cannot drift from each other and every field has one traceable
> justification. Nothing here is normative until accepted. Every formerly open choice is now
> an **explicit maintainer decision** (§9, decided 2026-08-23) — none was made silently by
> implementation.
>
> **Authoritative inputs (only these):** the adopted architecture decisions AD-02..AD-14
> (esp. AD-03..AD-07), the frozen [`../INTEGRITY.md`](../INTEGRITY.md), the accepted migration
> semantics ([`../../v0.2-design/MIGRATION.md`](../../v0.2-design/MIGRATION.md)), and the v0.1
> wire surface (`../../v0.1/core.schema.json`) as a compatibility/migration reference only.
> Stage-4 fixture envelopes, verifier result envelopes, and evidence-harness structures are
> **test-harness objects and are deliberately NOT carried into this wire design.**

## 1. Frozen bindings (expressed, never redesigned)

The schemas will *express* the following and may not alter any of it. Where a constraint is
not schema-enforceable, the decision matrix (§5) says so and names the semantic verifier
obligation instead — a schema pass is never presented as cryptographic validity:

- top-level `airep_version` — exactly `"0.2"` (const);
- top-level `artifact_type` — per-family exact const (`decision` / `control` / `execution` / `effect`);
- `chain_id`, `record_id` (globally collision-resistant), `sequence` identity/ordering
  semantics per AD-05; cross-artifact references via global `record_id` or qualified
  `{chain_id, record_id}`;
- `integrity.previous` / `integrity.current` / `integrity.signature` members and the WP-α01
  hash/signature construction, domain tags, binding-derived suite semantics, informative-only
  wire `alg` label, witness construction, and fail-closed/no-fallback behavior (frozen
  INTEGRITY §§1–7);
- the assurance boundary: schema validation confers no Core/Authenticated/Witnessed class, no
  signature validity, no provenance, no evidence truth (§8).

## 2. Common core shape (proposed)

Every artifact of every family carries this common core; family-specific members are added on
top (§3). All objects below are **closed** (§6).

```
{
  "airep_version":  "0.2",                       // const
  "artifact_type":  "<family const>",
  "chain_id":       <string>,                    // globally collision-resistant, signed content
  "record_id":      <string>,                    // globally collision-resistant, signed content
  "sequence":       <non-negative safe integer>, // monotonic within the chain
  "subject": {                                    // who produced this artifact
    "producer":      <string>,                    // required
    "timestamp_utc": <string>,                    // required; format = ODQ-6
    "runtime":       <string>,                    // optional (v0.1 carry; see ODQ-4)
    "principal":     { ... }                      // optional; v0.1 principal + established_by carried forward unchanged
  },
  "scope": {                                      // honest scope — the project's core thesis
    "covers":         [<string>...],
    "does_not_cover": [<string>...]               // stays mandatory (adopted baseline)
  },
  "integrity": {
    "previous":  "sha256:<64 lowhex>",            // genesis = sha256: + 64 zeros
    "current":   "sha256:<64 lowhex>",
    "signature": { "alg": <string>, "value": <128 lowercase hex> }  // alg = informative label only
  },
  "profiles": { "<namespaced-id>": { ... }, ... } // optional; the ONLY extension surface
}
```

Notes: `sequence` is ordering, `record_id` is identity — never conflated (AD-05).
`subject.principal` — member vocabulary and `established_by` semantics retained from v0.1
(`asserted_by_caller` … `not_established`); **v0.2 closure applied**, and when `principal` is
present `established_by` is required (ODQ-4). **Signature wire encoding is an explicit
maintainer decision (2026-08-23), not an implementation default:** `integrity.signature.value`
is exactly the 64-byte Ed25519 signature as **128 lowercase hex characters**, pattern
`^[0-9a-f]{128}$` — the frozen text defines what is signed, this decision pins how the bytes
ride the wire; the v0.2 suite registry contains only `ed25519`, and a future suite is a
spec/version change. The v0.1 members `decision_index` (superseded by `sequence`) and
`integrity.canonical_json` (redundant — the v0.2 normative construction mandates JCS) are
**dropped** — ODQ-5.

## 3. Per-family members and the field-difference matrix

| Member | decision | control | execution | effect | Rationale (source) |
|---|:---:|:---:|:---:|:---:|---|
| `input {input_ref, input_digest, digest_projection?}` | **req** | — | — | — | AD-06: required input digest **with named-projection semantics carried on the wire** (final hardening, 2026-08-23): `digest_projection` is an optional **namespaced identifier string** (grammar below). Absent ⇒ `input_digest` binds the full governed-input bytes; present ⇒ it binds the output of the named projection rule. Schema validates the name/pattern only; that the rule exists and the digest was produced by it is semantic verifier / projection tooling work. AD-06's "named projection" thereby never depends on profiles for core-digest interpretation. `governance_state` REMOVED from neutral core (maintainer, 2026-08-23): it was the one open object AD-07 could not close; policy basis lives in `claim.basis`/`directive.policy_basis`/evidence refs, deployment state goes to profiles |
| `claim {assertion, basis}` | **req** | — | — | — | governance decision semantics (v0.1 lineage) |
| `directive {verb, policy_basis}` | **req** | — | — | — | v0.1 lineage; closed verb enum carried (ODQ-8) |
| `output {result_ref, result_digest, redacted?}` | **req** | — | — | — | AD-06: required `result_digest`; v0.1 `output.redacted` RETAINED as optional boolean — **no JSON Schema `default`** (default materialization invites hash-preimage-divergent tooling behavior) |
| `evidence[] {type, ref, resolvable, content_hash}` | **req** | opt | opt | opt | AD-06; `content_hash` required on every item wherever the array appears (ODQ-9) |
| `decision_ref` (cross-artifact reference) | — | **req** | **req** | **req** | AD-03/AD-05: every evidence artifact answers a decision; shape per ODQ-10 |
| `instruction_id` / `instruction_digest` | — | **req** | **req** | — | AD-03 correlation keys; v0.1 `control_delivery` lineage (`instruction_hash` renamed for digest-vocabulary consistency — §7). Effect's duplicate correlation members REMOVED — `execution_ref` is the explicit join |
| `control_event` (`dispatched` \| `received` \| `delivery_failed`) | — | **req** | — | — | AD-03: two-sided boundary evidence; `delivery_failed` stays a positive fact |
| `boundary_side` (`issuer` \| `receiver`) | — | **req** | — | — | two-sided lifecycle needs the reporting side explicit |
| `authority { issuer_id?, writable_by_controlled_system }` | — | **req** | — | — | retained invariant; **Control Evidence ONLY** (maintainer, 2026-08-23) — exact closed shape; not a core member of any other family |
| `execution_event` (`executed` \| `failed` \| `suppressed`) | — | — | **req** | — | AD-03; `executed` replaces `completed` (maintainer): Execution answers whether the action ran — material success is Effect Evidence's question, and `completed` invited that confusion |
| `authorized_action_digest` | — | **req** | — | — | **TOCTOU placement (maintainer, 2026-08-23):** what was authorized is the CONTROL side's statement |
| `executed_action_digest` | — | — | **req** | — | what actually ran is the EXECUTOR's statement; the AD-03 mechanical TOCTOU check is the cross-artifact reconciliation of these two digests from two different evidence producers — never co-located in one artifact |
| `observer_relationship` (`same_executor` \| `independent` \| `unknown`) | — | — | — | **req** | AD-03 (rounds 1–2): closed enum, exactly these three; producer-declared at Core, verified-independence at Authenticated+ (semantic verifier, not schema) |
| `execution_ref` (cross-artifact reference) | — | — | — | **req** | effect answers an execution |
| `observed_state { description, state_digest? }` | — | — | — | **req** | what was observed, bindable to bytes |

**Decided family spine** (maintainer, 2026-08-23):

- **Decision:** `input` + `claim` + `directive` + `output` + required `evidence[]` with hashes.
- **Control:** `decision_ref` + `instruction_id` + `instruction_digest` + `authorized_action_digest` + `control_event` + `boundary_side` + `authority`.
- **Execution:** `decision_ref` + `instruction_id` + `instruction_digest` + `executed_action_digest` + `execution_event`.
- **Effect:** `decision_ref` + `execution_ref` + `observer_relationship` + `observed_state`.

`evidence[]` is required on Decision, optional on the other three families; wherever an
evidence item appears it carries `content_hash` (ODQ-9).

Everything else is common core (§2). No family adds free-form members: anything not in this
matrix or §2 lives under `profiles` with a namespaced id (§6). The AD-11 authorization
reference and AD-10 SCITT anchor material are **profiles**, not core members, per the adopted
architecture.

## 4. What the schema proves — and does not

Schema-enforceable (structure): member presence/absence, closure, consts, enums, string
patterns (e.g. `^sha256:[0-9a-f]{64}$`), JSON types, safe-integer bounds **as parsed values**.

NOT schema-enforceable (semantic verifier obligations, already implemented by the WP-α01
integrity verifiers or deferred to class semantics): hash recomputation under the domain tag;
signature validity under binding-derived suites; the **lexical** no-sign/no-fraction/no-exponent
constraint on **witness-claim integers** (JSON Schema sees parsed values — WP-α01's lexeme
lesson; per ODQ-13 this lexical rule stays witness-claim-specific and is not carried to
artifact-level `sequence`); `witnessed_at` and `timestamp_utc` Gregorian calendar validity;
cross-artifact reference resolution and digest reconciliation (the TOCTOU equality of
Control's `authorized_action_digest` against Execution's `executed_action_digest` — two
artifacts, two producers); observer-independence verification; witness key
independence/revocation (conformance-class carry-forward, §8).

## 5. Decision matrix (per field)

Columns: `field/path | families | req/opt | JSON type | closed/open | normative source |
schema-enforceable? | semantic verifier required?`

| field/path | families | req | JSON type | closure | source | schema? | semantic verifier? |
|---|---|---|---|---|---|---|---|
| `airep_version` | all | req | string const `"0.2"` | closed | frozen §5 | yes | tag derivation uses it (frozen) |
| `artifact_type` | all | req | string const per family | closed | frozen §5 | yes | tag derivation uses it (frozen) |
| `chain_id` | all | req | string | closed | AD-05 | type only | collision-resistance not provable |
| `record_id` | all | req | string | closed | AD-05 | type only | global uniqueness not provable |
| `sequence` | all | req | integer 0..2^53−1 | closed | AD-05; frozen §2; ODQ-13 | value bounds (parsed value) | — (lexical rule NOT carried to artifact level, ODQ-13) |
| `subject.producer` | all | req | string | closed | v0.1 lineage | yes | identity truth: no |
| `subject.timestamp_utc` | all | req | string, `YYYY-MM-DDTHH:MM:SS(.1-9 digits)?Z` (ODQ-6) | closed | v0.1 lineage; ODQ-6 | pattern | calendar validity: verifier |
| `subject.principal.*` | all | opt | object (v0.1 shape) | closed | v0.1 STATUS §5, carried | yes | `established_by` truth: no |
| `scope.covers` / `scope.does_not_cover` | all | req | array of string | closed | adopted baseline | yes | content truth: no |
| `integrity.previous` / `current` | all | req | `sha256:` pattern | closed | frozen §2 | pattern | recomputation: verifier |
| `integrity.signature.alg` | all | req | non-empty string, NO enum | closed | frozen §3.2; ODQ-7 | presence only | MUST NOT drive verification |
| `integrity.signature.value` | all | req | `^[0-9a-f]{128}$` (Ed25519, maintainer decision) | closed | frozen §3 + wire-encoding decision | pattern | validity: verifier |
| `profiles.*` | all | opt | object, namespaced keys | keys patterned; values profile-owned | AD-07 | key pattern | profile semantics: per profile |
| `input.input_digest` | decision | req | `sha256:` pattern (ODQ-11) | closed | AD-06 | pattern | digest-of-what: verifier/projection rule |
| `input.digest_projection` | decision | opt | namespaced-id string (exact grammar below) | closed | AD-06 (final hardening) | pattern | projection-rule existence + digest provenance: verifier/tooling |
| `output.result_digest` | decision | req | `sha256:` pattern (ODQ-11) | closed | AD-06 | pattern | idem |
| `evidence[].content_hash` | all (item-level, wherever `evidence[]` appears) | req | `sha256:` pattern | closed | AD-06; ODQ-9 | pattern | byte binding: verifier |
| `output.redacted` | decision | opt | boolean, **no schema default** | closed | v0.1 retained (maintainer) | yes | — |
| `decision_ref` | ctrl/exec/effect | req | reference object (ODQ-10) | closed | AD-03/05 | shape | resolution: verifier |
| `instruction_id` / `instruction_digest` | ctrl/exec | req | string / pattern | closed | AD-03 | yes/pattern | correlation: verifier |
| `control_event`, `boundary_side` | control | req | closed enums | closed | AD-03 | yes | event truth: no |
| `authority {issuer_id?, writable_by_controlled_system}` | control ONLY | req | closed object; boolean req | closed | adopted baseline (maintainer: exact shape) | yes | authority truth: no |
| `execution_event` | execution | req | enum `executed\|failed\|suppressed` | closed | AD-03 (maintainer: `executed` not `completed`) | yes | outcome truth: no |
| `authorized_action_digest` | control | req | `sha256:` pattern | closed | AD-03 TOCTOU (maintainer placement) | pattern | **cross-artifact equality: verifier** |
| `executed_action_digest` | execution | req | `sha256:` pattern | closed | AD-03 TOCTOU (maintainer placement) | pattern | **cross-artifact equality: verifier** |
| `observer_relationship` | effect | req | enum `same_executor\|independent\|unknown` | closed | AD-03 r1–2 | yes | **independence: verifier at Auth+** |
| `execution_ref` | effect | req | reference object (ODQ-10) | closed | AD-03 | shape | resolution: verifier |
| `observed_state.state_digest` | effect | opt | `sha256:` pattern | closed | design | pattern | binding: verifier |

## 6. Closure discipline (AD-07 made concrete)

- **Closed** (`additionalProperties: false` or the 2020-12 equivalent, per ODQ-1/ODQ-3): the
  artifact top level, `subject`, `subject.principal`, `scope`, `integrity`,
  `integrity.signature`, `input`, `claim`, `output`, `directive`, `authority`,
  `observed_state`, each `evidence[]` item, every family-specific object above, and every
  cross-artifact reference object. There is no open object left in core — `governance_state`,
  the one v0.1 object that could not be closed, is removed (§3, §7).
- **The single extension surface** is `profiles`: an object whose keys match a namespaced
  identifier pattern (representation → ODQ-12) and whose values are profile-owned objects.
  Core neutrality is mechanical: strip `profiles` and the artifact still validates.
- No other open object exists anywhere in core; there is no path to add a core member without
  a spec change.

## 7. v0.1 compatibility: deliberate breaks and retained points

**Deliberate breaks** (restated for traceability; all adopted or decided at maintainer
review): one-record-does-everything → four families; `decision_index` → `sequence` + new
`chain_id`/`record_id`; open sub-objects → closed everywhere; optional digests → required
`input_digest`/`result_digest` + universal `evidence[].content_hash` (ODQ-9); untagged
hash/signature → WP-α01 construction; `control_delivery` profile events → first-class
Control/Execution/Effect artifacts; `instruction_hash` → `instruction_digest` (vocabulary
consistency; same value semantics); `canonical_json` dropped (ODQ-5);
**`input.governance_state` REMOVED from neutral core** (maintainer, 2026-08-23 — the only
uncloseable v0.1 object; deployment-specific state moves to profiles; recorded in
BREAKING_CHANGES and the migration mapping).

**Retained:** `scope.does_not_cover` mandatory; `subject.principal` member vocabulary and
`established_by` semantics (v0.2 closure applied); `authority.writable_by_controlled_system`
(now in its exact closed Control-only shape); `delivery_failed` as a positive fact;
`output.redacted` optional boolean (no schema default); the `profiles`
single-extension-point pattern; genesis `previous` value; `sha256:<64 lowhex>` string form;
the v0.1 directive verb enum (ODQ-8).

**v0.1 lineage preservation rule (final hardening, 2026-08-23 — binding on the schema
author):** *v0.1-lineage member type/enum/cardinality constraints that this design contract
does not explicitly change are preserved in v0.2; AD-07 closure and this contract's explicit
decisions apply on top of them.* Verified examples of what this carries: `claim.basis` array
of string with `minItems: 1`; the closed `evidence[].type` enum (`retrieval` / `tool_call` /
`memory` / `policy` / `human_approval` / `external_url` / `eval` / `other`); the
`scope.covers`/`does_not_cover` array-of-string shapes. An explicitly decided change (e.g.
dropping `output.redacted`'s v0.1 `default: false`) wins over the carried constraint. The
schema author makes no new constraint decisions under this rule — anything neither carried
nor explicitly decided is a question back to the maintainer, not an implementation choice.

## 8. Assurance boundary (unchanged)

Schema validation confers **no** assurance class, no signature validity, no provenance, no
evidence truth. Conformance-class semantics are out of scope for this phase, and the
carry-forward stands: **witness key independence + revocation assurance semantics** return
when the conformance-class text opens; neither leaks into schema language as an assurance
claim.

## 9. DESIGN DECISIONS (ODQ-1..15 — decided by maintainer review, 2026-08-23)

Every former open question is now closed by an explicit maintainer decision; none was decided
by implementation default:

| # | Decision |
|---|---|
| ODQ-1 | **ADOPT: JSON Schema 2020-12** (`$schema` accordingly); compatible with the v0.1 surface. |
| ODQ-2 | **ADOPT:** repo-style canonical raw URLs for `$id`; `$ref`s relative wherever possible; content reproducibility is pinned by release tag/SHA, never by `$id`. |
| ODQ-3 | **ADOPT WITH CONSTRAINT:** `common.schema.json` + 4 family entry schemas. The common file is NOT a standalone artifact validator — it carries `$defs`/base constraints only; each family entry schema owns its top-level closure, and composition MUST NOT let the common base accidentally reject family-specific members. |
| ODQ-4 | **MODIFIED:** `producer` + `timestamp_utc` required; `runtime` optional; `principal` optional — **but when `principal` is present, `established_by` is required**. Principal member vocabulary and `established_by` semantics retained from v0.1; **v0.2 closure applied** (the object is closed). `trace_id` is NOT a core member — OTel correlation stays in the AD-12 profile. |
| ODQ-5 | **ADOPT DROP** of `integrity.canonical_json` and `decision_index`. Corrected rationale: the domain tag does not "attest" JCS — `canonical_json` is redundant **because the v0.2 normative construction mandates JCS**; `sequence` supersedes the index. Migration projection maps both per MIGRATION. |
| ODQ-6 | **REJECT the witness grammar for core timestamps.** Adopted format: `YYYY-MM-DDTHH:MM:SS` + **optional 1–9 fractional digits** + literal `Z`; no leap second; no offsets. **Exact structural pattern (final hardening, 2026-08-23 — implementers invent no regex):** `^[0-9]{4}-(?:0[1-9]\|1[0-2])-(?:0[1-9]\|[12][0-9]\|3[01])T(?:[01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$` — structural only; Gregorian-invalid combinations (e.g. `2026-02-30`) are rejected by semantic validation, not schema. Rationale: fast runtime events must not lose sub-second information; the second-only rule is witness-claim-specific (frozen §4.2) and is not generalized. |
| ODQ-7 | **ADOPT:** `integrity.signature.alg` required, non-empty string, **no enum** — the wire label is informative-only (frozen §3.2) and the schema must not turn it into a crypto selector. |
| ODQ-8 | **ADOPT:** v0.1 closed verb enum unchanged: `release` / `block` / `defer` / `redact` / `escalate_to_human` / `kill`. |
| ODQ-9 | **ADOPT: schema-required always.** Every `evidence[]` item, wherever it appears, carries `content_hash`. Presence is a Core wire requirement; hash correctness / authenticated assurance remain verifier/class matters. Consistent with MIGRATION's universal `evidence[].content_hash`; BREAKING_CHANGES row 6 updated to record the schema-phase decision (SCHEMA as well as CLASS). |
| ODQ-10 | **ADOPT:** closed reference object `{"record_id": <string, required>, "chain_id": <string, optional>}`. No bare-sequence references, ever (AD-05). |
| ODQ-11 | **ADOPT:** every v0.2 digest field matches `^sha256:[0-9a-f]{64}$`. Algorithm agility is a future wire-version change. |
| ODQ-12 | **ADOPT: flat dotted keys** with **at least two namespace segments**. **Exact namespaced-id grammar (final hardening, 2026-08-23; also governs `input.digest_projection`):** `^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$` — lowercase ASCII; each segment starts with a letter and continues with lowercase letters/digits/hyphens; `airep.migration` passes, a single segment does not. The AIREP-owned migration profile's real key is `airep.migration` (`profiles.airep.migration` is the prose path). The registered short-name registry starts EMPTY; adding a short name is a schema/spec change (AD-07). |
| ODQ-13 | **ADOPT:** artifact-level `sequence` = integer in 0..2^53−1 as a **parsed-value constraint only**. The WP-α01 lexical-token rule (`no sign/fraction/exponent` on the source spelling) is **witness-claim-specific** (frozen §4.2) and is NOT carried to the artifact-level member. |
| ODQ-14 | **ADOPT:** `null` is never valid anywhere in core; optionality = absence. |
| ODQ-15 | **ADOPT:** unknown top-level members rejected; no forward-compatibility escape hatch; extension only via `profiles`. |

## 10. Deliverable gate

This document is the whole Stage-1 deliverable. No `.schema.json`, no validators, no
producers exist or will be written before the maintainer verdict
(`ARTIFACT_SCHEMA_DESIGN_ACCEPTED — SCHEMA IMPLEMENTATION AUTHORIZED`). All fifteen design
questions and the six wire-level placements (TOCTOU digest split, Control-only `authority`,
`governance_state` removal, signature wire encoding, `output.redacted` retention, execution
enum) are maintainer decisions recorded in §3/§9 — implementation expresses them, it does not
revisit them.
