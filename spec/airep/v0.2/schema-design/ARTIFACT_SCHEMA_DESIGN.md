# AIREP v0.2 — Artifact Schema Design Contract (Stage 1)

> **Status: DESIGN CONTRACT for maintainer review — no JSON Schema exists yet.** This document
> fixes the common wire shape of the four v0.2 artifact families before any `.schema.json` is
> written, so the four schemas cannot drift from each other and every field has one traceable
> justification. Nothing here is normative until accepted; every open choice is an explicit
> OPEN DESIGN QUESTION (§9), not a silent implementation decision.
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
    "signature": { "alg": <string>, "value": <hex string> }   // alg = informative label only
  },
  "profiles": { "<namespaced-id>": { ... }, ... } // optional; the ONLY extension surface
}
```

Notes: `sequence` is ordering, `record_id` is identity — never conflated (AD-05).
`subject.principal` keeps the v0.1 design verbatim (identity provenance via `established_by`;
`asserted_by_caller` … `not_established`) — it was praised at architecture review and nothing
in v0.2 changes it. The v0.1 members `decision_index` (superseded by `sequence`) and
`integrity.canonical_json` (superseded by the domain tag, which encodes the canonicalization
in the signed bytes) are proposed **dropped** — ODQ-5.

## 3. Per-family members and the field-difference matrix

| Member | decision | control | execution | effect | Rationale (source) |
|---|:---:|:---:|:---:|:---:|---|
| `input {input_ref, input_digest, governance_state?}` | **req** | — | — | — | AD-06: required input digest; v0.1 lineage |
| `claim {assertion, basis}` | **req** | — | — | — | governance decision semantics (v0.1 lineage) |
| `directive {verb, policy_basis}` | **req** | — | — | — | v0.1 lineage; closed verb enum carried (ODQ-8) |
| `output {result_ref, result_digest}` | **req** | — | — | — | AD-06: required `result_digest` |
| `evidence[] {type, ref, resolvable, content_hash}` | **req** | opt | opt | opt | AD-06; `content_hash` universality → ODQ-9 |
| `decision_ref` (cross-artifact reference) | — | **req** | **req** | **req** | AD-03/AD-05: every evidence artifact answers a decision; shape → ODQ-10 |
| `instruction_id` / `instruction_digest` | — | **req** | **req** | opt | AD-03 correlation keys; v0.1 `control_delivery` lineage (`instruction_hash` renamed for digest-vocabulary consistency — §7) |
| `control_event` (`dispatched` \| `received` \| `delivery_failed`) | — | **req** | — | — | AD-03: two-sided boundary evidence; `delivery_failed` stays a positive fact |
| `boundary_side` (`issuer` \| `receiver`) | — | **req** | — | — | two-sided lifecycle needs the reporting side explicit |
| `authority { writable_by_controlled_system, ... }` | — | **req** | opt | — | retained invariant (adopted baseline: "does not weaken") |
| `execution_event` (`completed` \| `failed` \| `suppressed`) | — | — | **req** | — | AD-03: execution outcome is evidence either way |
| `executed_action_digest` | — | — | **req** | — | AD-03 TOCTOU: authorized vs executed digest equality is the mechanical check |
| `authorized_action_digest` | — | opt | **req** | — | the other half of the TOCTOU pair (from the decision/control side) |
| `observer_relationship` (`same_executor` \| `independent` \| `unknown`) | — | — | — | **req** | AD-03 (rounds 1–2): closed enum, exactly these three; producer-declared at Core, verified-independence at Authenticated+ (semantic verifier, not schema) |
| `execution_ref` (cross-artifact reference) | — | — | — | **req** | effect answers an execution |
| `observed_state { description, state_digest? }` | — | — | — | **req** | what was observed, bindable to bytes |

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
constraint on integers (JSON Schema sees parsed values — WP-α01's lexeme lesson); `witnessed_at`
Gregorian calendar validity; cross-artifact reference resolution and digest reconciliation
(TOCTOU equality); observer-independence verification; witness key independence/revocation
(conformance-class carry-forward, §8).

## 5. Decision matrix (per field)

Columns: `field/path | families | req/opt | JSON type | closed/open | normative source |
schema-enforceable? | semantic verifier required?`

| field/path | families | req | JSON type | closure | source | schema? | semantic verifier? |
|---|---|---|---|---|---|---|---|
| `airep_version` | all | req | string const `"0.2"` | closed | frozen §5 | yes | tag derivation uses it (frozen) |
| `artifact_type` | all | req | string const per family | closed | frozen §5 | yes | tag derivation uses it (frozen) |
| `chain_id` | all | req | string | closed | AD-05 | type only | collision-resistance not provable |
| `record_id` | all | req | string | closed | AD-05 | type only | global uniqueness not provable |
| `sequence` | all | req | integer 0..2^53−1 | closed | AD-05; frozen §2 | value bounds only | **lexical spelling: verifier** |
| `subject.producer` | all | req | string | closed | v0.1 lineage | yes | identity truth: no |
| `subject.timestamp_utc` | all | req | string (ODQ-6 format) | closed | v0.1 lineage | pattern | calendar validity: verifier |
| `subject.principal.*` | all | opt | object (v0.1 shape) | closed | v0.1 STATUS §5, carried | yes | `established_by` truth: no |
| `scope.covers` / `scope.does_not_cover` | all | req | array of string | closed | adopted baseline | yes | content truth: no |
| `integrity.previous` / `current` | all | req | `sha256:` pattern | closed | frozen §2 | pattern | recomputation: verifier |
| `integrity.signature.alg` | all | ODQ-7 | string | closed | frozen §3.2 | presence only | MUST NOT drive verification |
| `integrity.signature.value` | all | req | hex string | closed | frozen §3 | pattern | validity: verifier |
| `profiles.*` | all | opt | object, namespaced keys | keys patterned; values profile-owned | AD-07 | key pattern | profile semantics: per profile |
| `input.input_digest` | decision | req | `sha256:` pattern (ODQ-11) | closed | AD-06 | pattern | digest-of-what: verifier/projection rule |
| `output.result_digest` | decision | req | `sha256:` pattern (ODQ-11) | closed | AD-06 | pattern | idem |
| `evidence[].content_hash` | decision (+opt others) | ODQ-9 | `sha256:` pattern | closed | AD-06 | pattern | byte binding: verifier |
| `decision_ref` | ctrl/exec/effect | req | reference object (ODQ-10) | closed | AD-03/05 | shape | resolution: verifier |
| `instruction_id` / `instruction_digest` | ctrl/exec | req | string / pattern | closed | AD-03 | yes/pattern | correlation: verifier |
| `control_event`, `boundary_side` | control | req | closed enums | closed | AD-03 | yes | event truth: no |
| `authority.writable_by_controlled_system` | control | req | boolean | closed | adopted baseline | yes | authority truth: no |
| `execution_event` | execution | req | closed enum | closed | AD-03 | yes | outcome truth: no |
| `authorized_action_digest` / `executed_action_digest` | execution | req | `sha256:` pattern | closed | AD-03 TOCTOU | pattern | **equality check: verifier** |
| `observer_relationship` | effect | req | enum `same_executor\|independent\|unknown` | closed | AD-03 r1–2 | yes | **independence: verifier at Auth+** |
| `execution_ref` | effect | req | reference object (ODQ-10) | closed | AD-03 | shape | resolution: verifier |
| `observed_state.state_digest` | effect | opt | `sha256:` pattern | closed | design | pattern | binding: verifier |

## 6. Closure discipline (AD-07 made concrete)

- **Closed** (`additionalProperties: false` or dialect equivalent): the artifact top level,
  `subject`, `subject.principal`, `scope`, `integrity`, `integrity.signature`, `input`,
  `claim`, `output`, `directive`, each `evidence[]` item, every family-specific object above,
  and every cross-artifact reference object.
- **The single extension surface** is `profiles`: an object whose keys match a namespaced
  identifier pattern (representation → ODQ-12) and whose values are profile-owned objects.
  Core neutrality is mechanical: strip `profiles` and the artifact still validates.
- No other open object exists anywhere in core; there is no path to add a core member without
  a spec change.

## 7. v0.1 compatibility: deliberate breaks and retained points

**Deliberate breaks** (all previously adopted as BREAKING; restated for traceability):
one-record-does-everything → four families; `decision_index` → `sequence` + new
`chain_id`/`record_id`; open sub-objects → closed everywhere; optional digests → required
`input_digest`/`result_digest` (+ `content_hash` per ODQ-9); untagged hash/signature → WP-α01
construction; `control_delivery` profile events → first-class Control/Execution/Effect
artifacts; `instruction_hash` → `instruction_digest` (vocabulary consistency; same value
semantics); `canonical_json` member proposed dropped (ODQ-5).

**Retained:** `scope.does_not_cover` mandatory; `subject.principal`+`established_by` verbatim;
`authority.writable_by_controlled_system`; `delivery_failed` as a positive fact; the
`profiles` single-extension-point pattern; genesis `previous` value; `sha256:<64 lowhex>`
string form.

## 8. Assurance boundary (unchanged)

Schema validation confers **no** assurance class, no signature validity, no provenance, no
evidence truth. Conformance-class semantics are out of scope for this phase, and the
carry-forward stands: **witness key independence + revocation assurance semantics** return
when the conformance-class text opens; neither leaks into schema language as an assurance
claim.

## 9. OPEN DESIGN QUESTIONS (reviewer decisions — none embedded in code)

| # | Question | Proposed answer + rationale |
|---|---|---|
| ODQ-1 | JSON Schema dialect / `$schema` | Propose draft 2020-12 (v0.1 used a modern draft; best `unevaluatedProperties` support for closure) — decision deferred |
| ODQ-2 | `$id` URI strategy | Propose canonical raw-repo URLs mirroring v0.1's working practice — deferred |
| ODQ-3 | File organization: shared `$defs` core + 4 family schemas vs 4 self-contained schemas | Propose one `common.schema.json` (`$defs`) + 4 family schemas referencing it — single source for the common core prevents drift; costs `$ref` resolution in consumers |
| ODQ-4 | `subject` exact member set (keep `runtime`? make `principal` recommended?) | Propose keep `runtime` optional, `principal` optional-but-SHOULD — v0.1 continuity, no new invention |
| ODQ-5 | Drop `integrity.canonical_json` and `decision_index`? | Propose drop both: the domain tag now attests canonicalization inside the signed bytes; `sequence` supersedes the index. Migration projection maps them per MIGRATION §sketch |
| ODQ-6 | `subject.timestamp_utc` format | Propose the frozen `witnessed_at` grammar (`YYYY-MM-DDTHH:MM:SSZ`, no leap second, valid Gregorian) for uniformity — but this extends a witness-claim rule to core; needs an explicit decision |
| ODQ-7 | `integrity.signature.alg` required or optional? | Propose required-as-label (v0.1 continuity, aids audit) while semantics stay informative-only (frozen) |
| ODQ-8 | Decision `directive.verb` enum contents | Propose carry the v0.1 closed verb enum unchanged (incl. `escalate_to_human`) — any rename was already classed BREAKING in v0.1's change control; not this phase's fight |
| ODQ-9 | `evidence[].content_hash`: schema-required always, or optional-with-class-gating (AD-06 says required *to earn the authenticated class*) | Propose schema-required always — simpler, drift-proof, no class logic in schemas; costs: producers of never-to-be-authenticated records still must hash |
| ODQ-10 | Cross-artifact reference exact wire shape | Propose closed object `{"record_id": <string>, "chain_id": <string, optional>}` — global `record_id` suffices; `chain_id` qualifies where resolvers are chain-scoped (AD-05) |
| ODQ-11 | Digest string form for `input_digest`/`result_digest`/`content_hash`/action digests | Propose reuse `sha256:<64 lowhex>` (uniform with `integrity.current`; agility arrives with future suites via version bump, mirroring frozen §2 rule 4) |
| ODQ-12 | Profile namespace representation | Propose flat dotted keys (`"org.airep.migration"`-style, pattern-constrained) matching the accepted `profiles.airep.migration` naming from MIGRATION — nested-namespace objects rejected as needless depth |
| ODQ-13 | Numeric maxima/minima not pinned by frozen text (e.g. artifact-level `sequence` upper bound) | Propose the same 0..2^53−1 safe-integer band as the frozen claim members, for uniformity — extension of a witness rule to core; needs decision |
| ODQ-14 | Nullable vs absent | Propose: `null` is never valid anywhere in core; optionality is expressed by absence only — one representation per state |
| ODQ-15 | Unknown top-level members | AD-07 closure already decides rejection; recorded here only to confirm NO forward-compatibility escape hatch is being added silently |

## 10. Deliverable gate

This document is the whole Stage-1 deliverable. No `.schema.json`, no validators, no
producers exist or will be written before the maintainer verdict
(`ARTIFACT_SCHEMA_DESIGN_ACCEPTED — SCHEMA IMPLEMENTATION AUTHORIZED`). OPEN DESIGN QUESTIONS
are answered by the reviewer, not by implementation defaults.
