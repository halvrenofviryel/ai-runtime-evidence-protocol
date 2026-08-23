# AIREP v0.1 → v0.2 — Breaking-change inventory

> Status: **Design.** This is the honest inventory of what the v0.2 architecture decisions
> ([`ARCHITECTURE_DECISIONS.md`](./ARCHITECTURE_DECISIONS.md)) change against the frozen v0.1 wire
> format and conformance semantics. Per v0.1's own change-control rule (STATUS.md), breaking
> changes are logged as **BREAKING**, never presented as additive. None of these changes lands in
> v0.1.

Impact vocabulary:

- **HASH** — changes computed hashes; every v0.2 hash differs from its v0.1 counterpart.
- **SCHEMA** — a v0.1-valid record is schema-invalid under v0.2 (or vice versa).
- **CLASS** — a record's conformance class changes under v0.2 rules with unchanged bytes.
- **VOCAB** — names change; machine and human consumers must update terminology.
- **ADDITIVE** — new capability; no v0.1 artifact is invalidated.

| # | v0.1 state (verified 2026-08-22) | v0.2 change | AD | Impact |
|---|---|---|---|---|
| 1 | One core record type; lifecycle events (`acknowledged`, `enforced`, `observed`, …) carried inside decision-shaped records via the `control_delivery` profile | Four sibling artifact types: Decision Receipt, Control Evidence, Execution Evidence, Effect Evidence, correlated by explicit keys | AD-03 | **SCHEMA** |
| 2 | v0.1 normative SPEC (§6) already requires in-place RFC 8785 hashing (`current` + `signature` removed, everything else retained); the **shipped reference packages diverge from the spec** by hashing a `{record, previous}` wrapper with sorted-key `json.dumps` (and `ensure_ascii`/`allow_nan` variance between packages) — an implementation-alignment gap, not a spec defect (v0.1 STATUS items 1–2) | The v0.1 in-place JCS rule is retained and extended with version+artifact-type domain separation; reference producers are **aligned to the spec** in alpha. No wrapper. No alternatives. | AD-04 | **HASH** (domain tag + producer alignment change computed hashes) |
| 3 | No chain identifier; no record identifier; `previous` gives relative binding only (limit acknowledged in THREAT_MODEL.md) | `chain_id` (globally collision-resistant, signed, genesis-chosen), `record_id` (globally collision-resistant, signed), and a separate monotonic `sequence` required on every artifact; cross-artifact references use global `record_id` or qualified `{chain_id, record_id}` | AD-05 | **HASH**, **SCHEMA** |
| 4 | `input.input_ref` required, input digest optional | Required input digest (or digest of a named projection, with the projection rule named) | AD-06 | **SCHEMA** |
| 5 | `output.result_ref` required, no result digest | Required `result_digest` | AD-06 | **SCHEMA** |
| 6 | `evidence[].content_hash` required only when `resolvable: false`, and only at the Verified class | `content_hash` required on every evidence entry — **schema-required wherever `evidence[]` appears** (schema-phase decision ODQ-9, 2026-08-23), and required for the authenticated class | AD-06; schema ODQ-9 | **SCHEMA**, **CLASS** |
| 7 | Top level closed; all core sub-objects (`subject`, `input`, `claim`, `output`, `evidence[]`, `directive`, `scope`, `integrity`, `integrity.signature`) are `additionalProperties: true` | All core sub-objects closed; extension only via namespaced `profiles` keys | AD-07 | **SCHEMA** |
| 8 | `integrity.signature.alg` open; `HMAC-SHA256` explicitly admitted at the Verified class | Asymmetric baseline (Ed25519 mandatory-to-implement); MAC integrity confined to a deployment-internal profile that cannot earn the portable authenticated class | AD-08 | **CLASS** |
| 9 | Class ladder named Core / Verified / Trusted; "Trusted" reachable only in opt-in strict mode | Ladder renamed (**decided**: AIREP-Core / AIREP-Authenticated / AIREP-Witnessed); Core claims "structurally valid and internally hash-consistent" (not "untampered"); Authenticated requires a verifier-accepted key binding; Witnessed is scoped to the anchor (head freshness + non-truncation); ladder boundary: each class establishes only its explicitly assigned provenance/integrity/freshness properties — no class provides truth assurance | AD-09 | **VOCAB** |
| 10 | `chain_witness` is the only head-witness mechanism | `chain_witness` retained for the offline case; SCITT (RFC 9943) binding profile added for transparency-service anchoring — normative order seal → register → receipt → subsequent anchor evidence; a receipt is never written back into the sealed object it attests | AD-10 | ADDITIVE |
| 11 | No authorization reference structure (authorization facts would live in free profile content) | Authorization reference profile: reference + digest of an external AuthZEN/OAuth decision artifact | AD-11 | ADDITIVE |
| 12 | `observability_transport` profile exists; no MCP/A2A mapping | Informative MCP, A2A, OTel mapping profiles, each pinned to the external spec version it was written against | AD-12 | ADDITIVE |
| 13 | Regulatory profiles flagged INDICATIVE in schema descriptions | Uniform mandatory crosswalk header: source version/date, informative status, not-covered list | AD-13 | — |
| 14 | `verify.mjs` runs no profile-schema validation; exit codes of the two verifiers documented as non-equivalent | Full verdict/class/reason/exit-code parity across both verifiers, CI-enforced over the shared corpus | AD-14 | — |
| 15 | `input.governance_state` — a deliberately open object in the v0.1 core | **REMOVED from the neutral core** (schema-phase maintainer decision, 2026-08-23): the one object AD-07 closure could not close; policy basis lives in `claim.basis` / `directive.policy_basis` / evidence refs; deployment-specific state moves to a namespaced profile | AD-07; schema design §3/§7 | **SCHEMA** |

## What is deliberately NOT changed

- The fail-closed class machinery — withheld classes, named unevaluated gates, "failed ≠ not
  measured", strict-mode operator inputs — carries into v0.2 in substance (AD-09 renames only).
- `scope.does_not_cover` stays mandatory. `subject.principal` with `established_by` stays.
  `authority.writable_by_controlled_system` and `delivery_failed` stay — they move with the
  control-evidence artifact, they do not weaken.
- The malicious-producer boundary stays: no v0.2 class asserts the truth of what a key-holding
  producer recorded.
- v0.1 artifacts, releases, tags, and DOIs are untouched (see [`MIGRATION.md`](./MIGRATION.md)).
