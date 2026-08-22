# AIREP v0.1 → v0.2 — Migration model

> Status: **Design.** This document states the migration *model* — the rules any future migration
> tooling must satisfy. The tooling itself is v0.2-alpha work and does not exist yet.

## Principles

1. **History is never rewritten.** Existing v0.1 chains remain valid v0.1 chains, verifiable
   forever under the v0.1 rules by the frozen v0.1 conformance kit. No v0.1 record is ever
   re-hashed, re-signed, or edited to "become" v0.2.

2. **Migration is projection, not conversion.** A v0.1 record is *projected* into v0.2 artifacts
   by a deterministic, documented mapping. The projection produces **new** artifacts with new
   integrity material (v0.2 hash domain, AD-04) — it does not claim the new bytes are what the
   original producer signed.

3. **Provenance is explicit.** Every projected artifact carries a provenance reference to its
   source: the v0.1 record's `integrity.current` hash and the chain context it came from. A
   consumer can always walk back from a projected v0.2 artifact to the originally signed v0.1
   bytes and re-verify them under v0.1 rules.

4. **Assurance never rises through projection.** A projected artifact's conformance class is
   capped at the class the source record earned under v0.1 verification, and the projection notes
   that the class was inherited-by-projection, not earned by v0.2 checks. Projection is a
   convenience for uniform consumption, not an assurance upgrade.

5. **Projection is total or refused.** If a v0.1 record cannot be projected without inventing
   information (e.g. a required v0.2 digest whose source bytes no longer exist), the projector
   refuses that field-level claim and emits the artifact with the gap named — it never fabricates
   a digest. "Not migratable" is an honest, recorded outcome.

## Sketch of the mapping (to be fixed in v0.2-alpha)

| v0.1 source | v0.2 target |
|---|---|
| Core record (decision semantics) | **Decision Receipt**: `subject`, `input`, `claim`, `directive`, `scope` map ≈1:1; new required `chain_id`/`record_id` minted at projection time and marked as projection-assigned |
| `profiles.control_delivery` issued/delivered/acknowledged events | **Control Evidence** artifacts, one per lifecycle event, correlated by the original `instruction_id` / `instruction_hash` |
| `profiles.control_delivery` enforced events, execution-side profile content (`execution_observation`, `enforcement_result`) | **Execution Evidence** artifacts |
| Effect-side profile content (`effect_observation`, `effect_assurance`) | **Effect Evidence** artifacts |
| `profiles.chain_witness` | Unchanged in role; optionally supplemented by a SCITT registration of the projected head (AD-10) |
| Other profiles (`key_trust`, regulatory crosswalks, `observability_transport`, …) | Carried as namespaced profiles on the appropriate artifact |

Fields v0.1 does not have (`chain_id`, `record_id`, `result_digest`, universal
`evidence[].content_hash`) are either minted-and-marked (identifiers) or gap-named (digests),
per principle 5.

## What the frozen v0.1 line still receives

- Documentation-correctness fixes (e.g. aligning STATUS.md with implemented verifier behaviour).
- Security fixes in the conformance tooling.
- Nothing else. Feature work, schema change, and semantics change happen only on the v0.2 line.

## Dual-verification window

From v0.2-alpha until v0.2 reaches its independence gate (AD-15), consumers holding v0.1 chains
need no action: v0.1 verification remains the supported path for v0.1 artifacts indefinitely.
"v0.1 is frozen" means unchanging, not unsupported.
