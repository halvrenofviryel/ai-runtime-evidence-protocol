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

4. **Source assurance and projection-artifact assurance are distinct — and never conflated.**
   Two different assurance statements exist, and each is tracked in its own channel:

   - **Source assurance:** what the original v0.1 record earned under v0.1 verification. This
     never rises through projection. A projected artifact records the source's v0.1 class as an
     inherited, clearly-labelled attribute (`source_assurance`, inherited-by-projection, not
     earned by v0.2 checks).
   - **Projection-artifact assurance:** what the *new* v0.2 artifact earns under v0.2
     verification on its own merits. A projector that correctly signs its output produces an
     artifact that can legitimately reach v0.2 **Authenticated** — authenticated *as the
     projector's statement about the source*, which is what its signature actually covers.

   The one forbidden inference is cross-channel: the projector being Authenticated says nothing
   about the source v0.1 record's authorship, and the source's v0.1 class says nothing about the
   projection's v0.2 class. A consumer reads both channels; neither substitutes for the other.

5. **No conformant artifact without its required content.** If required v0.2 information is not
   derivable from the source (e.g. a required digest whose source bytes no longer exist), the
   projector does **not** emit a v0.2 artifact for that record — an object missing a required
   field is not a conformant v0.2 artifact and is never presented as one. Instead the projector
   emits a **migration/projection report**: a separate, non-artifact output that identifies the
   source record (by its v0.1 `integrity.current`), states which required v0.2 fields were not
   derivable, and why. "Not projectable" is an honest, recorded outcome; a half-populated
   "artifact" is not.

## Sketch of the mapping (to be fixed in v0.2-alpha)

| v0.1 source | v0.2 target |
|---|---|
| Core record (decision semantics) | **Decision Receipt**: `subject`, `input`, `claim`, `directive`, `scope` map ≈1:1; new required `chain_id`/`record_id` minted at projection time and marked as projection-assigned |
| `profiles.control_delivery` issued/delivered/acknowledged events | **Control Evidence** artifacts, one per lifecycle event, correlated by the original `instruction_id` / `instruction_hash` |
| `profiles.control_delivery` enforced events, execution-side profile content (`execution_observation`, `enforcement_result`) | **Execution Evidence** artifacts |
| Effect-side profile content (`effect_observation`, `effect_assurance`) | **Effect Evidence** artifacts |
| `profiles.chain_witness` | Unchanged in role; optionally supplemented by a SCITT registration of the projected head (AD-10) |
| Other profiles (`key_trust`, regulatory crosswalks, `observability_transport`, …) | Carried as namespaced profiles on the appropriate artifact |

Fields v0.1 does not have are handled per principles 4–5: identifiers (`chain_id`, `record_id`,
`sequence`) are minted at projection time and marked projection-assigned; required digests
(`result_digest`, universal `evidence[].content_hash`) are computed from source bytes where those
bytes are available, and where they are not, **no v0.2 artifact is emitted** — the record goes to
the migration/projection report instead.

## What the frozen v0.1 line still receives

- Documentation-correctness fixes (e.g. aligning STATUS.md with implemented verifier behaviour).
- Security fixes in the conformance tooling.
- Nothing else. Feature work, schema change, and semantics change happen only on the v0.2 line.

## Dual-verification window

From v0.2-alpha until v0.2 reaches its independence gate (AD-15), consumers holding v0.1 chains
need no action: v0.1 verification remains the supported path for v0.1 artifacts indefinitely.
"v0.1 is frozen" means unchanging, not unsupported.
