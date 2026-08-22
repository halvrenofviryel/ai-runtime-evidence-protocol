# AIREP v0.2 — Specification tree (partial, under construction)

**This tree is intentionally incomplete.** It grows section by section as WP-α work packages
freeze; nothing exists here before its gate passes.

| Present | Status |
|---|---|
| [`INTEGRITY.md`](./INTEGRITY.md) | **Normative.** The v0.2 integrity construction — domain tags, hash/signature/witness preimages, binding rules. Stage-2 integration of the frozen WP-α01 Stage-1 baseline (freeze basis `9a30f97`, PR #26). Byte-affecting changes require a WP-α01 Stage-1 re-review. |
| [`vectors/`](./vectors/) | Stage-3 cross-language fixed vectors: shared semantic inputs, two independently written generators (Python / Node), a third-party comparator, and the byte-agreement evidence manifest. |
| [`stage4/`](./stage4/) | Stage-4 test contract (normalized result contract, closed reason-code registry, fixture envelope + A1–A13 matrix) for the **WP-α01 integrity verifiers** — integrity-construction verifiers only, not full v0.2 conformance verifiers. |

**Absent by design (blocked):** the four artifact schemas (decision / control / execution /
effect), the profile schemas, the conformance classes text, and the verifiers. They open only
after WP-α01 completes as a whole (stages 2–4 accepted).

The design record for everything here lives in
[`../v0.2-design/`](../v0.2-design/) — architecture decisions, breaking-change inventory,
migration model, and the frozen WP-α01 construction document.
