# AIREP v0.2 — Specification tree (alpha)

**Status: v0.2 is alpha and unreleased.** The published, citable version of AIREP is **v0.1**
(see [`../v0.1/`](../v0.1/)). This tree grows section by section as each work package freezes;
nothing appears here before its gate passes. Nothing here supersedes v0.1 until v0.2 is
released.

| Present | Status |
|---|---|
| [`INTEGRITY.md`](./INTEGRITY.md) | **Normative.** The v0.2 integrity construction — domain tags, hash/signature/witness preimages, binding rules. Stage-2 integration of the frozen WP-α01 Stage-1 baseline (freeze basis `9a30f97`, PR #26). Byte-affecting changes require a WP-α01 Stage-1 re-review. |
| [`vectors/`](./vectors/) | Stage-3 cross-language fixed vectors: shared semantic inputs, two independently written generators (Python / Node), a third-party comparator, and the byte-agreement evidence manifest. |
| [`stage4/`](./stage4/) | Stage-4 test contract (normalized result contract, closed reason-code registry, fixture envelope + A1–A13 matrix) for the **WP-α01 integrity verifiers** — integrity-construction verifiers only, not full v0.2 conformance verifiers. WP-α01 ACCEPTED/CLOSED 2026-08-23. |
| [`schema-design/`](./schema-design/) | Artifact-schema phase Stage 1: the **schema design contract** for the four artifact families — ACCEPTED 2026-08-23 as the frozen implementation basis. |
| [`schemas/`](./schemas/) | The five JSON Schema (2020-12) files mechanically expressing the accepted design contract — ACCEPTED 2026-08-23 as the implementation basis. Schema validation confers no assurance class, signature validity, or evidence truth. |
| [`schema-validation/`](./schema-validation/) | Schema fixture/validation phase — **COMPLETE 2026-08-23**: 117-fixture corpus + two-engine harness, ALL GATES PASSED. Measured claim only: the five schemas discriminate the measured corpus as expected under two independent engines. |
| [`conformance-design/`](./conformance-design/) | Conformance-class phase Stage 1: the **class design contract** (Core → Authenticated → Witnessed; verifier-accepted binding; witness-key independence; snapshot revocation) — ACCEPTED 2026-08-23. |
| [`class-verification/`](./class-verification/) | Class-verifier implementation contract **plus two separately authored verifiers, a 60-case corpus with 15 process probes, a parity comparator with five negative proofs, and the offline reproduction basis**. Class-verifier corpus/parity phase COMPLETE. The measured claim is parity and conformance to the frozen expected values on the measured corpus — not correctness of the underlying semantics, and not third-party audit. |

**Still absent:** the profile schemas, the normative conformance-classes text, and any
**producer** implementation. Producer work has not started. The stable-release criteria of
AD-15 — including genuine external independence and interoperability evidence — are not met, so
there is no plain `v0.2` and no stable `v0.2.0`.

The design record for everything here lives in
[`../v0.2-design/`](../v0.2-design/) — architecture decisions, breaking-change inventory,
migration model, and the frozen WP-α01 construction document.
