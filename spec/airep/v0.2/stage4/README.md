# WP-α01 Stage 4 — Adversarial corpus + integrity-verifier parity

**Status: CONTRACT — no verifier implementation exists yet.** This directory defines the
Stage-4 test contract before any code is authored, so the contract itself can be reviewed
first.

**Terminology (binding for everything in this stage):** the two programs this stage produces
are **AIREP v0.2 WP-α01 integrity verifiers** (equivalently: *integrity-construction
verifiers*). They verify the hash/signature/witness construction of
[`../INTEGRITY.md`](../INTEGRITY.md) and the A1–A13 obligations — nothing more. They are NOT
full v0.2 conformance verifiers: artifact schemas, profile validation, and conformance-class
semantics do not exist yet, and no document in this stage may use "full v0.2 verifier".
Likewise the fixtures are **construction/adversarial fixtures**, never "v0.2-conformant
artifacts".

| Document | Contents |
|---|---|
| [`STAGE4_CONTRACT.md`](./STAGE4_CONTRACT.md) | The test contract: normalized result contract, verifier obligations, independence mandate, parity comparator contract, gate rules, evidence package |
| [`REASON_CODES.md`](./REASON_CODES.md) | The closed normalized reason-code registry |
| [`FIXTURES.md`](./FIXTURES.md) | Fixture-envelope definition + the full fixture matrix (positive controls, A1–A13 with splits, supplementary structural fixtures) |

**Frozen inputs this stage may not touch:** `spec/airep/v0.2/INTEGRITY.md` (frozen normative;
a genuine byte ambiguity found there is a **STAGE1_REREVIEW_REQUIRED** stop, never a Stage-4
fix), the WP-α01 Stage-1 design document, everything under `spec/airep/v0.1/`. The four
artifact schemas, profile schemas, conformance classes, and production producers remain
BLOCKED and out of scope.
