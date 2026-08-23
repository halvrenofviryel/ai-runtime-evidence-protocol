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

**Implementation notes recorded from the accepted contract review (no contract change):**

- The parity comparator MUST also enforce the **Verdict class** column of
  [`REASON_CODES.md`](./REASON_CODES.md): a reason paired with the wrong verdict class (e.g.
  `PASS_WITH_CAVEAT` + `SIGNATURE_INVALID`, or `REJECT` + `WIRE_ALG_IGNORED`) is a shape
  violation and a gate failure.
- S1 evidence is formulated without claiming observation of a verifier's internal state: the
  builder records the construction probe's canonical-body digest and `current`; the comparator
  **independently re-performs** the mechanical subtraction on the sealed S1 fixture and
  measures equality with the probe; the two integrity verifiers' `PASS ["OK"]` on `S1-1` is
  the verifier-side enforcement evidence. Normalized results never expose internal canonical
  bytes, and the manifest never pretends they do.

**Frozen inputs this stage may not touch:** `spec/airep/v0.2/INTEGRITY.md` (frozen normative;
a genuine byte ambiguity found there is a **STAGE1_REREVIEW_REQUIRED** stop, never a Stage-4
fix), the WP-α01 Stage-1 design document, everything under `spec/airep/v0.1/`. The four
artifact schemas, profile schemas, conformance classes, and production producers remain
BLOCKED and out of scope.
