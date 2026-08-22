# Stage-4 fixture-envelope definition and fixture matrix

> Fixtures are **test-harness objects only**. The envelope defined here MUST NOT be
> represented, described, or reused as an AIREP wire schema; fixture bodies are
> **construction/adversarial fixtures**, never "v0.2-conformant artifacts" (the artifact
> schemas do not exist yet).

## 1. Fixture envelope

One JSON file per fixture under `corpus/`, named `<fixture_id>.json`:

```jsonc
{
  "fixture_id": "A2-1",
  "normative_case": "A2",          // "P*" positive control, "A1".."A13" (INTEGRITY §7), "S*" supplementary
  "description": "...",
  "inputs": {
    "artifact": { … },             // the artifact under test, exactly as presented to the verifier
    "head_artifacts": { … },       // optional: resolvable heads for witness fixtures, keyed by id
    "witness": { … },              // optional: witness block (claim + signature + wire label) as presented
    "producer_binding":  { "public_key_hex": "…", "suite": "ed25519" },        // verifier-accepted; may be absent (K-fixtures)
    "witness_trust_store": { "<witness_id>": { "public_key_hex": "…", "suite": "ed25519", "trusted": true } },
    "now": "YYYY-MM-DDTHH:MM:SSZ",             // deterministic clock for freshness
    "freshness_window_seconds": 3600
  },
  "expected": { "verdict": "PASS|PASS_WITH_CAVEAT|REJECT", "reasons": ["…"] }
}
```

Rules: every fixture is fully deterministic (no system clock, no randomness — Ed25519 is
deterministic and all keys are the published TEST-ONLY seeds from Stage 3); `expected.reasons`
follows the same dedup + ASCII-ascending ordering as results; tampered fixtures are produced
by generating a valid object first and then applying the named tamper, so each fixture's
recipe states *what was changed* relative to valid.

## 2. Fixture matrix

Splits (`A11a`, `A4-1`/`A4-2`, …) preserve the normative numbering of INTEGRITY §7 — a split
never renumbers a normative case. Every rejection fixture MUST fail closed under both
verifiers (STAGE4_CONTRACT §5).

### Positive controls (an all-negative corpus is insufficient)

| id | Construction | Expected |
|---|---|---|
| P1–P4 | One valid artifact per context (`decision`, `control`, `execution`, `effect`): correct hash tag, correct sig preimage, binding supplied | `PASS` `["OK"]` ×4 |
| P5 | Valid witness verification: resolvable head, reconciling five-member claim, fresh signed `witnessed_at`, trusted witness key distinct from the producer's | `PASS` `["OK"]` |

> P5 scope note: the distinct witness key is **fixture hygiene only**. The Stage-4 integrity
> verifiers do not evaluate witness *independence* or revocation assurance — those belong to
> the future conformance-class semantics, and being "independent" earns nothing in a Stage-4
> verdict. The distinct key is used so this corpus does not contaminate that later boundary.

### A1–A13 (INTEGRITY §7 required outcomes preserved)

| id | Case (tamper relative to valid) | Expected |
|---|---|---|
| A1-1 | Body's `current` computed under a different context's hash tag, presented under its own declared type | `REJECT` `["HASH_MISMATCH"]` — paired with the §2a A1 tag-divergence harness assertion, which together cover frozen A1's full obligation |
| A2-1 | Valid decision artifact, then `artifact_type` rewritten to `"execution"` | `REJECT` `["HASH_MISMATCH"]` |
| A3-1 | Control artifact carrying a signature produced over a `sig/decision` preimage with the same `current` | `REJECT` `["SIGNATURE_INVALID"]` |
| A4-1 | Witness signature bytes presented as a record signature | `REJECT` `["SIGNATURE_INVALID"]` |
| A4-2 | Record signature bytes presented as a witness signature | `REJECT` `["WITNESS_SIGNATURE_INVALID"]` |
| A5-1 | A v0.1 record (no `airep_version`/`artifact_type`, untagged hash, bare-`current` signature) presented as v0.2 | `REJECT` `["UNSUPPORTED_VERSION"]` — auxiliary check outside the integrity verifiers: `spec/airep/v0.1/conformance/verify.py` still accepts the same bytes under v0.1 rules (freeze intact) |
| A6-1 | `artifact_type` set to a syntactically valid but unregistered context (e.g. `"decision2"`), hash computed under that invented tag | `REJECT` `["UNREGISTERED_TAG"]` |
| A7-1 | Case variant (`artifact_type: "Decision"`, hash under uppercase-context tag) | `REJECT` `["UNREGISTERED_TAG"]` |
| A8-1 | `current` computed with CRLF (or trailing LF) as separator at production time | `REJECT` `["HASH_MISMATCH"]` |
| A9-1 | Body **declares `airep_version: "0.2"`**, but its `current` and signature were deliberately produced under `0.3` tags at build time | `REJECT` `["HASH_MISMATCH"]` (the verifier derives only the declared `0.2` tags; no cross-version attempt) |
| A9-2 | Valid `0.2` artifact whose declared `airep_version` was rewritten to `"0.3"` **after sealing** | `REJECT` `["UNSUPPORTED_VERSION"]` (the only supported wire version is `0.2`; fail closed before any tag derivation) |
| A10-1 | Old, valid witness signature over a stale signed `witnessed_at`; an **unsigned** freshness field beside it set to `now` | `REJECT` `["WITNESS_STALE"]` — the unsigned field changes nothing |
| A11a-1 | Valid record signature; wire `alg` label rewritten to another suite name | `PASS_WITH_CAVEAT` `["WIRE_ALG_IGNORED"]` |
| A11b-1 | Signature produced over a preimage embedding a suite-id different from the binding's suite | `REJECT` `["SIGNATURE_INVALID"]` (indistinguishable from any other signature failure — see REASON_CODES) |
| A12-1 | Witness signature produced under tag version `0.3` while the referenced head declares `0.2` | `REJECT` `["WITNESS_SIGNATURE_INVALID"]` (verifier constructs only the head-derived tag; no search) |
| A13a-1 | Valid witness signature; wire-carried witness algorithm label rewritten | `PASS_WITH_CAVEAT` `["WIRE_ALG_IGNORED"]` |
| A13b-1 | Witness signature over a preimage embedding a suite-id different from the trust-store binding | `REJECT` `["WITNESS_SIGNATURE_INVALID"]` |

### Supplementary structural fixtures (INTEGRITY §2/§4.2/§4.3 MUSTs)

| id | Case | Expected |
|---|---|---|
| S1-1 | **Present-member subtraction (verifier fixture):** a sealed artifact presented **containing both** `integrity.current` and `integrity.signature`; the verifier performs the mechanical subtraction and verifies normally | `PASS` `["OK"]` — plus the S1 harness assertion below |
| S2-1 | Witness claim referencing a head absent from `head_artifacts` | `REJECT` `["WITNESS_HEAD_UNRESOLVED"]` |
| S3-1 | Resolvable head, but claim `sequence` (or `current`) differs from the head's members | `REJECT` `["WITNESS_HEAD_MISMATCH"]` |
| S4-1 | `witnessed_at` = leap second (`…T23:59:60Z`) inside an otherwise valid signed claim | `REJECT` `["WITNESS_TIME_INVALID"]` |
| S4-2 | `witnessed_at` = invalid calendar date (`2026-02-30T12:00:00Z`) | `REJECT` `["WITNESS_TIME_INVALID"]` |
| S5-1 | No `producer_binding` supplied; wire `alg` present and syntactically valid | `REJECT` `["KEY_BINDING_UNAVAILABLE"]` — the wire label is never a substitute |
| S5-2 | Binding names a suite the verifier does not implement | `REJECT` `["SUITE_UNSUPPORTED"]` |

## 2a. Harness assertions (builder/comparator level — not verifier verdicts)

Two obligations are measured by the corpus builder and the parity comparator directly, because
they are properties of the construction rather than of a verifier's accept/reject decision. A
verifier result never stands in for them; both are recorded with their measured values in the
parity manifest, and a failed assertion fails the gate:

- **A1 tag divergence.** For one shared canonical body the builder computes `current` under
  the `decision` hash tag and under the `control` hash tag and asserts
  `H(tag_decision ‖ LF ‖ body) ≠ H(tag_control ‖ LF ‖ body)`; and only the current computed
  under the tag derived from the declared pair is the one a fixture may present as valid.
  Fixture `A1-1` then measures the verifier-side rejection of the wrong-tag current; the
  assertion measures the divergence itself. Together they cover frozen A1's full obligation.
- **S1 subtraction-path equality.** The builder produces a **construction probe** (not a
  fixture, no normalized result): the S1 body *without* `integrity.current`/`integrity.signature`,
  canonicalized to `probe.canonical_body` and `probe.current`. The comparator asserts that the
  canonical body and recomputed `current` the verifiers reach for `S1-1` (the sealed,
  members-present artifact) are byte-identical to the probe's. An unsealed body is never
  presented to an integrity verifier as a `PASS` fixture — `PASS` remains "every required
  check succeeded", which includes the signature.

## 3. Corpus generation

The corpus is generated by a deterministic builder (next commit, after contract review) that
constructs each valid object per the frozen INTEGRITY text and applies each fixture's named
tamper. If any fixture **cannot** be produced from the frozen text as written, generation
STOPS and reports `STAGE1_REREVIEW_REQUIRED` (STAGE4_CONTRACT §5) — a fixture is never bent to
fit. The corpus manifest records each fixture file's SHA-256 and the corpus aggregate SHA-256.
