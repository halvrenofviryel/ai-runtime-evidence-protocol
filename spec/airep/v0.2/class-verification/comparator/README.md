# AIREP v0.2 class-verifier parity comparator

Third-party measurement tool for the two independently authored class verifiers
(`verifier_py/class_verifier.py` and `verifier_node_r2/class_verifier.mjs`)
against the frozen 45-case corpus and `CLASS_VERIFIER_CONTRACT.md`.

This directory contains **measurement**, not authoring and not acceptance.

## Independence posture

- **stdlib only.** `argparse`, `copy`, `hashlib`, `json`, `os`, `re`,
  `subprocess`, `sys`. No `ajv`, no `jsonschema`, no `cryptography`, no
  third-party package of any kind.
- **Imports nothing from either verifier.** No JCS helper, no ordering helper,
  no reason-set helper, no digest helper, no constant. UTF-8 tuple ordering,
  ASCII-ascending set checks, SHA-256 digesting of operator input bytes, the
  closed 31-reason registry (`registry.py`) and the section 2 envelope
  invariants are implemented here from the contract. Sharing a helper with an
  implementation would make the two runtimes agree *because they share code*,
  which destroys the measurement.
- **Recomputes evidence input digests itself** from the exact bytes of each
  case's `bindings.json` / `independence.json` / `revocation.json`. The digests
  the verifiers report in their `evidence` blocks are treated as claims under
  test, never as inputs.
- **Never writes to frozen material.** No verifier source, corpus file,
  `expected.json`, manifest, contract, schema or dependency bundle is modified.
  Probe inputs are authored fresh into the run directory from copies; the
  negative proofs mutate copies in a temporary directory.

## Usage

Official run (executes both verifiers, twice each):

```
python3 comparator/compare.py --root . \
    --out-dir comparator/evidence/official_run \
    --result  comparator/evidence/RESULT.json \
    --summary comparator/evidence/SUMMARY.txt
```

Compare a pre-existing output pair (used by the negative proofs; the gates that
require running the verifiers are then reported `NOT_MEASURED`, never `PASS`):

```
python3 comparator/compare.py --root . --py-out A.json --node-out B.json --result R.json
```

Negative proofs (control + three proofs):

```
python3 comparator/negative_proofs/run_all.py
```

Comparator exit codes: `0` all hard gates PASS · `1` a hard gate FAILED ·
`2` a hard gate was NOT_MEASURED · `3` harness error · `4` evidence bundle
invalid.

## What is a HARD GATE

Fourteen gates. A divergence in any of them is a comparator FAILURE and is
reported, never tolerated and never adjusted away.

| Gate | Surface |
|---|---|
| G1 | the full 45-case fixture set is present, byte-intact against `corpus_manifest.json` (every recorded digest plus the aggregate rule recomputed), and every case is evaluated by both implementations — no silent truncation |
| G2 | exit semantics agree between Python and Node, across the corpus run and a 20-row CLI probe matrix; the 19 rows the contract pins are additionally checked against the contract's own expected code |
| G3 | `class` |
| G4 | `authenticated_failures` |
| G5 | `authenticated_withheld` |
| G6 | `authenticated_caveats` |
| G7 | `witnessed_failures` |
| G8 | `witnessed_withheld` |
| G9 | `observer_assessment` |
| G10 | the `evidence` block: cross-implementation equality **and** equality against the comparator's own independently recomputed input digests, `now` and `freshness_window_seconds` |
| G11 | verdict envelope: closed top-level and per-verdict membership, `artifact_ref` shape, legal `class` and `observer_assessment` values, all five reason arrays present, registry-only reasons in the correct `(tier, channel)`, deduplicated and ASCII-ascending, `evidence` member shape and types, and the four section 2 consistency invariants |
| G12 | UTF-8 tuple ordering of the verdict array, absence of duplicate `(chain_id, record_id)` tuples in each output, identical ordering across the two implementations, and duplicate-tuple *rejection* behaviour |
| G13 | each implementation's equality against the frozen `expected.json` values (`class`, all five channels, `observer_assessment`) — read by the comparator only |
| G14 | per-implementation determinism: each verifier byte-identical across repeated corpus runs |

## What is AUXILIARY (not a gate)

| id | Observation |
|---|---|
| A1 | **cross-runtime byte equality of the two output files.** Recorded as evidence only. Byte equality is neither necessary nor sufficient for parity; if the two files are byte-identical that is an observation about two serializers, not the parity result. Parity is G1–G14. |
| A2 | **ordering exercise strength.** Whether the corpus contains non-ASCII identifiers. |
| A3 | **duplicate-tuple handling probe.** The raw per-implementation observation behind the G12 duplicate-rejection surface. |

## What the comparator deliberately does NOT establish

- **Not acceptance.** This is implementer/measurement evidence produced by a
  third integration context. Only an authorized independent acceptance stage
  can assign `ACCEPTED`.
- **Not implementation independence.** Agreement between the two verifiers is
  consistent with independent authoring; it does not prove it. Nor does the
  comparator's own independence prove the verifiers' independence.
- **Not correctness of the contract, the corpus, or the pinned expected
  values.** G13 measures conformance *to* `expected.json`; it cannot tell you
  the expected values are right. If a frozen artifact looks defective the
  comparator reports it — it never fixes it.
- **Not cryptographic verification.** The comparator does not verify Ed25519
  signatures, recompute artifact hashes, or validate artifacts against the
  accepted schemas. It measures whether the two implementations agree, agree
  with the pinned expectations, and emit a legal envelope.
- **Not coverage of ordering on non-ASCII identifiers.** All 45 corpus
  identifiers are ASCII, where UTF-8 byte order and UTF-16 code-unit order
  coincide. G12 therefore does not establish cross-runtime ordering agreement
  on the non-ASCII identifiers the contract explicitly admits. Reported as a
  measured limitation (A2), not rounded up.
- **Not coverage of the single-case (`--request`) verdict path beyond exit
  codes.** The semantic gates are measured on the batch corpus path.
- **Not a claim about any behaviour outside the 45 corpus cases and the
  probe matrix.**

## Negative proofs

`negative_proofs/run_all.py` runs a control plus three proofs. Each proof takes
a known-good pair of outputs, mutates a **copy** of one side, and asserts that
the comparator reports FAILURE **and** names the expected cause — the finding
code and its fields, not merely a non-zero exit.

- **Control** — an unmutated pair trips no gate (so each proof's failure is
  attributable to its mutation, not to the proof harness).
- **`proof_1_class_flip.py`** — flips one `class` value; asserts `G3
  class-mismatch` with the exact case and both values, plus `G13
  expected-mismatch`, and asserts the envelope gate stayed clean so that the
  class gate is demonstrably what caught it.
- **`proof_2_reason_mutation.py`** — adds, drops and renames one reason inside
  three different channels, each mutation kept envelope-legal; asserts `G7/G8/G4
  reason-set-mismatch` with the exact before/after sets.
- **`proof_3_envelope_invariant.py`** — five envelope/invariant breaks: a
  section 2 invariant (`class = AIREP-Witnessed` with a non-empty withheld
  array), an unknown member, a missing required member, a reason outside the
  closed registry, and broken ordering; asserts `G11 invariant-violation` (both
  named invariants), `G11 envelope-unknown-member`, `G11
  envelope-missing-member`, `G11 reason-not-in-registry` and `G12
  order-violation` respectively.

## Files

```
comparator/
  compare.py                              the comparator
  registry.py                             closed reason registry + legal value sets (from the contract)
  README.md                               this file
  negative_proofs/
    harness.py                            copy-only mutation plumbing and cause assertions
    proof_1_class_flip.py
    proof_2_reason_mutation.py
    proof_3_envelope_invariant.py
    run_all.py                            control + all three proofs
  evidence/
    RESULT.json                           machine-readable official result
    SUMMARY.txt                           readable official summary
    NEGATIVE_PROOFS.txt                   captured negative-proof run
    official_run/                         both verifiers' outputs (2 runs each) and the probe inputs
```
