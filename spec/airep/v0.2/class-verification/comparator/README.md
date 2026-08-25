# AIREP v0.2 class-verifier parity comparator

A parity measurement tool for the two independently authored class verifiers
(`verifier_py/class_verifier.py` and `verifier_node_r2/class_verifier.mjs`)
against the frozen 45-case corpus and `CLASS_VERIFIER_CONTRACT.md`, **authored
in a third integration context**.

This directory contains **measurement**, not authoring and not acceptance.

> **Naming note — do not let this drift back.** "Third integration context"
> means independent *of both verifier implementations*: this tool reads neither
> verifier as a source of truth and imports no code from either. It is **not a
> third party** — not an outside organisation, not an independent auditor, not
> an acceptance authority. It is same-project, implementer-side measurement
> evidence. The only correct use of "third-party" in this directory is the
> dependency sense, in the Independence posture bullet below ("no third-party
> package of any kind"); that line is about packages and is correct as written.

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
| G1 | the full **60-case** scored fixture set (45 C0 + 15 C1) is present, byte-intact against `corpus_manifest.json` (all **416** recorded digests plus the aggregate rule recomputed), the declared counts match, the **60-case combined index is rebuilt** by the comparator from the two root arrays and its digest checked against the pinned value, the **265-path C0 subset is re-aggregated** and must still equal the pre-C1 aggregate (C1 strictly additive), the **execution-basis cross-SHA identities** hold, and every case is evaluated by both implementations — no silent truncation |
| G2 | exit semantics agree between Python and Node, across the corpus run and a 19-row contract-pinned CLI probe matrix (each row also checked against the contract's own expected code), **plus** the §9 R-9 `--request FILE --out PATH` probe: exit 2, empty stdout, and `PATH` neither created nor modified — asserted for both implementations against a non-existent path and against a pre-written sentinel (bytes and `mtime_ns`), **plus** the **15 committed C1 process probes** × 2 implementations, each asserting its pinned `expected_exit`, `expected_results_file` and `must_not_create` |
| G3 | `class`, across all 60 cases |
| G4 | `authenticated_failures` |
| G5 | `authenticated_withheld` |
| G6 | `authenticated_caveats` |
| G7 | `witnessed_failures` |
| G8 | `witnessed_withheld` |
| G9 | `observer_assessment` |
| G10 | the `evidence` block: cross-implementation equality **and** equality against the comparator's own independently recomputed input digests, `now` and `freshness_window_seconds` |
| G11 | verdict envelope: closed top-level and per-verdict membership, `artifact_ref` shape, legal `class` and `observer_assessment` values, all five reason arrays present, registry-only reasons in the correct `(tier, channel)`, deduplicated and ASCII-ascending, `evidence` member shape and types, and the four section 2 consistency invariants |
| G12 | UTF-8 tuple ordering of the verdict array, absence of duplicate `(chain_id, record_id)` tuples in each output, identical ordering across the two implementations (the comparator's independent gate under amended §2), **and** the verifier's own §9 R-10 rejection duty: exit 1, no results file created and no pre-existing file modified, no duplicate-bearing output — asserted for both implementations in both path variants, **plus** the exact order of all 60 verdicts recomputed with the comparator's **own** UTF-8 byte comparator (no helper imported from either verifier), an explicit **ORD2-must-precede-ORD1** discrimination assertion, and a cross-check of the committed `corpus/ordering/expected_verdict_order.json` fixture |
| G13 | each implementation's equality, **separately**, against the frozen `expected.json` values (`class`, all five channels, `observer_assessment`) on all **60/60** cases — read by the comparator only |
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

## Run history

| Run | Evidence | Outcome |
|---|---|---|
| 1 | `evidence/RESULT.json`, `SUMMARY.txt`, `FINDINGS.md`, `NEGATIVE_PROOFS.txt`, `official_run/` | **FAILURE** — 2 findings on the run-validity / CLI surface (`--request … --out …`, duplicate-tuple rejection); the 45-case semantic surface was clean. Accepted by the maintainer as a valid measurement; both findings closed by rulings §9 R-9 and R-10. |
| 2 | `evidence/RESULT_RUN2.json`, `SUMMARY_RUN2.txt`, `FINDINGS_RUN2.md`, `NEGATIVE_PROOFS_RUN2.txt`, `official_run_2/` | **PASS** — 0 findings, all 14 hard gates PASS. |

| C1 | `evidence/RESULT_C1.json`, `SUMMARY_C1.txt`, `FINDINGS_C1.md`, `NEGATIVE_PROOFS_C1.txt`, `basis.json`, `official_run_c1/` | **PASS** — 0 findings, all 14 hard gates PASS, now over 60 scored cases and 15 process probes. |

Runs 1 and 2 are **immutable** and are never overwritten by a later run.

### C1: strict extension, nothing loosened

Every run-2 gate is retained with its run-2 strictness. C1 surfaces are **added to** the existing gates, never substituted for them: the 19-row pinned CLI matrix and the R-9 sentinel probe are still run and still asserted; the R-10 duplicate probe is unchanged in both path variants; `check_order_and_uniqueness` still runs on both outputs alongside the new whole-order computation. The C0 constants survive as their own named values (`EXPECTED_C0_CASE_COUNT`, `EXPECTED_C0_FILE_COUNT`, `PINNED_C0_AGGREGATE`) rather than being folded into looser combined numbers, so C0 preservation is asserted on its own terms.

**Nothing was loosened.** No gate was removed, downgraded to an observation, or replaced by a C1 probe; no exemption was added; no tolerance was widened. The two auxiliary observations that changed did so in the direction of *more* assurance: A2 moved from recording an untested-ordering limitation to recording that the discriminating pair is exercised, and the execution-basis cross-SHA check is a new way for G1 to FAIL, not a new way for it to pass.

### What changed between run 1 and run 2, and what was NOT loosened

Changed: the naming correction (see the note at the top of this file); stdout
capture added to the verifier runner; `file_state()` / `side_effect_findings()`
/ `SENTINEL` added so "neither created nor modified" is measurable; the
`request-with-out` row moved out of the generic exit matrix into its own probe
with **four** assertions instead of one; the duplicate probe rewritten with
**four** assertions per implementation across two path variants.

**Nothing was loosened.** Both changed probes moved from `contract_pinned=false`
with an exit-code-only comparison to `contract_pinned=true` with a pinned
expected code *and* side-effect assertions — strictly more is asserted, on
strictly more inputs. G1, G3–G11, G13 and G14 are untouched. No gate was
downgraded to an observation, no exemption was added, and no tolerance was
widened anywhere. The only removal is the generic matrix row for
`--request … --out …`, which was replaced by a superset of its assertions; the
matrix comment at that site records why.

Both rewritten probes were additionally **replayed against synthetic
pre-remediation behaviour** to show they still reproduce run 1's findings — a
clean run is the expected outcome now, which is exactly when a probe most easily
passes for the wrong reason. See `evidence/FINDINGS_RUN2.md`.

## Negative proofs

`negative_proofs/run_all.py` runs a control plus **five** proofs (three C0, two C1) against the **latest** official run's known-good output (override with `AIREP_COMPARATOR_GOOD`; the path chosen is printed, never inferred). Each proof takes
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
- **`proof_4_ordering_mutation.py`** (C1) — transposes ORD1 and ORD2, the UTF-8 vs
  UTF-16 discriminating pair; asserts `G12 ordering-discriminator-violated` naming
  the required relation, plus `G12 order-not-utf8-expected` against the comparator's
  own computation of all 60 positions, and asserts that G11 and every semantic parity
  gate stayed clean so the ordering surface is demonstrably what caught it.
- **`proof_5_c1_probe_mutation.py`** (C1) — drives the C1 probe matrix with a
  synthetic runner that misbehaves on exactly one pinned probe: (a) the wrong exit
  code, asserting `c1-probe-exit-mismatch` + `c1-probe-exit-divergence`; (b) a
  results file falsely created, asserting `c1-probe-results-file-mismatch` +
  `c1-probe-must-not-create-violated` + `c1-probe-out-path-created`. Both sub-proofs
  additionally assert that **no other probe** produced a finding, and a control
  confirms the unmutated matrix is silent.

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
    proof_4_ordering_mutation.py          C1: UTF-8 vs UTF-16 discriminating pair
    proof_5_c1_probe_mutation.py          C1: pinned process probe, synthetic runner
    run_all.py                            control + all five proofs
  evidence/
    RESULT.json / SUMMARY.txt             run 1 machine-readable result and summary (IMMUTABLE)
    FINDINGS.md                           run 1 findings, stated at their measured strength
    NEGATIVE_PROOFS.txt                   run 1 captured negative-proof run
    official_run/                         run 1 verifier outputs (2 runs each) and probe inputs
    RESULT_RUN2.json / SUMMARY_RUN2.txt   run 2 machine-readable result and summary
    FINDINGS_RUN2.md                      run 2 record -- states explicitly that run 2 is clean
    NEGATIVE_PROOFS_RUN2.txt              run 2 captured negative-proof run
    official_run_2/                       run 2 verifier outputs, probe inputs and sentinels
    RESULT_C1.json / SUMMARY_C1.txt       C1 machine-readable result and summary
    FINDINGS_C1.md                        C1 record -- states explicitly that C1 is clean
    NEGATIVE_PROOFS_C1.txt                C1 captured negative-proof run (5 proofs + control)
    basis.json                            the two SHAs with their roles named, and which
                                          properties are measured vs relayed
    official_run_c1/                      C1 verifier outputs over 60 cases, the rebuilt
                                          combined index, probe inputs and sentinels
```
