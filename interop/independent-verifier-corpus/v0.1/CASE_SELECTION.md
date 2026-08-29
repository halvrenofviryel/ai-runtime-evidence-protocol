# Case selection

**This file is generated from `CASE_INDEX.json` and `expected/expected_results.jsonl`.**
Do not edit it by hand: every category and count below is derived, so it cannot drift
away from the structured data the package ships.

Selected from the 60 scored class-verification cases (45 C0 + 15 C1) and the 15
release-declared CLI/process-exit probes at the pinned commit.

## Probe count reconciliation

| Quantity | Count |
|---|---|
| Release-declared official CLI/process-exit probes (`probe_index.json`) | **15** |
| Of those, probes with input-file directories on disk | **13** |
| CLI-only probes with no input files (`PRB-CLI-CORPUS-NO-OUT`, `PRB-CLI-HELP`) | **2** |
| Filesystem entries under `corpus/probes/` (13 dirs + `probe_index.json`) | **14** |

Not every directory is an official scored probe, and not every official probe has a
directory.

## Selection matrix

| Pkg id | Source | Category | Class | Exit | Property | Family | Rule | Capabilities | Not redundant because |
|---|---|---|---|---|---|---|---|---|---|
| `CLS-P1` | `P1` | **positive** | AIREP-Authenticated | 0 | expected class earned cleanly | decision | INTEGRITY §2,§3; contract §3 stages 0-5 | JCS, SHA-256, Ed25519, schema, trust binding, revocation | clean Decision earns AIREP-Authenticated; witness absent is WITHHELD not FAIL |
| `CLS-P2` | `P2` | **positive** | AIREP-Witnessed | 0 | expected class earned cleanly | decision | contract §3 stages 6-11; INTEGRITY §4 | JCS, SHA-256, Ed25519, schema, trust binding, revocation, freshness, independence | clean witnessed Decision earns AIREP-Witnessed with all five channels empty |
| `CLS-P3` | `P3` | **positive** | AIREP-Authenticated | 0 | expected class earned cleanly | effect | contract §3 observer assessment; AD-03 | JCS, SHA-256, Ed25519, schema, reference resolution, trust binding, observer assessment | clean Effect with referenced Execution; observer assessment independent |
| `CLS-CTL1` | `CTL1` | **positive** | AIREP-Authenticated | 0 | expected class earned cleanly | control | control.schema.json; INTEGRITY §5 | JCS, SHA-256, Ed25519, schema, trust binding | clean issuer-side Control Evidence artifact |
| `CLS-NG1` | `NG1` | **positive** | AIREP-Witnessed | 0 | expected class earned cleanly | decision | INTEGRITY §4.3; non-genesis head | JCS, SHA-256, Ed25519, reference resolution, freshness | witness over a NON-GENESIS chain head |
| `CLS-FR3` | `FR3` | **positive** | AIREP-Witnessed | 0 | expected class earned cleanly | decision | contract §3 stage 10 boundary | freshness | freshness exactly at the window boundary still earns Witnessed |
| `CLS-PS1` | `PS1` | **failure** | AIREP-Core | 0 | definitive normative failure, with a verdict emitted | decision | INTEGRITY §3; contract stage 4 | Ed25519, trust binding | record signature made with a key other than the bound one |
| `CLS-PS2` | `PS2` | **caveat** | AIREP-Authenticated | 0 | passes while recording a caveat | decision | INTEGRITY §3.2 wire alg informative only | Ed25519, trust binding | valid Ed25519 signature, misleading wire alg: the binding selects the suite, not the wire label |
| `CLS-XT1` | `XT1` | **failure** | AIREP-Core | 0 | definitive normative failure, with a verdict emitted | decision | contract §3 stage 3 revocation | revocation, trust binding | producer binding revoked in the snapshot: definitive FAILURE |
| `CLS-IND4` | `IND4` | **failure** | AIREP-Authenticated | 0 | definitive normative failure, with a verdict emitted | decision | contract §1.2 independence policy | independence policy | producer/witness pair listed non-independent: definitive witness FAILURE |
| `CLS-FR1` | `FR1` | **failure** | AIREP-Authenticated | 0 | definitive normative failure, with a verdict emitted | decision | contract §3 stage 10 freshness | freshness | witness outside the freshness window |
| `CLS-WM3` | `WM3` | **failure** | AIREP-Authenticated | 0 | definitive normative failure, with a verdict emitted | decision | contract §0 reference resolution | reference resolution | head_ref names a record_id present in neither artifact nor related_artifacts |
| `CLS-PB2` | `PB2` | **withheld** | AIREP-Core | 0 | assurance withheld — the check could not run | decision | contract §4 withheld vs failure; stage 2 | trust binding | no producer binding entry: assurance WITHHELD, not failed |
| `CLS-WB2` | `WB2` | **withheld** | AIREP-Authenticated | 0 | assurance withheld — the check could not run | decision | contract §4; stage 7 | trust binding | no witness binding entry: witness assurance WITHHELD |
| `CLS-OB4` | `OB4` | **withheld** | AIREP-Authenticated | 0 | assurance withheld — the check could not run | effect | contract §3 observer assessment | reference resolution, observer assessment | Effect declares independent; referenced Execution cannot earn the class, so observer is unknown |
| `CLS-LEX1` | `LEX1` | **failure** | AIREP-Authenticated | 0 | definitive normative failure, with a verdict emitted | decision | INTEGRITY §2 lexical form; frozen ruling E-1 | JCS, lexical form preservation | witness claim length written 1e0: the semantic JSON value alone is insufficient |
| `PROC-UNP` | `PRB-REQUEST-UNPARSEABLE` | **indeterminate** | — | 1 | no verdict is emitted at all | n/a | contract §6.4 exit 1 run-invalid | process exit | request is not parseable: run-invalid, no verdict is emitted |
| `PROC-NGR` | `PRB-CLI-NOW-NOT-GREGORIAN` | **indeterminate** | — | 2 | no verdict is emitted at all | n/a | contract §6.4 exit 2 usage error | process exit | operator clock input is format-valid but not a Gregorian date: usage error |

## Counts (derived)

| Category | n |
|---|---|
| positive | 6 |
| failure | 6 |
| caveat | 1 |
| withheld | 3 |
| indeterminate | 2 |

| Family | n |
|---|---|
| control | 1 |
| decision | 13 |
| effect | 2 |
| n/a | 2 |

**Cases emitting no verdict at all: 2** — `PROC-NGR`, `PROC-UNP`.
Every other case emits a verdict, the definitive failures included: a failure is a
*verdict*, not the absence of one. `CLS-LEX1` emits `AIREP-Authenticated` at exit 0 with a
definitive `witness-claim-invalid` and a reconstructed signing input, so it is a failure
case.

## Artifact families

**`execution` is present as bytes but never as a primary artifact.** It appears as a
`related_artifacts` member inside `CLS-P3` and `CLS-OB4`, and as fixed vector `V3`. The
package does not claim four evaluated families.

## Control scope

`CTL1` is the only **selected primary Control case in this compact scored corpus**. It is
not the only Control artifact in the release: the pinned tree carries roughly thirty more
under `schema-validation/corpus/`, plus Stage-4 material.

Separately, and more narrowly: searching every `.json` under the pinned `spec/airep/v0.2`
tree for the values `"receiver"`, `"received"` or `"delivery_failed"` returns exactly one
file — `schemas/control.schema.json`, which *defines* the enum. **No fixture in the pinned
release carries a receiver-side value.** That is a statement about this release only. It
does not imply receiver-side evidence was never produced elsewhere, and it does not imply
non-delivery. Paired control-delivery reconciliation is therefore **not tested** here, and
no paired case was synthesised.

## Sampling policy, and the population it samples from

| Population of the 60 scored source cases | Count |
|---|---|
| contains at least one **definitive failure** reason | **22** |
| contains **withheld** reasons only, no failure | **35** |
| **fully clean** — neither failure nor withheld | **3** |

This package selects **all 3** clean cases and **6 of the 22** definitive-failure cases.

**That is not a proportionate sample, and no balance claim is made.** An earlier draft
asserted the selection was "not a favourable subset"; the assertion did not survive
checking and is withdrawn.

The policy is **rule coverage, not proportional representation**: one case per distinct
normative property, so a verifier passing all 18 has exercised each rule at least once.
Omitted failure cases each duplicate a property already covered — `PB1`, `PB3` and `XT1`
all exercise producer-binding rejection, and only `XT1` is selected.

A reader wanting proportional coverage of the failure space should use the full public
60-case release corpus. This is the compact set, and compactness has a cost stated here
rather than argued away.

## Byte material

Per-case canonical bytes and hash preimages for **17 of 18** cases; signature preimages for
the 16 with a resolving producer binding; the full chain for the 6 fixed vectors.
`PROC-UNP` has none — its request is unparseable by design.
