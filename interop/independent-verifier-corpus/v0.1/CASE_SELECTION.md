# Case selection

Selected from the 60 scored class-verification cases (45 C0 + 15 C1) and the 15
release-declared CLI/process-exit probes at the pinned commit.

## Probe count reconciliation

Three different numbers are easy to conflate, so all three are stated:

| Quantity | Count |
|---|---|
| Release-declared official CLI/process-exit probes (`probe_index.json`) | **15** |
| Of those, probes with input-file directories on disk | **13** |
| CLI-only probes with no input files (`PRB-CLI-CORPUS-NO-OUT`, `PRB-CLI-HELP`) | **2** |
| Filesystem entries under `corpus/probes/` (13 dirs + `probe_index.json`) | **14** |

Not every directory is an official scored probe, and not every official probe has a directory.

## Selection matrix

| Pkg id | Source | Source path | Normative rule | Unique property | Category | Family | Capabilities | Not redundant because | Does not establish |
|---|---|---|---|---|---|---|---|---|---|
| `CLS-P1` | `P1` | `spec/airep/v0.2/class-verification/corpus/cases/P1` | INTEGRITY §2,§3; contract §3 stages 0-5 | expected class earned cleanly | positive | decision | JCS,SHA-256,Ed25519,schema,trust binding,revocation | clean Decision earns AIREP-Authenticated; witness absent is WITHHELD not FAIL | one release-pinned case only; no claim beyond it |
| `CLS-P2` | `P2` | `spec/airep/v0.2/class-verification/corpus/cases/P2` | contract §3 stages 6-11; INTEGRITY §4 | expected class earned cleanly | positive | decision | JCS,SHA-256,Ed25519,schema,trust binding,revocation,freshness,independence | clean witnessed Decision earns AIREP-Witnessed with all five channels empty | one release-pinned case only; no claim beyond it |
| `CLS-P3` | `P3` | `spec/airep/v0.2/class-verification/corpus/cases/P3` | contract §3 observer assessment; AD-03 | expected class earned cleanly | positive | effect | JCS,SHA-256,Ed25519,schema,reference resolution,trust binding,observer assessment | clean Effect with referenced Execution; observer assessment independent | one release-pinned case only; no claim beyond it |
| `CLS-CTL1` | `CTL1` | `spec/airep/v0.2/class-verification/corpus/cases/CTL1` | control.schema.json; INTEGRITY §5 | expected class earned cleanly | positive | control | JCS,SHA-256,Ed25519,schema,trust binding | clean issuer-side Control Evidence artifact | one release-pinned case only; no claim beyond it |
| `CLS-NG1` | `NG1` | `spec/airep/v0.2/class-verification/corpus/cases/NG1` | INTEGRITY §4.3; non-genesis head | expected class earned cleanly | positive | decision | JCS,SHA-256,Ed25519,reference resolution,freshness | witness over a NON-GENESIS chain head | one release-pinned case only; no claim beyond it |
| `CLS-FR3` | `FR3` | `spec/airep/v0.2/class-verification/corpus/cases/FR3` | contract §3 stage 10 boundary | expected class earned cleanly | positive | decision | freshness | freshness exactly at the window boundary still earns Witnessed | one release-pinned case only; no claim beyond it |
| `CLS-PS1` | `PS1` | `spec/airep/v0.2/class-verification/corpus/cases/PS1` | INTEGRITY §3; contract stage 4 | definitive normative failure | failure | decision | Ed25519,trust binding | record signature made with a key other than the bound one | one release-pinned case only; no claim beyond it |
| `CLS-PS2` | `PS2` | `spec/airep/v0.2/class-verification/corpus/cases/PS2` | INTEGRITY §3.2 wire alg informative only | passes while recording a caveat | caveat | decision | Ed25519,trust binding | valid Ed25519 signature, misleading wire alg: the binding selects the suite, not the wire label | one release-pinned case only; no claim beyond it |
| `CLS-XT1` | `XT1` | `spec/airep/v0.2/class-verification/corpus/cases/XT1` | contract §3 stage 3 revocation | definitive normative failure | failure | decision | revocation,trust binding | producer binding revoked in the snapshot: definitive FAILURE | one release-pinned case only; no claim beyond it |
| `CLS-IND4` | `IND4` | `spec/airep/v0.2/class-verification/corpus/cases/IND4` | contract §1.2 independence policy | definitive normative failure | failure | decision | independence policy | producer/witness pair listed non-independent: definitive witness FAILURE | one release-pinned case only; no claim beyond it |
| `CLS-FR1` | `FR1` | `spec/airep/v0.2/class-verification/corpus/cases/FR1` | contract §3 stage 10 freshness | definitive normative failure | failure | decision | freshness | witness outside the freshness window | one release-pinned case only; no claim beyond it |
| `CLS-WM3` | `WM3` | `spec/airep/v0.2/class-verification/corpus/cases/WM3` | contract §0 reference resolution | definitive normative failure | failure | decision | reference resolution | head_ref names a record_id present in neither artifact nor related_artifacts | one release-pinned case only; no claim beyond it |
| `CLS-PB2` | `PB2` | `spec/airep/v0.2/class-verification/corpus/cases/PB2` | contract §4 withheld vs failure; stage 2 | assurance withheld, not failed | withheld | decision | trust binding | no producer binding entry: assurance WITHHELD, not failed | one release-pinned case only; no claim beyond it |
| `CLS-WB2` | `WB2` | `spec/airep/v0.2/class-verification/corpus/cases/WB2` | contract §4; stage 7 | assurance withheld, not failed | withheld | decision | trust binding | no witness binding entry: witness assurance WITHHELD | one release-pinned case only; no claim beyond it |
| `CLS-OB4` | `OB4` | `spec/airep/v0.2/class-verification/corpus/cases/OB4` | contract §3 observer assessment | assurance withheld, not failed | withheld | effect | reference resolution,observer assessment | Effect declares independent; referenced Execution cannot earn the class, so observer is unknown | one release-pinned case only; no claim beyond it |
| `CLS-LEX1` | `LEX1` | `spec/airep/v0.2/class-verification/corpus/cases/LEX1` | INTEGRITY §2 lexical form; E-1 | no verdict can be produced | indeterminate | decision | JCS,lexical preservation | witness claim length written 1e0: the semantic JSON value alone is insufficient | one release-pinned case only; no claim beyond it |
| `PROC-UNP` | `PRB-REQUEST-UNPARSEABLE` | `spec/airep/v0.2/class-verification/corpus/probes/PRB-REQUEST-UNPARSEABLE` | contract §6.4 exit 1 run-invalid | no verdict can be produced | indeterminate | n/a | process exit | request is not parseable: run-invalid, no verdict is emitted | one release-pinned case only; no claim beyond it |
| `PROC-NGR` | `PRB-CLI-NOW-NOT-GREGORIAN` | `spec/airep/v0.2/class-verification/corpus/probes/PRB-CLI-NOW-NOT-GREGORIAN` | contract §6.4 exit 2 usage error | no verdict can be produced | indeterminate | n/a | process exit | operator clock input is format-valid but not a Gregorian date: usage error | one release-pinned case only; no claim beyond it |

## Artifact families

`decision` 13 · `effect` 2 · `control` 1 · 2 process probes evaluate no artifact.

**`execution` is present as bytes but never as a primary artifact.** It appears as a
`related_artifacts` member inside `CLS-P3` and `CLS-OB4`, which is how the frozen corpus
exercises the family. The package does not claim four evaluated families.

## Control delivery

`CTL1` is the only Control artifact in the release (`issuer` / `dispatched`). No receiver-side
artifact and no paired delivery case exists at the pin, so paired control-delivery
reconciliation is **not** tested and none was synthesised. Absence of a receiver-side record
does not prove non-delivery.

## Sampling policy, and the population it samples from

The 60 scored source cases break down as:

| Population | Count |
|---|---|
| contains at least one **definitive failure** reason | **22** |
| contains **withheld** reasons only, no failure | **35** |
| **fully clean** — neither failure nor withheld | **3** |

This package selects **all 3** fully clean cases and **6 of the 22** definitive-failure cases.

**That is not a proportionate sample, and no balance claim is made.** An earlier draft asserted the
selection was "not a favourable subset" on the strength of a count that had `CLS-LEX1`
miscategorised; the assertion did not survive checking and has been withdrawn.

The actual policy is **rule coverage, not proportional representation**: one case per distinct
normative property, chosen so that a verifier which passes all 18 has exercised each rule at least
once. Sixteen definitive-failure cases are deliberately omitted because each duplicates a property
already covered — for example, `PB1`, `PB3` and `XT1` all exercise producer-binding rejection, and
only `XT1` is selected.

A reader who wants proportional coverage of the failure space should use the full 60-case release
corpus, which is public. This package is the compact set, and compactness has a cost that is
stated here rather than argued away.

## Byte material

Per-case canonical bytes and hash preimages are provided for **17 of 18** cases; signature
preimages for the 16 with a resolving producer binding; the full chain for the 6 fixed vectors.
`PROC-UNP` has none — its request is unparseable by design. See the README table.
