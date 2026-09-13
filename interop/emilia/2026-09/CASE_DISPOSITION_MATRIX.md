# EMILIA case status and disposition matrix — revision 2 (selection: candidate 0.2.0)

Static inspection of the selected `evidence/revision-0.2/` bytes plus one network-less
`PRE_FREEZE_REHEARSAL` of the beta reference CLI over the eight selected records with
**proposed, first-party** operator inputs. Not a re-run of the third-party test suite
(119 tests, author-reported). Not an accepted reference run.

| Case ID | Intended question | Selected source (0.2.0) | Observed prerequisite presence | Proposed records | Disposition | Open requirement |
| --- | --- | --- | --- | --- | --- | --- |
| AEI-EMILIA-001 | Partial target delivery | `retained/AEI-EMILIA-001/` (byte-identical to 0.1.0) | Original fixture unchanged (`2d8faa1b…`); original O1/O2 preimages, governed Decision input and source-backed Control authority absent | **0** (deliberate) | Parent `ctrl-freeze-42` and targets EP-A/EP-B retained; separate ledger is non-core scope | Original Control prerequisites |
| AEI-EMILIA-002 | Freeze before entry: positive refusal | `retained/AEI-EMILIA-002/` | Native admission, reservation, serialized freeze and refusal present; production authority/currentness absent | Decision + Execution (`suppressed`) | Positive action/instruction-bound refusal → candidate `suppressed`. Not a missing-evidence case | Disclosed-projection basis remains open |
| AEI-EMILIA-003 | Indeterminate outcome | `retained/AEI-EMILIA-003/` | Native axes consistent (`provider_and_effect_indeterminate`); executor report absent | Decision | Provider entry / custody ≠ action-ran evidence; correctly no Execution | Executor source remains open |
| AEI-EMILIA-004 | Action-ran evidence, Effect absent | `AEI-EMILIA-004/` (revised) | **Native `Gate.run` execution receipt** present (`native_evidence[].kind = execution`, `outcome = executed`) **plus** action-bound trace `record.set`; `observer_report: null` | Decision + Execution (`executed`) | **Supported execution.** Effect absence is not non-effect evidence. Instrumentation (executor, collector) disclosed as new test code, distinct from the native receipt | Source-selection basis and operator inputs remain open |
| AEI-EMILIA-005 | Execution then divergent observed state | `AEI-EMILIA-005/` (revised) | Native execution receipt + trace `record.set → environment.overwrite → record.get`; `observer_report` with `observer_id`, `relationship: same_executor`, `method: local-record-store.get`, `window` | Decision + Execution (`executed`) + Effect (`observer_relationship: same_executor`) | **Supported execution + disclosed same-executor divergent observation.** Not intended success, not independent observation | Observer-policy basis remains open |

## Rehearsal findings (PRE_FREEZE_REHEARSAL, open/previously exposed)

Beta CLI `tools.airep_v02 verify` and `reconcile` at `8a6c01ec…`, offline venv from the beta's
hash-verified wheel bundle, `bwrap --unshare-net`, over the four per-case
`artifacts.proposed.json` arrays with the proposed lab operator inputs. All commands exited 0
(evaluation completed). Exit 0 means evaluation completed; it is not an acceptance of any result. Results and the operator-file revisions
they forced are recorded in first-party operator-review records that are retained privately and
not published here. Any
`withheld`, `NOT_EVALUATED` or negative state there is preserved as produced.

## Coverage limit

`COMMITTED` + `INDETERMINATE`, as described in `MAPPING_CONTRACT_v0.3.md` section 2, is exercised by no selected
case. Recorded as a coverage limit; not "covered"; no sixth case added.
