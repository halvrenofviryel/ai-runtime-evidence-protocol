# Semantic crosswalk: EEE ↔ AIREP Embedded Evaluation Profile 0.1

This is a semantic comparison of the pinned sources in [SOURCES.md](./SOURCES.md), not a field-name
matching exercise. “Safe” means a transformation can preserve the represented claim under the
listed qualification. It does not mean the two schemas are equivalent. The authoritative row data,
including loss notes and source paths, is in [CROSSWALK.json](./CROSSWALK.json).

## Classification summary

| Class | Count | Reading |
|---|---:|---|
| `EXACT_OR_NEAR_EXACT` | 4 | A value can usually be copied with source identity retained. |
| `PARTIAL` | 10 | Both represent part of the concept, with material scope or granularity differences. |
| `EEE_ONLY` | 6 | The current EEE forms carry detail the AIREP companion profile does not model. |
| `AIREP_ONLY` | 7 | The current AIREP profile makes evaluation-context or claim-boundary state explicit. |
| `DERIVABLE_WITH_QUALIFICATION` | 1 | A new derived fact can be recorded only with provenance and method. |
| `NOT_SAFELY_DERIVABLE` | 3 | A value would require unsupported inference or a new assertion. |
| `DIFFERENT_CLAIM` | 4 | Superficially related fields make materially different assertions. |

The result is deliberately not “EEE is metadata, AIREP is evidence.” EEE carries metric direction,
ranges, uncertainty, rich generation configuration, source relationship, agent/tool/sandbox state,
and sample traces. Conversely, the AIREP profile deliberately does not try to be an instance-result
schema; it emphasizes explicit evaluation state, declarations, evidence availability and scope.

## Main findings

1. Raw metric values, task identity, framework revision and evaluation/run identity can be preserved
   in this experiment, but only because the selected source is singular and revisions are pinned.
2. EEE's `evaluator_relationship` is relative to the model developer. It is not the AIREP profile's
   declaration of independence, conflict disclosure and basis.
3. An EEE score has no general transformation into AIREP `PASS` or `FAIL`. A predeclared criterion
   and chronology are additional facts. This experiment records `INCONCLUSIVE` and no threshold.
4. AIREP's `execution_status`, evidence visibility/resolvability, disclosure and `does_not_cover`
   have no single aggregate EEE equivalent. They must not be inferred from file presence or run exit.
5. EEE's metric direction/range, uncertainty and instance traces have no lossless AIREP destination.
   AIREP can retain the native files as evidence, but that is not the same as representing their
   internal semantics.
6. Digests are safely transferable only when the destination says what bytes were actually hashed.
   Reported checksums, flat-object hashes and recomputed local hashes are distinct observations.
7. EEE's unresolved `evaluation_timestamp` format is an upstream ambiguity, not permission for a
   mapper to normalize silently. The local mapper omits it and records an offset-bearing run window
   only in the AIREP context.

## Claim-preservation hazards in EEE ↔ AIREP transformation

| Hazard | Source → destination | Loss/change and safe treatment | R-CP | Exercised? |
|---|---|---|---|---|
| Result selection ambiguity | LightEval/EEE multi-result → one AIREP observation | Selecting `all`, an unqualified metric, or one of multiple tasks changes the claim. Require exact task+metric and refuse multi-task input. | R-CP-1, R-CP-2 | Yes, negative tests. |
| Execution/observation/assessment collapse | Completed run + raw score → AIREP PASS | Process completion and a score do not establish a criterion verdict. Preserve `RAN`, metric value, and explicit `INCONCLUSIVE`. | R-CP-3, R-CP-5 | Yes. |
| Direction/range loss | EEE metric config → AIREP observation | A numeric value without “higher is better” and range can reverse interpretation. Retain native evidence; mapper refuses missing/contradictory direction. | R-CP-4 | Yes. |
| Numerical transformation | Rounded/normalized score → threshold result | Rounding can cross a threshold. Do not create a criterion; retain the exact JSON number and label later calculations as derived. | R-CP-4, R-CP-5 | Yes, negative test. |
| Criterion laundering | EEE raw score → AIREP criterion | A criterion is a new assertion unless source/declaration supports its chronology. The experiment declares that no PASS/FAIL threshold was predeclared. | R-CP-5 | Yes. |
| Coverage/denominator loss | `max_samples=2` → “complete benchmark” | A cap is neither exact population nor completeness. Record the cap and limitation; do not infer denominator. | R-CP-6 | Yes. |
| Identity strengthening | Model/revision string → executed checkpoint verified | Configuration identifies intended inputs, not cryptographic execution identity. Preserve identifiers and state the verification limit. | R-CP-7 | Yes. |
| Relationship strengthening | EEE `third_party` → independent evaluator | Relationship and independence are different claims. AIREP records `unknown` independence with a basis. | R-CP-7 | Yes. |
| Evidence strengthening | URL/path/checksum → public, resolvable, recomputed bytes | Keep visibility, resolvability, hash scope and hash origin separate. Hash only bytes supplied to the exporter. | R-CP-8 | Yes. |
| Multi-hop loss | native → EEE/AIREP → later consumer | Qualification can disappear after a second transform. Each output retains source digests, mapping identity and non-claims. | R-CP-9, R-CP-10 | Partly; second hop is analyzed, not executed. |
| Schema truth laundering | Validator PASS → semantic truth/interoperability | Validation checks a pinned structural/semantic model only. Reports explicitly deny truth, safety and interoperability. | R-CP-10 | Yes. |
| Downstream attribution | Analyst threshold → source evaluator verdict | A later judgment must name its author/basis. No such judgment is added here. | R-CP-11 | Yes, by refusal. |
| Mapping drift | Moving EEE/datastore/profile → undocumented conversion | Pin code, datastore, schemas, model, dataset and mapper version; retain validation evidence. | R-CP-12 | Yes. |

## Directional interpretation

EEE → AIREP can safely carry a selected raw observation and identifiers when the mapping keeps the
native artifact, selector, direction and limitations. It cannot synthesize independence, evidence
availability, a threshold or a verdict. AIREP → EEE can carry identifiers and a numeric observation
only if the destination metric semantics are known; it cannot flatten AIREP execution, disclosure,
scope and evidence states into a score without loss. Instance-level EEE messages/tool calls are not
AIREP Decision/Control/Execution/Effect lifecycle artifacts.
