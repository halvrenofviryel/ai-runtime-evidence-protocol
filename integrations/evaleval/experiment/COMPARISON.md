# Same-source comparison

This comparison covers two derived representations of the same real LightEval evidence. The native
JSON and Parquet bytes remain authoritative. “Represented” below does not mean independently true;
source facts, declarations, derivations, validator results and analyst conclusions are separated.

## 1. Source run identity

LightEval `0.13.1.dev0` at commit `6b9d193b48de24d1ee87f3089303643b993cf4f9`
ran `sshleifer/tiny-gpt2` at revision
`5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be` on the HellaSwag validation task.
The task dataset was pinned to `Rowan/hellaswag` revision
`218ec52e09a7e7462a5400043bb9a69a41d06b76`. The run used CPU, no credential
and a two-sample cap. The native selector `results['hellaswag|0']['em']` reports `0.0` and
`em_stderr` reports `0.0`.

Those identifiers are source configuration facts. They do not cryptographically prove which model
weights executed. The two-row Parquet and run window support the local statement that the selected
run produced two details rows between the separately captured UTC timestamps; they do not establish
complete HellaSwag coverage.

## 2. Exact native files and digests

| Role | Path under `native/` | Bytes | SHA-256 |
|---|---|---:|---|
| Aggregate result | `results/sshleifer/tiny-gpt2/results_2026-09-24T00-59-40.590371.json` | 3,827 | `1b3464e5237d77d648b1960b7a879f4674d59a3c04d97279135a1b0fa59e103b` |
| Sample details | `details/sshleifer/tiny-gpt2/2026-09-24T00-59-40.590371/details_hellaswag_0_2026-09-24T00-59-40.590371.parquet` | 24,016 | `c4f6ea15515ff7f0d1cfc9a6c23e1079dfc5b07fa508dab717d12777f315b298` |
| UTC run window | `run-window.json` | 95 | `e42b54daf171792af018ac1cfd309ae483cb4297f38d2bf83d807ccc91b6bc89` |

The original LightEval details filename contained `hellaswag|0`; only that filename was made
portable when copied. The Parquet bytes and digest are unchanged. LightEval's filename date id is
timezone-naive and is not interpreted as UTC.

## 3. EEE representation

The local mapper emitted EEE schema `0.3.0` record
`f741fa4b-ad52-42c5-9820-d2b9f93d1723.json` (SHA-256
`ae3f6c27bc2f5cc4ab6c0df6793940cf093d2fecf56857b849e7eec7af8a62fb`). The
record preserves the exact selected score and standard error, metric direction/range, metric source
functions, model/dataset revisions, generation parameters, configuration digests and the two-sample
cap. It explicitly says population completeness, a criterion, a source verdict and executed identity
are not established.

The mapper is local, non-upstream and not endorsed by EvalEval. EEE `evaluation_timestamp` is omitted
because upstream issue #237 leaves its wire format unresolved. `retrieved_timestamp` is the mapping
record creation time, not evaluation time.

The pinned EEE validator at commit `d734a861e80e1aae136e617007b74bce5bfe156a` exited `0`,
reported `valid: true`, and produced no errors or warnings. This is a validator result, not an
interoperability or truth result.

## 4. AIREP representation

The existing AIREP LightEval exporter emitted `embedded-evaluation.profile.json` (SHA-256
`b4eb510d82fafc0d78aa4f2d69be773d24f2760dd31dd813fc290f324db7f5a8`) and an
evidence manifest (SHA-256
`d7e0126b7097a9bb4286e3d21a53447197fa9a1e59f81b0c65b04de72bdc087d`). The
payload validates against profile schema SHA-256
`ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b`.

The profile records `RAN`, the raw `em=0.0` observation, and explicit `INCONCLUSIVE`. Its criterion
statement says no PASS/FAIL threshold was predeclared. It records access, UTC run window, safeguards
unknown, evidence digests/visibility, the deliberate sample-cap deviation and negative scope. It does
not wrap the evaluation trace into AIREP Decision, Control, Execution or Effect artifacts.

## 5. Information represented in both

- LightEval name, package version and exact source revision.
- Target model id and configured revision, with an explicit verification limit.
- HellaSwag task, dataset, pinned dataset revision and validation split.
- Exact selected native metric value `0.0`.
- Native general/task configuration digests and sample cap/limitation.
- A declared evaluator/source organization relationship, without proving identity or independence.

## 6. Information represented only by EEE

- Typed metric id/kind/unit, lower-is-better flag, `[0,1]` range and continuous score type.
- Source-reported standard error and its method label.
- Generation arguments and task-generation detail such as temperature, prompt function, stop
  sequence and few-shot count.
- A natural destination for richer aggregate/instance result semantics. The native Parquet is not
  converted into an EEE instance companion in this experiment.

## 7. Information represented only by AIREP

- Separate execution state, criterion statement and observation status.
- Evaluator access tier, capabilities and limitations.
- Independence status, conflict-disclosure state and declaration basis.
- Offset-bearing run interval, runtime environment and safeguard state.
- Evidence role, visibility, resolvability and recomputed digest over supplied bytes.
- Disclosure of the material sample-cap deviation and explicit `covers`/`does_not_cover` boundaries.

## 8. Information requiring explicit context in either mapping

The native LightEval files do not state evaluator organization/relationship, model deployment and
availability classification, metric registry classification/range, independence, conflicts, access
tier, safeguard state, wall-clock UTC interval, evidence visibility or claim scope. Those are
declarations in the two context JSON files. The EEE metric registry id/kind/unit/range are supplied
under the pinned EEE field guidance and checked against the native `higher_is_better` value. The
AIREP execution/observation wording and limitations are explicit context; only the metric value and
configuration references are selected from native results.

## 9. Information that neither representation establishes

Neither output establishes the factual truth of declarations, exact executed weight bytes, result
truth, benchmark completeness, representativeness, evaluator competence or independence, model
capability/safety/alignment, general reproducibility, EvalEval endorsement, or interoperability
between EEE and AIREP.

## 10. Claim-preservation risks

The highest-risk transforms are raw score → PASS/FAIL without a prior criterion; `third_party` →
independent; configured revision → verified execution identity; `max_samples=2` → complete coverage;
path/URL → public and resolvable evidence; reported checksum → recomputed digest; timezone-naive
filename → UTC time; and validator PASS → semantic truth. The mapper or context explicitly refuses,
qualifies or records each of these. Details and R-CP mappings are in `CROSSWALK.md`.

## 11. What this experiment does NOT establish

This experiment does not show semantic equivalence, bidirectional lossless conversion, a shared
conformance suite, EvalEval adoption, official converter status, model performance, model safety, or
independent reproducibility. It demonstrates only that one pinned native run can be represented in
both current structures while material differences and non-claims remain visible.
