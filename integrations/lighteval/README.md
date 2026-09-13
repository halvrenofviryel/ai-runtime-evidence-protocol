# LightEval / Inspect / OpenEvals → AIREP Embedded Evaluation Profile exporter

**Status:** non-normative integration. Nothing here is part of the AIREP specification or of
the profile basis; it is one way to fill the profile from native evaluation output.

The exporter reads the files an evaluation harness already wrote, hashes them, and produces
the `airep.embedded-evaluation` companion-profile payload (profile version `0.1`, carrier
AIREP `0.2`) together with a content-addressed evidence manifest and a schema validation
report. The native result files remain the source evidence; the payload is context and
provenance metadata bound to them.

## Inputs

| Input | Evidence role | Notes |
|---|---|---|
| `--results results_*.json` | `aggregate-result` | LightEval `EvaluationTracker` results file (`config_general`, `results`, `versions`, `config_tasks`, …). |
| `--details details_*.parquet` | `sample-details` | Hashed as bytes; never parsed. |
| `--raw-output FILE` | `raw-output` | Any raw model output file. |
| `--log FILE` | `system-log` | Harness or system logs. |
| `--context context.json` | — | **Required.** Everything the exporter must not infer. See [`example_context.json`](./example_context.json). |

## What is mapped from the results file

| Native field | Profile field |
|---|---|
| `config_general.model_name`, `model_config.revision` | `target.model_id`, `target.model_revision` (context values win) |
| `config_general.lighteval_sha` | `evaluation.framework.revision` |
| `config_general` (canonical JSON digest) | `evaluation.framework.configuration_digest` |
| `config_tasks[task].hf_repo` / `hf_subset` / `hf_revision` / `evaluation_splits` | `evaluation.tasks[]` (`dataset_ref`, `dataset_revision`, `split`, `configuration_digest`) |
| `config_tasks[task].effective_num_docs` | `measurement.sample_count` |
| `results[task][metric]` vs. `criterion.threshold` | `measurement.observed.status` (`PASS`/`FAIL`), `metric_value`, `execution_status = RAN` |
| results filename date id + `total_evaluation_time_secondes` | `evaluation.started_at` / `ended_at` (LightEval's `start_time`/`end_time` are monotonic counters, not timestamps; the derivation is recorded in `measurement.limitations`) |

## What is never inferred

`engagement.independence`, `access.tier`, `access.capabilities`, `access.limitations`,
`evaluation.environment`, `evaluation.safeguards` and `scope` must be declared in the context.
A missing declaration is an error, not a default.

## Measurement-state discipline

The exporter refuses (exit `2`, no payload) when the inputs contradict each other:

- `execution_status: NOT_RUN` declared while a results file with task results is supplied;
- `RAN`/`PARTIAL` declared without a results file;
- an explicit `observed.status` that contradicts the threshold result;
- a declared metric that is absent from the results while `RAN` would be reported;
- a metric without a threshold and without an explicit observed status;
- `NOT_RUN` with anything but `NOT_MEASURED`/`NOT_APPLICABLE`; `INVALIDATED` with `PASS`/`FAIL`.

Absence of evaluation evidence is preserved as `NOT_RUN → NOT_MEASURED`; it never becomes success.

## Hugging Face `verifyToken`

If the context carries `platform_verification.verify_token` (copied from a model's
`.eval_results/*.yaml` entry), the exporter records it as
`verification[] = {kind: "platform-verification", status: "NOT_EVALUATED", digest: sha256(token)}`.
The token itself is not stored, not validated and not reinterpreted: it does not mean the model is
safe or aligned, the evaluation is complete, the evaluator is independent, or that any AIREP
assurance class applies.

## Outputs

```text
out/embedded-evaluation.profile.json   # written only when it validates against the pinned basis
out/evidence-manifest.json             # inputs with SHA-256, basis digests, claim boundaries
out/validation-report.json             # schema result; "PASS" = validates against the exact basis only
```

The schema and registry are loaded from
[`spec/airep/v0.2/profiles/embedded-evaluation/`](../../spec/airep/v0.2/profiles/embedded-evaluation/)
and the schema bytes are checked against the registry `basis_digest` before use.

## Run

```bash
python3 integrations/lighteval/export_embedded_evaluation.py \
  --results path/to/results_2026-09-12T10-20-00.000000.json \
  --details path/to/details_*.parquet \
  --context integrations/lighteval/example_context.json \
  --out-dir out/
python3 -m unittest discover -s integrations/lighteval/tests -v
```

Dependency: `jsonschema` (Draft 2020-12). No network access, no model execution.

## Boundary

The exporter does not emit an AIREP Decision, Control, Execution or Effect artifact. Wrapping the
payload in a carrier artifact is only appropriate where that family's semantics are actually
satisfied by a real governance decision, control instruction, execution or observation; packaging
benchmark output is not one of those.
