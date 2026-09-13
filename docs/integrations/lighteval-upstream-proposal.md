# Design note — a generic evaluation-evidence exporter hook for LightEval

**Status:** design note, not a proposal that has been made. No upstream pull request has been
opened against `huggingface/lighteval`, `huggingface/hub-docs`, Inspect or OpenEvals, and
nothing here claims Hugging Face review or endorsement.

## What LightEval does today (inspected `main`, September 2026)

`lighteval.logging.evaluation_tracker.EvaluationTracker` coordinates the loggers and owns the
output path:

- `EvaluationTracker.results` assembles one dictionary with `config_general`, `results`,
  `versions`, `config_tasks`, `summary_tasks` and `summary_general`.
- `EvaluationTracker.save()` computes a `date_id`, writes `results_{date_id}.json` through
  `save_results`, writes `details_{task}_{date_id}.parquet` through `save_details`, and then,
  depending on flags, calls `push_to_hub`, `push_to_wandb` or the TensorBoard exporter.
- `push_to_hub` uploads the results JSON and details parquet to a `details_{model}` dataset
  repository and regenerates its metadata card.
- `GeneralConfigLogger.start_time` / `end_time` are `time.perf_counter()` values; the wall-clock
  identity of a run lives in the `date_id` embedded in the filenames.

Every downstream consumer therefore has to re-derive provenance from files and filenames after
the fact. There is no point at which a third party can be handed "the exact bytes that were just
written, and their identities" by the tracker itself.

## Proposed abstraction (generic, not AIREP-specific)

Add an optional, ordered list of **evidence exporters** to `EvaluationTracker`, invoked once
per `save()` after the native files exist and before any push:

```python
class EvidenceExporter(Protocol):
    def export(self, event: EvaluationEvidenceEvent) -> None: ...

@dataclass(frozen=True)
class EvaluationEvidenceEvent:
    date_id: str
    results_path: str                 # results_{date_id}.json as written
    results: dict                     # the same dictionary that was serialised
    details_paths: dict[str, str]     # task_name -> details parquet path
    general_config: GeneralConfigLogger
    task_configs: dict[str, LightevalTaskConfig]
    versions: dict[str, int]
```

`EvaluationTracker(..., evidence_exporters=[...])` would call each exporter inside `save()`;
an exporter failure is logged and must not abort the native save.

Design constraints the hook must respect:

1. **Native formats are untouched.** `results_*.json`, `details_*.parquet`, the details dataset
   card and the Hub push keep their current shape and semantics.
2. **`verifyToken` semantics are untouched.** The Hub's `.eval_results/*.yaml` `verifyToken`
   remains the Hub's own attestation that an evaluation ran under its verified path; an exporter
   may carry it as opaque platform-verification evidence and must not mint, validate or extend it.
3. **Inspect / OpenEvals semantics are untouched.** The hook is a post-write notification with
   file identities; it does not alter scoring, aggregation or logging.
4. **No new dependency in core.** The protocol is a small dataclass and a `Protocol`; concrete
   exporters live outside LightEval.
5. **Opt-in and silent by default.** No exporter is registered unless the caller passes one.

## Why a generic hook rather than an AIREP flag

An AIREP-specific option would bind LightEval to one evidence format. The hook is useful to any
consumer that needs the written bytes and their identities at the moment they are produced:
provenance systems (W3C PROV), transparency logs (SCITT registrations of a results digest),
audit tooling, or an organisation's own evidence store. AIREP's Embedded Evaluation Profile
exporter ([`integrations/lighteval/`](../../integrations/lighteval/)) would be **one consumer**
of the hook: it would hash `results_path` and `details_paths`, take `task_configs` and
`general_config` as the mapping source, and still require its own explicitly declared context
for evaluator identity, independence and access tier — the hook cannot and should not supply those.

## What the hook would not do

- It would not assert that a run is complete, correct, reproducible or safe.
- It would not replace the Hub results push or the model-card results widget.
- It would not compute or verify any signature; integrity is the consumer's business.

## Sequencing

1. Keep the Phionyx-side exporter working against the files LightEval writes today (done in this
   repository; tests run on synthetic LightEval-shaped data).
2. Gather at least one external consumer that would use the same hook.
3. Only then open an upstream issue describing the `EvidenceExporter` protocol, with the
   AIREP exporter and one non-AIREP exporter as worked examples.
