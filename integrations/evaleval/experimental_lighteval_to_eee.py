#!/usr/bin/env python3
"""Experimental LightEval -> EEE aggregate mapper for the AIREP study.

This is a first-party AIREP research mapping. It is not an EvalEval converter,
is not upstream, is not endorsed by EvalEval, and is not interoperability
evidence. Native LightEval bytes remain authoritative.

The mapper deliberately handles one narrow, pinned source shape: one selected
LightEval task and one selected numeric metric. Values that LightEval does not
carry must be declared in the context file, and claim-strengthening defaults
are refused.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import sys
import uuid


MAPPER_ID = "airep-study.lighteval-to-eee"
MAPPER_VERSION = "0.1.0"
EEE_SCHEMA_VERSION = "0.3.0"


class MappingError(ValueError):
    """The source and declarations do not support the requested mapping."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MappingError(f"duplicate JSON member {key!r} is ambiguous")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MappingError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise MappingError(f"{label} must be a JSON object")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require_path(value: dict, path: str) -> object:
    node: object = value
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise MappingError(f"explicit context is required for {path}; it is never inferred")
        node = node[part]
    return node


def require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MappingError(f"{name} must be a non-empty string")
    return value.strip()


def epoch_text(rfc3339: object, name: str) -> str:
    text = require_text(rfc3339, name)
    if text.endswith("Z"):
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    else:
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MappingError(f"{name} must carry an explicit timezone offset")
    return f"{parsed.timestamp():.6f}".rstrip("0").rstrip(".")


def stable_uuid(source_raw: bytes, task: str, metric: str) -> str:
    seed = hashlib.sha256(source_raw + b"\0" + task.encode() + b"\0" + metric.encode()).digest()
    raw = bytearray(seed[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _validate_context(context: dict) -> None:
    forbidden = {
        "criterion": "LightEval does not establish a predeclared criterion",
        "source_verdict": "a score must not be promoted to a source PASS/FAIL verdict",
        "independence": "EEE evaluator_relationship is not proof of independence",
        "population_complete": "max_samples is not a completeness claim",
        "evidence_available": "a native path or URL does not establish later availability",
    }
    for field, reason in forbidden.items():
        if field in context:
            raise MappingError(f"context field {field!r} is refused: {reason}")
    relationship = require_text(
        require_path(context, "source.evaluator_relationship"),
        "source.evaluator_relationship",
    )
    if relationship not in {"first_party", "third_party", "collaborative", "other"}:
        raise MappingError("source.evaluator_relationship is not an EEE enum value")
    if require_path(context, "source.source_type") != "evaluation_run":
        raise MappingError("this mapper consumes native run output; source_type must be evaluation_run")


def build_record(source_raw: bytes, context_raw: bytes) -> tuple[dict, dict, str]:
    source = strict_json(source_raw, "LightEval results")
    context = strict_json(context_raw, "mapping context")
    _validate_context(context)

    results = source.get("results")
    configs = source.get("config_tasks")
    general = source.get("config_general")
    if not isinstance(results, dict) or not isinstance(configs, dict) or not isinstance(general, dict):
        raise MappingError("unsupported LightEval result shape: results/config_tasks/config_general are required")

    task = require_text(require_path(context, "selector.task"), "selector.task")
    metric = require_text(require_path(context, "selector.metric"), "selector.metric")
    if task == "all":
        raise MappingError("the LightEval synthetic 'all' aggregate is not an unambiguous source task")
    non_all = [name for name in results if name != "all"]
    if task not in results:
        raise MappingError(f"selected task {task!r} is absent; available source tasks: {non_all!r}")
    if len(non_all) != 1:
        raise MappingError("this narrow mapper refuses multi-task input; split or select under a reviewed mapping")
    task_result = results[task]
    task_config = configs.get(task)
    if not isinstance(task_result, dict) or not isinstance(task_config, dict):
        raise MappingError("selected task needs both a result object and its exact task configuration")
    if metric not in task_result:
        raise MappingError(f"selected metric {metric!r} is absent from task {task!r}")
    score = task_result[metric]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise MappingError("selected score must be a finite JSON number, not a boolean")

    metric_defs = task_config.get("metrics")
    if not isinstance(metric_defs, list):
        raise MappingError("task configuration has no metric definitions")
    matching = [item for item in metric_defs if isinstance(item, dict) and item.get("metric_name") == metric]
    if len(matching) != 1:
        raise MappingError("selected metric must resolve to exactly one native metric definition")
    metric_def = matching[0]
    higher = metric_def.get("higher_is_better")
    if not isinstance(higher, bool):
        raise MappingError("metric direction is absent; lower_is_better must not be guessed")

    max_samples = general.get("max_samples")
    if isinstance(max_samples, bool) or not isinstance(max_samples, int) or max_samples <= 0:
        raise MappingError("this experiment requires an explicit positive max_samples cap")

    native_commit = require_text(general.get("lighteval_sha"), "config_general.lighteval_sha")
    expected_commit = require_text(
        require_path(context, "expected.lighteval_commit"), "expected.lighteval_commit"
    )
    if native_commit != expected_commit:
        raise MappingError(f"LightEval commit mismatch: {native_commit} != {expected_commit}")

    model_config = general.get("model_config")
    if not isinstance(model_config, dict):
        raise MappingError("native model_config is required")
    generation_parameters = model_config.get("generation_parameters")
    if not isinstance(generation_parameters, dict):
        raise MappingError("native model_config.generation_parameters must be an object")
    model_id = require_text(model_config.get("model_name") or general.get("model_name"), "model name")
    model_revision = require_text(model_config.get("revision"), "model revision")
    if model_id != require_path(context, "expected.model_id"):
        raise MappingError("declared model id does not match the native run configuration")
    if model_revision != require_path(context, "expected.model_revision"):
        raise MappingError("declared model revision does not match the native run configuration")

    dataset_repo = require_text(task_config.get("hf_repo"), "task hf_repo")
    dataset_revision = require_text(task_config.get("hf_revision"), "task hf_revision")
    if dataset_repo != require_path(context, "expected.dataset_repo"):
        raise MappingError("declared dataset repo does not match the native task configuration")
    if dataset_revision != require_path(context, "expected.dataset_revision"):
        raise MappingError("declared dataset revision does not match the native task configuration")
    splits = task_config.get("evaluation_splits")
    if not isinstance(splits, list) or len(splits) != 1 or not isinstance(splits[0], str):
        raise MappingError("this mapper requires exactly one explicit evaluation split")

    stderr_key = require_text(require_path(context, "selector.stderr_metric"), "selector.stderr_metric")
    stderr = task_result.get(stderr_key)
    if isinstance(stderr, bool) or not isinstance(stderr, (int, float)) or not math.isfinite(stderr):
        raise MappingError("the selected source standard error must be a finite number")

    source_digest = sha256(source_raw)
    record_id = stable_uuid(source_raw, task, metric)
    raw_model_id = model_id
    developer, model_name = raw_model_id.split("/", 1) if "/" in raw_model_id else (None, raw_model_id)
    if not developer:
        raise MappingError("model id has no source-supported developer prefix")
    evaluation_id = f"{task.split('|', 1)[0]}/{raw_model_id.replace('/', '_')}/{source_digest[7:23]}"

    task_config_digest = sha256(canonical(task_config))
    general_config_digest = sha256(canonical(general))
    metric_id = require_text(require_path(context, "metric.metric_id"), "metric.metric_id")
    metric_kind = require_text(require_path(context, "metric.metric_kind"), "metric.metric_kind")
    metric_unit = require_text(require_path(context, "metric.metric_unit"), "metric.metric_unit")
    score_type = require_text(require_path(context, "metric.score_type"), "metric.score_type")
    min_score = require_path(context, "metric.min_score")
    max_score = require_path(context, "metric.max_score")
    if (
        isinstance(min_score, bool)
        or isinstance(max_score, bool)
        or not isinstance(min_score, (int, float))
        or not isinstance(max_score, (int, float))
        or not math.isfinite(min_score)
        or not math.isfinite(max_score)
        or min_score >= max_score
    ):
        raise MappingError("metric min_score/max_score must be finite numbers with min_score < max_score")
    if not min_score <= score <= max_score:
        raise MappingError("selected score falls outside the explicitly declared metric range")
    lower_is_better = not higher
    declared_lower = require_path(context, "metric.lower_is_better")
    if declared_lower is not lower_is_better:
        raise MappingError("declared EEE metric direction contradicts LightEval higher_is_better")

    record = {
        "schema_version": EEE_SCHEMA_VERSION,
        "evaluation_id": evaluation_id,
        "retrieved_timestamp": epoch_text(
            require_path(context, "record_created_at"), "record_created_at"
        ),
        "source_metadata": {
            "source_name": require_text(require_path(context, "source.source_name"), "source.source_name"),
            "source_type": "evaluation_run",
            "source_organization_name": require_text(
                require_path(context, "source.source_organization_name"),
                "source.source_organization_name",
            ),
            "evaluator_relationship": require_path(context, "source.evaluator_relationship"),
            "additional_details": {
                "relationship_basis": require_text(
                    require_path(context, "source.relationship_basis"), "source.relationship_basis"
                ),
                "native_results_sha256": source_digest[7:],
                "mapping_profile": MAPPER_ID + "@" + MAPPER_VERSION,
            },
        },
        "eval_library": {
            "name": "lighteval",
            "version": require_text(require_path(context, "lighteval.package_version"), "lighteval.package_version"),
            "additional_details": {
                "repository": "https://github.com/huggingface/lighteval",
                "commit": native_commit,
                "general_config_sha256": general_config_digest[7:],
                "max_samples_cap": str(max_samples),
                "partial_run": "true",
            },
        },
        "model_info": {
            "name": model_name,
            "id": raw_model_id,
            "developer": developer,
            "inference_platform": require_text(
                require_path(context, "model.inference_platform"), "model.inference_platform"
            ),
            "inference_engine": {
                "name": require_text(
                    require_path(context, "model.inference_engine.name"),
                    "model.inference_engine.name",
                ),
                "version": require_text(
                    require_path(context, "model.inference_engine.version"),
                    "model.inference_engine.version",
                ),
            },
            "additional_details": {
                "revision": model_revision,
                "deployment_type": require_text(
                    require_path(context, "model.deployment_type"), "model.deployment_type"
                ),
                "model_availability": require_text(
                    require_path(context, "model.model_availability"), "model.model_availability"
                ),
                "model_id_resolution": "source-hf-id; registry lookup not performed",
                "executed_identity_status": "declared-by-native-run-config; not independently verified",
            },
        },
        "evaluation_results": [
            {
                "evaluation_result_id": f"{task}#{metric}",
                "evaluation_name": task,
                "source_data": {
                    "dataset_name": require_text(
                        require_path(context, "dataset.dataset_name"), "dataset.dataset_name"
                    ),
                    "source_type": "hf_dataset",
                    "hf_repo": dataset_repo,
                    "hf_split": splits[0],
                    "additional_details": {
                        "dataset_revision": dataset_revision,
                        "task_configuration_sha256": task_config_digest[7:],
                        "max_samples_cap": str(max_samples),
                        "population_completeness": "not established",
                    },
                },
                "metric_config": {
                    "evaluation_description": require_text(
                        require_path(context, "metric.description"), "metric.description"
                    ),
                    "metric_id": metric_id,
                    "metric_name": metric,
                    "metric_kind": metric_kind,
                    "metric_unit": metric_unit,
                    "lower_is_better": lower_is_better,
                    "score_type": score_type,
                    "min_score": min_score,
                    "max_score": max_score,
                    "additional_details": {
                        "metric_id_registry_revision": require_text(
                            require_path(context, "metric.registry_revision"),
                            "metric.registry_revision",
                        ),
                        "source_metric_definition": require_text(
                            metric_def.get("sample_level_fn"), "native metric sample_level_fn"
                        ),
                        "source_corpus_aggregation": require_text(
                            metric_def.get("corpus_level_fn"), "native metric corpus_level_fn"
                        ),
                    },
                },
                "score_details": {
                    "score": score,
                    "details": {
                        "source_selector": f"results[{task!r}][{metric!r}]",
                        "partial_run": "true",
                        "max_samples_cap": str(max_samples),
                        "criterion": "not present in native LightEval results",
                        "verdict": "not attributed to source evaluator",
                    },
                    "uncertainty": {
                        "standard_error": {
                            "value": stderr,
                            "method": "source-reported by LightEval",
                        }
                    },
                },
                "generation_config": {
                    "generation_args": {
                        "temperature": generation_parameters.get("temperature")
                    },
                    "additional_details": {
                        "model_revision": model_revision,
                        "task_generation_size": str(task_config.get("generation_size")),
                        "num_fewshots": str(task_config.get("num_fewshots")),
                        "prompt_function": str(task_config.get("prompt_function")),
                        "stop_sequence": json.dumps(task_config.get("stop_sequence")),
                    },
                },
            }
        ],
    }

    output_digest = sha256(json.dumps(record, indent=2).encode("utf-8") + b"\n")
    report = {
        "study": "non-normative first-party mapping study",
        "mapper": {"id": MAPPER_ID, "version": MAPPER_VERSION},
        "source": {
            "format": "LightEval results_*.json",
            "sha256": source_digest,
            "selection": {"task": task, "metric": metric, "stderr_metric": stderr_key},
            "interpretation_basis": {
                "repository": "https://github.com/huggingface/lighteval",
                "commit": native_commit,
            },
        },
        "destination": {
            "format": "Every Eval Ever aggregate EvaluationLog",
            "schema_version": EEE_SCHEMA_VERSION,
            "output_sha256": output_digest,
        },
        "preserved_or_explicitly_derived": [
            "selected task and metric",
            "numeric score and source-reported standard error",
            "metric direction and [0,1] scale under the pinned metric guidance",
            "model and dataset identifiers plus pinned revisions",
            "LightEval version/commit, configuration digests and sample cap",
            "declared evaluator relationship, kept distinct from independence",
        ],
        "material_limits": [
            "EEE evaluation_timestamp is omitted because its upstream wire format is unresolved",
            "max_samples is a cap, not proof of exact population size or completeness",
            "no source criterion or PASS/FAIL verdict exists",
            "no evaluator independence is established",
            "model configuration names a revision but does not independently prove executed identity",
            "native details parquet is retained separately and is not converted to an EEE instance sidecar",
            "schema validation does not establish semantic equivalence, truth or interoperability",
        ],
        "not_established": [
            "model capability or safety",
            "result truth, completeness or reproducibility",
            "EvalEval or Hugging Face endorsement",
            "EEE-AIREP interoperability",
        ],
    }
    return record, report, record_id


def write_mapping(results_path: Path, context_path: Path, out_root: Path) -> tuple[Path, Path]:
    record, report, record_id = build_record(results_path.read_bytes(), context_path.read_bytes())
    destination = out_root / "data" / "hellaswag" / "sshleifer" / "tiny-gpt2"
    destination.mkdir(parents=True, exist_ok=True)
    record_path = destination / f"{record_id}.json"
    record_raw = json.dumps(record, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    record_path.write_text(record_raw, encoding="utf-8")
    report["destination"]["path"] = record_path.relative_to(out_root).as_posix()
    report_path = out_root / "mapping-report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return record_path, report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--out-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        record, report = write_mapping(args.results, args.context, args.out_root)
    except (MappingError, OSError, ValueError) as exc:
        print(f"mapping refused: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {record}")
    print(f"wrote {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
