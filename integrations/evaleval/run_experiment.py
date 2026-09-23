#!/usr/bin/env python3
"""Reproduce the real LightEval run or rerun the offline EEE/AIREP mappings.

The two phases are deliberately separate. ``generate-native`` needs network
access to public model/dataset files. ``offline`` verifies and consumes only
the committed native bytes, then validates against exact pinned local sources.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

import experimental_lighteval_to_eee as eee_mapper


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
EXPERIMENT = HERE / "experiment"
NATIVE = EXPERIMENT / "native"
CONTEXT = EXPERIMENT / "context"

AIREP_START = "c77237e16902ada783f75f8056c5adf8c25c33f6"
EEE_COMMIT = "d734a861e80e1aae136e617007b74bce5bfe156a"
EEE_SCHEMA_VERSION = "0.3.0"
EEE_SCHEMA_SHA256 = "c9c6195aec8a9dfa0b2aba4924ac1aa8a184c9d8ca97cee778cb531088e39b48"
LIGHTEVAL_COMMIT = "6b9d193b48de24d1ee87f3089303643b993cf4f9"
LIGHTEVAL_PACKAGE_VERSION = "0.13.1.dev0"
MODEL_ID = "sshleifer/tiny-gpt2"
MODEL_REVISION = "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be"
DATASET_ID = "Rowan/hellaswag"
DATASET_REVISION = "218ec52e09a7e7462a5400043bb9a69a41d06b76"
PROFILE_SHA256 = "ce57bd493d1a3166051bc9029972d6be215793edcd3f1b314534959659b3da8b"


class ReproductionError(RuntimeError):
    """A pinned input or generated output failed a reproducibility check."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def git_output(root: Path, *args: str) -> str:
    run = subprocess.run(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if run.returncode:
        raise ReproductionError(f"git {' '.join(args)} failed for {root}: {run.stderr.strip()}")
    return run.stdout.strip()


def require_empty(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise ReproductionError(f"refusing non-empty output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReproductionError(f"required package is not installed: {name}") from exc


def parquet_rows(path: Path) -> int:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ReproductionError("pyarrow is required to verify the committed details row count") from exc
    return pq.read_metadata(path).num_rows


def verify_native(native_root: Path) -> tuple[dict, dict[str, Path]]:
    manifest_path = native_root / "native-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReproductionError(f"cannot read native manifest: {exc}") from exc
    files: dict[str, Path] = {}
    for item in manifest.get("files", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ReproductionError("native manifest contains an invalid file entry")
        path = native_root / item["path"]
        if not path.is_file():
            raise ReproductionError(f"missing native evidence: {path}")
        if path.stat().st_size != item.get("bytes"):
            raise ReproductionError(f"native evidence size mismatch: {path}")
        if digest(path) != item.get("sha256"):
            raise ReproductionError(f"native evidence digest mismatch: {path}")
        role = item.get("role")
        if not isinstance(role, str) or role in files:
            raise ReproductionError(f"native evidence role is absent or duplicated: {role!r}")
        files[role] = path
        if role == "sample-details" and parquet_rows(path) != item.get("rows"):
            raise ReproductionError("details parquet row count differs from native manifest")

    required = {"aggregate-result", "sample-details", "declared-wall-clock-window"}
    if set(files) != required:
        raise ReproductionError(f"native evidence roles differ: {set(files)!r} != {required!r}")
    source = json.loads(files["aggregate-result"].read_text(encoding="utf-8"))
    general = source.get("config_general") or {}
    model = general.get("model_config") or {}
    task = (source.get("config_tasks") or {}).get("hellaswag|0") or {}
    checks = {
        "LightEval commit": (general.get("lighteval_sha"), LIGHTEVAL_COMMIT),
        "model id": (model.get("model_name") or general.get("model_name"), MODEL_ID),
        "model revision": (model.get("revision"), MODEL_REVISION),
        "dataset id": (task.get("hf_repo"), DATASET_ID),
        "dataset revision": (task.get("hf_revision"), DATASET_REVISION),
        "sample cap": (general.get("max_samples"), 2),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise ReproductionError(f"native {label} mismatch: {actual!r} != {expected!r}")
    return manifest, files


def build_native_manifest(output_dir: Path, started: str, ended: str) -> dict:
    result_files = list(output_dir.glob("results/**/results_*.json"))
    detail_files = list(output_dir.glob("details/**/details_*.parquet"))
    if len(result_files) != 1 or len(detail_files) != 1:
        raise ReproductionError(
            f"expected one result and one details file; got {result_files!r}, {detail_files!r}"
        )
    result_path, detail_path = result_files[0], detail_files[0]
    source = json.loads(result_path.read_text(encoding="utf-8"))
    task_result = source["results"]["hellaswag|0"]
    run_window = output_dir / "run-window.json"
    run_window.write_text(json.dumps({"started_at": started, "ended_at": ended}, indent=2) + "\n")
    files = []
    for path, role in (
        (result_path, "aggregate-result"),
        (detail_path, "sample-details"),
        (run_window, "declared-wall-clock-window"),
    ):
        item = {
            "path": path.relative_to(output_dir).as_posix(),
            "role": role,
            "bytes": path.stat().st_size,
            "sha256": digest(path),
        }
        if role == "sample-details":
            item["rows"] = parquet_rows(path)
        files.append(item)
    return {
        "study": "same-source EEE and AIREP mapping experiment",
        "authority": "The listed native LightEval files are source evidence; derived documents are not replacements.",
        "run": {
            "status": "completed", "started_at": started, "ended_at": ended,
            "execution_method": "Python API lighteval.main_accelerate.accelerate with a pinned HellaSwag hf_revision",
            "reproduction_command": "python3 integrations/evaleval/run_experiment.py generate-native --lighteval-root /path/to/lighteval-at-6b9d193 --output-dir /tmp/eee-airep-native",
            "sample_cap": 2, "credentials_used": False, "paid_inference_used": False,
            "warning": "Partial mapping experiment; not a capability comparison.",
        },
        "inputs": {
            "lighteval_commit": LIGHTEVAL_COMMIT,
            "lighteval_package_version": package_version("lighteval"),
            "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
            "dataset_id": DATASET_ID, "dataset_revision": DATASET_REVISION,
            "dataset_split": "validation", "task": "hellaswag|0", "metric": "em",
        },
        "environment": {
            "python": platform.python_version(), "platform": platform.platform(),
            "processor": platform.processor() or platform.machine(), "device": "cpu",
            "packages": {name: package_version(name) for name in
                         ("torch", "transformers", "datasets", "accelerate", "pyarrow")},
        },
        "files": files,
        "source_observations": {
            "result_selector": "results['hellaswag|0']['em']", "metric_value": task_result["em"],
            "standard_error_selector": "results['hellaswag|0']['em_stderr']",
            "standard_error": task_result["em_stderr"], "details_rows": parquet_rows(detail_path),
            "results_filename_timestamp_note": "LightEval's date id is timezone-naive local time; run-window.json carries separately captured UTC times.",
        },
    }


def generate_native(lighteval_root: Path, output_dir: Path) -> None:
    if git_output(lighteval_root, "rev-parse", "HEAD") != LIGHTEVAL_COMMIT:
        raise ReproductionError(f"LightEval checkout must be exactly {LIGHTEVAL_COMMIT}")
    if git_output(lighteval_root, "status", "--porcelain", "--untracked-files=no"):
        raise ReproductionError("LightEval tracked files must be clean; uncommitted code can change the run")
    if package_version("lighteval") != LIGHTEVAL_PACKAGE_VERSION:
        raise ReproductionError(
            f"installed LightEval package must be exactly {LIGHTEVAL_PACKAGE_VERSION}"
        )
    require_empty(output_dir)
    sys.path.insert(0, str(lighteval_root / "src"))
    from lighteval.main_accelerate import accelerate
    from lighteval.tasks.tasks.hellaswag import hellaswag

    if hellaswag.hf_repo != DATASET_ID:
        raise ReproductionError(f"pinned task repository changed: {hellaswag.hf_repo!r}")
    hellaswag.hf_revision = DATASET_REVISION
    started = utc_now()
    with tempfile.TemporaryDirectory(prefix="eee-airep-native-") as temporary:
        generated = Path(temporary)
        accelerate(
            model_args=(f"pretrained={MODEL_ID},revision={MODEL_REVISION},dtype=float32,"
                        "device=cpu,batch_size=1"),
            tasks="hellaswag|0",
            output_dir=str(generated),
            save_details=True,
            push_to_hub=False,
            push_to_tensorboard=False,
            public_run=False,
            wandb=False,
            max_samples=2,
            dataset_loading_processes=1,
        )
        ended = utc_now()
        for source in generated.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(generated)
            # Some shared filesystems refuse LightEval's task separator in names.
            portable = Path(*[part.replace("|", "_") for part in relative.parts])
            destination = output_dir / portable
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    manifest = build_native_manifest(output_dir, started, ended)
    (output_dir / "native-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    verify_native(output_dir)
    print(f"wrote and verified native evidence in {output_dir}")


def run_checked(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    run = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         check=False, **kwargs)
    if run.returncode:
        raise ReproductionError(
            f"command failed ({run.returncode}): {' '.join(command)}\n{run.stdout}\n{run.stderr}"
        )
    return run


def offline(eee_root: Path, out_root: Path, native_root: Path) -> None:
    require_empty(out_root)
    _, files = verify_native(native_root)
    if git_output(eee_root, "rev-parse", "HEAD") != EEE_COMMIT:
        raise ReproductionError(f"EEE checkout must be exactly {EEE_COMMIT}")
    if git_output(eee_root, "status", "--porcelain", "--untracked-files=no"):
        raise ReproductionError("EEE tracked files must be clean; uncommitted code can change validation")
    eee_schema = eee_root / "every_eval_ever" / "schemas" / "eval.schema.json"
    if digest(eee_schema) != EEE_SCHEMA_SHA256:
        raise ReproductionError("EEE aggregate schema digest differs from the pinned basis")
    profile_dir = REPO / "spec" / "airep" / "v0.2" / "profiles" / "embedded-evaluation"
    profile_schema = profile_dir / "embedded-evaluation.schema.json"
    if digest(profile_schema) != PROFILE_SHA256:
        raise ReproductionError("AIREP profile schema digest differs from the pinned basis")
    ancestor = subprocess.run(
        ["git", "-c", f"safe.directory={REPO}", "-C", str(REPO), "merge-base", "--is-ancestor", AIREP_START, "HEAD"],
        check=False,
    )
    if ancestor.returncode:
        raise ReproductionError(f"AIREP checkout does not descend from starting commit {AIREP_START}")

    eee_out = out_root / "eee"
    airep_out = out_root / "airep"
    eee_out.mkdir()
    airep_out.mkdir()
    record_path, mapping_report = eee_mapper.write_mapping(
        files["aggregate-result"], CONTEXT / "eee-context.json", eee_out
    )

    validator_target = record_path.relative_to(eee_out).as_posix()
    validator_command = [
        sys.executable, "-m", "every_eval_ever", "validate", "--format", "json", validator_target
    ]
    validator_env = dict(os.environ)
    validator_env["PYTHONPATH"] = str(eee_root)
    validation = subprocess.run(
        validator_command, cwd=eee_out, env=validator_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    validation_capture = {
        "command": validator_command,
        "exit_code": validation.returncode,
        "stdout": validation.stdout,
        "stderr": validation.stderr,
        "passed": validation.returncode == 0,
        "meaning": "PASS means validation under the pinned EEE implementation; it does not establish semantic equivalence, result truth or interoperability.",
        "eee_commit": EEE_COMMIT,
        "schema_version": EEE_SCHEMA_VERSION,
        "schema_sha256": EEE_SCHEMA_SHA256,
        "record": str(record_path.relative_to(out_root)),
        "record_sha256": digest(record_path),
        "mapping_report": str(mapping_report.relative_to(out_root)),
    }
    (eee_out / "validation-report.json").write_text(
        json.dumps(validation_capture, indent=2) + "\n", encoding="utf-8"
    )
    if validation.returncode:
        raise ReproductionError("pinned EEE validator rejected the mapped record; see validation-report.json")

    exporter_command = [
        sys.executable, str(REPO / "integrations" / "lighteval" / "export_embedded_evaluation.py"),
        "--results", str(files["aggregate-result"]),
        "--details", str(files["sample-details"]),
        "--context", str(CONTEXT / "airep-context.json"),
        "--profile-dir", str(profile_dir), "--out-dir", str(airep_out),
    ]
    run_checked(exporter_command, cwd=REPO)
    output_files = {}
    for name in ("embedded-evaluation.profile.json", "evidence-manifest.json", "validation-report.json"):
        output_files[name] = {"bytes": (airep_out / name).stat().st_size,
                              "sha256": digest(airep_out / name)}
    summary = {
        "native_manifest_sha256": digest(native_root / "native-manifest.json"),
        "eee": {"record_sha256": digest(record_path), "validation_exit_code": validation.returncode},
        "airep": {"profile_basis_sha256": PROFILE_SHA256, "outputs": output_files},
        "non_claims": ["result truth", "model safety", "population completeness",
                       "evaluator independence", "reproducibility", "EEE-AIREP interoperability"],
    }
    (out_root / "offline-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"offline mapping and validation passed; outputs are in {out_root}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    native = sub.add_parser("generate-native", help="run the tiny real evaluation (network required)")
    native.add_argument("--lighteval-root", type=Path, required=True)
    native.add_argument("--output-dir", type=Path, required=True)
    local = sub.add_parser("offline", help="map and validate committed native bytes")
    local.add_argument("--eee-root", type=Path, required=True)
    local.add_argument("--out-root", type=Path, required=True)
    local.add_argument("--native-root", type=Path, default=NATIVE)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-native":
            generate_native(args.lighteval_root.resolve(), args.output_dir.resolve())
        else:
            offline(args.eee_root.resolve(), args.out_root.resolve(), args.native_root.resolve())
    except (ReproductionError, eee_mapper.MappingError, OSError, ValueError) as exc:
        print(f"reproduction refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
