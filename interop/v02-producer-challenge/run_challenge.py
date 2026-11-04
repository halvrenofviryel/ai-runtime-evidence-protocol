#!/usr/bin/env python3
"""Evaluate a data-only producer submission with the exact beta release code."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


TAG = "v0.2.0-beta.1"
COMMIT = "8a6c01ecce457aa94330c0ed7219e4c56ebfe771"
SCHEMA = "airep-v02-producer-challenge-submission-v1"
REQUIRED = {"SUBMISSION.json", "lifecycle.json", "bindings.json", "revocation.json"}
OPTIONAL = {"independence.json"}
MAX_BYTES = 8 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise ValueError(message)


def load_inputs(directory: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    if not directory.is_dir() or directory.is_symlink():
        fail("submission must be a real directory")
    entries = {path.name for path in directory.iterdir()}
    missing = REQUIRED - entries
    unexpected = entries - REQUIRED - OPTIONAL
    if missing or unexpected:
        fail(f"submission paths differ: missing={sorted(missing)} unexpected={sorted(unexpected)}")
    values: dict[str, object] = {}
    rows: list[dict[str, object]] = []
    for name in sorted(entries):
        path = directory / name
        if not path.is_file() or path.is_symlink():
            fail(f"submission member must be a regular file: {name}")
        data = path.read_bytes()
        if not data or len(data) > MAX_BYTES:
            fail(f"submission member has invalid size: {name}")
        try:
            values[name] = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            fail(f"submission member is not UTF-8 JSON: {name}: {exc}")
        rows.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    metadata = values["SUBMISSION.json"]
    if not isinstance(metadata, dict) or metadata.get("schema") != SCHEMA:
        fail("SUBMISSION.json has the wrong schema")
    if metadata.get("target") != {"tag": TAG, "commit": COMMIT}:
        fail("SUBMISSION.json does not target the exact beta")
    producer = metadata.get("producer_implementation")
    if not isinstance(producer, dict) or any(
        not isinstance(producer.get(key), str) or not producer[key].strip()
        for key in ("name", "repository", "commit", "license")
    ):
        fail("SUBMISSION.json lacks producer implementation provenance")
    reproduction = metadata.get("reproduction")
    command = reproduction.get("command_argv") if isinstance(reproduction, dict) else None
    if (
        not isinstance(command, list) or not command
        or any(not isinstance(item, str) or not item for item in command)
        or not isinstance(reproduction.get("environment"), str)
        or not reproduction["environment"].strip()
    ):
        fail("SUBMISSION.json lacks a reproducible command/environment record")
    authorship = metadata.get("authorship")
    if not isinstance(authorship, dict) or not isinstance(
        authorship.get("independence_is_self_attested"), bool
    ):
        fail("SUBMISSION.json lacks the authorship self-attestation boundary")
    lifecycle = values["lifecycle.json"]
    if not isinstance(lifecycle, list) or not lifecycle:
        fail("lifecycle.json must be a non-empty array")
    families = {item.get("artifact_type") for item in lifecycle if isinstance(item, dict)}
    expected = {"decision", "control", "execution", "effect"}
    if not expected.issubset(families):
        fail(f"lifecycle.json lacks artifact families: {sorted(expected - families)}")
    return values, rows


def export_release(destination: Path) -> None:
    resolved = subprocess.check_output(
        ["git", "rev-parse", f"{TAG}^{{commit}}"], cwd=ROOT, text=True
    ).strip()
    if resolved != COMMIT:
        fail(f"local tag resolves to {resolved}, expected {COMMIT}")
    archive = subprocess.check_output(["git", "archive", "--format=tar", COMMIT], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(destination, filter="data")


def run(command: list[str], *, cwd: Path) -> dict[str, object]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    submission = args.submission.resolve()
    results = args.results.resolve()
    try:
        _, rows = load_inputs(submission)
        results.mkdir(parents=True, exist_ok=False)
        with tempfile.TemporaryDirectory(prefix="airep-beta1-") as temporary:
            checkout = Path(temporary)
            export_release(checkout)
            common = [
                "--input", str(submission / "lifecycle.json"),
                "--bindings", str(submission / "bindings.json"),
                "--revocation", str(submission / "revocation.json"),
            ]
            if (submission / "independence.json").exists():
                common.extend(["--independence-policy", str(submission / "independence.json")])
            verification = run(
                [sys.executable, "-m", "tools.airep_v02", "verify", *common,
                 "--out", str(results / "verification.json")], cwd=checkout
            )
            reconciliation = run(
                [sys.executable, "-m", "tools.airep_v02", "reconcile", *common,
                 "--out", str(results / "reconciliation.json")], cwd=checkout
            )
        commands = {"verification": verification, "reconciliation": reconciliation}
        record = {
            "schema": "airep-v02-producer-challenge-run-v1",
            "target": {"tag": TAG, "commit": COMMIT},
            "runner_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "submission_files": rows,
            "commands": commands,
            "result": "EVALUATED" if all(item["exit_code"] == 0 for item in commands.values()) else "REJECTED_OR_NOT_EVALUATED",
            "boundaries": [
                "The consumer/verifier is the first-party beta release code.",
                "Submission metadata, authorship, authority and independence are not established by this runner.",
                "A completed run does not establish event truth, complete history, deployment use or general interoperability."
            ],
        }
        (results / "RUN_RECORD.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"result": record["result"], "run_record": str(results / "RUN_RECORD.json")}))
        return 0 if record["result"] == "EVALUATED" else 1
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"invalid challenge input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
