#!/usr/bin/env python3
"""Bootstrap and run the human-facing AIREP v0.2 lifecycle demo.

The presentation layer deliberately derives every displayed governance state from
the reconciler outputs. A completed evaluation exits zero even when a supplied
case contains MISSING, NOT_EVALUATED, INDETERMINATE, or FAILURE states. Non-zero
is reserved for setup, execution, or result-parsing failures.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / ".airep-demo"
OFFLINE_PYTHON = (
    ROOT
    / "spec/airep/v0.2/class-verification/offline-python-deps/prepare_offline_venv.py"
)
OFFLINE_NODE = (
    ROOT
    / "spec/airep/v0.2/class-verification/offline-node-deps/materialize_node_modules.py"
)
REQUIRED_PYTHON_PACKAGES = {"cryptography": "48.0.0", "jsonschema": "4.25.1"}


class DemoError(RuntimeError):
    """An infrastructure or result-shape failure, not a governance verdict."""


def run(argv, *, cwd=ROOT):
    try:
        completed = subprocess.run(
            [str(arg) for arg in argv],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise DemoError(f"could not run {argv[0]}: {exc}") from exc
    if completed.returncode:
        output = "\n".join(
            part.rstrip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        raise DemoError(
            f"command exited {completed.returncode}: {' '.join(map(str, argv))}"
            + (f"\n{output}" if output else "")
        )
    return completed.stdout


def require_runtime_axis():
    if sys.version_info[:2] != (3, 12):
        raise DemoError(
            "the reproduced demo axis requires Python 3.12 "
            f"(found {platform.python_version()})"
        )
    version = run(["node", "--version"]).strip()
    match = re.fullmatch(r"v(\d+)\..*", version)
    if not match or int(match.group(1)) != 20:
        raise DemoError(f"the reproduced demo axis requires Node 20 (found {version!r})")


def venv_python(venv):
    posix = venv / "bin/python"
    return posix if posix.exists() else venv / "Scripts/python.exe"


def python_environment_ready(python):
    if not python.exists():
        return False
    probe = (
        "import importlib.metadata as m,json;"
        "print(json.dumps({n:m.version(n) for n in ('cryptography','jsonschema')}))"
    )
    try:
        versions = json.loads(run([python, "-c", probe]))
    except (DemoError, json.JSONDecodeError):
        return False
    return versions == REQUIRED_PYTHON_PACKAGES


def prepare_python_environment():
    venv = STATE_DIR / "venv"
    python = venv_python(venv)
    if python_environment_ready(python):
        print("Python dependencies: cached pinned environment")
        return python

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    linux_x86_64 = sys.platform.startswith("linux") and platform.machine().lower() in {
        "x86_64",
        "amd64",
    }
    if linux_x86_64:
        run([sys.executable, OFFLINE_PYTHON, "--venv", venv])
        source = "vendored, hash-verified wheel bundle"
    else:
        if venv.exists():
            shutil.rmtree(venv)
        run([sys.executable, "-m", "venv", venv])
        python = venv_python(venv)
        run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "jsonschema==4.25.1",
                "cryptography==48.0.0",
            ]
        )
        source = "pinned packages from the configured Python index"
    python = venv_python(venv)
    if not python_environment_ready(python):
        raise DemoError("the prepared Python environment failed its version check")
    print(f"Python dependencies: prepared from {source}")
    return python


def prepare_dependencies(skip_bootstrap):
    require_runtime_axis()
    if skip_bootstrap:
        python = Path(sys.executable)
        if not python_environment_ready(python):
            raise DemoError("--skip-bootstrap requires the pinned Python dependencies")
        return python
    python = prepare_python_environment()
    run([sys.executable, OFFLINE_NODE])
    print("Node dependencies: materialized from vendored, hash-verified tarballs")
    return python


def load_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoError(f"could not parse demo result {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DemoError(f"demo result is not a JSON object: {path}")
    return value


def one_check_state(report, name):
    matches = [
        entry.get("state")
        for entry in report.get("checks", [])
        if entry.get("check") == name
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise DemoError(f"expected exactly one {name!r} check in reconciler output")
    return matches[0]


def one_record_class(report, record_id):
    matches = []
    for record in report.get("records", []):
        if record.get("artifact_ref", {}).get("record_id") == record_id:
            matches.append(record.get("class_result", {}).get("class"))
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise DemoError(f"expected exactly one class result for {record_id!r}")
    return matches[0]


def overall_state(report):
    state = report.get("summary", {}).get("status")
    if not isinstance(state, str):
        raise DemoError("reconciler output has no summary.status")
    return state


def render_rows(rows):
    width = max(len(label) for label, _ in rows)
    return "\n".join(f"  {label:<{width}}  {value}" for label, value in rows)


def render_demo(complete, missing_receipt, node_result, output):
    node_class = node_result.get("class")
    observer = node_result.get("observer_assessment")
    if not isinstance(node_class, str) or not isinstance(observer, str):
        raise DemoError("Node verifier output is missing class or observer_assessment")

    complete_rows = [
        ("Decision record", one_record_class(complete, "demo.decision")),
        ("Issuer dispatch", one_check_state(complete, "issuer_dispatch")),
        ("Receiver receipt", one_check_state(complete, "receiver_receipt")),
        ("Execution evidence", one_check_state(complete, "execution_evidence")),
        ("TOCTOU comparison", one_check_state(complete, "toctou")),
        ("Effect binding", one_check_state(complete, "effect_binding")),
        ("Intended-target coverage", one_check_state(complete, "intended_target_coverage")),
        ("Overall", overall_state(complete)),
    ]
    negative_rows = [
        ("Issuer dispatch", one_check_state(missing_receipt, "issuer_dispatch")),
        ("Receiver receipt", one_check_state(missing_receipt, "receiver_receipt")),
        ("Execution evidence", one_check_state(missing_receipt, "execution_evidence")),
        ("TOCTOU comparison", one_check_state(missing_receipt, "toctou")),
        ("Overall", overall_state(missing_receipt)),
    ]
    node_rows = [("Class", node_class), ("Observer assessment", observer)]
    return "\n".join(
        [
            "",
            "COMPLETE SUPPLIED LIFECYCLE",
            render_rows(complete_rows),
            "",
            "MISSING-RECEIPT VARIANT",
            render_rows(negative_rows),
            "",
            "NODE VERIFIER (EFFECT RECORD)",
            render_rows(node_rows),
            "",
            "A completed evaluation exits 0 even when governance states are negative or withheld.",
            "MISSING is not proof that delivery or execution did not occur.",
            f"Artifacts: {output}",
        ]
    )


def choose_output(requested):
    if requested is not None:
        output = requested.expanduser().resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = STATE_DIR / "runs" / f"{stamp}-{os.getpid()}"
    if output.exists():
        raise DemoError(f"output path already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="new directory for the generated artifacts")
    parser.add_argument(
        "--skip-bootstrap",
        action="store_true",
        help="use the current pinned Python environment and already-materialized Node dependencies",
    )
    args = parser.parse_args(argv)

    python = prepare_dependencies(args.skip_bootstrap)
    output = choose_output(args.out)
    run([python, ROOT / "examples/v02/run_lifecycle.py", "--out", output])

    node_stdout = run(
        [
            "node",
            ROOT / "tools/airep_v02/verify_node.mjs",
            "--request",
            output / "requests/demo.effect.json",
            "--bindings",
            output / "bindings.json",
            "--revocation",
            output / "revocation.json",
            "--independence-policy",
            output / "independence.json",
        ]
    )
    try:
        node_result = json.loads(node_stdout)
    except json.JSONDecodeError as exc:
        raise DemoError(f"could not parse Node verifier output: {exc}") from exc
    if not isinstance(node_result, dict):
        raise DemoError("Node verifier output is not a JSON object")
    (output / "node-verification.json").write_text(
        json.dumps(node_result, indent=2) + "\n", encoding="utf-8"
    )

    complete = load_json(output / "reconciliation.json")
    missing_receipt = load_json(output / "variants/no-receipt.result.json")
    print(render_demo(complete, missing_receipt, node_result, output))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"DEMO ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
