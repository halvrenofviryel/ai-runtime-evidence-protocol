#!/usr/bin/env python3
"""Exercise the challenge plumbing with the explicitly first-party demo fixture."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def invoke(submission: Path, results: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HERE / "run_challenge.py"), "--submission", str(submission),
         "--results", str(results)], cwd=ROOT, text=True, capture_output=True
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="airep-challenge-test-") as temporary:
        base = Path(temporary)
        fixture = base / "first-party-fixture"
        subprocess.run(
            [sys.executable, "examples/v02/run_lifecycle.py", "--out", str(fixture)],
            cwd=ROOT, check=True, capture_output=True, text=True
        )
        submission = base / "submission"
        submission.mkdir()
        for name in ("lifecycle.json", "bindings.json", "revocation.json", "independence.json"):
            shutil.copyfile(fixture / name, submission / name)
        metadata = json.loads((HERE / "SUBMISSION_TEMPLATE.json").read_text())
        metadata["producer_implementation"] = {
            "name": "AIREP first-party CI fixture",
            "repository": "https://github.com/halvrenofviryel/ai-runtime-evidence-protocol",
            "commit": "8a6c01ecce457aa94330c0ed7219e4c56ebfe771",
            "license": "Apache-2.0",
        }
        metadata["reproduction"] = {
            "command_argv": [sys.executable, "examples/v02/run_lifecycle.py", "--out", "OUTPUT"],
            "environment": "CI fixture; expressly not independent evidence",
        }
        (submission / "SUBMISSION.json").write_text(json.dumps(metadata, indent=2) + "\n")

        completed = invoke(submission, base / "result")
        assert completed.returncode == 0, completed.stderr
        record = json.loads((base / "result/RUN_RECORD.json").read_text())
        assert record["target"]["commit"] == "8a6c01ecce457aa94330c0ed7219e4c56ebfe771"
        assert record["result"] == "EVALUATED"
        assert all(item["exit_code"] == 0 for item in record["commands"].values())
        assert json.loads((base / "result/verification.json").read_text())["verdicts"]

        (submission / "extra.json").write_text("{}\n")
        rejected = invoke(submission, base / "rejected")
        assert rejected.returncode == 2
        assert "unexpected=['extra.json']" in rejected.stderr

    print("V02_PRODUCER_CHALLENGE_OK: exact-beta evaluation and input rejection verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
