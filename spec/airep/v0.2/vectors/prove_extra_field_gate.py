#!/usr/bin/env python3
"""Deterministic proof that the Stage-3 vector comparator fails on an injected extra field.

Positive control: runs compare_vectors.py on the committed outputs -> MUST exit 0.
Negative control: copies the committed outputs, injects one extra field into one vector of
one copy, runs the comparator on the copies -> MUST exit 1.

Exit 0 iff both controls behave as required. No timestamps, no randomness.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CMP = HERE / "compare_vectors.py"
PY_OUT = HERE / "out" / "python_vectors.json"
NODE_OUT = HERE / "out" / "node_vectors.json"


def run(*args) -> int:
    return subprocess.run([sys.executable, str(CMP), *map(str, args)],
                          capture_output=True, text=True).returncode


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        pos_manifest = tdp / "positive_manifest.md"
        rc_pos = run(PY_OUT, NODE_OUT, pos_manifest)
        if rc_pos != 0:
            print(f"FAIL: positive control expected exit 0, got {rc_pos}")
            return 1

        tampered = json.loads(PY_OUT.read_text(encoding="utf-8"))
        first_vec = sorted(tampered["vectors"])[0]
        tampered["vectors"][first_vec]["injected_extra_field"] = "tamper"
        tampered_path = tdp / "python_vectors_tampered.json"
        tampered_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")

        neg_manifest = tdp / "negative_manifest.md"
        rc_neg = run(tampered_path, NODE_OUT, neg_manifest)
        if rc_neg != 1:
            print(f"FAIL: negative control expected exit 1, got {rc_neg}")
            return 1
        if "EXTRA FIELD" not in neg_manifest.read_text(encoding="utf-8"):
            print("FAIL: negative manifest does not name the extra field")
            return 1

    print("PROOF OK: comparator exits 0 on committed outputs and exits 1 on an injected extra field")
    return 0


if __name__ == "__main__":
    sys.exit(main())
