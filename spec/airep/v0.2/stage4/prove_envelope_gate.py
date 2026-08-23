#!/usr/bin/env python3
"""Deterministic proof that the Stage-4 parity comparator gates the results-file ENVELOPE.

Positive control: comparator on the committed results files -> MUST exit 0.
Negative control: a copy of results_python.json with an injected top-level "metadata"
member -> MUST exit 1, with the envelope violation named in the emitted manifest.

Exit 0 iff both controls behave as required. Stdlib only; no timestamps, no randomness.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CMP = HERE / "parity_compare.py"
RES_PY = HERE / "results" / "results_python.json"
RES_NODE = HERE / "results" / "results_node.json"


def run(*args) -> int:
    return subprocess.run([sys.executable, str(CMP), *map(str, args)],
                          capture_output=True, text=True).returncode


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        rc_pos = run(RES_PY, RES_NODE, tdp / "positive_manifest.md")
        if rc_pos != 0:
            print(f"FAIL: positive control expected exit 0, got {rc_pos}")
            return 1

        doc = json.loads(RES_PY.read_text(encoding="utf-8"))
        doc["metadata"] = "unexpected"
        tampered = tdp / "results_python_metadata.json"
        tampered.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")

        neg_manifest = tdp / "negative_manifest.md"
        rc_neg = run(tampered, RES_NODE, neg_manifest)
        if rc_neg != 1:
            print(f"FAIL: negative control expected exit 1, got {rc_neg}")
            return 1
        if "root keys" not in neg_manifest.read_text(encoding="utf-8"):
            print("FAIL: negative manifest does not name the envelope violation")
            return 1

    print("PROOF OK: parity comparator exits 0 on committed envelopes and exits 1 on an injected top-level metadata member")
    return 0


if __name__ == "__main__":
    sys.exit(main())
