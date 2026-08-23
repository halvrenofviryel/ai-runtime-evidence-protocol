#!/usr/bin/env python3
"""The three committed negative proofs of VALIDATION_CONTRACT s4.4 (a-c).

(a) flipped expected      -> comparator exit 1;
(b) extra result field    -> comparator exit 1;
(c) correct-failure corruption: a fixture's declared scope/keyword corrupted while the
    verdict stays INVALID in both engines -> comparator exit 1 (the correct-failure gate
    itself can fail, not only verdict/shape gates).

Plus a positive control (committed corpus/results -> exit 0). Deterministic, stdlib only.
Exit 0 iff all four controls behave as required.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CMP = HERE / "compare_schema_results.py"
CORPUS = HERE / "corpus"
RES_PY = HERE / "results" / "results_python_schema.json"
RES_NODE = HERE / "results" / "results_node_schema.json"
TARGET = "control-neg-empty-instruction-id"


def run(corpus, py, node, out):
    return subprocess.run([sys.executable, str(CMP), str(corpus), str(py), str(node), str(out)],
                          capture_output=True, text=True).returncode


def clone_corpus(tdp):
    c = tdp / "corpus"
    shutil.copytree(CORPUS, c)
    shutil.copy(HERE / "schema_corpus_manifest.json", tdp / "schema_corpus_manifest.json")
    return c


def rebuild_manifest(tdp, c):
    import hashlib
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(c.glob("*.json"))}
    agg = hashlib.sha256("".join(f"{files[n]}  {n}\n" for n in sorted(files)).encode()).hexdigest()
    m = json.loads((tdp / "schema_corpus_manifest.json").read_text())
    m["files"], m["aggregate_sha256"] = files, agg
    (tdp / "schema_corpus_manifest.json").write_text(json.dumps(m, sort_keys=True, indent=1) + "\n")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        if run(CORPUS, RES_PY, RES_NODE, tdp / "pos.md") != 0:
            print("FAIL: positive control expected exit 0")
            return 1

        # (a) flipped expected
        c = clone_corpus(tdp / "a")
        fx = json.loads((c / f"{TARGET}.json").read_text())
        fx["expected"] = "VALID"
        (c / f"{TARGET}.json").write_text(json.dumps(fx, sort_keys=True, indent=1) + "\n")
        rebuild_manifest(tdp / "a", c)
        if run(c, RES_PY, RES_NODE, tdp / "a.md") != 1:
            print("FAIL: flipped-expected control expected exit 1")
            return 1

        # (b) extra result field
        doc = json.loads(RES_PY.read_text())
        doc["results"][TARGET]["debug"] = "x"
        py2 = tdp / "results_python_extra.json"
        py2.write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
        if run(CORPUS, py2, RES_NODE, tdp / "b.md") != 1:
            print("FAIL: extra-field control expected exit 1")
            return 1

        # (c) correct-failure corruption: verdict stays INVALID; declared scope/keyword no longer match
        c = clone_corpus(tdp / "c")
        fx = json.loads((c / f"{TARGET}.json").read_text())
        fx["expected_error_scope"] = "/authority"
        fx["expected_error_keywords"] = ["maximum"]
        (c / f"{TARGET}.json").write_text(json.dumps(fx, sort_keys=True, indent=1) + "\n")
        rebuild_manifest(tdp / "c", c)
        rc = run(c, RES_PY, RES_NODE, tdp / "c.md")
        if rc != 1:
            print(f"FAIL: correct-failure corruption expected exit 1, got {rc}")
            return 1
        if "correct-failure" not in (tdp / "c.md").read_text():
            print("FAIL: manifest does not name the correct-failure violation")
            return 1

    print("PROOF OK: positive exit 0; flipped-expected, extra-field, and correct-failure corruption each exit 1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
