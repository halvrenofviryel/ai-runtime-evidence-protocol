#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verifier-parity test: verify.py and verify.mjs reach the SAME verdict.

Generates a battery of good and adversarial AIREP records and runs both the Python reference
verifier (full Draft-2020-12 schema) and the independent Node verifier on each, asserting they
agree on pass/fail and match the expected verdict. This is the runnable evidence behind the
conformance kit's claim that the two implementations agree on conformance — not only on the hash
bytes. The Node half is skipped if `node` is not installed (the expected-verdict half still runs).

Usage:  python3 test_verifier_parity.py    (exit 0 if every case agrees, 1 otherwise)
"""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent
BASE = json.loads((SPEC / "examples" / "neutral_record.json").read_text())


def mut(fn):
    r = copy.deepcopy(BASE)
    fn(r)
    return r


def _del(r, *path):
    d = r
    for k in path[:-1]:
        d = d[k]
    del d[path[-1]]


def _tamper(r):  # edit a field WITHOUT recomputing integrity.current
    r["output"]["result_ref"] = r["output"]["result_ref"][:-1] + "0"


# name -> (record, expected_pass)
CASES = {
    "good (control)": (copy.deepcopy(BASE), True),
    "vendor key in core top-level": (mut(lambda r: r.__setitem__("vendor_x", {"a": 1})), False),
    "directive.verb out of enum": (mut(lambda r: r["directive"].__setitem__("verb", "approve")), False),
    "missing nested subject.runtime": (mut(lambda r: _del(r, "subject", "runtime")), False),
    "scope.covers wrong type (string)": (mut(lambda r: r["scope"].__setitem__("covers", "all")), False),
    "claim.basis empty (minItems)": (mut(lambda r: r["claim"].__setitem__("basis", [])), False),
    "integrity.canonical_json not true": (mut(lambda r: r["integrity"].__setitem__("canonical_json", False)), False),
    "evidence[].resolvable wrong type": (mut(lambda r: r["evidence"][0].__setitem__("resolvable", "yes")), False),
    "tampered field (hash mismatch)": (mut(_tamper), False),
}


def run(cmd, rec):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(rec, f)
        path = f.name
    try:
        return subprocess.run(cmd + [path], capture_output=True).returncode == 0
    finally:
        Path(path).unlink(missing_ok=True)


def main():
    have_node = shutil.which("node") is not None
    fails = 0
    print(f"verifier parity  (node {'present' if have_node else 'ABSENT — python-only vs expected verdict'})")
    print(f"  {'case':<36} | py  | mjs | expect | ok")
    print(f"  {'-' * 36}-|-----|-----|--------|----")
    for name, (rec, expect_pass) in CASES.items():
        py = run([sys.executable, str(HERE / "verify.py")], rec)
        ok = (py == expect_pass)
        mjs_str = " — "
        if have_node:
            mjs = run(["node", str(HERE / "verify.mjs")], rec)
            ok = ok and (mjs == py)
            mjs_str = " P " if mjs else " F "
        if not ok:
            fails += 1
        print(f"  {name:<36} | {' P ' if py else ' F '} |{mjs_str}| {'  P   ' if expect_pass else '  F   '} | {'✓' if ok else '✗'}")
    print(f"RESULT: {'all verifiers agree with the expected verdict' if not fails else f'{fails} disagreement(s)'}")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
