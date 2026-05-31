#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""JCS (RFC 8785) cross-runtime agreement test for AIREP.

Proves that `conformance/jcs.py` (Python) and the Node canonicalizer (the same algorithm
`verify.mjs` uses) produce byte-identical canonical output — including the cases where naive
sorted-key `json.dumps` diverges from RFC 8785 (`1.0`->`1`, `1e-07`->`1e-7`, `-0.0`->`0`).
Both runtimes parse the SAME JSON source text and then canonicalize, so this tests parsing and
serialization end to end. If Node is not installed, the Python side is still checked against a
set of hand-verified expected vectors.

Usage:  python3 test_jcs.py     (exit 0 if all agree, 1 otherwise)
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import jcs  # noqa: E402

# JSON source texts — both runtimes parse the SAME source, then canonicalize.
BATTERY = [
    "1", "0", "-0.0", "1.0", "100", "-5", "1e-07", "1.5e+30", "3.14159",
    "true", "false", "null", '"plain"', '"a\\"b"', '"ünïcode"',
    "[1,2,3]", "[]", "{}",
    '{"b":1,"a":2}', '{"z":{"y":1},"a":[true,null,"x"]}',
    '{"k":1.0,"n":1e-07,"m":-0.0}',
    '{"é":1,"a":2,"Z":3}',  # key sort across case + non-ASCII
]

# Unambiguous expected canonical forms (the json.dumps-divergent cases), so the test still
# asserts something meaningful when Node is unavailable.
EXPECT = {
    "1.0": "1",
    "-0.0": "0",
    "100": "100",
    '{"b":1,"a":2}': '{"a":2,"b":1}',
    '{"é":1,"a":2,"Z":3}': '{"Z":3,"a":2,"é":1}',
}

NODE_CANON = r"""
const s = require('fs').readFileSync(0, 'utf8');
function c(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(c).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + c(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}
process.stdout.write(c(JSON.parse(s)));
"""


def py_canon(src):
    return jcs.canonicalize(json.loads(src)).decode("utf-8")


def node_canon(src):
    out = subprocess.run(["node", "-e", NODE_CANON], input=src,
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    return out.stdout


def main():
    fails = 0
    have_node = shutil.which("node") is not None
    print(f"JCS cross-runtime agreement  (node {'present' if have_node else 'ABSENT — python-only'})")
    for src in BATTERY:
        py = py_canon(src)
        exp = EXPECT.get(src)
        if exp is not None and py != exp:
            print(f"  FAIL  py({src}) = {py!r}  expected {exp!r}")
            fails += 1
            continue
        if have_node:
            nd = node_canon(src)
            agree = py == nd
            fails += 0 if agree else 1
            tail = "" if agree else f"   <-- node={nd!r}"
            print(f"  {'PASS' if agree else 'FAIL'}  {src:<30} -> {py!r}{tail}")
        else:
            print(f"  PASS  {src:<30} -> {py!r}  (python-only; vs expected where known)")
    print(f"RESULT: {'all canonical forms agree' if not fails else f'{fails} mismatch(es)'}")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
