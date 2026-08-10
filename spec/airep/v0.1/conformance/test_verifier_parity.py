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
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import jcs  # noqa: E402  (RFC 8785 canonicalization — conformance/jcs.py)

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


def run_out(cmd, rec, extra=()):
    """Run a verifier, returning (exit0: bool, stdout: str). The record path is the FIRST
    argument (verify.mjs reads args[0] positionally as the file); flags go AFTER it."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(rec, f)
        path = f.name
    try:
        p = subprocess.run(cmd + [path, *extra], capture_output=True, text=True)
        return p.returncode == 0, p.stdout
    finally:
        Path(path).unlink(missing_ok=True)


def _profile_divergence_record():
    """BASE + a key_trust profile block that VIOLATES profiles/key_trust.schema.json
    (public_key must be a string; here it is an int), with integrity.current recomputed so the
    ONLY failing dimension is the profile schema. This is the isolated WP-08 reproducer."""
    r = copy.deepcopy(BASE)
    r["profiles"] = {"key_trust": {"public_key": 12345}}
    body = {k: v for k, v in r.items() if k != "integrity"}
    integ = r["integrity"]
    body["integrity"] = {k: v for k, v in integ.items() if k not in ("current", "signature")}
    r["integrity"]["current"] = "sha256:" + hashlib.sha256(jcs.canonicalize(body)).hexdigest()
    return r


def profile_divergence_check(have_node):
    """WP-08 regression. The profile-schema dimension is the ONE place the two verifiers diverge
    BY DESIGN: verify.py validates profiles and rejects an invalid block (INVALID, exit 1); the
    Node verifier runs no profile-schema engine. The pin is NOT that they agree on exit code — it
    is that Node no longer renders its exit 0 as a clean pass: it must NAME the unmeasured profile
    dimension (`profile_not_measured=key_trust`) rather than a bare `class=Core`. Returns
    (ok, lines)."""
    rec = _profile_divergence_record()
    lines = ["", "WP-08 profile-dimension divergence (invalid key_trust block):"]
    ok = True

    py_ok, py_out = run_out([sys.executable, str(HERE / "verify.py")], rec, extra=["--class"])
    py_reject = (not py_ok) and ("profile:key_trust" in py_out) and ("INVALID" in py_out)
    lines.append(f"  verify.py : rejects on profile schema (INVALID, exit!=0) -> {'✓' if py_reject else '✗'}")
    ok = ok and py_reject

    if have_node:
        node_ok, node_out = run_out(["node", str(HERE / "verify.mjs")], rec, extra=["--class"])
        # Declared: Node's core checks pass (exit 0) — matching verify.py's exit is NOT the goal.
        # Required: it must not read as a clean Core; the unmeasured profile dimension is named.
        node_names_gap = node_ok and ("profile_not_measured=key_trust" in node_out)
        lines.append(f"  verify.mjs: exit 0 BUT names profile_not_measured=key_trust (not a bare Core) -> {'✓' if node_names_gap else '✗'}")
        ok = ok and node_names_gap
    else:
        lines.append("  verify.mjs: skipped (node absent)")
    return ok, lines


def empty_input_check(have_node):
    """WP-02 regression. An empty input (zero records) is not a vacuously perfect chain: zero
    records means zero checks ran, so the unmeasured case must never inherit a pass. BOTH verifiers
    MUST fail-closed (exit != 0) AND name the reason (`no-records`) — never 'all records OK' / exit 0.
    That fail-open on absence is precisely the bug class this kit exists to prevent, so it is pinned
    here directly (the CASES battery only exercises single non-empty records). Returns (ok, lines)."""
    lines = ["", "WP-02 empty-input fail-closed (zero-record .jsonl):"]
    ok = True
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        path = f.name  # left intentionally empty: zero records
    try:
        p = subprocess.run([sys.executable, str(HERE / "verify.py"), path], capture_output=True, text=True)
        py_closed = (p.returncode != 0) and ("no-records" in p.stdout)
        lines.append(f"  verify.py : rejects empty input (no-records, exit!=0) -> {'✓' if py_closed else '✗'}")
        ok = ok and py_closed
        if have_node:
            pn = subprocess.run(["node", str(HERE / "verify.mjs"), path], capture_output=True, text=True)
            node_closed = (pn.returncode != 0) and ("no-records" in pn.stdout)
            lines.append(f"  verify.mjs: rejects empty input (no-records, exit!=0) -> {'✓' if node_closed else '✗'}")
            ok = ok and node_closed
        else:
            lines.append("  verify.mjs: skipped (node absent)")
    finally:
        Path(path).unlink(missing_ok=True)
    return ok, lines


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

    div_ok, div_lines = profile_divergence_check(have_node)
    for ln in div_lines:
        print(ln)
    if not div_ok:
        fails += 1

    empty_ok, empty_lines = empty_input_check(have_node)
    for ln in empty_lines:
        print(ln)
    if not empty_ok:
        fails += 1

    print(f"RESULT: {'all verifiers agree with the expected verdict' if not fails else f'{fails} disagreement(s)'}")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
