#!/usr/bin/env python3
"""Run the control plus all three committed negative proofs.

The control matters: it shows that an UNMUTATED pair does not trip any
comparison gate, so each proof's failure is attributable to its mutation and
not to the proof harness.
"""

import copy
import os
import subprocess
import sys

import harness as H

HERE = os.path.dirname(os.path.abspath(__file__))
PROOFS = ["proof_1_class_flip.py",
          "proof_2_reason_mutation.py",
          "proof_3_envelope_invariant.py"]


def control():
    print("known-good pair: %s" % os.path.relpath(H.GOOD, os.path.dirname(HERE)))
    good = H.known_good()
    work = H.workspace()
    try:
        code, payload = H.run_comparator(copy.deepcopy(good), copy.deepcopy(good),
                                         work, "control")
        failed = [g["id"] for g in payload["gates"] if g["outcome"] == "FAIL"]
        if failed:
            raise H.ProofFailure("control pair should trip no gate, but %s FAILED" % failed)
        unmeasured = [g["id"] for g in payload["gates"] if g["outcome"] == "NOT_MEASURED"]
        print("CONTROL  unmutated pair: no gate FAILED; exit %d; "
              "NOT_MEASURED in compare-only mode: %s" % (code, unmeasured))
        if code != 2:
            raise H.ProofFailure(
                "control expected exit 2 (hard gates NOT_MEASURED in compare-only "
                "mode, never rounded up to PASS), got %d" % code)
    finally:
        H.cleanup(work)


def main():
    control()
    print()
    failures = []
    for name in PROOFS:
        proc = subprocess.run([sys.executable, os.path.join(HERE, name)],
                              cwd=HERE, capture_output=True)
        sys.stdout.write(proc.stdout.decode("utf-8", "replace"))
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        if proc.returncode != 0:
            failures.append(name)
        print()
    if failures:
        print("NEGATIVE PROOFS: FAIL -- %s" % ", ".join(failures))
        return 1
    print("NEGATIVE PROOFS: all 3 proofs demonstrated the comparator failing "
          "for the expected cause.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("CONTROL FAILED: %s\n" % exc)
        sys.exit(1)
