#!/usr/bin/env python3
"""NEGATIVE PROOF 5 (C1) -- pinned CLI/process probe mutation.

C1 added 15 committed process probes, each pinning an exit code, whether a
results file may exist afterwards, and a must_not_create list. This proof drives
the comparator's C1 probe matrix with a SYNTHETIC runner: the real Python
verifier on one side, and on the other a stub that misbehaves on exactly one
pinned probe. It then asserts the process gate fails for that cause.

Two sub-proofs, matching the two failure shapes the maintainer named:
  (a) wrong exit code on a pinned probe;
  (b) a results file falsely created where the probe pins expected_results_file
      false and lists the destination under must_not_create.

Only one probe misbehaves in each sub-proof; every other probe is delegated to
the real verifier, so a finding on the mutated probe cannot be confused with
noise from the rest of the matrix.
"""

import json
import os
import sys

import harness as H

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import compare as C  # noqa: E402  -- the comparator under test, not a verifier

ROOT = H.ROOT
TARGET_EXIT = "PRB-CLI-NOW-NOT-GREGORIAN"   # pinned expected_exit 2
TARGET_FILE = "PRB-CLI-REQUEST-WITH-OUT"    # pinned exit 2, must_not_create ${OUT}


class StubRunner:
    """Python side = the real verifier. Node side = the real verifier except on
    one probe, where a specific pinned property is violated."""

    def __init__(self, root, mode):
        self.real = C.Runner(root)
        self.mode = mode

    def python(self, args):
        return self.real.python(args)

    def node(self, args):
        joined = " ".join(args)
        if self.mode == "wrong-exit" and ("/%s/" % TARGET_EXIT) in joined:
            return {"argv": args, "exit": 0, "stdout_bytes": 0,
                    "stdout_head": "", "stderr_head": ""}
        if self.mode == "false-results-file" and ("/%s/" % TARGET_FILE) in joined \
                and "--out" in args:
            out_path = args[args.index("--out") + 1]
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write('{\n "verdicts": []\n}\n')
            return {"argv": args, "exit": 2, "stdout_bytes": 0,
                    "stdout_head": "", "stderr_head": "usage error"}
        return self.real.node(args)


def codes(findings, probe_id):
    return sorted({f["code"] for f in findings if f.get("probe_id") == probe_id})


def find(findings, code, **fields):
    for f in findings:
        if f.get("code") == code and all(f.get(k) == v for k, v in fields.items()):
            return f
    raise H.ProofFailure(
        "expected finding %s matching %s; got %s"
        % (code, json.dumps(fields, sort_keys=True),
           json.dumps(sorted({x.get("code") for x in findings}), sort_keys=True)))


def main():
    work = H.workspace()
    lines = []
    try:
        # ---- (a) wrong exit on a pinned probe ----
        _, findings = C.c1_probe_matrix(StubRunner(ROOT, "wrong-exit"), ROOT,
                                        os.path.join(work, "a"))
        f = find(findings, "c1-probe-exit-mismatch",
                 probe_id=TARGET_EXIT, impl="node", expected=2, actual=0)
        find(findings, "c1-probe-exit-divergence", probe_id=TARGET_EXIT,
             python=2, node=0)
        other = sorted({x.get("probe_id") for x in findings} - {TARGET_EXIT})
        if other:
            raise H.ProofFailure("findings leaked to unrelated probes: %s" % other)
        lines.append("(a) wrong exit  : %s node exit 0 against pinned 2 | "
                     "c1-probe-exit-mismatch + c1-probe-exit-divergence, "
                     "no other probe affected" % TARGET_EXIT)

        # ---- (b) results file falsely created where must_not_create pins absence ----
        _, findings = C.c1_probe_matrix(StubRunner(ROOT, "false-results-file"), ROOT,
                                        os.path.join(work, "b"))
        find(findings, "c1-probe-results-file-mismatch", probe_id=TARGET_FILE,
             impl="node", expected_results_file=False, results_file_present=True)
        find(findings, "c1-probe-must-not-create-violated", probe_id=TARGET_FILE,
             impl="node")
        find(findings, "c1-probe-out-path-created", probe_id=TARGET_FILE, impl="node")
        other = sorted({x.get("probe_id") for x in findings} - {TARGET_FILE})
        if other:
            raise H.ProofFailure("findings leaked to unrelated probes: %s" % other)
        lines.append("(b) false file  : %s node exits 2 correctly but writes ${OUT} | "
                     "c1-probe-results-file-mismatch + c1-probe-must-not-create-violated "
                     "+ c1-probe-out-path-created, no other probe affected" % TARGET_FILE)

        # ---- control: the real pair produces no probe finding at all ----
        _, clean = C.c1_probe_matrix(C.Runner(ROOT), ROOT, os.path.join(work, "c"))
        if clean:
            raise H.ProofFailure(
                "control failed: the unmutated matrix produced findings %s"
                % json.dumps(clean, sort_keys=True))
        lines.append("control        : unmutated matrix over all 15 probes x 2 "
                     "implementations produced 0 findings")

        H.report("5 / C1 pinned probe mutation (synthetic runner)", lines)
        _ = f
    finally:
        H.cleanup(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("PROOF 5 FAILED: %s\n" % exc)
        sys.exit(1)
