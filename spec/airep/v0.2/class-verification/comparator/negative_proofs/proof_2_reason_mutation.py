#!/usr/bin/env python3
"""NEGATIVE PROOF 2 -- reason mutation inside the five channels.

Three sub-mutations, each on a COPY of a known-good pair, each mutating one
reason on the Node side only: ADD one, DROP one, RENAME one. Every mutation
keeps the envelope legal (registry-valid reason, sorted, deduplicated,
invariants satisfied), so the reason-set parity gate for that channel is the
gate that must catch it.
"""

import copy
import sys

import harness as H


def sub_add(good):
    node = copy.deepcopy(good)
    v = H.find_verdict(node, "cv-rec-p1")
    assert v["witnessed_withheld"] == ["no-witness-supplied"]
    # registry-valid, keeps ASCII-ascending order, keeps class != AIREP-Witnessed
    v["witnessed_withheld"] = ["independence-policy-missing", "no-witness-supplied"]
    return ("ADD", node, "G8", "witnessed_withheld", "cv-rec-p1", "P1",
            ["no-witness-supplied"],
            ["independence-policy-missing", "no-witness-supplied"])


def sub_drop(good):
    node = copy.deepcopy(good)
    v = H.find_verdict(node, "cv-rec-wm1")
    assert v["witnessed_failures"] == ["witness-claim-invalid"], v["witnessed_failures"]
    v["witnessed_failures"] = []
    return ("DROP", node, "G7", "witnessed_failures", "cv-rec-wm1", "WM1",
            ["witness-claim-invalid"], [])


def sub_rename(good):
    node = copy.deepcopy(good)
    v = H.find_verdict(node, "cv-rec-pb1")
    assert v["authenticated_failures"] == ["producer-binding-revoked"]
    # renamed to another authenticated-tier FAILURE reason: still registry-legal,
    # still consistent with class == AIREP-Core
    v["authenticated_failures"] = ["producer-binding-not-trusted"]
    return ("RENAME", node, "G4", "authenticated_failures", "cv-rec-pb1", "PB1",
            ["producer-binding-revoked"], ["producer-binding-not-trusted"])


def main():
    good = H.known_good()
    work = H.workspace()
    lines = []
    try:
        for builder in (sub_add, sub_drop, sub_rename):
            kind, node, gid, channel, rec, case, before, after = builder(good)
            py_doc = copy.deepcopy(good)
            code, payload = H.run_comparator(py_doc, node, work, "reason_%s" % kind.lower())
            f = H.expect_failure_because(
                payload, code, gid, "reason-set-mismatch",
                case_id=case, record_id=rec, field=channel,
                python=before, node=after)
            # sharpness: the mutated reason set is still envelope-legal, so the
            # envelope gate must not be the one that caught it
            H.expect_gate_clean(payload, "G11")
            lines.append("%-7s %s %s: %s -> %s | caught by %s reason-set-mismatch, "
                         "exit %d, G11 clean"
                         % (kind, case, channel, before, after, gid, code))
        H.report("2 / reason mutation (add, drop, rename)", lines)
    finally:
        H.cleanup(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("PROOF 2 FAILED: %s\n" % exc)
        sys.exit(1)
