#!/usr/bin/env python3
"""NEGATIVE PROOF 1 -- class flip.

Takes a known-good pair of outputs, flips one `class` value on the Node side,
and shows the comparator reporting FAILURE *because of the class mismatch* --
not because of some unrelated collateral effect.

The flip is deliberately chosen to be envelope-invariant-clean
(AIREP-Authenticated -> AIREP-Core on a verdict with no caveats and no
authenticated reasons), so the class-parity gate G3 is the gate that must catch
it. If G11 caught it instead, the proof would be worthless.
"""

import copy
import sys

import harness as H


def main():
    good = H.known_good()
    py_doc = copy.deepcopy(good)
    node_doc = copy.deepcopy(good)

    target = H.find_verdict(node_doc, "cv-rec-p1")
    before = target["class"]
    assert before == "AIREP-Authenticated", before
    assert not target["authenticated_failures"] and not target["authenticated_withheld"]
    assert not target["authenticated_caveats"]
    target["class"] = "AIREP-Core"

    work = H.workspace()
    try:
        code, payload = H.run_comparator(py_doc, node_doc, work, "class_flip")
        f = H.expect_failure_because(
            payload, code, "G3", "class-mismatch",
            record_id="cv-rec-p1", chain_id="cv-chain-p1", case_id="P1",
            field="class", python="AIREP-Authenticated", node="AIREP-Core")
        # the flip must also be caught against the frozen expected values
        H.expect_failure_because(
            payload, code, "G13", "expected-mismatch",
            impl="node", case_id="P1", field="class",
            expected="AIREP-Authenticated", actual="AIREP-Core")
        # sharpness: the mutation is invariant-clean, so the envelope gate must
        # NOT be what caught it
        H.expect_gate_clean(payload, "G11")
        H.report("1 / class flip", [
            "mutated: node-side verdict cv-rec-p1 class %s -> AIREP-Core" % before,
            "comparator exit: %d (expected 1)" % code,
            "cause: G3 class-mismatch %s" % f,
            "corroborating: G13 expected-mismatch (node vs frozen expected.json)",
            "sharpness: G11 envelope gate stayed clean, so G3 is what caught it",
        ])
    finally:
        H.cleanup(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("PROOF 1 FAILED: %s\n" % exc)
        sys.exit(1)
