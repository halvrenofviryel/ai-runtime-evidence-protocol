#!/usr/bin/env python3
"""NEGATIVE PROOF 3 -- verdict-envelope and invariant violations.

Five sub-mutations on COPIES of a known-good pair, each breaking one distinct
envelope rule from CLASS_VERIFIER_CONTRACT.md section 2, and each asserted
against the specific finding it must produce:

  a  section 2 consistency invariant  -- class AIREP-Witnessed with a non-empty
                                          withheld array (the example the
                                          contract itself names)
  b  closed verdict membership        -- an unknown member
  c  closed verdict membership        -- a missing required member
  d  closed reason registry           -- a reason outside the 31-reason registry
  e  deterministic ordering           -- verdicts out of UTF-8 tuple order
"""

import copy
import sys

import harness as H


def main():
    good = H.known_good()
    work = H.workspace()
    lines = []
    try:
        # (a) invariant: class == AIREP-Witnessed with a non-empty withheld array
        node = copy.deepcopy(good)
        v = H.find_verdict(node, "cv-rec-p1")
        assert v["witnessed_withheld"] == ["no-witness-supplied"]
        v["class"] = "AIREP-Witnessed"
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "inv")
        H.expect_failure_because(payload, code, "G11", "invariant-violation",
                                 impl="node", record_id="cv-rec-p1",
                                 invariant="witnessed-implies-all-clean",
                                 value="AIREP-Witnessed")
        H.expect_failure_because(payload, code, "G11", "invariant-violation",
                                 impl="node", record_id="cv-rec-p1",
                                 invariant="witness-negative-implies-not-witnessed",
                                 value="AIREP-Witnessed")
        lines.append("(a) invariant  : class->AIREP-Witnessed with witnessed_withheld "
                     "non-empty | G11 invariant-violation "
                     "{witnessed-implies-all-clean, witness-negative-implies-not-witnessed}, "
                     "exit %d" % code)

        # (b) closed membership: unknown member
        node = copy.deepcopy(good)
        H.find_verdict(node, "cv-rec-p2")["assurance_score"] = 0.99
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "unknown")
        H.expect_failure_because(payload, code, "G11", "envelope-unknown-member",
                                 impl="node", record_id="cv-rec-p2",
                                 member="assurance_score")
        lines.append("(b) membership : added unknown member 'assurance_score' | "
                     "G11 envelope-unknown-member, exit %d" % code)

        # (c) closed membership: required member removed
        node = copy.deepcopy(good)
        del H.find_verdict(node, "cv-rec-p2")["authenticated_caveats"]
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "missing")
        H.expect_failure_because(payload, code, "G11", "envelope-missing-member",
                                 impl="node", record_id="cv-rec-p2",
                                 member="authenticated_caveats")
        lines.append("(c) membership : removed required member 'authenticated_caveats' | "
                     "G11 envelope-missing-member, exit %d" % code)

        # (d) closed reason registry: a reason outside the 31-reason registry
        node = copy.deepcopy(good)
        H.find_verdict(node, "cv-rec-p1")["witnessed_withheld"] = ["witness-probably-fine"]
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "registry")
        H.expect_failure_because(payload, code, "G11", "reason-not-in-registry",
                                 impl="node", record_id="cv-rec-p1",
                                 channel="witnessed_withheld",
                                 reason="witness-probably-fine")
        lines.append("(d) registry   : reason 'witness-probably-fine' outside the closed "
                     "31-reason registry | G11 reason-not-in-registry, exit %d" % code)

        # (e) deterministic ordering: two verdicts transposed
        node = copy.deepcopy(good)
        node["verdicts"][0], node["verdicts"][1] = node["verdicts"][1], node["verdicts"][0]
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "order")
        H.expect_failure_because(payload, code, "G12", "order-violation",
                                 impl="node", index=0)
        lines.append("(e) ordering   : transposed verdicts 0 and 1 on the node side | "
                     "G12 order-violation, exit %d" % code)

        H.report("3 / envelope and invariant violations", lines)
    finally:
        H.cleanup(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("PROOF 3 FAILED: %s\n" % exc)
        sys.exit(1)
