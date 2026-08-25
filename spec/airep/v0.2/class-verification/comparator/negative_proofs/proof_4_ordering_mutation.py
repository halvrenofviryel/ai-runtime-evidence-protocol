#!/usr/bin/env python3
"""NEGATIVE PROOF 4 (C1) -- ordering mutation on the UTF-8 discriminating pair.

C1 added ORD1 (record_id ending U+10000, UTF-8 f0 90 80 80) and ORD2 (record_id
ending U+FF00, UTF-8 ef bc 80) in the same chain. Under the section 2 UTF-8 byte
rule ORD2 MUST precede ORD1; under JavaScript's native UTF-16 code-unit order
the high surrogate d800 sorts before ff00, giving the opposite. The pair is a
naive-JavaScript-sort detector.

This proof swaps the two verdicts on one side of a known-good pair and shows G12
failing specifically on UTF-8 ordering -- naming the discriminating pair, not
merely reporting "the two files differ".
"""

import copy
import json
import sys

import harness as H

ORD2_SUFFIX = "＀"      # UTF-8 ef bc 80 -- must come FIRST
ORD1_SUFFIX = "\U00010000"  # UTF-8 f0 90 80 80 -- must come SECOND


def main():
    good = H.known_good()
    node = copy.deepcopy(good)

    idx = {}
    for i, v in enumerate(node["verdicts"]):
        rid = v["artifact_ref"]["record_id"]
        if rid.endswith(ORD2_SUFFIX):
            idx["ORD2"] = i
        elif rid.endswith(ORD1_SUFFIX):
            idx["ORD1"] = i
    if set(idx) != {"ORD1", "ORD2"}:
        raise H.ProofFailure(
            "the known-good output does not carry both ordering fixtures: %s" % sorted(idx))
    if idx["ORD2"] >= idx["ORD1"]:
        raise H.ProofFailure(
            "precondition failed: the known-good output already has ORD2 at %d and ORD1 at "
            "%d, so it is not correctly ordered to begin with" % (idx["ORD2"], idx["ORD1"]))

    i, j = idx["ORD2"], idx["ORD1"]
    node["verdicts"][i], node["verdicts"][j] = node["verdicts"][j], node["verdicts"][i]

    work = H.workspace()
    try:
        code, payload = H.run_comparator(copy.deepcopy(good), node, work, "ordering")
        # the C1-specific cause: the discriminating pair is now in UTF-16 order
        f = H.expect_failure_because(
            payload, code, "G12", "ordering-discriminator-violated",
            impl="node", required="ORD2 must precede ORD1")
        # and the whole-order equality against the comparator's own UTF-8 computation
        H.expect_failure_because(payload, code, "G12", "order-not-utf8-expected",
                                 impl="node")
        # sharpness: the swap is envelope-legal, so the envelope gate is not the catcher
        H.expect_gate_clean(payload, "G11")
        # sharpness: no semantic field changed, so the parity gates must stay clean
        for gid in ("G3", "G4", "G5", "G6", "G7", "G8", "G9", "G13"):
            H.expect_gate_clean(payload, gid)
        H.report("4 / ordering mutation (C1 UTF-8 discriminating pair)", [
            "mutated: node-side verdicts %d and %d transposed (ORD2 <-> ORD1)" % (i, j),
            "comparator exit: %d (expected 1)" % code,
            "cause: G12 ordering-discriminator-violated %s"
            % json.dumps({k: v for k, v in f.items()
                          if k in ("code", "impl", "required", "index_of_first",
                                   "index_of_second")}, sort_keys=True),
            "corroborating: G12 order-not-utf8-expected against the comparator's own "
            "UTF-8 byte computation of all 60 positions",
            "sharpness: G11 and every semantic parity gate (G3-G9, G13) stayed clean, "
            "so the ordering surface is what caught it",
        ])
    finally:
        H.cleanup(work)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except H.ProofFailure as exc:
        sys.stderr.write("PROOF 4 FAILED: %s\n" % exc)
        sys.exit(1)
