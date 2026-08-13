"""Tests for the sequence_integrity check.

The corpus pins each chain's verdict (and whether truncation was checked). These
tests also assert the load-bearing guarantees directly: an index gap/duplicate/
reorder, a broken link, and a chain shorter than its witnessed length all FAIL; a
witnessed chain whose length matches PASSes; malformed chains are INCONCLUSIVE.
"""
from __future__ import annotations

import json
from pathlib import Path

from sequence_integrity_check import GENESIS, check_sequence_integrity

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sequence_integrity_cases.json"

H = {n: "sha256:" + c * 64 for n, c in (("a", "a"), ("b", "b"), ("c", "c"))}


def _cases():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def test_corpus_verdicts_match():
    for case in _cases():
        out = check_sequence_integrity(case["chain"])
        assert out["verdict"] == case["expected"], (
            f"{case['name']}: {out['verdict']} != {case['expected']} ({out['errors']})"
        )
        if "expected_truncation_checked" in case:
            assert out["truncation_checked"] == case["expected_truncation_checked"], (
                f"{case['name']}: truncation_checked mismatch"
            )


def _rec(i, prev, cur, witness_len=None):
    r = {"subject": {"decision_index": i}, "integrity": {"previous": prev, "current": cur}}
    if witness_len is not None:
        r["profiles"] = {"chain_witness": {"chain_id": "c", "head": {"decision_index": i, "current": cur, "length": witness_len}}}
    return r


def test_valid_chain_passes():
    chain = [_rec(0, GENESIS, H["a"]), _rec(1, H["a"], H["b"])]
    assert check_sequence_integrity(chain)["verdict"] == "PASS"


def test_index_gap_fails():
    chain = [_rec(0, GENESIS, H["a"]), _rec(2, H["a"], H["b"])]
    out = check_sequence_integrity(chain)
    assert out["verdict"] == "FAIL"
    assert any("expected 1" in e for e in out["errors"])


def test_broken_link_fails():
    chain = [_rec(0, GENESIS, H["a"]), _rec(1, H["c"], H["b"])]
    out = check_sequence_integrity(chain)
    assert out["verdict"] == "FAIL"
    assert any("does not link" in e for e in out["errors"])


def test_genesis_wrong_fails():
    chain = [_rec(0, H["a"], H["b"])]
    assert check_sequence_integrity(chain)["verdict"] == "FAIL"


def test_truncation_detected():
    chain = [_rec(0, GENESIS, H["a"]), _rec(1, H["a"], H["b"], witness_len=3)]
    out = check_sequence_integrity(chain)
    assert out["verdict"] == "FAIL"
    assert out["truncation_checked"] is True
    assert any("truncation" in e for e in out["errors"])


def test_witness_length_match_passes():
    chain = [_rec(0, GENESIS, H["a"]), _rec(1, H["a"], H["b"], witness_len=2)]
    out = check_sequence_integrity(chain)
    assert out["verdict"] == "PASS"
    assert out["truncation_checked"] is True


def test_total_over_malformed_input():
    bad = [
        None, {}, "x", 7, [],
        [1], ["x"],
        [{"integrity": {"previous": GENESIS, "current": H["a"]}}],                 # no decision_index
        [{"subject": {"decision_index": "0"}, "integrity": {"previous": GENESIS, "current": H["a"]}}],  # non-int index
        [{"subject": {"decision_index": True}, "integrity": {"previous": GENESIS, "current": H["a"]}}],  # bool index
        [{"subject": {"decision_index": 0}, "integrity": {"previous": GENESIS, "current": "nope"}}],     # bad current
        [{"subject": {"decision_index": 0}, "integrity": {"previous": "nope", "current": H["a"]}}],      # bad previous
        # witness present but no head.length -> cannot reconcile the length claim
        [{"subject": {"decision_index": 0}, "integrity": {"previous": GENESIS, "current": H["a"]},
          "profiles": {"chain_witness": {"head": {"decision_index": 0, "current": H["a"]}}}}],
    ]

    for b in bad:
        out = check_sequence_integrity(b)
        assert out["verdict"] == "INCONCLUSIVE", f"{b!r} -> {out['verdict']}"


def test_total_over_malformed_truthy_profiles():
    """A non-dict but truthy profiles on the tail must not raise (membership on a scalar)."""
    for profiles in (1, True, "x", 3.5):
        chain = [{"subject": {"decision_index": 0},
                  "integrity": {"previous": GENESIS, "current": H["a"]},
                  "profiles": profiles}]
        out = check_sequence_integrity(chain)
        # no usable witness -> truncation not asserted; the sequence itself is a valid 1-record chain
        assert out["verdict"] == "PASS", f"profiles={profiles!r} -> {out['verdict']}"
        assert out["truncation_checked"] is False
