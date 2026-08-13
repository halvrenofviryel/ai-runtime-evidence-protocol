"""Tests for the evaluator_signature check.

The corpus pins each record's verdict (and, where stated, whether independence was
established). These tests also assert the two load-bearing guarantees directly: the
check never returns PASS when the evaluator key equals the producer key, and never
returns PASS when there is no producer key to establish independence against.
"""
from __future__ import annotations

import json
from pathlib import Path

from evaluator_signature_check import check_evaluator_signature

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "evaluator_signature_cases.json"


def _cases():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def test_corpus_verdicts_match():
    for case in _cases():
        result = check_evaluator_signature(case["record"])
        assert result["verdict"] == case["expected"], (
            f"{case['name']}: {result['verdict']} != {case['expected']} ({result['errors']})"
        )
        if "expected_independence" in case:
            assert result["independence"] == case["expected_independence"], (
                f"{case['name']}: independence {result['independence']} != {case['expected_independence']}"
            )


def _base_record(**es_over):
    es = {
        "evaluator_id": "auditor", "evaluator_key_id": "eval-k",
        "signed_over": "sha256:" + "1" * 64, "verdict": "concur",
        "evaluated_at": "2026-05-30T01:00:00Z", "signature": {"alg": "Ed25519", "value": "ab"},
    }
    es.update(es_over)
    return {
        "subject": {"timestamp_utc": "2026-05-30T00:00:00Z"},
        "integrity": {"current": "sha256:" + "1" * 64},
        "profiles": {"key_trust": {"key_id": "prod-k"}, "evaluator_signature": es},
    }


def test_producer_key_never_passes():
    r = _base_record(evaluator_key_id="prod-k")
    out = check_evaluator_signature(r)
    assert out["verdict"] == "FAIL"
    assert any("not independent" in e for e in out["errors"])


def test_no_producer_key_is_inconclusive_not_pass():
    r = _base_record()
    del r["profiles"]["key_trust"]
    out = check_evaluator_signature(r)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["independence"] == "unconfirmed"


def test_binding_mismatch_fails():
    r = _base_record(signed_over="sha256:" + "2" * 64)
    assert check_evaluator_signature(r)["verdict"] == "FAIL"


def test_independent_attestation_passes():
    assert check_evaluator_signature(_base_record())["verdict"] == "PASS"


def test_total_over_malformed_input():
    bad = [
        None, [], "x", 7, {}, {"profiles": "no"}, {"profiles": {}},
        {"profiles": {"evaluator_signature": "no"}},
        {"profiles": {"evaluator_signature": {"verdict": []}}},          # unhashable verdict
        {"integrity": {"current": "sha256:" + "1" * 64},
         "profiles": {"evaluator_signature": {"evaluator_id": "a", "evaluator_key_id": "b",
                      "signed_over": "sha256:" + "1" * 64, "verdict": "concur",
                      "evaluated_at": "nope", "signature": {"alg": "Ed25519", "value": "x"}}}},  # bad date
        # no valid integrity.current to bind to:
        {"profiles": {"key_trust": {"key_id": "p"}, "evaluator_signature": {
            "evaluator_id": "a", "evaluator_key_id": "b", "signed_over": "sha256:" + "1" * 64,
            "verdict": "concur", "evaluated_at": "2026-05-30T01:00:00Z",
            "signature": {"alg": "Ed25519", "value": "x"}}}},
    ]
    for b in bad:
        out = check_evaluator_signature(b)
        assert out["verdict"] == "INCONCLUSIVE", f"{b!r} -> {out['verdict']}"
