from __future__ import annotations

import json

from enas_obligation_reconciler import (
    FIXTURE,
    reconcile_obligation_bundle,
    run_bundle_fixture,
)


def test_obligation_bundle_fixture_outcomes():
    # The reconciler is the bounded G3 reference for the cross-record layer the
    # single-record WP-OP checker does not cover: reference resolution, §8.4
    # transition chaining, A3 end-to-end conservation, and A7 global closure.
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_bundle_fixture()
    assert len(outcomes) == 17
    assert sum(v == "PASS" for v in expected.values()) == 5
    assert sum(v == "FAIL" for v in expected.values()) == 11
    assert sum(v == "INCONCLUSIVE" for v in expected.values()) == 1
    for name, verdict, result in outcomes:
        assert verdict == expected[name], (name, result)


def test_reconciler_is_total_over_malformed_bundles():
    # TOTAL over malformed input: a missing anchor yields a verdict, never an exception.
    for bad in ({}, {"origin_contract": {}}, {"transitions": []}, {"origin_contract": {}, "transitions": [1], "closure": {}}):
        result = reconcile_obligation_bundle(bad)
        assert result["global_verdict"] in {"INCONCLUSIVE", "FAIL"}
        assert "reconciliation_errors" in result
