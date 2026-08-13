"""Tests for the control_delivery bundle reconciler.

The corpus in fixtures/control_delivery_cases.json pins each bundle's global verdict
and, where stated, per-instruction status. These tests also assert the reconciler's
load-bearing guarantee directly: it never returns DELIVERED for an instruction that
has no independent enforcement-side observation (APTS-HO-008: an unacknowledged
instruction MUST NOT be treated as delivered).
"""
from __future__ import annotations

from control_delivery_reconciler import (
    reconcile_control_delivery_bundle,
    run_bundle_fixture,
)


def test_corpus_verdicts_and_statuses_match():
    for name, case, result in run_bundle_fixture():
        assert result["global_verdict"] == case["expected"], (
            f"{name}: verdict {result['global_verdict']} != {case['expected']}"
        )
        for iid, want in (case.get("expected_status") or {}).items():
            assert result["instructions"].get(iid, {}).get("status") == want, (
                f"{name}: {iid} status {result['instructions'].get(iid)} != {want}"
            )


def _issuer_only_delivered_bundle():
    return {
        "records": [
            {"instruction_id": "x", "instruction_hash": "sha256:ab", "phase": "issued",
             "observed_by": "issuer", "observed_at": "2026-05-30T00:00:00Z"},
            {"instruction_id": "x", "instruction_hash": "sha256:ab", "phase": "delivered",
             "observed_by": "issuer", "observed_at": "2026-05-30T00:00:01Z"},
        ]
    }


def test_issuer_only_is_never_delivered():
    """The APTS-HO-008 normative line, enforced by construction."""
    result = reconcile_control_delivery_bundle(_issuer_only_delivered_bundle())
    inst = result["instructions"]["x"]
    assert inst["status"] == "UNCONFIRMED"
    assert inst["status"] != "DELIVERED"
    assert inst["default_safe"] is True
    assert inst["operator_notification_required"] is True  # item 10
    assert result["global_verdict"] == "PASS"  # honestly flagged is a correct outcome


def test_enforcement_side_ack_makes_it_delivered():
    bundle = _issuer_only_delivered_bundle()
    bundle["records"].append(
        {"instruction_id": "x", "instruction_hash": "sha256:ab", "phase": "acknowledged",
         "observed_by": "enforcement_point", "observed_at": "2026-05-30T00:00:02Z"}
    )
    result = reconcile_control_delivery_bundle(bundle)
    assert result["instructions"]["x"]["status"] == "DELIVERED"
    assert result["instructions"]["x"]["operator_notification_required"] is False


def test_substitution_is_fail():
    bundle = {
        "records": [
            {"instruction_id": "y", "instruction_hash": "sha256:aa", "phase": "issued",
             "observed_by": "issuer", "observed_at": "2026-05-30T00:00:00Z"},
            {"instruction_id": "y", "instruction_hash": "sha256:bb", "phase": "acknowledged",
             "observed_by": "enforcement_point", "observed_at": "2026-05-30T00:00:01Z"},
        ]
    }
    result = reconcile_control_delivery_bundle(bundle)
    assert result["global_verdict"] == "FAIL"
    assert result["instructions"]["y"]["status"] == "SUBSTITUTION"


def test_delivery_failed_needs_a_reason():
    bundle = {
        "records": [
            {"instruction_id": "z", "instruction_hash": "sha256:aa", "phase": "delivery_failed",
             "observed_by": "enforcement_point", "observed_at": "2026-05-30T00:00:00Z",
             "failure": {"hypothesis": "maybe"}},
        ]
    }
    result = reconcile_control_delivery_bundle(bundle)
    assert result["global_verdict"] == "FAIL"
    assert any("failure.reason" in e for e in result["reconciliation_errors"])


def test_total_over_malformed_input():
    def _rec(**over):
        base = {"instruction_id": "a", "instruction_hash": "sha256:aa", "phase": "issued",
                "observed_by": "issuer", "observed_at": "2026-05-30T00:00:00Z"}
        base.update(over)
        return base

    bad_inputs = [
        None, [], "x", 3,
        {"records": "no"}, {"records": []}, {"records": [1]},
        {"records": [_rec(failure="oops")]},              # failure not an object
        {"records": [_rec(phase="teleported")]},           # bad phase enum
        {"records": [_rec(observed_by="issuerx")]},        # bad observer enum
        {"records": [_rec(instruction_hash="not-a-hash")]},  # bad hash form
        {"records": [_rec(instruction_id=7)]},             # non-string id (would break sort)
        {"records": [_rec(instruction_id="a"), _rec(instruction_id=object())]},  # mixed-type ids
        {"records": [_rec(phase=[])]},                      # unhashable enum value (would TypeError)
        {"records": [_rec(observed_by={})]},               # unhashable observer value
        {"records": [_rec(observed_at=None)]},             # missing/typeless observed_at (schema-required)
        {"records": [{"instruction_id": "a", "instruction_hash": "sha256:aa", "phase": "issued",
                      "observed_by": "issuer"}]},          # observed_at absent entirely
        {"records": [_rec(observed_at="not-a-date")]},      # observed_at bad date-time format
        {"records": [_rec(observed_at="2026-05-30T00:00:00")]},  # RFC3339 but no timezone
        {"records": [_rec(observed_at="2026-05-30")]},      # date only, no time/timezone
    ]
    for bad in bad_inputs:
        result = reconcile_control_delivery_bundle(bad)
        assert result["global_verdict"] == "INCONCLUSIVE", f"{bad!r} -> {result['global_verdict']}"
        assert result["instructions"] == {}


def test_enum_checks_hold_without_jsonschema(monkeypatch):
    """The bounded structural layer must catch bad enums even if jsonschema is absent."""
    import control_delivery_reconciler as mod

    monkeypatch.setattr(mod, "Draft202012Validator", None)
    bundle = {"records": [{"instruction_id": "a", "instruction_hash": "sha256:aa",
                           "phase": "teleported", "observed_by": "issuer",
                           "observed_at": "2026-05-30T00:00:00Z"}]}
    result = mod.reconcile_control_delivery_bundle(bundle)
    assert result["global_verdict"] == "INCONCLUSIVE"


def test_enforced_no_effect_is_delivered_but_flagged():
    bundle = {
        "records": [
            {"instruction_id": "w", "instruction_hash": "sha256:aa", "phase": "issued",
             "observed_by": "issuer", "observed_at": "2026-05-30T00:00:00Z"},
            {"instruction_id": "w", "instruction_hash": "sha256:aa", "phase": "enforced",
             "observed_by": "enforcement_point", "observed_at": "2026-05-30T00:00:02Z", "result": "no_effect"},
        ]
    }
    result = reconcile_control_delivery_bundle(bundle)
    inst = result["instructions"]["w"]
    assert inst["status"] == "DELIVERED"
    assert inst["enforced_result"] == "no_effect"  # delivered != effective
