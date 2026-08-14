from __future__ import annotations

import json
from pathlib import Path

import pytest
from enas_gate_adapter import gate_report_to_bundle, reconcile_gate_report
from enas_obligation_reconciler import reconcile_obligation_bundle

CAPTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_gate_report_capture.json"
)


def _captured_report() -> dict:
    return json.loads(CAPTURE.read_text(encoding="utf-8"))["report"]


def test_captured_real_gate_report_reconciles_to_a_conserved_lineage():
    # A verbatim real phionyx-pipeline session report maps onto WP-OP records that the
    # INDEPENDENT reconciler confirms is a conserved, well-closed lineage. The captured
    # session sent 7 claims back for revision and passed 1, so the honest closure is a
    # non-success (unresolved != failure) — still a valid conserved bundle.
    report = _captured_report()
    bundle = gate_report_to_bundle(report)
    assert len(bundle["origin_contract"]["obligations"]) == 8
    dispositions = {d["obligation_id"]: d["disposition"] for d in bundle["closure"]["obligation_dispositions"]}
    assert sum(v == "DISCHARGED" for v in dispositions.values()) == 1
    assert sum(v == "UNRESOLVED" for v in dispositions.values()) == 7
    # pending-revision claims are ESCALATED/INCONCLUSIVE, NOT failed — honest non-success.
    assert bundle["closure"]["terminal_outcome"] == "ESCALATED"
    assert bundle["closure"]["global_verdict"] == "INCONCLUSIVE"
    assert reconcile_obligation_bundle(bundle)["global_verdict"] == "PASS"


def test_all_pass_directives_without_observed_enforcement_are_inconclusive():
    # A gate directive is a DECISION, not an observed enforcement effect. All-"pass"
    # directives with NO observed outcome must NOT reach SUCCEEDED/PASS — enforcement is
    # NOT_MEASURED, so the honest closure is ESCALATED/INCONCLUSIVE with
    # enforcement_confirmed=False. (Regression guard for the measurement-positivity fix:
    # this closure used to hardcode enforcement_confirmed=True and claim PASS.)
    report = {"trace_id": "t-allpass", "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}]}
    bundle = gate_report_to_bundle(report)
    assert bundle["closure"]["enforcement_confirmed"] is False
    assert bundle["closure"]["invariants_revalidated"] is False
    assert bundle["closure"]["terminal_outcome"] == "ESCALATED"
    assert bundle["closure"]["global_verdict"] == "INCONCLUSIVE"
    assert reconcile_gate_report(report)["global_verdict"] == "PASS"  # conserved lineage regardless


def test_all_pass_with_observed_enforcement_reaches_a_successful_closure():
    # The SUCCEEDED/PASS path IS reachable — but only when the report actually attests an
    # observed enforcement outcome for every claim (outcome_observed truthy), which is what
    # closure_accounting's own semantic check requires for a PASS.
    report = {
        "trace_id": "t-allpass-observed",
        "claims": [
            {"claim": "a", "directive": "pass", "outcome_observed": True},
            {"claim": "b", "directive": "pass", "outcome_observed": True},
        ],
    }
    bundle = gate_report_to_bundle(report)
    assert bundle["closure"]["enforcement_confirmed"] is True
    assert bundle["closure"]["invariants_revalidated"] is True
    assert bundle["closure"]["terminal_outcome"] == "SUCCEEDED"
    assert bundle["closure"]["global_verdict"] == "PASS"
    assert reconcile_gate_report(report)["global_verdict"] == "PASS"


def test_captured_report_closure_does_not_claim_confirmed_enforcement():
    # The captured directive-only report attests no enforcement outcome -> the closure must
    # report enforcement_confirmed=False (the positivity the reviewer flagged, now fixed).
    bundle = gate_report_to_bundle(_captured_report())
    assert bundle["closure"]["enforcement_confirmed"] is False
    assert bundle["closure"]["invariants_revalidated"] is False


def test_blocked_claim_becomes_a_failed_obligation():
    report = {"trace_id": "t-block", "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "block"}]}
    bundle = gate_report_to_bundle(report)
    dispositions = {d["obligation_id"]: d["disposition"] for d in bundle["closure"]["obligation_dispositions"]}
    assert "FAILED" in dispositions.values()
    assert bundle["closure"]["global_verdict"] == "FAIL"
    assert reconcile_gate_report(report)["global_verdict"] == "PASS"  # honest failure is conserved


def test_reconciler_catches_a_tampered_gate_bundle():
    # Drop one claim's disposition from the mapped closure: every record stays
    # single-record-valid, but the closure no longer accounts the full claim set — a purely
    # CROSS-record break the independent reconciler catches as FAIL.
    report = _captured_report()
    tampered = gate_report_to_bundle(report)
    tampered["closure"]["obligation_dispositions"] = tampered["closure"]["obligation_dispositions"][:-1]
    assert reconcile_obligation_bundle(tampered)["global_verdict"] == "FAIL"


def test_malformed_reports_raise_valueerror_not_crash():
    # TOTAL over malformed input: a clear ValueError, never a raw AttributeError/TypeError.
    for bad in (
        {"trace_id": "t", "claims": []},
        {"trace_id": "t"},
        {"trace_id": "t", "claims": {"claim": "a", "directive": "pass"}},
        {"trace_id": "t", "claims": [None]},
        None,
        [],
        "not-a-report",
    ):
        with pytest.raises(ValueError):
            gate_report_to_bundle(bad)


def test_non_string_directive_is_treated_as_unresolved():
    report = {"trace_id": "t", "claims": [{"claim": "a", "directive": ["pass"]}]}
    bundle = gate_report_to_bundle(report)
    assert bundle["closure"]["obligation_dispositions"][0]["disposition"] == "UNRESOLVED"
    assert reconcile_gate_report(report)["global_verdict"] == "PASS"
