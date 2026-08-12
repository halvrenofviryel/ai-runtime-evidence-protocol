from __future__ import annotations

import copy

import pytest
from enas_obligation_reconciler import reconcile_obligation_bundle
from enas_reference_orchestrator import (
    ObligationOrchestrator,
    OrchestratorError,
    emit_reference_failure_bundle,
    emit_reference_success_bundle,
)


def test_emitted_success_bundle_reconciles_to_pass():
    # emit -> reconcile round-trip: records derived from a real run pass the INDEPENDENT reconciler.
    bundle = emit_reference_success_bundle()
    result = reconcile_obligation_bundle(bundle)
    assert result["global_verdict"] == "PASS", result


def test_emitted_failure_bundle_is_a_valid_conserved_lineage():
    # an honest failure run is still a conserved, well-closed lineage (closure != success).
    bundle = emit_reference_failure_bundle()
    result = reconcile_obligation_bundle(bundle)
    assert result["global_verdict"] == "PASS", result
    assert bundle["closure"]["global_verdict"] == "FAIL"


def test_reconciler_catches_a_corrupted_emitted_record():
    # If the emitter (or anything downstream) tampers a record, the independent reconciler
    # must reject it — the round-trip PASS is not the emitter trusting itself.
    bundle = emit_reference_success_bundle()
    tampered = copy.deepcopy(bundle)
    # drop one obligation's disposition from closure: every record stays single-record-valid,
    # but the closure no longer disposes the full accountable set — a purely CROSS-record break
    # that only the reconciler (not the per-record checker) can catch.
    tampered["closure"]["obligation_dispositions"] = tampered["closure"]["obligation_dispositions"][:-1]
    result = reconcile_obligation_bundle(tampered)
    assert result["global_verdict"] == "FAIL", result


def test_orchestrator_guards():
    orch = ObligationOrchestrator("c")
    orch.declare("ob-1", "REQUIRE", "x")
    with pytest.raises(OrchestratorError):
        orch.declare("ob-1", "REQUIRE", "dup")
    with pytest.raises(OrchestratorError):
        orch.discharge("ob-missing")
    with pytest.raises(OrchestratorError):
        orch.bundle()  # before close()
