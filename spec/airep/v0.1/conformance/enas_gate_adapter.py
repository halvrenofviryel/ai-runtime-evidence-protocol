"""ENAS gate adapter — bind the WP-OP reference to a real Phionyx pipeline gate.

The reference emitter (``enas_reference_orchestrator.py``) proves emit->reconcile
over a bounded in-process run. This module binds the same reconciler to an
EXTERNAL runtime boundary: the Phionyx pipeline governance gate. Its
``phionyx_session_report`` exposes a per-claim governance lifecycle — every
governed claim runs claim_created -> evidence_declared -> evidence_verified ->
gate_decision -> signed_record_persisted -> outcome_observed, and the gate emits a
directive (pass / regenerate / rewrite / block / ...).

That lifecycle IS an obligation lifecycle. This adapter maps a real session report
onto WP-OP records and reconciles them, so the obligation bundle is derived from
actual gate telemetry rather than authored by hand:

- each governed claim becomes an obligation (the claim MUST be substantiated);
- the gate directive is the disposition — ``pass`` discharges the obligation,
  ``block`` / ``reject`` fail it, and a revise directive (``regenerate`` /
  ``rewrite`` / ``hedge`` / ``require_tool``) leaves it unresolved at the snapshot;
- one conservation transition records the dispositions and the closure accounts
  every claim, with a global ``PASS`` only when every claim was discharged.

**Boundary (honest).** This maps a *captured* report from one real trace; the
directive->disposition mapping is a modelling choice, and a snapshot's "unresolved"
is pending-revision, not a permanent verdict. Binding the reconciler to a live feed
and having the gate itself emit conformant records are further, external-review-
gated steps. A reconciled ``PASS`` means the mapped bundle is a conserved, closed
lineage — not that the gate is itself ENAS-conformant.
"""

from __future__ import annotations

from typing import Any

from enas_obligation_reconciler import reconcile_obligation_bundle

# Gate directive -> obligation disposition. A claim the gate PASSED is discharged;
# a blocked/rejected claim failed; anything sent back for revision is unresolved at
# this snapshot (it is pending, not yet substantiated).
_DISCHARGE = {"pass"}
_FAIL = {"block", "reject"}


def _disposition(directive: str) -> str:
    if directive in _DISCHARGE:
        return "DISCHARGED"
    if directive in _FAIL:
        return "FAILED"
    return "UNRESOLVED"


def gate_report_to_bundle(report: dict[str, Any]) -> dict[str, Any]:
    """Map a phionyx_session_report-shaped dict onto a WP-OP obligation bundle.

    Raises ValueError if the report carries no governed claims (an origin contract
    needs at least one obligation).
    """
    if not isinstance(report, dict):
        raise ValueError("gate report must be an object")
    claims = report.get("claims")
    if not isinstance(claims, list):
        raise ValueError("gate report `claims` must be a list")
    if not claims:
        raise ValueError("gate report has no governed claims to map")
    trace_id = report.get("trace_id") or "gate-trace"

    obligations = []
    dispositions = []
    discharged, failed, unresolved = [], [], []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            raise ValueError(f"gate report claim[{index}] is not an object")
        oid = f"claim-{index}"
        statement = claim.get("claim")
        obligations.append(
            {
                "obligation_id": oid,
                "kind": "REQUIRE",
                "statement": (statement if isinstance(statement, str) and statement else "governed claim")[:120],
                "assignment_mode": "TRANSFER",
                "lifecycle_state": "OPEN",
            }
        )
        directive = claim.get("directive")
        fate = _disposition(directive if isinstance(directive, str) else "")
        dispositions.append({"obligation_id": oid, "disposition": fate})
        {"DISCHARGED": discharged, "FAILED": failed, "UNRESOLVED": unresolved}[fate].append(oid)

    all_ids = [o["obligation_id"] for o in obligations]
    transition = {
        "profile_type": "conservation_accounting",
        "schema_version": "enas-profile-0.1",
        "accounting_id": f"ca-{trace_id}",
        "transition_ref": trace_id,
        "before": all_ids,
        "created": [],
        "after": [],
        "discharged": discharged,
        "transformed": [],
        "revoked": [],
        "failed": failed,
        "unresolved": unresolved,
        "global_pass_claimed": False,
    }
    # Honest terminal/verdict mapping (do NOT conflate pending-revision with failure):
    #   all discharged        -> SUCCEEDED / PASS
    #   any failed            -> FAILED / FAIL
    #   only unresolved (pending revision, no failure) -> ESCALATED / INCONCLUSIVE
    # (§9.1: ESCALATED = unresolved judgment transferred to an authorized principal;
    #  INCONCLUSIVE = measured but not determined — not a failure.)
    if not failed and not unresolved:
        terminal_outcome, global_verdict = "SUCCEEDED", "PASS"
    elif failed:
        terminal_outcome, global_verdict = "FAILED", "FAIL"
    else:
        terminal_outcome, global_verdict = "ESCALATED", "INCONCLUSIVE"
    closure = {
        "profile_type": "closure_accounting",
        "schema_version": "enas-profile-0.1",
        "closure_id": f"cl-{trace_id}",
        "contract_ref": trace_id,
        "obligation_dispositions": dispositions,
        "invariants_revalidated": True,
        "enforcement_confirmed": True,
        "terminal_outcome": terminal_outcome,
        "global_verdict": global_verdict,
    }
    return {
        "bundle_id": f"gate-{trace_id}",
        "origin_contract": {
            "profile_type": "origin_contract",
            "schema_version": "enas-profile-0.1",
            "contract_id": trace_id,
            "contract_version": 1,
            "issuer": "phionyx-pipeline-gate",
            "authority_basis": "runtime governance gate",
            "capability_boundary": {"mediated_effects": ["claim_gating"], "evidence_channels": ["session_report"]},
            "obligations": obligations,
            "authority_ceiling": "gate directive authority",
            "allowed_transformations": ["STRUCTURAL_EQUIVALENCE"],
            "completion_rule": "every governed claim discharged",
        },
        "transitions": [transition],
        "closure": closure,
    }


def reconcile_gate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Map a real gate session report to a bundle and reconcile it end-to-end."""
    return reconcile_obligation_bundle(gate_report_to_bundle(report))
