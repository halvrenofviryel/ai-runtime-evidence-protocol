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

- each governed claim becomes an obligation, identified by the claim's STABLE
  ``claim_id`` when present (never by its text — P0-C) and positionally otherwise;
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

**Enforcement is measured, not assumed.** A gate *directive* is a DECISION, not an
observed enforcement effect. ``enforcement_confirmed`` / ``invariants_revalidated``
are therefore derived from whether the report actually attests an observed outcome
(``_enforcement_observed``); a directive-only report leaves them False, and a closure
with unconfirmed enforcement cannot reach a SUCCEEDED/PASS terminal — it is
INCONCLUSIVE. Reporting enforcement as confirmed on the strength of a "pass" directive
alone would serialize a proxy as the thing measured (Measurement Axioms) — this
adapter must not.
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


def _enforcement_observed(report: dict[str, Any], claims: list[dict[str, Any]]) -> bool:
    """Whether the report carries a positive, OBSERVED enforcement outcome.

    A gate *directive* is a DECISION, not an observed enforcement effect — the proxy
    is not the thing measured (Measurement Axioms). ``enforcement_confirmed`` may be
    True ONLY if the report actually attests that enforcement was observed for the
    governed claims. A directive-only report carries no such observation, so this
    returns False (NOT a hardcoded True): enforcement is then NOT_MEASURED, and the
    closure cannot honestly reach a SUCCEEDED/PASS terminal — see gate_report_to_bundle.

    Accepts an explicit signal when a report provides one: a report-level boolean
    ``outcome_observed``, or a per-claim truthy ``outcome_observed`` on every claim.
    """
    report_level = report.get("outcome_observed")
    if isinstance(report_level, bool):
        return report_level
    return bool(claims) and all(bool(c.get("outcome_observed")) for c in claims)


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

    # Bind obligation identity to each claim's STABLE claim_id (P0-C) — never to the
    # claim text, and only positionally as a last resort. Use claim_ids as obligation
    # ids ONLY when every claim carries a distinct non-empty one (so two same-text
    # claims stay distinct by id, and colliding/absent ids fall back to positional
    # without risking a duplicate obligation id).
    claim_ids = [c.get("claim_id") if isinstance(c, dict) else None for c in claims]
    valid_ids = [i for i in claim_ids if isinstance(i, str) and i]
    use_claim_ids = len(valid_ids) == len(claims) and len(set(valid_ids)) == len(claims)

    obligations = []
    dispositions = []
    discharged, failed, unresolved = [], [], []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            raise ValueError(f"gate report claim[{index}] is not an object")
        oid = claim_ids[index] if use_claim_ids else f"claim-{index}"
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
    # enforcement_confirmed / invariants_revalidated are MEASUREMENTS, not constants.
    # The adapter observes gate DIRECTIVES; enforcement is confirmed only when the
    # report actually attests an observed outcome (a directive-only report -> False).
    enforcement_confirmed = _enforcement_observed(report, claims)
    # Honest terminal/verdict mapping (do NOT conflate pending-revision with failure,
    # and do NOT read a gate directive as a confirmed enforced outcome):
    #   any failed                                   -> FAILED / FAIL
    #   pending revision, OR enforcement NOT observed -> ESCALATED / INCONCLUSIVE
    #   all discharged AND enforcement observed       -> SUCCEEDED / PASS
    # (§9.1: ESCALATED = unresolved/undetermined transferred to a principal;
    #  INCONCLUSIVE = measured the decision but not the enforced effect — not a failure.
    #  A SUCCEEDED/PASS closure REQUIRES confirmed enforcement — closure_accounting's own
    #  semantic check enforces this — so directives alone can never reach PASS here.)
    if failed:
        terminal_outcome, global_verdict = "FAILED", "FAIL"
    elif unresolved or not enforcement_confirmed:
        terminal_outcome, global_verdict = "ESCALATED", "INCONCLUSIVE"
    else:
        terminal_outcome, global_verdict = "SUCCEEDED", "PASS"
    closure = {
        "profile_type": "closure_accounting",
        "schema_version": "enas-profile-0.1",
        "closure_id": f"cl-{trace_id}",
        "contract_ref": trace_id,
        "obligation_dispositions": dispositions,
        "invariants_revalidated": enforcement_confirmed,
        "enforcement_confirmed": enforcement_confirmed,
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
