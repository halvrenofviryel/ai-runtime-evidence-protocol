"""ENAS obligation-protocol reference emitter (bounded G3 slice).

A small in-process orchestrator that executes an obligation lifecycle and emits
the WP-OP records from its own state transitions, so the records are derived from
execution rather than hand-authored. ``bundle()`` round-trips through
``enas_obligation_reconciler.reconcile_obligation_bundle``. Scope and boundary are
documented in ``conformance/README.md`` (a round-trip PASS is agreement between
the emitter and the independent reconciler, not evidence about any external
system).
"""

from __future__ import annotations

from typing import Any


class OrchestratorError(RuntimeError):
    """Raised when a step is attempted against an obligation not currently live."""


class ObligationOrchestrator:
    def __init__(
        self,
        contract_id: str,
        issuer: str = "reference-issuer",
        authority_basis: str = "reference charter",
    ) -> None:
        self._contract_id = contract_id
        self._issuer = issuer
        self._authority_basis = authority_basis
        self._obligations: list[dict[str, Any]] = []
        self._live: list[str] = []  # ordered outstanding set
        self._seen: set[str] = set()
        self._handoffs: list[dict[str, Any]] = []
        self._transformations: list[dict[str, Any]] = []
        self._transitions: list[dict[str, Any]] = []
        self._closure: dict[str, Any] | None = None
        self._fate: dict[str, str] = {}  # obligation_id -> terminal fate reached in-run
        self._n = 0

    def _next(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n}"

    def declare(self, obligation_id: str, kind: str, statement: str, assignment_mode: str = "TRANSFER") -> None:
        if obligation_id in self._seen:
            raise OrchestratorError(f"obligation {obligation_id} already declared")
        self._obligations.append(
            {
                "obligation_id": obligation_id,
                "kind": kind,
                "statement": statement,
                "assignment_mode": assignment_mode,
                "lifecycle_state": "OPEN",
            }
        )
        self._live.append(obligation_id)
        self._seen.add(obligation_id)

    def _transition(self, transition_ref: str, before: list[str], **buckets: Any) -> None:
        # `before` is the outstanding set snapshotted BEFORE the caller mutated self._live;
        # `after` is the new live set (post-mutation).
        transition = {
            "profile_type": "conservation_accounting",
            "schema_version": "enas-profile-0.1",
            "accounting_id": self._next("ca"),
            "transition_ref": transition_ref,
            "before": before,
            "created": [],
            "after": list(self._live),
            "discharged": [],
            "transformed": [],
            "revoked": [],
            "failed": [],
            "unresolved": [],
            "global_pass_claimed": False,
        }
        transition.update(buckets)
        transition["after"] = list(self._live)
        self._transitions.append(transition)

    def discharge(self, obligation_id: str, sender: str = "agent-a", receiver: str = "agent-b") -> None:
        if obligation_id not in self._live:
            raise OrchestratorError(f"cannot discharge {obligation_id}: not live")
        before = list(self._live)
        handoff_id = self._next("ho")
        self._handoffs.append(
            {
                "profile_type": "obligation_handoff",
                "schema_version": "enas-profile-0.1",
                "handoff_id": handoff_id,
                "obligation_ids": [obligation_id],
                "sender": sender,
                "receiver": receiver,
                "assignment_mode": "TRANSFER",
                "acceptance_state": "FULFILLED",
                "semantic_delta": {"preserved": [], "delegated": [], "discharged": [obligation_id], "transformed": [], "created": [], "revoked": [], "unresolved": []},
            }
        )
        self._live.remove(obligation_id)
        self._fate[obligation_id] = "DISCHARGED"
        self._transition(handoff_id, before, discharged=[obligation_id])

    def transform(self, predecessor: str, successor: str, transformation_class: str = "STRUCTURAL_EQUIVALENCE") -> None:
        if predecessor not in self._live:
            raise OrchestratorError(f"cannot transform {predecessor}: not live")
        if successor in self._seen:
            raise OrchestratorError(f"successor {successor} is not a fresh identity")
        before = list(self._live)
        transformation_id = self._next("tr")
        self._transformations.append(
            {
                "profile_type": "transformation_record",
                "schema_version": "enas-profile-0.1",
                "transformation_id": transformation_id,
                "predecessor_obligation": predecessor,
                "successor_obligations": [successor],
                "transformation_class": transformation_class,
                "loss_vector": [{"property": "scope", "status": "PRESERVED"}],
                "discharges_predecessor": False,
            }
        )
        self._live.remove(predecessor)
        self._live.append(successor)
        self._seen.add(successor)
        self._transition(transformation_id, before, created=[successor], transformed=[{"obligation_id": predecessor, "successor_ref": successor}])

    def close(self, fail_remaining: bool = False) -> None:
        # dispose every accountable obligation: those already terminal in-run keep their fate;
        # everything still live is disposed now (DISCHARGED, or FAILED if fail_remaining).
        dispositions = [{"obligation_id": oid, "disposition": fate} for oid, fate in self._fate.items()]
        close_fate = "FAILED" if fail_remaining else "DISCHARGED"
        for oid in self._live:
            dispositions.append({"obligation_id": oid, "disposition": close_fate})
        any_failure = fail_remaining and bool(self._live)
        self._closure = {
            "profile_type": "closure_accounting",
            "schema_version": "enas-profile-0.1",
            "closure_id": self._next("cl"),
            "contract_ref": self._contract_id,
            "obligation_dispositions": dispositions,
            "invariants_revalidated": True,
            "enforcement_confirmed": True,
            "terminal_outcome": "FAILED" if any_failure else "SUCCEEDED",
            "global_verdict": "FAIL" if any_failure else "PASS",
        }
        self._live = []

    def bundle(self) -> dict[str, Any]:
        if self._closure is None:
            raise OrchestratorError("bundle requested before close()")
        return {
            "bundle_id": f"emitted-{self._contract_id}",
            "origin_contract": {
                "profile_type": "origin_contract",
                "schema_version": "enas-profile-0.1",
                "contract_id": self._contract_id,
                "contract_version": 1,
                "issuer": self._issuer,
                "authority_basis": self._authority_basis,
                "capability_boundary": {"mediated_effects": ["file_write"], "evidence_channels": ["audit_log"]},
                "obligations": self._obligations,
                "authority_ceiling": "reference ceiling",
                "allowed_transformations": ["STRUCTURAL_EQUIVALENCE", "SEMANTIC_BOUNDED"],
                "completion_rule": "every declared obligation reaches a terminal disposition",
            },
            "transitions": self._transitions,
            "handoffs": self._handoffs,
            "transformations": self._transformations,
            "closure": self._closure,
        }


def emit_reference_success_bundle() -> dict[str, Any]:
    """A canonical successful run: declare 3, discharge one, transform one, close."""
    orch = ObligationOrchestrator("contract-ref-success")
    orch.declare("ob-a", "REQUIRE", "produce the artifact")
    orch.declare("ob-b", "REQUIRE", "record the decision")
    orch.declare("ob-c", "PRESERVE", "keep the ethics gate", assignment_mode="OBSERVE")
    orch.discharge("ob-a")
    orch.transform("ob-b", "ob-b2")
    orch.close()
    return orch.bundle()


def emit_reference_failure_bundle() -> dict[str, Any]:
    """A canonical honest-failure run: one obligation is left failed at close."""
    orch = ObligationOrchestrator("contract-ref-failure")
    orch.declare("ob-a", "REQUIRE", "produce the artifact")
    orch.declare("ob-b", "REQUIRE", "the step that fails")
    orch.discharge("ob-a")
    orch.close(fail_remaining=True)
    return orch.bundle()
