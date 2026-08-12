#!/usr/bin/env python3
"""Bounded schema and semantic checks for the experimental ENAS profiles.

These checks establish only the declared record contracts. They do not prove
that a runtime emitted a record at the claimed boundary or that an effect
occurred.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / "profiles"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "enas_profiles" / "enas_profile_cases.json"
LIFECYCLE_PROFILE_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_lifecycle_profile_cases.json"
)
RECOVERY_CLOSURE_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_recovery_closure_cases.json"
)
CLAIM_COVERAGE_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_claim_coverage_cases.json"
)
OBLIGATION_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_obligation_protocol_cases.json"
)

SCHEMAS = {
    name: PROFILE_DIR / f"{name}.schema.json"
    for name in (
        "decision_input_manifest",
        "evidence_use",
        "execution_link",
        "effect_assurance",
        "verification_package",
        "assurance_claim",
        "coverage_declaration",
        "enforcement_acknowledgement",
        "enforcement_result",
        "execution_observation",
        "effect_observation",
        "interruption_event",
        "oversight_loss_event",
        "residual_capability_disposition",
        "contamination_record",
        "re_establishment_record",
        "disclosure_manifest",
        "retention_policy_binding",
        "disposition_event",
        "lifecycle_record_manifest",
        "retry_attempt",
        "liveness_budget",
        "liveness_closure",
        "fairness_declaration",
        "failure_class_response",
        "claim_configuration",
        "nondeterminism_record",
        "reliance_claim",
        "observed_operating_path",
        "claim_coverage_registry",
        "origin_contract",
        "obligation_handoff",
        "transformation_record",
        "fork_join_record",
        "conservation_accounting",
        "amendment_revocation_event",
        "closure_accounting",
    )
}


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _duplicates(values: list[str]) -> bool:
    return len(values) != len(set(values))


def _as_dict(value: Any) -> dict[str, Any]:
    """Return ``value`` if it is a dict, else an empty dict.

    Bundle validators must be TOTAL over malformed input: a record/link/endpoint that is
    present but not an object must yield a validation error, never an ``AttributeError``.
    Every ``.get`` on a value that a caller supplied inside a list/field goes through this.
    """
    return value if isinstance(value, dict) else {}


def _decision_input_manifest(doc: dict[str, Any]) -> list[str]:
    ids = [item["input_id"] for item in doc["inputs"]]
    return ["duplicate input_id"] if _duplicates(ids) else []


def _evidence_use(doc: dict[str, Any]) -> list[str]:
    if doc["relation"] == "USED_MATERIAL" and not doc.get("measurement_basis"):
        return ["USED_MATERIAL requires measurement_basis"]
    return []


def _execution_link(doc: dict[str, Any]) -> list[str]:
    errors = []
    attempt = doc["action_attempt_id"]
    if doc["source_attempt_id"] != attempt or doc["target_attempt_id"] != attempt:
        errors.append("execution link crosses action attempts")
    expected = {
        "ACTION_TO_DECISION": ("ACTION", "DECISION"),
        "DECISION_TO_INSTRUCTION": ("DECISION", "INSTRUCTION"),
        "INSTRUCTION_TO_ACKNOWLEDGEMENT": ("INSTRUCTION", "ACKNOWLEDGEMENT"),
        "ACKNOWLEDGEMENT_TO_APPLICATION": ("ACKNOWLEDGEMENT", "APPLICATION"),
        "APPLICATION_TO_EXECUTION": ("APPLICATION", "EXECUTION"),
        "EXECUTION_TO_EFFECT": ("EXECUTION", "EFFECT"),
    }[doc["relation"]]
    if (doc["source"]["type"], doc["target"]["type"]) != expected:
        errors.append("link relation does not match node types")
    return errors


def _effect_assurance(doc: dict[str, Any]) -> list[str]:
    errors = []
    claim = doc["effect_claim"]
    if claim != "NONE" and not doc["basis_refs"]:
        errors.append("positive effect claim requires evidence")
    if claim == "PREVENTION_OBSERVED" and not doc["control_boundary"]["complete_mediation"]:
        errors.append("prevention requires complete mediation")
    if claim in {"EFFECT_OBSERVED", "PREVENTION_OBSERVED"}:
        if doc["observer"]["health"] != "HEALTHY" or doc["evidence_channel"]["health"] != "HEALTHY":
            errors.append("effect claim requires healthy observer and evidence channel")
    return errors


def _enforcement_acknowledgement(doc: dict[str, Any]) -> list[str]:
    # The schema itself fixes the producer role to a receiver-side record.
    # An unhealthy evidence channel does not make the event impossible; it
    # limits the assurance that may later be derived from the record.
    return []


def _enforcement_result(doc: dict[str, Any]) -> list[str]:
    errors = []
    if doc["application_status"] == "APPLIED":
        if doc["acknowledgement_result"] != "ACCEPTED":
            errors.append("application cannot be APPLIED after a non-accepted acknowledgement")
        if doc["applied_disposition"] != doc["requested_disposition"]:
            errors.append("applied disposition does not match the requested disposition")
    elif doc["applied_disposition"] != "NONE":
        errors.append("non-applied enforcement result must use applied_disposition NONE")
    return errors


def _execution_observation(doc: dict[str, Any]) -> list[str]:
    errors = []
    if _dt(doc["completed_at"]) < _dt(doc["started_at"]):
        errors.append("execution completed before it started")
    if doc["status"] == "SUPPRESSED":
        if doc["applied_disposition"] not in {"DENY", "DEFER"}:
            errors.append("suppressed execution requires DENY or DEFER")
        if doc["transport_status"] != "NOT_ATTEMPTED":
            errors.append("suppressed execution cannot report a transport attempt")
    if doc["status"] in {"ATTEMPTED", "ACCEPTED"} and doc["applied_disposition"] != "ALLOW":
        errors.append("attempted or accepted execution requires applied ALLOW")
    return errors


def _effect_observation(doc: dict[str, Any]) -> list[str]:
    errors = []
    if _dt(doc["window_end"]) < _dt(doc["window_start"]):
        errors.append("effect observation window is negative")
    conclusive = doc["result"] in {"OBSERVED", "NOT_OBSERVED_WITHIN_BOUNDARY"}
    if conclusive:
        if doc["observer_health"] != "HEALTHY" or doc["evidence_channel"]["health"] != "HEALTHY":
            errors.append("conclusive effect result requires healthy observer and evidence channel")
        if not doc["source_of_truth_readback"] or "SOURCE_OF_TRUTH_READBACK" not in doc["basis_types"]:
            errors.append("conclusive effect result requires source-of-truth readback")
    if doc["result"] == "OBSERVED" and doc["post_state_digest"] != doc["expected_state_digest"]:
        errors.append("observed post-state does not match the expected state")
    if doc["result"] == "OBSERVED" and set(doc["basis_types"]) == {"TRANSPORT_RESPONSE"}:
        errors.append("transport response alone cannot establish an effect")
    return errors


def _verification_package(doc: dict[str, Any]) -> list[str]:
    errors = []
    artifact_ids = [item["artifact_id"] for item in doc["artifacts"]]
    artifact_types = {item["artifact_type"] for item in doc["artifacts"]}
    if _duplicates(artifact_ids):
        errors.append("duplicate artifact_id")
    missing = set(doc["required_artifact_types"]) - artifact_types
    if missing:
        errors.append("required artifact type omitted")
    dimensions = [item["dimension"] for item in doc["assurance_vector"]]
    if _duplicates(dimensions):
        errors.append("duplicate assurance dimension")
    for item in doc["assurance_vector"]:
        if item["state"] == "PASS" and not item["evidence_refs"]:
            errors.append("PASS dimension requires evidence")
        if set(item["evidence_refs"]) - set(artifact_ids):
            errors.append("assurance vector references unknown artifact")
    return errors


def _assurance_claim(doc: dict[str, Any]) -> list[str]:
    errors = []
    if _dt(doc["valid_from"]) >= _dt(doc["valid_until"]):
        errors.append("claim validity window is not positive")
    dimensions = doc["dimensions"]
    keys = [(item["dimension"], item["subject_id"]) for item in dimensions]
    if len(keys) != len(set(keys)):
        errors.append("duplicate dimension/subject")
    for item in dimensions:
        if item["state"] == "PASS" and not item["evidence_refs"]:
            errors.append("PASS dimension requires evidence")
    if doc["validation_state"] == "INDEPENDENTLY_VALIDATED":
        if not doc["separated_from_producer"] or doc["producer_id"] == doc["verifier_id"]:
            errors.append("independent validation lacks separation")
    reliance = doc["reliance"]
    states = {item["dimension"]: item["state"] for item in dimensions}
    if reliance["asserted"]:
        if not reliance["basis_dimensions"]:
            errors.append("asserted reliance requires basis dimensions")
        if any(states.get(name) != "PASS" for name in reliance["basis_dimensions"]):
            errors.append("reliance basis is not PASS")
        if "valid_until" not in reliance or _dt(reliance["valid_until"]) > _dt(doc["valid_until"]):
            errors.append("reliance outlives claim")
    return errors


def _coverage_declaration(doc: dict[str, Any]) -> list[str]:
    errors = []
    region_ids = [item["region_id"] for item in doc["regions"]]
    if _duplicates(region_ids):
        errors.append("duplicate region_id")
    if doc["baseline"]["source_class"] == "INDEPENDENT" and not doc["baseline"]["separated_from_evaluator"]:
        errors.append("independent baseline lacks separation")
    region_by_id = {item["region_id"]: item for item in doc["regions"]}
    negative = doc["negative_result"]
    unknown = {item["region_id"] for item in doc["regions"] if item["state"] in {"UNKNOWN", "UNTESTED"}}
    declared_unknown = set(negative["unknown_region_ids"])
    if declared_unknown - set(region_by_id):
        errors.append("negative result references unknown region")
    if negative["asserted"]:
        if negative["observer_health"] != "HEALTHY" or negative["evidence_channel_health"] != "HEALTHY":
            errors.append("negative result requires healthy observation paths")
        if declared_unknown != unknown:
            errors.append("negative result does not disclose the exact unknown region set")
    if doc["coverage_conclusion"] == "COMPLETE" and unknown:
        errors.append("complete coverage contains unknown or untested regions")
    return errors


# --- WP-CQ: contamination, quarantine, and re-establishment (ENAS spec §10.19, §4.40) ---

def _contamination_record(doc: dict[str, Any]) -> list[str]:
    errors = []
    if _dt(doc["latest_influence"]) < _dt(doc["earliest_influence"]):
        errors.append("contamination influence window is negative")
    # §10.19 L2185-2186: quarantine the ENTIRE unresolved region — the affected
    # artifacts AND the full dependency region, not the first detected artifact.
    affected = set(
        doc["affected_states"]
        + doc["affected_evidence"]
        + doc["affected_decisions"]
        + doc["affected_actions"]
        + doc["affected_claims"]
        + doc["dependency_graph"]["member_ids"]
    )
    quarantined = set(doc["quarantine_region"]["member_ids"])
    if affected - quarantined:
        errors.append("quarantine region is narrower than the affected and dependency region")
    return errors


def _re_establishment_record(doc: dict[str, Any]) -> list[str]:
    errors = []
    if not any(check["separated_from_producer"] for check in doc["independent_checks"]):
        errors.append("re-establishment requires a producer-independent check")
    if not doc["remeasurements"]:
        errors.append("re-establishment requires a remeasurement")
    if (
        doc["restoration_or_replacement_method"] == "TIME_EXPIRY"
        and not doc["changed_components"]
        and not doc["changed_credentials"]
    ):
        errors.append("time expiry alone is not removal without replacement or expiry proof")
    if any(change["new_status"] == "ACTIVE" for change in doc["claim_status_changes"]):
        errors.append("affected claim left ACTIVE pending revalidation")
    return errors


# --- WP-LV: recovery and bounded liveness (ENAS spec §11.1-11.7) ---

_RESPONSE_SEVERITY = {
    "RETRY": 1, "REPAIR": 1, "REMEASURE": 1,
    "ESCALATE": 2, "ROLLBACK": 2,
    "BLOCK": 3, "REJECT": 3, "TERMINAL_NON_SUCCESS": 3, "GLOBAL_PASS_PROHIBITED": 3,
}

# ENAS spec §11.1 L2202-2219 table: the acceptable responses are FIXED per failure class by
# the spec, not self-declared. Each entry is the exact set the table permits for that
# class (numeric severity alone is insufficient — RETRY and REPAIR share a severity
# but are not interchangeable). Per §11.1 L2221 the origin contract MAY select a
# STRICTER response; the only universally-valid stricter actions are escalation,
# halting, and prohibiting the global pass — modelled explicitly below.
_FAILURE_CLASS_ALLOWED = {
    "UNSUPPORTED_FORMAT_OR_VERSION": {"REJECT"},
    "INVALID_INTEGRITY": {"BLOCK"},
    "MISSING_INPUT": {"REPAIR"},
    "REQUIRED_MEASUREMENT_ABSENT": {"REMEASURE", "TERMINAL_NON_SUCCESS"},
    "TRANSIENT_FAILURE": {"RETRY", "ESCALATE"},
    "SEMANTIC_AMBIGUITY": {"REMEASURE", "ESCALATE"},
    "UNAUTHORIZED_SCOPE": {"REJECT"},
    "OBLIGATION_LOSS": {"REPAIR", "BLOCK"},
    "INVARIANT_VIOLATION": {"BLOCK", "ROLLBACK", "REPAIR"},
    "ENFORCEMENT_DELIVERY_FAILURE": {"BLOCK"},
    "INTERRUPTION_CHANNEL_UNAVAILABLE": {"BLOCK", "TERMINAL_NON_SUCCESS"},
    "STOP_ACK_CESSATION_UNPROVED": {"BLOCK"},
    "MATERIAL_RESIDUAL_UNACCOUNTED": {"ESCALATE"},
    "CONTAMINATED_DEPENDENCY": {"BLOCK", "REMEASURE"},
    "CLAIM_CONFIG_CHANGED": {"REMEASURE"},
    "REQUIRED_ARTIFACT_OMITTED": {"BLOCK", "REJECT"},
    "INCOMPLETE_TERMINAL_FULFILMENT": {"GLOBAL_PASS_PROHIBITED"},
    "BUDGET_EXHAUSTION": {"TERMINAL_NON_SUCCESS", "ESCALATE"},
    "DEADLOCK": {"TERMINAL_NON_SUCCESS", "ESCALATE"},
    "ORPHANED_OBLIGATION": {"GLOBAL_PASS_PROHIBITED"},
}
# Escalation / halting / prohibiting the global pass are valid stricter actions for
# any class (§11.1 L2221 "MAY select a stricter response"), so they are accepted on
# top of each class's table set — a corrective response from a different class is not.
_STRICTER_UNIVERSAL = {"ESCALATE", "BLOCK", "REJECT", "TERMINAL_NON_SUCCESS", "GLOBAL_PASS_PROHIBITED"}


def _retry_attempt(doc: dict[str, Any]) -> list[str]:
    if not any(doc["changed"].values()):
        return ["retry under materially identical conditions is not progress"]
    return []


def _liveness_budget(doc: dict[str, Any]) -> list[str]:
    # Exhaustion never resolves to implicit success: the schema enum already
    # excludes it; a budget with no bound is rejected by minProperties.
    return []


def _liveness_closure(doc: dict[str, Any]) -> list[str]:
    errors = []
    outcome = doc["terminal_outcome"]
    if doc["orphaned_obligation_present"] and outcome["kind"] == "SUCCESS":
        errors.append("orphaned obligation prohibits a global PASS")
    if outcome["recovery_class"] == "ROLLBACK" and not outcome["original_state_restored"]:
        errors.append("rollback claimed without restoring the original state (compensation is not rollback)")
    repair = doc["repair_revalidation"]
    if repair["repair_changed_dependency"] and not repair["affected_evidence_revalidated"]:
        errors.append("repair changed a dependency without revalidating affected evidence")
    detection = doc["deadlock_orphan_detection"]
    if detection["conformance_level"] in {"CHAIN", "SYSTEM"} and not detection["performed"] and not detection["detection_bound"]:
        errors.append("deadlock/orphan detection neither performed nor bounded at chain-or-higher conformance")
    # §11.6 L2270-2279: a detected condition cannot coexist with a global PASS, and
    # an ownerless obligation is an orphaned obligation.
    conditions = detection["conditions"]
    if any(state == "PRESENT" for state in conditions.values()) and outcome["kind"] == "SUCCESS":
        errors.append("a detected deadlock/orphan condition is present but the terminal outcome is SUCCESS")
    if conditions["ownerless_obligations"] == "PRESENT" and not doc["orphaned_obligation_present"]:
        errors.append("an ownerless obligation is present but orphaned_obligation_present is false")
    return errors


def _fairness_declaration(doc: dict[str, Any]) -> list[str]:
    if doc["applicable"] and doc["status"] == "NOT_MEASURED" and not doc["disclosed_in_closure"]:
        return ["applicable-but-unmeasured fairness property silently omitted from closure"]
    return []


def _failure_class_response(doc: dict[str, Any]) -> list[str]:
    errors = []
    table = _FAILURE_CLASS_ALLOWED[doc["failure_class"]]
    # The class's own minimum severity is a hard floor: a "universal stricter" action
    # only counts when it is at least as strong as the class minimum (ESCALATE is not
    # stronger than BLOCK, so it cannot stand in for a class whose minimum is BLOCK).
    floor = min(_RESPONSE_SEVERITY[response] for response in table)

    def acceptable(response: str) -> bool:
        if response in table:
            return True
        return response in _STRICTER_UNIVERSAL and _RESPONSE_SEVERITY[response] >= floor

    if not acceptable(doc["required_minimum_response"]):
        errors.append("declared required minimum understates or mismatches the class's §11.1 response")
    if not acceptable(doc["selected_response"]):
        errors.append("selected response understates or mismatches the class's §11.1 response")
    if _RESPONSE_SEVERITY[doc["selected_response"]] < _RESPONSE_SEVERITY[doc["required_minimum_response"]]:
        errors.append("selected response is weaker than the declared required minimum")
    check = doc["axiom_violation_check"]
    if not check["performed"]:
        errors.append("axiom-violation check was not performed")
    if check["violation_found"]:
        errors.append("selected response violates an axiom")
    return errors


# --- WP-DR: disclosure, retention, and claim lifecycle (ENAS spec §4.44, §13.4, §10.6, §4.45) ---

def _disclosure_manifest(doc: dict[str, Any]) -> list[str]:
    errors = []
    disposed = {"REDACTED", "COMMITTED_WITHHELD", "DESTROYED_BY_POLICY", "UNAVAILABLE"}
    if any(a["disposition"] in disposed for a in doc["artifacts"]) and not doc["withheld_dimensions"]:
        errors.append("withheld or unavailable artifact not reflected in withheld_dimensions")
    if doc["selective_disclosure_proof"]["implies_no_uncommitted"]:
        errors.append("selective-disclosure proof must not imply no uncommitted artifact exists")
    evented = {ref["artifact_id"] for ref in doc["disposition_event_refs"]}
    for artifact in doc["artifacts"]:
        if artifact["disposition"] in {"REDACTED", "DESTROYED_BY_POLICY"} and artifact["artifact_id"] not in evented:
            errors.append("artifact disposition performed without a disposition event")
    if doc["claim_validation_state"] == "INDEPENDENTLY_CONFIRMED" and (
        doc["producer_id"] == doc["verifier_id"] or not doc["separated_from_producer"]
    ):
        errors.append("producer assertion presented as independent confirmation")
    return errors


def _retention_policy_binding(doc: dict[str, Any]) -> list[str]:
    errors = []
    observed = doc["observed_retention"]
    if not observed["matches_policy"] and observed["relied_on_by_claim"]:
        errors.append("evidence retained contrary to the declared policy supports a claim")
    # §13.4 L2401-2402: no indefinite-by-default. Indefinite retention is admissible
    # only with an explicit lawful basis; append-only provenance is not such a basis.
    rule = doc["retention_or_expiry_rule"]
    if rule["kind"] == "INDEFINITE" and rule["basis"] != "EXPLICIT_LAWFUL_INDEFINITE":
        errors.append("indefinite retention without an explicit lawful basis (append-only is not a basis)")
    return errors


def _disposition_event(doc: dict[str, Any]) -> list[str]:
    if doc["action"] == "DESTRUCTION" and doc["replayability"] != "NOT_REPLAYABLE":
        return ["destroyed evidence cannot be reported as replayable"]
    return []


_REQUIRED_LIFECYCLE_TYPES = {
    "ACTION_ATTEMPT", "DECISION", "ENFORCEMENT_INSTRUCTION", "ENFORCEMENT_ACKNOWLEDGEMENT",
    "ENFORCEMENT_RESULT", "EXECUTION", "EFFECT_OBSERVATION", "EVIDENCE_CHANNEL_HEALTH",
}


def _lifecycle_record_manifest(doc: dict[str, Any]) -> list[str]:
    errors = []
    present = {record["record_type"] for record in doc["records"]}
    # §10.6 L1932-1945: all eight typed records are required and must stay distinct.
    # The required set is fixed by the spec, not self-declared by the producer.
    if _REQUIRED_LIFECYCLE_TYPES - set(doc["required_record_types"]):
        errors.append("declared required set omits a spec-mandated lifecycle record type")
    if _REQUIRED_LIFECYCLE_TYPES - present:
        errors.append("a spec-mandated lifecycle record type is absent")
    if any(not record["semantically_distinct"] for record in doc["records"]):
        errors.append("typed lifecycle records collapsed into an undifferentiated status")
    return errors


# --- WP-SR: stop and residual closure (ENAS spec §10.16-10.18, §4.38-4.39, §11.1) ---

# §10.16 L2140-2142 + §11.1 L2213: evidence of one stage MUST NOT establish a later
# stage. Each interruption_event records ONE stage; the strongest `result` it may
# claim is bounded by that stage. Proven cessation needs an independent observation
# (CESSATION_OBSERVED); closure needs authorized resumption.
_STAGE_ALLOWED_RESULTS = {
    "STOP_AUTHORIZED": {"STAGE_RECORDED"},
    "STOP_ISSUED": {"STAGE_RECORDED"},
    "STOP_ACKNOWLEDGED": {"STAGE_RECORDED"},
    "CESSATION_APPLIED": {"STAGE_RECORDED"},
    "CESSATION_OBSERVED": {"STAGE_RECORDED", "CESSATION_PROVEN"},
    "RESIDUAL_EFFECTS_ACCOUNTED": {"STAGE_RECORDED", "RESIDUALS_ACCOUNTED"},
    "RESUMPTION_AUTHORIZED": {"STAGE_RECORDED", "CLOSURE_COMPLETE"},
}


def _interruption_event(doc: dict[str, Any]) -> list[str]:
    errors = []
    stage = doc["stage"]
    result = doc["result"]
    if result not in _STAGE_ALLOWED_RESULTS[stage]:
        errors.append(f"result '{result}' exceeds what stage '{stage}' establishes")
    # An assurance-positive result cannot rest on an unhealthy/unmeasured evidence channel.
    if result in {"CESSATION_PROVEN", "RESIDUALS_ACCOUNTED", "CLOSURE_COMPLETE"} and doc["evidence_channel_health"] != "HEALTHY":
        errors.append(f"result '{result}' requires a HEALTHY evidence channel")
    # A proof/closure result must be backed by the stage's own evidence, not merely
    # asserted at a stage that could carry it (§10.16 L2136 observation; §10.17 resumption health).
    if stage == "CESSATION_OBSERVED" and result == "CESSATION_PROVEN" and doc["observation"]["observer_result"] != "CONFIRMED":
        errors.append("CESSATION_PROVEN requires a CONFIRMED independent observation")
    if stage == "RESUMPTION_AUTHORIZED" and result == "CLOSURE_COMPLETE" and (
        doc["resumption"]["control_health"] != "HEALTHY" or doc["resumption"]["evidence_health"] != "HEALTHY"
    ):
        errors.append("CLOSURE_COMPLETE requires healthy control and evidence paths at resumption")
    if stage == "RESIDUAL_EFFECTS_ACCOUNTED" and result == "RESIDUALS_ACCOUNTED":
        for item in doc["residual_accounting"]["items"]:
            if not item["classified"] or item["disposition"] == "UNRESOLVED":
                errors.append("residual effect listed but not classified and dispositioned")
                break
    witness = doc["independent_witness"]
    if witness["assurance_level"] == "HIGH" and (witness["sole_enforcement_path"] or witness["sole_witness"]):
        errors.append("high-assurance interruption relies on the candidate's own sole enforcement path or witness")
    return errors


def _oversight_loss_event(doc: dict[str, Any]) -> list[str]:
    errors = []
    if doc["crossed_tolerance"]:
        # §10.17 L2153-2156: crossing tolerance MUST prevent new high-risk
        # actualization; autonomy MUST NOT be the default response.
        if doc["action_taken"] == "CONTINUED_AUTONOMOUS":
            errors.append("oversight tolerance crossed but autonomous operation continued as the default")
        if not doc["new_high_risk_prevented"]:
            errors.append("oversight tolerance crossed without preventing new high-risk actualization")
    return errors


def _residual_capability_disposition(doc: dict[str, Any]) -> list[str]:
    errors = []
    if doc["current_state"] in {"REMOVED", "REVOKED"} and doc["verification_method"] == "HOLDER_SELF_DECLARATION":
        errors.append("holder self-declaration cannot establish REMOVED or REVOKED")
    if doc["current_state"] == "UNACCOUNTED" and doc["closure_claimed_complete"]:
        errors.append("material residual capability UNACCOUNTED while closure claims complete")
    return errors


# --- WP-CC: claim configuration and coverage (ENAS spec §4.34-4.47, P34-P47) ---

def _claim_configuration(doc: dict[str, Any]) -> list[str]:
    # §4.34 / P36: a product name or mutable version label is NOT a configuration identity.
    if doc["identity_basis"] != "CONTENT_ADDRESSED":
        return ["a product name or mutable version label is not a configuration identity"]
    return []


def _nondeterminism_record(doc: dict[str, Any]) -> list[str]:
    errors = []
    if not doc["run_design"]["declared_before_evaluation"] and doc["supports_unqualified_claim"]:
        errors.append("a post-hoc run design cannot support an unqualified assurance claim")
    if doc["reproduction_class"] == "PROBABILISTIC_REDISCOVERY" and doc["claimed_as"] == "DETERMINISTIC":
        errors.append("probabilistic rediscovery must remain distinct from deterministic reproduction")
    if doc["reproduction_class"] == "PROBABILISTIC_REDISCOVERY" and (
        not (doc["stochastic_inputs"] or doc["uncontrolled_dependencies"]) or not doc["variance_sources"]
    ):
        errors.append("probabilistic rediscovery must name a nondeterminism source and expose material variance")
    return errors


def _reliance_claim(doc: dict[str, Any]) -> list[str]:
    errors = []
    if _dt(doc["validity"]["until"]) <= _dt(doc["validity"]["from"]):
        errors.append("reliance validity window is not positive")
    if doc["inherits_without_acceptance"]:
        errors.append("technical assurance must not silently inherit legal/acceptance/substitution meaning")
    if doc["asserted_meaning"] != "TECHNICAL_ASSURANCE" and not doc["external_acceptance_dependencies"]:
        errors.append("a non-technical reliance meaning requires declared external acceptance dependencies")
    return errors


def _observed_operating_path(doc: dict[str, Any]) -> list[str]:
    errors = []
    if doc["declared_capability_only"]:
        errors.append("declared capability is not evidence of the path actually taken")
    if any(event["material"] and not event["disclosed"] for event in doc["assistance_events"]):
        errors.append("undisclosed material assistance invalidates the autonomy/independence/verification dimensions")
    # §P35: the aggregate assurance class IS the weakest link — the claimed class MUST EQUAL the
    # least-assured segment. Derived from the ordered per-segment classes; there is no "claim
    # higher" escape hatch (a composition rule raising assurance above the weakest segment would be
    # exactly the self-attested uplift ENAS forbids). NOTE: the per-segment labels themselves are
    # producer-attested; verifying their truthfulness is a bundle-reconciliation concern, not
    # something a single-record checker can establish.
    order = {"OBSERVED": 0, "PRODUCER_VALIDATED": 1, "INDEPENDENTLY_CONFIRMED": 2, "RETESTED": 3}
    least = min(order[segment["assurance_class"]] for segment in doc["segments"])
    if order[doc["classification"]["claimed_assurance_class"]] != least:
        errors.append("the claimed assurance class must equal the least-assured segment (the aggregate is the weakest link)")
    return errors


def _claim_coverage_registry(doc: dict[str, Any]) -> list[str]:
    errors = []
    if doc["config_identity_basis"] != "CONTENT_ADDRESSED":
        errors.append("a claim must be bound to a content-addressed configuration, not a product name or mutable version")
    change = doc["config_change"]
    # §P36: a material change may keep a claim ACTIVE ONLY with an explicit carry-forward
    # justification; NONE / INVALIDATED / SUSPENDED with an ACTIVE claim is automatic inheritance.
    if change["material_change_occurred"] and doc["claim_status"] == "ACTIVE" and change["disposition"] != "CARRY_FORWARD_JUSTIFIED":
        errors.append("a material configuration change requires an explicit carry-forward justification to keep a claim ACTIVE (no automatic inheritance)")
    # §P36: the carry-forward itself must be substantiated (rule/unchanged-properties/evidence),
    # not self-certified by the enum value alone.
    if change["disposition"] == "CARRY_FORWARD_JUSTIFIED" and "carry_forward" not in change:
        errors.append("a carry-forward justification requires structured evidence (rule, unchanged properties, evidence refs)")
    # §P42: a non-current lifecycle state must be machine-resolvable to its supporting event/reference.
    lifecycle = doc.get("lifecycle", {})
    status = doc["claim_status"]
    if status == "REVOKED" and "revocation_ref" not in lifecycle:
        errors.append("a REVOKED claim requires a resolvable revocation reference")
    if status == "SUPERSEDED" and "successor_claim_ref" not in lifecycle:
        errors.append("a SUPERSEDED claim requires a resolvable successor claim reference")
    if status == "UNDER_REVIEW" and "review_ref" not in lifecycle:
        errors.append("an UNDER_REVIEW claim requires a resolvable review reference")
    return errors


def _origin_contract(doc: dict[str, Any]) -> list[str]:
    # §7.2/P5: obligation identity MUST be stable and unique — a duplicated obligation_id
    # destroys the lineage that conservation (A3) depends on.
    errors = []
    ids = [ob["obligation_id"] for ob in doc["obligations"]]
    if _duplicates(ids):
        errors.append("obligation_id values must be unique within an origin contract")
    # §8.4/A3: a TRANSFORMED obligation exists only through explicit predecessor->successor
    # lineage; without a successor_ref its meaning has silently disappeared from accounting.
    for ob in doc["obligations"]:
        if ob["lifecycle_state"] == "TRANSFORMED" and "successor_ref" not in ob:
            errors.append("a TRANSFORMED obligation requires an explicit successor_ref (predecessor-successor lineage)")
    return errors


def _obligation_handoff(doc: dict[str, Any]) -> list[str]:
    # §8.5: an OBSERVE receiver may inspect or propose but cannot discharge; ambiguous or
    # non-discharging delegation MUST NOT transfer discharge authority.
    errors = []
    delta = doc["semantic_delta"]
    # §4.9/A3: the delta accounts for the obligations actually handed off — every disposition
    # except newly created work must name an id present in obligation_ids, or the record is
    # discharging/transforming an obligation it never received.
    handed = set(doc["obligation_ids"])
    for key in ("preserved", "delegated", "discharged", "transformed", "revoked", "unresolved"):
        if any(oid not in handed for oid in delta[key]):
            errors.append(f"semantic_delta.{key} names an obligation absent from obligation_ids")
    # §8.4: an obligation cannot land in two incompatible terminal categories of one handoff.
    terminal = [oid for key in ("discharged", "transformed", "revoked", "unresolved") for oid in delta[key]]
    if _duplicates(terminal):
        errors.append("an obligation appears in more than one terminal disposition of the handoff")
    if doc["assignment_mode"] == "OBSERVE" and delta["discharged"]:
        errors.append("an OBSERVE handoff cannot discharge an obligation")
    # §4.8: sending is not fulfilment — a FULFILLED handoff must actually account for a
    # discharge (or a valid transformation/revocation), not merely assert the terminal label.
    if doc["acceptance_state"] == "FULFILLED" and not (delta["discharged"] or delta["transformed"] or delta["revoked"]):
        errors.append("a FULFILLED handoff must account for a discharged, transformed, or revoked obligation")
    # §4.8: a REJECTED handoff transferred nothing — it cannot have discharged or created work.
    if doc["acceptance_state"] == "REJECTED" and (delta["discharged"] or delta["created"]):
        errors.append("a REJECTED handoff cannot discharge or create obligations")
    return errors


def _transformation_record(doc: dict[str, Any]) -> list[str]:
    # §8.10: NOT_MEASURED and INVALID transformations cannot discharge a predecessor obligation.
    errors = []
    cls = doc["transformation_class"]
    if cls in {"NOT_MEASURED", "INVALID"} and doc["discharges_predecessor"]:
        errors.append("a NOT_MEASURED or INVALID transformation cannot discharge its predecessor obligation")
    # §8.10: an AUTHORIZED_VARIATION needs an authorizing principal AND successor obligations;
    # human approval authorizes a variation, it does not by itself demonstrate equivalence.
    if cls == "AUTHORIZED_VARIATION" and ("authorization" not in doc or not doc["successor_obligations"]):
        errors.append("an AUTHORIZED_VARIATION requires an authorizing principal and explicit successor obligations")
    # §8.10/P7: a SEMANTIC_BOUNDED transformation must expose its loss as a vector over named
    # properties; an absent loss vector means bounded loss was never established.
    if cls == "SEMANTIC_BOUNDED" and not doc["loss_vector"]:
        errors.append("a SEMANTIC_BOUNDED transformation must expose an explicit loss vector")
    # §8.10: an EXACT_REPRESENTATION claiming discharge cannot also declare a LOST property —
    # a bijective method that lost a property is not exact.
    if cls == "EXACT_REPRESENTATION" and any(item["status"] == "LOST" for item in doc["loss_vector"]):
        errors.append("an EXACT_REPRESENTATION cannot declare a LOST property")
    # §8.4/A3: a preserving transformation, or any transformation that discharges its
    # predecessor, replaces the obligation's active representation — it MUST name at least one
    # successor obligation, or the obligation has silently vanished inside the record.
    if (cls in {"EXACT_REPRESENTATION", "STRUCTURAL_EQUIVALENCE", "SEMANTIC_BOUNDED"} or doc["discharges_predecessor"]) and not doc["successor_obligations"]:
        errors.append("a preserving or discharging transformation must name at least one successor obligation")
    return errors


def _fork_join_record(doc: dict[str, Any]) -> list[str]:
    # §8.7: a JOIN phase must carry the join authority's evaluation.
    errors = []
    if doc["phase"] == "JOIN" and "join" not in doc:
        errors.append("a JOIN record requires the join authority's evaluation")
        return errors
    if doc["phase"] == "JOIN":
        join = doc["join"]
        # §8.6/§8.7: the parent obligation cannot be closed while coverage is incomplete,
        # conflicts are unresolved, or an invariant is not preserved across the merged state.
        if join["parent_closed"] and not (join["coverage_complete"] and join["conflicts_resolved"] and join["invariants_preserved"]):
            errors.append("a JOIN cannot close the parent obligation without complete coverage, resolved conflicts, and preserved invariants")
        # §8.7: last-writer-wins is not a normative conflict rule unless the origin contract
        # explicitly authorizes it for the affected obligation.
        if join["conflict_rule"] == "LAST_WRITER_WINS" and not join["last_writer_wins_authorized"]:
            errors.append("last-writer-wins conflict resolution requires explicit origin-contract authorization")
    return errors


def _conservation_accounting(doc: dict[str, Any]) -> list[str]:
    # §8.4: the identity-preserving partition
    #   O_before (+) O_created = O_after (+) O_discharged (+) O_transformed (+) O_revoked (+) O_failed (+) O_unresolved
    # An obligation present in none, or in more than one incompatible terminal category, means
    # conservation has NOT been established.
    errors = []
    lhs = list(doc["before"]) + list(doc["created"])
    transformed_ids = [item["obligation_id"] for item in doc["transformed"]]
    rhs = (
        list(doc["after"])
        + list(doc["discharged"])
        + transformed_ids
        + list(doc["revoked"])
        + list(doc["failed"])
        + list(doc["unresolved"])
    )
    if _duplicates(lhs):
        errors.append("an obligation appears more than once on the entering side of the transition")
    if _duplicates(rhs):
        errors.append("an obligation appears in more than one terminal or after category")
    if sorted(lhs) != sorted(rhs):
        errors.append("the conservation invariant is violated: the entering and resulting obligation sets differ")
    # §8.4: an O_transformed entry is valid only when its successor is present in O_created or
    # O_after and carries explicit lineage.
    successor_pool = set(doc["created"]) | set(doc["after"])
    for item in doc["transformed"]:
        if item["successor_ref"] not in successor_pool:
            errors.append("a transformed obligation's successor must be present in the created or after set")
    # A3/A7: global PASS is prohibited while any obligation is terminally failed or unresolved.
    if doc["global_pass_claimed"] and (doc["failed"] or doc["unresolved"]):
        errors.append("global PASS is prohibited while an obligation remains failed or unresolved")
    return errors


def _amendment_revocation_event(doc: dict[str, Any]) -> list[str]:
    # §8.8: an amendment MUST NOT retroactively authorize an action that was unauthorized when
    # performed — the historical authorization failure must remain visible.
    errors = []
    if doc["retroactive_authorization"]:
        errors.append("an amendment or revocation cannot retroactively authorize a previously unauthorized action")
    # §8.8: revocation MUST propagate to reachable branches; a branch whose revocation status
    # cannot be established MUST NOT continue a now-questionable actualization.
    if doc["event_type"] == "REVOCATION" and doc["in_flight_disposition"] == "CONTINUE" and not doc.get("revocation_reachable", False):
        errors.append("a revocation with unestablished branch reachability cannot let in-flight work CONTINUE")
    return errors


def _closure_accounting(doc: dict[str, Any]) -> list[str]:
    # §4.14/A7: closure is not success. A global PASS or SUCCEEDED terminal outcome is sound only
    # when every obligation is discharged or validly revoked, no obligation is failed or
    # unresolved, invariants are revalidated, and required enforcement is confirmed.
    errors = []
    # §4.14/A7: closure accounts for EACH obligation exactly once — a duplicated obligation_id
    # (e.g. one both DISCHARGED and FAILED) is not a coherent terminal accounting.
    oids = [item["obligation_id"] for item in doc["obligation_dispositions"]]
    if _duplicates(oids):
        errors.append("an obligation appears in more than one closure disposition")
    dispositions = {item["disposition"] for item in doc["obligation_dispositions"]}
    claims_success = doc["terminal_outcome"] == "SUCCEEDED" or doc["global_verdict"] == "PASS"
    if claims_success and ({"FAILED", "UNRESOLVED"} & dispositions):
        errors.append("a SUCCEEDED/PASS closure cannot contain a failed or unresolved obligation")
    if claims_success and not (doc["invariants_revalidated"] and doc["enforcement_confirmed"]):
        errors.append("a SUCCEEDED/PASS closure requires revalidated invariants and confirmed enforcement")
    # A7: a global PASS is issued against the whole contract; it must agree with a SUCCEEDED
    # terminal outcome rather than being promoted beside a non-success outcome.
    if doc["global_verdict"] == "PASS" and doc["terminal_outcome"] != "SUCCEEDED":
        errors.append("a global PASS must coincide with a SUCCEEDED terminal outcome")
    return errors


SEMANTIC: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "decision_input_manifest": _decision_input_manifest,
    "evidence_use": _evidence_use,
    "execution_link": _execution_link,
    "effect_assurance": _effect_assurance,
    "verification_package": _verification_package,
    "assurance_claim": _assurance_claim,
    "coverage_declaration": _coverage_declaration,
    "enforcement_acknowledgement": _enforcement_acknowledgement,
    "enforcement_result": _enforcement_result,
    "execution_observation": _execution_observation,
    "effect_observation": _effect_observation,
    "contamination_record": _contamination_record,
    "re_establishment_record": _re_establishment_record,
    "retry_attempt": _retry_attempt,
    "liveness_budget": _liveness_budget,
    "liveness_closure": _liveness_closure,
    "fairness_declaration": _fairness_declaration,
    "failure_class_response": _failure_class_response,
    "disclosure_manifest": _disclosure_manifest,
    "retention_policy_binding": _retention_policy_binding,
    "disposition_event": _disposition_event,
    "lifecycle_record_manifest": _lifecycle_record_manifest,
    "interruption_event": _interruption_event,
    "oversight_loss_event": _oversight_loss_event,
    "residual_capability_disposition": _residual_capability_disposition,
    "claim_configuration": _claim_configuration,
    "nondeterminism_record": _nondeterminism_record,
    "reliance_claim": _reliance_claim,
    "observed_operating_path": _observed_operating_path,
    "claim_coverage_registry": _claim_coverage_registry,
    "origin_contract": _origin_contract,
    "obligation_handoff": _obligation_handoff,
    "transformation_record": _transformation_record,
    "fork_join_record": _fork_join_record,
    "conservation_accounting": _conservation_accounting,
    "amendment_revocation_event": _amendment_revocation_event,
    "closure_accounting": _closure_accounting,
}


def validate_document(profile: str, document: dict[str, Any]) -> list[str]:
    schema = json.loads(SCHEMAS[profile].read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [error.message for error in validator.iter_errors(document)]
    if not errors:
        errors.extend(SEMANTIC[profile](document))
    return errors


def _canonical_digest(document: dict[str, Any]) -> str:
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_issuer_bundle(bundle: dict[str, Any]) -> list[str]:
    """Validate the bounded T4 issuer graph before a receiver relies on it."""
    if not isinstance(bundle, dict):
        return ["issuer bundle is not an object"]
    errors: list[str] = []
    if bundle.get("boundary") != "T4_PRE_TOOL_USE_ISSUER":
        errors.append("issuer bundle has an unsupported boundary")
    if bundle.get("disposition") not in {"ALLOW", "DENY"}:
        errors.append("issuer bundle has an unsupported disposition")
    records = bundle.get("records")
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        return [*errors, "issuer bundle records must be an object array"]

    allowed = {"decision_input_manifest", "evidence_use", "execution_link"}
    for record in records:
        profile = record.get("profile_type")
        if profile not in allowed:
            errors.append("issuer bundle contains an unsupported record type")
        else:
            errors.extend(
                f"{profile}: {message}" for message in validate_document(profile, record)
            )

    manifests = [record for record in records if record.get("profile_type") == "decision_input_manifest"]
    links = [record for record in records if record.get("profile_type") == "execution_link"]
    uses = [record for record in records if record.get("profile_type") == "evidence_use"]
    if len(manifests) != 1:
        errors.append("issuer bundle requires exactly one decision-input manifest")
        return errors
    manifest = manifests[0]
    relation_counts = {
        relation: sum(link.get("relation") == relation for link in links)
        for relation in ("ACTION_TO_DECISION", "DECISION_TO_INSTRUCTION")
    }
    if len(links) != 2:
        errors.append("issuer bundle requires exactly two typed links")
    for relation, count in relation_counts.items():
        if count != 1:
            errors.append(f"issuer bundle requires exactly one {relation} link")
    if any(count != 1 for count in relation_counts.values()):
        return errors

    trace_id = manifest.get("trace_id")
    attempt_id = manifest.get("action_attempt_id")
    decision_id = manifest.get("decision_id")
    action_link = next(link for link in links if link.get("relation") == "ACTION_TO_DECISION")
    instruction_link = next(link for link in links if link.get("relation") == "DECISION_TO_INSTRUCTION")
    for link in links:
        if (
            link.get("trace_id") != trace_id
            or link.get("action_attempt_id") != attempt_id
            or link.get("source_attempt_id") != attempt_id
            or link.get("target_attempt_id") != attempt_id
        ):
            errors.append("issuer link crosses manifest identity")
    action_target = _as_dict(action_link.get("target"))
    instruction_source = _as_dict(instruction_link.get("source"))
    if action_target.get("id") != decision_id:
        errors.append("issuer action link does not target the manifest decision")
    if instruction_source.get("id") != decision_id:
        errors.append("issuer instruction link does not originate from the manifest decision")
    if action_target.get("digest") != instruction_source.get("digest"):
        errors.append("issuer decision digest differs across typed links")

    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        return [*errors, "issuer manifest has no inputs"]
    input_by_id = {
        item.get("input_id"): item for item in inputs if isinstance(item, dict)
    }
    if len(input_by_id) != len(inputs) or None in input_by_id:
        errors.append("issuer manifest has duplicate or invalid input identifiers")
    action_input = input_by_id.get("action-commitment")
    if action_input is None or _as_dict(action_link.get("source")).get("digest") != action_input.get("digest"):
        errors.append("issuer action commitment does not match the action link")
    if len(uses) != len(inputs):
        errors.append("issuer bundle requires one evidence-use event per input")
    observed_use_ids: set[str] = set()
    for use in uses:
        evidence_id = use.get("evidence_id")
        source = input_by_id.get(evidence_id)
        if source is None or evidence_id in observed_use_ids:
            errors.append("issuer evidence-use event is duplicate or references an unknown input")
            continue
        observed_use_ids.add(evidence_id)
        if (
            use.get("trace_id") != trace_id
            or use.get("action_attempt_id") != attempt_id
            or use.get("decision_id") != decision_id
            or use.get("manifest_id") != manifest.get("manifest_id")
            or use.get("evidence_digest") != source.get("digest")
            or use.get("relation") != "USED_MATERIAL"
        ):
            errors.append("issuer evidence-use event does not reconcile with the manifest")
    return errors


def validate_lifecycle_bundle(bundle: dict[str, Any]) -> list[str]:
    """Validate record content and the receiver-to-effect typed graph.

    This validator is intentionally bounded to one action attempt. It verifies
    the record digests carried by each edge and refuses shared-trace-only or
    cross-attempt joins. It does not establish that a producer ran at the named
    deployment boundary.
    """
    if not isinstance(bundle, dict):
        return ["lifecycle bundle is not an object"]
    errors: list[str] = []
    records = bundle.get("records")
    links = bundle.get("links")
    instruction = bundle.get("instruction")
    if not isinstance(records, list) or not isinstance(links, list) or not isinstance(instruction, dict):
        return ["lifecycle bundle requires instruction, records, and links"]

    id_fields = {
        "enforcement_acknowledgement": ("ACKNOWLEDGEMENT", "enforcement_ack_id"),
        "enforcement_result": ("APPLICATION", "enforcement_result_id"),
        "execution_observation": ("EXECUTION", "execution_id"),
        "effect_observation": ("EFFECT", "effect_observation_id"),
    }
    expected_profiles = set(id_fields)
    profile_counts = {
        profile: sum(record.get("profile_type") == profile for record in records if isinstance(record, dict))
        for profile in expected_profiles
    }
    for profile, count in profile_counts.items():
        if count != 1:
            errors.append(f"lifecycle requires exactly one {profile} record")
    if len(records) != len(expected_profiles):
        errors.append("lifecycle contains duplicate or unsupported records")

    nodes: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    attempt_id = bundle.get("action_attempt_id")
    trace_id = bundle.get("trace_id")
    decision_id = bundle.get("decision_id")
    for record in records:
        profile = record.get("profile_type") if isinstance(record, dict) else None
        if profile not in id_fields:
            errors.append("unsupported lifecycle record type")
            continue
        profile_errors = validate_document(profile, record)
        errors.extend(f"{profile}: {message}" for message in profile_errors)
        if record.get("action_attempt_id") != attempt_id:
            errors.append("lifecycle record crosses action attempts")
        if record.get("trace_id") != trace_id or record.get("decision_id") != decision_id:
            errors.append("lifecycle record crosses trace or decision identity")
        node_type, id_field = id_fields[profile]
        record_id = record.get(id_field)
        if record_id is None:
            errors.append(f"lifecycle {profile} record is missing its {id_field}")
            continue
        nodes[(node_type, record_id)] = (_canonical_digest(record), record)

    instruction_key = ("INSTRUCTION", instruction.get("id"))
    nodes[instruction_key] = (instruction.get("digest"), instruction)
    if not all(isinstance(link, dict) for link in links):
        errors.append("lifecycle links must all be objects")
    expected_relations = {
        "INSTRUCTION_TO_ACKNOWLEDGEMENT",
        "ACKNOWLEDGEMENT_TO_APPLICATION",
        "APPLICATION_TO_EXECUTION",
        "EXECUTION_TO_EFFECT",
    }
    if len(links) != len(expected_relations):
        errors.append("lifecycle requires exactly four typed links")
    relation_counts = {
        relation: sum(link.get("relation") == relation for link in links if isinstance(link, dict))
        for relation in expected_relations
    }
    for relation, count in relation_counts.items():
        if count != 1:
            errors.append(f"lifecycle requires exactly one {relation} link")

    observed_relations: set[str] = set()
    for link in links:
        if not isinstance(link, dict):
            errors.append("lifecycle link is not an object")
            continue
        link_errors = validate_document("execution_link", link)
        errors.extend(f"execution_link: {message}" for message in link_errors)
        if link.get("action_attempt_id") != attempt_id or link.get("trace_id") != trace_id:
            errors.append("execution link crosses bundle identity")
        relation = link.get("relation")
        observed_relations.add(relation)
        for endpoint in ("source", "target"):
            node = _as_dict(link.get(endpoint))
            known = nodes.get((node.get("type"), node.get("id")))
            if known is None:
                errors.append(f"execution link references unknown {endpoint} node")
            elif node.get("digest") != known[0]:
                errors.append(f"execution link {endpoint} digest mismatch")
    missing = expected_relations - observed_relations
    if missing:
        errors.append("lifecycle graph is missing required relations")

    if all(count == 1 for count in profile_counts.values()):
        by_profile = {
            profile: next(
                record for record in records
                if isinstance(record, dict) and record.get("profile_type") == profile
            )
            for profile in expected_profiles
        }
        ack = by_profile["enforcement_acknowledgement"]
        application = by_profile["enforcement_result"]
        execution = by_profile["execution_observation"]
        effect = by_profile["effect_observation"]
        ack_digest = _canonical_digest(ack)
        application_digest = _canonical_digest(application)
        execution_digest = _canonical_digest(execution)
        if ack.get("instruction_id") != instruction.get("id") or ack.get("instruction_digest") != instruction.get("digest"):
            errors.append("acknowledgement does not bind the lifecycle instruction")
        if application.get("instruction_id") != instruction.get("id") or application.get("instruction_digest") != instruction.get("digest"):
            errors.append("application does not bind the lifecycle instruction")
        if application.get("enforcement_ack_id") != ack.get("enforcement_ack_id") or application.get("acknowledgement_digest") != ack_digest:
            errors.append("application does not bind the acknowledgement record")
        if execution.get("enforcement_result_id") != application.get("enforcement_result_id") or execution.get("enforcement_result_digest") != application_digest:
            errors.append("execution does not bind the application record")
        if effect.get("execution_id") != execution.get("execution_id") or effect.get("execution_digest") != execution_digest:
            errors.append("effect does not bind the execution record")
        try:
            if _dt(application["observed_at"]) < _dt(ack["observed_at"]):
                errors.append("application predates acknowledgement")
        except (KeyError, TypeError, ValueError, AttributeError):
            errors.append("lifecycle contains an invalid cross-record timestamp")
    return errors


def validate_issuer_lifecycle_pair(
    issuer_bundle: dict[str, Any], lifecycle_bundle: dict[str, Any]
) -> list[str]:
    """Validate exact issuer-to-receiver identity without claiming deployment truth."""
    errors = [f"issuer: {message}" for message in validate_issuer_bundle(issuer_bundle)]
    errors.extend(
        f"lifecycle: {message}" for message in validate_lifecycle_bundle(lifecycle_bundle)
    )
    if not isinstance(issuer_bundle, dict) or not isinstance(lifecycle_bundle, dict):
        return errors
    records = issuer_bundle.get("records")
    if not isinstance(records, list):
        return errors
    manifests = [
        record for record in records
        if isinstance(record, dict) and record.get("profile_type") == "decision_input_manifest"
    ]
    instruction_links = [
        record
        for record in records
        if isinstance(record, dict)
        and record.get("profile_type") == "execution_link"
        and record.get("relation") == "DECISION_TO_INSTRUCTION"
    ]
    if len(manifests) != 1 or len(instruction_links) != 1:
        return errors
    manifest = manifests[0]
    instruction = _as_dict(instruction_links[0].get("target"))
    for field in ("trace_id", "action_attempt_id", "decision_id"):
        if lifecycle_bundle.get(field) != manifest.get(field):
            errors.append(f"pair: lifecycle {field} does not match issuer")
    lifecycle_instruction = lifecycle_bundle.get("instruction")
    if not isinstance(lifecycle_instruction, dict) or lifecycle_instruction.get("id") != instruction.get("id") or lifecycle_instruction.get("digest") != instruction.get("digest"):
        errors.append("pair: lifecycle instruction does not match issuer")
    lifecycle_records = lifecycle_bundle.get("records")
    if isinstance(lifecycle_records, list):
        applications = [
            record for record in lifecycle_records
            if isinstance(record, dict) and record.get("profile_type") == "enforcement_result"
        ]
        if len(applications) == 1 and applications[0].get("requested_disposition") != issuer_bundle.get("disposition"):
            errors.append("pair: application requested disposition does not match issuer")
    return errors


def run_fixture(path: Path = FIXTURE) -> list[tuple[str, str, list[str]]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    outcomes = []
    for case in fixture["cases"]:
        errors = validate_document(case["profile"], case["document"])
        actual = "REJECT" if errors else "PASS"
        outcomes.append((case["name"], actual, errors))
    return outcomes


def main() -> int:
    fixture_paths = (FIXTURE, LIFECYCLE_PROFILE_FIXTURE, RECOVERY_CLOSURE_FIXTURE, CLAIM_COVERAGE_FIXTURE, OBLIGATION_FIXTURE)
    fixtures = [json.loads(path.read_text(encoding="utf-8")) for path in fixture_paths]
    outcomes = [outcome for path in fixture_paths for outcome in run_fixture(path)]
    expected = {
        case["name"]: case["expected"]
        for fixture in fixtures
        for case in fixture["cases"]
    }
    failures = []
    for name, actual, errors in outcomes:
        want = expected[name]
        print(f"{name}: {actual} (expected {want})")
        if actual != want:
            failures.append((name, errors))
    if failures:
        for name, errors in failures:
            print(f"  {name}: {errors}")
        return 1
    print(f"ENAS profiles: {len(outcomes)} matched expected outcomes across five fixture corpora")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
