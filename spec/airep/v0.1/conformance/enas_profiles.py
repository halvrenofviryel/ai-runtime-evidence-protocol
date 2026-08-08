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
    )
}


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _duplicates(values: list[str]) -> bool:
    return len(values) != len(set(values))


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
    if action_link.get("target", {}).get("id") != decision_id:
        errors.append("issuer action link does not target the manifest decision")
    if instruction_link.get("source", {}).get("id") != decision_id:
        errors.append("issuer instruction link does not originate from the manifest decision")
    if action_link.get("target", {}).get("digest") != instruction_link.get("source", {}).get("digest"):
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
    if action_input is None or action_link.get("source", {}).get("digest") != action_input.get("digest"):
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
        nodes[(node_type, record[id_field])] = (_canonical_digest(record), record)

    instruction_key = ("INSTRUCTION", instruction.get("id"))
    nodes[instruction_key] = (instruction.get("digest"), instruction)
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
        link_errors = validate_document("execution_link", link)
        errors.extend(f"execution_link: {message}" for message in link_errors)
        if link.get("action_attempt_id") != attempt_id or link.get("trace_id") != trace_id:
            errors.append("execution link crosses bundle identity")
        relation = link.get("relation")
        observed_relations.add(relation)
        for endpoint in ("source", "target"):
            node = link.get(endpoint, {})
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
            profile: next(record for record in records if record.get("profile_type") == profile)
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
        except (KeyError, TypeError, ValueError):
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
    records = issuer_bundle.get("records")
    if not isinstance(records, list):
        return errors
    manifests = [record for record in records if record.get("profile_type") == "decision_input_manifest"]
    instruction_links = [
        record
        for record in records
        if record.get("profile_type") == "execution_link"
        and record.get("relation") == "DECISION_TO_INSTRUCTION"
    ]
    if len(manifests) != 1 or len(instruction_links) != 1:
        return errors
    manifest = manifests[0]
    instruction = instruction_links[0].get("target", {})
    for field in ("trace_id", "action_attempt_id", "decision_id"):
        if lifecycle_bundle.get(field) != manifest.get(field):
            errors.append(f"pair: lifecycle {field} does not match issuer")
    lifecycle_instruction = lifecycle_bundle.get("instruction")
    if not isinstance(lifecycle_instruction, dict) or lifecycle_instruction.get("id") != instruction.get("id") or lifecycle_instruction.get("digest") != instruction.get("digest"):
        errors.append("pair: lifecycle instruction does not match issuer")
    lifecycle_records = lifecycle_bundle.get("records")
    if isinstance(lifecycle_records, list):
        applications = [
            record for record in lifecycle_records if record.get("profile_type") == "enforcement_result"
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
    fixture_paths = (FIXTURE, LIFECYCLE_PROFILE_FIXTURE)
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
    print(f"ENAS profiles: {len(outcomes)} matched expected outcomes across two fixture corpora")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
