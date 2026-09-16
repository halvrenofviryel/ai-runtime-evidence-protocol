#!/usr/bin/env python3
"""Generate deterministic, non-normative Hermes -> AIREP v0.2 fixtures.

This module deliberately uses the repository's producer, verifier, and
reconciler.  It is not a second AIREP implementation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from tools.airep_v02 import Chain, digest_json, reference  # noqa: E402
from tools.airep_v02.json_input import dumps, loads  # noqa: E402
from tools.airep_v02.reconcile import reconcile  # noqa: E402
from tools.airep_v02.verify import evaluate_request, operator_inputs  # noqa: E402

MAPPING_VERSION = "0.1"
GENERATED_AT = "2026-09-16T17:07:48Z"
AIREP_COMMIT = "2c44cb66d2722e9bf039f1e7659afe727db4d50a"
HERMES_COMMIT = "9796235822b89e08597a402dad045b5b4464e474"
FIXTURE_TIME = "2026-09-16T12:00:00Z"

# TEST FIXTURE KEY — NEVER USE IN PRODUCTION.
# These intentionally obvious, fixed seeds have no authority outside this corpus.
TEST_FIXTURE_SEEDS = {
    "governor": bytes.fromhex("11" * 32),
    "executor": bytes.fromhex("22" * 32),
}
KEY_NOTICE = "TEST FIXTURE KEY — NEVER USE IN PRODUCTION"

SCENARIOS = (
    ("HERMES-AIREP-01", "01-human-deny", "explicit human denial"),
    ("HERMES-AIREP-02", "02-timeout", "runtime fail-closed timeout"),
    ("HERMES-AIREP-03", "03-release-no-dispatch", "release without dispatch evidence"),
    ("HERMES-AIREP-04", "04-dispatch-no-execution", "dispatch without receipt or execution"),
    ("HERMES-AIREP-05", "05-executed", "received and executed"),
    ("HERMES-AIREP-06", "06-suppressed", "executor suppression"),
    ("HERMES-AIREP-07", "07-action-mismatch", "authorized/executed action mismatch"),
    ("HERMES-AIREP-08", "08-stale-request", "stale request rejected"),
    ("HERMES-AIREP-09", "09-consumed-crash-unknown", "consumed then crash; execution unknown"),
    ("HERMES-AIREP-10", "10-concurrent-replay", "one native consume; replay rejected"),
    ("HERMES-AIREP-11", "11-effect-observed", "same-executor effect observation"),
)

SCOPE = {
    "covers": ["Deterministic fixture report of explicitly named Hermes scenario facts"],
    "does_not_cover": [
        "Truth beyond the synthetic source facts",
        "Complete Hermes event history",
        "Hermes authorization or exactly-once enforcement correctness",
        "Approver authentication, policy correctness, execution, or real-world effect beyond the named report",
        "Independent observation",
    ],
}


def key_for(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(TEST_FIXTURE_SEEDS[role])


def public_key_hex(role: str) -> str:
    return key_for(role).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(value), encoding="utf-8")


def read_json(path: Path):
    return loads(path.read_bytes())


def governed_intent(number: int) -> dict:
    suffix = f"{number:02d}"
    return {
        "projection_version": "example.hermes.fixture-intent.v1",
        "tool": "terminal",
        "action": "execute",
        "target": f"fixture-target-{suffix}",
        "parameters": {"command": f"printf hermes-airep-{suffix}"},
    }


def action_projection(number: int, *, mismatch: bool = False) -> dict:
    suffix = f"{number:02d}"
    command_suffix = "-different" if mismatch else ""
    return {
        "projection_version": "example.hermes.fixture-action.v1",
        "tool": "terminal",
        "action": "execute",
        "target": f"fixture-target-{suffix}",
        "parameters": {"command": f"printf hermes-airep-{suffix}{command_suffix}"},
    }


def identities(number: int) -> dict:
    suffix = f"{number:02d}"
    return {
        "request_id": f"hermes-request-{suffix}",
        "instruction_id": f"hermes-instruction-{suffix}-v1",
        "decision_id": f"hermes-airep-{suffix}-decision",
        "governor_chain": f"hermes-airep-{suffix}-governor-chain",
        "executor_chain": f"hermes-airep-{suffix}-executor-chain",
    }


def fixture_facts(number: int, scenario_id: str, title: str) -> dict:
    ids = identities(number)
    intent = governed_intent(number)
    authorized = action_projection(number)
    observed = {
        "approval_request_id": ids["request_id"],
        "governed_intent_exists": True,
    }
    constructed = {
        "governed_intent_projection": intent,
        "authorized_action_projection": authorized,
    }
    mapping = {
        "governed_intent_digest": "digest_json (RFC 8785 JSON via the AIREP producer)",
        "authorization_action_digest": "digest_json (RFC 8785 JSON via the AIREP producer)",
        "approval_request_id_is_instruction_id": False,
        "fixture_projection_notice": (
            "This projection is local to the integration fixtures. "
            "It is not a Hermes-native authorization contract."
        ),
    }
    facts = {
        "scenario_id": scenario_id,
        "title": title,
        "source_kind": "deterministic synthetic scenario, not a production Hermes run",
        "observed_source_facts": observed,
        "fixture_only_constructed_values": constructed,
        "mapping_choices": mapping,
    }

    if number == 1:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "deny"},
            authorization_instruction_issued=False,
            execution_observed=False,
        )
    elif number == 2:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "runtime", "choice": "timeout"},
            runtime_behavior="fail-closed",
            human_denial_observed=False,
            authorization_instruction_issued=False,
            execution_observed=False,
        )
    elif number == 3:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            release_decision_established=True,
            authorization_instruction_dispatch_observed=False,
            execution_observed=False,
        )
    elif number == 4:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=False,
            execution_observed=False,
        )
    elif number == 5:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            execution_event="executed",
        )
    elif number == 6:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            execution_event="suppressed",
        )
        mapping["suppressed_execution_digest_semantics"] = (
            "The schema-required executed_action_digest identifies the executor-reported action "
            "whose attempt was suppressed; execution_event=suppressed states that it did not run."
        )
    elif number == 7:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            execution_event="executed",
            executed_action_differs_from_authorized_action=True,
        )
        constructed["executed_action_projection"] = action_projection(number, mismatch=True)
    elif number == 8:
        observed.update(
            decision_event={
                "request_id": ids["request_id"],
                "source": "runtime",
                "choice": "stale-request-rejected",
            },
            rejected_interaction_created_release=False,
            runtime_block_decision_established=True,
            execution_observed=False,
        )
    elif number == 9:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            native_authorization_state="consumed",
            process_outcome="crash-before-execution-resolution",
            execution_state="unknown",
        )
    elif number == 10:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            execution_event="executed",
            native_consume_race={
                "consumer_a": "consume-succeeded",
                "consumer_b": "replay-rejected",
                "property_owner": "Hermes native authorization layer",
            },
            rejected_replay_created_release=False,
        )
    elif number == 11:
        observed.update(
            decision_event={"request_id": ids["request_id"], "source": "human", "choice": "once"},
            authorization_instruction_dispatch_observed=True,
            receiver_receipt_observed=True,
            execution_event="executed",
            effect_observation={"observer_relationship": "same_executor", "state": "fixture-state-updated"},
        )
        constructed["observed_state_projection"] = {
            "projection_version": "example.hermes.fixture-state.v1",
            "target": f"fixture-target-{number:02d}",
            "state": "fixture-state-updated",
        }
    else:  # pragma: no cover - callers use the fixed scenario table
        raise ValueError(f"unknown scenario {number}")
    return facts


def decision_payload(number: int, facts: dict, verb: str, reason: str, *, human_release: bool = False) -> dict:
    event = facts["observed_source_facts"]["decision_event"]
    event_type = "human_approval" if human_release else "other"
    result = {
        "decision": verb,
        "reason": reason,
        "approval_request_id": facts["observed_source_facts"]["approval_request_id"],
    }
    facts["fixture_only_constructed_values"]["decision_result"] = result
    return {
        "input": {
            "input_ref": "native_facts.json#/fixture_only_constructed_values/governed_intent_projection",
            "input_digest": digest_json(
                facts["fixture_only_constructed_values"]["governed_intent_projection"]
            ),
            "digest_projection": "example.hermes.fixture-intent-v1",
        },
        "claim": {
            "assertion": f"The synthetic Hermes scenario reports a {verb} decision: {reason}.",
            "basis": [f"fixture-source:{reason}"],
        },
        "directive": {"verb": verb, "policy_basis": ["example.hermes.fixture-policy"]},
        "output": {
            "result_ref": "native_facts.json#/fixture_only_constructed_values/decision_result",
            "result_digest": digest_json(result),
        },
        "evidence": [
            {
                "type": event_type,
                "ref": "native_facts.json#/observed_source_facts/decision_event",
                "resolvable": True,
                "content_hash": digest_json(event),
            }
        ],
    }


def instruction_values(number: int, facts: dict) -> tuple[str, str, str]:
    ids = identities(number)
    action_digest = digest_json(facts["fixture_only_constructed_values"]["authorized_action_projection"])
    instruction = {
        "projection_version": "example.hermes.fixture-instruction.v1",
        "instruction_id": ids["instruction_id"],
        "decision_record_id": ids["decision_id"],
        "approval_request_id": ids["request_id"],
        "authorized_action_digest": action_digest,
    }
    facts["fixture_only_constructed_values"]["authorization_instruction_projection"] = instruction
    return ids["instruction_id"], digest_json(instruction), action_digest


def control_payload(decision: dict, instruction_id: str, instruction_digest: str,
                    action_digest: str, event: str, side: str) -> dict:
    return {
        "decision_ref": reference(decision),
        "instruction_id": instruction_id,
        "instruction_digest": instruction_digest,
        "authorized_action_digest": action_digest,
        "control_event": event,
        "boundary_side": side,
        "authority": {
            "issuer_id": "example.hermes.governor",
            "writable_by_controlled_system": side == "receiver",
        },
    }


def execution_payload(decision: dict, instruction_id: str, instruction_digest: str,
                      action_digest: str, event: str) -> dict:
    return {
        "decision_ref": reference(decision),
        "instruction_id": instruction_id,
        "instruction_digest": instruction_digest,
        "executed_action_digest": action_digest,
        "execution_event": event,
    }


def expected_for(number: int, families: list[str]) -> dict:
    states = {
        "artifact_admission": ["SATISFIED"] * len(families),
        "record_authentication": ["SATISFIED"] * len(families),
        "chain_link": ["SATISFIED"] * len(families),
        "intended_target_coverage": ["NOT_EVALUATED"],
    }
    negative = {}
    if number in (1, 2, 3, 8):
        states["instruction_evidence"] = ["MISSING"]
    elif number == 4:
        states.update(
            instruction_evidence=["SATISFIED"],
            issuer_dispatch=["SATISFIED"],
            receiver_receipt=["MISSING"],
            execution_evidence=["MISSING"],
            toctou=["NOT_EVALUATED"],
        )
    elif number in (5, 6, 7, 11):
        states.update(
            instruction_evidence=["SATISFIED"],
            issuer_dispatch=["SATISFIED"],
            receiver_receipt=["SATISFIED"],
            execution_evidence=["SATISFIED"],
            toctou=["FAILURE" if number == 7 else "SATISFIED"],
            execution_outcome=["FAILURE" if number == 6 else "SATISFIED"],
        )
        if number != 11:
            states["effect_evidence"] = ["MISSING"]
        else:
            states.update(
                effect_evidence=["SATISFIED"],
                effect_binding=["SATISFIED"],
                observer_relationship=["SATISFIED"],
            )
    elif number == 9:
        states.update(
            instruction_evidence=["SATISFIED"],
            issuer_dispatch=["SATISFIED"],
            receiver_receipt=["SATISFIED"],
            execution_evidence=["MISSING"],
            toctou=["NOT_EVALUATED"],
        )
    elif number == 10:
        states.update(
            instruction_evidence=["SATISFIED", "MISSING"],
            issuer_dispatch=["SATISFIED"],
            receiver_receipt=["SATISFIED"],
            execution_evidence=["SATISFIED"],
            execution_outcome=["SATISFIED"],
            toctou=["SATISFIED"],
            effect_evidence=["MISSING"],
        )
    if number == 6:
        negative = {"execution_outcome": ["FAILURE"]}
    elif number == 7:
        negative = {"toctou": ["FAILURE"]}
    return {
        "artifact_family_counts": dict(sorted(Counter(families).items())),
        "absent_families": [family for family in ("decision", "control", "execution", "effect") if family not in families],
        "verification_class": "AIREP-Authenticated",
        "reconciliation_states": states,
        "expected_negative_states": negative,
        "global_satisfied_status_required": False,
    }


def build_scenario(number: int, scenario_id: str, title: str) -> tuple[dict, list[dict], dict]:
    facts = fixture_facts(number, scenario_id, title)
    ids = identities(number)
    governor = Chain(
        key_for("governor"), "example.hermes.governor", chain_id=ids["governor_chain"]
    )
    executor = Chain(
        key_for("executor"), "example.hermes.executor", chain_id=ids["executor_chain"]
    )
    artifacts: list[dict] = []

    if number == 1:
        decision = governor.emit_decision(
            decision_payload(number, facts, "block", "explicit-human-denial"),
            record_id=ids["decision_id"], timestamp=FIXTURE_TIME, scope=SCOPE,
        )
        artifacts.append(decision)
    elif number == 2:
        decision = governor.emit_decision(
            decision_payload(number, facts, "block", "runtime-fail-closed-timeout"),
            record_id=ids["decision_id"], timestamp=FIXTURE_TIME, scope=SCOPE,
        )
        artifacts.append(decision)
    elif number == 8:
        decision = governor.emit_decision(
            decision_payload(number, facts, "block", "stale-request-rejected"),
            record_id=ids["decision_id"], timestamp=FIXTURE_TIME, scope=SCOPE,
        )
        artifacts.append(decision)
    else:
        decision = governor.emit_decision(
            decision_payload(number, facts, "release", "human-approved-once", human_release=True),
            record_id=ids["decision_id"], timestamp=FIXTURE_TIME, scope=SCOPE,
        )
        artifacts.append(decision)
        if number != 3:
            instruction_id, instruction_digest, authorized_digest = instruction_values(number, facts)
            dispatch = governor.emit_control(
                control_payload(decision, instruction_id, instruction_digest, authorized_digest,
                                "dispatched", "issuer"),
                record_id=f"hermes-airep-{number:02d}-dispatch",
                timestamp=FIXTURE_TIME, scope=SCOPE,
            )
            artifacts.append(dispatch)
            if number not in (4,):
                receipt = executor.emit_control(
                    control_payload(decision, instruction_id, instruction_digest, authorized_digest,
                                    "received", "receiver"),
                    record_id=f"hermes-airep-{number:02d}-receipt",
                    timestamp=FIXTURE_TIME, scope=SCOPE,
                )
                artifacts.append(receipt)
            if number in (5, 6, 7, 10, 11):
                executed = facts["fixture_only_constructed_values"].get(
                    "executed_action_projection",
                    facts["fixture_only_constructed_values"]["authorized_action_projection"],
                )
                event = "suppressed" if number == 6 else "executed"
                execution = executor.emit_execution(
                    execution_payload(decision, instruction_id, instruction_digest,
                                      digest_json(executed), event),
                    record_id=f"hermes-airep-{number:02d}-execution",
                    timestamp=FIXTURE_TIME, scope=SCOPE,
                )
                artifacts.append(execution)
                if number == 11:
                    observed_state = facts["fixture_only_constructed_values"]["observed_state_projection"]
                    effect = executor.emit_effect(
                        {
                            "decision_ref": reference(decision),
                            "execution_ref": reference(execution),
                            "observer_relationship": "same_executor",
                            "observed_state": {
                                "description": "The same fixture executor reports the updated fixture state.",
                                "state_digest": digest_json(observed_state),
                            },
                        },
                        record_id="hermes-airep-11-effect",
                        timestamp=FIXTURE_TIME, scope=SCOPE,
                    )
                    artifacts.append(effect)
            if number == 10:
                replay_event = {
                    "request_id": ids["request_id"],
                    "source": "runtime",
                    "choice": "replay-rejected",
                }
                facts["observed_source_facts"]["replay_decision_event"] = replay_event
                replay_result = {
                    "decision": "block",
                    "reason": "native-replay-rejected",
                    "approval_request_id": ids["request_id"],
                }
                facts["fixture_only_constructed_values"]["replay_decision_result"] = replay_result
                replay_payload = {
                    "input": {
                        "input_ref": "native_facts.json#/fixture_only_constructed_values/governed_intent_projection",
                        "input_digest": digest_json(
                            facts["fixture_only_constructed_values"]["governed_intent_projection"]
                        ),
                        "digest_projection": "example.hermes.fixture-intent-v1",
                    },
                    "claim": {
                        "assertion": "The synthetic Hermes native layer reports the replay rejected.",
                        "basis": ["fixture-source:native-replay-rejected"],
                    },
                    "directive": {
                        "verb": "block",
                        "policy_basis": ["example.hermes.fixture-replay-policy"],
                    },
                    "output": {
                        "result_ref": "native_facts.json#/fixture_only_constructed_values/replay_decision_result",
                        "result_digest": digest_json(replay_result),
                    },
                    "evidence": [{
                        "type": "other",
                        "ref": "native_facts.json#/observed_source_facts/replay_decision_event",
                        "resolvable": True,
                        "content_hash": digest_json(replay_event),
                    }],
                }
                replay = governor.emit_decision(
                    replay_payload,
                    record_id="hermes-airep-10-replay-block-decision",
                    timestamp=FIXTURE_TIME, scope=SCOPE,
                )
                artifacts.append(replay)

    families = [artifact["artifact_type"] for artifact in artifacts]
    return facts, artifacts, expected_for(number, families)


def operator_documents() -> tuple[dict, dict]:
    bindings = {"bindings": {}, "producer_bindings": {}, "witness_bindings": {}}
    revocation = {"snapshot_id": "example.hermes.fixture-revocation-snapshot", "bindings": {}}
    for role in ("governor", "executor"):
        producer = f"example.hermes.{role}"
        bindings["bindings"][producer] = {
            "subject_identity": producer,
            "role": "producer",
            "suite": "ed25519",
            "trusted": True,
            "public_key_hex": public_key_hex(role),
        }
        bindings["producer_bindings"][producer] = producer
        revocation["bindings"][producer] = {"state": "active"}
    return bindings, revocation


def ops_for(root: Path):
    return operator_inputs(
        bindings=str(root / "fixture_operator_inputs/bindings.json"),
        revocation=str(root / "fixture_operator_inputs/revocation.json"),
    )


def verification_for(artifacts: list[dict], reconciliation: dict, ops) -> dict:
    verdicts = []
    for index, artifact in enumerate(artifacts):
        verdicts.append(evaluate_request({
            "artifact": artifact,
            "related_artifacts": artifacts[:index] + artifacts[index + 1:],
        }, ops=ops))
    chain_states = [
        check["state"] for check in reconciliation["checks"] if check["check"] == "chain_link"
    ]
    return {
        "scope": (
            "AIREP v0.2 schema/tagged-hash/signature/class verification using pinned, "
            "test-only producer bindings and revocation inputs. Authentication does not establish report truth."
        ),
        "operator_inputs": [
            "../../fixture_operator_inputs/bindings.json",
            "../../fixture_operator_inputs/revocation.json",
        ],
        "all_records_authenticated": all(v["class"] == "AIREP-Authenticated" for v in verdicts),
        "chain_link_states": chain_states,
        "verdicts": verdicts,
    }


def states_for(reconciliation: dict, names: dict[str, list[str]]) -> dict:
    return {
        name: [check["state"] for check in reconciliation["checks"] if check["check"] == name]
        for name in names
    }


def fixture_readme(scenario_id: str, title: str, expected: dict, reconciliation: dict) -> str:
    families = ", ".join(
        f"{family} x{count}" for family, count in expected["artifact_family_counts"].items()
    )
    states = states_for(reconciliation, expected["reconciliation_states"])
    rows = "\n".join(f"| `{name}` | `{', '.join(values)}` |" for name, values in states.items())
    return f"""# {scenario_id} — {title}

This directory is a deterministic synthetic mapping fixture, not a captured production Hermes run.

- Artifact families: {families}
- Verification: pinned test-only inputs classify every record as `AIREP-Authenticated`.
- Global reconciliation status is not treated as a pass/fail oracle.
- Missing stages remain absent; no `Execution(unknown)` record is invented.
- `native_facts.json` separates scenario source facts, fixture-only constructed values, and mapping choices.

| Named reconciliation check | Expected state(s) |
|---|---|
{rows}

`AIREP-Authenticated` here means only that the repository verifier accepted the fixture producer
binding, active revocation entry, signature, schema, and integrity inputs. It does not prove the
truth of the synthetic facts, Hermes policy correctness, authorization consumption, execution,
effect, or complete history.
"""


def fixture_manifest(fixtures: Path) -> list[dict]:
    manifest = []
    for path in sorted(p for p in fixtures.rglob("*") if p.is_file()):
        manifest.append({
            "path": path.relative_to(fixtures).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return manifest


def corpus_digest(manifest: list[dict]) -> str:
    return "sha256:" + hashlib.sha256(dumps(manifest).encode("utf-8")).hexdigest()


def build_summary(root: Path) -> dict:
    fixtures = root / "fixtures"
    entries = []
    for scenario_id, directory, title in SCENARIOS:
        fixture = fixtures / directory
        artifacts = read_json(fixture / "artifacts.json")
        expected = read_json(fixture / "expected.json")
        verification = read_json(fixture / "verification.json")
        reconciliation = read_json(fixture / "reconciliation.json")
        entries.append({
            "id": scenario_id,
            "directory": directory,
            "title": title,
            "artifact_family_counts": expected["artifact_family_counts"],
            "record_count": len(artifacts),
            "all_records_authenticated_under_test_inputs": verification["all_records_authenticated"],
            "important_reconciliation_states": states_for(
                reconciliation, expected["reconciliation_states"]
            ),
            "expected_negative_states": expected["expected_negative_states"],
            "reconciliation_summary": reconciliation["summary"],
        })
    manifest = fixture_manifest(fixtures)
    return {
        "mapping_version": MAPPING_VERSION,
        "generated_at": GENERATED_AT,
        "airep_commit": AIREP_COMMIT,
        "hermes_commit": HERMES_COMMIT,
        "verification_scope": "AIREP-Authenticated under pinned test-only bindings and revocation inputs",
        "fixtures": entries,
        "corpus": {
            "root": "fixtures",
            "file_count": len(manifest),
            "manifest": manifest,
            "manifest_digest": corpus_digest(manifest),
        },
    }


def build_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    fixtures = root / "fixtures"
    inputs = root / "fixture_operator_inputs"
    fixtures.mkdir()
    inputs.mkdir()
    bindings, revocation = operator_documents()
    write_json(inputs / "bindings.json", bindings)
    write_json(inputs / "revocation.json", revocation)
    (inputs / "README.md").write_text(
        f"# Fixture verifier inputs\n\n**{KEY_NOTICE}.**\n\n"
        "These pinned public-key bindings and active revocation entries exist only to exercise the "
        "AIREP-Authenticated path honestly for this deterministic corpus. They confer no production authority.\n",
        encoding="utf-8",
    )
    ops = ops_for(root)
    for number, (scenario_id, directory, title) in enumerate(SCENARIOS, 1):
        fixture = fixtures / directory
        fixture.mkdir()
        facts, artifacts, expected = build_scenario(number, scenario_id, title)
        reconciliation = reconcile(artifacts, ops=ops)
        verification = verification_for(artifacts, reconciliation, ops)
        write_json(fixture / "native_facts.json", facts)
        write_json(fixture / "artifacts.json", artifacts)
        write_json(fixture / "verification.json", verification)
        write_json(fixture / "reconciliation.json", reconciliation)
        write_json(fixture / "expected.json", expected)
        (fixture / "README.md").write_text(
            fixture_readme(scenario_id, title, expected, reconciliation), encoding="utf-8"
        )
    write_json(root / "summary.json", build_summary(root))


def generated_files(root: Path) -> dict[str, bytes]:
    result = {}
    for name in ("fixtures", "fixture_operator_inputs"):
        directory = root / name
        if directory.exists():
            for path in sorted(p for p in directory.rglob("*") if p.is_file()):
                result[path.relative_to(root).as_posix()] = path.read_bytes()
    summary = root / "summary.json"
    if summary.exists():
        result["summary.json"] = summary.read_bytes()
    return result


def install_generated(staging: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name in ("fixtures", "fixture_operator_inputs", "summary.json"):
        target = output / name
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()
        os.replace(staging / name, target)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--regenerate", action="store_true", help="explicitly replace generated outputs")
    action.add_argument("--check", action="store_true", help="compare a fresh generation byte-for-byte")
    parser.add_argument("--output", type=Path, default=INTEGRATION)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    with tempfile.TemporaryDirectory(prefix="hermes-airep-generate-") as tmp:
        staging = Path(tmp) / "generated"
        build_tree(staging)
        if args.check:
            actual, fresh = generated_files(output), generated_files(staging)
            if actual != fresh:
                missing = sorted(set(fresh) - set(actual))
                extra = sorted(set(actual) - set(fresh))
                changed = sorted(path for path in set(actual) & set(fresh) if actual[path] != fresh[path])
                print(json.dumps({"missing": missing, "extra": extra, "changed": changed}, indent=2))
                return 1
            print(f"byte-identical: {len(fresh)} generated files; {read_json(staging / 'summary.json')['corpus']['manifest_digest']}")
            return 0
        install_generated(staging, output)
    print(f"regenerated deterministic Hermes fixtures in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
