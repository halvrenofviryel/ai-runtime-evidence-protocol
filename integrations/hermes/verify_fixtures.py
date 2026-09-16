#!/usr/bin/env python3
"""Validate the committed Hermes mapping corpus with AIREP v0.2 code."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys
import tempfile

INTEGRATION = Path(__file__).resolve().parent
ROOT = INTEGRATION.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(INTEGRATION))

import generate_fixtures as generator  # noqa: E402
from tools.airep_v02.json_input import loads  # noqa: E402
from tools.airep_v02.producer import check_core  # noqa: E402
from tools.airep_v02.reconcile import reconcile  # noqa: E402


class ValidationError(RuntimeError):
    pass


def read_json(path: Path):
    return loads(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def check_states(result: dict, name: str) -> list[str]:
    return [check["state"] for check in result["checks"] if check["check"] == name]


def recompute_verification(artifacts: list[dict], result: dict, ops) -> dict:
    return generator.verification_for(artifacts, result, ops)


def verify_references(artifacts: list[dict], fixture_name: str) -> None:
    by_id = {artifact["record_id"]: artifact for artifact in artifacts}
    require(len(by_id) == len(artifacts), f"{fixture_name}: duplicate record_id")
    for artifact in artifacts:
        if artifact["artifact_type"] == "decision":
            continue
        decision_ref = artifact["decision_ref"]
        target = by_id.get(decision_ref["record_id"])
        require(target is not None, f"{fixture_name}: missing decision reference")
        require(target["artifact_type"] == "decision", f"{fixture_name}: decision_ref wrong family")
        require(target["chain_id"] == decision_ref.get("chain_id", target["chain_id"]),
                f"{fixture_name}: decision_ref wrong chain")
        if artifact["artifact_type"] == "effect":
            execution_ref = artifact["execution_ref"]
            execution = by_id.get(execution_ref["record_id"])
            require(execution is not None and execution["artifact_type"] == "execution",
                    f"{fixture_name}: unresolved execution_ref")
            require(execution["chain_id"] == execution_ref.get("chain_id", execution["chain_id"]),
                    f"{fixture_name}: execution_ref wrong chain")


def verify_semantics(directory: str, facts: dict, artifacts: list[dict]) -> None:
    observed = facts["observed_source_facts"]
    request_id = observed["approval_request_id"]
    instruction_ids = {
        artifact["instruction_id"] for artifact in artifacts
        if artifact["artifact_type"] in ("control", "execution")
    }
    require(request_id not in instruction_ids,
            f"{directory}: approval request_id was reused as instruction_id")

    non_answers = {"timeout", "cancelled", "notify_failed", "transport_failed"}
    decision_events = [
        value for key, value in observed.items()
        if key.endswith("decision_event") and isinstance(value, dict)
    ]
    if any(event.get("choice") in non_answers for event in decision_events):
        for artifact in artifacts:
            if artifact["artifact_type"] == "decision":
                require(all(item["type"] != "human_approval" for item in artifact["evidence"]),
                        f"{directory}: unanswered approval mislabeled as human approval")
                require("human denial" not in artifact["claim"]["assertion"].lower(),
                        f"{directory}: unanswered approval mislabeled as human denial")

    if directory == "01-human-deny":
        decision = next(a for a in artifacts if a["artifact_type"] == "decision")
        require(all(item["type"] != "human_approval" for item in decision["evidence"]),
                "01-human-deny: denial must not be positive human_approval evidence")
    if directory == "07-action-mismatch":
        controls = [a["authorized_action_digest"] for a in artifacts if a["artifact_type"] == "control"]
        executions = [a["executed_action_digest"] for a in artifacts if a["artifact_type"] == "execution"]
        require(controls and executions and set(controls).isdisjoint(executions),
                "07-action-mismatch: mismatch was normalized away")
    if directory in ("03-release-no-dispatch", "09-consumed-crash-unknown"):
        require(not any(a["artifact_type"] == "execution" for a in artifacts),
                f"{directory}: fabricated Execution for unknown state")
    if directory == "03-release-no-dispatch":
        require(not any(a["artifact_type"] == "control" for a in artifacts),
                "03-release-no-dispatch: approval alone manufactured Control")
    if directory == "04-dispatch-no-execution":
        require(not any(a.get("control_event") == "received" for a in artifacts),
                "04-dispatch-no-execution: issuer dispatch manufactured receiver receipt")
    if directory == "10-concurrent-replay":
        require(sum(a["artifact_type"] == "execution" for a in artifacts) == 1,
                "10-concurrent-replay: rejected replay duplicated execution evidence")
        blocked = [a for a in artifacts if a["artifact_type"] == "decision" and a["directive"]["verb"] == "block"]
        require(len(blocked) == 1, "10-concurrent-replay: expected one replay block decision")
        blocked_ids = {a["record_id"] for a in blocked}
        require(not any(
            a["artifact_type"] != "decision" and a["decision_ref"]["record_id"] in blocked_ids
            for a in artifacts
        ), "10-concurrent-replay: rejected replay has successful lifecycle evidence")
    if directory == "11-effect-observed":
        effect = next(a for a in artifacts if a["artifact_type"] == "effect")
        require(effect["observer_relationship"] == "same_executor",
                "11-effect-observed: fixture overclaims observer independence")


def verify_no_private_material() -> None:
    forbidden = (
        re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(rb'"seed_hex"\s*:'),
        re.compile(rb"AKIA[0-9A-Z]{16}"),
    )
    for path in sorted(p for p in INTEGRATION.rglob("*") if p.is_file()):
        data = path.read_bytes()
        for pattern in forbidden:
            require(not pattern.search(data), f"production-looking private material in {path}")
    source = (INTEGRATION / "generate_fixtures.py").read_text(encoding="utf-8")
    require(generator.KEY_NOTICE in source, "fixed fixture seeds lack the required key warning")


def verify_determinism() -> None:
    with tempfile.TemporaryDirectory(prefix="hermes-airep-verify-") as tmp:
        fresh = Path(tmp) / "generated"
        generator.build_tree(fresh)
        committed_files = generator.generated_files(INTEGRATION)
        fresh_files = generator.generated_files(fresh)
        require(committed_files == fresh_files, "fresh fixture generation is not byte-identical")


def validate() -> dict:
    source_basis = read_json(INTEGRATION / "SOURCE_BASIS.json")
    require(source_basis["airep_commit"] == generator.AIREP_COMMIT, "AIREP basis drift")
    require(source_basis["hermes_commit"] == generator.HERMES_COMMIT, "Hermes basis drift")
    require(source_basis["mapping_version"] == generator.MAPPING_VERSION, "mapping version drift")

    fixtures = INTEGRATION / "fixtures"
    discovered = sorted(path for path in fixtures.iterdir() if path.is_dir())
    expected_directories = [directory for _, directory, _ in generator.SCENARIOS]
    require([path.name for path in discovered] == expected_directories,
            "fixture directory set does not match the scenario registry")
    ops = generator.ops_for(INTEGRATION)
    seen_record_ids: set[str] = set()
    rows = []

    for scenario_id, directory, title in generator.SCENARIOS:
        fixture = fixtures / directory
        facts = read_json(fixture / "native_facts.json")
        artifacts = read_json(fixture / "artifacts.json")
        expected = read_json(fixture / "expected.json")
        saved_verification = read_json(fixture / "verification.json")
        saved_reconciliation = read_json(fixture / "reconciliation.json")
        require(facts["scenario_id"] == scenario_id, f"{directory}: scenario id mismatch")
        require(isinstance(artifacts, list) and artifacts, f"{directory}: empty artifact set")

        for artifact in artifacts:
            check_core(artifact)
            require(artifact["record_id"] not in seen_record_ids,
                    f"{directory}: globally duplicate record_id")
            seen_record_ids.add(artifact["record_id"])
        verify_references(artifacts, directory)

        actual_families = Counter(a["artifact_type"] for a in artifacts)
        require(dict(sorted(actual_families.items())) == expected["artifact_family_counts"],
                f"{directory}: artifact family counts changed")
        for family in expected["absent_families"]:
            require(family not in actual_families, f"{directory}: expected {family} to remain absent")

        actual_reconciliation = reconcile(artifacts, ops=ops)
        require(actual_reconciliation == saved_reconciliation,
                f"{directory}: committed reconciliation does not reproduce")
        actual_verification = recompute_verification(artifacts, actual_reconciliation, ops)
        require(actual_verification == saved_verification,
                f"{directory}: committed verifier output does not reproduce")
        require(actual_verification["all_records_authenticated"],
                f"{directory}: a record is not AIREP-Authenticated under test inputs")
        require(all(verdict["class"] == expected["verification_class"]
                    for verdict in actual_verification["verdicts"]),
                f"{directory}: unexpected class result")
        require(all(not verdict["authenticated_failures"] and not verdict["authenticated_withheld"]
                    for verdict in actual_verification["verdicts"]),
                f"{directory}: authentication failure/withholding")
        require(set(check_states(actual_reconciliation, "chain_link")) == {"SATISFIED"},
                f"{directory}: chain linkage is not satisfied")

        for name, wanted in expected["reconciliation_states"].items():
            actual = check_states(actual_reconciliation, name)
            require(Counter(actual) == Counter(wanted),
                    f"{directory}: {name} states {actual!r} != {wanted!r}")
        require(not expected["global_satisfied_status_required"],
                f"{directory}: fixture incorrectly requires global SATISFIED")
        verify_semantics(directory, facts, artifacts)
        rows.append({
            "id": scenario_id,
            "directory": directory,
            "records": len(artifacts),
            "families": dict(sorted(actual_families.items())),
            "class": expected["verification_class"],
            "reconciliation_status": actual_reconciliation["summary"]["status"],
            "negative_states": expected["expected_negative_states"],
            "title": title,
        })

    verify_no_private_material()
    expected_summary = generator.build_summary(INTEGRATION)
    actual_summary = read_json(INTEGRATION / "summary.json")
    require(actual_summary == expected_summary, "summary.json does not match the fixture corpus")
    verify_determinism()
    return {
        "status": "ok",
        "fixtures": rows,
        "record_count": len(seen_record_ids),
        "corpus_manifest_digest": actual_summary["corpus"]["manifest_digest"],
    }


def main() -> int:
    try:
        result = validate()
    except (ValidationError, ValueError, TypeError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    for row in result["fixtures"]:
        print(
            f"{row['id']}: {row['records']} records; {row['class']}; "
            f"reconciliation={row['reconciliation_status']}"
        )
    print(
        f"OK: {len(result['fixtures'])} fixtures, {result['record_count']} records; "
        f"{result['corpus_manifest_digest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
