from __future__ import annotations

import json

from enas_profiles import (
    CLAIM_COVERAGE_FIXTURE,
    FIXTURE,
    LIFECYCLE_PROFILE_FIXTURE,
    OBLIGATION_FIXTURE,
    RECOVERY_CLOSURE_FIXTURE,
    run_fixture,
)


def test_enas_profile_fixture_outcomes():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_fixture()
    assert len(outcomes) == 24
    assert sum(value == "PASS" for value in expected.values()) == 7
    assert sum(value == "REJECT" for value in expected.values()) == 17
    for name, actual, errors in outcomes:
        assert actual == expected[name], (name, errors)


def test_enas_lifecycle_profile_fixture_outcomes():
    fixture = json.loads(LIFECYCLE_PROFILE_FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_fixture(LIFECYCLE_PROFILE_FIXTURE)
    assert len(outcomes) == 16
    assert sum(value == "PASS" for value in expected.values()) == 4
    assert sum(value == "REJECT" for value in expected.values()) == 12
    for name, actual, errors in outcomes:
        assert actual == expected[name], (name, errors)


def test_enas_recovery_closure_fixture_outcomes():
    # WP-SR / WP-CQ / WP-DR / WP-LV record schemas: G2 (machine-validatable
    # records + negative fixtures) for the four E.2 packages whose first missing
    # artifact was the record schema itself.
    fixture = json.loads(RECOVERY_CLOSURE_FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_fixture(RECOVERY_CLOSURE_FIXTURE)
    assert len(outcomes) == 55
    assert sum(value == "PASS" for value in expected.values()) == 16
    assert sum(value == "REJECT" for value in expected.values()) == 39
    for name, actual, errors in outcomes:
        assert actual == expected[name], (name, errors)


def test_enas_claim_coverage_fixture_outcomes():
    # WP-CC record schemas: claim configuration (content-addressed identity),
    # nondeterminism + run design, reliance (non-inheritance), observed operating
    # path (least-assured + assistance disclosure), and the claim coverage registry
    # binding each claim to a content-addressed configuration.
    fixture = json.loads(CLAIM_COVERAGE_FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_fixture(CLAIM_COVERAGE_FIXTURE)
    assert len(outcomes) == 31
    assert sum(value == "PASS" for value in expected.values()) == 11
    assert sum(value == "REJECT" for value in expected.values()) == 20
    for name, actual, errors in outcomes:
        assert actual == expected[name], (name, errors)


def test_enas_obligation_protocol_fixture_outcomes():
    # WP-OP Echo Obligation Protocol record schemas: origin contract (stable
    # obligation identity), obligation handoff (send != accept != fulfil),
    # transformation (loss vector; NOT_MEASURED/INVALID cannot discharge),
    # fork/join (weakest-link closure, no unauthorized last-writer-wins), the
    # conservation accounting invariant (O_before ⊎ O_created =
    # O_after ⊎ O_discharged ⊎ O_transformed ⊎ O_revoked ⊎ O_failed ⊎ O_unresolved),
    # amendment/revocation (no retroactive authorization), and closure (closure is
    # not success; global PASS only against a fully accounted contract).
    fixture = json.loads(OBLIGATION_FIXTURE.read_text(encoding="utf-8"))
    expected = {case["name"]: case["expected"] for case in fixture["cases"]}
    outcomes = run_fixture(OBLIGATION_FIXTURE)
    assert len(outcomes) == 36
    assert sum(value == "PASS" for value in expected.values()) == 11
    assert sum(value == "REJECT" for value in expected.values()) == 25
    for name, actual, errors in outcomes:
        assert actual == expected[name], (name, errors)
