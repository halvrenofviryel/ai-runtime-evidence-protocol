from __future__ import annotations

import json

from enas_profiles import FIXTURE, LIFECYCLE_PROFILE_FIXTURE, run_fixture


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
