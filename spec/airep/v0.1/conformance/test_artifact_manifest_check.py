"""Tests for the artifact_manifest check.

The corpus pins each record's verdict (and whether the temporal ordering was
checked). These tests also assert the load-bearing guarantees directly: a duplicate
artifact_id and an artifact collected after the decision both FAIL; a record with no
decision timestamp still PASSes on structure but records temporal_checked=False.
"""
from __future__ import annotations

import json
from pathlib import Path

from artifact_manifest_check import check_artifact_manifest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "artifact_manifest_cases.json"


def _cases():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def test_corpus_verdicts_match():
    for case in _cases():
        out = check_artifact_manifest(case["record"])
        assert out["verdict"] == case["expected"], (
            f"{case['name']}: {out['verdict']} != {case['expected']} ({out['errors']})"
        )
        if "expected_temporal_checked" in case:
            assert out["temporal_checked"] == case["expected_temporal_checked"], (
                f"{case['name']}: temporal_checked {out['temporal_checked']} != {case['expected_temporal_checked']}"
            )


def _record(artifacts, ts="2026-05-30T12:00:00Z"):
    rec = {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": artifacts}}}
    if ts is not None:
        rec["subject"] = {"timestamp_utc": ts}
    return rec


def _art(**over):
    a = {"artifact_id": "a1", "digest": "sha256:aa", "collected_at": "2026-05-30T11:00:00Z",
         "source": "s", "collector": "c"}
    a.update(over)
    return a


def test_duplicate_id_fails():
    out = check_artifact_manifest(_record([_art(artifact_id="d"), _art(artifact_id="d", digest="sha256:bb")]))
    assert out["verdict"] == "FAIL"
    assert any("duplicate artifact_id" in e for e in out["errors"])


def test_collected_after_decision_fails():
    out = check_artifact_manifest(_record([_art(collected_at="2026-05-30T13:00:00Z")]))
    assert out["verdict"] == "FAIL"
    assert any("postdates" in e for e in out["errors"])


def test_no_decision_timestamp_passes_but_untemporal():
    out = check_artifact_manifest(_record([_art()], ts=None))
    assert out["verdict"] == "PASS"
    assert out["temporal_checked"] is False


def test_valid_passes_with_temporal_check():
    out = check_artifact_manifest(_record([_art()]))
    assert out["verdict"] == "PASS"
    assert out["temporal_checked"] is True


def test_total_over_malformed_input():
    bad = [
        None, [], "x", 7, {}, {"profiles": "no"}, {"profiles": {}},
        {"profiles": {"artifact_manifest": "no"}},
        {"profiles": {"artifact_manifest": {"manifest_id": "", "artifacts": [_art()]}}},   # empty manifest_id
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": []}}},          # empty list
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": ["x"]}}},        # non-dict artifact
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art(digest="bad")]}}},  # bad digest
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art(collected_at="nope")]}}},  # bad date
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art(size_bytes=-1)]}}},  # bad size
        {"profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art(size_bytes=True)]}}},  # bool not int
        # subject present but malformed -> must NOT silently skip the temporal check:
        {"subject": True, "profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art()]}}},
        {"subject": [], "profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art()]}}},
        {"subject": {"timestamp_utc": "nope"}, "profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art()]}}},
        {"subject": {"timestamp_utc": "2026-05-30T00:00:00"}, "profiles": {"artifact_manifest": {"manifest_id": "m", "artifacts": [_art()]}}},  # no timezone
    ]
    for b in bad:
        out = check_artifact_manifest(b)
        assert out["verdict"] == "INCONCLUSIVE", f"{b!r} -> {out['verdict']}"
