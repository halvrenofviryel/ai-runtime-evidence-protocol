from __future__ import annotations

import json
from pathlib import Path

from enas_gate_feed import GateFeed

CAPTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "enas_profiles"
    / "enas_gate_report_capture.json"
)


def _sequence_source(reports):
    it = iter(reports)
    return lambda: next(it)


def test_feed_tracks_a_pending_claim_resolving_over_polls():
    # Poll 1: claim "a" is sent for revision (pending), "b" passes.
    # Poll 2: "a" is revised and passes -> the feed observes it RESOLVE.
    # Poll 3: a new claim "c" is blocked -> the run fails.
    reports = [
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "rewrite"}, {"claim": "b", "directive": "pass"}]},
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}]},
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}, {"claim": "c", "directive": "block"}]},
    ]
    feed = GateFeed(_sequence_source(reports))

    p1 = feed.poll()
    assert p1["global_verdict"] == "INCONCLUSIVE"  # "a" pending
    assert p1["dispositions"] == {"a": "UNRESOLVED", "b": "DISCHARGED"}
    assert p1["delta"]["new_pending"] == ["a"]
    assert p1["delta"]["new_terminal"] == ["b"]

    p2 = feed.poll()
    assert p2["global_verdict"] == "PASS"  # all discharged now
    assert p2["delta"]["resolved"] == ["a"]  # UNRESOLVED -> DISCHARGED observed live

    p3 = feed.poll()
    assert p3["global_verdict"] == "FAIL"  # "c" blocked
    assert p3["delta"]["new_terminal"] == ["c"]
    assert p3["dispositions"]["c"] == "FAILED"

    # the two verdicts are separate: the gate OUTCOME varies (INCONCLUSIVE/PASS/FAIL) while the
    # mapped bundle stays structurally sound (reconciler integrity == PASS on every poll).
    assert p1["reconciled"] == p2["reconciled"] == p3["reconciled"] == "PASS"


def test_feed_deduplicates_revisions_to_the_latest_directive():
    # The same claim revised regenerate -> regenerate -> pass is ONE obligation ending DISCHARGED.
    report = {"trace_id": "t", "claims": [
        {"claim": "x", "directive": "regenerate"},
        {"claim": "x", "directive": "regenerate"},
        {"claim": "x", "directive": "pass"},
    ]}
    feed = GateFeed(_sequence_source([report]))
    result = feed.poll()
    assert result["dispositions"] == {"x": "DISCHARGED"}
    assert result["global_verdict"] == "PASS"


def test_empty_and_malformed_polls_are_inconclusive_not_a_crash():
    feed = GateFeed(_sequence_source([{"trace_id": "t", "claims": []}, {}, {"claims": 1}, None]))
    for _ in range(4):
        assert feed.poll()["global_verdict"] == "INCONCLUSIVE"  # empty / missing / non-list / non-dict


def test_a_blocked_claim_is_never_masked_by_a_later_same_text_pass():
    # A hard block then a same-text pass must NOT launder the failure away.
    report = {"trace_id": "t", "claims": [{"claim": "x", "directive": "block"}, {"claim": "x", "directive": "pass"}]}
    result = GateFeed(_sequence_source([report])).poll()
    assert result["dispositions"] == {"x": "FAILED"}
    assert result["global_verdict"] == "FAIL"


def test_a_transient_non_observation_preserves_delta_continuity():
    # poll1 pending -> poll2 NON-observation (malformed: no claims key) -> poll3 passes:
    # the missing sample must not wipe state, so the resolution is still seen.
    reports = [
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "rewrite"}]},
        {"trace_id": "t"},  # no claims key -> non-observation
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "pass"}]},
    ]
    feed = GateFeed(_sequence_source(reports))
    feed.poll()  # a pending
    feed.poll()  # non-observation, must not wipe state
    p3 = feed.poll()
    assert p3["delta"]["resolved"] == ["a"]  # continuity preserved across the missing sample
    assert p3["global_verdict"] == "PASS"


def test_a_malformed_entry_list_is_not_a_zero_claim_observation():
    # A non-empty claims list whose entries are all malformed reduces to {} but is NOT a clean
    # zero-claim observation — it must preserve state, not falsely report disappearance/reset.
    reports = [
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "rewrite"}]},
        {"claims": [None]},  # malformed entries -> non-observation, not a real empty
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "pass"}]},
    ]
    feed = GateFeed(_sequence_source(reports))
    feed.poll()
    p2 = feed.poll()
    assert p2["delta"]["disappeared"] == []  # state NOT reset by a malformed sample
    p3 = feed.poll()
    assert p3["delta"]["resolved"] == ["a"]  # continuity preserved


def test_a_wellformed_empty_report_reports_real_disappearance():
    # A valid report with an explicitly empty claims list is a real zero-claim observation:
    # prior claims genuinely disappeared (distinct from a missing/malformed sample).
    reports = [
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "rewrite"}]},
        {"trace_id": "t", "claims": []},
    ]
    feed = GateFeed(_sequence_source(reports))
    feed.poll()
    p2 = feed.poll()
    assert p2["delta"]["disappeared"] == ["a"]
    assert p2["global_verdict"] == "INCONCLUSIVE"


def test_feed_over_the_captured_real_report():
    # A single poll of the verbatim captured real session report: 1 passed, 7 pending -> INCONCLUSIVE.
    report = json.loads(CAPTURE.read_text(encoding="utf-8"))["report"]
    result = GateFeed(_sequence_source([report])).poll()
    assert result["global_verdict"] == "INCONCLUSIVE"
    # the captured report's 8 entries dedup to distinct claim texts, still with pending ones
    assert "UNRESOLVED" in result["dispositions"].values()
