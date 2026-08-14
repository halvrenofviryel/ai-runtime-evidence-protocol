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
    # Polls 2 & 3 attest observed enforcement (outcome_observed) — a directive alone is a
    # DECISION, not an enforced effect, so PASS requires the source to observe the outcome.
    reports = [
        {"trace_id": "t", "claims": [{"claim": "a", "directive": "rewrite"}, {"claim": "b", "directive": "pass"}]},
        {"trace_id": "t", "outcome_observed": True, "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}]},
        {"trace_id": "t", "outcome_observed": True, "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}, {"claim": "c", "directive": "block"}]},
    ]
    feed = GateFeed(_sequence_source(reports))

    p1 = feed.poll()
    assert p1["global_verdict"] == "INCONCLUSIVE"  # "a" pending
    assert p1["dispositions"] == {"a": "UNRESOLVED", "b": "DISCHARGED"}
    assert p1["delta"]["new_pending"] == ["a"]
    assert p1["delta"]["new_terminal"] == ["b"]

    p2 = feed.poll()
    assert p2["global_verdict"] == "PASS"  # all discharged AND enforcement observed
    assert p2["delta"]["resolved"] == ["a"]  # UNRESOLVED -> DISCHARGED observed live

    p3 = feed.poll()
    assert p3["global_verdict"] == "FAIL"  # "c" blocked (a failure outranks observation)
    assert p3["delta"]["new_terminal"] == ["c"]
    assert p3["dispositions"]["c"] == "FAILED"

    # the two verdicts are separate: the gate OUTCOME varies (INCONCLUSIVE/PASS/FAIL) while the
    # mapped bundle stays structurally sound (reconciler integrity == PASS on every poll).
    assert p1["reconciled"] == p2["reconciled"] == p3["reconciled"] == "PASS"


def test_all_discharged_directives_without_observed_enforcement_are_inconclusive():
    # A feed watching directives go pass->pass is still watching DECISIONS, not observed
    # enforcement. With no outcome_observed attestation, an all-discharged poll must NOT reach
    # PASS — it is INCONCLUSIVE. (Regression guard: this poll used to report PASS on directives
    # alone, the same measurement-positivity the snapshot adapter had.)
    report = {"trace_id": "t", "claims": [{"claim": "a", "directive": "pass"}, {"claim": "b", "directive": "pass"}]}
    result = GateFeed(_sequence_source([report])).poll()
    assert result["dispositions"] == {"a": "DISCHARGED", "b": "DISCHARGED"}
    assert result["global_verdict"] == "INCONCLUSIVE"  # discharged directives, enforcement NOT observed
    assert result["reconciled"] == "PASS"  # the mapped bundle is still structurally conserved


def test_feed_deduplicates_revisions_to_the_latest_directive():
    # The same claim revised regenerate -> regenerate -> pass is ONE obligation ending DISCHARGED.
    # The source attests observed enforcement, so the resolved obligation reaches PASS.
    report = {"trace_id": "t", "outcome_observed": True, "claims": [
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
        {"trace_id": "t", "outcome_observed": True, "claims": [{"claim": "a", "directive": "pass"}]},
    ]
    feed = GateFeed(_sequence_source(reports))
    feed.poll()  # a pending
    feed.poll()  # non-observation, must not wipe state
    p3 = feed.poll()
    assert p3["delta"]["resolved"] == ["a"]  # continuity preserved across the missing sample
    assert p3["global_verdict"] == "PASS"  # resolved AND enforcement observed


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
    assert "UNRESOLVED" in result["dispositions"].values()
    # HONEST FALLBACK (P0-C): the captured report carries NO claim_id, so identity
    # degrades to text — its 8 governed claims (lifecycle.funnel.claim_created == 8)
    # collapse to their 5 distinct texts. This under-count is exactly why a stable
    # claim_id is required; with ids the eight would stay distinct (tests below).
    assert report["lifecycle"]["funnel"]["claim_created"] == 8
    assert all("claim_id" not in c for c in report["claims"])
    assert len(result["dispositions"]) == 5  # 8 entries, 5 distinct texts (degraded)


def test_same_text_distinct_claim_ids_are_not_collapsed():
    # THE P0-C feed regression: two DISTINCT governed claims that share text but carry
    # distinct claim_ids must NOT collapse — the feed keys on identity, not text.
    report = {"trace_id": "t", "outcome_observed": True, "claims": [
        {"claim_id": "clm-1", "claim": "fixed the test", "directive": "pass"},
        {"claim_id": "clm-2", "claim": "fixed the test", "directive": "pass"},
    ]}
    result = GateFeed(_sequence_source([report])).poll()
    assert set(result["dispositions"]) == {"clm-1", "clm-2"}  # keyed by id, both present
    assert result["dispositions"] == {"clm-1": "DISCHARGED", "clm-2": "DISCHARGED"}
    assert result["delta"]["new_terminal"] == ["clm-1", "clm-2"]


def test_a_claim_is_tracked_by_id_across_edited_text():
    # A claim revised across polls keeps ONE claim_id even as its text is edited; the feed
    # must watch it RESOLVE by identity (text-keying would see two different claims instead).
    reports = [
        {"trace_id": "t", "claims": [{"claim_id": "clm-1", "claim": "draft", "directive": "rewrite"}]},
        {"trace_id": "t", "outcome_observed": True, "claims": [{"claim_id": "clm-1", "claim": "draft, revised", "directive": "pass"}]},
    ]
    feed = GateFeed(_sequence_source(reports))
    p1 = feed.poll()
    assert p1["dispositions"] == {"clm-1": "UNRESOLVED"}
    p2 = feed.poll()
    assert p2["delta"]["resolved"] == ["clm-1"]  # same identity, watched resolving despite edited text
    assert p2["delta"]["disappeared"] == []  # NOT seen as a vanished claim + a new one
    assert p2["global_verdict"] == "PASS"


def test_identity_mode_switch_across_polls_resets_continuity_not_false_match():
    # poll1 is id-mode (claim_id "x", pending); poll2 degrades to text-mode and contains a
    # DIFFERENT claim whose text happens to be "x". These are different identities in different
    # namespaces — the feed must NOT read the id-"x" as resolving into the text-"x".
    reports = [
        {"trace_id": "t", "claims": [{"claim_id": "x", "claim": "alpha", "directive": "rewrite"}]},
        {"trace_id": "t", "outcome_observed": True, "claims": [{"claim": "x", "directive": "pass"}]},  # no id -> text mode
    ]
    feed = GateFeed(_sequence_source(reports))
    p1 = feed.poll()
    assert p1["dispositions"] == {"x": "UNRESOLVED"}  # id-keyed
    p2 = feed.poll()
    assert p2["dispositions"] == {"x": "DISCHARGED"}  # text-keyed — a DIFFERENT identity
    assert p2["delta"]["resolved"] == []              # NOT falsely matched across namespaces
    assert p2["delta"]["new_terminal"] == ["x"]       # the text-"x" is genuinely new
    assert p2["delta"]["disappeared"] == ["x"]        # the id-"x" is no longer trackable
    assert any("identity namespace changed" in e for e in p2["reconciliation_errors"])


def test_mixed_id_and_idless_claims_degrade_to_text_without_collision():
    # A report mixing an id-bearing claim with an id-less one whose TEXT equals that id must
    # NOT collide into one lifecycle. Identity is all-or-nothing per report, so a mixed report
    # degrades to text keys for all — the two stay distinct by their (distinct) texts.
    report = {"trace_id": "t", "outcome_observed": True, "claims": [
        {"claim_id": "x", "claim": "identified", "directive": "pass"},
        {"claim": "x", "directive": "block"},
    ]}
    result = GateFeed(_sequence_source([report])).poll()
    assert set(result["dispositions"]) == {"identified", "x"}  # text keys (degraded), not collapsed
    assert result["dispositions"]["x"] == "FAILED"
    assert result["global_verdict"] == "FAIL"


def test_a_same_text_pass_never_launders_a_distinct_claim_ids_block():
    # Identity + sticky-FAILED together: a blocked claim (clm-2) is not laundered by a
    # DIFFERENT claim (clm-1) that shares its text and passed.
    report = {"trace_id": "t", "outcome_observed": True, "claims": [
        {"claim_id": "clm-1", "claim": "same text", "directive": "pass"},
        {"claim_id": "clm-2", "claim": "same text", "directive": "block"},
    ]}
    result = GateFeed(_sequence_source([report])).poll()
    assert result["dispositions"] == {"clm-1": "DISCHARGED", "clm-2": "FAILED"}
    assert result["global_verdict"] == "FAIL"
