"""ENAS gate feed — a live, resampling binding to the Phionyx pipeline gate.

``enas_gate_adapter`` maps a single captured ``phionyx_session_report`` to a WP-OP
bundle. This turns that one-shot map into a **live feed**: a ``GateFeed`` holds a
``report_source`` callable and, on each ``poll()``, resamples the CURRENT report,
deduplicates claims to their latest gate directive, reconciles the resulting
obligation bundle, and reports how each obligation's disposition *changed since the
previous poll*.

That temporal view closes the honesty gap the snapshot adapter leaves open: a
snapshot can only call a revise-pending claim ``UNRESOLVED``, but a feed watches it
**resolve** — an obligation that was ``UNRESOLVED`` in one poll becoming
``DISCHARGED`` (the revision passed) or ``FAILED`` (blocked) in the next is exactly
the obligation lifecycle unfolding over real time.

The source is dependency-injected: a running Phionyx process wires the live
``phionyx_session_report`` MCP tool as ``report_source``; the tests wire a
simulated evolving source. Boundary (honest): the feed observes whatever the source
reports; the directive->disposition mapping is a modelling choice; a ``PASS`` poll
means the current mapped bundle is a conserved lineage, not that the gate is itself
ENAS-conformant. A gate directive is a DECISION, not an observed enforcement effect,
so a directive-only feed reaches at most INCONCLUSIVE — a ``PASS`` poll additionally
requires the source to attest observed enforcement (report-level ``outcome_observed``).
Live wiring to a production gate and gate-native record emission remain
external-review-gated.
"""

from __future__ import annotations

from typing import Any, Callable

from enas_gate_adapter import _disposition, gate_report_to_bundle
from enas_obligation_reconciler import reconcile_obligation_bundle


# Map a reduced disposition back to a representative directive so the deduped report
# can be re-fed to the record-level adapter.
_DISPOSITION_DIRECTIVE = {"DISCHARGED": "pass", "FAILED": "block", "UNRESOLVED": "rewrite"}


def _reduce_claims(report: dict[str, Any]) -> tuple[dict[str, str], dict[str, dict[str, str | None]]]:
    """Reduce a report's claim entries to one disposition per stable claim IDENTITY.

    Identity is a STABLE ``claim_id``, never the claim text (P0-C). Two claims that
    share text but carry distinct ``claim_id``s are DISTINCT governed claims and must
    not collapse; a claim revised across attempts keeps ONE ``claim_id`` and is tracked
    as one lifecycle even if its text is edited. Text is the identity key only as a
    DEGRADED fallback — a fragile proxy the source should replace with a real id (the
    runtime already tracks one in ``contracts/v4/claim.py``).

    Identity mode is **all-or-nothing per report** (like the record adapter): claim_id
    is used only when EVERY dict claim carries a non-empty one, so id keys and
    text-fallback keys never share a namespace (a claim_id must never collide with a
    different claim's text). A report mixing id-bearing and id-less claims degrades to
    text keys for all, and does not thread ids downstream.

    Reduction rule: a hard **FAILED** (block/reject) is STICKY — it can never be masked
    by a later same-identity pass (that would launder a real failure). Otherwise the
    latest directive wins (a revise → pass is a legitimate resolution). Total over
    malformed input (non-dict report, non-list claims, non-dict entry, entries with no
    usable identity are skipped).

    Returns ``(dispositions, meta)``: ``dispositions`` maps identity_key -> reduced
    disposition; ``meta`` maps identity_key -> ``{"text", "claim_id"}`` (the latest
    representative text/id for that identity, used to rebuild the deduped report).
    """
    claims = report.get("claims") if isinstance(report, dict) else None
    if not isinstance(claims, list):
        claims = []
    dict_claims = [c for c in claims if isinstance(c, dict)]
    # all-or-nothing: only key by claim_id when every claim carries a non-empty one.
    use_ids = bool(dict_claims) and all(
        isinstance(c.get("claim_id"), str) and c.get("claim_id") for c in dict_claims
    )

    state: dict[str, str] = {}
    meta: dict[str, dict[str, str | None]] = {}
    for claim in dict_claims:
        cid = claim.get("claim_id")
        cid = cid if isinstance(cid, str) and cid else None
        text = claim.get("claim")
        text = text if isinstance(text, str) and text else None
        if use_ids and cid is not None:
            key, rep_text, rep_cid = cid, (text if text is not None else cid), cid
        elif not use_ids and text is not None:
            key, rep_text, rep_cid = text, text, None  # degraded: text as identity, no id threaded
        else:
            continue  # no usable identity
        directive = claim.get("directive")
        fate = _disposition(directive if isinstance(directive, str) else "")
        if fate == "FAILED":
            state[key] = "FAILED"  # sticky: a blocked claim stays failed
        elif state.get(key) != "FAILED":
            state[key] = fate  # latest non-failed disposition wins
        meta[key] = {"text": rep_text, "claim_id": rep_cid}  # latest representative
    return state, meta


class GateFeed:
    def __init__(self, report_source: Callable[[], dict[str, Any]]) -> None:
        self._source = report_source
        self._prev: dict[str, str] = {}  # claim IDENTITY (claim_id, else text) -> disposition, last poll
        self._mode: str | None = None  # identity namespace of the last non-empty poll: "id" | "text"
        self._polls = 0

    def poll(self) -> dict[str, Any]:
        """Resample the source, reconcile the current state, and report the delta.

        Returns ``{poll, global_verdict, dispositions, delta, reconciliation_errors}``.
        An empty report yields an INCONCLUSIVE poll rather than raising — a live feed
        must survive an empty sample.
        """
        self._polls += 1
        report = self._source()
        current, meta = _reduce_claims(report)  # claim IDENTITY -> reduced disposition (+ meta)

        if not current:
            # Distinguish two zero-claim cases:
            #  - a WELL-FORMED report with an (explicitly) empty claims list is a real
            #    observation of zero governed claims: any prior claims genuinely disappeared,
            #    so emit `disappeared` and reset the tracked state;
            #  - a malformed / missing sample is a NON-observation: preserve prior state and
            #    claim nothing (a missing sample is not evidence).
            # A real zero-claim observation is an EXPLICITLY empty claims list. A non-empty
            # list that reduced to {} (all entries malformed) is a malformed sample, not a
            # clean zero-claim observation — so it must NOT trigger disappearance/reset.
            observed = isinstance(report, dict) and report.get("claims") == []
            empty_delta = {k: [] for k in ("resolved", "regressed", "new_pending", "new_terminal", "still_pending", "disappeared")}
            if observed:
                empty_delta["disappeared"] = sorted(self._prev)
                self._prev = {}
            note = "gate report has zero governed claims" if observed else "gate report is a non-observation (malformed or missing sample)"
            return {
                "poll": self._polls,
                "global_verdict": "INCONCLUSIVE",
                "terminal_outcome": "ESCALATED",
                "reconciled": "INCONCLUSIVE",
                "dispositions": {},
                "delta": empty_delta,
                "reconciliation_errors": [note],
            }

        # Identity namespace (P0-C): "id" when this poll carried claim_ids, else "text". _delta
        # compares keys, so a poll whose namespace differs from the previous one cannot establish
        # continuity across it — comparing would falsely match a claim_id "x" to a text "x".
        # Reset instead: a mode switch honestly reads as the old identities disappearing and the
        # new ones appearing (with a reconciliation note), never as a spurious resolution.
        poll_mode = "id" if any(m["claim_id"] for m in meta.values()) else "text"
        mode_switch = self._mode is not None and poll_mode != self._mode
        if mode_switch:
            delta = self._delta({}, current)
            delta["disappeared"] = sorted(self._prev)
        else:
            delta = self._delta(self._prev, current)
        trace_id = report.get("trace_id") if isinstance(report, dict) else None
        # Rebuild one representative claim per identity, carrying the stable claim_id
        # through to the record-level adapter so obligation identity is id-bound (P0-C),
        # not positional. Falls back to the identity key as the statement when a claim
        # carried an id but no text.
        deduped = {
            "trace_id": trace_id or f"gate-poll-{self._polls}",
            "claims": [
                {
                    "claim": meta[key]["text"] or key,
                    "directive": _DISPOSITION_DIRECTIVE[disposition],
                    **({"claim_id": meta[key]["claim_id"]} if meta[key]["claim_id"] else {}),
                }
                for key, disposition in current.items()
            ],
        }
        # Enforcement is a MEASUREMENT, not a directive. Watching a claim's directive go
        # pass->pass over polls is still watching DECISIONS, not observed enforcement — so a
        # directive-only feed can no more reach PASS than the snapshot adapter can. Propagate
        # the source's own enforcement attestation (report-level `outcome_observed`) into the
        # deduped report; absent it, the adapter leaves the closure INCONCLUSIVE (never PASS).
        report_observed = report.get("outcome_observed")
        if isinstance(report_observed, bool):
            deduped["outcome_observed"] = report_observed
        bundle = gate_report_to_bundle(deduped)
        result = reconcile_obligation_bundle(bundle)
        prev_mode = self._mode
        self._prev = current
        self._mode = poll_mode
        errors = list(result["reconciliation_errors"])
        if mode_switch:
            errors.insert(0, f"identity namespace changed ({prev_mode}->{poll_mode}); continuity reset")
        # Two distinct verdicts, kept separate:
        #  - global_verdict: the GATE OUTCOME (closure) — did every obligation discharge AND
        #    was enforcement observed? PASS (all discharged + enforcement observed) /
        #    FAIL (any failed) / INCONCLUSIVE (revision-pending, OR enforcement not observed).
        #  - reconciled: the RECONCILER's structural integrity check on the mapped bundle;
        #    expected PASS for adapter output — anything else means a mapping/tamper defect.
        return {
            "poll": self._polls,
            "global_verdict": bundle["closure"]["global_verdict"],
            "terminal_outcome": bundle["closure"]["terminal_outcome"],
            "reconciled": result["global_verdict"],
            "dispositions": current,
            "delta": delta,
            "reconciliation_errors": errors,
        }

    @staticmethod
    def _delta(prev: dict[str, str], current: dict[str, str]) -> dict[str, list[str]]:
        terminal = {"DISCHARGED", "FAILED", "VALIDLY_REVOKED"}
        resolved = sorted(t for t, d in current.items() if prev.get(t) == "UNRESOLVED" and d in terminal)
        regressed = sorted(t for t, d in current.items() if prev.get(t) in terminal and d != prev.get(t))
        new_pending = sorted(t for t, d in current.items() if t not in prev and d == "UNRESOLVED")
        new_terminal = sorted(t for t, d in current.items() if t not in prev and d in terminal)
        still_pending = sorted(t for t, d in current.items() if prev.get(t) == "UNRESOLVED" and d == "UNRESOLVED")
        disappeared = sorted(t for t in prev if t not in current)
        return {
            "resolved": resolved,
            "regressed": regressed,
            "disappeared": disappeared,
            "new_pending": new_pending,
            "new_terminal": new_terminal,
            "still_pending": still_pending,
        }
