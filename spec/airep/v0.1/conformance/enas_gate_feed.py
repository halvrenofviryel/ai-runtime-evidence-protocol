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
ENAS-conformant. Live wiring to a production gate and gate-native record emission
remain external-review-gated.
"""

from __future__ import annotations

from typing import Any, Callable

from enas_gate_adapter import _disposition, gate_report_to_bundle
from enas_obligation_reconciler import reconcile_obligation_bundle


# Map a reduced disposition back to a representative directive so the deduped report
# can be re-fed to the record-level adapter.
_DISPOSITION_DIRECTIVE = {"DISCHARGED": "pass", "FAILED": "block", "UNRESOLVED": "rewrite"}


def _reduce_claims(report: dict[str, Any]) -> dict[str, str]:
    """Reduce a report's claim entries to one disposition per claim text.

    A live gate report lists every gate call, including successive revisions of the
    same claim. Reduction rule: a hard **FAILED** (block/reject) is STICKY — it can
    never be masked by a later same-text pass (that would launder a real failure).
    Otherwise the latest directive wins (a revise → pass is a legitimate resolution).
    Total over malformed input (non-dict report, non-list claims, non-dict entry,
    non-string text/directive are skipped).
    """
    state: dict[str, str] = {}
    claims = report.get("claims") if isinstance(report, dict) else None
    if not isinstance(claims, list):
        claims = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        text = claim.get("claim")
        if not isinstance(text, str) or not text:
            continue
        directive = claim.get("directive")
        fate = _disposition(directive if isinstance(directive, str) else "")
        if fate == "FAILED":
            state[text] = "FAILED"  # sticky: a blocked claim stays failed
        elif state.get(text) != "FAILED":
            state[text] = fate  # latest non-failed disposition wins
    return state


class GateFeed:
    def __init__(self, report_source: Callable[[], dict[str, Any]]) -> None:
        self._source = report_source
        self._prev: dict[str, str] = {}  # claim text -> disposition, from the last poll
        self._polls = 0

    def poll(self) -> dict[str, Any]:
        """Resample the source, reconcile the current state, and report the delta.

        Returns ``{poll, global_verdict, dispositions, delta, reconciliation_errors}``.
        An empty report yields an INCONCLUSIVE poll rather than raising — a live feed
        must survive an empty sample.
        """
        self._polls += 1
        report = self._source()
        current = _reduce_claims(report)  # claim text -> reduced disposition

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

        delta = self._delta(self._prev, current)
        trace_id = report.get("trace_id") if isinstance(report, dict) else None
        deduped = {
            "trace_id": trace_id or f"gate-poll-{self._polls}",
            "claims": [{"claim": text, "directive": _DISPOSITION_DIRECTIVE[disposition]} for text, disposition in current.items()],
        }
        bundle = gate_report_to_bundle(deduped)
        result = reconcile_obligation_bundle(bundle)
        self._prev = current
        # Two distinct verdicts, kept separate:
        #  - global_verdict: the GATE OUTCOME (closure) — did every obligation discharge?
        #    PASS (all discharged) / FAIL (any failed) / INCONCLUSIVE (revision-pending).
        #  - reconciled: the RECONCILER's structural integrity check on the mapped bundle;
        #    expected PASS for adapter output — anything else means a mapping/tamper defect.
        return {
            "poll": self._polls,
            "global_verdict": bundle["closure"]["global_verdict"],
            "terminal_outcome": bundle["closure"]["terminal_outcome"],
            "reconciled": result["global_verdict"],
            "dispositions": current,
            "delta": delta,
            "reconciliation_errors": result["reconciliation_errors"],
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
