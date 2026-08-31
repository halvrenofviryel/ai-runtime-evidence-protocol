#!/usr/bin/env python3
"""Minimal reference implementation for Agent Control Delivery Evidence Reconciliation.

This is a measurement reference, not an IETF or NIST implementation and not a wire
format. It intentionally uses a tiny JSON input model so the reconciliation semantics
can be tested without depending on AIREP, SCITT, OpenTelemetry, or any particular agent
protocol.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DISPOSITIONS = (
    "CONFIRMED",
    "EXPLICIT_FAILURE",
    "UNCONFIRMED",
    "SUBSTITUTION",
    "CONFLICT",
    "INVALID",
    "INDETERMINATE",
)

REQ = ("instruction_id", "attempt_id", "instruction_digest", "target_id", "target_boundary")


def _key(obj: dict[str, Any]) -> tuple[str, str, str]:
    return (obj["instruction_id"], obj["attempt_id"], obj["target_id"])


def _has_strings(obj: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(isinstance(obj.get(f), str) and bool(obj[f]) for f in fields)


def reconcile(case: dict[str, Any]) -> dict[str, Any]:
    population_closed = case.get("target_population_closed") is True
    obligations = case.get("obligations")
    receiver = case.get("receiver_observations", [])
    failures = case.get("failure_observations", [])

    if not isinstance(obligations, list) or not obligations:
        return {
            "population_closed": population_closed,
            "conservation_ok": False,
            "complete_delivery_claim_supported": False,
            "error": "missing non-empty obligations population",
        }

    r_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    f_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for rec in receiver:
        if isinstance(rec, dict) and _has_strings(rec, ("instruction_id", "attempt_id", "target_id")):
            r_by_key.setdefault(_key(rec), []).append(rec)
    for rec in failures:
        if isinstance(rec, dict) and _has_strings(rec, ("instruction_id", "attempt_id", "target_id")):
            f_by_key.setdefault(_key(rec), []).append(rec)

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for obl in obligations:
        if not isinstance(obl, dict) or not _has_strings(obl, REQ):
            results.append({"disposition": "INVALID", "reason": "malformed obligation"})
            continue

        key = _key(obl)
        if key in seen:
            results.append({
                "instruction_id": obl["instruction_id"],
                "attempt_id": obl["attempt_id"],
                "target_id": obl["target_id"],
                "disposition": "INVALID",
                "reason": "duplicate obligation key",
            })
            continue
        seen.add(key)

        if obl.get("binding_status") == "unresolved":
            disposition = "INDETERMINATE"
            reason = "required target/trust binding unresolved"
        else:
            recs = r_by_key.get(key, [])
            fails = f_by_key.get(key, [])
            valid_recs = [r for r in recs if r.get("native_verification") == "valid"]
            invalid_recs = [r for r in recs if r.get("native_verification") == "invalid"]
            indet_recs = [r for r in recs if r.get("native_verification") == "indeterminate"]

            matching = [
                r for r in valid_recs
                if r.get("instruction_digest") == obl["instruction_digest"]
                and r.get("target_boundary") == obl["target_boundary"]
                and r.get("event") == "received"
            ]
            mismatching_digest = [
                r for r in valid_recs
                if isinstance(r.get("instruction_digest"), str)
                and r.get("instruction_digest") != obl["instruction_digest"]
            ]
            mismatching_boundary = [
                r for r in valid_recs
                if isinstance(r.get("target_boundary"), str)
                and r.get("target_boundary") != obl["target_boundary"]
            ]
            valid_failures = [f for f in fails if f.get("native_verification") == "valid"]

            if matching and (mismatching_digest or mismatching_boundary or valid_failures):
                disposition = "CONFLICT"
                reason = "matching and incompatible applicable observations coexist"
            elif invalid_recs:
                disposition = "INVALID"
                reason = "applicable receiver evidence fails native verification"
            elif mismatching_digest:
                disposition = "SUBSTITUTION"
                reason = "receiver observation binds different instruction content"
            elif mismatching_boundary:
                disposition = "INDETERMINATE"
                reason = "receiver observation is not bound to the required target boundary"
            elif valid_failures:
                disposition = "EXPLICIT_FAILURE"
                reason = "positive attributable failure observation"
            elif matching:
                disposition = "CONFIRMED"
                reason = "receiver observation matches obligation"
            elif indet_recs:
                disposition = "INDETERMINATE"
                reason = "receiver evidence cannot be natively verified"
            else:
                disposition = "UNCONFIRMED"
                reason = "no qualifying receiver observation at cutoff"

        results.append({
            "instruction_id": obl.get("instruction_id"),
            "attempt_id": obl.get("attempt_id"),
            "target_id": obl.get("target_id"),
            "disposition": disposition,
            "reason": reason,
        })

    counts = Counter(r["disposition"] for r in results)
    for d in DISPOSITIONS:
        counts.setdefault(d, 0)

    conservation_ok = sum(counts.values()) == len(obligations)
    all_confirmed = counts["CONFIRMED"] == len(obligations)

    return {
        "population_closed": population_closed,
        "obligation_count": len(obligations),
        "counts": {d: counts[d] for d in DISPOSITIONS},
        "conservation_ok": conservation_ok,
        "measured_delivery_confirmation_fraction": (
            counts["CONFIRMED"] / len(obligations) if population_closed else None
        ),
        "complete_delivery_claim_supported": bool(
            population_closed and conservation_ok and all_confirmed
        ),
        "obligations": results,
        "claim_note": (
            "false means the available evidence does not support complete delivery; "
            "it does not by itself prove non-delivery"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--case", help="run only one named case")
    args = parser.parse_args()

    doc = json.loads(args.fixture.read_text(encoding="utf-8"))
    failures = 0

    for case in doc.get("cases", []):
        if args.case and case.get("name") != args.case:
            continue
        result = reconcile(case)
        expected = case.get("expected", {})
        ok = all(result.get(k) == v for k, v in expected.items())
        print(json.dumps({"name": case.get("name"), "ok": ok, "result": result}, indent=2))
        failures += 0 if ok else 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
