#!/usr/bin/env python3
"""Single-record check for the evaluator_signature profile — the independence a schema can't assert.

evaluator_signature.schema.json can require that an attestation is well-formed. It
cannot establish the property that makes the attestation worth having: that the
EVALUATOR's key is DISTINCT from the PRODUCER's, and that the attestation is bound
to the exact record presented. Both are relations between the profile block and the
rest of the record. This module checks them.

Given ONE full AIREP record, it returns a verdict on its evaluator_signature block:

  PASS          the attestation is well-formed, bound to this record
                (signed_over == integrity.current), consistent in time
                (evaluated_at >= subject.timestamp_utc), and INDEPENDENT
                (evaluator_key_id differs from the producer's profiles.key_trust.key_id).
  FAIL          a positive violation: signed_over != integrity.current (the evaluator
                signed a different record); OR evaluator_key_id == the producer key
                (not independent — the whole point); OR evaluated_at precedes the
                record's own timestamp.
  INCONCLUSIVE  cannot reconcile: the record or the block is malformed / not
                schema-shaped, OR there is no profiles.key_trust.key_id to compare
                against, so independence cannot be ESTABLISHED (a bare distinct
                evaluator_id/key_id string is not proof of a distinct key without the
                producer key to compare it to).

The check is TOTAL over malformed input (returns a verdict, never raises) and never
reports PASS on an attestation whose independence it could not establish. Honest
limit: it does not re-verify the signature value (that needs the evaluator's public
key and a crypto routine) and does not prove the evaluator performed a competent
evaluation — only that a distinct key attested one, bound to this record.
"""
from __future__ import annotations

import re
from typing import Any

VALID_VERDICTS = {"concur", "dissent", "inconclusive"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# RFC 3339 date-time with a required timezone (matches the schema's format: date-time intent).
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
REQUIRED = ("evaluator_id", "evaluator_key_id", "signed_over", "verdict", "evaluated_at", "signature")


def _result(verdict: str, errors: list[str], independence: str) -> dict[str, Any]:
    return {"verdict": verdict, "errors": errors, "independence": independence}


def _structural_errors(block: dict[str, Any]) -> list[str]:
    """Bounded shape checks independent of jsonschema, for the fields the verdict reads."""
    errs: list[str] = []
    for field in REQUIRED:
        if field not in block:
            errs.append(f"missing required field: {field}")
    eid = block.get("evaluator_id")
    if "evaluator_id" in block and (not isinstance(eid, str) or not eid):
        errs.append("evaluator_id must be a non-empty string")
    ekid = block.get("evaluator_key_id")
    if "evaluator_key_id" in block and (not isinstance(ekid, str) or not ekid):
        errs.append("evaluator_key_id must be a non-empty string")
    so = block.get("signed_over")
    if "signed_over" in block and (not isinstance(so, str) or not SHA256_RE.match(so)):
        errs.append("signed_over must be 'sha256:<64 hex>'")
    verdict = block.get("verdict")
    if "verdict" in block and not (isinstance(verdict, str) and verdict in VALID_VERDICTS):
        errs.append(f"verdict must be one of {sorted(VALID_VERDICTS)}")
    ea = block.get("evaluated_at")
    if "evaluated_at" in block and (not isinstance(ea, str) or not RFC3339_RE.match(ea)):
        errs.append("evaluated_at must be an RFC 3339 date-time with a timezone")
    sig = block.get("signature")
    if "signature" in block:
        if not isinstance(sig, dict):
            errs.append("signature must be an object")
        else:
            if not isinstance(sig.get("alg"), str) or not sig.get("alg"):
                errs.append("signature.alg must be a non-empty string")
            if not isinstance(sig.get("value"), str) or not sig.get("value"):
                errs.append("signature.value must be a non-empty string")
    return errs


def check_evaluator_signature(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return _result("INCONCLUSIVE", ["record is not an object"], "unconfirmed")
    profiles = record.get("profiles")
    block = profiles.get("evaluator_signature") if isinstance(profiles, dict) else None
    if not isinstance(block, dict):
        return _result("INCONCLUSIVE", ["no profiles.evaluator_signature block"], "unconfirmed")

    errs = _structural_errors(block)
    if errs:
        return _result("INCONCLUSIVE", errs, "unconfirmed")

    integrity = record.get("integrity")
    current = integrity.get("current") if isinstance(integrity, dict) else None
    if not isinstance(current, str) or not SHA256_RE.match(current):
        return _result("INCONCLUSIVE",
                       ["record has no valid integrity.current to bind the attestation to"],
                       "unconfirmed")

    failures: list[str] = []

    # bound to THIS record
    if block["signed_over"] != current:
        failures.append(
            f"signed_over {block['signed_over']} != integrity.current {current} "
            "— the evaluator signed a different record than the one presented"
        )

    # independence: evaluator key vs producer key
    kt = profiles.get("key_trust") if isinstance(profiles, dict) else None
    producer_key = kt.get("key_id") if isinstance(kt, dict) else None
    if isinstance(producer_key, str) and producer_key:
        if producer_key == block["evaluator_key_id"]:
            failures.append(
                f"evaluator_key_id {block['evaluator_key_id']} == producer key_trust.key_id "
                "— an attestation by the producer's own key is not independent"
            )
        independence = "established"
    else:
        independence = "unconfirmed"  # no producer key to compare against

    # temporal consistency: evaluation cannot predate the record it evaluates
    subject = record.get("subject")
    produced_at = subject.get("timestamp_utc") if isinstance(subject, dict) else None
    if isinstance(produced_at, str) and RFC3339_RE.match(produced_at):
        if _to_utc(block["evaluated_at"]) < _to_utc(produced_at):
            failures.append(
                f"evaluated_at {block['evaluated_at']} precedes subject.timestamp_utc "
                f"{produced_at} — the record was evaluated before it was produced"
            )

    if failures:
        return _result("FAIL", failures, independence)
    if independence == "unconfirmed":
        return _result("INCONCLUSIVE",
                       ["independence cannot be established: no profiles.key_trust.key_id to "
                        "compare evaluator_key_id against"],
                       independence)
    return _result("PASS", [], independence)


def _to_utc(rfc3339: str):
    """Parse a regex-validated RFC 3339 string to an aware datetime for comparison."""
    from datetime import datetime

    return datetime.fromisoformat(rfc3339.replace("Z", "+00:00").replace("z", "+00:00"))
