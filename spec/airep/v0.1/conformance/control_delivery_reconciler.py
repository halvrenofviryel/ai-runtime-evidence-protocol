#!/usr/bin/env python3
"""Bundle reconciler for the control_delivery profile — the RELATION a single record cannot carry.

`profiles/control_delivery.schema.json` makes each phase of one control instruction
separately recordable (issued / delivered / acknowledged / enforced / observed /
delivery_failed), each observed from ONE side of a boundary (issuer /
enforcement_point / witness). The schema validates one record. But the property a
standard requires here is a RELATION between records from two sides: an instruction
may not be treated as delivered unless an INDEPENDENT enforcement-side observation
confirms it. This module is that relation — the working construct behind the
standards contribution, not just the schema that states it.

Maps to APTS-HO-008 (OWASP APTS, Human Oversight; "Control Channel Delivery
Requirements", merged into OWASP:main 2026-07-30, PR #67 — text fetched from the
standard, not paraphrased from memory):
  - normative:  "An unacknowledged kill instruction MUST NOT be treated as delivered."
  - item 9:     end-to-end delivery across network / mount / namespace / container /
                privilege-separation / IPC boundaries  ->  the profile's `boundary` enum.
  - item 10:    an acknowledgement, enforcement result, or explicit delivery failure;
                the ABSENCE of all three triggers operator notification and
                default-safe handling  ->  the UNCONFIRMED verdict below.

Per-instruction status:
  DELIVERED     an enforcement_point (or witness) record attests acknowledged / enforced /
                observed for this instruction_id — independent confirmation exists.
  FAILED        a well-formed delivery_failed record exists (failure.reason present).
  UNCONFIRMED   only issuer-side records exist; per APTS-HO-008 this is default-safe =
                NOT delivered, and operator_notification_required = True.
  SUBSTITUTION  the same instruction_id appears with more than one instruction_hash —
                the sides did not see the same instruction.

global_verdict (ENAS outcome algebra):
  INCONCLUSIVE  a record is not schema-valid / missing a correlation field, or the bundle
                is not a well-formed {"records": [...]} — it cannot be reconciled.
  FAIL          a reconciliation rule is violated: SUBSTITUTION, or a delivery_failed
                record without an observed failure.reason.
  PASS          every instruction resolves to a determinate, correctly-derived status
                (including honestly UNCONFIRMED) with no reconciliation violation.

The reconciler is TOTAL over malformed input: it returns a verdict, never raises.
The guarantee the fixtures exercise: it NEVER returns DELIVERED for an instruction
lacking an independent enforcement-side observation. That is the APTS-HO-008
normative line, enforced by construction rather than asserted in prose.

Honest limit: no single side can prove non-delivery on its own — a receiver cannot
know what it never received. This reconciler makes the GAP between an issuer record
and a missing enforcement-side record legible; it does not, and cannot, decide from
records alone why an instruction did not arrive.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

try:  # jsonschema is optional; without it the semantic layer still runs
    from jsonschema import Draft202012Validator, FormatChecker
except Exception:  # pragma: no cover - exercised only when the dep is absent
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE.parent / "profiles" / "control_delivery.schema.json"
FIXTURE = HERE / "fixtures" / "control_delivery_cases.json"

# Independent confirmation that an instruction actually arrived comes from a
# non-issuer observer attesting one of these phases.
CONFIRMING_PHASES = {"acknowledged", "enforced", "observed"}
CONFIRMING_OBSERVERS = {"enforcement_point", "witness"}

# Closed enums mirrored from control_delivery.schema.json so the semantic layer is
# correct WITHOUT jsonschema — the join and derivation keys, and the fields the
# verdict reads, are checked here regardless of whether the optional validator ran.
VALID_PHASES = {"issued", "delivered", "acknowledged", "enforced", "observed", "delivery_failed"}
VALID_OBSERVERS = {"issuer", "enforcement_point", "witness"}
VALID_RESULTS = {"applied", "refused", "no_effect"}
VALID_BOUNDARIES = {"none", "mount", "namespace", "container", "network", "ipc", "privilege_separation", "other"}
HASH_RE = re.compile(r"^[a-z0-9-]+:[A-Fa-f0-9]+$")
# RFC 3339 date-time with a REQUIRED timezone (Z or numeric offset) — the profile
# of ISO-8601 the schema's `format: date-time` intends. Stricter than
# datetime.fromisoformat (which accepts date-only and timezone-less values).
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def _structural_errors(rec: dict[str, Any]) -> list[str]:
    """Bounded type/enum checks independent of jsonschema. Mirrors the schema's
    required fields and closed enums for exactly the fields the reconciler joins on
    or reads, so a schema-invalid record is INCONCLUSIVE in both runtime modes and
    the reconciler stays total (no field is dereferenced before its type is checked)."""
    errs: list[str] = []
    iid = rec.get("instruction_id")
    if not isinstance(iid, str) or not iid:
        errs.append("instruction_id must be a non-empty string")
    ihash = rec.get("instruction_hash")
    if not isinstance(ihash, str) or not HASH_RE.match(ihash):
        errs.append("instruction_hash must be a string of the form '<alg>:<hex>'")
    # isinstance-before-membership so an unhashable value (list/dict) is a clean
    # error, never a TypeError — the reconciler must stay total.
    phase = rec.get("phase")
    if not (isinstance(phase, str) and phase in VALID_PHASES):
        errs.append(f"phase must be one of {sorted(VALID_PHASES)}")
    observed_by = rec.get("observed_by")
    if not (isinstance(observed_by, str) and observed_by in VALID_OBSERVERS):
        errs.append(f"observed_by must be one of {sorted(VALID_OBSERVERS)}")
    observed_at = rec.get("observed_at")
    if not isinstance(observed_at, str) or not RFC3339_RE.match(observed_at):
        errs.append("observed_at must be an RFC 3339 date-time with a timezone (e.g. 2026-05-30T00:00:00Z)")
    if "result" in rec and not (isinstance(rec["result"], str) and rec["result"] in VALID_RESULTS):
        errs.append(f"result must be one of {sorted(VALID_RESULTS)}")
    if "boundary" in rec and not (isinstance(rec["boundary"], str) and rec["boundary"] in VALID_BOUNDARIES):
        errs.append(f"boundary must be one of {sorted(VALID_BOUNDARIES)}")
    if "failure" in rec and not isinstance(rec["failure"], dict):
        errs.append("failure must be an object")
    return errs


def _validator() -> Any:
    if Draft202012Validator is None:
        return None
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        return Draft202012Validator(schema, format_checker=FormatChecker())
    except Exception:
        # A missing/corrupt schema file degrades to the bounded structural layer,
        # which still enforces every verdict-driving field — never a crash.
        return None


def _schema_errors(validator: Any, doc: dict[str, Any]) -> list[str]:
    if validator is None:
        return []
    return [e.message for e in validator.iter_errors(doc)]


def _inconclusive(record_errors: dict[str, list[str]], recon: list[str]) -> dict[str, Any]:
    return {
        "global_verdict": "INCONCLUSIVE",
        "instructions": {},
        "record_errors": record_errors,
        "reconciliation_errors": recon,
    }


def reconcile_control_delivery_bundle(bundle: Any) -> dict[str, Any]:
    """Reconcile a set of control_delivery phase records into per-instruction status.

    Returns ``{"global_verdict", "instructions", "record_errors", "reconciliation_errors"}``.
    """
    record_errors: dict[str, list[str]] = {}
    recon: list[str] = []

    if not isinstance(bundle, dict):
        return _inconclusive(record_errors, ["bundle is not an object"])
    records = bundle.get("records")
    if not isinstance(records, list) or not records:
        return _inconclusive(record_errors, ["bundle is missing a non-empty 'records' list"])

    validator = _validator()
    groups: dict[str, list[dict[str, Any]]] = {}
    malformed = False
    for index, rec in enumerate(records):
        label = f"records[{index}]"
        if not isinstance(rec, dict):
            record_errors[label] = ["record is not an object"]
            malformed = True
            continue
        # schema layer (optional) + bounded structural layer (always) — a record
        # that fails either cannot be reconciled.
        errs = _schema_errors(validator, rec) + _structural_errors(rec)
        if errs:
            record_errors[label] = errs
            malformed = True
            continue
        groups.setdefault(rec["instruction_id"], []).append(rec)

    if malformed:
        # An invalid record cannot be reconciled — INCONCLUSIVE, never a silent FAIL/PASS.
        return _inconclusive(record_errors, recon)

    instructions: dict[str, dict[str, Any]] = {}
    for iid, recs in sorted(groups.items()):
        hashes = {r["instruction_hash"] for r in recs}
        if len(hashes) > 1:
            recon.append(
                f"{iid}: substitution — same instruction_id with differing instruction_hash {sorted(hashes)}"
            )
            instructions[iid] = {
                "status": "SUBSTITUTION",
                "default_safe": True,
                "operator_notification_required": True,
            }
            continue

        failed = [r for r in recs if r["phase"] == "delivery_failed"]
        if failed:
            for r in failed:
                reason = (r.get("failure") or {}).get("reason")
                if not reason:
                    recon.append(f"{iid}: delivery_failed recorded without an observed failure.reason")
            instructions[iid] = {
                "status": "FAILED",
                "default_safe": True,
                "operator_notification_required": False,
            }
            continue

        confirmed = [
            r for r in recs
            if r["phase"] in CONFIRMING_PHASES and r["observed_by"] in CONFIRMING_OBSERVERS
        ]
        if confirmed:
            enforced_result = next(
                (r.get("result") for r in recs if r["phase"] == "enforced"), None
            )
            instructions[iid] = {
                "status": "DELIVERED",
                "default_safe": False,
                "operator_notification_required": False,
                "enforced_result": enforced_result,  # 'no_effect' is delivered-but-ineffective, not failed
            }
        else:
            # Only issuer-side records. APTS-HO-008: MUST NOT be treated as delivered.
            instructions[iid] = {
                "status": "UNCONFIRMED",
                "default_safe": True,
                "operator_notification_required": True,
            }

    verdict = "FAIL" if recon else "PASS"
    return {
        "global_verdict": verdict,
        "instructions": instructions,
        "record_errors": record_errors,
        "reconciliation_errors": recon,
    }


def run_bundle_fixture(path: Path = FIXTURE) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    outcomes = []
    for case in fixture["cases"]:
        result = reconcile_control_delivery_bundle(case["bundle"])
        outcomes.append((case["name"], case, result))
    return outcomes


def main() -> int:
    failures = 0
    for name, case, result in run_bundle_fixture():
        want_verdict = case["expected"]
        got_verdict = result["global_verdict"]
        ok = got_verdict == want_verdict
        # optional per-instruction status assertions
        status_mismatch = []
        for iid, want_status in (case.get("expected_status") or {}).items():
            got_status = result["instructions"].get(iid, {}).get("status")
            if got_status != want_status:
                status_mismatch.append(f"{iid}: {got_status} (want {want_status})")
        if status_mismatch:
            ok = False
        flag = "" if ok else "  <-- MISMATCH"
        print(f"{name}: {got_verdict} (expected {want_verdict})"
              + (f" | status {status_mismatch}" if status_mismatch else "") + flag)
        if not ok:
            failures += 1
    if failures:
        print(f"\ncontrol_delivery reconciler: {failures} case(s) did not match expected", file=sys.stderr)
        return 1
    total = len(run_bundle_fixture())
    print(f"\ncontrol_delivery reconciler: {total} bundles matched expected verdicts + statuses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
