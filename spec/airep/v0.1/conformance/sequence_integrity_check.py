#!/usr/bin/env python3
"""Sequence integrity as a first-class, checkable property — contiguity + linkage + no truncation.

The AIREP core binds each record only to its immediate predecessor (integrity.previous
== the prior record's integrity.current): a RELATIVE binding. That leaves two gaps the
core's own THREAT_MODEL.md names as open — an index GAP mid-chain, and TAIL TRUNCATION
(dropping the last N records leaves a still-relatively-valid shorter chain). verify.py
checks decision_index == position as part of full record verification, and validate.py
demonstrates truncation detection for ONE committed witnessed vector; neither exposes
sequence integrity as a standalone property a reviewer can run over an arbitrary chain.
This module does.

Given a presented chain (a list of records), it checks:
  - CONTIGUITY: decision_index is 0, 1, 2, ... n-1 in order — a gap, a duplicate, or a
    reorder is a positive FAIL, not a silent pass.
  - LINKAGE: the first record's integrity.previous is GENESIS; each later record's
    integrity.previous equals the prior record's integrity.current.
  - NO TRUNCATION: when the tail record carries a chain_witness head length, the presented
    length must equal the witnessed length; a shorter presented chain is truncation.

  PASS          contiguous, linked, and (if a witness length is present) length matches.
  FAIL          a positive violation: index gap/duplicate/reorder, a broken previous-link,
                or a presented length that disagrees with the witnessed length.
  INCONCLUSIVE  the chain is malformed / not schema-shaped (not a non-empty list of records
                each carrying an integer decision_index and sha256 integrity.current/previous),
                so the sequence cannot be reconciled.

TOTAL over malformed input (returns a verdict, never raises).

Honest limit: this checks the sequence STRUCTURE — index contiguity, the previous-link
string matching, and presented-vs-witnessed length. It does NOT re-verify the content
hashes (verify.py does) or the witness signature. A matching previous-link string does not
prove the hash is cryptographically correct, and a witnessed length defends against
truncation only if the witness is signed by a key independent of the producer (the
chain_witness profile's own caveat). truncation_checked=False means no witness length was
present to compare against — contiguity/linkage still hold, but truncation is not asserted.
"""
from __future__ import annotations

import re
from typing import Any

GENESIS = "sha256:" + "0" * 64
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _result(verdict: str, errors: list[str], checked: int, truncation_checked: bool) -> dict[str, Any]:
    return {"verdict": verdict, "errors": errors, "records_checked": checked,
            "truncation_checked": truncation_checked}


def _record_shape_error(i: int, rec: Any) -> str | None:
    if not isinstance(rec, dict):
        return f"records[{i}] is not an object"
    subject = rec.get("subject")
    di = subject.get("decision_index") if isinstance(subject, dict) else None
    if not isinstance(di, int) or isinstance(di, bool) or di < 0:
        return f"records[{i}] has no non-negative integer subject.decision_index"
    integrity = rec.get("integrity")
    if not isinstance(integrity, dict):
        return f"records[{i}] has no integrity object"
    cur, prev = integrity.get("current"), integrity.get("previous")
    if not isinstance(cur, str) or not SHA256_RE.match(cur):
        return f"records[{i}].integrity.current is not a sha256 digest"
    if not isinstance(prev, str) or not SHA256_RE.match(prev):
        return f"records[{i}].integrity.previous is not a sha256 digest"
    return None


def _witness_length(rec: dict[str, Any]) -> Any:
    profiles = rec.get("profiles")
    cw = profiles.get("chain_witness") if isinstance(profiles, dict) else None
    head = cw.get("head") if isinstance(cw, dict) else None
    return head.get("length") if isinstance(head, dict) else None


def check_sequence_integrity(chain: Any) -> dict[str, Any]:
    if not isinstance(chain, list) or not chain:
        return _result("INCONCLUSIVE", ["chain must be a non-empty list of records"], 0, False)
    shape_errs = [e for e in (_record_shape_error(i, r) for i, r in enumerate(chain)) if e]
    if shape_errs:
        return _result("INCONCLUSIVE", shape_errs, len(chain), False)

    failures: list[str] = []

    # contiguity + order: decision_index must be exactly its position
    for i, rec in enumerate(chain):
        di = rec["subject"]["decision_index"]
        if di != i:
            failures.append(
                f"records[{i}] has decision_index {di}, expected {i} "
                "— a gap, duplicate, or reorder in the sequence"
            )

    # linkage: genesis at the head, each previous == prior current
    if chain[0]["integrity"]["previous"] != GENESIS:
        failures.append("records[0].integrity.previous is not the genesis value")
    for i in range(1, len(chain)):
        if chain[i]["integrity"]["previous"] != chain[i - 1]["integrity"]["current"]:
            failures.append(
                f"records[{i}].integrity.previous does not link to records[{i - 1}].integrity.current"
            )

    # no truncation: presented length must equal the witnessed length, when a witness is present
    witnessed = _witness_length(chain[-1])
    truncation_checked = isinstance(witnessed, int) and not isinstance(witnessed, bool)
    tail_profiles = chain[-1].get("profiles")
    witness_present = isinstance(tail_profiles, dict) and isinstance(tail_profiles.get("chain_witness"), dict)
    if witness_present and not truncation_checked:
        # a witness is present but its head length is missing/ill-typed: cannot reconcile the length claim
        return _result("INCONCLUSIVE",
                       ["tail record carries a chain_witness but no integer head.length to compare against"],
                       len(chain), False)
    if truncation_checked and witnessed != len(chain):
        failures.append(
            f"presented length {len(chain)} != witnessed head.length {witnessed} "
            + ("— tail truncation" if len(chain) < witnessed else "— length disagreement with the witness")
        )

    if failures:
        return _result("FAIL", failures, len(chain), truncation_checked)
    return _result("PASS", [], len(chain), truncation_checked)
