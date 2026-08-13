#!/usr/bin/env python3
"""Single-record check for the artifact_manifest profile — collection-time hashing, checked.

artifact_manifest.schema.json can require that each collected artifact carries a
digest, a collected_at, and its provenance. It cannot check two relations that make
the manifest trustworthy: that each artifact is identified UNIQUELY within the
manifest, and that no artifact claims to have been collected AFTER the decision it
supposedly informed. Given ONE full AIREP record, this module checks both.

  PASS          the manifest is well-formed (every artifact has a digest, a
                collected_at, a source and a collector), artifact_ids are unique,
                and — when the record carries subject.timestamp_utc — no artifact's
                collected_at postdates the decision.
  FAIL          a positive violation: a duplicate artifact_id, or an artifact
                collected AFTER subject.timestamp_utc (it could not have informed
                the decision).
  INCONCLUSIVE  cannot reconcile: the record or block is malformed / not
                schema-shaped.

TOTAL over malformed input (returns a verdict, never raises). Honest limit: the
digest establishes the artifact's CONTENT is unchanged since it was recorded; it
does NOT prove the digest was computed at the stated collected_at. When the record
has no subject.timestamp_utc, the temporal ordering is not asserted (result carries
temporal_checked=False) — the manifest is still structurally valid, since the
collection-time metadata it exists to carry is present. A subject.timestamp_utc that
is PRESENT but not a valid RFC 3339 date-time (or a non-object subject) is
INCONCLUSIVE, never a silent PASS — a malformed decision timestamp must not let an
artifact evade the collected-after-decision check.
"""
from __future__ import annotations

import re
from typing import Any

DIGEST_RE = re.compile(r"^[a-z0-9-]+:[A-Fa-f0-9]+$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
ARTIFACT_REQUIRED = ("artifact_id", "digest", "collected_at", "source", "collector")


def _result(verdict: str, errors: list[str], checked: int, temporal_checked: bool) -> dict[str, Any]:
    return {"verdict": verdict, "errors": errors, "artifacts_checked": checked,
            "temporal_checked": temporal_checked}


def _artifact_errors(index: int, art: Any) -> list[str]:
    """Bounded shape checks independent of jsonschema, for the fields the verdict reads."""
    if not isinstance(art, dict):
        return [f"artifacts[{index}] is not an object"]
    errs: list[str] = []
    for field in ARTIFACT_REQUIRED:
        if field not in art:
            errs.append(f"artifacts[{index}] missing required field: {field}")
    aid = art.get("artifact_id")
    if "artifact_id" in art and (not isinstance(aid, str) or not aid):
        errs.append(f"artifacts[{index}].artifact_id must be a non-empty string")
    digest = art.get("digest")
    if "digest" in art and (not isinstance(digest, str) or not DIGEST_RE.match(digest)):
        errs.append(f"artifacts[{index}].digest must be '<alg>:<hex>'")
    ca = art.get("collected_at")
    if "collected_at" in art and (not isinstance(ca, str) or not RFC3339_RE.match(ca)):
        errs.append(f"artifacts[{index}].collected_at must be an RFC 3339 date-time with a timezone")
    for field in ("source", "collector"):
        val = art.get(field)
        if field in art and (not isinstance(val, str) or not val):
            errs.append(f"artifacts[{index}].{field} must be a non-empty string")
    if "size_bytes" in art and not (isinstance(art["size_bytes"], int) and not isinstance(art["size_bytes"], bool) and art["size_bytes"] >= 0):
        errs.append(f"artifacts[{index}].size_bytes must be a non-negative integer")
    return errs


def check_artifact_manifest(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return _result("INCONCLUSIVE", ["record is not an object"], 0, False)
    profiles = record.get("profiles")
    block = profiles.get("artifact_manifest") if isinstance(profiles, dict) else None
    if not isinstance(block, dict):
        return _result("INCONCLUSIVE", ["no profiles.artifact_manifest block"], 0, False)

    manifest_id = block.get("manifest_id")
    errs: list[str] = []
    if not isinstance(manifest_id, str) or not manifest_id:
        errs.append("manifest_id must be a non-empty string")
    artifacts = block.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errs.append("artifacts must be a non-empty list")
        return _result("INCONCLUSIVE", errs, 0, False)
    for i, art in enumerate(artifacts):
        errs.extend(_artifact_errors(i, art))
    if errs:
        return _result("INCONCLUSIVE", errs, len(artifacts), False)

    # The temporal invariant consumes subject.timestamp_utc. Distinguish three states:
    #   absent            -> the invariant is simply not asserted (temporal_checked=False, PASS on structure)
    #   present + valid    -> check it
    #   present + invalid  -> the record is malformed in a field we rely on -> INCONCLUSIVE, never a
    #                         silent PASS that lets a bad decision timestamp evade the collected-after check
    subject = record.get("subject")
    if subject is not None and not isinstance(subject, dict):
        return _result("INCONCLUSIVE", ["subject must be an object when present"], len(artifacts), False)
    produced_at = subject.get("timestamp_utc") if isinstance(subject, dict) else None
    if produced_at is not None and not (isinstance(produced_at, str) and RFC3339_RE.match(produced_at)):
        return _result("INCONCLUSIVE",
                       ["subject.timestamp_utc is present but not an RFC 3339 date-time with a timezone"],
                       len(artifacts), False)
    temporal_checked = produced_at is not None

    failures: list[str] = []

    # unique artifact_id within the manifest
    seen: set[str] = set()
    for art in artifacts:
        aid = art["artifact_id"]
        if aid in seen:
            failures.append(f"duplicate artifact_id '{aid}' — an ambiguous collection, not two records of one artifact")
        seen.add(aid)

    # temporal: no artifact collected after the decision it supports
    if temporal_checked:
        decision_ts = _to_utc(produced_at)
        for art in artifacts:
            if _to_utc(art["collected_at"]) > decision_ts:
                failures.append(
                    f"artifact '{art['artifact_id']}' collected_at {art['collected_at']} postdates "
                    f"subject.timestamp_utc {produced_at} — it could not have informed the decision"
                )

    if failures:
        return _result("FAIL", failures, len(artifacts), temporal_checked)
    return _result("PASS", [], len(artifacts), temporal_checked)


def _to_utc(rfc3339: str):
    """Parse a regex-validated RFC 3339 string to an aware datetime for comparison."""
    from datetime import datetime

    return datetime.fromisoformat(rfc3339.replace("Z", "+00:00").replace("z", "+00:00"))
