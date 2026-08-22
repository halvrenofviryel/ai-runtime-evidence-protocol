#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 WP-alpha01 integrity verifier (Python) — Stage 4.

This program is an *integrity verifier* (integrity-construction verifier): it
verifies the hash / record-signature / head-witness construction frozen in
``spec/airep/v0.2/INTEGRITY.md`` against the Stage-4 fixture corpus, and emits
normalized results per ``STAGE4_CONTRACT.md`` section 1. It is NOT a conformance
verifier for artifact schemas, profiles, or conformance classes.

Authoring basis (independence mandate, STAGE4_CONTRACT section 3): this file was
written from the frozen INTEGRITY.md, the stage4/ contract directory, the
Stage-3 public fixed vectors, and the pre-existing v0.1 RFC 8785 implementation
(``spec/airep/v0.1/conformance/jcs.py``, imported below) ONLY. It does not read,
import, call, or shell out to the corpus builder, the vector generators, the
comparators, or the Node integrity verifier or its output.

Evaluation uses each fixture's ``inputs`` member only. The ``expected`` member
is deleted immediately after JSON parse, before any evaluation, so it cannot
influence a verdict.

Output: ``../results/results_python.json`` =
``{"results": {"<fixture_id>": {"fixture_id", "verdict", "reasons"}}}``,
keys sorted, trailing newline, byte-deterministic, no metadata.

Exit code: 0 iff a normalized result was produced for every corpus fixture
(verdicts are data, not exit codes); nonzero only on harness failure.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# --- locations (relative to this file; no cwd dependence) ---------------------
_HERE = Path(__file__).resolve()
_STAGE4_DIR = _HERE.parents[1]                      # .../v0.2/stage4
_CORPUS_DIR = _STAGE4_DIR / "corpus"
_RESULTS_PATH = _STAGE4_DIR / "results" / "results_python.json"
_JCS_PATH = _HERE.parents[3] / "v0.1" / "conformance" / "jcs.py"

# --- RFC 8785 canonicalizer: reuse the pre-existing v0.1 implementation -------
_spec = importlib.util.spec_from_file_location("airep_v01_jcs", _JCS_PATH)
_jcs_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_jcs_mod)
jcs = _jcs_mod.canonicalize  # (obj) -> canonical UTF-8 bytes

# --- frozen construction constants (INTEGRITY.md sections 1, 3.1, 5) ----------
LF = b"\x0a"
SUPPORTED_WIRE_VERSION = "0.2"          # the only wire version this verifier implements
REGISTERED_CONTEXTS = ("decision", "control", "execution", "effect")  # closed registry, case-sensitive
SUPPORTED_SUITES = ("ed25519",)         # closed suite registry; the only suite implemented

# INTEGRITY section 4.2: witnessed_at is exactly YYYY-MM-DDTHH:MM:SSZ.
_TS_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$")
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


class _Reject(Exception):
    """Single-decisive-reason rejection (STAGE4_CONTRACT section 2a)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# --- timestamp handling (INTEGRITY section 4.2) -------------------------------
def _is_leap(y: int) -> bool:
    return (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)


def _parse_ts_strict(value):
    """Validate per INTEGRITY 4.2 (format regex AND real Gregorian calendar;
    hour 00-23, minute 00-59, second 00-59 — leap-second 60 forbidden).
    Returns seconds since an arbitrary fixed epoch, or None if invalid."""
    if not isinstance(value, str):
        return None
    m = _TS_RE.match(value)
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    if not (1 <= mo <= 12):
        return None
    dim = _DAYS_IN_MONTH[mo - 1] + (1 if (mo == 2 and _is_leap(y)) else 0)
    if not (1 <= d <= dim):
        return None
    if h > 23 or mi > 59 or s > 59:  # second 60 (leap second) is not permitted
        return None
    # days since 0001-01-01 (proleptic Gregorian), then seconds
    days = 0
    for yy in range(1, y):
        days += 366 if _is_leap(yy) else 365
    for mm in range(1, mo):
        days += _DAYS_IN_MONTH[mm - 1] + (1 if (mm == 2 and _is_leap(y)) else 0)
    days += d - 1
    return ((days * 24 + h) * 60 + mi) * 60 + s


# --- lexeme-preserving JSON numbers -------------------------------------------
# INTEGRITY 4.2's "no sign, no fraction, no exponent" for the claim's
# sequence/length is a LEXICAL constraint on the SOURCE SPELLING of the numeric
# token (STAGE4_CONTRACT 2a claim-structure step, numeric-lexeme hardening).
# Standard JSON parsing erases the spelling (1.0, 1e0, -0 all parse to a plain
# number), so fixtures are loaded with parse hooks that carry each numeric
# token's exact source lexeme alongside its value. The wrappers subclass
# int/float, so value semantics (equality, arithmetic, JCS canonicalization)
# are unchanged everywhere else in this program.
class _LexInt(int):
    """int whose JSON source token is retained (json.loads parse_int hook)."""

    lexeme: str

    def __new__(cls, lexeme: str):
        obj = super().__new__(cls, lexeme)
        obj.lexeme = lexeme
        return obj


class _LexFloat(float):
    """float whose JSON source token is retained (json.loads parse_float hook)."""

    lexeme: str

    def __new__(cls, lexeme: str):
        obj = super().__new__(cls, lexeme)
        obj.lexeme = lexeme
        return obj


# Valid source spellings for the claim's sequence/length members: "0" or a
# nonzero digit followed by digits. Anything else — sign, fraction, exponent —
# is a lexical violation.
_UINT_LEXEME_RE = re.compile(r"^(0|[1-9][0-9]*)$")


# --- helpers ------------------------------------------------------------------
def _json_value_equal(a, b) -> bool:
    """Equality of two JSON values as JSON values (bools are not numbers)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    return a == b


def _verify_ed25519(pubkey_hex, signature_hex, preimage: bytes) -> bool:
    """Pure Ed25519 (RFC 8032) over the raw preimage bytes. Fail closed: any
    malformed key/signature or verification error is False."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(signature_hex), preimage)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _wire_label_disagrees(wire_alg, suite_id: str) -> bool:
    """Caveat test only (never selects behaviour, INTEGRITY 3.2): does the
    unauthenticated wire algorithm label name a suite other than the
    binding-derived suite? The wire label is informative prose, not a canonical
    suite identifier, so a case variant of the same algorithm name (e.g.
    "Ed25519" for suite-id "ed25519") does not name a different suite; an
    absent label makes no statement and cannot disagree."""
    if wire_alg is None:
        return False
    if not isinstance(wire_alg, str):
        return True
    return wire_alg.lower() != suite_id


def _result(fixture_id: str, verdict: str, reasons) -> dict:
    return {
        "fixture_id": fixture_id,
        "verdict": verdict,
        "reasons": sorted(set(reasons)),  # dedup + ASCII-ascending
    }


# --- artifact path (STAGE4_CONTRACT 2a) ---------------------------------------
# version -> tag registry -> hash -> producer binding -> suite -> signature
#   -> optional wire-alg caveat
def _eval_artifact_path(inputs: dict) -> dict:
    artifact = inputs.get("artifact")
    if not isinstance(artifact, dict):
        # No artifact object at all: nothing declares a version -> fail closed
        # at the first step of the pinned precedence.
        raise _Reject("UNSUPPORTED_VERSION")

    # 1. version — declared airep_version absent/malformed/unsupported
    version = artifact.get("airep_version")
    if not isinstance(version, str) or version != SUPPORTED_WIRE_VERSION:
        raise _Reject("UNSUPPORTED_VERSION")

    # 2. tag registry — (airep_version, artifact_type) must map to a registered
    #    tag; the registry is closed and case-sensitive (INTEGRITY 1.2, 5).
    artifact_type = artifact.get("artifact_type")
    if not isinstance(artifact_type, str) or artifact_type not in REGISTERED_CONTEXTS:
        raise _Reject("UNREGISTERED_TAG")

    hash_tag = f"AIREP/{version}/hash/{artifact_type}"
    sig_tag = f"AIREP/{version}/sig/{artifact_type}"

    # 3. hash — mechanical subtraction per INTEGRITY 2, exactly these steps.
    body = json.loads(json.dumps(artifact))  # logical copy; artifact never mutated
    integrity = body.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("current", None)
        integrity.pop("signature", None)
    preimage = hash_tag.encode("ascii") + LF + jcs(body)
    computed_current = "sha256:" + sha256(preimage).hexdigest()

    wire_integrity = artifact.get("integrity")
    wire_current = wire_integrity.get("current") if isinstance(wire_integrity, dict) else None
    if not isinstance(wire_current, str) or wire_current != computed_current:
        raise _Reject("HASH_MISMATCH")

    # 4. producer binding — verifier-accepted key binding must be supplied;
    #    the wire alg label is never a substitute (REASON_CODES).
    binding = inputs.get("producer_binding")
    if not isinstance(binding, dict) or not isinstance(binding.get("public_key_hex"), str):
        raise _Reject("KEY_BINDING_UNAVAILABLE")

    # 5. suite — behaviour derives ONLY from the binding (INTEGRITY 3.2).
    suite = binding.get("suite")
    if suite not in SUPPORTED_SUITES:
        raise _Reject("SUITE_UNSUPPORTED")

    # 6. signature — sig preimage per INTEGRITY 3; pure Ed25519 over raw bytes.
    signature = wire_integrity.get("signature") if isinstance(wire_integrity, dict) else None
    sig_value = signature.get("value") if isinstance(signature, dict) else None
    sig_preimage = (
        sig_tag.encode("ascii") + LF + suite.encode("ascii") + LF + wire_current.encode("ascii")
    )
    if not isinstance(sig_value, str) or not _verify_ed25519(
        binding["public_key_hex"], sig_value, sig_preimage
    ):
        raise _Reject("SIGNATURE_INVALID")

    # 7. optional wire-alg caveat — only on an otherwise-passing result.
    caveats = []
    wire_alg = signature.get("alg") if isinstance(signature, dict) else None
    if _wire_label_disagrees(wire_alg, suite):
        caveats.append("WIRE_ALG_IGNORED")
    return {"caveats": caveats}


# --- witness path (STAGE4_CONTRACT 2a, fidelity-gate revision 2026-08-22) -----
# head resolve -> head version -> claim structure -> head reconcile
#   -> witnessed_at validity -> witness binding -> suite -> witness signature
#   -> freshness -> optional wire-alg caveat
_CLAIM_MEMBERS = frozenset(("chain_id", "sequence", "current", "length", "witnessed_at"))
_MAX_SAFE_INT = 2**53 - 1
_CURRENT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _is_lexical_uint(v) -> bool:
    """INTEGRITY 4.2 numeric constraint for the claim's sequence/length,
    enforced against the SOURCE TOKEN: the value must have been parsed from a
    lexeme spelled `0` or nonzero-digit-then-digits (no sign, no fraction, no
    exponent — a lexical constraint json value semantics cannot express), and
    must sit within the IEEE-754 safe integer range. Fail closed: a value
    without a captured lexeme never passes."""
    if isinstance(v, bool) or not isinstance(v, int):
        return False  # bools and fraction/exponent spellings (floats) fail
    lexeme = getattr(v, "lexeme", None)
    if not isinstance(lexeme, str) or _UINT_LEXEME_RE.match(lexeme) is None:
        return False
    return 0 <= v <= _MAX_SAFE_INT


def _eval_witness_path(inputs: dict) -> dict:
    witness = inputs["witness"]
    if not isinstance(witness, dict):
        raise _Reject("WITNESS_HEAD_UNRESOLVED")

    # 1. head resolve — witness.head_ref names the key in inputs.head_artifacts.
    head_ref = witness.get("head_ref")
    heads = inputs.get("head_artifacts")
    if (
        not isinstance(heads, dict)
        or not isinstance(head_ref, str)
        or head_ref not in heads
        or not isinstance(heads[head_ref], dict)
    ):
        raise _Reject("WITNESS_HEAD_UNRESOLVED")
    head = heads[head_ref]

    # 2. head version — the resolved head's airep_version must be a version
    #    this integrity verifier implements (v0.2: exactly "0.2"); the closed
    #    tag registry is enforced on the witness path too — never a
    #    cryptographic accept under another version's tag.
    head_version = head.get("airep_version")
    if not isinstance(head_version, str) or head_version != SUPPORTED_WIRE_VERSION:
        raise _Reject("UNSUPPORTED_VERSION")

    # 3. claim structure — the presented claim's member set is exactly the
    #    closed five of INTEGRITY 4, and the four non-time members satisfy
    #    their pinned 4.2 constraints. Extra members are never silently
    #    ignored and never silently included in a rebuilt claim: structure
    #    fails first. (witnessed_at time semantics are the dedicated step
    #    below — WITNESS_TIME_INVALID, never this code.)
    claim = witness.get("claim")
    if (
        not isinstance(claim, dict)
        or set(claim.keys()) != _CLAIM_MEMBERS
        or not isinstance(claim["chain_id"], str)
        or not _is_lexical_uint(claim["sequence"])            # non-negative safe integer, lexically unsigned-plain
        or not isinstance(claim["current"], str)
        or _CURRENT_RE.match(claim["current"]) is None        # exactly sha256: + 64 lowercase hex
        or not _is_lexical_uint(claim["length"])
        or claim["length"] < 1                                # positive safe integer
    ):
        raise _Reject("WITNESS_CLAIM_INVALID")

    # 4. head reconcile — claim chain_id/sequence/current against the resolved
    #    head's own members (INTEGRITY 4.3).
    head_integrity = head.get("integrity")
    head_current = head_integrity.get("current") if isinstance(head_integrity, dict) else None
    if not (
        _json_value_equal(claim["chain_id"], head.get("chain_id"))
        and _json_value_equal(claim["sequence"], head.get("sequence"))
        and _json_value_equal(claim["current"], head_current)
    ):
        raise _Reject("WITNESS_HEAD_MISMATCH")

    # 5. witnessed_at validity — INTEGRITY 4.2 time semantics.
    witnessed_epoch = _parse_ts_strict(claim["witnessed_at"])
    if witnessed_epoch is None:
        raise _Reject("WITNESS_TIME_INVALID")

    # 6. witness binding — a trust-store entry is verifier-accepted only when
    #    it explicitly carries trusted: true; a missing or non-true trusted
    #    member is fail-closed (no default-trust).
    store = inputs.get("witness_trust_store")
    witness_id = witness.get("witness_id")
    entry = store.get(witness_id) if isinstance(store, dict) and isinstance(witness_id, str) else None
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("public_key_hex"), str)
        or entry.get("trusted") is not True
    ):
        raise _Reject("KEY_BINDING_UNAVAILABLE")

    # 7. suite — solely from the trust-store binding (INTEGRITY 4.3).
    suite = entry.get("suite")
    if suite not in SUPPORTED_SUITES:
        raise _Reject("SUITE_UNSUPPORTED")

    # 8. witness signature — tag version equals the referenced head's declared
    #    airep_version (INTEGRITY 4.3; pinned to "0.2" by step 2); preimage per
    #    INTEGRITY 4 over JCS of the presented claim (exactly five members
    #    after step 3); no search of alternate versions, tags, suites, or v0.1
    #    constructions.
    signature = witness.get("signature")
    sig_value = signature.get("value") if isinstance(signature, dict) else None
    if not isinstance(sig_value, str):
        raise _Reject("WITNESS_SIGNATURE_INVALID")
    witness_tag = f"AIREP/{head_version}/sig/head-witness"
    preimage = witness_tag.encode("ascii") + LF + suite.encode("ascii") + LF + jcs(claim)
    if not _verify_ed25519(entry["public_key_hex"], sig_value, preimage):
        raise _Reject("WITNESS_SIGNATURE_INVALID")

    # 9. freshness — ONLY the signed witnessed_at, against the fixture-supplied
    #    deterministic clock and window (INTEGRITY 4.1; unsigned freshness
    #    fields never enter this decision). A signed timestamp in the future
    #    beyond the window is also stale (REASON_CODES).
    now_epoch = _parse_ts_strict(inputs.get("now"))
    window = inputs.get("freshness_window_seconds")
    if now_epoch is None or isinstance(window, bool) or not isinstance(window, (int, float)):
        raise RuntimeError("harness failure: fixture-supplied now/window invalid")
    if abs(now_epoch - witnessed_epoch) > window:
        raise _Reject("WITNESS_STALE")

    # 10. optional wire-alg caveat — the wire-carried witness algorithm label
    #     is informative only.
    caveats = []
    wire_alg = signature.get("alg") if isinstance(signature, dict) else None
    if _wire_label_disagrees(wire_alg, suite):
        caveats.append("WIRE_ALG_IGNORED")
    return {"caveats": caveats}


# --- per-fixture evaluation ---------------------------------------------------
def evaluate_fixture(fixture: dict) -> dict:
    fixture_id = fixture["fixture_id"]
    inputs = fixture["inputs"]
    try:
        # Fixture kind rule (corpus_manifest / FIXTURES.md): inputs.witness
        # present => witness-path fixture; otherwise artifact-path fixture.
        if "witness" in inputs:
            outcome = _eval_witness_path(inputs)
        else:
            outcome = _eval_artifact_path(inputs)
    except _Reject as rej:
        # A REJECT carries exactly ONE reason: the first decisive failure.
        return _result(fixture_id, "REJECT", [rej.code])
    caveats = outcome["caveats"]
    if caveats:
        return _result(fixture_id, "PASS_WITH_CAVEAT", caveats)
    return _result(fixture_id, "PASS", ["OK"])


# --- harness ------------------------------------------------------------------
def main() -> int:
    fixture_files = sorted(_CORPUS_DIR.glob("*.json"))
    if not fixture_files:
        print(f"harness failure: no fixtures found in {_CORPUS_DIR}", file=sys.stderr)
        return 3

    results = {}
    for path in fixture_files:
        try:
            with path.open("r", encoding="utf-8") as fh:
                # parse hooks surface each numeric token's exact source lexeme
                # (required for the claim-structure lexical constraint).
                fixture = json.load(fh, parse_int=_LexInt, parse_float=_LexFloat)
            # Non-consultation guarantee: drop the expected member before any
            # evaluation. Verdicts derive from "inputs" only.
            fixture.pop("expected", None)
            fixture_id = fixture.get("fixture_id")
            if not isinstance(fixture_id, str) or fixture_id in results:
                print(f"harness failure: bad/duplicate fixture_id in {path.name}", file=sys.stderr)
                return 3
            results[fixture_id] = evaluate_fixture(fixture)
        except Exception as exc:  # noqa: BLE001 — a fixture without a result is a harness failure
            print(f"harness failure on {path.name}: {exc}", file=sys.stderr)
            return 3

    if len(results) != len(fixture_files):
        print("harness failure: result count != fixture count", file=sys.stderr)
        return 3

    _RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _RESULTS_PATH.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump({"results": results}, fh, sort_keys=True, indent=1, ensure_ascii=False)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
