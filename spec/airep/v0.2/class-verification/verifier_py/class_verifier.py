#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 class verifier (Python reference implementation).

Implements CLASS_VERIFIER_CONTRACT.md sections 0-6, section 8 and the normative
section 9 source-review errata (E-1..E-6) over the FROZEN INTEGRITY.md
constructions and the accepted CONFORMANCE_CLASS_DESIGN.md semantics.

The frozen byte constructions are consumed exactly as written; nothing here
re-designs them:

  * hash preimage        -> ``hash_preimage`` / ``compute_current``      (INTEGRITY 2)
  * record-sig preimage  -> ``record_sig_preimage``                      (INTEGRITY 3)
  * head-witness preimage-> ``witness_sig_preimage``                     (INTEGRITY 4)

Exit codes (contract 6.4): 0 evaluation completed; 1 unparseable request /
artifact / operator file or stage-0/1 artifact invalidity; 2 CLI usage or
config error; --help exits 0 with nothing evaluated.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# --------------------------------------------------------------------------
# JCS (RFC 8785) canonicalizer -- loaded from the REPOSITORY, not from PyPI.
#
# The canonical bytes AIREP hashes over are defined by the repository's own
# frozen canonicalizer at <repo>/spec/airep/v0.1/conformance/jcs.py. A bare
# `import jcs` resolved to whatever happened to be installed in the authoring
# environment, so the verifier could not execute from the committed repository
# without an out-of-band package download. It is now loaded deterministically
# by explicit relative path, resolved against THIS file's location so the
# working directory never matters. Public API consumed here: `canonicalize(obj)
# -> bytes` (that module's documented stable surface). Nothing is vendored and
# no copy is made: the single repository file is the one source of those bytes.
# --------------------------------------------------------------------------

JCS_RELPATH = (os.pardir, os.pardir, os.pardir, "v0.1", "conformance", "jcs.py")


def _load_repo_jcs():
    path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), *JCS_RELPATH)
    )
    spec = importlib.util.spec_from_file_location("airep_v0_1_jcs", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load the repository JCS canonicalizer at %s" % path)
    module = importlib.util.module_from_spec(spec)
    # Loading by path would otherwise drop a __pycache__ next to a FROZEN file.
    # The verifier writes nothing into the frozen tree.
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    if not callable(getattr(module, "canonicalize", None)):
        raise ImportError("%s does not expose canonicalize()" % path)
    return module


jcs = _load_repo_jcs()

# --------------------------------------------------------------------------
# Frozen registries (INTEGRITY 1.2, 3.1)
# --------------------------------------------------------------------------

WIRE_VERSION = "0.2"
ARTIFACT_CONTEXTS = ("decision", "control", "execution", "effect")
HASH_TAGS = {f"AIREP/{WIRE_VERSION}/hash/{c}" for c in ARTIFACT_CONTEXTS}
SIG_TAGS = {f"AIREP/{WIRE_VERSION}/sig/{c}" for c in ARTIFACT_CONTEXTS}
WITNESS_TAG_CONTEXT = "head-witness"
SUITE_REGISTRY = {"ed25519"}

LF = b"\x0a"

# --------------------------------------------------------------------------
# Closed reason registry (contract 5). reason -> (tier, kind)
# --------------------------------------------------------------------------

REASON_REGISTRY: Dict[str, Tuple[str, str]] = {
    "producer-binding-missing": ("authenticated", "WITHHELD"),
    "producer-binding-not-trusted": ("authenticated", "FAILURE"),
    "producer-binding-malformed": ("authenticated", "WITHHELD"),
    "producer-suite-unsupported": ("authenticated", "WITHHELD"),
    "producer-revocation-state-missing": ("authenticated", "WITHHELD"),
    "producer-revocation-state-malformed": ("authenticated", "WITHHELD"),
    "producer-binding-revoked": ("authenticated", "FAILURE"),
    "producer-signature-invalid": ("authenticated", "FAILURE"),
    "producer-key-self-revoked": ("authenticated", "CAVEAT"),
    "wire-alg-mismatch": ("authenticated", "CAVEAT"),
    "no-witness-supplied": ("witnessed", "WITHHELD"),
    "witness-binding-missing": ("witnessed", "WITHHELD"),
    "witness-binding-not-trusted": ("witnessed", "FAILURE"),
    "witness-binding-malformed": ("witnessed", "WITHHELD"),
    "witness-suite-unsupported": ("witnessed", "WITHHELD"),
    "witness-revocation-state-missing": ("witnessed", "WITHHELD"),
    "witness-revocation-state-malformed": ("witnessed", "WITHHELD"),
    "independence-policy-missing": ("witnessed", "WITHHELD"),
    "independence-policy-malformed": ("witnessed", "WITHHELD"),
    "independence-relation-absent": ("witnessed", "WITHHELD"),
    "freshness-inputs-missing": ("witnessed", "WITHHELD"),
    "witness-binding-revoked": ("witnessed", "FAILURE"),
    "witness-head-unresolved": ("witnessed", "FAILURE"),
    "witness-head-mismatch": ("witnessed", "FAILURE"),
    "witness-claim-invalid": ("witnessed", "FAILURE"),
    "witness-identity-not-distinct": ("witnessed", "FAILURE"),
    "witness-key-not-distinct": ("witnessed", "FAILURE"),
    "independence-explicitly-denied": ("witnessed", "FAILURE"),
    "witness-signature-invalid": ("witnessed", "FAILURE"),
    "witness-time-invalid": ("witnessed", "FAILURE"),
    "witness-freshness-outside-window": ("witnessed", "FAILURE"),
}

CLASS_CORE = "AIREP-Core"
CLASS_AUTHENTICATED = "AIREP-Authenticated"
CLASS_WITNESSED = "AIREP-Witnessed"

# --------------------------------------------------------------------------
# Grammars
# --------------------------------------------------------------------------

RE_NAMESPACED = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$")
RE_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RE_PUBKEY = re.compile(r"^[0-9a-f]{64}$")
RE_SIGVALUE = re.compile(r"^[0-9a-f]{128}$")
# INTEGRITY 4.2: witnessed_at is exactly YYYY-MM-DDTHH:MM:SSZ.
RE_WITNESSED_AT = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$")
# Contract 1.4: --now is YYYY-MM-DDTHH:MM:SS(.1-9)?Z
RE_NOW = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$"
)
# Errata E-1: INTEGRITY 4.2's "no sign, no fraction, no exponent" constrains the
# SOURCE SPELLING of the claim's numeric tokens, not merely the parsed value.
RE_JSON_UINT_LEXEME = re.compile(r"^(0|[1-9][0-9]*)$")

MAX_SAFE_INT = 9007199254740991


class RunInvalid(Exception):
    """Exit-1 condition: nothing parseable / no verdict producible."""


class UsageError(Exception):
    """Exit-2 condition: CLI usage or config error."""


# --------------------------------------------------------------------------
# (a) FROZEN HASH CONSTRUCTION  -- INTEGRITY 2 + 5
# --------------------------------------------------------------------------

def hash_tag(airep_version: str, artifact_type: str) -> str:
    """Tag selection is a function, never a search (INTEGRITY 5)."""
    tag = "AIREP/" + airep_version + "/hash/" + artifact_type
    if tag not in HASH_TAGS:
        raise RunInvalid("unregistered hash tag context: %r" % tag)
    return tag


def sig_tag(airep_version: str, artifact_type: str) -> str:
    tag = "AIREP/" + airep_version + "/sig/" + artifact_type
    if tag not in SIG_TAGS:
        raise RunInvalid("unregistered sig tag context: %r" % tag)
    return tag


def hash_preimage(artifact: dict) -> bytes:
    """tag-bytes LF jcs-bytes, with integrity.current + integrity.signature deleted."""
    tag = hash_tag(artifact["airep_version"], artifact["artifact_type"])
    body = copy.deepcopy(artifact)          # the artifact itself is never mutated
    integrity = body.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("current", None)
        integrity.pop("signature", None)
    return tag.encode("ascii") + LF + jcs.canonicalize(body)


def compute_current(artifact: dict) -> str:
    return "sha256:" + hashlib.sha256(hash_preimage(artifact)).hexdigest()


# --------------------------------------------------------------------------
# (b) FROZEN RECORD-SIGNATURE PREIMAGE  -- INTEGRITY 3
#     sig-tag-bytes LF suite-id-bytes LF current-bytes
#     suite-id comes from the verifier-accepted BINDING, never the wire alg (3.2).
# --------------------------------------------------------------------------

def record_sig_preimage(airep_version: str, artifact_type: str, suite_id: str, current: str) -> bytes:
    return (
        sig_tag(airep_version, artifact_type).encode("ascii")
        + LF
        + suite_id.encode("ascii")
        + LF
        + current.encode("ascii")
    )


# --------------------------------------------------------------------------
# (c) FROZEN HEAD-WITNESS PREIMAGE  -- INTEGRITY 4
#     "AIREP/<version>/sig/head-witness" LF suite-id-bytes LF jcs-claim-bytes
#     <version> equals the airep_version of the REFERENCED HEAD ARTIFACT (4.3).
# --------------------------------------------------------------------------

def witness_sig_preimage(head_airep_version: str, suite_id: str, claim: dict) -> bytes:
    tag = "AIREP/" + head_airep_version + "/sig/" + WITNESS_TAG_CONTEXT
    if head_airep_version != WIRE_VERSION:
        raise RunInvalid("unregistered witness tag version: %r" % tag)
    return tag.encode("ascii") + LF + suite_id.encode("ascii") + LF + jcs.canonicalize(claim)


def ed25519_verify(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """No search, no fallback: one key, one suite, one preimage."""
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    try:
        key.verify(sig, message)
    except (InvalidSignature, Exception):  # noqa: BLE001 - fail closed on anything
        return False
    return True


def verify_suite_signature(suite_id: str, public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    if suite_id == "ed25519":
        return ed25519_verify(public_key_hex, signature_hex, message)
    return False


# --------------------------------------------------------------------------
# Stage 0 -- accepted family schema validation
# --------------------------------------------------------------------------

_SCHEMA_CACHE: Dict[str, Any] = {}


def _load_schemas(schema_dir: str):
    if "validators" in _SCHEMA_CACHE:
        return _SCHEMA_CACHE["validators"]
    import jsonschema
    from referencing import Registry, Resource

    docs = {}
    for name in ("common", "decision", "control", "execution", "effect"):
        path = os.path.join(schema_dir, name + ".schema.json")
        with open(path, "rb") as fh:
            docs[name] = json.loads(fh.read().decode("utf-8"))

    registry = Registry()
    for name, doc in docs.items():
        registry = registry.with_resource(doc["$id"], Resource.from_contents(doc))

    validators = {}
    for name in ("decision", "control", "execution", "effect"):
        cls = jsonschema.validators.validator_for(docs[name])
        validators[name] = cls(docs[name], registry=registry)
    _SCHEMA_CACHE["validators"] = validators
    return validators


def schema_validate(artifact: Any, schema_dir: str) -> None:
    """Raise RunInvalid when the artifact is not a well-formed v0.2 artifact."""
    if not isinstance(artifact, dict):
        raise RunInvalid("artifact is not a JSON object")
    atype = artifact.get("artifact_type")
    if not isinstance(atype, str) or atype not in ARTIFACT_CONTEXTS:
        raise RunInvalid("unknown artifact_type: %r" % (atype,))
    validator = _load_schemas(schema_dir)[atype]
    errors = sorted(validator.iter_errors(artifact), key=lambda e: list(e.path))
    if errors:
        raise RunInvalid("schema validation failed: %s" % errors[0].message)


# --------------------------------------------------------------------------
# Operator inputs (contract 1)
# --------------------------------------------------------------------------

def _read_json_file(path: str, what: str) -> Tuple[Any, bytes]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RunInvalid("cannot read %s file %s: %s" % (what, path, exc))
    try:
        return json.loads(raw.decode("utf-8")), raw
    except (ValueError, UnicodeDecodeError) as exc:
        raise RunInvalid("cannot parse %s file %s: %s" % (what, path, exc))


# Contract 1.1 shape, closed and required (errata E-4).
BINDING_STORE_MEMBERS = {"bindings", "producer_bindings", "witness_bindings"}
BINDING_ENTRY_MEMBERS = {"subject_identity", "role", "public_key_hex", "suite", "trusted"}


def _digest_of(raw: Optional[bytes]) -> Optional[str]:
    """(h) evidence digests: SHA-256 of the exact operator input FILE BYTES."""
    if raw is None:
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class OperatorInputs:
    def __init__(self) -> None:
        self.bindings_doc: Optional[Any] = None
        self.bindings_digest: Optional[str] = None
        self.independence_doc: Optional[Any] = None
        self.independence_digest: Optional[str] = None
        self.revocation_doc: Optional[Any] = None
        self.revocation_digest: Optional[str] = None
        self.now: Optional[str] = None
        self.window: Optional[int] = None

    # ---- binding store -------------------------------------------------
    def _binding_maps(self) -> Tuple[Optional[dict], Optional[dict], Optional[dict]]:
        """Errata E-4: the store's container members are REQUIRED and its
        members are CLOSED. A missing container, an unknown member at the top
        level, or an unknown member in any `bindings` entry makes the whole
        document malformed -- fail closed, never silently tolerated."""
        doc = self.bindings_doc
        if not isinstance(doc, dict):
            return None, None, None
        if set(doc.keys()) != BINDING_STORE_MEMBERS:
            return None, None, None
        b = doc.get("bindings")
        p = doc.get("producer_bindings")
        w = doc.get("witness_bindings")
        if not (isinstance(b, dict) and isinstance(p, dict) and isinstance(w, dict)):
            return None, None, None
        for entry in b.values():
            if not isinstance(entry, dict) or set(entry.keys()) - BINDING_ENTRY_MEMBERS:
                return None, None, None
        return b, p, w

    def lookup_binding(self, role: str, wire_id: Any) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
        """Resolve a wire-carried id to an accepted binding.

        Returns (binding_id, entry, reason_suffix). reason_suffix is one of
        'binding-missing' / 'binding-not-trusted' / 'binding-malformed' /
        'suite-unsupported', or None when the binding is accepted.
        """
        # Section 9 R-8, sub-step 7a -- WIRE-ID USABILITY PRECEDES STORE
        # RESOLUTION. With no usable wire id the verifier has not determined
        # WHICH binding it would evaluate, so the store-resolution gate (7b) is
        # never reached: an absent or non-string id is `*-binding-missing`
        # (WITHHELD) even when the store itself is malformed. The producer path
        # resolves its own wire id -- `subject.producer` is schema-required and
        # typed `string`, established at stage 0 -- so it always reaches 7b and
        # can still report `producer-binding-malformed` on the same store.
        if not isinstance(wire_id, str):
            return None, None, "binding-missing"
        if self.bindings_doc is None:
            return None, None, "binding-missing"
        # 7b: store resolution, then the referenced entry (R-3 governs inside).
        # A WELL-FORMED store with no map entry for a usable id stays
        # `*-binding-missing` here -- that is 7b, distinct from 7a above.
        bindings, producer_map, witness_map = self._binding_maps()
        role_map = producer_map if role == "producer" else witness_map
        if bindings is None or role_map is None:
            return None, None, "binding-malformed"
        if wire_id not in role_map:
            return None, None, "binding-missing"
        binding_id = role_map[wire_id]
        if not isinstance(binding_id, str) or binding_id not in bindings:
            return None, None, "binding-malformed"
        entry = bindings[binding_id]
        # Entry type and member closure were already established document-wide
        # by _binding_maps (errata E-4); a malformed store never reaches here.

        # Section 9 R-3: structural malformation PRECEDES the semantic trust
        # decision. `*-binding-not-trusted` applies only when the input is
        # structurally valid and `trusted` is present but not literally `true`,
        # so every *-binding-malformed test runs first.
        if not RE_NAMESPACED.match(binding_id):
            return binding_id, entry, "binding-malformed"
        if "trusted" not in entry:
            return binding_id, entry, "binding-malformed"
        subject_identity = entry.get("subject_identity")
        if not isinstance(subject_identity, str) or not RE_NAMESPACED.match(subject_identity):
            return binding_id, entry, "binding-malformed"
        if entry.get("role") != role:
            return binding_id, entry, "binding-malformed"
        pk = entry.get("public_key_hex")
        if not isinstance(pk, str) or not RE_PUBKEY.match(pk):
            return binding_id, entry, "binding-malformed"
        suite = entry.get("suite")
        if not isinstance(suite, str):
            return binding_id, entry, "binding-malformed"

        # The entry is structurally valid: now the operator policy's definitive
        # negative (R-3), which still precedes the suite registry.
        if entry["trusted"] is not True:
            return binding_id, entry, "binding-not-trusted"

        if suite not in SUITE_REGISTRY:
            return binding_id, entry, "suite-unsupported"
        return binding_id, entry, None

    # ---- revocation snapshot -------------------------------------------
    def revocation_state(self, binding_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Returns (state, reason_suffix). Snapshot model: no timestamps (design 4)."""
        doc = self.revocation_doc
        if doc is None:
            return None, "revocation-state-missing"
        if not isinstance(doc, dict) or set(doc.keys()) - {"snapshot_id", "bindings"}:
            return None, "revocation-state-malformed"
        snapshot_id = doc.get("snapshot_id")
        if not isinstance(snapshot_id, str) or not RE_NAMESPACED.match(snapshot_id):
            return None, "revocation-state-malformed"
        table = doc.get("bindings")
        if not isinstance(table, dict):
            return None, "revocation-state-malformed"
        if binding_id not in table:
            return None, "revocation-state-missing"
        entry = table[binding_id]
        if not isinstance(entry, dict) or set(entry.keys()) - {"state"}:
            return None, "revocation-state-malformed"
        state = entry.get("state")
        if state not in ("active", "revoked"):
            return None, "revocation-state-malformed"
        return state, None

    # ---- independence policy -------------------------------------------
    def independence_policy(self) -> Tuple[Optional[str], Optional[set], Optional[set]]:
        """Returns (reason, independent_set, non_independent_set)."""
        doc = self.independence_doc
        if doc is None:
            return "independence-policy-missing", None, None
        if not isinstance(doc, dict) or set(doc.keys()) - {"independent_pairs", "non_independent_pairs"}:
            return "independence-policy-malformed", None, None
        pos, neg = set(), set()
        for key, sink in (("independent_pairs", pos), ("non_independent_pairs", neg)):
            if key not in doc:
                return "independence-policy-malformed", None, None
            arr = doc[key]
            if not isinstance(arr, list):
                return "independence-policy-malformed", None, None
            for item in arr:
                if not isinstance(item, dict) or set(item.keys()) != {"a", "b"}:
                    return "independence-policy-malformed", None, None
                a, b = item["a"], item["b"]
                for endpoint in (a, b):
                    if not isinstance(endpoint, str) or not RE_NAMESPACED.match(endpoint):
                        return "independence-policy-malformed", None, None
                sink.add(frozenset((a, b)))
        if pos & neg:                       # a pair in both lists: fail closed
            return "independence-policy-malformed", None, None
        return None, pos, neg


# --------------------------------------------------------------------------
# Reference resolution (contract 0)
# --------------------------------------------------------------------------

def resolve_reference(ref: Any, candidates: List[dict]) -> Tuple[Optional[dict], str]:
    """Zero matches -> unresolved; more than one -> ambiguous, fail closed."""
    if not isinstance(ref, dict):
        return None, "unresolved"
    record_id = ref.get("record_id")
    chain_id = ref.get("chain_id")
    if not isinstance(record_id, str):
        return None, "unresolved"
    matches = []
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        if cand.get("record_id") != record_id:
            continue
        if chain_id is not None and cand.get("chain_id") != chain_id:
            continue
        matches.append(cand)
    if len(matches) != 1:
        return None, "unresolved"
    return matches[0], "ok"


# --------------------------------------------------------------------------
# Head-witness claim structural validation (INTEGRITY 4.2, five members)
# --------------------------------------------------------------------------

CLAIM_MEMBERS = {"chain_id", "sequence", "current", "length", "witnessed_at"}

CLAIM_NUMERIC_MEMBERS = ("sequence", "length")


def _is_json_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _LexemeInt(int):
    """int carrying the exact source token it was parsed from (errata E-1)."""

    lexeme: str

    def __new__(cls, token: str) -> "_LexemeInt":
        obj = super().__new__(cls, int(token))
        obj.lexeme = token
        return obj


class _LexemeFloat(float):
    """float carrying the exact source token it was parsed from (errata E-1)."""

    lexeme: str

    def __new__(cls, token: str) -> "_LexemeFloat":
        obj = super().__new__(cls, float(token))
        obj.lexeme = token
        return obj


def claim_numeric_lexemes(raw: bytes) -> Dict[str, Optional[str]]:
    """Re-derive the SOURCE SPELLING of the claim's numeric tokens (errata E-1).

    Ordinary ``json.loads`` erases the spelling (``1e0``, ``1.0``, ``-0`` all
    parse to a number), so the request bytes are re-parsed once with
    ``parse_int``/``parse_float`` hooks that keep each number's exact source
    token. Only the head-witness claim's numeric members are read back; the
    lexeme-bearing document is never used anywhere else, so JCS canonical bytes
    and every other code path stay untouched.

    A member whose lexeme cannot be recovered (absent, or not a JSON number)
    maps to ``None``, which the structural gate treats as a lexical violation.
    """
    lexemes: Dict[str, Optional[str]] = {name: None for name in CLAIM_NUMERIC_MEMBERS}
    try:
        doc = json.loads(raw.decode("utf-8"), parse_int=_LexemeInt, parse_float=_LexemeFloat)
    except (ValueError, UnicodeDecodeError):
        return lexemes
    if not isinstance(doc, dict):
        return lexemes
    head_witness = doc.get("head_witness")
    if not isinstance(head_witness, dict):
        return lexemes
    claim = head_witness.get("claim")
    if not isinstance(claim, dict):
        return lexemes
    for name in CLAIM_NUMERIC_MEMBERS:
        value = claim.get(name)
        if isinstance(value, (_LexemeInt, _LexemeFloat)):
            lexemes[name] = value.lexeme
    return lexemes


def claim_structurally_valid(claim: Any, lexemes: Optional[Dict[str, Optional[str]]]) -> bool:
    """Intrinsic claim defects only -> `witness-claim-invalid` (errata E-1/E-5).

    `witnessed_at` is type-checked here; its format and Gregorian validity are a
    separate stage-6 gate reported as `witness-time-invalid` (errata E-2).
    """
    if not isinstance(claim, dict) or set(claim.keys()) != CLAIM_MEMBERS:
        return False
    if not isinstance(claim["chain_id"], str):
        return False
    seq = claim["sequence"]
    if not _is_json_int(seq) or seq < 0 or seq > MAX_SAFE_INT:
        return False
    cur = claim["current"]
    if not isinstance(cur, str) or not RE_SHA256.match(cur):
        return False
    length = claim["length"]
    if not _is_json_int(length) or length < 1 or length > MAX_SAFE_INT:
        return False
    if not isinstance(claim["witnessed_at"], str):
        return False
    # E-1: the parsed value passing is not sufficient -- the source spelling of
    # each numeric token MUST itself match ^(0|[1-9][0-9]*)$. No source bytes
    # available means the lexical rule could not be applied: fail closed.
    if lexemes is None:
        return False
    for name in CLAIM_NUMERIC_MEMBERS:
        lexeme = lexemes.get(name)
        if not isinstance(lexeme, str) or not RE_JSON_UINT_LEXEME.match(lexeme):
            return False
    return True


def claim_time_structurally_valid(claim: Any) -> bool:
    """E-2: `witnessed_at` format + Gregorian validity, evaluated at stage 6
    independently of whether clock inputs were supplied."""
    if not isinstance(claim, dict):
        return False
    value = claim.get("witnessed_at")
    if not isinstance(value, str):
        return False
    return parse_witnessed_at_ns(value) is not None


_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _valid_gregorian(y: int, mo: int, d: int, h: int, mi: int, s: int) -> bool:
    if not 1 <= mo <= 12:
        return False
    dim = _DAYS_IN_MONTH[mo - 1]
    if mo == 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)):
        dim = 29
    if not 1 <= d <= dim:
        return False
    # Leap second value 60 is not permitted in v0.2.
    return 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Howard Hinnant's days_from_civil; proleptic Gregorian, no library clamping."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_witnessed_at_ns(value: str) -> Optional[int]:
    m = RE_WITNESSED_AT.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    if not _valid_gregorian(y, mo, d, h, mi, s):
        return None
    return (_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s) * 1_000_000_000


def parse_now_ns(value: str) -> Optional[int]:
    m = RE_NOW.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    if not _valid_gregorian(y, mo, d, h, mi, s):
        return None
    frac = m.group(7) or ""
    nanos = int((frac + "000000000")[:9]) if frac else 0
    return (_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s) * 1_000_000_000 + nanos


# --------------------------------------------------------------------------
# Evaluation request envelope (contract 0) -- closed object
# --------------------------------------------------------------------------

def parse_request(doc: Any) -> Tuple[dict, List[dict], Optional[dict]]:
    if not isinstance(doc, dict):
        raise RunInvalid("evaluation request is not a JSON object")
    if set(doc.keys()) - {"artifact", "related_artifacts", "head_witness"}:
        raise RunInvalid("evaluation request carries unknown members (closed envelope)")
    artifact = doc.get("artifact")
    if not isinstance(artifact, dict):
        raise RunInvalid("evaluation request has no artifact object")
    related = doc.get("related_artifacts", [])
    if not isinstance(related, list) or any(not isinstance(a, dict) for a in related):
        raise RunInvalid("related_artifacts is not an array of objects")
    # Section 9 R-7: the ONLY optional thing at this level is the `head_witness`
    # OBJECT. Its absence is `no-witness-supplied`; a present-but-null or
    # non-object value is run-invalid; a member FOREIGN to the harness is
    # run-invalid. Absence of a KNOWN member is NOT run-invalid -- it is a
    # semantic evidence failure/withholding reported by the stage that needs it
    # (claim -> 6a, head_ref -> 6b, witness_id -> 7, signature -> 9). `is None`
    # would conflate an explicit `null` with absence, so membership is tested.
    hw = None
    if "head_witness" in doc:
        hw = doc["head_witness"]
        if not isinstance(hw, dict):
            raise RunInvalid("head_witness is present but not a JSON object")
        if set(hw.keys()) - {"head_ref", "witness_id", "claim", "signature"}:
            raise RunInvalid("head_witness carries unknown members (closed envelope)")
        # R-4 (unchanged): closure applies to `head_ref` and `signature` WHEN
        # PRESENT AS OBJECTS. It creates no requiredness, and a non-object value
        # is a semantic defect for its own stage, never harness closure.
        if isinstance(hw.get("head_ref"), dict) and set(hw["head_ref"].keys()) - {"record_id", "chain_id"}:
            raise RunInvalid("head_witness.head_ref carries unknown members (closed envelope)")
        if isinstance(hw.get("signature"), dict) and set(hw["signature"].keys()) - {"alg", "value"}:
            raise RunInvalid("head_witness.signature carries unknown members (closed envelope)")
    return artifact, related, hw


# --------------------------------------------------------------------------
# Authentication of an arbitrary artifact (used by the observer path)
# --------------------------------------------------------------------------

def authenticate_artifact(artifact: dict, ops: OperatorInputs, schema_dir: str) -> Tuple[bool, Optional[str], Optional[dict]]:
    """Verify one artifact to Authenticated in its own right (contract 0).

    Schema, frozen hash recomputation, producer binding, revocation snapshot and
    signature. Emits no reasons: this is the observer path's yes/no question.
    """
    try:
        schema_validate(artifact, schema_dir)
    except RunInvalid:
        return False, None, None
    try:
        if compute_current(artifact) != artifact["integrity"]["current"]:
            return False, None, None
    except (RunInvalid, KeyError, TypeError, ValueError):
        return False, None, None
    binding_id, entry, reason = ops.lookup_binding("producer", artifact.get("subject", {}).get("producer"))
    if reason is not None or entry is None or binding_id is None:
        return False, binding_id, entry
    state, rev_reason = ops.revocation_state(binding_id)
    if rev_reason is not None or state != "active":
        return False, binding_id, entry
    try:
        preimage = record_sig_preimage(
            artifact["airep_version"], artifact["artifact_type"], entry["suite"],
            artifact["integrity"]["current"],
        )
    except RunInvalid:
        return False, binding_id, entry
    ok = verify_suite_signature(
        entry["suite"], entry["public_key_hex"],
        artifact["integrity"]["signature"].get("value", ""), preimage,
    )
    return bool(ok), binding_id, entry


# --------------------------------------------------------------------------
# (e) THE THREE-CONDITION INDEPENDENCE GATE (design 3 / contract 1.2)
# --------------------------------------------------------------------------

def independence_conditions(
    entry_a: dict, binding_id_a: str, entry_b: dict, binding_id_b: str,
    positive: Optional[set], negative: Optional[set],
) -> Tuple[bool, bool, Optional[str]]:
    """Returns (identities_distinct, keys_distinct, relation).

    relation is 'independent' | 'denied' | 'absent' | None (policy unusable).
    All three conditions must hold for independence; absence is unproven,
    never independent.
    """
    identities_distinct = entry_a.get("subject_identity") != entry_b.get("subject_identity")
    keys_distinct = entry_a.get("public_key_hex") != entry_b.get("public_key_hex")
    if positive is None or negative is None:
        return identities_distinct, keys_distinct, None
    pair = frozenset((binding_id_a, binding_id_b))
    if pair in negative:
        return identities_distinct, keys_distinct, "denied"
    if pair in positive:
        return identities_distinct, keys_distinct, "independent"
    return identities_distinct, keys_distinct, "absent"


# --------------------------------------------------------------------------
# (d) STAGE ORDER + REASON DEPENDENCY DAG (contract 3 + 4)
# --------------------------------------------------------------------------

def evaluate(request_doc: Any, ops: OperatorInputs, schema_dir: str,
             claim_lexemes: Optional[Dict[str, Optional[str]]] = None) -> dict:
    """`claim_lexemes` carries the head-witness claim's numeric SOURCE tokens
    (errata E-1); omitting it fails the lexical rule closed."""
    artifact, related, head_witness = parse_request(request_doc)

    # ---- Stage 0: accepted family schema validation --------------------
    schema_validate(artifact, schema_dir)   # RunInvalid -> exit 1, no class

    # ---- Stage 1: Core, frozen hash/domain-tag recomputation -----------
    try:
        recomputed = compute_current(artifact)
    except (TypeError, ValueError) as exc:
        raise RunInvalid("hash recomputation failed: %s" % exc)
    if recomputed != artifact["integrity"]["current"]:
        raise RunInvalid("integrity.current does not match the recomputed hash preimage")

    klass = CLASS_CORE
    auth_failures: List[str] = []
    auth_withheld: List[str] = []
    auth_caveats: List[str] = []
    wit_failures: List[str] = []
    wit_withheld: List[str] = []

    def emit(reason: str) -> None:
        tier, kind = REASON_REGISTRY[reason]
        if tier == "authenticated":
            target = {"FAILURE": auth_failures, "WITHHELD": auth_withheld, "CAVEAT": auth_caveats}[kind]
        else:
            target = {"FAILURE": wit_failures, "WITHHELD": wit_withheld}[kind]
        if reason not in target:
            target.append(reason)

    # ================= AUTHENTICATED TIER ==============================
    # Stage 2: producer binding resolution. Prerequisites: none.
    p_binding_id, p_entry, p_reason = ops.lookup_binding(
        "producer", artifact.get("subject", {}).get("producer")
    )
    producer_binding_accepted = p_reason is None
    if p_reason is not None:
        emit("producer-" + p_reason)

    # Stage 3: producer revocation. Prerequisite: producer binding accepted.
    producer_revoked = False
    producer_revocation_clean = False
    if producer_binding_accepted:
        state, rev_reason = ops.revocation_state(p_binding_id)
        if rev_reason is not None:
            emit("producer-" + rev_reason)
        elif state == "revoked":
            producer_revoked = True
            emit("producer-binding-revoked")
        else:
            producer_revocation_clean = True

    # Stage 4: producer signature over the frozen record-signature preimage.
    # Prerequisite: producer binding accepted AND not revoked.
    if producer_binding_accepted and not producer_revoked:
        try:
            preimage = record_sig_preimage(
                artifact["airep_version"], artifact["artifact_type"],
                p_entry["suite"], artifact["integrity"]["current"],
            )
            sig_ok = verify_suite_signature(
                p_entry["suite"], p_entry["public_key_hex"],
                artifact["integrity"]["signature"].get("value", ""), preimage,
            )
        except (RunInvalid, KeyError, TypeError, ValueError):
            sig_ok = False
        if not sig_ok:
            emit("producer-signature-invalid")

    # Stage 5: Authenticated iff 2-4 all clean.
    authenticated = (
        producer_binding_accepted
        and producer_revocation_clean
        and not auth_failures
        and not auth_withheld
    )
    if authenticated:
        klass = CLASS_AUTHENTICATED
        # Caveat sources are pinned, not inferred (contract 5).
        profiles = artifact.get("profiles")
        if isinstance(profiles, dict):
            kt = profiles.get("airep.key-trust")
            if isinstance(kt, dict):
                rev = kt.get("revocation")
                if isinstance(rev, dict) and rev.get("revoked") is True:
                    emit("producer-key-self-revoked")
        wire_alg = artifact["integrity"]["signature"].get("alg")
        if isinstance(wire_alg, str) and wire_alg.lower() != p_entry["suite"].lower():
            emit("wire-alg-mismatch")

    # ================= WITNESSED TIER (runs diagnostically) =============
    stage6_clean = False
    head_artifact: Optional[dict] = None
    claim: Any = None

    if head_witness is None:
        emit("no-witness-supplied")
    else:
        claim = head_witness.get("claim")
        # Stage 6 is ONE gate with three DEPENDENT sub-steps (section 9 R-2):
        # shape -> resolution/reconciliation -> time. Exactly one of them may
        # report; a failing sub-step suppresses the ones after it. Shape and
        # time therefore never both report.
        #
        # 6a. frozen five-member claim shape + numeric SOURCE LEXEMES (E-1).
        claim_ok = claim_structurally_valid(claim, claim_lexemes)
        if not claim_ok:
            emit("witness-claim-invalid")
        else:
            # 6b. head resolution, must-be-primary, reconciliation (R-2/R-5).
            candidates = [artifact] + related
            # R-7: an absent / non-object / record_id-less head_ref reaches
            # resolve_reference as a non-reference and is `unresolved`.
            resolved, status = resolve_reference(head_witness.get("head_ref"), candidates)
            if status != "ok":
                # zero matches or ambiguous: fail closed, same reason
                emit("witness-head-unresolved")
            elif resolved is not artifact:
                # The witness must witness THIS artifact (contract 0).
                emit("witness-head-mismatch")
            elif (
                claim["chain_id"] != artifact.get("chain_id")
                or claim["sequence"] != artifact.get("sequence")
                or claim["current"] != artifact["integrity"]["current"]
            ):
                emit("witness-head-mismatch")
            # 6c. witnessed_at format + Gregorian validity (E-2, sequenced by
            # R-2). Runs only after 6a and 6b are clean. Clock inputs play no
            # part in this check.
            elif not claim_time_structurally_valid(claim):
                emit("witness-time-invalid")
            else:
                head_artifact = resolved
                stage6_clean = True

    # Stage 7: witness binding + revocation. Prerequisite: stage 6 clean.
    w_binding_id: Optional[str] = None
    w_entry: Optional[dict] = None
    stage7_clean = False
    if stage6_clean:
        w_binding_id, w_entry, w_reason = ops.lookup_binding(
            "witness", head_witness.get("witness_id")
        )
        if w_reason is not None:
            emit("witness-" + w_reason)
        else:
            state, rev_reason = ops.revocation_state(w_binding_id)
            if rev_reason is not None:
                emit("witness-" + rev_reason)
            elif state == "revoked":
                emit("witness-binding-revoked")
            else:
                stage7_clean = True

    # Stage 8: independence. Prerequisites: producer binding accepted AND
    # stage 7 clean AND independence policy present.
    if producer_binding_accepted and stage7_clean:
        policy_reason, positive, negative = ops.independence_policy()
        if policy_reason is not None:
            emit(policy_reason)
        ident_ok, keys_ok, relation = independence_conditions(
            p_entry, p_binding_id, w_entry, w_binding_id, positive, negative
        )
        if not ident_ok:
            emit("witness-identity-not-distinct")
        if not keys_ok:
            emit("witness-key-not-distinct")
        if relation == "denied":
            emit("independence-explicitly-denied")
        elif relation == "absent":
            emit("independence-relation-absent")

    # Stage 9: witness signature. Prerequisite: stage 7 clean.
    if stage7_clean:
        # R-7: an absent or non-object `signature`, and an absent or wrong-typed
        # `signature.value`, are all `witness-signature-invalid` -- never
        # run-invalid, and never a silent pass.
        sig_obj = head_witness.get("signature")
        sig_value = sig_obj.get("value") if isinstance(sig_obj, dict) else None
        if not isinstance(sig_value, str):
            wsig_ok = False
        else:
            try:
                preimage = witness_sig_preimage(
                    head_artifact["airep_version"], w_entry["suite"], claim
                )
                wsig_ok = verify_suite_signature(
                    w_entry["suite"], w_entry["public_key_hex"], sig_value, preimage,
                )
            except (RunInvalid, KeyError, TypeError, ValueError):
                wsig_ok = False
        if not wsig_ok:
            emit("witness-signature-invalid")

    # Stage 10: RECENCY ONLY (errata E-2 -- witnessed_at's format and Gregorian
    # validity are settled at stage 6). Prerequisites: stage 6 clean AND clock
    # inputs present; stage-6 cleanliness already guarantees a parseable value.
    if stage6_clean:
        if ops.now is None or ops.window is None:
            emit("freshness-inputs-missing")
        else:
            witnessed_ns = parse_witnessed_at_ns(claim["witnessed_at"])
            now_ns = parse_now_ns(ops.now)
            # abs(now - witnessed_at) <= window; boundary-equal is fresh.
            if abs(now_ns - witnessed_ns) > ops.window * 1_000_000_000:
                emit("witness-freshness-outside-window")

    # Stage 11: Witnessed iff 6-10 clean AND Authenticated earned.
    if authenticated and not wit_failures and not wit_withheld:
        klass = CLASS_WITNESSED

    # ================= observer assessment (contract 0/3, design 7) =====
    observer = "not_applicable"
    if artifact["artifact_type"] == "effect":
        declared = artifact.get("observer_relationship")
        if declared == "independent":
            observer = "unknown"
            exec_artifact, status = resolve_reference(
                artifact.get("execution_ref"), [artifact] + related
            )
            if status == "ok" and exec_artifact is not None:
                exec_ok, x_binding_id, x_entry = authenticate_artifact(
                    exec_artifact, ops, schema_dir
                )
                # Errata E-3: authenticating the referenced Execution artifact
                # is NECESSARY BUT NOT SUFFICIENT -- the primary Effect artifact
                # must itself have earned Authenticated before a wire
                # `independent` can be the effective assessment.
                if exec_ok and authenticated and x_entry is not None:
                    _, positive, negative = ops.independence_policy()
                    ident_ok, keys_ok, relation = independence_conditions(
                        p_entry, p_binding_id, x_entry, x_binding_id, positive, negative
                    )
                    if ident_ok and keys_ok and relation == "independent":
                        observer = "independent"
        elif declared in ("same_executor", "unknown"):
            observer = declared
        else:
            observer = "unknown"

    verdict = {
        "artifact_ref": {
            "chain_id": artifact.get("chain_id"),
            "record_id": artifact.get("record_id"),
        },
        "class": klass,
        "authenticated_failures": sorted(set(auth_failures)),
        "authenticated_withheld": sorted(set(auth_withheld)),
        "authenticated_caveats": sorted(set(auth_caveats)),
        "witnessed_failures": sorted(set(wit_failures)),
        "witnessed_withheld": sorted(set(wit_withheld)),
        "observer_assessment": observer,
        "evidence": {
            "now": ops.now,
            "freshness_window_seconds": ops.window,
            "bindings_digest": ops.bindings_digest,
            "independence_policy_digest": ops.independence_digest,
            "revocation_digest": ops.revocation_digest,
        },
    }
    _assert_invariants(verdict)
    return verdict


def _assert_invariants(v: dict) -> None:
    """Contract 2 consistency invariants -- the verifier MUST satisfy them."""
    klass = v["class"]
    assert klass in (CLASS_CORE, CLASS_AUTHENTICATED, CLASS_WITNESSED), klass
    for channel in (
        "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
        "witnessed_failures", "witnessed_withheld",
    ):
        arr = v[channel]
        assert arr == sorted(set(arr)), channel
        for r in arr:
            assert r in REASON_REGISTRY, r
            tier, kind = REASON_REGISTRY[r]
            assert channel.startswith(tier), (channel, r)
            assert kind == {
                "failures": "FAILURE", "withheld": "WITHHELD", "caveats": "CAVEAT",
            }[channel.rsplit("_", 1)[1]], (channel, r)
    if v["authenticated_failures"] or v["authenticated_withheld"]:
        assert klass == CLASS_CORE
    if v["witnessed_failures"] or v["witnessed_withheld"]:
        assert klass != CLASS_WITNESSED
    if v["authenticated_caveats"]:
        assert klass != CLASS_CORE
    if klass == CLASS_WITNESSED:
        assert not v["authenticated_failures"] and not v["authenticated_withheld"]
        assert not v["witnessed_failures"] and not v["witnessed_withheld"]
    assert v["observer_assessment"] in (
        "same_executor", "independent", "unknown", "not_applicable",
    )


# --------------------------------------------------------------------------
# (g) UTF-8 BYTE ORDERING for the results array (contract 2)
# --------------------------------------------------------------------------

def verdict_sort_key(verdict: dict) -> Tuple[bytes, bytes]:
    """Unsigned lexicographic order over each string's UTF-8 bytes; no NFC/NFD."""
    ref = verdict["artifact_ref"]
    chain_id = ref.get("chain_id")
    record_id = ref.get("record_id")
    return (
        (chain_id or "").encode("utf-8"),
        (record_id or "").encode("utf-8"),
    )


def dump_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _parse_window(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise UsageError("--freshness-window must be an integer number of seconds >= 0")
    if isinstance(raw, str):
        if not re.match(r"^(0|[1-9][0-9]*)$", raw):
            raise UsageError("--freshness-window must be an integer number of seconds >= 0")
        raw = int(raw)
    if raw < 0:
        raise UsageError("--freshness-window must be >= 0")
    return raw


def _parse_now(raw: Any) -> str:
    if not isinstance(raw, str) or parse_now_ns(raw) is None:
        raise UsageError("--now must be YYYY-MM-DDTHH:MM:SS(.1-9)?Z and a valid Gregorian datetime")
    return raw


def build_ops(bindings: Optional[str], independence: Optional[str], revocation: Optional[str],
              now: Optional[str], window: Optional[str]) -> OperatorInputs:
    ops = OperatorInputs()
    if bindings is not None:
        ops.bindings_doc, raw = _read_json_file(bindings, "bindings")
        ops.bindings_digest = _digest_of(raw)
    if independence is not None:
        ops.independence_doc, raw = _read_json_file(independence, "independence policy")
        ops.independence_digest = _digest_of(raw)
    if revocation is not None:
        ops.revocation_doc, raw = _read_json_file(revocation, "revocation snapshot")
        ops.revocation_digest = _digest_of(raw)
    if now is not None:
        ops.now = _parse_now(now)
    if window is not None:
        ops.window = _parse_window(window)
    return ops


def run_single(args, schema_dir: str) -> int:
    ops = build_ops(args.bindings, args.independence_policy, args.revocation,
                    args.now, args.freshness_window)
    doc, raw = _read_json_file(args.request, "evaluation request")
    verdict = evaluate(doc, ops, schema_dir, claim_numeric_lexemes(raw))
    sys.stdout.write(dump_json(verdict))
    return 0


def run_corpus(corpus_dir: str, out_path: str, schema_dir: str) -> int:
    index_path = os.path.join(corpus_dir, "case_index.json")
    index, _ = _read_json_file(index_path, "case index")
    if not isinstance(index, list):
        raise RunInvalid("case_index.json is not an array")
    verdicts: List[dict] = []
    for case in index:
        files = case.get("files", {})

        def path_for(key: str) -> Optional[str]:
            rel = files.get(key)
            if rel is None:
                return None
            full = os.path.join(corpus_dir, rel)
            return full if os.path.exists(full) else None

        now = window = None
        clock_path = path_for("clock")
        if clock_path is not None:
            clock, _ = _read_json_file(clock_path, "clock")
            if not isinstance(clock, dict) or set(clock.keys()) - {"now", "freshness_window_seconds"}:
                raise UsageError("clock input %s is malformed" % clock_path)
            if "now" in clock:
                now = _parse_now(clock["now"])
            if "freshness_window_seconds" in clock:
                window = _parse_window(clock["freshness_window_seconds"])
        ops = build_ops(path_for("bindings"), path_for("independence"),
                        path_for("revocation"), None, None)
        ops.now = now
        ops.window = window
        request_path = path_for("request")
        if request_path is None:
            raise RunInvalid("case %r has no request file" % case.get("case_id"))
        doc, raw = _read_json_file(request_path, "evaluation request")
        verdicts.append(evaluate(doc, ops, schema_dir, claim_numeric_lexemes(raw)))

    verdicts.sort(key=verdict_sort_key)
    seen = set()
    for v in verdicts:
        key = verdict_sort_key(v)
        if key in seen:
            raise RunInvalid("duplicate (chain_id, record_id) tuple: %r" % (key,))
        seen.add(key)
    with open(out_path, "wb") as fh:
        fh.write(dump_json({"verdicts": verdicts}).encode("utf-8"))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="class_verifier.py",
        description="AIREP v0.2 class verifier (contract sections 0-6).",
        add_help=True,
    )
    parser.add_argument("--request")
    parser.add_argument("--bindings")
    parser.add_argument("--independence-policy", dest="independence_policy")
    parser.add_argument("--revocation")
    parser.add_argument("--now")
    parser.add_argument("--freshness-window", dest="freshness_window")
    parser.add_argument("--corpus")
    parser.add_argument("--out")
    parser.add_argument("--schema-dir", dest="schema_dir")
    args = parser.parse_args(argv)   # argparse exits 2 on usage errors, 0 on --help

    # Portability (errata S9 note): the default must resolve in the COMMITTED
    # repository layout -- this file at <v0.2>/class-verification/verifier_py/
    # and the accepted schemas at <v0.2>/schemas/. Inside an authoring snapshot
    # that places them elsewhere, pass --schema-dir explicitly.
    schema_dir = args.schema_dir or os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "schemas")
    )

    try:
        if args.corpus is not None:
            if args.request is not None:
                raise UsageError("--corpus and --request are mutually exclusive")
            if args.out is None:
                raise UsageError("--corpus requires --out")
            return run_corpus(args.corpus, args.out, schema_dir)
        if args.request is None:
            raise UsageError("one of --request or --corpus is required")
        if args.out is not None:
            raise UsageError("--out is only valid with --corpus")
        return run_single(args, schema_dir)
    except UsageError as exc:
        sys.stderr.write("usage error: %s\n" % exc)
        return 2
    except RunInvalid as exc:
        sys.stderr.write("invalid: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
