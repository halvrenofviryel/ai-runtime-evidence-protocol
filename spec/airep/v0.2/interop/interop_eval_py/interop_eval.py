#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 Python reference interop evaluator (AD15-IR-2), post-erratum.

Implements ``INTEROP_REFERENCE_EVALUATOR_CONTRACT.md`` at contract basis
``930b9457db00c1d66e2d355f59a6cf5811d52d3a``
(sha256 ``ea705ec2b8775a37aa4bdbf387a5eb5295c0e8bd8a000ad443104c3a24a6c63a``)
over the FROZEN Python class verifier, which is invoked as a SUBPROCESS and is
never imported, vendored or re-implemented (contract 3).

Composition, in the contract's own order:

  * section 5    ``manifest.json`` at the bundle root, pinned encoding; symlinks
                 forbidden; every listed file digest-verified BEFORE parsing;
  * section 5.1  the closed section-0 request envelope, RFC 8785 (JCS)
                 serialized; ``request_envelope_digest`` over exactly those
                 bytes; numeric preflight on integral VALUE, not JSON spelling;
  * section 3    frozen-verifier digest assertion before use -- THIS LANE ONLY;
  * section 6    R-A / R-B / R-C, with the section 6.1 applicability matrix;
  * section 7    the Level-1 mapping, plus 7.1 (``authenticated_withheld`` =>
                 MEASUREMENT_INVALID) and 7.2 (the causal guard on frozen
                 ``exit 1``);
  * section 8    one bundle per invocation, one JSON result object, full
                 preflight before any invocation, and the 8.5 exit/stdout table.

Deliberately NOT implemented:

  * cross-lane envelope-digest equality (ruling ``AD15-IR-4``, contract 5.1 and
    8.1 duty 2). A single Python invocation cannot observe the peer lane's
    digest. It is an aggregate-harness gate and is not part of the 7.2
    preflight-clean condition;
  * the peer lane's verifier digest. Contract 8.2.1: it "does not appear in
    evaluator output at all", not even as an unasserted carried constant. This
    file therefore does not name it;
  * ``head_witness``. Contract 5 pins it absent from every official W1 bundle,
    and the closed manifest ``role`` set has no value that could carry one, so
    the envelope never gains the member;
  * clock inputs. Contract 5 pins official W1 operator-input composition as
    exactly one ``bindings``, one ``revocation``, one ``independence_policy``
    and NO ``clock``.

Exit codes (contract 8.5) -- the dividing line is whether bundle identity was
established, and nothing else:

  0  exactly one result object, ``measurement_status: MEASURED``, Level-1 verdict
  1  stdout empty -- ``manifest.json`` absent, not parseable as strict JSON, or
     carrying no usable ``scenario_id`` from the registered twelve
  2  stdout empty -- CLI usage error
  3  exactly one result object, MEASUREMENT_INVALID or ERROR, ``level1: null``,
     ``predicates: null``, ``nonmeasurement`` populated

stdlib only; no third-party dependency is added. Diagnostics go to stderr and
are never a source of semantics (contract 8.3, 8.5).

-----------------------------------------------------------------------------
RECORDED AMBIGUITIES -- resolved in the direction the contract determines, and
reported rather than buried. None of them can change the measured result of a
conforming official W1 bundle.

  A1  Contract 8.1 shows ``interop-eval --bundle DIR [operator-input flags]``,
      but contract 5 pins the operator inputs as bundle members addressed by
      the closed ``role`` set, and 5.1 says the evaluator "passes through the
      files the bundle ships". Role-derivation is the determinate reading and
      is what this evaluator uses. The three flags are still accepted, but
      ONLY as a consistency assertion: each must resolve to the same file the
      role already selected, or it is a usage error. A flag can therefore never
      change what is measured.

  A2  Numeric-preflight JSON Pointers are rooted at the DOCUMENT carrying the
      offending number, with the bundle-relative path in ``detail``. Contract
      5.1 defines the number set by envelope reachability but names operator
      inputs in the same breath, and operator inputs are not envelope members,
      so no envelope-rooted pointer can address them. No harness duty (8.1)
      compares ``json_pointer`` across lanes.

  A3  The closed reason registry (8.2.2) has no row for a symlink under the
      bundle, an on-disk file absent from ``files[]``, or duplicate object
      members in the manifest. All three are section-5 file-set/path rules, so
      they are reported as ``manifest-invalid``.

  A4  The registry has no row for the frozen verifier exiting 0 with
      unparseable stdout, or exiting 2. Neither is ``verifier-not-invocable``
      (it executed) nor ``verifier-run-invalid`` (that row is scoped to exit 1),
      so both are reported as ``internal-error``.

  A5  Contract 8.2 lists ``withheld_reasons`` as a result member and qualifies
      it "whenever any ``*_withheld`` channel is non-empty". It is emitted
      unconditionally, as ``[]`` when nothing is withheld, so the object shape
      is fixed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

EVALUATOR_VERSION = "0.2.0"

# --------------------------------------------------------------------------
# JCS (RFC 8785) canonicalizer -- loaded from the REPOSITORY, not from PyPI,
# and not copied. The canonical bytes are defined by the repository's own
# canonicalizer at <repo>/spec/airep/v0.1/conformance/jcs.py; resolving it by
# explicit relative path against THIS file keeps the working directory
# irrelevant and adds no third-party dependency (contract 5.1).
# Public API consumed: canonicalize(obj) -> bytes.
# --------------------------------------------------------------------------

JCS_RELPATH = (os.pardir, os.pardir, os.pardir, "v0.1", "conformance", "jcs.py")


def _load_repo_jcs():
    path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), *JCS_RELPATH)
    )
    spec = importlib.util.spec_from_file_location("airep_v0_1_jcs_interop", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load the repository JCS canonicalizer at %s" % path)
    module = importlib.util.module_from_spec(spec)
    # Never drop a __pycache__ next to a repository spec file.
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
# Frozen inputs (contract 3, 8.2.1) -- THIS LANE ONLY
# --------------------------------------------------------------------------

CLASS_VERIFICATION_RELPATH = (os.pardir, os.pardir, "class-verification")

#: Contract 3: "the Python evaluator invokes only verifier_py". Crossing the
#: lanes is forbidden, so this lane knows -- and emits (8.2.1) -- exactly two
#: digests, both of which it recomputes itself. The peer lane's verifier digest
#: is deliberately absent from this file and from every result object.
FROZEN_VERIFIER_RELPATH = ("verifier_py", "class_verifier.py")
FROZEN_CONTRACT_RELPATH = ("CLASS_VERIFIER_CONTRACT.md",)

FROZEN_VERIFIER_SHA256 = \
    "5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc"
FROZEN_CONTRACT_SHA256 = \
    "7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885"


# --------------------------------------------------------------------------
# Scenario registry and bundle shape (contract 5, 6.1, 8.5)
# --------------------------------------------------------------------------

#: The registered twelve. A manifest naming anything else carries "no usable
#: scenario_id" and is contract-8.5 exit 1.
SINGLE_ARTIFACT_FAMILY: Dict[str, str] = {
    "IOP-P-DEC": "decision",
    "IOP-P-CTL": "control",
    "IOP-P-EXE": "execution",
    "IOP-P-EFF": "effect",
    "IOP-B-DEC": "decision",
    "IOP-B-CTL": "control",
    "IOP-B-EXE": "execution",
    "IOP-B-EFF": "effect",
}
RECONCILIATION_SCENARIOS = (
    "IOP-R-CLEAN", "IOP-R-TOCTOU", "IOP-R-XREF", "IOP-R-INDEP",
)
SCENARIO_IDS = frozenset(SINGLE_ARTIFACT_FAMILY) | frozenset(RECONCILIATION_SCENARIOS)

ARTIFACT_TYPES = ("decision", "control", "execution", "effect")

MANIFEST_FILENAME = "manifest.json"
MANIFEST_VERSION = "1"
MANIFEST_MEMBERS = frozenset({"manifest_version", "scenario_id", "files"})
FILE_ENTRY_MEMBERS = frozenset({"path", "role", "sha256"})
ROLES = ("artifact", "bindings", "independence_policy", "revocation", "clock")

#: Official W1 operator-input composition (contract 5): exactly one each of
#: these, and no ``clock``.
REQUIRED_OPERATOR_ROLES = ("bindings", "independence_policy", "revocation")

#: role -> frozen class-verifier flag.
OPERATOR_FLAG = {
    "bindings": "--bindings",
    "independence_policy": "--independence-policy",
    "revocation": "--revocation",
}

HEX_DIGITS = frozenset("0123456789abcdef")


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"

MEASURED = "MEASURED"
MEASUREMENT_INVALID = "MEASUREMENT_INVALID"
ERROR = "ERROR"

ACCEPT = "ACCEPT"
REJECT = "REJECT"
RECONCILIATION_MISMATCH = "RECONCILIATION_MISMATCH"
INDEPENDENCE_NOT_ESTABLISHED = "INDEPENDENCE_NOT_ESTABLISHED"

#: Closed reason registry (contract 8.2.2). The value is the
#: ``measurement_status`` that MUST accompany the reason, so the pairing is not
#: left to this implementation.
REASON_STATUS: Dict[str, str] = {
    "manifest-invalid": ERROR,
    "manifest-digest-mismatch": ERROR,
    "bundle-file-missing": ERROR,
    "bundle-json-invalid": ERROR,
    "bundle-shape-invalid": ERROR,
    "numeric-preflight-violation": ERROR,
    "verifier-digest-mismatch": ERROR,
    "verifier-not-invocable": ERROR,
    "verifier-run-invalid": ERROR,
    "internal-error": ERROR,
    "authenticated-withheld": MEASUREMENT_INVALID,
}

#: Contract 7.2: frozen ``exit 1`` may be read as Level-1 REJECT only for these
#: scenarios (stage-0 / stage-1 invalidity targets), and no other.
EXIT1_REJECT_SCENARIOS = frozenset({"IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"})

MAX_SAFE_INTEGER = 9007199254740991  # 2**53 - 1


# --------------------------------------------------------------------------
# Exceptions -- one per band of the contract-8.5 exit table
# --------------------------------------------------------------------------

class UsageError(Exception):
    """CLI usage error -> exit 2, stdout empty."""


class BundleIdentityError(Exception):
    """Bundle identity could not be established -> exit 1, stdout empty.

    Exactly the three contract-8.5 conditions: ``manifest.json`` absent, not
    parseable as strict JSON, or carrying no usable ``scenario_id``.
    """


class NonMeasurement(Exception):
    """Identity established, scenario not measured -> exit 3 with a result object.

    ``reason`` is a value from the closed registry; ``measurement_status`` is
    taken FROM that registry rather than chosen here, so the pairing cannot
    drift (contract 8.2.2).
    """

    def __init__(self, reason: str, detail: str,
                 json_pointer: Optional[str] = None,
                 withheld_reasons: Optional[List[dict]] = None,
                 artifacts: Optional[List[dict]] = None) -> None:
        super().__init__(detail)
        if reason not in REASON_STATUS:
            raise KeyError("reason %r is outside the closed registry" % reason)
        if (json_pointer is not None) != (reason == "numeric-preflight-violation"):
            raise ValueError(
                "json_pointer is mandatory for numeric-preflight-violation and "
                "permitted for no other reason")
        self.reason = reason
        self.detail = detail
        self.json_pointer = json_pointer
        self.status = REASON_STATUS[reason]
        self.withheld_reasons = withheld_reasons or []
        #: Contract 8.3.1: an empty array before any invocation; afterwards, an
        #: entry for each invocation actually attempted and only those.
        self.artifacts = artifacts or []
        #: Stamped once the manifest has yielded a usable scenario_id, so the
        #: exit-3 object can name the scenario it failed on (contract 8.5).
        self.scenario_id: Optional[str] = None
        #: Contract 8.2.1: the two digests THIS lane recomputed, whenever they
        #: were recomputed at all. Never a value this lane did not measure.
        self.verifier_digests: Dict[str, str] = {}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def pointer_escape(token: str) -> str:
    """RFC 6901 reference-token escaping."""
    return token.replace("~", "~0").replace("/", "~1")


def byte_key(text: str) -> bytes:
    """Ascending UTF-8 byte order (contract 5.1, 8.4)."""
    return text.encode("utf-8")


def dump_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def warn(message: str) -> None:
    sys.stderr.write(message.rstrip("\n") + "\n")


def _reject_constant(token: str) -> Any:
    raise ValueError("strict JSON forbids the literal %s" % token)


def _reject_duplicate_members(pairs: Sequence[Tuple[str, Any]]) -> dict:
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateMember(key)
        seen[key] = value
    return seen


class _DuplicateMember(Exception):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


# --------------------------------------------------------------------------
# Numeric preflight (contract 5.1)
# --------------------------------------------------------------------------

def numeric_preflight(value: Any, base_pointer: str = "") -> Optional[Tuple[str, str]]:
    """Return ``(json_pointer, detail)`` for the first inadmissible number, or
    ``None`` when every number in ``value`` is admissible.

    Pinned checks:

      * finite and IEEE-754 representable -- no NaN, no infinity;
      * integer-VALUED numbers: absolute value <= 2**53 - 1.

    The bound is on the MATHEMATICAL VALUE, not on JSON spelling. ``1e20``
    decodes to a float whose value is integral, so it is rejected; ``1.5`` is
    not integer-valued and is judged only by the finiteness rule. Reading the
    bound as a syntax rule would let ``1e20`` through in one lane and not the
    other, which is precisely the divergence this preflight prevents.
    """
    stack: List[Tuple[str, Any]] = [(base_pointer, value)]
    while stack:
        pointer, node = stack.pop()
        if isinstance(node, bool):
            continue                      # bool is not a JSON number
        if isinstance(node, int):
            if abs(node) > MAX_SAFE_INTEGER:
                return pointer, "integer-valued number exceeds 2**53-1 in magnitude"
            continue
        if isinstance(node, float):
            # json decodes NaN/Infinity/-Infinity, and an overflowing exponent
            # (1e400) decodes to inf; both are rejected here.
            if node != node or node in (float("inf"), float("-inf")):
                return pointer, "number is not finite"
            if node.is_integer() and abs(node) > MAX_SAFE_INTEGER:
                return pointer, "integer-valued number exceeds 2**53-1 in magnitude"
            continue
        if isinstance(node, dict):
            for key in sorted(node, key=byte_key, reverse=True):
                stack.append((pointer + "/" + pointer_escape(key), node[key]))
            continue
        if isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((pointer + "/" + str(index), node[index]))
    return None


# --------------------------------------------------------------------------
# Manifest (contract 5) -- identity band, then structural band
# --------------------------------------------------------------------------

class FileEntry:
    __slots__ = ("path", "role", "sha256")

    def __init__(self, path: str, role: str, sha256: str) -> None:
        self.path = path
        self.role = role
        self.sha256 = sha256


class Manifest:
    def __init__(self, scenario_id: str, entries: List[FileEntry]) -> None:
        self.scenario_id = scenario_id
        self.entries = entries

    def by_role(self, role: str) -> List[FileEntry]:
        return [e for e in self.entries if e.role == role]


def load_manifest_identity(bundle_dir: str) -> Tuple[dict, str]:
    """Establish bundle identity, or raise ``BundleIdentityError`` (exit 1).

    Contract 8.5 pins the exit-1 band to exactly three conditions:
    ``manifest.json`` absent, not parseable as strict JSON, or carrying no
    usable ``scenario_id`` from the registered twelve. Everything downstream of
    this function is exit 3 with a named reason.
    """
    path = os.path.join(bundle_dir, MANIFEST_FILENAME)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise BundleIdentityError("manifest unreadable at %s: %s" % (path, exc))
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_members,
        )
    except _DuplicateMember:
        # Parsed as a document but carries an ambiguous member. Identity is not
        # trustworthy from an ambiguous object, so this stays in the exit-1
        # band rather than naming a scenario read out of a duplicated key.
        raise BundleIdentityError(
            "manifest carries duplicate object members; identity is ambiguous")
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleIdentityError("manifest is not parseable as strict JSON: %s" % exc)
    if not isinstance(doc, dict):
        raise BundleIdentityError("manifest is not a JSON object")
    scenario_id = doc.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in SCENARIO_IDS:
        raise BundleIdentityError(
            "manifest carries no usable scenario_id from the registered twelve")
    return doc, scenario_id


def _bad_manifest(detail: str) -> NonMeasurement:
    return NonMeasurement("manifest-invalid", detail)


def validate_manifest(doc: dict, scenario_id: str) -> Manifest:
    """Apply the pinned manifest encoding (contract 5). Failures are
    ``manifest-invalid`` at exit 3 -- identity is already established.
    """
    extra = sorted(set(doc) - MANIFEST_MEMBERS)
    if extra:
        raise _bad_manifest("manifest carries unknown member(s): %s" % ", ".join(extra))
    missing = sorted(MANIFEST_MEMBERS - set(doc))
    if missing:
        raise _bad_manifest("manifest is missing member(s): %s" % ", ".join(missing))
    if doc["manifest_version"] != MANIFEST_VERSION:
        raise _bad_manifest(
            "manifest_version is %r, not the string %r"
            % (doc["manifest_version"], MANIFEST_VERSION))
    raw_files = doc["files"]
    if not isinstance(raw_files, list):
        raise _bad_manifest("files is not an array")
    if not raw_files:
        raise _bad_manifest("files is empty")

    entries: List[FileEntry] = []
    seen: Dict[str, None] = {}
    for index, raw in enumerate(raw_files):
        if not isinstance(raw, dict):
            raise _bad_manifest("files[%d] is not an object" % index)
        unknown = sorted(set(raw) - FILE_ENTRY_MEMBERS)
        if unknown:
            raise _bad_manifest(
                "files[%d] carries unknown member(s): %s" % (index, ", ".join(unknown)))
        absent = sorted(FILE_ENTRY_MEMBERS - set(raw))
        if absent:
            raise _bad_manifest(
                "files[%d] is missing member(s): %s" % (index, ", ".join(absent)))
        path, role, digest = raw["path"], raw["role"], raw["sha256"]
        if not isinstance(path, str) or not path:
            raise _bad_manifest("files[%d].path is not a non-empty string" % index)
        _validate_manifest_path(index, path)
        if path in seen:
            raise _bad_manifest("files lists path %r more than once" % path)
        seen[path] = None
        if role not in ROLES:
            raise _bad_manifest("files[%d].role %r is outside the closed set" % (index, role))
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(c not in HEX_DIGITS for c in digest):
            raise _bad_manifest(
                "files[%d].sha256 is not exactly 64 lowercase hex characters "
                "with no prefix" % index)
        entries.append(FileEntry(path, role, digest))

    paths = [e.path for e in entries]
    if paths != sorted(paths, key=byte_key):
        raise _bad_manifest("files is not sorted ascending by path in UTF-8 byte order")
    return Manifest(scenario_id, entries)


def _validate_manifest_path(index: int, path: str) -> None:
    if "\\" in path:
        raise _bad_manifest("files[%d].path %r contains a backslash" % (index, path))
    if path.startswith("/") or os.path.isabs(path):
        raise _bad_manifest("files[%d].path %r is absolute" % (index, path))
    segments = path.split("/")
    for segment in segments:
        if segment == "":
            raise _bad_manifest(
                "files[%d].path %r is not normalized (empty segment)" % (index, path))
        if segment == ".":
            raise _bad_manifest(
                "files[%d].path %r is not normalized ('.' segment)" % (index, path))
        if segment == os.pardir:
            raise _bad_manifest(
                "files[%d].path %r contains a '..' segment" % (index, path))
    if path == MANIFEST_FILENAME:
        raise _bad_manifest(
            "files lists the root %s, which it must exclude" % MANIFEST_FILENAME)


# --------------------------------------------------------------------------
# Bundle file set (contract 5)
# --------------------------------------------------------------------------

def scan_bundle(bundle_dir: str) -> List[str]:
    """Return every regular file under ``bundle_dir``, bundle-relative, except
    the root ``manifest.json``.

    Symbolic links are forbidden ANYWHERE under the bundle -- including one
    whose target resolves inside it -- because a digest over a link's target is
    not a digest over the bundle's own bytes.
    """
    found: List[str] = []

    def walk(directory: str, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: byte_key(e.name))
        except OSError as exc:
            raise _bad_manifest("bundle directory %s unreadable: %s" % (directory, exc))
        for entry in entries:
            rel = entry.name if not prefix else prefix + "/" + entry.name
            if entry.is_symlink():
                raise _bad_manifest("bundle carries a symbolic link at %r" % rel)
            if entry.is_dir(follow_symlinks=False):
                walk(entry.path, rel)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise _bad_manifest(
                    "bundle carries a non-regular, non-directory entry at %r" % rel)
            if rel == MANIFEST_FILENAME:
                continue
            found.append(rel)

    walk(bundle_dir, "")
    found.sort(key=byte_key)
    return found


def verify_bundle_files(bundle_dir: str, manifest: Manifest) -> Dict[str, bytes]:
    """File-set correspondence, then per-file digest verification, BEFORE
    anything is parsed (contract 5).
    """
    on_disk = scan_bundle(bundle_dir)
    listed = {e.path for e in manifest.entries}
    unlisted = [p for p in on_disk if p not in listed]
    if unlisted:
        raise _bad_manifest(
            "bundle carries file(s) absent from files[]: %s" % ", ".join(unlisted))
    present = set(on_disk)
    for entry in manifest.entries:
        if entry.path not in present:
            raise NonMeasurement(
                "bundle-file-missing",
                "files[] lists %r but no such regular file is present" % entry.path)

    contents: Dict[str, bytes] = {}
    for entry in manifest.entries:
        full = os.path.join(bundle_dir, *entry.path.split("/"))
        try:
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            raise NonMeasurement(
                "bundle-file-missing", "%r could not be read: %s" % (entry.path, exc))
        measured = sha256_hex(data)
        if measured != entry.sha256:
            raise NonMeasurement(
                "manifest-digest-mismatch",
                "%r: manifest says %s, bundle bytes measure %s"
                % (entry.path, entry.sha256, measured))
        contents[entry.path] = data
    return contents


def parse_bundle_files(manifest: Manifest, contents: Dict[str, bytes]) -> Dict[str, Any]:
    """Parse every listed file. NaN / Infinity are left for the numeric
    preflight, which reports them with the mandatory JSON Pointer.
    """
    parsed: Dict[str, Any] = {}
    for entry in manifest.entries:
        try:
            parsed[entry.path] = json.loads(contents[entry.path].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise NonMeasurement(
                "bundle-json-invalid", "%r is not parseable JSON: %s" % (entry.path, exc))
    return parsed


# --------------------------------------------------------------------------
# Bundle shape (contract 5)
# --------------------------------------------------------------------------

class Artifact:
    __slots__ = ("path", "value", "record_id", "chain_id", "artifact_type")

    def __init__(self, path: str, value: dict) -> None:
        self.path = path
        self.value = value
        self.record_id = value["record_id"]
        self.chain_id = value.get("chain_id")
        self.artifact_type = value["artifact_type"]

    @property
    def ref(self) -> Dict[str, str]:
        ref: Dict[str, str] = {"record_id": self.record_id}
        if isinstance(self.chain_id, str):
            ref["chain_id"] = self.chain_id
        return ref


def _bad_shape(detail: str) -> NonMeasurement:
    return NonMeasurement("bundle-shape-invalid", detail)


def build_artifacts(manifest: Manifest, parsed: Dict[str, Any]) -> List[Artifact]:
    """Bundle shape, pinned by contract 5, keyed on the scenario the manifest
    names -- not guessed from what the files happen to look like.
    """
    scenario_id = manifest.scenario_id
    entries = manifest.by_role("artifact")

    expected = 1 if scenario_id in SINGLE_ARTIFACT_FAMILY else 4
    if len(entries) != expected:
        raise _bad_shape(
            "%s requires exactly %d artifact(s); the bundle carries %d"
            % (scenario_id, expected, len(entries)))

    artifacts: List[Artifact] = []
    for entry in entries:
        value = parsed[entry.path]
        if not isinstance(value, dict):
            raise _bad_shape("artifact %r is not a JSON object" % entry.path)
        record_id = value.get("record_id")
        artifact_type = value.get("artifact_type")
        if not isinstance(record_id, str) or not record_id:
            raise _bad_shape("artifact %r carries no usable record_id" % entry.path)
        if artifact_type not in ARTIFACT_TYPES:
            raise _bad_shape(
                "artifact %r carries artifact_type %r, outside the four families"
                % (entry.path, artifact_type))
        chain_id = value.get("chain_id")
        if chain_id is not None and not isinstance(chain_id, str):
            raise _bad_shape("artifact %r carries a non-string chain_id" % entry.path)
        artifacts.append(Artifact(entry.path, value))

    if scenario_id in SINGLE_ARTIFACT_FAMILY:
        family = SINGLE_ARTIFACT_FAMILY[scenario_id]
        if artifacts[0].artifact_type != family:
            raise _bad_shape(
                "%s requires the single artifact of the %s family; the bundle "
                "carries a %s" % (scenario_id, family, artifacts[0].artifact_type))
    else:
        present = sorted(a.artifact_type for a in artifacts)
        if present != sorted(ARTIFACT_TYPES):
            raise _bad_shape(
                "%s requires exactly one each of Decision, Control, Execution and "
                "Effect; the bundle carries %s" % (scenario_id, ", ".join(present)))

    ids = [a.record_id for a in artifacts]
    if len(set(ids)) != len(ids):
        raise _bad_shape("the bundle carries two artifacts with the same record_id")

    artifacts.sort(key=lambda a: byte_key(a.record_id))
    return artifacts


def check_operator_composition(manifest: Manifest) -> Dict[str, FileEntry]:
    """Official W1 composition: exactly one ``bindings``, exactly one
    ``revocation``, exactly one ``independence_policy``, and NO ``clock``.

    ``clock`` remains a legal ``role`` for future runs; it simply does not occur
    in this one, because no scenario here evaluates freshness.
    """
    clocks = manifest.by_role("clock")
    if clocks:
        raise _bad_shape(
            "official W1 bundles carry no clock input; the bundle carries %d"
            % len(clocks))
    selected: Dict[str, FileEntry] = {}
    for role in REQUIRED_OPERATOR_ROLES:
        found = manifest.by_role(role)
        if len(found) != 1:
            raise _bad_shape(
                "official W1 bundles carry exactly one %s input; the bundle "
                "carries %d" % (role, len(found)))
        selected[role] = found[0]
    return selected


# --------------------------------------------------------------------------
# Frozen-verifier digest assertion (contract 3, 8.2.1)
# --------------------------------------------------------------------------

def class_verification_dir() -> str:
    return os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), *CLASS_VERIFICATION_RELPATH))


def frozen_verifier_path() -> str:
    return os.path.join(class_verification_dir(), *FROZEN_VERIFIER_RELPATH)


def frozen_contract_path() -> str:
    return os.path.join(class_verification_dir(), *FROZEN_CONTRACT_RELPATH)


FROZEN_FILES = (
    ("class_verifier", frozen_verifier_path, FROZEN_VERIFIER_SHA256),
    ("class_verifier_contract", frozen_contract_path, FROZEN_CONTRACT_SHA256),
)


def measure_frozen_digests() -> Tuple[Dict[str, str], Optional[str]]:
    """Recompute the two frozen files THIS lane uses.

    Returns the ``verifier_digests`` object (contract 8.2.1) built from values
    this lane actually measured -- never a carried constant -- together with the
    first mismatch detail, or ``None`` when both match. The comparison is turned
    into a verdict by ``assert_frozen_digests`` at its pinned position in the
    contract-8.3.1 preflight order; measuring early only lets a result object
    report what was measured.
    """
    measured: Dict[str, str] = {}
    problem: Optional[str] = None
    for key, path_of, expected in FROZEN_FILES:
        path = path_of()
        try:
            with open(path, "rb") as handle:
                actual = sha256_hex(handle.read())
        except OSError as exc:
            if problem is None:
                problem = ("frozen file %s is unreadable, so its digest cannot be "
                           "asserted: %s" % (path, exc))
            continue
        measured[key] = "sha256:" + actual
        if actual != expected and problem is None:
            problem = ("%s: contract pins %s, the tree measures %s"
                       % (path, expected, actual))
    return measured, problem


def assert_frozen_digests(problem: Optional[str]) -> None:
    """A digest mismatch is a hard ERROR: the run is not valid and no Level-1
    verdict is emitted (contract 3).
    """
    if problem is not None:
        raise NonMeasurement("verifier-digest-mismatch", problem)


# --------------------------------------------------------------------------
# Request envelope (contract 5.1)
# --------------------------------------------------------------------------

def build_envelope(primary: Artifact, artifacts: List[Artifact]) -> dict:
    """The closed section-0 envelope for ``primary``.

    ``related_artifacts`` is the OTHER artifacts of the same bundle and no
    others, ascending by UTF-8 byte order of ``record_id``; for a
    single-artifact scenario it is the EMPTY ARRAY -- present, never absent.
    ``head_witness`` is never added: contract 5 pins it absent from every
    official W1 bundle and the closed role set cannot express one.
    """
    related = sorted((a for a in artifacts if a is not primary),
                     key=lambda a: byte_key(a.record_id))
    return {
        "artifact": primary.value,
        "related_artifacts": [a.value for a in related],
    }


def envelope_bytes(envelope: dict) -> bytes:
    """RFC 8785 canonical bytes; ``request_envelope_digest`` is over exactly these."""
    return jcs.canonicalize(envelope)


# --------------------------------------------------------------------------
# Frozen-verifier invocation (contract 3: subprocess, never imported)
# --------------------------------------------------------------------------

def invoke_frozen_verifier(request: bytes, flags: List[str]) -> Tuple[int, bytes, bytes]:
    """Run the frozen Python class verifier on one request envelope.

    Nothing is written into the frozen tree: the request lives in a temporary
    directory that is removed on return.
    """
    verifier = frozen_verifier_path()
    with tempfile.TemporaryDirectory(prefix="airep-interop-eval-") as workdir:
        request_path = os.path.join(workdir, "request.json")
        with open(request_path, "wb") as handle:
            handle.write(request)
        argv = [sys.executable, verifier, "--request", request_path] + list(flags)
        try:
            completed = subprocess.run(argv, capture_output=True, check=False)
        except OSError as exc:
            raise NonMeasurement(
                "verifier-not-invocable", "frozen verifier could not be executed: %s" % exc)
    return completed.returncode, completed.stdout, completed.stderr


# --------------------------------------------------------------------------
# Reconciliation predicates (contract 6)
# --------------------------------------------------------------------------

def resolve_reference(reference: Any, artifacts: List[Artifact]) -> str:
    """v0.2 reference semantics: match ``record_id``, additionally ``chain_id``
    when the reference carries one. Zero matches is unresolved; more than one is
    ambiguous and fails closed. An evaluator MUST NOT pick one (contract 5).
    """
    if not isinstance(reference, dict):
        return "unresolved"
    record_id = reference.get("record_id")
    if not isinstance(record_id, str):
        return "unresolved"
    chain_id = reference.get("chain_id")
    matches = [
        a for a in artifacts
        if a.record_id == record_id and (chain_id is None or a.chain_id == chain_id)
    ]
    if len(matches) == 1:
        return "resolved"
    return "ambiguous" if len(matches) > 1 else "unresolved"


#: The complete cross-artifact reference set contract 6 R-A names:
#: Control->Decision, Execution->Decision, Effect->Decision, Effect->Execution.
REFERENCE_EDGES = {
    "control": ("decision_ref",),
    "execution": ("decision_ref",),
    "effect": ("decision_ref", "execution_ref"),
}


def predicate_r_a(artifacts: List[Artifact]) -> Tuple[str, List[str]]:
    """R-A -- every cross-artifact reference in the bundle resolves uniquely.

    Unique reference resolution AND NOTHING MORE (contract 6, confirmed at
    erratum): there is deliberately no check that a ``decision_ref`` resolves to
    an artifact of the Decision family. Adding one would be a stricter, unpinned
    predicate; bundle shape already fixes family composition.
    """
    problems: List[str] = []
    for artifact in artifacts:
        for member in REFERENCE_EDGES.get(artifact.artifact_type, ()):
            outcome = resolve_reference(artifact.value.get(member), artifacts)
            if outcome != "resolved":
                problems.append("%s /%s %s" % (artifact.record_id, member, outcome))
    return (FAIL if problems else PASS), problems


def predicate_r_b(artifacts: List[Artifact]) -> Tuple[str, List[str]]:
    """R-B -- the Control's ``authorized_action_digest`` and the Execution's
    ``executed_action_digest``, compared as EXACT STRINGS. Both are
    ``sha256_digest`` by schema, so no normalization, case folding or re-hashing
    is performed.
    """
    control = _sole(artifacts, "control")
    execution = _sole(artifacts, "execution")
    authorized = control.value.get("authorized_action_digest")
    executed = execution.value.get("executed_action_digest")
    if isinstance(authorized, str) and isinstance(executed, str) \
            and authorized == executed:
        return PASS, []
    return FAIL, ["authorized %r != executed %r" % (authorized, executed)]


def predicate_r_c(artifacts: List[Artifact],
                  verdicts: Dict[str, Optional[dict]]) -> Tuple[str, List[str]]:
    """R-C -- independence, TAKEN FROM the frozen verifier's
    ``observer_assessment`` for the Effect and never re-derived here: that is a
    frozen stage-8 property, and re-implementing it would create a second,
    unpinned definition (contract 6).
    """
    effect = _sole(artifacts, "effect")
    verdict = verdicts.get(effect.record_id)
    if not isinstance(verdict, dict):
        raise NonMeasurement(
            "internal-error",
            "R-C has no frozen verdict for the Effect %r" % effect.record_id)
    wire = effect.value.get("observer_relationship")
    effective = verdict.get("observer_assessment")
    if wire == "independent" and effective == "unknown":
        return FAIL, ["wire observer_relationship 'independent', effective 'unknown'"]
    return PASS, []


def _sole(artifacts: List[Artifact], artifact_type: str) -> Artifact:
    found = [a for a in artifacts if a.artifact_type == artifact_type]
    if len(found) != 1:
        # Unreachable: bundle shape already pinned exactly one of each.
        raise NonMeasurement(
            "internal-error",
            "expected exactly one %s after shape validation, found %d"
            % (artifact_type, len(found)))
    return found[0]


# --------------------------------------------------------------------------
# Level-1 mapping (contract 7)
# --------------------------------------------------------------------------

def map_level1(reject: bool, predicates: Dict[str, str]) -> str:
    """Contract 7, in the pinned order."""
    if reject:
        return REJECT
    if predicates["R_C"] == FAIL:
        return INDEPENDENCE_NOT_ESTABLISHED
    if predicates["R_A"] == FAIL or predicates["R_B"] == FAIL:
        return RECONCILIATION_MISMATCH
    return ACCEPT


# --------------------------------------------------------------------------
# Result object (contract 8.2)
# --------------------------------------------------------------------------

def build_result(scenario_id: str, status: str, level1: Optional[str],
                 predicates: Optional[Dict[str, str]],
                 nonmeasurement: Optional[dict], artifacts: List[dict],
                 withheld_reasons: List[dict],
                 verifier_digests: Dict[str, str]) -> dict:
    return {
        "scenario_id": scenario_id,
        "measurement_status": status,
        "level1": level1,
        "predicates": predicates,
        "nonmeasurement": nonmeasurement,
        "artifacts": artifacts,
        "withheld_reasons": withheld_reasons,
        "verifier_digests": verifier_digests,
        "evaluator_version": EVALUATOR_VERSION,
    }


def nonmeasurement_object(exc: NonMeasurement) -> dict:
    """The closed contract-8.2.2 object. ``json_pointer`` appears only for
    ``numeric-preflight-violation``, where it is mandatory.
    """
    obj = {"reason": exc.reason, "detail": exc.detail}
    if exc.json_pointer is not None:
        obj["json_pointer"] = exc.json_pointer
    return obj


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate_bundle(args, invoke=None) -> dict:
    """Evaluate exactly one bundle and return the MEASURED result object.

    Raises ``BundleIdentityError`` (exit 1), ``UsageError`` (exit 2) or
    ``NonMeasurement`` (exit 3). ``invoke`` is the frozen-verifier subprocess
    seam, resolved from the module global when not supplied so that tests can
    substitute a stub and exercise the mapping without any corpus bytes.
    """
    if invoke is None:
        invoke = invoke_frozen_verifier
    bundle_dir = os.path.abspath(args.bundle)
    doc, scenario_id = load_manifest_identity(bundle_dir)   # exit-1 band ends here
    verifier_digests, digest_problem = measure_frozen_digests()
    try:
        return _evaluate(args, bundle_dir, doc, scenario_id, invoke,
                         verifier_digests, digest_problem)
    except NonMeasurement as exc:
        # Identity IS established from here on, so the caller owes a result
        # object naming the scenario it failed on (contract 8.5).
        exc.scenario_id = scenario_id
        exc.verifier_digests = verifier_digests
        raise


def _evaluate(args, bundle_dir: str, doc: dict, scenario_id: str, invoke,
              verifier_digests: Dict[str, str], digest_problem: Optional[str]) -> dict:
    # ---- contract 8.3.1 step 1: the WHOLE preflight, before any invocation ---
    manifest = validate_manifest(doc, scenario_id)
    contents = verify_bundle_files(bundle_dir, manifest)
    parsed = parse_bundle_files(manifest, contents)
    artifacts = build_artifacts(manifest, parsed)
    operator_entries = check_operator_composition(manifest)
    _assert_operator_flags_consistent(args, bundle_dir, operator_entries)

    for entry in manifest.entries:
        offending = numeric_preflight(parsed[entry.path])
        if offending is not None:
            pointer, why = offending
            raise NonMeasurement(
                "numeric-preflight-violation",
                "%s (%s): %s" % (entry.path, entry.role, why),
                json_pointer=pointer)

    assert_frozen_digests(digest_problem)

    flags: List[str] = []
    for role in REQUIRED_OPERATOR_ROLES:
        entry = operator_entries[role]
        flags += [OPERATOR_FLAG[role],
                  os.path.join(bundle_dir, *entry.path.split("/"))]

    # ---- one frozen-verifier invocation per artifact ------------------------
    entries: List[dict] = []
    verdicts: Dict[str, Optional[dict]] = {}
    for artifact in artifacts:
        request = envelope_bytes(build_envelope(artifact, artifacts))
        try:
            code, stdout, stderr = invoke(request, flags)
        except NonMeasurement as exc:
            # The invocation was never completed, so it contributes no entry: an
            # absent measurement is represented by absence, never by a fabricated
            # exit code or digest (contract 8.3.1).
            exc.artifacts = entries
            raise
        verdict: Optional[dict] = None
        if code == 0:
            try:
                verdict = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise NonMeasurement(
                    "internal-error",
                    "frozen verifier exited 0 for %s but stdout is not parseable "
                    "JSON: %s" % (artifact.record_id, exc),
                    artifacts=entries)
            if not isinstance(verdict, dict):
                raise NonMeasurement(
                    "internal-error",
                    "frozen verifier exited 0 for %s but stdout is not a JSON "
                    "object" % artifact.record_id,
                    artifacts=entries)
        entries.append({
            "artifact_ref": artifact.ref,
            "request_envelope_digest": digest_str(request),
            "verifier_exit_code": code,
            # Contract 8.3: null whenever the exit code is 1, because no verdict
            # exists. stderr is hashed for audit and NEVER parsed for semantics.
            "verifier_result": verdict,
            "verifier_stderr_digest": digest_str(stderr),
        })
        verdicts[artifact.record_id] = verdict

    # ---- contract 7.2: the causal guard on a non-zero frozen exit -----------
    # Reaching this point means the request was preflight-clean in the sense 7.2
    # requires: the manifest verified, the numeric preflight passed, the envelope
    # was built per 5.1, and the operator inputs are the bundle's own.
    # Cross-lane envelope equality is NOT part of this condition and never was
    # implementable here -- it is an aggregate-harness gate (AD15-IR-4, 8.1).
    for entry in entries:
        code = entry["verifier_exit_code"]
        record_id = entry["artifact_ref"]["record_id"]
        if code == 0:
            continue
        if code == 1:
            if scenario_id in EXIT1_REJECT_SCENARIOS:
                continue                   # a targeted stage-0 / stage-1 failure
            raise NonMeasurement(
                "verifier-run-invalid",
                "frozen verifier exit 1 for %s under %s is outside the two "
                "contract-7.2 conditions, so it is this evaluator's error rather "
                "than the artifact's" % (record_id, scenario_id),
                artifacts=entries)
        raise NonMeasurement(
            "internal-error",
            "frozen verifier exited %d for %s; only 0 and 1 are classifiable"
            % (code, record_id),
            artifacts=entries)

    # ---- contract 8.2 withheld_reasons, contract 7.1 ------------------------
    withheld_reasons: List[dict] = []
    authenticated_withheld = False
    for entry in entries:
        verdict = entry["verifier_result"]
        if not isinstance(verdict, dict):
            continue
        auth = list(verdict.get("authenticated_withheld") or [])
        wit = list(verdict.get("witnessed_withheld") or [])
        if auth or wit:
            withheld_reasons.append({
                "artifact_ref": entry["artifact_ref"],
                "authenticated_withheld": auth,
                "witnessed_withheld": wit,
            })
        if auth:
            authenticated_withheld = True

    if authenticated_withheld:
        # Contract 7.1: withheld is the ABSENCE of a measurement. Not REJECT --
        # nothing was refused -- and emphatically not ACCEPT.
        raise NonMeasurement(
            "authenticated-withheld",
            "a non-empty authenticated_withheld channel makes %s "
            "measurement-invalid (contract 7.1)" % scenario_id,
            withheld_reasons=withheld_reasons,
            artifacts=entries)

    # ---- predicates (contract 6, 6.1) ---------------------------------------
    if scenario_id in SINGLE_ARTIFACT_FAMILY:
        # A single-artifact scenario has no bundle graph, no Control/Execution
        # pair and no observer relationship: it is not run through the
        # predicates at all. NOT_APPLICABLE is a MEASURED outcome (8.2.3).
        predicates = {"R_A": NOT_APPLICABLE, "R_B": NOT_APPLICABLE,
                      "R_C": NOT_APPLICABLE}
    else:
        r_a, why_a = predicate_r_a(artifacts)
        r_b, why_b = predicate_r_b(artifacts)
        r_c, why_c = predicate_r_c(artifacts, verdicts)
        # All three are evaluated even when one has already failed: WHICH
        # predicate fired is the measurement (contract 6.1).
        predicates = {"R_A": r_a, "R_B": r_b, "R_C": r_c}
        for label, reasons in (("R-A", why_a), ("R-B", why_b), ("R-C", why_c)):
            for reason in reasons:
                warn("%s %s: %s" % (scenario_id, label, reason))

    # ---- Level-1 mapping (contract 7) ---------------------------------------
    reject = False
    for entry in entries:
        if entry["verifier_exit_code"] == 1:
            reject = True                  # invalid: no class at all
            continue
        verdict = entry["verifier_result"]
        if isinstance(verdict, dict) and (verdict.get("authenticated_failures") or []):
            reject = True                  # definitive Authenticated-tier failure

    level1 = map_level1(reject, predicates)

    # Contract 8.3.1 rule 4: a MEASURED result's artifacts[] length MUST equal
    # the bundle's artifact count from section 5.
    if len(entries) != len(artifacts):
        raise NonMeasurement(
            "internal-error",
            "MEASURED result would carry %d artifact entries for a %d-artifact "
            "bundle" % (len(entries), len(artifacts)),
            artifacts=entries)

    return build_result(scenario_id, MEASURED, level1, predicates, None, entries,
                        withheld_reasons, verifier_digests)


def _assert_operator_flags_consistent(args, bundle_dir: str,
                                      selected: Dict[str, FileEntry]) -> None:
    """Ambiguity A1: the operator-input flags are accepted, but only as an
    assertion that they name the file the manifest ``role`` already selected. A
    flag can never change what is measured.
    """
    supplied = (("bindings", args.bindings),
                ("independence_policy", args.independence_policy),
                ("revocation", args.revocation))
    for role, value in supplied:
        if value is None:
            continue
        expected = os.path.realpath(
            os.path.join(bundle_dir, *selected[role].path.split("/")))
        given = os.path.realpath(
            value if os.path.isabs(value) else os.path.join(os.getcwd(), value))
        if given != expected:
            raise UsageError(
                "%s names %s, but the bundle manifest selects %s for role %r; "
                "operator inputs are the bundle's own (contract 5.1)"
                % (OPERATOR_FLAG[role], given, expected, role))


# --------------------------------------------------------------------------
# CLI (contract 8.1, 8.5)
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interop_eval.py",
        description=("AIREP v0.2 Python reference interop evaluator "
                     "(INTEROP_REFERENCE_EVALUATOR_CONTRACT.md). One invocation "
                     "evaluates exactly one scenario bundle and writes at most "
                     "one JSON result object to stdout."),
        add_help=True,
    )
    parser.add_argument("--bundle")
    # Accepted only as a consistency assertion against the manifest roles (A1).
    parser.add_argument("--bindings")
    parser.add_argument("--independence-policy", dest="independence_policy")
    parser.add_argument("--revocation")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)   # argparse exits 2 on usage errors, 0 on --help

    try:
        if args.bundle is None:
            raise UsageError("--bundle is required")
        result = evaluate_bundle(args)
    except UsageError as exc:
        warn("usage error: %s" % exc)
        return 2
    except BundleIdentityError as exc:
        # Identity was never established: silence on stdout (contract 8.5).
        warn("bundle identity: %s" % exc)
        return 1
    except NonMeasurement as exc:
        warn("%s: %s" % (exc.reason, exc.detail))
        if exc.scenario_id is None:
            # Unreachable by construction: NonMeasurement is only raised
            # downstream of an established identity. Fail closed rather than
            # emit a result object with an invented identity.
            warn("no bundle identity for an exit-3 result object")
            return 1
        sys.stdout.write(dump_json(build_result(
            exc.scenario_id, exc.status, None, None, nonmeasurement_object(exc),
            exc.artifacts, exc.withheld_reasons, exc.verifier_digests)))
        return 3
    sys.stdout.write(dump_json(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
