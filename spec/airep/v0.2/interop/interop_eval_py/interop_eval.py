#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 Python reference interop evaluator (AD15-IR-2).

Implements ``INTEROP_REFERENCE_EVALUATOR_CONTRACT.md`` sections 5-8 over the
FROZEN Python class verifier, which is invoked as a SUBPROCESS and never
imported, vendored or re-implemented (contract section 3).

Composition, in the contract's own order:

  * section 5    manifest verification (per-file sha256) BEFORE anything is parsed;
  * section 5.1  numeric preflight, then the closed section-0 request envelope,
                 serialized with RFC 8785 (JCS); ``request_envelope_digest`` is
                 taken over exactly those bytes;
  * section 3    frozen-verifier digest assertion before use;
  * section 6    the three reconciliation predicates R-A / R-B / R-C, with the
                 section 6.1 applicability matrix;
  * section 7    the Level-1 mapping, in the pinned order, plus 7.1
                 (``authenticated_withheld`` => MEASUREMENT_INVALID) and 7.2
                 (the causal guard on frozen ``exit 1``);
  * section 8    one bundle per invocation, one JSON result object, and the
                 8.5 exit/stdout table.

Deliberately NOT implemented, per ruling ``AD15-IR-4``: cross-lane envelope
digest comparison. A single Python invocation cannot observe the Node lane's
digest; the comparison belongs to the aggregate harness. This evaluator emits
only its own ``request_envelope_digest`` per artifact.

Exit codes (contract 8.5):
  0  exactly one result object, ``measurement_status: MEASURED``, Level-1 verdict
  1  no result object, stdout empty -- manifest missing/unparseable, bundle
     identity unknown, a manifest-listed file absent
  2  no result object, stdout empty -- CLI usage error
  3  exactly one result object, MEASUREMENT_INVALID or ERROR, ``level1: null``

stdlib only. Diagnostics go to stderr and are never a source of semantics
(contract 8.3, 8.5).

-----------------------------------------------------------------------------
UNPINNED INPUT SURFACES -- read this before changing anything below.

The contract fixes what the manifest MEANS (section 5: it names the
``scenario_id`` and lists every file the bundle ships, each with a sha256 over
its original bytes) but pins no member names for it, and corpus bytes are on
HOLD, so no manifest exists to read.  ``load_manifest`` therefore accepts the
three shapes that express exactly that meaning and nothing more, and it is the
single function to change if the corpus lands on a different spelling:

    {"scenario_id": "...", "files": {"<relpath>": "<64 hex>"}}
    {"scenario_id": "...", "files": {"<relpath>": {"sha256": "<64 hex>"}}}
    {"scenario_id": "...", "files": [{"path": "<relpath>", "sha256": "<64 hex>"}]}

Two further surfaces are unpinned and are handled structurally rather than by
inventing manifest metadata:

  * WHICH listed files are artifacts -- decided by structure (a JSON object
    carrying ``airep_version`` "0.2" and a known ``artifact_type``), not by a
    manifest role field. Every listed file is still digest-verified.
  * WHICH file carries a ``head_witness`` -- named by ``--head-witness``. None
    of the twelve scenarios defines one.

These are recorded as findings in the authoring report, not resolved here.
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
from typing import Any, Dict, List, Optional, Tuple

EVALUATOR_VERSION = "0.1.0"

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
# Frozen inputs (contract 3)
# --------------------------------------------------------------------------

CLASS_VERIFICATION_RELPATH = (os.pardir, os.pardir, "class-verification")

#: The three digests contract 3 pins, keyed exactly as its table names them.
#: They are recorded in every result object (contract 8.2).
FROZEN_DIGESTS: Dict[str, str] = {
    "verifier_py/class_verifier.py":
        "5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc",
    "verifier_node_r2/class_verifier.mjs":
        "e678ff5706547d4fb79ab8ad013bdf6f41e4429065a42309d6a4a6515632bde4",
    "CLASS_VERIFIER_CONTRACT.md":
        "7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885",
}

#: Contract 3: "the Python evaluator invokes only verifier_py". Crossing the
#: lanes is forbidden, so this lane recomputes and compares only the two frozen
#: files it actually uses. The Node row is carried from the contract table as
#: the contract's own statement of that file's digest; it is NOT asserted here,
#: because asserting it would require this lane to reach into the other lane's
#: tree. Contract 8.2 says "the three asserted digests from section 3" while
#: contract 3 scopes assertion to "before use" -- flagged as a finding, not
#: silently resolved.
ASSERTED_BY_THIS_LANE: Tuple[str, ...] = (
    "verifier_py/class_verifier.py",
    "CLASS_VERIFIER_CONTRACT.md",
)

ARTIFACT_TYPES = ("decision", "control", "execution", "effect")
WIRE_VERSION = "0.2"

#: Contract 7.2: frozen ``exit 1`` may be read as Level-1 REJECT only for these
#: scenarios (stage-0 / stage-1 invalidity targets), and no other.
EXIT1_REJECT_SCENARIOS = frozenset({"IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"})

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

MAX_SAFE_INTEGER = 9007199254740991  # 2**53 - 1


class UsageError(Exception):
    """CLI usage error -> exit 2, stdout empty (contract 8.5)."""


class BundleIdentityError(Exception):
    """Bundle identity could not be established -> exit 1, stdout empty."""


class Unmeasurable(Exception):
    """Identity known, scenario not measurable -> exit 3 with a result object.

    ``status`` is MEASUREMENT_INVALID or ERROR (contract 8.5).
    """

    def __init__(self, status: str, detail: str,
                 withheld_reasons: Optional[List[dict]] = None,
                 artifacts: Optional[List[dict]] = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.withheld_reasons = withheld_reasons or []
        self.artifacts = artifacts or []
        #: Stamped by ``evaluate_bundle`` once the manifest has been parsed, so
        #: the exit-3 result object can name the scenario it failed on without
        #: re-reading the manifest (contract 8.5).
        self.scenario_id: Optional[str] = None


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


def record_sort_key(record_id: str) -> bytes:
    """Ascending UTF-8 byte order (contract 5.1, 8.4)."""
    return record_id.encode("utf-8")


def dump_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def warn(message: str) -> None:
    sys.stderr.write(message.rstrip("\n") + "\n")


# --------------------------------------------------------------------------
# Numeric preflight (contract 5.1)
# --------------------------------------------------------------------------

def numeric_preflight(value: Any, base_pointer: str = "") -> Optional[Tuple[str, str]]:
    """Walk ``value`` and return ``(json_pointer, reason)`` for the first number
    outside the pinned envelope, or ``None`` when every number is admissible.

    Pinned checks, in the contract's own words:

      * finite and IEEE-754 representable -- no NaN, no infinity;
      * integers: absolute value <= 2**53 - 1.

    "Integer" is taken as JSON integer SYNTAX, which is what ``json`` decodes to
    ``int``; a number written with a fraction or exponent decodes to ``float``
    and is checked only for finiteness. That reading is recorded as a finding.
    """
    stack: List[Tuple[str, Any]] = [(base_pointer, value)]
    while stack:
        pointer, node = stack.pop()
        if isinstance(node, bool):
            continue                      # bool is not a JSON number
        if isinstance(node, int):
            if abs(node) > MAX_SAFE_INTEGER:
                return pointer, "integer magnitude exceeds 2**53-1"
            continue
        if isinstance(node, float):
            # json decodes NaN/Infinity/-Infinity, and overflowing exponents
            # (1e400) decode to inf; both are rejected here.
            if node != node or node in (float("inf"), float("-inf")):
                return pointer, "number is not finite"
            continue
        if isinstance(node, dict):
            for key in sorted(node, key=lambda k: k.encode("utf-8"), reverse=True):
                stack.append((pointer + "/" + pointer_escape(key), node[key]))
            continue
        if isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((pointer + "/" + str(index), node[index]))
    return None


# --------------------------------------------------------------------------
# Bundle manifest (contract 5)
# --------------------------------------------------------------------------

class Manifest:
    def __init__(self, scenario_id: str, files: Dict[str, str]) -> None:
        self.scenario_id = scenario_id
        self.files = files            # relative path -> lowercase hex sha256


def _normalize_files(raw: Any) -> Dict[str, str]:
    files: Dict[str, str] = {}

    def put(path: Any, digest: Any) -> None:
        if not isinstance(path, str) or not path:
            raise BundleIdentityError("manifest file entry has no usable path")
        if not isinstance(digest, str):
            raise BundleIdentityError("manifest entry %r has no sha256 string" % path)
        digest = digest[7:] if digest.startswith("sha256:") else digest
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise BundleIdentityError(
                "manifest entry %r has a malformed sha256 %r" % (path, digest))
        if path in files:
            raise BundleIdentityError("manifest lists %r twice" % path)
        files[path] = digest

    if isinstance(raw, dict):
        for path, entry in raw.items():
            if isinstance(entry, dict):
                put(path, entry.get("sha256"))
            else:
                put(path, entry)
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                raise BundleIdentityError("manifest files array holds a non-object")
            put(entry.get("path"), entry.get("sha256"))
    else:
        raise BundleIdentityError("manifest 'files' is neither an object nor an array")
    if not files:
        raise BundleIdentityError("manifest lists no files")
    return files


def load_manifest(bundle_dir: str) -> Manifest:
    """Read and parse the bundle manifest.

    Every failure here is a contract-8.5 ``exit 1``: without a parsed manifest
    there is no ``scenario_id``, so there is nothing to write a result object
    about.
    """
    path = os.path.join(bundle_dir, "manifest.json")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise BundleIdentityError("manifest unreadable at %s: %s" % (path, exc))
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleIdentityError("manifest is not parseable JSON: %s" % exc)
    if not isinstance(doc, dict):
        raise BundleIdentityError("manifest is not a JSON object")
    scenario_id = doc.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise BundleIdentityError("manifest carries no usable scenario_id")
    if "files" not in doc:
        raise BundleIdentityError("manifest carries no 'files' member")
    return Manifest(scenario_id, _normalize_files(doc["files"]))


def verify_manifest(bundle_dir: str, manifest: Manifest) -> Dict[str, bytes]:
    """Verify every listed file against its manifest digest BEFORE parsing.

    A listed file that is absent is contract-8.5 ``exit 1`` ("a required
    artifact absent"); a file present with the wrong digest is a hard ERROR at
    ``exit 3`` ("a file failing its manifest digest").
    """
    contents: Dict[str, bytes] = {}
    for relpath in sorted(manifest.files, key=lambda p: p.encode("utf-8")):
        full = os.path.normpath(os.path.join(bundle_dir, relpath))
        if os.path.relpath(full, bundle_dir).startswith(os.pardir):
            raise BundleIdentityError("manifest path %r escapes the bundle" % relpath)
        try:
            with open(full, "rb") as handle:
                data = handle.read()
        except OSError:
            raise BundleIdentityError("manifest lists %r but it is absent" % relpath)
        actual = sha256_hex(data)
        if actual != manifest.files[relpath]:
            raise Unmeasurable(
                ERROR,
                "manifest digest mismatch for %s: expected %s, measured %s"
                % (relpath, manifest.files[relpath], actual))
        contents[relpath] = data
    return contents


# --------------------------------------------------------------------------
# Frozen-verifier digest assertion (contract 3)
# --------------------------------------------------------------------------

def class_verification_dir() -> str:
    return os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), *CLASS_VERIFICATION_RELPATH))


def assert_frozen_digests() -> None:
    """Recompute and compare the frozen files THIS lane uses. Mismatch is a hard
    ERROR: the run is not valid and no Level-1 verdict is emitted (contract 3).
    """
    base = class_verification_dir()
    for name in ASSERTED_BY_THIS_LANE:
        path = os.path.join(base, *name.split("/"))
        try:
            with open(path, "rb") as handle:
                measured = sha256_hex(handle.read())
        except OSError as exc:
            raise Unmeasurable(ERROR, "frozen file %s unreadable: %s" % (name, exc))
        if measured != FROZEN_DIGESTS[name]:
            raise Unmeasurable(
                ERROR,
                "frozen digest assertion failed for %s: expected %s, measured %s"
                % (name, FROZEN_DIGESTS[name], measured))


def frozen_verifier_path() -> str:
    return os.path.join(class_verification_dir(), "verifier_py", "class_verifier.py")


# --------------------------------------------------------------------------
# Artifacts
# --------------------------------------------------------------------------

class Artifact:
    def __init__(self, relpath: str, value: dict) -> None:
        self.relpath = relpath
        self.value = value
        self.record_id = value["record_id"]
        self.chain_id = value.get("chain_id")
        self.artifact_type = value["artifact_type"]

    @property
    def ref(self) -> dict:
        ref: Dict[str, str] = {"record_id": self.record_id}
        if isinstance(self.chain_id, str):
            ref["chain_id"] = self.chain_id
        return ref


def looks_like_artifact(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("airep_version") == WIRE_VERSION
        and value.get("artifact_type") in ARTIFACT_TYPES
        and isinstance(value.get("record_id"), str)
    )


def collect_artifacts(contents: Dict[str, bytes], skip: List[str]) -> List[Artifact]:
    """Classify manifest-listed files structurally (see the module docstring)."""
    artifacts: List[Artifact] = []
    for relpath in sorted(contents, key=lambda p: p.encode("utf-8")):
        if relpath in skip:
            continue
        try:
            value = json.loads(contents[relpath].decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue                      # not an artifact; still digest-verified
        if looks_like_artifact(value):
            artifacts.append(Artifact(relpath, value))
    artifacts.sort(key=lambda a: record_sort_key(a.record_id))
    return artifacts


def by_type(artifacts: List[Artifact], artifact_type: str) -> List[Artifact]:
    return [a for a in artifacts if a.artifact_type == artifact_type]


# --------------------------------------------------------------------------
# Request envelope (contract 5.1)
# --------------------------------------------------------------------------

def build_envelope(primary: Artifact, artifacts: List[Artifact],
                   head_witness: Optional[dict]) -> dict:
    """The closed section-0 envelope for ``primary``.

    ``related_artifacts`` is the OTHER artifacts of the same bundle and no
    others, ascending by UTF-8 byte order of ``record_id``; for a
    single-artifact scenario it is the empty array -- present, never absent.
    """
    related = [a for a in artifacts if a is not primary]
    related.sort(key=lambda a: record_sort_key(a.record_id))
    envelope: Dict[str, Any] = {
        "artifact": primary.value,
        "related_artifacts": [a.value for a in related],
    }
    if head_witness is not None:
        envelope["head_witness"] = head_witness
    return envelope


def envelope_bytes(envelope: dict) -> bytes:
    """RFC 8785 canonical bytes; ``request_envelope_digest`` is taken over these."""
    return jcs.canonicalize(envelope)


# --------------------------------------------------------------------------
# Frozen-verifier invocation (contract 3: subprocess, never imported)
# --------------------------------------------------------------------------

def invoke_frozen_verifier(request: bytes, operator_flags: List[str]
                           ) -> Tuple[int, bytes, bytes]:
    """Run the frozen Python class verifier on one request envelope.

    Nothing is written into the frozen tree: the request lives in a temporary
    directory that is removed on return.
    """
    verifier = frozen_verifier_path()
    with tempfile.TemporaryDirectory(prefix="airep-interop-eval-") as workdir:
        request_path = os.path.join(workdir, "request.json")
        with open(request_path, "wb") as handle:
            handle.write(request)
        argv = [sys.executable, verifier, "--request", request_path] + operator_flags
        try:
            completed = subprocess.run(argv, capture_output=True, check=False)
        except OSError as exc:
            raise Unmeasurable(ERROR, "frozen verifier not invocable: %s" % exc)
    return completed.returncode, completed.stdout, completed.stderr


# --------------------------------------------------------------------------
# Reconciliation predicates (contract 6)
# --------------------------------------------------------------------------

def resolve_reference(reference: dict, artifacts: List[Artifact]) -> str:
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
        if a.record_id == record_id
        and (chain_id is None or a.chain_id == chain_id)
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
    """R-A -- every cross-artifact reference in the bundle resolves uniquely."""
    problems: List[str] = []
    for artifact in artifacts:
        for member in REFERENCE_EDGES.get(artifact.artifact_type, ()):
            outcome = resolve_reference(artifact.value.get(member), artifacts)
            if outcome != "resolved":
                problems.append("%s /%s %s" % (artifact.record_id, member, outcome))
    return (FAIL if problems else PASS), problems


def predicate_r_b(artifacts: List[Artifact]) -> Tuple[str, List[str]]:
    """R-B -- Control ``authorized_action_digest`` vs Execution
    ``executed_action_digest``, compared as EXACT strings. Both are
    ``sha256_digest`` by schema, so no normalization, case folding or re-hashing
    is performed.
    """
    controls = by_type(artifacts, "control")
    executions = by_type(artifacts, "execution")
    if len(controls) != 1 or len(executions) != 1:
        raise Unmeasurable(
            ERROR,
            "R-B needs exactly one Control and one Execution; bundle carries "
            "%d and %d" % (len(controls), len(executions)))
    authorized = controls[0].value.get("authorized_action_digest")
    executed = executions[0].value.get("executed_action_digest")
    if isinstance(authorized, str) and isinstance(executed, str) and authorized == executed:
        return PASS, []
    return FAIL, ["authorized %r != executed %r" % (authorized, executed)]


def predicate_r_c(artifacts: List[Artifact], verdicts: Dict[str, Optional[dict]]
                  ) -> Tuple[str, List[str]]:
    """R-C -- independence, TAKEN FROM the frozen verifier's
    ``observer_assessment`` for the Effect and never re-derived here (contract
    6: re-implementing it would create a second, unpinned definition).

    An Effect whose wire ``observer_relationship`` is ``independent`` while the
    frozen output reports an effective assessment of ``unknown`` fails.
    """
    effects = by_type(artifacts, "effect")
    if len(effects) != 1:
        raise Unmeasurable(
            ERROR, "R-C needs exactly one Effect; bundle carries %d" % len(effects))
    effect = effects[0]
    verdict = verdicts.get(effect.record_id)
    if not isinstance(verdict, dict):
        raise Unmeasurable(ERROR, "R-C has no frozen verdict for the Effect")
    wire = effect.value.get("observer_relationship")
    effective = verdict.get("observer_assessment")
    if wire == "independent" and effective == "unknown":
        return FAIL, ["wire observer_relationship 'independent', effective 'unknown'"]
    return PASS, []


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
                 predicates: Dict[str, str], artifacts: List[dict],
                 withheld_reasons: List[dict]) -> dict:
    return {
        "scenario_id": scenario_id,
        "measurement_status": status,
        "level1": level1,
        "predicates": predicates,
        "artifacts": artifacts,
        "withheld_reasons": withheld_reasons,
        "verifier_digests": dict(FROZEN_DIGESTS),
        "evaluator_version": EVALUATOR_VERSION,
    }


def na_predicates() -> Dict[str, str]:
    return {"R_A": NOT_APPLICABLE, "R_B": NOT_APPLICABLE, "R_C": NOT_APPLICABLE}


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def operator_flags(args, bundle_dir: str, manifest: Manifest) -> Tuple[List[str], List[str]]:
    """Build the pass-through operator-input flags for the frozen verifier.

    File-valued inputs are passed BY PATH, unchanged: contract 5.1 forbids an
    evaluator from synthesizing, filtering, reordering or re-emitting them. Each
    must be the bundle's own -- inside the bundle and covered by the manifest --
    which is what makes "the bundle's own operator-input bytes" auditable rather
    than assumed (contract 5).
    """
    flags: List[str] = []
    consumed: List[str] = []
    for flag, value in (("--bindings", args.bindings),
                        ("--independence-policy", args.independence_policy),
                        ("--revocation", args.revocation)):
        if value is None:
            continue
        relpath = _bundle_relpath(value, bundle_dir, manifest)
        consumed.append(relpath)
        flags += [flag, os.path.normpath(os.path.join(bundle_dir, relpath))]
    # Clock inputs are literal operator values on the frozen CLI, not documents;
    # they are forwarded verbatim.
    if args.now is not None:
        flags += ["--now", args.now]
    if args.freshness_window is not None:
        flags += ["--freshness-window", args.freshness_window]
    return flags, consumed


def _bundle_relpath(value: str, bundle_dir: str, manifest: Manifest) -> str:
    full = os.path.normpath(value if os.path.isabs(value)
                            else os.path.join(bundle_dir, value))
    relpath = os.path.relpath(full, bundle_dir)
    if relpath.startswith(os.pardir):
        raise Unmeasurable(
            ERROR, "operator input %s is outside the bundle" % value)
    if relpath not in manifest.files:
        raise Unmeasurable(
            ERROR, "operator input %s is not covered by the manifest" % relpath)
    return relpath


def evaluate_bundle(args, invoke=invoke_frozen_verifier) -> Tuple[int, dict]:
    """Evaluate exactly one bundle. Returns ``(exit_code, result_object)``.

    ``invoke`` is the frozen-verifier subprocess seam; tests substitute a stub so
    that no corpus bytes are required to exercise the mapping.
    """
    bundle_dir = os.path.abspath(args.bundle)
    if not os.path.isdir(bundle_dir):
        raise BundleIdentityError("bundle directory %s does not exist" % bundle_dir)

    manifest = load_manifest(bundle_dir)                       # exit 1 on failure
    scenario_id = manifest.scenario_id
    try:
        return _evaluate_verified(args, bundle_dir, manifest, invoke)
    except Unmeasurable as exc:
        # Identity IS established from here on, so the caller owes a result
        # object naming the scenario it failed on (contract 8.5).
        exc.scenario_id = scenario_id
        raise


def _evaluate_verified(args, bundle_dir: str, manifest: Manifest,
                       invoke) -> Tuple[int, dict]:
    """Everything downstream of a parsed manifest."""
    scenario_id = manifest.scenario_id
    contents = verify_manifest(bundle_dir, manifest)           # before any parsing

    assert_frozen_digests()                                    # contract 3

    flags, consumed = operator_flags(args, bundle_dir, manifest)

    head_witness = None
    if args.head_witness is not None:
        hw_rel = _bundle_relpath(args.head_witness, bundle_dir, manifest)
        consumed.append(hw_rel)
        try:
            head_witness = json.loads(contents[hw_rel].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise Unmeasurable(ERROR, "head_witness file %s is not parseable JSON: %s"
                               % (hw_rel, exc))

    artifacts = collect_artifacts(contents, consumed)
    if not artifacts:
        raise Unmeasurable(ERROR, "bundle carries no AIREP v0.2 artifact")

    # Contract 6.1 applicability is structural: a single-artifact scenario has no
    # bundle graph, no Control/Execution pair and no observer relationship, so it
    # is not run through the predicates at all. The only other shape the contract
    # defines is the four-artifact reconciliation bundle.
    single = len(artifacts) == 1
    if not single:
        types = sorted(a.artifact_type for a in artifacts)
        if types != sorted(ARTIFACT_TYPES):
            raise Unmeasurable(
                ERROR,
                "bundle is neither single-artifact nor a four-artifact "
                "reconciliation bundle; carries %s" % ", ".join(types))

    # ---- numeric preflight, before any envelope is assembled (contract 5.1) --
    for artifact in artifacts:
        offending = numeric_preflight(artifact.value)
        if offending is not None:
            raise Unmeasurable(
                ERROR, "numeric preflight rejected %s at JSON Pointer %r: %s"
                % (artifact.relpath, offending[0] or "", offending[1]))
    if head_witness is not None:
        offending = numeric_preflight(head_witness)
        if offending is not None:
            raise Unmeasurable(
                ERROR, "numeric preflight rejected head_witness at JSON Pointer "
                "%r: %s" % (offending[0] or "", offending[1]))
    for relpath in consumed:
        try:
            document = json.loads(contents[relpath].decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue          # the frozen verifier owns operator-input parsing
        offending = numeric_preflight(document)
        if offending is not None:
            raise Unmeasurable(
                ERROR, "numeric preflight rejected operator input %s at JSON "
                "Pointer %r: %s" % (relpath, offending[0] or "", offending[1]))

    # ---- one frozen-verifier invocation per artifact ------------------------
    entries: List[dict] = []
    verdicts: Dict[str, Optional[dict]] = {}
    exit_codes: Dict[str, int] = {}
    for artifact in artifacts:
        request = envelope_bytes(build_envelope(artifact, artifacts, head_witness))
        code, stdout, stderr = invoke(request, flags)
        verdict: Optional[dict] = None
        if code == 0:
            try:
                verdict = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise Unmeasurable(
                    ERROR, "frozen verifier exited 0 with unparseable stdout for "
                    "%s: %s" % (artifact.record_id, exc))
            if not isinstance(verdict, dict):
                raise Unmeasurable(
                    ERROR, "frozen verifier emitted a non-object verdict for %s"
                    % artifact.record_id)
        entries.append({
            "artifact_ref": artifact.ref,
            "request_envelope_digest": digest_str(request),
            "verifier_exit_code": code,
            # contract 8.3: null whenever the exit code is 1, because no verdict
            # exists. stderr is hashed for audit and NEVER parsed for semantics.
            "verifier_result": verdict,
            "verifier_stderr_digest": digest_str(stderr),
        })
        verdicts[artifact.record_id] = verdict
        exit_codes[artifact.record_id] = code

    entries.sort(key=lambda e: record_sort_key(e["artifact_ref"]["record_id"]))

    # ---- contract 7.2: the causal guard on frozen exit 1 --------------------
    # Reaching this point means the request was preflight-clean in every sense
    # this lane can observe: the manifest verified, the numeric preflight
    # passed, the envelope was built per 5.1, and the operator inputs are the
    # bundle's own. The clause "both lanes produced identical envelope bytes" is
    # NOT observable from a single Python invocation and is the aggregate
    # harness's gate under ruling AD15-IR-4; it is flagged, not silently
    # reinterpreted.
    for record_id, code in sorted(exit_codes.items(), key=lambda kv: record_sort_key(kv[0])):
        if code == 0:
            continue
        if code == 1 and scenario_id in EXIT1_REJECT_SCENARIOS:
            continue                       # a targeted stage-0 / stage-1 failure
        raise Unmeasurable(
            ERROR,
            "frozen verifier exit %d for %s is the evaluator's own error under "
            "contract 7.2, not the artifact's" % (code, record_id),
            artifacts=entries)

    # ---- contract 8.2 withheld_reasons, contract 7.1 ------------------------
    withheld_reasons: List[dict] = []
    authenticated_withheld_seen = False
    for entry in entries:
        verdict = entry["verifier_result"]
        if not isinstance(verdict, dict):
            continue
        auth = verdict.get("authenticated_withheld") or []
        wit = verdict.get("witnessed_withheld") or []
        if auth or wit:
            withheld_reasons.append({
                "artifact_ref": entry["artifact_ref"],
                "authenticated_withheld": list(auth),
                "witnessed_withheld": list(wit),
            })
        if auth:
            authenticated_withheld_seen = True

    if authenticated_withheld_seen:
        # Contract 7.1: withheld is the ABSENCE of a measurement. Not REJECT --
        # nothing was refused -- and emphatically not ACCEPT.
        raise Unmeasurable(
            MEASUREMENT_INVALID,
            "a non-empty authenticated_withheld channel makes this scenario "
            "measurement-invalid (contract 7.1)",
            withheld_reasons=withheld_reasons,
            artifacts=entries)

    # ---- predicates (contract 6, 6.1) ---------------------------------------
    predicates = na_predicates()
    if not single:
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
        verdict = entry["verifier_result"]
        if entry["verifier_exit_code"] == 1:
            reject = True                  # invalid: no class at all
            continue
        if isinstance(verdict, dict) and (verdict.get("authenticated_failures") or []):
            reject = True                  # definitive Authenticated-tier failure

    level1 = map_level1(reject, predicates)
    result = build_result(scenario_id, MEASURED, level1, predicates, entries,
                          withheld_reasons)
    return 0, result


# --------------------------------------------------------------------------
# CLI (contract 8.1, 8.5)
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="interop_eval.py",
        description=("AIREP v0.2 Python reference interop evaluator "
                     "(INTEROP_REFERENCE_EVALUATOR_CONTRACT.md). One invocation "
                     "evaluates exactly one scenario bundle."),
        add_help=True,
    )
    parser.add_argument("--bundle")
    parser.add_argument("--bindings")
    parser.add_argument("--independence-policy", dest="independence_policy")
    parser.add_argument("--revocation")
    parser.add_argument("--now")
    parser.add_argument("--freshness-window", dest="freshness_window")
    parser.add_argument("--head-witness", dest="head_witness")
    args = parser.parse_args(argv)   # argparse exits 2 on usage errors, 0 on --help

    try:
        if args.bundle is None:
            raise UsageError("--bundle is required")
        code, result = evaluate_bundle(args)
    except UsageError as exc:
        warn("usage error: %s" % exc)
        return 2
    except BundleIdentityError as exc:
        # Bundle identity was never established: silence on stdout (contract 8.5).
        warn("bundle preflight: %s" % exc)
        return 1
    except Unmeasurable as exc:
        warn("%s: %s" % (exc.status.lower(), exc.detail))
        if exc.scenario_id is None:
            # Unreachable by construction: Unmeasurable is only raised
            # downstream of a parsed manifest. Fail closed rather than emit a
            # result object with an invented identity.
            warn("no bundle identity for an exit-3 result object")
            return 1
        sys.stdout.write(dump_json(build_result(
            exc.scenario_id, exc.status, None, na_predicates(),
            exc.artifacts, exc.withheld_reasons)))
        return 3
    sys.stdout.write(dump_json(result))
    return code


if __name__ == "__main__":
    sys.exit(main())
