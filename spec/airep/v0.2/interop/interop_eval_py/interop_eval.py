#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 Python reference interop evaluator (AD15-IR-2), post-erratum.

Implements ``INTEROP_REFERENCE_EVALUATOR_CONTRACT.md`` at contract basis
``cd7b634f46e1106aca8f228d9633150cbc111855``
(sha256 ``fa87cb246d4bb006ca1cb6aa461252815215376d6291dfee3aa51bb79ce7b1d2``),
alongside ``INTEROP_CORPUS_CONTRACT.md``
(sha256 ``ac15ec39dd738d5c4ab6cba03aad92682a0f1b3af1d613ff88b26f2f4587d8bd``),
i.e. the canonical post-Erratum-4 contracts, over the FROZEN Python class
verifier, which is invoked as a SUBPROCESS and is never imported, vendored or
re-implemented (contract 3).

Erratum 4 rulings carried here:

  * E4-1  the help carve-out is ONE EXACT SINGLE-TOKEN INVOCATION. The
          meta-action is ``--help`` AND NOTHING ELSE: it exits 0 with human text
          on stdout and no result object. ``-h`` is NOT an alias -- it is a CLI
          usage error at exit 2 -- and ``--help`` combined with any other
          argument is a usage error too, because only the LONE help invocation
          is carved out. Help text content and byte length are NOT a parity
          requirement. This SUPERSEDES E3-4's "exactly one flag wide", which was
          ambiguous enough that two lanes measurably diverged on ``-h``;
  * E4-2  the identity boundary is a DIRECT READ of ``DIR/manifest.json``, not
          an enumeration of the bundle first. All five of these are identity not
          established -> exit 1, stdout empty, no result object: the bundle root
          cannot be accessed; ``DIR/manifest.json`` is not found; it is found but
          cannot be opened or read; its bytes do not parse as strict JSON; no
          registered ``scenario_id`` can be obtained. A root manifest that
          cannot be read NEVER yields ``bundle-file-unreadable`` -- a reason
          belongs to a result object, and there is no scenario to name one
          after;
  * E4-3  ``bundle-directory-unreadable`` joins the closed registry -> ERROR,
          exit 3. After identity is established, a bundle traversal that cannot
          complete because a directory cannot be enumerated is THAT reason and
          not ``manifest-invalid``: the latter says the layout is WRONG, this
          says the layout could not be MEASURED. Enumeration succeeding but a
          listed file being absent remains ``bundle-file-missing``; a listed
          regular file whose bytes cannot be read remains
          ``bundle-file-unreadable``;
  * E4-4  ruling ``AD15-IR-7``: duplicate semantic IDs are NOT preflight
          invalidity. There is no bundle-wide preflight gate on duplicate
          ``record_id`` or duplicate ``(chain_id, record_id)``. Such artifacts
          still reach frozen stage evaluation, and a reference lookup yielding
          more than one match is ambiguous under R-A and the frozen resolution
          semantics. This evaluator never picks one and never synthesizes an ID.
          Frozen ``R-10`` is an invariant on the BATCH verifier's own emitted
          verdict set and is not widened into a bundle preflight. The ruling
          CONFIRMS the removal already carried here under A6.

Erratum 3 rulings carried here:

  * E3-1  ruling ``AD15-IR-6``: ``related_artifacts`` is ordered by ascending
          UTF-8 byte order of the MANIFEST-RELATIVE ``artifact_path``, not of
          ``record_id``. ``artifact_path`` always exists, so the request
          envelope -- and with it the ``request_envelope_digest`` harness duty 2
          compares -- is always defined. The pre-erratum resolution here (fail a
          multi-artifact bundle closed when an artifact carried no usable
          ``record_id``) is SUPERSEDED: such an artifact now reaches frozen
          stage 0. ``record_id`` remains ONLY the AIREP semantic
          reference-resolution key and R-A is untouched;
  * E3-2  ``bundle-file-unreadable`` joins the closed registry, and the four
          filesystem reasons are bounded exactly -- path absent or a definite
          ``ENOENT`` on read is ``bundle-file-missing``; present, a permitted
          regular file, but open/read fails or errors is
          ``bundle-file-unreadable``; bytes read but unparseable is
          ``bundle-json-invalid``; bytes read but the digest disagrees is
          ``manifest-digest-mismatch``;
  * E3-3  "a manifest with the wrong name or location" is REMOVED from
          ``manifest-invalid``. NO manifest discovery is performed: identity
          comes only from ``manifest.json`` at the bundle root, and its absence
          is exit 1 with empty stdout. A wrongly-named or misplaced file BESIDE
          a valid root manifest needs no special rule -- it is an unlisted
          regular file, or a listed entry with an invalid ``role``;
  * E3-4  ``--help`` is a CLI META-ACTION, not an evaluation: exit 0, human
          text on stdout, NO result object, ``--bundle`` not required, and the
          contract-8.5 exit table does not apply to it. Every other CLI usage
          error remains exit 2. Its "exactly one flag wide" phrasing is
          SUPERSEDED by E4-1 above, which pins the carve-out to one exact
          single-token invocation.

Erratum 2 rulings carried here:

  * E2-1  every bundle-layout violation is ``manifest-invalid`` -- forbidden
          symlinks, an on-disk regular file ``files[]`` does not list, a
          ``files[]`` entry whose target is not a permitted file kind, a FIFO /
          socket / device or other non-regular non-directory object, and the
          manifest closure / sort / ``role`` / ``path`` / digest-encoding rules.
          Directories are containers only and are never ``files[]`` entries.
          E3-3 removed the wrong-name/location clause from this surface;
  * E2-2  every abnormal frozen run is ``verifier-run-invalid`` -- a
          non-qualifying ``exit 1``, ``exit 2`` or any other impermissible exit,
          ``exit 0`` with empty stdout, ``exit 0`` with non-strict-JSON stdout,
          and ``exit 0`` carrying a malformed / multiple / wrong-shape result.
          ``verifier-not-invocable`` is ONLY a process that could not be spawned
          or executed at all; ``internal-error`` is ONLY this evaluator's own
          unexpected internal fault;
  * E2-3  ruling ``AD15-IR-5``: ``artifact_path`` is required and is the total
          result identity, ``artifact_ref`` is object-or-``null``, ``artifacts[]``
          is ordered by UTF-8 byte order of ``artifact_path``, and a
          ``record_id`` is NEVER synthesized. R-A is unchanged -- reference
          resolution still uses ``record_id`` (additionally ``chain_id`` where
          the reference carries one), and the manifest path never participates
          in it.

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
  1  stdout empty -- bundle identity could not be established under contract
     5's direct-read identity boundary, and only that (E4-2): bundle root
     inaccessible; root ``manifest.json`` absent; present but unopenable or
     unreadable; not parseable as strict JSON; no registered ``scenario_id``
  2  stdout empty -- CLI usage error, which includes every help spelling and
     combination except the lone ``--help`` meta-action (E4-1)
  3  exactly one result object, MEASUREMENT_INVALID or ERROR, ``level1: null``,
     ``predicates: null``, ``nonmeasurement`` populated

stdlib only; no third-party dependency is added. Diagnostics go to stderr and
are never a source of semantics (contract 8.3, 8.5).

-----------------------------------------------------------------------------
RECORDED AMBIGUITIES -- resolved in the direction the contract determines, and
reported rather than buried. None of them can change the measured result of a
conforming official W1 bundle.

  A1  OPEN in one respect -- see the exit-band note at the end. Contract 8.1
      shows ``interop-eval --bundle DIR [operator-input flags]``,
      but contract 5 pins the operator inputs as bundle members addressed by
      the closed ``role`` set, and 5.1 says the evaluator "passes through the
      files the bundle ships". Role-derivation is the determinate reading and
      is what this evaluator uses. The three flags are still accepted, but
      ONLY as a consistency assertion: each must resolve to the same file the
      role already selected, or it is a usage error. A flag can therefore never
      change what is measured.

      EXIT-BAND NOTE (open): a flag/manifest mismatch is raised as a usage
      error, so it exits 2 with empty stdout -- but the mismatch is only
      detectable AFTER ``manifest.json`` has yielded a usable ``scenario_id``,
      and 8.5 says that once identity is established "the evaluator owes a
      result object naming the scenario it failed on". Whether this belongs in
      the exit-2 row ("CLI usage error") or must become an exit-3 reason is not
      pinned, and a peer lane resolving A1 differently lands in a different exit
      band for the same inputs. Left as exit 2 pending a maintainer ruling; it
      cannot arise in an official run, which passes no operator-input flags.

  A2  Numeric-preflight JSON Pointers are rooted at the DOCUMENT carrying the
      offending number, with the bundle-relative path in ``detail``. Contract
      5.1 defines the number set by envelope reachability but names operator
      inputs in the same breath, and operator inputs are not envelope members,
      so no envelope-rooted pointer can address them. No harness duty (8.1)
      compares ``json_pointer`` across lanes.

  A3  CLOSED by Erratum 2. Symlinks and an on-disk file absent from ``files[]``
      are now enumerated normatively under ``manifest-invalid``, which is what
      this lane already did.

  A4  CLOSED by Erratum 2, AGAINST this lane's pre-erratum reading. ``exit 0``
      with unparseable stdout and ``exit 2`` were reported as ``internal-error``
      here; both are now ``verifier-run-invalid``. ``internal-error`` is
      henceforth this evaluator's own fault only.

  A5  Contract 8.2 lists ``withheld_reasons`` as a result member and qualifies
      it "whenever any ``*_withheld`` channel is non-empty". It is emitted
      unconditionally, as ``[]`` when nothing is withheld, so the object shape
      is fixed. Its per-entry shape is unpinned; ``artifact_path`` is used as
      the identity there too, for consistency with ``AD15-IR-5``.

  A6  CLOSED by Erratum 3, AGAINST this lane's pre-erratum resolution. The
      pre-erratum contract ordered ``related_artifacts`` by ``record_id`` while
      ``AD15-IR-5`` had already made ``record_id`` optional, so a multi-artifact
      bundle carrying an unidentifiable artifact had no defined envelope. This
      lane failed such a bundle CLOSED as ``bundle-shape-invalid`` rather than
      invent an order; ruling ``AD15-IR-6`` now keys the envelope on
      ``artifact_path``, which always exists, so the envelope is always defined
      and the fail-closed path is REMOVED. Both defects this lane recorded under
      that resolution are thereby settled: the artifact reaches frozen stage 0
      as ``AD15-IR-5`` requires, and no registry row is used outside its own
      definition.

      Removed with it: the pre-erratum preflight rejection of a bundle carrying
      two artifacts with the SAME ``record_id``. That removal was a reading of
      contract 5 and 8.2.2 -- ``bundle-shape-invalid`` is defined as artifact
      count, family composition or operator-input composition, none of which a
      duplicate ``record_id`` is, while contract 5 pins the opposite treatment
      explicitly -- and Erratum 4 has now CONFIRMED it as ruling ``AD15-IR-7``,
      so it is contract-backed rather than inferred. There is no bundle-wide
      preflight gate on a duplicate ``record_id`` or a duplicate
      ``(chain_id, record_id)``: such artifacts reach frozen stage evaluation,
      and the duplicate is left for R-A to report as a FAIL under the frozen
      resolution semantics ("more than one match is ambiguous and fails closed.
      An evaluator MUST NOT pick one"). Frozen ``R-10`` binds the BATCH
      verifier's own emitted verdict set and is not widened into a bundle rule;
      this evaluator submits each artifact as a separate request.

  A7  CLOSED by ruling ``W1-CORPUS-IR-1`` in ``INTEROP_CORPUS_CONTRACT.md``.
      Contract 5 pins bundle FAMILY COMPOSITION, which can only be checked by
      reading ``artifact_type``, so an artifact broken at stage 0 hard enough to
      lose its ``artifact_type`` would be converted into this evaluator's own
      ``bundle-shape-invalid`` preflight failure. The corpus contract now makes
      the precondition explicit rather than incidental: all twelve official W1
      fixtures MUST retain a usable, schema-consistent ``artifact_type``, and it
      MUST NOT be the mutation target of a mandatory scenario. The composition
      check is therefore kept exactly as it is, and the collision is closed on
      the corpus side where it belongs.

  A8  Duplicate manifest object members are unpinned. Contract 5's direct-read
      identity boundary pins exit 1 to exactly five conditions (E4-2), and a
      duplicated member is still parseable as strict JSON (RFC 8259 permits it)
      and still yields a registered ``scenario_id``, so identity IS established. Both
      runtimes decode duplicates last-wins by default, so identity is taken from
      the decoded value and the duplicate is then reported as
      ``manifest-invalid`` at exit 3 under E2-1's manifest-rule surface. The
      pre-erratum reading put this in the exit-1 band, which contradicted 8.5.

  A9  CLOSED by Erratum 3 (E3-2), AGAINST this lane's pre-erratum mapping. A
      listed file that is present and of a permitted kind but UNREADABLE had no
      registry row and was reported here as ``bundle-file-missing``, which says
      something false about the bundle. ``bundle-file-unreadable`` now exists
      and the boundary is exact: path absent, or a definite ``ENOENT`` on read,
      is ``bundle-file-missing``; anything else that fails at open or read time
      is ``bundle-file-unreadable``.

  A10 CLOSED by Erratum 3 (E3-3), CONFIRMING this lane's construction. "A
      manifest with the wrong name or location" is no longer listed under
      ``manifest-invalid``, and no manifest discovery is performed: identity
      comes only from ``manifest.json`` at the bundle root, whose absence is
      exit 1 (contract 8.5). A manifest placed anywhere else is an ordinary
      regular file under the bundle and is caught as an unlisted on-disk file or
      by the closed ``role`` set. No separate code path exists and none is
      invented.

  A11 CLOSED by Erratum 3 (E3-4). ``--help`` is a CLI meta-action, not an
      evaluation: exit 0, human-readable text on stdout, no result object,
      ``--bundle`` not required, and the contract-8.5 exit table does not apply.
      The surface stays unreachable from the aggregate harness, which performs
      exactly twelve ``--bundle`` invocations (8.1) and never invokes it.

      The residual recorded here is CLOSED by Erratum 4 (E4-1). "Exactly one
      flag wide" was ambiguous, and the two lanes measurably diverged on it --
      one reading it as a statement about SPELLINGS and refusing ``-h``, the
      other as a statement about the EXIT-0 LICENCE and accepting it. The
      carve-out is now one exact single-token invocation: ``--help`` alone.

      This lane's ``-h`` behaviour is CONFIRMED (it was already exit 2), and its
      handling of ``--help`` COMBINED WITH OTHER ARGUMENTS is CORRECTED AGAINST
      the pre-erratum construction: registering ``--help`` as an argparse
      ``action="help"`` made ``--help --bundle DIR`` exit 0 with a help screen,
      whereas E4-1 makes only the LONE invocation a meta-action. ``--help`` is
      therefore no longer registered as an option at all; it is matched in
      ``main`` as an exact whole-argv equality, and every other argv reaching
      the parser with ``--help`` in it fails as an unrecognised argument at
      exit 2. Help text content and byte length are not a parity requirement.

  A12 The FROZEN verdict envelope (frozen contract 2) is shape-checked before a
      verdict is trusted -- required members, the closed ``class`` set, the five
      always-present reason arrays, and the closed ``observer_assessment`` set.
      This is E2-2's "wrong-shape result" case and is a shape check ONLY: no
      frozen decision is recomputed and no checked value influences a predicate.
      Frozen 2 does not declare the envelope closed, so an unknown member is
      deliberately tolerated.

  A13 CLOSED by Erratum 4. Both limbs were reported OPEN here because E3-2
      bounds its four filesystem reasons over a LISTED FILE and neither I/O
      failure was one:

        (i)  CLOSED by E4-3, AGAINST this lane's pre-erratum mapping. A
             DIRECTORY under the bundle that cannot be enumerated was reported
             as ``manifest-invalid``, with the discomfort recorded here that it
             is not strictly a rule VIOLATION, only an inability to check one.
             The registry now carries ``bundle-directory-unreadable`` for
             exactly that, and the distinction is the one this entry was
             groping for: ``manifest-invalid`` says the layout is WRONG, the new
             reason says the layout could not be MEASURED;
        (ii) CLOSED by E4-2, CONFIRMING this lane's construction. The root
             ``manifest.json`` PRESENT but unreadable is exit 1 with no result
             object -- the identity boundary is a direct read, and being
             unopenable or unreadable is now one of its five enumerated
             conditions. The contract also pins the corollary this entry
             reasoned to independently: a root manifest that cannot be read
             NEVER yields ``bundle-file-unreadable``, because a reason belongs
             to a result object and there is no scenario to name one after.
             Unreadable and absent are genuinely indistinguishable here.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

EVALUATOR_VERSION = "0.2.3"   # post-Erratum-4 (E4-1..E4-4, AD15-IR-7)

#: Contract 8.5 / E4-1: the CLI meta-action is this EXACT argv and no other.
HELP_INVOCATION = ["--help"]

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
    "bundle-file-unreadable": ERROR,
    "bundle-directory-unreadable": ERROR,
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

    Exactly the five conditions of contract 5's DIRECT-READ identity boundary
    (E4-2), which contract 8.5's exit-1 row now points at rather than restates:
    the bundle root cannot be accessed; ``DIR/manifest.json`` is not found; it
    is found but cannot be opened or read; its bytes do not parse as strict
    JSON; or no registered ``scenario_id`` can be obtained from it.
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


def write_result(text: str) -> None:
    """Write the one result object to stdout as UTF-8, whatever the locale.

    ``record_id`` / ``chain_id`` are free-form core strings that MAY be
    non-ASCII (frozen contract 2). Writing them through ``sys.stdout`` in a
    non-UTF-8 locale raises ``UnicodeEncodeError`` AFTER bundle identity is
    established, which would leave exit 1 with empty stdout -- precisely what
    contract 8.5 forbids once identity exists -- and would make contract-8.4
    determinism a property of the operator's environment rather than of the
    bundle. Going through the byte buffer removes the coupling, and the
    explicit flush keeps a pipe-backed stdout from truncating.
    """
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:                     # a text-only stream, e.g. under test
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    buffer.write(text.encode("utf-8"))
    buffer.flush()


def warn(message: str) -> None:
    sys.stderr.write(message.rstrip("\n") + "\n")


def _reject_constant(token: str) -> Any:
    raise ValueError("strict JSON forbids the literal %s" % token)


class _DuplicateRecorder:
    """Last-wins object decoding that REMEMBERS duplicated member names.

    Ambiguity A8: a duplicated member is still parseable as strict JSON, so
    contract 8.5 leaves bundle identity established and the violation belongs at
    exit 3 as ``manifest-invalid``. Last-wins is the default of both runtimes,
    so identity cannot diverge across lanes while the duplicate is reported.
    """

    def __init__(self) -> None:
        self.duplicates: List[str] = []

    def __call__(self, pairs: Sequence[Tuple[str, Any]]) -> dict:
        out: Dict[str, Any] = {}
        for key, value in pairs:
            if key in out and key not in self.duplicates:
                self.duplicates.append(key)
            out[key] = value
        return out


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


def load_manifest_identity(bundle_dir: str) -> Tuple[dict, str, List[str]]:
    """Establish bundle identity, or raise ``BundleIdentityError`` (exit 1).

    THE IDENTITY BOUNDARY IS A DIRECT READ (Erratum 4, E4-2). Identity comes
    from reading the bytes of ``DIR/manifest.json`` DIRECTLY -- the bundle is
    NOT enumerated first, and nothing here touches any other path. All five of
    the following are identity not established -> exit 1, stdout empty, no
    result object: the bundle root cannot be accessed; ``DIR/manifest.json`` is
    not found; it is found but cannot be opened or read; its bytes do not parse
    as strict JSON; no registered ``scenario_id`` can be obtained from it. The
    first three all surface as ``OSError`` from the one ``open`` below, which is
    why they need no separate probe: an inaccessible root, an absent file and an
    unreadable file are indistinguishable to this evaluator precisely because
    none of them yields an identity.

    Everything downstream of this function is exit 3 with a named reason --
    including a duplicated manifest member, which is parseable strict JSON and
    therefore does NOT withhold identity (ambiguity A8).

    NO MANIFEST DISCOVERY IS PERFORMED (Erratum 3, E3-3). Identity comes only
    from ``manifest.json`` at the bundle ROOT; nothing else is looked for under
    any other name or in any other directory. Its absence is exit 1 -- never
    ``manifest-invalid``, which would require an identity this evaluator does
    not have. A wrongly-named or misplaced file sitting BESIDE a valid root
    manifest needs no rule of its own: it is an unlisted regular file, or a
    listed entry with an invalid ``role``, and the ordinary layout rules make it
    ``manifest-invalid`` at exit 3.

    A SYMLINKED root manifest is deliberately NOT diverted here. E2-1 enumerates
    "a forbidden symlink anywhere under the bundle" under ``manifest-invalid``,
    and 8.5 pins the exit-1 band to exactly three conditions of which "present
    but a link" is not one. Identity is therefore taken from the link's target
    and ``scan_bundle`` reports the symlink as ``manifest-invalid`` at exit 3,
    so the harness receives a result object naming the scenario.
    """
    path = os.path.join(bundle_dir, MANIFEST_FILENAME)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        # E4-2: root inaccessible, manifest absent, and manifest present but
        # unopenable or unreadable are three of the five identity conditions and
        # all exit 1. A ROOT MANIFEST THAT CANNOT BE READ NEVER YIELDS
        # `bundle-file-unreadable`: the root manifest is excluded from `files[]`
        # by contract 5, and more fundamentally a reason belongs to a result
        # object, of which there is none here because there is no scenario to
        # name one after. This closes recorded ambiguity A13(ii) in favour of
        # what this lane already did.
        raise BundleIdentityError("manifest unreadable at %s: %s" % (path, exc))
    recorder = _DuplicateRecorder()
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=recorder,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleIdentityError("manifest is not parseable as strict JSON: %s" % exc)
    if not isinstance(doc, dict):
        raise BundleIdentityError("manifest is not a JSON object")
    scenario_id = doc.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in SCENARIO_IDS:
        raise BundleIdentityError(
            "manifest carries no usable scenario_id from the registered twelve")
    return doc, scenario_id, recorder.duplicates


def _bad_manifest(detail: str) -> NonMeasurement:
    return NonMeasurement("manifest-invalid", detail)


def validate_manifest(doc: dict, scenario_id: str,
                      duplicates: Sequence[str] = ()) -> Manifest:
    """Apply the pinned manifest encoding (contract 5). Failures are
    ``manifest-invalid`` at exit 3 -- identity is already established, and
    Erratum 2 makes that reason cover the whole manifest-rule surface.
    """
    if duplicates:
        raise _bad_manifest(
            "manifest carries duplicate object member(s): %s"
            % ", ".join(sorted(duplicates)))
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

    Runs only AFTER identity is established (E4-2): the manifest is read
    directly and this traversal never contributes to identity. A traversal that
    cannot complete is ``bundle-directory-unreadable`` (E4-3), never a layout
    reason.
    """
    found: List[str] = []

    def walk(directory: str, prefix: str) -> None:
        # E4-3: enumeration failure is NOT a layout violation. `manifest-invalid`
        # says the layout is WRONG; this says the layout could not be MEASURED,
        # which is a different true thing about the bundle. Permission denied,
        # an I/O error, or any other failure to enumerate a directory -- and
        # equally a failure to determine the KIND of an entry it yielded, since
        # traversal has not completed until that is known -- is
        # `bundle-directory-unreadable` at exit 3.
        try:
            entries = scan_directory(directory)
        except OSError as exc:
            raise NonMeasurement(
                "bundle-directory-unreadable",
                "bundle traversal could not complete: directory %r could not be "
                "enumerated: %s" % (prefix or ".", exc))
        for entry in entries:
            rel = entry.name if not prefix else prefix + "/" + entry.name
            try:
                is_link = entry.is_symlink()
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError as exc:
                raise NonMeasurement(
                    "bundle-directory-unreadable",
                    "bundle traversal could not complete: the kind of %r could "
                    "not be determined: %s" % (rel, exc))
            if is_link:
                raise _bad_manifest("bundle carries a symbolic link at %r" % rel)
            if is_dir:
                walk(entry.path, rel)
                continue
            if not is_file:
                raise _bad_manifest(
                    "bundle carries a non-regular, non-directory entry at %r" % rel)
            if rel == MANIFEST_FILENAME:
                continue
            found.append(rel)

    walk(bundle_dir, "")
    found.sort(key=byte_key)
    return found


def scan_directory(directory: str) -> List[os.DirEntry]:
    """Enumerate one directory, raising ``OSError`` verbatim.

    A named seam, so the E4-3 boundary between `bundle-directory-unreadable` and
    the layout reasons can be exercised deterministically rather than only
    through filesystem permissions, which are not portable.
    """
    with os.scandir(directory) as scan:
        return sorted(scan, key=lambda e: byte_key(e.name))


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
        if entry.path in present:
            continue
        # Erratum 2 separates the two cases the pre-erratum code conflated. A
        # files[] entry whose target EXISTS but is not a permitted file kind --
        # a directory being the ordinary case, since directories are containers
        # only and are never files[] entries -- is a LAYOUT violation and so
        # `manifest-invalid`. Only a target that is not there at all is
        # `bundle-file-missing`. `scan_bundle` has already rejected every
        # symlink and every non-regular non-directory object under the bundle,
        # so anything reached here is a directory or is absent.
        full = os.path.join(bundle_dir, *entry.path.split("/"))
        if os.path.isdir(full):
            raise _bad_manifest(
                "files[] entry %r names a directory; directories are containers "
                "only and are never files[] entries" % entry.path)
        if os.path.exists(full):
            raise _bad_manifest(
                "files[] entry %r names an object that is not a permitted file "
                "kind" % entry.path)
        raise NonMeasurement(
            "bundle-file-missing",
            "files[] lists %r but no such regular file is present" % entry.path)

    contents: Dict[str, bytes] = {}
    for entry in manifest.entries:
        full = os.path.join(bundle_dir, *entry.path.split("/"))
        try:
            data = read_bundle_file(full)
        except OSError as exc:
            # Erratum 3 (E3-2) bounds the four filesystem reasons exactly. The
            # file was present and of a permitted kind a moment ago -- scan and
            # the presence check have both run -- so a definite ENOENT here is a
            # file that went away and is still `bundle-file-missing`; every
            # other open/read failure is `bundle-file-unreadable`, which says
            # the true thing: the medium failed, the bundle is not incomplete.
            if getattr(exc, "errno", None) == errno.ENOENT:
                raise NonMeasurement(
                    "bundle-file-missing",
                    "files[] lists %r but it is no longer present: %s"
                    % (entry.path, exc))
            raise NonMeasurement(
                "bundle-file-unreadable",
                "%r is present and a permitted regular file, but its bytes "
                "could not be read: %s" % (entry.path, exc))
        measured = sha256_hex(data)
        if measured != entry.sha256:
            raise NonMeasurement(
                "manifest-digest-mismatch",
                "%r: manifest says %s, bundle bytes measure %s"
                % (entry.path, entry.sha256, measured))
        contents[entry.path] = data
    return contents


def read_bundle_file(full_path: str) -> bytes:
    """Read one listed bundle file, raising ``OSError`` verbatim.

    A named seam, so the E3-2 boundary between ``bundle-file-missing`` and
    ``bundle-file-unreadable`` can be exercised deterministically rather than
    only through filesystem permissions, which are not portable.
    """
    with open(full_path, "rb") as handle:
        return handle.read()


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
    """One bundle artifact.

    Ruling ``AD15-IR-5``: ``path`` -- the manifest-relative path -- is the TOTAL
    result identity and always exists, because the manifest lists every file.
    ``record_id`` is wire semantics and may be absent; an artifact that must be
    rejected at stage 0 may carry no usable one, and this evaluator MUST NOT
    synthesize it.
    """

    __slots__ = ("path", "value", "record_id", "chain_id", "artifact_type")

    def __init__(self, path: str, value: dict) -> None:
        self.path = path
        self.value = value
        record_id = value.get("record_id")
        self.record_id: Optional[str] = record_id if isinstance(record_id, str) \
            and record_id else None
        self.chain_id = value.get("chain_id")
        self.artifact_type = value.get("artifact_type")

    @property
    def ref(self) -> Optional[Dict[str, str]]:
        """The structured reference, or ``None`` when no usable ``record_id``
        exists (``AD15-IR-5``). Never a fabricated identity.
        """
        if self.record_id is None:
            return None
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
        # AD15-IR-5: there is deliberately NO record_id precondition here. An
        # artifact with no usable record_id must reach the frozen stage-0
        # evaluation it belongs to rather than be converted into this
        # evaluator's own preflight failure.
        artifact_type = value.get("artifact_type")
        if artifact_type not in ARTIFACT_TYPES:
            # Ambiguity A7: kept because contract 5 pins FAMILY COMPOSITION,
            # which cannot be checked without artifact_type.
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

    # AD15-IR-6 (E3-1) REMOVED the two record_id preconditions that stood here.
    # A multi-artifact bundle carrying an artifact with no usable record_id is
    # no longer failed closed: the envelope now orders on artifact_path, which
    # always exists, so the envelope -- and the request_envelope_digest harness
    # duty 2 compares -- is always defined, and the artifact reaches the frozen
    # stage-0 evaluation it belongs to. A duplicate record_id is likewise not a
    # preflight rule: contract 5 pins it as R-A's business ("more than one match
    # is ambiguous and fails closed"), which a preflight rejection would make
    # unreachable, and 8.2.2 confines `bundle-shape-invalid` to artifact count,
    # family composition and operator-input composition. See recorded A6.

    # AD15-IR-5 / contract 8.4: result ordering is UTF-8 byte order of
    # artifact_path, which always exists -- not of record_id, which may not.
    artifacts.sort(key=lambda a: byte_key(a.path))
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

    ``related_artifacts`` is EVERY OTHER artifact of the same bundle and no
    others, ascending by UTF-8 byte order of the MANIFEST-RELATIVE
    ``artifact_path`` (ruling ``AD15-IR-6``); for a single-artifact scenario it
    is the EMPTY ARRAY -- present, never absent. ``head_witness`` is never
    added: contract 5 pins it absent from every official W1 bundle and the
    closed role set cannot express one.

    Ordering keys on ``artifact_path`` because it ALWAYS exists -- the manifest
    lists every file -- so the envelope, and with it the
    ``request_envelope_digest`` harness duty 2 compares, is always defined even
    when an artifact carries no usable ``record_id``. ``record_id`` remains only
    the AIREP semantic reference-resolution key (R-A); the manifest path never
    participates in that resolution. The path is the ORDERING key only: it is
    not a member of the envelope, which carries artifact values alone.
    """
    related = sorted((a for a in artifacts if a is not primary),
                     key=lambda a: byte_key(a.path))
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

def _run_invalid(detail: str, entries: List[dict]) -> NonMeasurement:
    """Erratum 2: every abnormal frozen run, and only those, land here.

    The frozen process STARTED but the invocation did not produce one of the
    process/result shapes the frozen contract permits.
    """
    return NonMeasurement("verifier-run-invalid", detail, artifacts=entries)


def _verdict_from_stdout(artifact: "Artifact", stdout: bytes,
                         entries: List[dict]) -> dict:
    """Decode the single verdict object an ``exit 0`` invocation owes us.

    Erratum 2 enumerates the exit-0 failures, all `verifier-run-invalid`:
    empty stdout, stdout that is not parseable as STRICT JSON, and stdout
    carrying a malformed, multiple or wrong-shape result instead of the single
    expected verdict object.

    Strictness is the contract's own word. ``NaN`` / ``Infinity`` are rejected
    because JSON has no such literals; a second concatenated document is
    rejected because ``json.loads`` refuses trailing data. Duplicate members are
    left at the runtimes' shared last-wins default and are deliberately NOT
    rejected here -- RFC 8259 permits them and rejecting them would be this
    lane inventing a rule the contract does not pin.
    """
    if not stdout.strip():
        raise _run_invalid(
            "frozen verifier exited 0 for %s with empty stdout" % artifact.path,
            entries)
    try:
        decoded = json.loads(stdout.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _run_invalid(
            "frozen verifier exited 0 for %s but stdout is not parseable as "
            "strict JSON: %s" % (artifact.path, exc),
            entries)
    if not isinstance(decoded, dict):
        raise _run_invalid(
            "frozen verifier exited 0 for %s but stdout carries a %s, not the "
            "single expected verdict object"
            % (artifact.path, type(decoded).__name__),
            entries)
    wrong = _wrong_shape(decoded)
    if wrong is not None:
        raise _run_invalid(
            "frozen verifier exited 0 for %s but the result is not a normalized "
            "verdict envelope: %s" % (artifact.path, wrong),
            entries)
    return decoded


#: The normalized verdict envelope, pinned by the FROZEN
#: ``CLASS_VERIFIER_CONTRACT.md`` section 2 -- required members, the closed
#: ``class`` set, the five always-present reason arrays, and the closed
#: ``observer_assessment`` set. This is a shape check on what the frozen
#: verifier returned, NOT a re-implementation of any frozen decision: no value
#: here is recomputed, compared with the artifact, or allowed to influence a
#: predicate. Section 2 does not declare the envelope closed, so an unknown
#: member is deliberately NOT rejected.
VERDICT_CHANNELS = (
    "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
    "witnessed_failures", "witnessed_withheld",
)
VERDICT_CLASSES = frozenset({
    "AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed"})
VERDICT_OBSERVER_ASSESSMENTS = frozenset({
    "same_executor", "independent", "unknown", "not_applicable"})


def _wrong_shape(verdict: dict) -> Optional[str]:
    """Return why ``verdict`` is not a normalized verdict envelope, or ``None``.

    Without this, an ``exit 0`` carrying an arbitrary JSON object reaches the
    Level-1 mapping, where every reader degrades to its positive branch --
    ``verdict.get("authenticated_failures") or []`` sees no failure,
    ``verdict.get("authenticated_withheld") or []`` sees no withheld tier, and
    R-C sees no ``unknown``. The result is a `MEASURED` / `ACCEPT` built on a
    measurement that never happened, which is the exact laundering contract 7.1
    forbids. E2-2 names this case, so it is refused here.
    """
    for member in ("artifact_ref", "class", "observer_assessment", "evidence"):
        if member not in verdict:
            return "required member %r is absent" % member
    if not isinstance(verdict["artifact_ref"], dict):
        return "artifact_ref is not an object"
    if not isinstance(verdict["evidence"], dict):
        return "evidence is not an object"
    if verdict["class"] not in VERDICT_CLASSES:
        return "class %r is outside the closed set" % (verdict["class"],)
    if verdict["observer_assessment"] not in VERDICT_OBSERVER_ASSESSMENTS:
        return ("observer_assessment %r is outside the closed set"
                % (verdict["observer_assessment"],))
    for channel in VERDICT_CHANNELS:
        if channel not in verdict:
            return "reason array %r is absent; frozen 2 requires all five always" % channel
        if not isinstance(verdict[channel], list):
            return "reason array %r is not an array" % channel
    return None


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
        for member in REFERENCE_EDGES.get(artifact.artifact_type or "", ()):
            outcome = resolve_reference(artifact.value.get(member), artifacts)
            if outcome != "resolved":
                problems.append("%s /%s %s" % (artifact.path, member, outcome))
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
    # Keyed by artifact_path: AD15-IR-5 makes it the total result identity, and
    # it is the only key guaranteed to exist and to be unique.
    verdict = verdicts.get(effect.path)
    if not isinstance(verdict, dict):
        raise NonMeasurement(
            "internal-error",
            "R-C has no frozen verdict for the Effect %r" % effect.path)
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
    # exit-1 band ends here
    doc, scenario_id, duplicates = load_manifest_identity(bundle_dir)
    verifier_digests, digest_problem = measure_frozen_digests()
    try:
        return _evaluate(args, bundle_dir, doc, scenario_id, duplicates, invoke,
                         verifier_digests, digest_problem)
    except NonMeasurement as exc:
        # Identity IS established from here on, so the caller owes a result
        # object naming the scenario it failed on (contract 8.5).
        exc.scenario_id = scenario_id
        exc.verifier_digests = verifier_digests
        raise
    except (UsageError, BundleIdentityError):
        raise
    except Exception as exc:                # noqa: BLE001 -- deliberate net
        # Contract 8.2.2: `internal-error` exists so that an unexpected fault
        # AFTER identity is established still produces a result object naming
        # the scenario, rather than a crash the harness has to infer. Erratum 2
        # narrows it to exactly this -- the evaluator's OWN fault.
        wrapped = NonMeasurement(
            "internal-error",
            "unexpected %s in the evaluator: %s" % (type(exc).__name__, exc))
        wrapped.scenario_id = scenario_id
        wrapped.verifier_digests = verifier_digests
        raise wrapped from exc


def _evaluate(args, bundle_dir: str, doc: dict, scenario_id: str,
              duplicates: Sequence[str], invoke,
              verifier_digests: Dict[str, str], digest_problem: Optional[str]) -> dict:
    # ---- contract 8.3.1 step 1: the WHOLE preflight, before any invocation ---
    manifest = validate_manifest(doc, scenario_id, duplicates)
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
            # E2-2: an exit-0 invocation that does not carry exactly one
            # well-formed verdict object is `verifier-run-invalid` -- the frozen
            # process started and misbehaved. It is NOT `internal-error`, which
            # is now this evaluator's own fault only, and NOT
            # `verifier-not-invocable`, which is now spawn failure only.
            verdict = _verdict_from_stdout(artifact, stdout, entries)
        entries.append({
            # AD15-IR-5: artifact_path is required and is the entry's identity;
            # artifact_ref is the structured reference or null. No record_id is
            # ever synthesized to fill it.
            "artifact_path": artifact.path,
            "artifact_ref": artifact.ref,
            "request_envelope_digest": digest_str(request),
            "verifier_exit_code": code,
            # Contract 8.3: null whenever the exit code is 1, because no verdict
            # exists. stderr is hashed for audit and NEVER parsed for semantics.
            "verifier_result": verdict,
            "verifier_stderr_digest": digest_str(stderr),
        })
        verdicts[artifact.path] = verdict

    # ---- contract 7.2: the causal guard on a non-zero frozen exit -----------
    # Reaching this point means the request was preflight-clean in the sense 7.2
    # requires: the manifest verified, the numeric preflight passed, the envelope
    # was built per 5.1, and the operator inputs are the bundle's own.
    # Cross-lane envelope equality is NOT part of this condition and never was
    # implementable here -- it is an aggregate-harness gate (AD15-IR-4, 8.1).
    for entry in entries:
        code = entry["verifier_exit_code"]
        path = entry["artifact_path"]
        if code == 0:
            continue
        if code == 1:
            if scenario_id in EXIT1_REJECT_SCENARIOS:
                continue                   # a targeted stage-0 / stage-1 failure
            raise _run_invalid(
                "frozen verifier exit 1 for %s under %s is outside the two "
                "contract-7.2 conditions, so it does not qualify as a Level-1 "
                "REJECT" % (path, scenario_id),
                entries)
        # E2-2: exit 2, or any other exit the frozen contract does not permit
        # for this invocation. Previously reported as `internal-error`, which is
        # now reserved for this evaluator's OWN unexpected fault -- an external
        # subprocess protocol failure is never `internal-error`.
        raise _run_invalid(
            "frozen verifier exited %d for %s; the frozen contract permits no "
            "such exit for this invocation" % (code, path),
            entries)

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
                # Ambiguity A5: identified by artifact_path, per AD15-IR-5.
                "artifact_path": entry["artifact_path"],
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
        # E4-1: the help carve-out is ONE EXACT SINGLE-TOKEN INVOCATION, so
        # `--help` is deliberately NOT registered as an option at all. It is
        # recognised in `main` only when it is the whole of argv; reaching the
        # parser with `--help` anywhere in it therefore fails as an unrecognised
        # argument, which is the exit-2 usage error the ruling requires. The
        # `-h` alias is likewise absent and prefix abbreviation is off, so `-h`
        # and `--hel` are ordinary usage errors too (A11).
        add_help=False,
        allow_abbrev=False,
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
    # E4-1: the meta-action is the SINGLE-TOKEN INVOCATION `--help` AND NOTHING
    # ELSE. "Exactly one flag wide" proved ambiguous and two lanes measurably
    # diverged on it, so the test is now an exact argv equality rather than a
    # membership test: `--help` exits 0 with human text and no result object;
    # `-h` is NOT an alias and is a usage error; and `--help` combined with any
    # other argument is a usage error too, because only the LONE help
    # invocation is carved out. Help text content and byte length are not a
    # parity requirement, so nothing here pins what is printed.
    if argv == HELP_INVOCATION:
        parser.print_help()
        return 0
    # argparse exits 2 on any usage error, raising SystemExit and bypassing
    # everything below, so no result object is ever written for one.
    args = parser.parse_args(argv)

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
        write_result(dump_json(build_result(
            exc.scenario_id, exc.status, None, None, nonmeasurement_object(exc),
            exc.artifacts, exc.withheld_reasons, exc.verifier_digests)))
        return 3
    write_result(dump_json(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
