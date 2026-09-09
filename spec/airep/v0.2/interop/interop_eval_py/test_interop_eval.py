#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the AIREP v0.2 Python reference interop evaluator (post-erratum).

Every input here is SYNTHETIC and built inside this file. No corpus fixture is
read or written: corpus construction is on HOLD (contract status line), and the
frozen class verifier is stubbed for everything except the two tests that
deliberately exercise the real subprocess seam.

Run:  python3 -m unittest discover -s spec/airep/v0.2/interop/interop_eval_py
  or: python3 -m pytest spec/airep/v0.2/interop/interop_eval_py -q
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import interop_eval as ev  # noqa: E402


# --------------------------------------------------------------------------
# Synthetic bundle construction
# --------------------------------------------------------------------------

def hexdigest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact(record_id: str, artifact_type: str, **extra) -> dict:
    doc = {
        "airep_version": "0.2",
        "artifact_type": artifact_type,
        "chain_id": "chain-synthetic",
        "record_id": record_id,
        "sequence": 1,
    }
    doc.update(extra)
    return doc


DECISION = artifact("a-decision", "decision")
CONTROL = artifact("b-control", "control",
                   decision_ref={"record_id": "a-decision"},
                   authorized_action_digest="sha256:" + "11" * 32)
EXECUTION = artifact("c-execution", "execution",
                     decision_ref={"record_id": "a-decision"},
                     executed_action_digest="sha256:" + "11" * 32)
EFFECT = artifact("d-effect", "effect",
                  decision_ref={"record_id": "a-decision"},
                  execution_ref={"record_id": "c-execution"},
                  observer_relationship="independent")

OPERATOR_INPUTS = {
    "operator/bindings.json": ({"bindings": []}, "bindings"),
    "operator/independence.json": ({"policy": "synthetic"}, "independence_policy"),
    "operator/revocation.json": ({"revoked": []}, "revocation"),
}


def four_artifacts(**overrides):
    """The four-artifact reconciliation shape, with per-family overrides."""
    out = {}
    for path, doc in (("artifacts/decision.json", DECISION),
                      ("artifacts/control.json", CONTROL),
                      ("artifacts/execution.json", EXECUTION),
                      ("artifacts/effect.json", EFFECT)):
        merged = json.loads(json.dumps(doc))
        merged.update(overrides.get(doc["artifact_type"], {}))
        out[path] = merged
    return out


def write_bundle(root: str, scenario_id: str, artifacts: dict,
                 operator=None, manifest_overrides=None, raw_files=None,
                 drop_from_disk=(), extra_disk_files=None, manifest_files=None):
    """Materialize a bundle directory and return its path.

    ``artifacts`` maps bundle-relative path -> JSON value (role ``artifact``).
    ``raw_files`` maps path -> exact bytes, bypassing json.dumps.
    """
    bundle = os.path.join(root, "bundle")
    os.makedirs(bundle, exist_ok=True)
    operator = OPERATOR_INPUTS if operator is None else operator

    on_disk = {}
    roles = {}
    for path, doc in artifacts.items():
        on_disk[path] = json.dumps(doc, sort_keys=True).encode("utf-8")
        roles[path] = "artifact"
    for path, (doc, role) in operator.items():
        on_disk[path] = json.dumps(doc, sort_keys=True).encode("utf-8")
        roles[path] = role
    for path, (data, role) in (raw_files or {}).items():
        on_disk[path] = data
        roles[path] = role

    entries = [{"path": p, "role": roles[p], "sha256": hexdigest(on_disk[p])}
               for p in sorted(on_disk, key=lambda s: s.encode("utf-8"))]
    if manifest_files is not None:
        entries = manifest_files

    for path, data in on_disk.items():
        if path in drop_from_disk:
            continue
        full = os.path.join(bundle, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
    for path, data in (extra_disk_files or {}).items():
        full = os.path.join(bundle, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)

    manifest = {"manifest_version": "1", "scenario_id": scenario_id, "files": entries}
    if manifest_overrides is not None:
        manifest = manifest_overrides(manifest)
    with open(os.path.join(bundle, "manifest.json"), "wb") as handle:
        if isinstance(manifest, bytes):
            handle.write(manifest)
        else:
            handle.write(json.dumps(manifest, indent=1).encode("utf-8"))
    return bundle


def verdict(record_id, chain_id="chain-synthetic", klass="AIREP-Authenticated",
            auth_failures=(), auth_withheld=(), observer="independent"):
    return {
        "artifact_ref": {"chain_id": chain_id, "record_id": record_id},
        "class": klass,
        "authenticated_failures": list(auth_failures),
        "authenticated_withheld": list(auth_withheld),
        "authenticated_caveats": [],
        "witnessed_failures": [],
        "witnessed_withheld": [],
        "observer_assessment": observer,
        "evidence": {},
    }


class StubVerifier:
    """Frozen-verifier subprocess seam replacement (contract-3 shape only)."""

    def __init__(self, by_record=None, default=(0, None), stderr=b""):
        self.by_record = by_record or {}
        self.default = default
        self.stderr = stderr
        self.calls = []

    def __call__(self, request, flags):
        envelope = json.loads(request.decode("utf-8"))
        # AD15-IR-5 permits an artifact with no usable record_id, so the stub
        # must not assume one.
        record_id = envelope["artifact"].get("record_id")
        self.calls.append((record_id, envelope, list(flags)))
        code, body = self.by_record.get(record_id, self.default)
        if body is None and code == 0:
            # E8-3: the frozen `common.schema.json` makes `record_id` a REQUIRED
            # STRING in `artifact_core`, so an artifact reaching an accepted
            # `exit 0` verdict always carried one. A stub synthesizing a null
            # `record_id` here models a frozen output that CANNOT EXIST, and the
            # typed Source-A gate now refuses it -- correctly. The stand-in keeps
            # the double inside the shape the frozen contract can actually
            # produce. What the no-record_id cases measure is unchanged: that the
            # artifact REACHED stage 0 (`stub.calls`) and that the Source-B
            # projection over the ARTIFACT is null, both asserted directly.
            body = verdict(record_id if isinstance(record_id, str)
                           else "stub-schema-valid-record-id")
        if isinstance(body, bytes):
            return code, body, self.stderr          # raw stdout, bypassing json
        stdout = b"" if body is None else json.dumps(body).encode("utf-8")
        return code, stdout, self.stderr


class Args:
    def __init__(self, bundle, bindings=None, independence_policy=None,
                 revocation=None):
        self.bundle = bundle
        self.bindings = bindings
        self.independence_policy = independence_policy
        self.revocation = revocation


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="airep interop test ")  # literal spaces
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def run_cli(self, bundle, extra=(), stub=None):
        """Drive main(). ``stub`` replaces the frozen-verifier subprocess seam at
        module level; without it the REAL frozen verifier is invoked.

        Stdout is BYTE-BACKED, not a bare ``io.StringIO``. ``write_result``
        branches on ``sys.stdout.buffer``, so a text-only stream took its
        fallback and the ``text.encode("utf-8")`` path -- the one that can fail
        on an unpaired surrogate and turn an exit-3 result into exit 1 with
        empty stdout -- was never exercised by any CLI-level test in this file.
        A test harness that cannot reach the failing branch is not a harness.
        """
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        err = io.StringIO()
        original = ev.invoke_frozen_verifier
        if stub is not None:
            ev.invoke_frozen_verifier = stub
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = ev.main(["--bundle", bundle] + list(extra))
                out.flush()
        finally:
            ev.invoke_frozen_verifier = original
        return code, raw.getvalue().decode("utf-8"), err.getvalue()

    def evaluate(self, bundle, stub=None, **kwargs):
        return ev.evaluate_bundle(Args(bundle, **kwargs),
                                  invoke=stub or StubVerifier())

    def nonmeasurement(self, bundle, stub=None, **kwargs):
        with self.assertRaises(ev.NonMeasurement) as ctx:
            self.evaluate(bundle, stub, **kwargs)
        return ctx.exception


# --------------------------------------------------------------------------
# Contract 5 -- manifest encoding, pinned exactly
# --------------------------------------------------------------------------

class ManifestIdentityBand(BundleCase):
    """Contract 5's DIRECT-READ identity boundary (E4-2): exit 1 is EXACTLY the
    five listed conditions and no others, and identity is taken by reading
    ``DIR/manifest.json`` directly rather than by enumerating the bundle first.

    HONESTY NOTE. Most of the E4-2 cases below are CONFIRMATIONS, not proofs of
    a fix: this lane already behaved this way, and they pass against the
    pre-erratum source too. Erratum 4's own method note -- "a test that passes
    with and without the fix is not a test" -- means they must not be read as
    evidence that E4-2 changed anything here. What they do is bind behaviour
    that was previously INFERRED (recorded ambiguity A13(ii)) to a rule that is
    now pinned, so a later regression fails. The two cases that genuinely
    discriminate against something are
    ``test_identity_is_read_directly_and_not_via_enumeration`` (fails if
    identity is taken by enumerating first) and
    ``test_unreadable_root_manifest_is_exit_1_not_a_result_object`` (fails if a
    reason code is minted for the root manifest).
    """

    def assert_no_identity(self, bundle):
        """Exit 1, stdout empty, NO result object -- the whole exit-1 band."""
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        return out

    def test_absent_manifest_is_exit_1_with_empty_stdout(self):
        empty = os.path.join(self.root, "empty")
        os.makedirs(empty)
        code, out, _ = self.run_cli(empty)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_bundle_directory_absent_is_exit_1(self):
        code, out, _ = self.run_cli(os.path.join(self.root, "nope"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_unparseable_manifest_is_exit_1(self):
        bundle = write_bundle(self.root, "IOP-P-DEC",
                              {"artifacts/d.json": DECISION},
                              manifest_overrides=lambda m: b"{not json")
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_nan_literal_in_manifest_is_not_strict_json(self):
        bundle = write_bundle(
            self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
            manifest_overrides=lambda m: b'{"scenario_id": "IOP-P-DEC", "x": NaN}')
        self.assertEqual(self.run_cli(bundle)[0], 1)

    def test_unregistered_scenario_id_is_exit_1(self):
        bundle = write_bundle(self.root, "IOP-X-NOPE", {"artifacts/d.json": DECISION})
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_manifest_without_scenario_id_is_exit_1(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              manifest_overrides=lambda m: {k: v for k, v in m.items()
                                                            if k != "scenario_id"})
        self.assertEqual(self.run_cli(bundle)[0], 1)

    def test_duplicate_manifest_members_is_exit_3_not_exit_1(self):
        """Ambiguity A8. A duplicated member is still parseable as strict JSON,
        CORRECTED BY ``AD15-IR-17``. The pre-erratum reading here took the
        last-wins value -- "the shared default of both runtimes" -- and reported
        exit 3. The ruling names that reasoning as the defect and splits the
        cases by NESTING: a duplicate TOP-LEVEL ``scenario_id`` is the exit-1
        band, because no registered ``scenario_id`` is DETERMINISTICALLY
        obtainable; every other duplicate stays exit 3. Both halves are asserted
        in ``DuplicateManifestMembers`` (W1-BLK-IR17); this case keeps the
        general exit-3 property on a NON-``scenario_id`` duplicate.
        """
        bundle = write_bundle(
            self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
            manifest_overrides=lambda m: (
                b'{"scenario_id": "IOP-P-DEC", "manifest_version": "9", '
                b'"manifest_version": "1", "files": []}'))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")
        self.assertIn("repeats object member name", result["nonmeasurement"]["detail"])

    def test_established_identity_never_falls_back_to_exit_1(self):
        """A structurally invalid manifest with a usable scenario_id is exit 3."""
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              manifest_overrides=lambda m: dict(m, surplus=1))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")

    # -- E4-2: the identity boundary is a DIRECT READ -------------------------

    def test_bundle_root_that_is_not_a_directory_is_exit_1(self):
        """First of the five: the bundle ROOT itself cannot be accessed. A
        regular file in the root's place makes ``DIR/manifest.json`` ENOTDIR,
        deterministically and without depending on permission enforcement.
        """
        not_a_dir = os.path.join(self.root, "root-is-a-file")
        with open(not_a_dir, "wb") as handle:
            handle.write(b"not a bundle")
        self.assert_no_identity(not_a_dir)

    def test_unreadable_root_manifest_is_exit_1_not_a_result_object(self):
        """E4-2's third condition, and the corollary it exists to pin: a root
        manifest that cannot be READ never yields ``bundle-file-unreadable``.
        The reason names a file listed in ``files[]``, from which the root
        manifest is excluded -- but more fundamentally a reason belongs to a
        result object, and there is no scenario to name one after.
        """
        if os.geteuid() == 0:
            self.skipTest("running as root: mode bits do not deny a read")
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        target = os.path.join(bundle, "manifest.json")
        os.chmod(target, 0)
        self.addCleanup(os.chmod, target, 0o600)
        try:
            with open(target, "rb"):
                self.skipTest("this filesystem does not enforce mode bits")
        except PermissionError:
            pass
        code, out, err = self.run_cli(bundle)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn("bundle-file-unreadable", out)
        self.assertNotIn("bundle-file-unreadable", err)

    def test_identity_is_read_directly_and_not_via_enumeration(self):
        """The boundary is a direct read, so a bundle whose CONTENT DIRECTORY
        cannot be enumerated still establishes identity and therefore still owes
        a result object naming the scenario. Were identity taken by enumerating
        first, this would collapse into the exit-1 band and the harness would
        lose the scenario name.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        original = ev.scan_directory
        self.addCleanup(setattr, ev, "scan_directory", original)
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno.EACCES, "Permission denied", path))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)                       # NOT the exit-1 band
        self.assertEqual(json.loads(out)["scenario_id"], "IOP-P-DEC")

    def test_the_exit_1_band_covers_all_five_conditions(self):
        """One case per E4-2 condition, each differing from the others in
        exactly one respect, so the enumeration is genuinely five wide rather
        than one condition spelled several ways. Condition 3 is driven through
        the ``open`` seam so it does not depend on mode-bit enforcement.
        """
        # 1 -- the bundle root itself cannot be accessed (ENOTDIR)
        root_is_file = os.path.join(self.root, "five-root-file")
        with open(root_is_file, "wb") as handle:
            handle.write(b"x")
        self.assert_no_identity(root_is_file)

        # 2 -- DIR/manifest.json is not found
        empty_root = os.path.join(self.root, "five-empty")
        os.makedirs(empty_root)
        self.assert_no_identity(empty_root)

        # 3 -- found, but cannot be opened or read
        unreadable = write_bundle(self.root, "IOP-P-DEC",
                                  {"artifacts/d.json": DECISION})
        original = ev.read_manifest_bytes
        self.addCleanup(setattr, ev, "read_manifest_bytes", original)
        ev.read_manifest_bytes = lambda path: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", path))
        self.assert_no_identity(unreadable)
        ev.read_manifest_bytes = original

        # 4 -- bytes do not parse as strict JSON
        self.assert_no_identity(write_bundle(
            self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
            manifest_overrides=lambda m: b"{not json"))

        # 5 -- no registered scenario_id can be obtained
        self.assert_no_identity(write_bundle(
            self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
            manifest_overrides=lambda m: {k: v for k, v in m.items()
                                          if k != "scenario_id"}))

    def test_a_bundle_outside_the_band_is_not_exit_1(self):
        """The negative half: a fault AFTER identity is established must leave
        the exit-1 band, or the enumeration above would be satisfied by an
        evaluator that simply exits 1 for everything.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              drop_from_disk=("artifacts/d.json",))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["scenario_id"], "IOP-P-DEC")


class ManifestEncoding(BundleCase):
    def bad(self, override, artifacts=None, **kwargs):
        bundle = write_bundle(self.root, "IOP-P-DEC",
                              artifacts or {"artifacts/d.json": DECISION},
                              manifest_overrides=override, **kwargs)
        return self.nonmeasurement(bundle)

    def test_unknown_manifest_member(self):
        self.assertEqual(self.bad(lambda m: dict(m, extra=1)).reason, "manifest-invalid")

    def test_missing_manifest_version(self):
        exc = self.bad(lambda m: {k: v for k, v in m.items() if k != "manifest_version"})
        self.assertEqual(exc.reason, "manifest-invalid")

    def test_manifest_version_must_be_the_string_1(self):
        self.assertEqual(self.bad(lambda m: dict(m, manifest_version=1)).reason,
                         "manifest-invalid")

    def test_file_entry_is_closed(self):
        def override(m):
            m["files"][0]["note"] = "x"
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_file_entry_requires_role(self):
        def override(m):
            del m["files"][0]["role"]
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_role_outside_the_closed_set(self):
        def override(m):
            m["files"][0]["role"] = "witness"
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_sha256_must_be_bare_hex_not_the_wire_form(self):
        def override(m):
            m["files"][0]["sha256"] = "sha256:" + m["files"][0]["sha256"]
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_sha256_must_be_lowercase(self):
        def override(m):
            m["files"][0]["sha256"] = m["files"][0]["sha256"].upper()
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_files_must_be_sorted_by_utf8_bytes(self):
        def override(m):
            m["files"] = list(reversed(m["files"]))
            return m
        exc = self.bad(override)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("sorted", exc.detail)

    def test_duplicate_path(self):
        def override(m):
            m["files"] = [m["files"][0], m["files"][0]] + m["files"][1:]
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_parent_segment_in_path(self):
        def override(m):
            m["files"][0]["path"] = "../escape.json"
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_backslash_in_path(self):
        def override(m):
            m["files"][0]["path"] = "artifacts\\d.json"
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_absolute_path(self):
        def override(m):
            m["files"][0]["path"] = "/etc/passwd"
            return m
        self.assertEqual(self.bad(override).reason, "manifest-invalid")

    def test_an_empty_files_array_is_bundle_shape_invalid_not_manifest_invalid(self):
        """Contract 5 pins closure, sort, `role`, `path` and digest encoding, and
        nowhere requires `files` to be non-empty. Rejecting it as
        `manifest-invalid` was this lane's own invention and is removed: zero
        artifacts fails the contract-5 count, which is what `bundle-shape-invalid`
        is defined over. The distinction is invisible to every aggregate duty --
        neither reason changes a Level-1 value -- which is exactly why it must
        not be left to the implementer.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {}, operator={},
                              manifest_files=[])
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-shape-invalid")

    def test_files_must_exclude_the_root_manifest(self):
        def override(m):
            m["files"].insert(0, {"path": "manifest.json", "role": "artifact",
                                  "sha256": "0" * 64})
            return m
        exc = self.bad(override)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("manifest.json", exc.detail)

    def test_file_on_disk_absent_from_files_is_manifest_invalid(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              extra_disk_files={"stowaway.json": b"{}"})
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("stowaway.json", exc.detail)

    def test_symlink_anywhere_under_the_bundle_is_rejected(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        os.symlink(os.path.join(bundle, "artifacts", "d.json"),
                   os.path.join(bundle, "artifacts", "link.json"))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("symbolic link", exc.detail)

    def test_listed_file_absent_from_disk(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              drop_from_disk=("artifacts/d.json",))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-file-missing")

    # -- Erratum 2, E2-1: the whole bundle-layout surface is manifest-invalid --

    def test_files_entry_naming_a_directory_is_manifest_invalid(self):
        """E2-1. Directories are containers only and are never files[] entries.
        The target EXISTS but is not a permitted file kind, so this is a layout
        violation, NOT bundle-file-missing.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              drop_from_disk=("artifacts/d.json",))
        os.makedirs(os.path.join(bundle, "artifacts", "d.json"))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("directory", exc.detail)

    def test_fifo_under_the_bundle_is_manifest_invalid(self):
        """E2-1: a FIFO, socket, device or any other non-regular, non-directory
        object under the bundle.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        try:
            os.mkfifo(os.path.join(bundle, "artifacts", "pipe"))
        except (AttributeError, OSError) as exc:      # pragma: no cover
            self.skipTest("this platform cannot create a FIFO: %s" % exc)
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("non-regular", exc.detail)

    def test_a_nested_directory_is_normal_and_needs_no_entry(self):
        """E2-1: directories are containers only. An empty one is not a finding,
        and a populated one contributes only its files.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        os.makedirs(os.path.join(bundle, "artifacts", "empty"))
        result = self.evaluate(bundle)
        self.assertEqual(result["measurement_status"], "MEASURED")

    def test_a_misplaced_manifest_is_caught_as_an_unlisted_file(self):
        """Ambiguity A10: identity comes only from manifest.json at the bundle
        root; a manifest anywhere else is an ordinary regular file.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              extra_disk_files={"nested/manifest.json": b"{}"})
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("nested/manifest.json", exc.detail)

    def test_a_symlinked_root_manifest_is_manifest_invalid_at_exit_3(self):
        """E2-1 puts "a forbidden symlink ANYWHERE under the bundle" under
        manifest-invalid, and the E4-2 identity boundary is a direct read: a
        link whose target opens and parses yields an identity, so none of the
        five exit-1 conditions is met. Identity is established from the target,
        then the symlink is reported against the named scenario.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        real = os.path.join(self.root, "elsewhere.json")
        shutil.move(os.path.join(bundle, "manifest.json"), real)
        os.symlink(real, os.path.join(bundle, "manifest.json"))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")
        self.assertIn("manifest.json", result["nonmeasurement"]["detail"])

    def test_digest_mismatch(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        with open(os.path.join(bundle, "artifacts", "d.json"), "ab") as handle:
            handle.write(b" ")
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-digest-mismatch")

    def test_unparseable_listed_file(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {},
                              raw_files={"artifacts/d.json": (b"{oops", "artifact")})
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-json-invalid")


# --------------------------------------------------------------------------
# Contract 5 -- bundle shape
# --------------------------------------------------------------------------

class BundleShape(BundleCase):
    def test_single_artifact_scenario_rejects_four(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", four_artifacts())
        self.assertEqual(self.nonmeasurement(bundle).reason, "bundle-shape-invalid")

    def test_reconciliation_scenario_rejects_one(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", {"artifacts/d.json": DECISION})
        self.assertEqual(self.nonmeasurement(bundle).reason, "bundle-shape-invalid")

    def test_single_artifact_family_must_match_the_scenario(self):
        bundle = write_bundle(self.root, "IOP-P-CTL", {"artifacts/d.json": DECISION})
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-shape-invalid")
        self.assertIn("control", exc.detail)

    def test_reconciliation_requires_one_of_each_family(self):
        arts = four_artifacts()
        arts["artifacts/effect.json"] = artifact("e-second-control", "control",
                                                 decision_ref={"record_id": "a-decision"},
                                                 authorized_action_digest="sha256:" + "11" * 32)
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        self.assertEqual(self.nonmeasurement(bundle).reason, "bundle-shape-invalid")

    def test_clock_role_is_out_of_composition_for_w1(self):
        operator = dict(OPERATOR_INPUTS)
        operator["operator/clock.json"] = ({"now": "2026-01-01T00:00:00Z"}, "clock")
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              operator=operator)
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-shape-invalid")
        self.assertIn("clock", exc.detail)

    def test_two_bindings_inputs_rejected(self):
        operator = dict(OPERATOR_INPUTS)
        operator["operator/bindings2.json"] = ({"bindings": []}, "bindings")
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              operator=operator)
        self.assertEqual(self.nonmeasurement(bundle).reason, "bundle-shape-invalid")

    def test_missing_revocation_input_rejected(self):
        operator = {k: v for k, v in OPERATOR_INPUTS.items() if "revocation" not in k}
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              operator=operator)
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-shape-invalid")
        self.assertIn("revocation", exc.detail)


# --------------------------------------------------------------------------
# Contract 5.1 -- numeric preflight, on integral VALUE
# --------------------------------------------------------------------------

class NumericPreflight(unittest.TestCase):
    def test_max_safe_integer_is_admissible(self):
        self.assertIsNone(ev.numeric_preflight({"n": 9007199254740991}))

    def test_one_past_max_safe_integer_is_rejected(self):
        self.assertIsNotNone(ev.numeric_preflight({"n": 9007199254740992}))

    def test_exponential_spelling_of_an_integral_value_is_rejected(self):
        """1e20 is integer-valued and exceeds the bound, despite its spelling."""
        value = json.loads('{"n": 1e20}')
        self.assertIsInstance(value["n"], float)
        found = ev.numeric_preflight(value)
        self.assertIsNotNone(found)
        self.assertEqual(found[0], "/n")

    def test_large_non_integral_value_is_judged_only_by_finiteness(self):
        self.assertIsNone(ev.numeric_preflight(json.loads('{"n": 1.5}')))
        self.assertIsNone(ev.numeric_preflight(json.loads('{"n": 1.0e-30}')))

    def test_nan_and_infinity_are_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e400"):
            with self.subTest(literal=literal):
                found = ev.numeric_preflight(json.loads('{"n": %s}' % literal))
                self.assertIsNotNone(found)

    def test_booleans_are_not_numbers(self):
        self.assertIsNone(ev.numeric_preflight({"a": True, "b": False}))

    def test_pointer_addresses_the_offending_number(self):
        doc = {"profiles": {"x/y~z": [{"deep": 10 ** 20}]}}
        found = ev.numeric_preflight(doc)
        self.assertEqual(found[0], "/profiles/x~1y~0z/0/deep")


class NumericPreflightInBundle(BundleCase):
    def test_violation_is_exit_3_with_a_mandatory_json_pointer(self):
        bundle = write_bundle(
            self.root, "IOP-P-DEC", {},
            raw_files={"artifacts/d.json": (
                json.dumps({"airep_version": "0.2", "artifact_type": "decision",
                            "record_id": "a-decision",
                            "profiles": {"vendor": {"big": 1e20}}}).encode("utf-8"),
                "artifact")})
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        nm = result["nonmeasurement"]
        self.assertEqual(nm["reason"], "numeric-preflight-violation")
        self.assertEqual(nm["json_pointer"], "/profiles/vendor/big")
        self.assertEqual(result["artifacts"], [])
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])

    def test_operator_input_numbers_are_also_preflighted(self):
        operator = dict(OPERATOR_INPUTS)
        operator["operator/revocation.json"] = ({"revoked": [], "n": 10 ** 20},
                                                "revocation")
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              operator=operator)
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "numeric-preflight-violation")
        self.assertEqual(exc.json_pointer, "/n")

    def test_json_pointer_is_permitted_for_no_other_reason(self):
        with self.assertRaises(ValueError):
            ev.NonMeasurement("manifest-invalid", "x", json_pointer="/a")
        with self.assertRaises(ValueError):
            ev.NonMeasurement("numeric-preflight-violation", "x")


# --------------------------------------------------------------------------
# Contract 5.1 -- the request envelope
# --------------------------------------------------------------------------

class Envelope(BundleCase):
    def test_single_artifact_related_is_the_empty_array(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(stub.calls[0][1]["related_artifacts"], [])

    def test_head_witness_is_never_present(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        for _, envelope, _ in stub.calls:
            self.assertNotIn("head_witness", envelope)
            self.assertEqual(set(envelope), {"artifact", "related_artifacts"})

    def test_related_artifacts_are_the_other_three_sorted_by_artifact_path(self):
        """Ruling ``AD15-IR-6``: the ordering key is the manifest-relative
        ``artifact_path``, not ``record_id``. The two disagree here on purpose --
        the paths sort d < e < f < g while the record_ids sort in the reverse
        direction -- so an implementation still keying on ``record_id`` produces
        the opposite order and fails.
        """
        arts = {
            "artifacts/d.json": artifact("z-decision", "decision"),
            "artifacts/e.json": artifact("y-control", "control",
                                         decision_ref={"record_id": "z-decision"},
                                         authorized_action_digest="sha256:" + "11" * 32),
            "artifacts/f.json": artifact("x-execution", "execution",
                                         decision_ref={"record_id": "z-decision"},
                                         executed_action_digest="sha256:" + "11" * 32),
            "artifacts/g.json": artifact("w-effect", "effect",
                                         decision_ref={"record_id": "z-decision"},
                                         execution_ref={"record_id": "x-execution"},
                                         observer_relationship="independent"),
        }
        by_record = {a["record_id"]: path for path, a in arts.items()}
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        self.assertEqual(len(stub.calls), 4)
        for record_id, envelope, _ in stub.calls:
            related = [a["record_id"] for a in envelope["related_artifacts"]]
            self.assertEqual(len(related), 3)
            self.assertNotIn(record_id, related)
            paths = [by_record[r] for r in related]
            self.assertEqual(paths, sorted(paths, key=lambda s: s.encode("utf-8")))
            # The record_id order is the REVERSE, so this is a discriminating
            # assertion and not a coincidence of the fixture.
            self.assertNotEqual(
                related, sorted(related, key=lambda s: s.encode("utf-8")))

    def test_an_artifact_without_a_record_id_still_orders_deterministically(self):
        """``AD15-IR-6``'s reason for existing: an artifact with no usable
        ``record_id`` no longer leaves the envelope undefined. It is ordered by
        its path like every other member, and it REACHES frozen stage 0 instead
        of becoming this evaluator's own preflight failure.
        """
        arts = four_artifacts()
        del arts["artifacts/effect.json"]["record_id"]
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)

        # Stage 0 was reached for all four, the unidentifiable one included.
        self.assertEqual(len(stub.calls), 4)
        self.assertIn(None, [c[0] for c in stub.calls])
        self.assertEqual(result["measurement_status"], "MEASURED")

        # `artifacts/effect.json` sorts third of four by path, so the artifact
        # with no record_id occupies a DEFINED slot in every other envelope.
        expected = ["artifacts/control.json", "artifacts/decision.json",
                    "artifacts/effect.json", "artifacts/execution.json"]
        for record_id, envelope, _ in stub.calls:
            related = envelope["related_artifacts"]
            self.assertEqual(len(related), 3)
            # No record_id is synthesized to fill the gap: when the primary is
            # one of the three identified artifacts, exactly one RELATED member
            # still carries no record_id at all.
            without = [a for a in related if "record_id" not in a]
            self.assertEqual(len(without), 0 if record_id is None else 1)
        # And the digest is reproducible: a second evaluation of the same bundle
        # yields the same per-path envelope digests.
        again = self.evaluate(bundle, StubVerifier())
        self.assertEqual([e["artifact_path"] for e in result["artifacts"]], expected)
        self.assertEqual(
            {e["artifact_path"]: e["request_envelope_digest"] for e in result["artifacts"]},
            {e["artifact_path"]: e["request_envelope_digest"] for e in again["artifacts"]})

    def test_digest_is_a_function_of_the_bundle_and_of_nothing_else(self):
        """Contract 5.1: the envelope is "a function of the bundle alone".

        ``AD15-IR-6`` moved the ordering key to ``artifact_path``, so the
        manifest paths are now part of what the envelope is a function of -- they
        are still part of the BUNDLE, and nothing outside it participates. Two
        materializations of the same bundle at different absolute locations, run
        from different working directories, must therefore agree exactly.

        The earlier version of this test asserted the opposite -- that varying
        the paths left the digests unchanged -- which was true only while the
        ordering keyed on ``record_id``.
        """
        arts = four_artifacts()
        root_b = tempfile.mkdtemp(prefix="airep interop test elsewhere ")
        self.addCleanup(shutil.rmtree, root_b, ignore_errors=True)
        first = self.evaluate(write_bundle(self.root, "IOP-R-CLEAN", arts))
        cwd = os.getcwd()
        os.chdir(root_b)
        try:
            second = self.evaluate(write_bundle(root_b, "IOP-R-CLEAN", arts))
        finally:
            os.chdir(cwd)
        by_path = lambda r: {e["artifact_path"]: e["request_envelope_digest"]
                             for e in r["artifacts"]}
        self.assertEqual(by_path(first), by_path(second))

    def test_renaming_the_paths_changes_the_envelope_because_order_changes(self):
        """The other half of ``AD15-IR-6``, asserted rather than assumed: the
        ordering key is the path, so a bundle whose artifacts sit at paths in the
        opposite sort order produces a DIFFERENT related_artifacts order and
        therefore different envelope bytes. This is the observation that
        distinguishes path-ordering from record_id-ordering.
        """
        arts = four_artifacts()
        forward = {
            "artifacts/1decision.json": arts["artifacts/decision.json"],
            "artifacts/2control.json": arts["artifacts/control.json"],
            "artifacts/3execution.json": arts["artifacts/execution.json"],
            "artifacts/4effect.json": arts["artifacts/effect.json"],
        }
        reversed_layout = {
            "artifacts/8decision.json": arts["artifacts/decision.json"],
            "artifacts/7control.json": arts["artifacts/control.json"],
            "artifacts/6execution.json": arts["artifacts/execution.json"],
            "artifacts/5effect.json": arts["artifacts/effect.json"],
        }
        root_b = tempfile.mkdtemp(prefix="airep interop test ")
        self.addCleanup(shutil.rmtree, root_b, ignore_errors=True)
        first = self.evaluate(write_bundle(self.root, "IOP-R-CLEAN", forward))
        second = self.evaluate(write_bundle(root_b, "IOP-R-CLEAN", reversed_layout))
        by_record = lambda r: {e["artifact_ref"]["record_id"]:
                               e["request_envelope_digest"] for e in r["artifacts"]}
        self.assertNotEqual(by_record(first), by_record(second))

    def test_digest_is_over_the_jcs_bytes(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        result = self.evaluate(bundle)
        expected = ev.digest_str(ev.jcs.canonicalize(
            {"artifact": DECISION, "related_artifacts": []}))
        self.assertEqual(result["artifacts"][0]["request_envelope_digest"], expected)

    def test_operator_inputs_are_passed_through_by_bundle_path(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        flags = stub.calls[0][2]
        self.assertEqual(flags[0::2], ["--bindings", "--independence-policy",
                                       "--revocation"])
        for path in flags[1::2]:
            self.assertTrue(path.startswith(bundle + os.sep), path)
            self.assertTrue(os.path.isfile(path))


# --------------------------------------------------------------------------
# Contract 6 / 6.1 -- predicates and applicability
# --------------------------------------------------------------------------

class Predicates(BundleCase):
    def reconciliation(self, scenario_id, artifacts=None, stub=None):
        bundle = write_bundle(self.root, scenario_id, artifacts or four_artifacts())
        return self.evaluate(bundle, stub)

    def test_clean_bundle_passes_all_three(self):
        result = self.reconciliation("IOP-R-CLEAN")
        self.assertEqual(result["predicates"],
                         {"R_A": "PASS", "R_B": "PASS", "R_C": "PASS"})
        self.assertEqual(result["level1"], "ACCEPT")

    def test_toctou_fails_only_r_b(self):
        arts = four_artifacts(execution={"executed_action_digest": "sha256:" + "22" * 32})
        result = self.reconciliation("IOP-R-TOCTOU", arts)
        self.assertEqual(result["predicates"],
                         {"R_A": "PASS", "R_B": "FAIL", "R_C": "PASS"})
        self.assertEqual(result["level1"], "RECONCILIATION_MISMATCH")

    def test_xref_fails_only_r_a(self):
        arts = four_artifacts(effect={"decision_ref": {"record_id": "iop-absent-0000"}})
        result = self.reconciliation("IOP-R-XREF", arts)
        self.assertEqual(result["predicates"],
                         {"R_A": "FAIL", "R_B": "PASS", "R_C": "PASS"})
        self.assertEqual(result["level1"], "RECONCILIATION_MISMATCH")

    def test_indep_fails_only_r_c(self):
        stub = StubVerifier(by_record={
            "d-effect": (0, verdict("d-effect", observer="unknown"))})
        result = self.reconciliation("IOP-R-INDEP", stub=stub)
        self.assertEqual(result["predicates"],
                         {"R_A": "PASS", "R_B": "PASS", "R_C": "FAIL"})
        self.assertEqual(result["level1"], "INDEPENDENCE_NOT_ESTABLISHED")

    def test_all_three_are_evaluated_even_after_a_failure(self):
        arts = four_artifacts(
            execution={"executed_action_digest": "sha256:" + "22" * 32},
            effect={"decision_ref": {"record_id": "iop-absent-0000"}})
        result = self.reconciliation("IOP-R-TOCTOU", arts)
        self.assertEqual(result["predicates"],
                         {"R_A": "FAIL", "R_B": "FAIL", "R_C": "PASS"})

    def test_r_a_is_reference_resolution_only_no_family_check(self):
        """A decision_ref pointing at the Control still resolves uniquely."""
        arts = four_artifacts(effect={"decision_ref": {"record_id": "b-control"},
                                      "execution_ref": {"record_id": "c-execution"},
                                      "observer_relationship": "independent"})
        result = self.reconciliation("IOP-R-CLEAN", arts)
        self.assertEqual(result["predicates"]["R_A"], "PASS")

    def test_chain_id_qualified_reference(self):
        arts = four_artifacts(effect={
            "decision_ref": {"record_id": "a-decision", "chain_id": "other-chain"},
            "execution_ref": {"record_id": "c-execution"},
            "observer_relationship": "independent"})
        result = self.reconciliation("IOP-R-CLEAN", arts)
        self.assertEqual(result["predicates"]["R_A"], "FAIL")

    def test_r_b_compares_exact_strings_no_case_folding(self):
        arts = four_artifacts(
            execution={"executed_action_digest": "sha256:" + "11" * 32})
        arts["artifacts/control.json"]["authorized_action_digest"] = \
            "SHA256:" + "11" * 32
        result = self.reconciliation("IOP-R-CLEAN", arts)
        self.assertEqual(result["predicates"]["R_B"], "FAIL")

    def test_r_c_is_taken_from_the_frozen_verdict_not_re_derived(self):
        """same_executor on the wire is not the pinned FAIL condition."""
        arts = four_artifacts(effect={
            "decision_ref": {"record_id": "a-decision"},
            "execution_ref": {"record_id": "c-execution"},
            "observer_relationship": "same_executor"})
        stub = StubVerifier(by_record={
            "d-effect": (0, verdict("d-effect", observer="unknown"))})
        result = self.reconciliation("IOP-R-CLEAN", arts, stub=stub)
        self.assertEqual(result["predicates"]["R_C"], "PASS")

    def test_single_artifact_scenarios_are_not_run_through_the_predicates(self):
        for scenario_id, family, doc in (("IOP-P-DEC", "decision", DECISION),
                                         ("IOP-P-CTL", "control", CONTROL),
                                         ("IOP-P-EXE", "execution", EXECUTION),
                                         ("IOP-P-EFF", "effect", EFFECT)):
            with self.subTest(scenario_id=scenario_id):
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, scenario_id, {"artifacts/a.json": doc})
                result = self.evaluate(bundle)
                self.assertEqual(result["predicates"],
                                 {"R_A": "NOT_APPLICABLE", "R_B": "NOT_APPLICABLE",
                                  "R_C": "NOT_APPLICABLE"})
                self.assertEqual(result["level1"], "ACCEPT")
                self.assertEqual(result["measurement_status"], "MEASURED")


# --------------------------------------------------------------------------
# Contract 7 / 7.1 / 7.2 -- Level-1 mapping and its guards
# --------------------------------------------------------------------------

class Level1Mapping(BundleCase):
    def test_authenticated_failure_is_reject(self):
        bundle = write_bundle(self.root, "IOP-B-EXE", {"artifacts/a.json": EXECUTION})
        stub = StubVerifier(by_record={
            "c-execution": (0, verdict("c-execution", klass="AIREP-Core",
                                       auth_failures=["record-signature-invalid"]))})
        result = self.evaluate(bundle, stub)
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["level1"], "REJECT")

    def test_frozen_exit_1_is_reject_only_for_the_three_pinned_scenarios(self):
        for scenario_id, family, doc in (("IOP-B-DEC", "decision", DECISION),
                                         ("IOP-B-CTL", "control", CONTROL),
                                         ("IOP-B-EFF", "effect", EFFECT)):
            with self.subTest(scenario_id=scenario_id):
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, scenario_id, {"artifacts/a.json": doc})
                result = self.evaluate(bundle, StubVerifier(default=(1, None)))
                self.assertEqual(result["level1"], "REJECT")
                self.assertIsNone(result["artifacts"][0]["verifier_result"])
                self.assertEqual(result["artifacts"][0]["verifier_exit_code"], 1)

    def test_frozen_exit_1_elsewhere_is_verifier_run_invalid(self):
        for scenario_id, doc in (("IOP-P-DEC", DECISION), ("IOP-B-EXE", EXECUTION)):
            with self.subTest(scenario_id=scenario_id):
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, scenario_id, {"artifacts/a.json": doc})
                with self.assertRaises(ev.NonMeasurement) as ctx:
                    ev.evaluate_bundle(Args(bundle),
                                       invoke=StubVerifier(default=(1, None)))
                self.assertEqual(ctx.exception.reason, "verifier-run-invalid")
                self.assertEqual(ctx.exception.status, "ERROR")

    def test_reject_precedes_the_reconciliation_predicates(self):
        stub = StubVerifier(by_record={
            "d-effect": (0, verdict("d-effect", klass="AIREP-Core",
                                    auth_failures=["record-signature-invalid"],
                                    observer="unknown"))})
        bundle = write_bundle(self.root, "IOP-R-INDEP", four_artifacts())
        result = self.evaluate(bundle, stub)
        self.assertEqual(result["level1"], "REJECT")
        self.assertEqual(result["predicates"]["R_C"], "FAIL")

    def test_independence_precedes_reconciliation(self):
        arts = four_artifacts(execution={"executed_action_digest": "sha256:" + "22" * 32})
        stub = StubVerifier(by_record={
            "d-effect": (0, verdict("d-effect", observer="unknown"))})
        bundle = write_bundle(self.root, "IOP-R-INDEP", arts)
        result = self.evaluate(bundle, stub)
        self.assertEqual(result["level1"], "INDEPENDENCE_NOT_ESTABLISHED")

    def test_authenticated_withheld_is_measurement_invalid_never_accept(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        stub = StubVerifier(by_record={
            "a-decision": (0, verdict("a-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-binding-absent"]))})
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.evaluate_bundle(Args(bundle), invoke=stub)
        exc = ctx.exception
        self.assertEqual(exc.reason, "authenticated-withheld")
        self.assertEqual(exc.status, "MEASUREMENT_INVALID")
        # AD15-IR-16 entry shape: one entry per (artifact, channel, reason).
        self.assertEqual(exc.withheld_reasons, [{
            "artifact_path": "artifacts/a.json",
            "channel": "authenticated_withheld",
            "reason": "producer-binding-absent"}])
        self.assertEqual(len(exc.artifacts), 1)

    def test_authenticated_withheld_is_the_only_measurement_invalid_reason(self):
        invalid = [r for r, s in ev.REASON_STATUS.items()
                   if s == ev.MEASUREMENT_INVALID]
        self.assertEqual(invalid, ["authenticated-withheld"])

    def test_witnessed_withheld_alone_does_not_invalidate(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   witnessed_withheld=["head-witness-absent"]))})
        result = self.evaluate(bundle, stub)
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["level1"], "ACCEPT")
        self.assertEqual(result["withheld_reasons"], [{
            "artifact_path": "artifacts/a.json",
            "channel": "witnessed_withheld",
            "reason": "head-witness-absent"}])


# --------------------------------------------------------------------------
# Contract 8.2 / 8.3 -- result object shape
# --------------------------------------------------------------------------

class ResultShape(BundleCase):
    def measured(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        return self.evaluate(bundle)

    def test_member_set_is_exactly_the_contract_list(self):
        self.assertEqual(set(self.measured()), {
            "scenario_id", "measurement_status", "level1", "predicates",
            "nonmeasurement", "artifacts", "withheld_reasons", "verifier_digests",
            "evaluator_version"})

    def test_measured_result_carries_no_nonmeasurement(self):
        self.assertIsNone(self.measured()["nonmeasurement"])

    def test_verifier_digests_are_own_lane_only(self):
        digests = self.measured()["verifier_digests"]
        self.assertEqual(set(digests), {"class_verifier", "class_verifier_contract"})
        self.assertEqual(digests["class_verifier"],
                         "sha256:" + ev.FROZEN_VERIFIER_SHA256)
        self.assertEqual(digests["class_verifier_contract"],
                         "sha256:" + ev.FROZEN_CONTRACT_SHA256)

    def test_no_peer_lane_verifier_digest_anywhere_in_the_source_or_output(self):
        """Contract 8.2.1: the peer digest does not appear in output at all."""
        emitted = json.dumps(self.measured())
        self.assertEqual(emitted.count("sha256:"), 4)  # 2 frozen + envelope + stderr
        with open(ev.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn(".mjs", source)
        self.assertNotIn("verifier_node", source)

    def test_artifact_entry_shape(self):
        """AD15-IR-5: artifact_path is required and is the entry's identity."""
        entry = self.measured()["artifacts"][0]
        self.assertEqual(set(entry), {
            "artifact_path", "artifact_ref", "request_envelope_digest",
            "verifier_exit_code", "verifier_result", "verifier_stderr_digest"})
        self.assertEqual(entry["artifact_path"], "artifacts/a.json")
        self.assertEqual(entry["artifact_ref"],
                         {"record_id": "a-decision", "chain_id": "chain-synthetic"})
        self.assertTrue(entry["verifier_stderr_digest"].startswith("sha256:"))

    def test_artifact_ref_omits_chain_id_when_the_bundle_carries_none(self):
        """``AD15-IR-18`` step 4: a missing ``chain_id`` is OMITTED, never null.

        The emitted entry is measured on a SOURCE-B path -- ``AD15-IR-18``
        pins the ``exit 0`` path to the VERDICT's ``artifact_ref``, so an
        exit-0 fixture here would measure the stub, not the projection.
        """
        doc = {k: v for k, v in DECISION.items() if k != "chain_id"}
        self.assertEqual(ev.artifact_ref_from_artifact(doc),
                         {"record_id": "a-decision"})
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.assertEqual(entry["artifact_ref"], {"record_id": "a-decision"})

    def test_measured_artifact_count_matches_the_bundle_shape(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        self.assertEqual(len(self.evaluate(bundle)["artifacts"]), 4)

    def test_artifacts_are_ordered_by_artifact_path_utf8_bytes(self):
        """AD15-IR-5 / contract 8.4. Ordering moved off record_id, which an
        artifact rejected at stage 0 may not have. The bundle here is built so
        the two orderings DIFFER, or the assertion would prove nothing.
        """
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        entries = self.evaluate(bundle)["artifacts"]
        paths = [e["artifact_path"] for e in entries]
        self.assertEqual(paths, sorted(paths, key=lambda s: s.encode("utf-8")))
        ids = [e["artifact_ref"]["record_id"] for e in entries]
        self.assertNotEqual(ids, sorted(ids, key=lambda s: s.encode("utf-8")))

    def test_a_post_invocation_internal_fault_lists_what_was_attempted(self):
        """Contract 8.3.1 rule 3: "once invocation begins, artifacts[] contains
        an entry for each invocation ACTUALLY ATTEMPTED, and only those." An
        `artifacts: []` here would assert a pre-invocation failure that did not
        happen -- four invocations completed before the fault.
        """
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        original = ev.map_level1
        self.addCleanup(setattr, ev, "map_level1", original)
        ev.map_level1 = lambda reject, predicates: (_ for _ in ()).throw(
            RuntimeError("synthetic fault after the invocation loop"))
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["nonmeasurement"]["reason"], "internal-error")
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertEqual([e["artifact_path"] for e in result["artifacts"]],
                         sorted(e["artifact_path"] for e in result["artifacts"]))

    def test_pre_invocation_error_emits_an_empty_artifacts_array(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              drop_from_disk=("artifacts/a.json",))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["artifacts"], [])

    def test_post_invocation_error_lists_only_attempted_invocations(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        stub = StubVerifier(by_record={"a-decision": (0, verdict("a-decision"))},
                            default=(1, None))
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.evaluate_bundle(Args(bundle), invoke=stub)
        self.assertEqual(ctx.exception.reason, "verifier-run-invalid")
        # CORRECTED BY ``AD15-IR-12``: a `verifier-run-invalid` run contributes
        # its entry AND ABORTS THE SCENARIO IMMEDIATELY. The pre-erratum
        # construction invoked all four artifacts and swept the exit codes
        # afterwards, which the ruling now forbids. `artifacts/control.json` is
        # the FIRST path in UTF-8 byte order and the stub exits 1 for it under
        # IOP-R-CLEAN, which 7.2 does not admit, so the run stops with exactly
        # that one entry -- the decision stub is never even reached.
        self.assertEqual([e["artifact_path"] for e in ctx.exception.artifacts],
                         ["artifacts/control.json"])

    def test_nonmeasurement_object_is_closed(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              drop_from_disk=("artifacts/a.json",))
        nm = json.loads(self.run_cli(bundle)[1])["nonmeasurement"]
        self.assertEqual(set(nm), {"reason", "detail"})
        self.assertIn(nm["reason"], ev.REASON_STATUS)

    def test_unmeasured_result_still_carries_this_lane_s_digests(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              drop_from_disk=("artifacts/a.json",))
        digests = json.loads(self.run_cli(bundle)[1])["verifier_digests"]
        self.assertEqual(set(digests), {"class_verifier", "class_verifier_contract"})

    def test_every_registry_reason_maps_to_a_declared_status(self):
        self.assertEqual(set(ev.REASON_STATUS), {
            "manifest-invalid", "manifest-digest-mismatch", "bundle-file-missing",
            "bundle-file-unreadable", "bundle-directory-unreadable",
            "bundle-entry-uninspectable", "frozen-identity-unreadable",
            "bundle-json-invalid", "bundle-shape-invalid",
            "numeric-preflight-violation", "verifier-digest-mismatch",
            "verifier-not-invocable", "verifier-run-invalid", "internal-error",
            "operator-input-assertion-mismatch", "authenticated-withheld"})

    def test_only_authenticated_withheld_is_measurement_invalid(self):
        invalid = {r for r, st in ev.REASON_STATUS.items() if st != "ERROR"}
        self.assertEqual(invalid, {"authenticated-withheld"})
        self.assertEqual(ev.REASON_STATUS["bundle-file-unreadable"], "ERROR")

    def test_reason_outside_the_registry_is_refused(self):
        with self.assertRaises(KeyError):
            ev.NonMeasurement("made-up-reason", "x")


# --------------------------------------------------------------------------
# Contract 3 / 8.2.1 -- frozen identity
# --------------------------------------------------------------------------

class FrozenIdentity(BundleCase):
    def test_the_tree_matches_the_pinned_digests(self):
        digests, problem = ev.measure_frozen_digests()
        self.assertIsNone(problem)
        self.assertEqual(digests["class_verifier"],
                         "sha256:" + ev.FROZEN_VERIFIER_SHA256)

    def test_a_mismatch_is_a_hard_error_before_any_invocation(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        original = ev.FROZEN_VERIFIER_SHA256
        ev.FROZEN_VERIFIER_SHA256 = "0" * 64
        ev.FROZEN_FILES = (
            ("class_verifier", ev.frozen_verifier_path, "0" * 64),
            ("class_verifier_contract", ev.frozen_contract_path,
             ev.FROZEN_CONTRACT_SHA256),
        )
        try:
            stub = StubVerifier()
            with self.assertRaises(ev.NonMeasurement) as ctx:
                ev.evaluate_bundle(Args(bundle), invoke=stub)
            self.assertEqual(ctx.exception.reason, "verifier-digest-mismatch")
            self.assertEqual(stub.calls, [])
            self.assertEqual(ctx.exception.artifacts, [])
        finally:
            ev.FROZEN_VERIFIER_SHA256 = original
            ev.FROZEN_FILES = (
                ("class_verifier", ev.frozen_verifier_path, original),
                ("class_verifier_contract", ev.frozen_contract_path,
                 ev.FROZEN_CONTRACT_SHA256),
            )

    def test_verifier_not_invocable(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})

        def explode(request, flags):
            raise ev.NonMeasurement("verifier-not-invocable", "synthetic OSError")

        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.evaluate_bundle(Args(bundle), invoke=explode)
        self.assertEqual(ctx.exception.reason, "verifier-not-invocable")
        self.assertEqual(ctx.exception.artifacts, [])

    def test_the_real_frozen_verifier_is_reachable_as_a_subprocess(self):
        """Exercises the actual subprocess seam. The artifact is synthetic
        nonsense, so the frozen verifier is expected to refuse it; the point is
        that it RAN and that its exit code reached the 7.2 guard.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC",
                              {"artifacts/a.json": {"airep_version": "0.2",
                                                    "artifact_type": "decision",
                                                    "record_id": "a-decision"}})
        code, out, err = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "verifier-run-invalid")
        self.assertEqual(len(result["artifacts"]), 1)
        self.assertEqual(result["artifacts"][0]["verifier_exit_code"], 1)
        self.assertIsNone(result["artifacts"][0]["verifier_result"])


# --------------------------------------------------------------------------
# Contract 8.5 -- exit / stdout, and 8.4 determinism
# --------------------------------------------------------------------------

class ExitTable(BundleCase):
    def test_measured_run_exits_0_with_exactly_one_object(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 0)
        result = json.loads(out)      # one object, or this raises
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertIsNotNone(result["level1"])

    def test_exit_0_never_has_empty_stdout(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())

    def test_missing_bundle_flag_is_exit_2_with_empty_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ev.main([])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")

    def test_inconsistent_operator_flag_is_result_bearing_at_exit_3(self):
        """CORRECTED BY ``AD15-IR-14``, AGAINST this lane, which reported exit 2
        with empty stdout. The mismatch is only detectable AFTER identity is
        established, and an established identity is owed a result object.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, _ = self.run_cli(bundle, ["--bindings", "/elsewhere/b.json"])
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "operator-input-assertion-mismatch")
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")

    def test_consistent_operator_flag_is_accepted_and_changes_nothing(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        plain = self.run_cli(bundle, stub=StubVerifier())
        flagged = self.run_cli(bundle, [
            "--bindings", os.path.join(bundle, "operator", "bindings.json")],
            stub=StubVerifier())
        self.assertEqual(plain[0], 0)
        self.assertEqual(flagged[0], 0)
        self.assertEqual(plain[1], flagged[1])

    def test_unmeasured_run_exits_3_with_nulls_and_a_reason(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              manifest_overrides=lambda m: dict(m, surplus=1))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])
        self.assertIsNotNone(result["nonmeasurement"])

    def test_predicates_are_null_never_a_triple_of_not_applicable(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              drop_from_disk=("artifacts/a.json",))
        self.assertIsNone(json.loads(self.run_cli(bundle)[1])["predicates"])

    def test_stderr_is_never_a_source_of_semantics(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        quiet = self.evaluate(bundle, StubVerifier(stderr=b""))
        noisy = self.evaluate(bundle, StubVerifier(stderr=b"REJECT everything"))
        self.assertEqual(quiet["level1"], noisy["level1"])
        self.assertNotEqual(quiet["artifacts"][0]["verifier_stderr_digest"],
                            noisy["artifacts"][0]["verifier_stderr_digest"])

    def test_output_is_byte_identical_across_runs(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        first = self.run_cli(bundle, stub=StubVerifier())[1]
        second = self.run_cli(bundle, stub=StubVerifier())[1]
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["measurement_status"], "MEASURED")

    def test_no_case_discovery_happens(self):
        """A sibling bundle directory is neither scanned nor reported."""
        sibling = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        os.rename(sibling, os.path.join(self.root, "other"))
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        result = json.loads(self.run_cli(bundle, stub=StubVerifier())[1])
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(len(result["artifacts"]), 1)


# --------------------------------------------------------------------------
# Erratum 2, E2-2 -- every abnormal frozen run is verifier-run-invalid
# --------------------------------------------------------------------------

class AbnormalFrozenRun(BundleCase):
    """Contract 8.2.2, Erratum 2.

    The frozen process STARTED but did not produce a process/result shape the
    frozen contract permits. Every case below was `internal-error` in this
    lane's pre-erratum candidate except the non-qualifying `exit 1`.
    """

    def abnormal(self, stub):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        exc = self.nonmeasurement(bundle, stub)
        self.assertEqual(exc.reason, "verifier-run-invalid")
        self.assertEqual(exc.status, "ERROR")
        return exc

    def test_exit_0_with_empty_stdout(self):
        exc = self.abnormal(StubVerifier(default=(0, b"")))
        self.assertIn("empty stdout", exc.detail)

    def test_exit_0_with_whitespace_only_stdout(self):
        self.abnormal(StubVerifier(default=(0, b"   \n")))

    def test_exit_0_with_non_json_stdout(self):
        exc = self.abnormal(StubVerifier(default=(0, b"not json at all")))
        self.assertIn("strict JSON", exc.detail)

    def test_exit_0_with_nan_is_not_strict_json(self):
        self.abnormal(StubVerifier(default=(0, b'{"observer_assessment": NaN}')))

    def test_exit_0_with_multiple_results(self):
        """Two concatenated documents are not the single expected verdict."""
        self.abnormal(StubVerifier(default=(0, b'{"a": 1}\n{"b": 2}')))

    def test_exit_0_with_a_non_object_result(self):
        exc = self.abnormal(StubVerifier(default=(0, b'["not", "an", "object"]')))
        self.assertIn("single expected verdict object", exc.detail)

    # -- "wrong-shape result": a JSON OBJECT that is not a verdict envelope --
    #
    # These are the cases that previously reached MEASURED / ACCEPT. The frozen
    # CLASS_VERIFIER_CONTRACT.md section 2 pins the envelope, so "wrong-shape"
    # is determinable and E2-2 requires refusing it.

    def test_exit_0_with_an_empty_object(self):
        exc = self.abnormal(StubVerifier(default=(0, b'{}')))
        self.assertIn("not a normalized verdict envelope", exc.detail)

    def test_exit_0_with_an_unrelated_object(self):
        self.abnormal(StubVerifier(default=(0, b'{"totally": "wrong"}')))

    def test_a_verdict_missing_a_reason_array_is_refused(self):
        """Frozen 2: all five reason arrays are PRESENT ALWAYS. A missing one
        would read as "no failures" and launder an unmeasured tier into ACCEPT.
        """
        for channel in ("authenticated_failures", "authenticated_withheld",
                        "authenticated_caveats", "witnessed_failures",
                        "witnessed_withheld"):
            with self.subTest(channel=channel):
                body = {k: v for k, v in verdict("a-decision").items()
                        if k != channel}
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, "IOP-P-DEC",
                                      {"artifacts/a.json": DECISION})
                with self.assertRaises(ev.NonMeasurement) as ctx:
                    ev.evaluate_bundle(
                        Args(bundle),
                        invoke=StubVerifier(default=(0, body)))
                self.assertEqual(ctx.exception.reason, "verifier-run-invalid")
                self.assertIn(channel, ctx.exception.detail)

    def test_a_verdict_with_an_out_of_set_class_is_refused(self):
        body = dict(verdict("a-decision"), **{"class": "AIREP-Pseudo"})
        exc = self.abnormal(StubVerifier(default=(0, body)))
        self.assertIn("class", exc.detail)

    def test_a_verdict_with_an_out_of_set_observer_assessment_is_refused(self):
        body = dict(verdict("a-decision"), observer_assessment="probably")
        exc = self.abnormal(StubVerifier(default=(0, body)))
        self.assertIn("observer_assessment", exc.detail)

    def test_a_verdict_missing_evidence_or_artifact_ref_is_refused(self):
        for member in ("evidence", "artifact_ref"):
            with self.subTest(member=member):
                body = {k: v for k, v in verdict("a-decision").items()
                        if k != member}
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, "IOP-P-DEC",
                                      {"artifacts/a.json": DECISION})
                with self.assertRaises(ev.NonMeasurement) as ctx:
                    ev.evaluate_bundle(Args(bundle),
                                       invoke=StubVerifier(default=(0, body)))
                self.assertEqual(ctx.exception.reason, "verifier-run-invalid")

    def test_a_garbage_effect_verdict_cannot_become_accept(self):
        """The laundering path contract 7.1 forbids, asserted end to end: a
        wrong-shape Effect verdict must not produce MEASURED / ACCEPT with a
        vacuous R_C PASS.
        """
        bundle = write_bundle(self.root, "IOP-R-INDEP", four_artifacts())
        stub = StubVerifier(by_record={
            "d-effect": (0, {"class": "AIREP-Authenticated"})})
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.evaluate_bundle(Args(bundle), invoke=stub)
        self.assertEqual(ctx.exception.reason, "verifier-run-invalid")

    def test_an_unknown_member_in_a_verdict_is_tolerated(self):
        """Frozen 2 does not declare the envelope closed, so the shape check
        must not invent closure (ambiguity A12).
        """
        body = dict(verdict("a-decision"), some_future_member=1)
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        result = self.evaluate(bundle, StubVerifier(default=(0, body)))
        self.assertEqual(result["measurement_status"], "MEASURED")

    def test_exit_2(self):
        """The case that diverged across the two lanes before Erratum 2."""
        exc = self.abnormal(StubVerifier(default=(2, None)))
        self.assertIn("exited 2", exc.detail)

    def test_any_other_impermissible_exit(self):
        for code in (3, 42, 127, -9):
            with self.subTest(code=code):
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, "IOP-P-DEC",
                                      {"artifacts/a.json": DECISION})
                with self.assertRaises(ev.NonMeasurement) as ctx:
                    ev.evaluate_bundle(Args(bundle),
                                       invoke=StubVerifier(default=(code, None)))
                self.assertEqual(ctx.exception.reason, "verifier-run-invalid")

    def test_abnormal_run_still_lists_the_attempted_invocation(self):
        """Contract 8.3.1 rule 3, and the entry must carry artifact_path."""
        exc = self.abnormal(StubVerifier(default=(2, None)))
        self.assertEqual(len(exc.artifacts), 1)
        self.assertEqual(exc.artifacts[0]["artifact_path"], "artifacts/a.json")
        self.assertEqual(exc.artifacts[0]["verifier_exit_code"], 2)

    def test_not_invocable_is_only_a_spawn_failure(self):
        """Erratum 2 narrows verifier-not-invocable to a process that could not
        be spawned or executed AT ALL.

        This drives the REAL invoke_frozen_verifier and makes the spawn itself
        fail, so the OSError -> verifier-not-invocable mapping is exercised
        rather than hand-raised.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        original = ev.sys.executable
        ev.sys.executable = os.path.join(self.root, "no-such-interpreter")
        try:
            exc = self.nonmeasurement(bundle, ev.invoke_frozen_verifier)
        finally:
            ev.sys.executable = original
        self.assertEqual(exc.reason, "verifier-not-invocable")
        self.assertEqual(exc.artifacts, [])       # nothing was ever attempted
        self.assertIn("could not be executed", exc.detail)

    def test_internal_error_is_the_evaluators_own_fault_only(self):
        """Erratum 2: an external subprocess protocol failure is never
        internal-error. A fault raised by the evaluator's own code still is,
        and still produces a result object naming the scenario.
        """
        def explode(request, flags):
            raise RuntimeError("evaluator bug")

        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, _ = self.run_cli(bundle, stub=explode)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "internal-error")
        self.assertIn("evaluator bug", result["nonmeasurement"]["detail"])

    def test_no_abnormal_run_is_ever_reported_as_internal_error(self):
        """The whole point of E2-2, asserted directly."""
        for stub in (StubVerifier(default=(0, b"")),
                     StubVerifier(default=(0, b"{")),
                     StubVerifier(default=(0, b"[]")),
                     StubVerifier(default=(2, None)),
                     StubVerifier(default=(9, None))):
            with self.subTest(stub=stub.default):
                root = tempfile.mkdtemp(prefix="airep interop test ")
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                bundle = write_bundle(root, "IOP-P-DEC",
                                      {"artifacts/a.json": DECISION})
                with self.assertRaises(ev.NonMeasurement) as ctx:
                    ev.evaluate_bundle(Args(bundle), invoke=stub)
                self.assertNotEqual(ctx.exception.reason, "internal-error")


# --------------------------------------------------------------------------
# Erratum 2, E2-3 / AD15-IR-5 -- artifact_path is the total result identity
# --------------------------------------------------------------------------

class ArtifactPathIdentity(BundleCase):
    def test_missing_record_id_reaches_the_frozen_verifier(self):
        """AD15-IR-5's stated consequence: a missing record_id is no longer
        converted into the evaluator's own preflight failure, it reaches the
        stage-0 evaluation it belongs to.
        """
        doc = {k: v for k, v in DECISION.items() if k != "record_id"}
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        stub = StubVerifier(default=(1, None))     # stage-1 invalidity, exit 1
        result = self.evaluate(bundle, stub)
        self.assertEqual(len(stub.calls), 1)       # it WAS invoked
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["level1"], "REJECT")

    def test_artifact_ref_is_null_when_no_usable_record_id_exists(self):
        doc = {k: v for k, v in CONTROL.items() if k != "record_id"}
        bundle = write_bundle(self.root, "IOP-B-CTL", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.assertIsNone(entry["artifact_ref"])
        self.assertEqual(entry["artifact_path"], "artifacts/a.json")

    def test_an_empty_record_id_remains_a_string(self):
        """CORRECTED BY ``AD15-IR-18`` step 5, AGAINST this lane. The projection
        is total over every JSON value and "empty strings remain strings; the
        evaluator does not add a minLength rule absent from the frozen schema".
        This lane previously returned ``null`` for an empty ``record_id``, which
        is exactly the quiet repair step 6 forbids.
        """
        doc = dict(DECISION, record_id="")
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.assertEqual(entry["artifact_ref"],
                         {"record_id": "", "chain_id": "chain-synthetic"})

    def test_a_non_string_record_id_is_not_usable(self):
        doc = dict(DECISION, record_id=17)
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.assertIsNone(entry["artifact_ref"])

    def test_no_record_id_is_ever_synthesized(self):
        """AD15-IR-5: never, for any reason. Neither the result object nor the
        envelope sent to the frozen verifier may gain one.
        """
        doc = {k: v for k, v in DECISION.items() if k != "record_id"}
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        stub = StubVerifier(default=(1, None))
        result = self.evaluate(bundle, stub)
        self.assertNotIn("record_id", stub.calls[0][1]["artifact"])
        self.assertNotIn("record_id", json.dumps(result["artifacts"][0]))

    def test_r_a_still_resolves_by_record_id_not_by_path(self):
        """AD15-IR-5: R-A is unchanged. The manifest path is harness identity
        only and never participates in reference resolution -- so a reference
        naming a bundle PATH resolves to nothing.
        """
        arts = four_artifacts(
            control={"decision_ref": {"record_id": "artifacts/decision.json"}})
        bundle = write_bundle(self.root, "IOP-R-XREF", arts)
        result = self.evaluate(bundle)
        self.assertEqual(result["predicates"]["R_A"], "FAIL")

    def test_multi_artifact_bundle_without_record_id_reaches_stage_0(self):
        """``AD15-IR-6`` SUPERSEDES this lane's pre-erratum resolution, which
        failed such a bundle closed as ``bundle-shape-invalid`` because contract
        5.1 then ordered ``related_artifacts`` by ``record_id``. The envelope now
        orders on ``artifact_path``, so it is defined, and the artifact must
        reach the frozen verifier rather than become a preflight failure.
        """
        arts = four_artifacts()
        del arts["artifacts/effect.json"]["record_id"]
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)             # no NonMeasurement
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(len(stub.calls), 4)
        entry = [e for e in result["artifacts"]
                 if e["artifact_path"] == "artifacts/effect.json"][0]
        # AD15-IR-18 Source A: on the accepted exit-0 path the emitted
        # `artifact_ref` is the VERDICT's, copied verbatim -- so what this case
        # measures is that the artifact REACHED stage 0 at all. The projection
        # over the artifact itself is null, and is asserted directly.
        self.assertIsNone(
            ev.artifact_ref_from_artifact(arts["artifacts/effect.json"]))
        self.assertEqual(entry["verifier_exit_code"], 0)
        self.assertTrue(entry["request_envelope_digest"].startswith("sha256:"))

    def test_a_duplicate_record_id_is_r_a_s_business_not_a_preflight_rule(self):
        """Ruling ``AD15-IR-7`` (E4-4). CONFIRMATION, not a fix: the preflight
        gate was already removed under A6, so this passes against the
        pre-erratum source too. E4-4 makes the removal contract-backed rather
        than inferred; the test binds it so a reinstated gate fails.

        Contract 5 pins the treatment of
        multiple matches: "more than one match is ambiguous and fails closed. An
        evaluator MUST NOT pick one." A preflight uniqueness rule would make
        that rule unreachable, converting a genuine reconciliation finding into
        the evaluator's own refusal, and ``bundle-shape-invalid`` (8.2.2) is
        confined to artifact count, family composition and operator-input
        composition -- none of which this is.
        """
        arts = four_artifacts(execution={"record_id": "a-decision"})
        bundle = write_bundle(self.root, "IOP-R-XREF", arts)
        result = self.evaluate(bundle)                   # measured, not refused
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(result["predicates"]["R_A"], "FAIL")
        self.assertEqual(result["level1"], "RECONCILIATION_MISMATCH")

    def test_duplicate_semantic_ids_reach_frozen_stage_evaluation(self):
        """``AD15-IR-7``'s operative consequence, asserted on the frozen-verifier
        seam rather than only on the verdict: all four artifacts are SUBMITTED.
        A bundle-wide preflight gate would refuse before any invocation, so this
        assertion is what distinguishes "no gate" from "a gate that happens to
        produce the same Level-1 value".
        """
        arts = four_artifacts(execution={"record_id": "a-decision"})
        bundle = write_bundle(self.root, "IOP-R-XREF", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)
        self.assertEqual(len(stub.calls), 4)
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertEqual(sorted(c[0] for c in stub.calls),
                         ["a-decision", "a-decision", "b-control", "d-effect"])

    def test_a_duplicate_chain_id_record_id_pair_is_not_a_preflight_gate_either(self):
        """``AD15-IR-7`` names duplicate ``record_id`` AND duplicate
        ``(chain_id, record_id)``. Every synthetic artifact here shares one
        ``chain_id``, so this pair is duplicated too, and it still reaches
        frozen evaluation. Frozen ``R-10`` binds the BATCH verifier's own
        emitted verdict set; this evaluator submits each artifact as a SEPARATE
        request, so that invariant does not generalize into a bundle rule.
        """
        arts = four_artifacts(execution={"record_id": "a-decision",
                                         "chain_id": "chain-synthetic"})
        decision = arts["artifacts/decision.json"]
        self.assertEqual(decision["chain_id"], "chain-synthetic")
        bundle = write_bundle(self.root, "IOP-R-XREF", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)
        self.assertEqual(result["measurement_status"], "MEASURED")
        self.assertEqual(len(stub.calls), 4)
        for _, envelope, _ in stub.calls:               # one request each
            self.assertIsInstance(envelope["artifact"], dict)
            self.assertEqual(len(envelope["related_artifacts"]), 3)

    def test_no_record_id_is_synthesized_for_a_duplicate(self):
        """The evaluator never picks one and never synthesizes an ID: the two
        colliding artifacts are submitted with their own bytes, unaltered.
        """
        arts = four_artifacts(execution={"record_id": "a-decision"})
        bundle = write_bundle(self.root, "IOP-R-XREF", arts)
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        colliding = [e for rid, e, _ in stub.calls if rid == "a-decision"]
        self.assertEqual(len(colliding), 2)
        types = sorted(e["artifact"]["artifact_type"] for e in colliding)
        self.assertEqual(types, ["decision", "execution"])

    def test_withheld_reasons_are_identified_by_artifact_path(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   witnessed_withheld=["head-witness-absent"]))})
        entry = self.evaluate(bundle, stub)["withheld_reasons"][0]
        self.assertEqual(entry["artifact_path"], "artifacts/a.json")

    def test_ordering_is_stable_under_manifest_path_renaming(self):
        """Determinism (8.4) now keys on artifact_path, so renaming the files
        reorders artifacts[] -- and the order still matches the paths.
        """
        arts = {
            "artifacts/z.json": DECISION,
            "artifacts/y.json": CONTROL,
            "artifacts/x.json": EXECUTION,
            "artifacts/w.json": EFFECT,
        }
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        paths = [e["artifact_path"] for e in self.evaluate(bundle)["artifacts"]]
        self.assertEqual(paths, ["artifacts/w.json", "artifacts/x.json",
                                 "artifacts/y.json", "artifacts/z.json"])


# --------------------------------------------------------------------------
# Envelope acceptance and output encoding
# --------------------------------------------------------------------------

class EnvelopeIsAcceptedByTheFrozenVerifier(BundleCase):
    """Contract 7.2 warns that a malformed REQUEST and a malformed ARTIFACT both
    exit 1: "without this pin, an evaluator that built a bad envelope would
    score its own bug as a successful detection".

    Observing exit 1 therefore proves nothing on its own. This asserts the
    envelope is structurally ACCEPTED -- that the frozen verifier got past
    request parsing to artifact evaluation. stderr is read here only as TEST
    evidence; the evaluator itself never parses it (contract 8.3).
    """

    def test_the_frozen_verifier_does_not_reject_our_request_envelope(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, err = self.run_cli(bundle)          # real frozen subprocess
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["artifacts"][0]["verifier_exit_code"], 1)
        # Re-run the frozen verifier by hand on the same envelope to read why.
        artifacts = [ev.Artifact("artifacts/a.json", DECISION)]
        request = ev.envelope_bytes(ev.build_envelope(artifacts[0], artifacts))
        rc, stdout, stderr = ev.invoke_frozen_verifier(request, [])
        text = (stderr + stdout).decode("utf-8", "replace").lower()
        for envelope_complaint in ("unknown member", "unparseable", "unreadable",
                                   "request envelope", "invalid request"):
            self.assertNotIn(envelope_complaint, text,
                             "frozen verifier rejected the ENVELOPE, not the "
                             "artifact: %s" % text[:400])
        self.assertIn("schema", text)   # it reached artifact schema validation


class OutputEncoding(BundleCase):
    def test_a_non_ascii_record_id_survives_a_non_utf8_stdout_locale(self):
        """Frozen contract 2: record_id / chain_id are free-form core strings
        that MAY be non-ASCII. Writing the result through a non-UTF-8 text
        stdout used to raise UnicodeEncodeError AFTER identity was established,
        leaving exit 1 with empty stdout -- which contract 8.5 forbids once
        identity exists -- and made contract-8.4 determinism depend on locale.
        """
        doc = dict(DECISION, record_id="a-decisiön")
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": doc})
        script = (
            "import json,sys;"
            "sys.path.insert(0, %r);"
            "import interop_eval as ev;"
            "sys.exit(ev.main(['--bundle', %r]))"
            % (os.path.dirname(os.path.abspath(ev.__file__)), bundle))
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        proc = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, env=env)
        self.assertEqual(proc.returncode, 3, proc.stderr[:400])
        result = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["artifacts"][0]["artifact_ref"]["record_id"],
                         "a-decisiön")


# --------------------------------------------------------------------------
# Erratum 3, E3-2 -- the four filesystem reasons are bounded exactly
# --------------------------------------------------------------------------

class FilesystemReasonBoundary(BundleCase):
    """Missing, unreadable, unparseable and digest-mismatched are FOUR distinct
    reasons over the same listed file. Collapsing any pair loses the distinction
    a reader needs to know whether the bundle is incomplete, the medium is
    faulty, or the content is wrong.

    Each case below differs from the others in exactly one respect, so the four
    assertions genuinely discriminate rather than merely co-occurring.
    """

    def one_artifact(self, **kwargs):
        return write_bundle(self.root, "IOP-P-DEC",
                            {"artifacts/d.json": DECISION}, **kwargs)

    def test_absent_from_disk_is_bundle_file_missing(self):
        exc = self.nonmeasurement(
            self.one_artifact(drop_from_disk=("artifacts/d.json",)))
        self.assertEqual(exc.reason, "bundle-file-missing")

    def test_present_but_unreadable_is_bundle_file_unreadable(self):
        """The row Erratum 3 added: the file IS there and IS a permitted regular
        file, so nothing is missing -- the bytes simply cannot be read. The
        pre-erratum code reported `bundle-file-missing` here, which said
        something false about the bundle.
        """
        if os.geteuid() == 0:
            self.skipTest("running as root: mode bits do not deny a read")
        bundle = self.one_artifact()
        target = os.path.join(bundle, "artifacts", "d.json")
        os.chmod(target, 0)
        self.addCleanup(os.chmod, target, 0o600)
        try:
            with open(target, "rb"):
                self.skipTest("this filesystem does not enforce mode bits")
        except PermissionError:
            pass
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-file-unreadable")
        self.assertEqual(exc.status, "ERROR")
        self.assertIn("artifacts/d.json", exc.detail)

    def test_read_error_that_is_definitely_enoent_stays_missing(self):
        """The boundary is on the errno, not on which call failed: a definite
        ENOENT at read time is still `bundle-file-missing`.
        """
        bundle = self.one_artifact()
        original = ev.read_bundle_file
        self.addCleanup(setattr, ev, "read_bundle_file", original)
        ev.read_bundle_file = lambda path: (_ for _ in ()).throw(
            OSError(errno.ENOENT, "No such file or directory", path))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-file-missing")

    def test_io_error_at_read_time_is_unreadable_not_missing(self):
        """Deterministic counterpart to the chmod case, so the discrimination
        does not depend on filesystem permissions being enforced.
        """
        bundle = self.one_artifact()
        original = ev.read_bundle_file
        self.addCleanup(setattr, ev, "read_bundle_file", original)
        ev.read_bundle_file = lambda path: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", path))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-file-unreadable")

    def test_read_but_unparseable_is_bundle_json_invalid(self):
        bundle = write_bundle(
            self.root, "IOP-P-DEC", {},
            raw_files={"artifacts/d.json": (b"{ not json", "artifact")})
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-json-invalid")

    def test_read_but_digest_disagrees_is_manifest_digest_mismatch(self):
        def rewrite(manifest):
            manifest["files"][0]["sha256"] = "0" * 64
            return manifest
        exc = self.nonmeasurement(self.one_artifact(manifest_overrides=rewrite))
        self.assertEqual(exc.reason, "manifest-digest-mismatch")

    def test_the_four_reasons_are_pairwise_distinct(self):
        """Stated as one assertion so a future collapse cannot pass silently."""
        self.assertEqual(
            len({"bundle-file-missing", "bundle-file-unreadable",
                 "bundle-json-invalid", "manifest-digest-mismatch"}), 4)
        for reason in ("bundle-file-missing", "bundle-file-unreadable",
                       "bundle-json-invalid", "manifest-digest-mismatch"):
            self.assertEqual(ev.REASON_STATUS[reason], "ERROR")

    def test_a_wrong_kind_target_is_still_a_layout_violation(self):
        """Erratum 3 did not move this: a files[] entry whose target exists but
        is a directory is `manifest-invalid`, because nothing is missing and
        nothing was unreadable -- the LAYOUT is wrong.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              drop_from_disk=("artifacts/d.json",))
        os.makedirs(os.path.join(bundle, "artifacts", "d.json"))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")


# --------------------------------------------------------------------------
# Erratum 4, E4-3 -- `bundle-directory-unreadable`: the layout could not be
# MEASURED, as distinct from being WRONG
# --------------------------------------------------------------------------

class DirectoryEnumerationBoundary(BundleCase):
    """E4-3. After identity is established, a traversal that cannot complete
    because a directory cannot be enumerated is `bundle-directory-unreadable`,
    NOT `manifest-invalid`. `manifest-invalid` says the layout is WRONG; this
    says the layout could not be MEASURED. The file-level rows are untouched:
    enumeration succeeding but a listed file being absent is still
    `bundle-file-missing`, and a listed regular file whose bytes cannot be read
    is still `bundle-file-unreadable`.

    Each case below differs from the others in exactly one respect, so the
    assertions genuinely discriminate rather than merely co-occurring.
    """

    def one_artifact(self, **kwargs):
        return write_bundle(self.root, "IOP-P-DEC",
                            {"artifacts/d.json": DECISION}, **kwargs)

    def fresh_artifact(self, name, **kwargs):
        """A one-artifact bundle under its OWN root.

        ``write_bundle`` materializes into ``<root>/bundle`` and reuses it, so
        two cases sharing a root contaminate each other -- an extra file written
        for one case is still on disk for the next and reports as an unlisted
        file. Any test comparing several bundle conditions must isolate them.
        """
        root = os.path.join(self.root, name)
        os.makedirs(root)
        return write_bundle(root, "IOP-P-DEC",
                            {"artifacts/d.json": DECISION}, **kwargs)

    def deny_enumeration(self, errno_value=errno.EACCES):
        """Replace the enumeration seam so the boundary is exercised
        deterministically rather than through filesystem permissions, which are
        not portable.
        """
        original = ev.scan_directory
        self.addCleanup(setattr, ev, "scan_directory", original)
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno_value, os.strerror(errno_value), path))

    def test_enumeration_failure_is_bundle_directory_unreadable(self):
        self.deny_enumeration()
        exc = self.nonmeasurement(self.one_artifact())
        self.assertEqual(exc.reason, "bundle-directory-unreadable")
        self.assertEqual(exc.status, "ERROR")

    def test_an_io_error_while_enumerating_is_the_same_reason(self):
        """"Permission, I/O, any failure" -- the reason is about the inability
        to enumerate, not about which errno produced it.
        """
        self.deny_enumeration(errno.EIO)
        self.assertEqual(self.nonmeasurement(self.one_artifact()).reason,
                         "bundle-directory-unreadable")

    def test_an_unenumerable_subdirectory_is_the_same_reason(self):
        """Permission-based counterpart, skipped where mode bits are not
        enforced. The failure is one level down, so identity and the root
        listing are both fine and only the subtree cannot be measured.
        """
        if os.geteuid() == 0:
            self.skipTest("running as root: mode bits do not deny enumeration")
        bundle = self.one_artifact()
        sub = os.path.join(bundle, "artifacts")
        os.chmod(sub, 0)
        self.addCleanup(os.chmod, sub, 0o700)
        try:
            os.listdir(sub)
            self.skipTest("this filesystem does not enforce mode bits")
        except PermissionError:
            pass
        self.assertEqual(self.nonmeasurement(bundle).reason,
                         "bundle-directory-unreadable")

    def test_it_is_reported_at_exit_3_with_a_result_object(self):
        """Identity IS established, so the harness is owed a result object
        naming the scenario -- the whole point of keeping this out of exit 1.
        """
        self.deny_enumeration()
        code, out, _ = self.run_cli(self.one_artifact())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "bundle-directory-unreadable")
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])
        self.assertEqual(result["artifacts"], [])       # pre-invocation
        self.assertNotIn("json_pointer", result["nonmeasurement"])

    def test_it_is_distinct_from_manifest_invalid(self):
        """The discrimination E4-3 exists for. A genuine LAYOUT violation --
        here an on-disk file `files[]` does not list -- stays `manifest-invalid`,
        while an unenumerable directory does not.
        """
        layout = self.fresh_artifact(
            "layout", extra_disk_files={"artifacts/stray.json": b"{}"})
        self.assertEqual(self.nonmeasurement(layout).reason, "manifest-invalid")
        self.deny_enumeration()
        self.assertEqual(self.nonmeasurement(self.fresh_artifact("denied")).reason,
                         "bundle-directory-unreadable")

    def test_it_is_distinct_from_the_two_listed_file_reasons(self):
        """Enumeration SUCCEEDING but a listed file being absent stays
        `bundle-file-missing`; a listed regular file whose bytes cannot be read
        stays `bundle-file-unreadable`. Neither is displaced by E4-3.
        """
        missing = self.fresh_artifact("missing",
                                      drop_from_disk=("artifacts/d.json",))
        self.assertEqual(self.nonmeasurement(missing).reason, "bundle-file-missing")

        unreadable = self.fresh_artifact("unreadable")
        original = ev.read_bundle_file
        self.addCleanup(setattr, ev, "read_bundle_file", original)
        ev.read_bundle_file = lambda path: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", path))
        self.assertEqual(self.nonmeasurement(unreadable).reason,
                         "bundle-file-unreadable")

    def test_the_four_reasons_are_observed_pairwise_distinct(self):
        """Four DIFFERENT bundle conditions must yield four DIFFERENT reasons.

        Asserting that four string literals differ would be true whatever the
        evaluator did; these four values are read back out of four evaluations,
        so a collapse in the mapping fails here.
        """
        observed = {}

        layout = self.fresh_artifact(
            "c1", extra_disk_files={"artifacts/stray.json": b"{}"})
        observed["layout wrong"] = self.nonmeasurement(layout).reason

        missing = self.fresh_artifact("c2", drop_from_disk=("artifacts/d.json",))
        observed["listed file absent"] = self.nonmeasurement(missing).reason

        unreadable = self.fresh_artifact("c3")
        original_read = ev.read_bundle_file
        self.addCleanup(setattr, ev, "read_bundle_file", original_read)
        ev.read_bundle_file = lambda path: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", path))
        observed["listed file unreadable"] = self.nonmeasurement(unreadable).reason
        ev.read_bundle_file = original_read

        self.deny_enumeration()
        observed["directory unenumerable"] = self.nonmeasurement(
            self.fresh_artifact("c4")).reason

        self.assertEqual(observed, {
            "layout wrong": "manifest-invalid",
            "listed file absent": "bundle-file-missing",
            "listed file unreadable": "bundle-file-unreadable",
            "directory unenumerable": "bundle-directory-unreadable"})
        self.assertEqual(len(set(observed.values())), 4)
        self.assertEqual(ev.REASON_STATUS["bundle-directory-unreadable"], "ERROR")

    def test_an_undeterminable_entry_kind_is_not_this_reason(self):
        """E5-3 CLOSES recorded ambiguity A14 AGAINST this lane's inference.

        Enumeration SUCCEEDS and yields an entry whose KIND then cannot be
        determined. This lane used to report `bundle-directory-unreadable` -- an
        inference from E4-3's faulty-medium rationale -- which is now wrong:
        enumeration succeeded, so that reason says something false. The reason is
        `bundle-entry-uninspectable`, asserted in full in `EntryInspectability`.
        """
        bundle = self.one_artifact()
        original = ev.entry_kind
        self.addCleanup(setattr, ev, "entry_kind", original)
        ev.entry_kind = lambda entry: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", entry.path))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-entry-uninspectable")
        self.assertNotEqual(exc.reason, "bundle-directory-unreadable")

    def test_no_frozen_verifier_is_invoked(self):
        """Traversal is preflight, and contract 8.3.1 forbids any invocation
        until the whole preflight has passed.
        """
        self.deny_enumeration()
        stub = StubVerifier()
        with self.assertRaises(ev.NonMeasurement):
            self.evaluate(self.one_artifact(), stub)
        self.assertEqual(stub.calls, [])


# --------------------------------------------------------------------------
# Erratum 3, E3-3 -- no manifest discovery is performed
# --------------------------------------------------------------------------

class NoManifestDiscovery(BundleCase):
    def build_without_root_manifest(self, other_name):
        """A bundle whose only manifest sits under some OTHER name or location."""
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        root_manifest = os.path.join(bundle, "manifest.json")
        moved = os.path.join(bundle, *other_name.split("/"))
        os.makedirs(os.path.dirname(moved), exist_ok=True)
        os.rename(root_manifest, moved)
        return bundle

    def test_wrongly_named_manifest_alone_is_exit_1_with_no_result_object(self):
        """E3-3: identity is not established, so there is no scenario to name.
        It is NOT `manifest-invalid`, which would require the identity the
        evaluator does not have.
        """
        bundle = self.build_without_root_manifest("bundle_manifest.json")
        code, out, err = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(err.strip())          # diagnostics go to stderr only

    def test_misplaced_manifest_alone_is_exit_1_with_no_result_object(self):
        bundle = self.build_without_root_manifest("meta/manifest.json")
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_no_other_name_or_location_is_ever_opened(self):
        """"The evaluator does not search for or accept any other name or
        location." Asserted by observation, not by reading the source: every
        path the evaluator opens is recorded, and only the bundle root
        manifest.json is among them.
        """
        bundle = self.build_without_root_manifest("bundle_manifest.json")
        opened = []
        import builtins
        original = builtins.open
        def recording_open(file, *a, **kw):
            opened.append(str(file))
            return original(file, *a, **kw)
        builtins.open = recording_open
        try:
            code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        finally:
            builtins.open = original
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        under_bundle = [p for p in opened if p.startswith(bundle)]
        self.assertEqual(under_bundle, [os.path.join(bundle, "manifest.json")])

    def test_a_second_manifest_beside_a_valid_root_one_is_an_ordinary_file(self):
        """E3-3's other half: a wrongly-named file BESIDE a valid root manifest
        needs no special rule. It is an unlisted regular file, so the ordinary
        layout rules make it `manifest-invalid` at exit 3 -- identity IS
        established, so a result object naming the scenario is owed.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              extra_disk_files={"MANIFEST.json": b"{}"})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")


# --------------------------------------------------------------------------
# Erratum 3, E3-4 -- --help is a CLI meta-action, not an evaluation
# --------------------------------------------------------------------------

class HelpMetaAction(BundleCase):
    def run_argv(self, argv):
        """Drive main() with a verbatim argv, catching argparse's SystemExit."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = ev.main(list(argv))
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_help_exits_0_with_help_text_and_no_result_object(self):
        """E4-1 makes help CONTENT a non-requirement, so nothing here asserts
        what the screen says -- only that something human-readable is written
        and that it is not a result object.
        """
        code, out, _ = self.run_argv(["--help"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())                     # human-readable text
        with self.assertRaises(ValueError):              # NOT a result object
            json.loads(out)

    def test_help_does_not_require_bundle(self):
        code, out, err = self.run_argv(["--help"])
        self.assertEqual(code, 0)
        self.assertNotIn("--bundle is required", err)
        self.assertNotIn("measurement_status", out)

    def test_the_exit_0_invariant_still_binds_every_evaluation_invocation(self):
        """The carve-out is not a general licence for exit 0 without a result
        object: an EVALUATION that exits 0 still owes exactly one.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["measurement_status"], "MEASURED")

    def test_every_other_usage_error_is_still_exit_2(self):
        for argv in (["--not-a-flag"], ["--bundle"], [], ["-h"], ["--hel"],
                     ["--help=1"]):
            code, out, _ = self.run_argv(argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "", argv)

    # -- E4-1: the carve-out is ONE EXACT SINGLE-TOKEN INVOCATION -------------

    def test_the_carve_out_is_one_exact_single_token_invocation(self):
        """E4-1 supersedes E3-4's "exactly one flag wide", which was ambiguous
        enough that two lanes measurably diverged on `-h`. The three
        discriminations are asserted together so no future widening can pass by
        satisfying one of them.
        """
        self.assertEqual(self.run_argv(["--help"])[0], 0)          # the lone one
        self.assertEqual(self.run_argv(["-h"])[0], 2)              # not an alias
        self.assertEqual(self.run_argv(["--help", "--bundle", "x"])[0], 2)

    def test_h_is_not_an_alias(self):
        """CONFIRMATION, not a fix: this lane already refused `-h`, so the case
        passes against the pre-erratum source. E4-1 settles which of the two
        defensible readings is correct -- the other lane read the same sentence
        the other way and exited 0 -- so the behaviour is now pinned rather than
        chosen. `-h` is a CLI usage error: exit 2, NO result object, and no help
        screen either, since it is not the meta-action.
        """
        code, out, _ = self.run_argv(["-h"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_help_with_any_other_argument_is_a_usage_error(self):
        """Only the LONE help invocation is carved out. Position is irrelevant:
        `--help` leading, trailing or beside a valid flag is exit 2 with empty
        stdout in every case.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        for argv in (["--help", "--bundle", bundle],
                     ["--bundle", bundle, "--help"],
                     ["--help", "--help"],
                     ["--help", "--not-a-flag"],
                     ["--help", "extra"]):
            code, out, _ = self.run_argv(argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "", argv)

    def test_help_text_content_is_not_a_parity_requirement(self):
        """E4-1 pins that the lanes may print different help and that nothing
        compares it. Asserted as an explicit non-requirement so a later author
        does not add a content or byte-length pin by reflex; the only property
        that binds is that SOMETHING human-readable is written and that it is
        not a result object.
        """
        code, out, _ = self.run_argv(["--help"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())
        with self.assertRaises(ValueError):
            json.loads(out)


# --------------------------------------------------------------------------
# Erratum 5, E5-3 -- `bundle-entry-uninspectable`
# --------------------------------------------------------------------------

class EntryInspectability(BundleCase):
    """The last gap in the filesystem taxonomy, and the reason it is its own row.

    Contract 8.2.2's boundary table is ordered by WHAT WAS ACTUALLY LEARNED:

      * entry name obtained, kind inspection could not complete
                                                -> `bundle-entry-uninspectable`
      * kind determined: symlink / forbidden object       -> `manifest-invalid`
      * kind determined: directory, cannot enumerate
                                                -> `bundle-directory-unreadable`
      * kind determined: regular file, bytes unreadable  -> `bundle-file-unreadable`

    Each row says only what was learned and stops there. Reporting a layout
    violation when the layout could not be inspected is the same error as
    reporting a missing file when the medium was merely unreadable.
    """

    def bundle_at(self, name):
        root = os.path.join(self.root, name)
        os.makedirs(root)
        return write_bundle(root, "IOP-P-DEC", {"artifacts/d.json": DECISION})

    def deny_kind(self, errno_value=errno.EIO):
        original = ev.entry_kind
        self.addCleanup(setattr, ev, "entry_kind", original)
        ev.entry_kind = lambda entry: (_ for _ in ()).throw(
            OSError(errno_value, os.strerror(errno_value), entry.path))

    def test_an_uninspectable_entry_has_its_own_reason(self):
        self.deny_kind()
        exc = self.nonmeasurement(self.bundle_at("k1"))
        self.assertEqual(exc.reason, "bundle-entry-uninspectable")
        self.assertEqual(exc.status, "ERROR")

    def test_it_is_reported_at_exit_3_with_an_empty_artifacts_array(self):
        self.deny_kind()
        code, out, _ = self.run_cli(self.bundle_at("k2"))
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "bundle-entry-uninspectable")
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])
        self.assertEqual(result["artifacts"], [])      # pre-invocation
        self.assertNotIn("json_pointer", result["nonmeasurement"])

    def test_the_permission_errno_does_not_change_the_reason(self):
        self.deny_kind(errno.EACCES)
        self.assertEqual(self.nonmeasurement(self.bundle_at("k3")).reason,
                         "bundle-entry-uninspectable")

    def test_no_frozen_verifier_is_invoked(self):
        self.deny_kind()
        stub = StubVerifier()
        with self.assertRaises(ev.NonMeasurement):
            self.evaluate(self.bundle_at("k4"), stub)
        self.assertEqual(stub.calls, [])

    def test_the_five_filesystem_reasons_are_observed_pairwise_distinct(self):
        """Five DIFFERENT bundle conditions must yield five DIFFERENT reasons.

        Read back out of five evaluations, not asserted between five literals: a
        collapse anywhere in the mapping fails here.
        """
        observed = {}

        observed["layout wrong"] = self.nonmeasurement(
            self.bundle_at_with(
                "d1", extra_disk_files={"artifacts/stray.json": b"{}"})).reason

        observed["listed file absent"] = self.nonmeasurement(
            self.bundle_at_with("d2", drop_from_disk=("artifacts/d.json",))).reason

        unreadable = self.bundle_at("d3")
        original_read = ev.read_bundle_file
        ev.read_bundle_file = lambda path: (_ for _ in ()).throw(
            OSError(errno.EIO, "Input/output error", path))
        try:
            observed["listed file unreadable"] = self.nonmeasurement(unreadable).reason
        finally:
            ev.read_bundle_file = original_read

        original_scan = ev.scan_directory
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno.EACCES, "Permission denied", path))
        try:
            observed["directory unenumerable"] = self.nonmeasurement(
                self.bundle_at("d4")).reason
        finally:
            ev.scan_directory = original_scan

        self.deny_kind()
        observed["entry kind unknown"] = self.nonmeasurement(
            self.bundle_at("d5")).reason

        self.assertEqual(observed, {
            "layout wrong": "manifest-invalid",
            "listed file absent": "bundle-file-missing",
            "listed file unreadable": "bundle-file-unreadable",
            "directory unenumerable": "bundle-directory-unreadable",
            "entry kind unknown": "bundle-entry-uninspectable"})
        self.assertEqual(len(set(observed.values())), 5)

    def bundle_at_with(self, name, **kwargs):
        root = os.path.join(self.root, name)
        os.makedirs(root)
        return write_bundle(root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                            **kwargs)


# --------------------------------------------------------------------------
# Erratum 5, E5-4 -- frozen-identity preflight order, and the two failures
# --------------------------------------------------------------------------

class FrozenIdentityBoundary(BundleCase):
    """`frozen-identity-unreadable` vs `verifier-digest-mismatch`.

    These are DIFFERENT things and the contract keeps them apart: a digest that
    could not be RECOMPUTED cannot be emitted, so `verifier_digests` is `null`;
    a digest that was recomputed and DISAGREES is retained verbatim, because a
    reader needs to see what was actually there. Collapsing the two would either
    fabricate a digest or hide the measured one.
    """

    def one_artifact(self):
        return write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})

    def deny_frozen_read(self, only=None):
        """Make the frozen-identity read fail -- for one named file, or both."""
        original = ev.read_frozen_file
        self.addCleanup(setattr, ev, "read_frozen_file", original)

        def reader(path):
            if only is None or path.endswith(only):
                raise OSError(errno.EACCES, "Permission denied", path)
            return original(path)

        ev.read_frozen_file = reader

    def pin_wrong(self, verifier=None, contract=None):
        """Repin one or both frozen digests to a value the tree cannot match."""
        original = ev.FROZEN_FILES
        self.addCleanup(setattr, ev, "FROZEN_FILES", original)
        ev.FROZEN_FILES = (
            ("class_verifier", ev.frozen_verifier_path,
             verifier or ev.FROZEN_VERIFIER_SHA256),
            ("class_verifier_contract", ev.frozen_contract_path,
             contract or ev.FROZEN_CONTRACT_SHA256),
        )

    # ---- the two failures are not the same thing ---------------------------

    def test_an_unreadable_frozen_verifier_is_frozen_identity_unreadable(self):
        self.deny_frozen_read(only="class_verifier.py")
        exc = self.nonmeasurement(self.one_artifact())
        self.assertEqual(exc.reason, "frozen-identity-unreadable")
        self.assertEqual(exc.status, "ERROR")
        self.assertIsNone(exc.verifier_digests)

    def test_an_unreadable_frozen_contract_is_the_same_reason(self):
        self.deny_frozen_read(only="CLASS_VERIFIER_CONTRACT.md")
        exc = self.nonmeasurement(self.one_artifact())
        self.assertEqual(exc.reason, "frozen-identity-unreadable")
        self.assertIsNone(exc.verifier_digests)

    def test_a_mismatched_frozen_verifier_is_verifier_digest_mismatch(self):
        self.pin_wrong(verifier="0" * 64)
        exc = self.nonmeasurement(self.one_artifact())
        self.assertEqual(exc.reason, "verifier-digest-mismatch")
        self.assertIsNotNone(exc.verifier_digests)

    def test_the_two_reasons_are_observed_distinct_on_the_same_bundle(self):
        """THE discrimination E5-4 exists for. Same bundle, two conditions, two
        reasons and two `verifier_digests` shapes -- read back out of two
        evaluations, so a collapse in either direction fails here.
        """
        observed = {}
        self.pin_wrong(verifier="0" * 64)
        mismatch = self.nonmeasurement(self.one_artifact())
        observed["digest disagrees"] = (mismatch.reason,
                                        mismatch.verifier_digests is None)
        ev.FROZEN_FILES = (
            ("class_verifier", ev.frozen_verifier_path, ev.FROZEN_VERIFIER_SHA256),
            ("class_verifier_contract", ev.frozen_contract_path,
             ev.FROZEN_CONTRACT_SHA256),
        )
        self.deny_frozen_read()
        unreadable = self.nonmeasurement(self.one_artifact())
        observed["file unreadable"] = (unreadable.reason,
                                       unreadable.verifier_digests is None)

        self.assertEqual(observed, {
            "digest disagrees": ("verifier-digest-mismatch", False),
            "file unreadable": ("frozen-identity-unreadable", True)})
        self.assertNotEqual(observed["digest disagrees"][0],
                            observed["file unreadable"][0])

    # ---- verifier_digests arity and content --------------------------------

    def test_verifier_digests_is_null_only_for_the_unreadable_reason(self):
        self.deny_frozen_read()
        code, out, _ = self.run_cli(self.one_artifact())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "frozen-identity-unreadable")
        self.assertIsNone(result["verifier_digests"])
        self.assertEqual(result["artifacts"], [])
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")

    def test_a_mismatch_retains_the_actual_recomputed_two_entry_object(self):
        """Step 5: the ACTUAL recomputed values are retained, never the expected
        ones. Asserted against a freshly hashed tree read, so the test cannot be
        satisfied by echoing the pin back.
        """
        self.pin_wrong(verifier="0" * 64)
        code, out, _ = self.run_cli(self.one_artifact())
        self.assertEqual(code, 3)
        digests = json.loads(out)["verifier_digests"]
        self.assertEqual(set(digests), {"class_verifier", "class_verifier_contract"})
        with open(ev.frozen_verifier_path(), "rb") as handle:
            actual = hexdigest(handle.read())
        self.assertEqual(digests["class_verifier"], "sha256:" + actual)
        self.assertNotEqual(digests["class_verifier"], "sha256:" + "0" * 64)

    def test_a_partially_unreadable_pair_never_yields_a_one_entry_object(self):
        """A15 is CLOSED: the object is exactly two entries or it is null. One
        readable file and one unreadable file used to produce a single entry.
        """
        self.deny_frozen_read(only="CLASS_VERIFIER_CONTRACT.md")
        digests, problem = ev.measure_frozen_digests()
        self.assertIsNone(digests)
        self.assertEqual(problem[0], "frozen-identity-unreadable")

    def test_a_measured_run_carries_exactly_two_recomputed_entries(self):
        result = self.evaluate(self.one_artifact())
        digests = result["verifier_digests"]
        self.assertEqual(len(digests), 2)
        with open(ev.frozen_contract_path(), "rb") as handle:
            self.assertEqual(digests["class_verifier_contract"],
                             "sha256:" + hexdigest(handle.read()))

    # ---- the pinned preflight order ----------------------------------------

    def test_frozen_identity_precedes_every_other_post_identity_preflight(self):
        """Contract 8.2.1 steps 2 and 6: the frozen identity is read IMMEDIATELY
        after bundle identity, and only THEN does bundle traversal and the
        remaining preflight begin. A bundle that would fail traversal must still
        report the frozen-identity failure, or the order is not the pinned one.
        """
        original = ev.scan_directory
        self.addCleanup(setattr, ev, "scan_directory", original)
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno.EACCES, "Permission denied", path))
        self.deny_frozen_read()
        self.assertEqual(self.nonmeasurement(self.one_artifact()).reason,
                         "frozen-identity-unreadable")

    def test_a_digest_mismatch_also_precedes_traversal(self):
        original = ev.scan_directory
        self.addCleanup(setattr, ev, "scan_directory", original)
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno.EACCES, "Permission denied", path))
        self.pin_wrong(contract="0" * 64)
        self.assertEqual(self.nonmeasurement(self.one_artifact()).reason,
                         "verifier-digest-mismatch")

    def test_a_broken_manifest_does_not_outrank_the_frozen_identity(self):
        """The manifest here violates the pinned encoding, which would be
        `manifest-invalid` on its own. The frozen identity is read first, so the
        frozen reason is what the harness receives.
        """
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              manifest_overrides=lambda m: dict(m, unexpected=True))
        self.assertEqual(self.nonmeasurement(bundle).reason, "manifest-invalid")
        self.deny_frozen_read()
        self.assertEqual(self.nonmeasurement(bundle).reason,
                         "frozen-identity-unreadable")

    def test_the_identity_band_still_outranks_the_frozen_identity(self):
        """The frozen read is post-identity: a bundle with no root manifest is
        still exit 1 with empty stdout, not a frozen-identity result object.
        """
        bundle = self.one_artifact()
        os.remove(os.path.join(bundle, "manifest.json"))
        self.deny_frozen_read()
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_no_frozen_verifier_is_invoked_on_either_failure(self):
        self.deny_frozen_read()
        stub = StubVerifier()
        with self.assertRaises(ev.NonMeasurement):
            self.evaluate(self.one_artifact(), stub)
        self.assertEqual(stub.calls, [])


# --------------------------------------------------------------------------
# Erratum 5, E5-1 -- ruling AD15-IR-8, identity establishment is monotonic
# --------------------------------------------------------------------------

class MonotonicIdentity(BundleCase):
    """Once the root manifest has been read, parsed and has yielded a registered
    `scenario_id`, identity IS established, and no later filesystem, traversal or
    preflight failure can retroactively unestablish it.

    E4-2 lists "the bundle root itself cannot be accessed" as an exit-1 identity
    condition and E4-3 makes an unenumerable directory after identity
    `bundle-directory-unreadable` at exit 3. On POSIX those meet in exactly one
    place, and the contract pins the worked case rather than leaving it inferred.
    """

    def one_artifact(self):
        return write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION})

    def test_the_0o111_worked_case_is_exit_3_not_exit_1(self):
        """Bundle directory mode 0o111: traverse permission lets
        `open(DIR/manifest.json)` succeed while `readdir(DIR)` fails EACCES.
        """
        if os.geteuid() == 0:
            self.skipTest("running as root: mode bits do not deny enumeration")
        bundle = self.one_artifact()
        os.chmod(bundle, 0o111)
        self.addCleanup(os.chmod, bundle, 0o700)
        try:
            os.listdir(bundle)
            self.skipTest("this filesystem does not enforce mode bits")
        except PermissionError:
            pass
        # The precondition the ruling turns on: the direct read still succeeds.
        with open(os.path.join(bundle, "manifest.json"), "rb") as handle:
            self.assertTrue(handle.read())
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "bundle-directory-unreadable")

    def test_identity_is_read_directly_and_never_by_enumeration(self):
        """The structural reason the 0o111 case lands where it does: nothing
        enumerates the bundle before identity exists. Denying enumeration
        outright still produces a result object NAMING the scenario.
        """
        original = ev.scan_directory
        self.addCleanup(setattr, ev, "scan_directory", original)
        ev.scan_directory = lambda path: (_ for _ in ()).throw(
            OSError(errno.EACCES, "Permission denied", path))
        code, out, _ = self.run_cli(self.one_artifact())
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["scenario_id"], "IOP-P-DEC")

    def test_every_post_identity_filesystem_failure_stays_at_exit_3(self):
        """Monotonicity, asserted over the whole post-identity filesystem
        surface rather than on one representative: none of these may fall back
        into the exit-1 band once a scenario_id has been obtained.
        """
        cases = {}

        def fresh(name, **kwargs):
            root = os.path.join(self.root, name)
            os.makedirs(root)
            return write_bundle(root, "IOP-P-DEC",
                                {"artifacts/d.json": DECISION}, **kwargs)

        cases["listed file absent"] = (
            fresh("m1", drop_from_disk=("artifacts/d.json",)), None)

        original_scan = ev.scan_directory
        original_kind = ev.entry_kind
        original_read = ev.read_bundle_file
        self.addCleanup(setattr, ev, "scan_directory", original_scan)
        self.addCleanup(setattr, ev, "entry_kind", original_kind)
        self.addCleanup(setattr, ev, "read_bundle_file", original_read)

        seams = [
            ("directory unenumerable", "scan_directory",
             lambda path: (_ for _ in ()).throw(
                 OSError(errno.EACCES, "Permission denied", path))),
            ("entry kind unknown", "entry_kind",
             lambda entry: (_ for _ in ()).throw(
                 OSError(errno.EIO, "Input/output error", entry.path))),
            ("listed file unreadable", "read_bundle_file",
             lambda path: (_ for _ in ()).throw(
                 OSError(errno.EIO, "Input/output error", path))),
        ]
        for index, (label, attr, seam) in enumerate(seams):
            cases[label] = (fresh("m%d" % (index + 2)), (attr, seam))

        for label, (bundle, seam) in cases.items():
            if seam is not None:
                setattr(ev, seam[0], seam[1])
            try:
                code, out, _ = self.run_cli(bundle)
            finally:
                if seam is not None:
                    setattr(ev, seam[0], {"scan_directory": original_scan,
                                          "entry_kind": original_kind,
                                          "read_bundle_file": original_read}[seam[0]])
            with self.subTest(condition=label):
                self.assertEqual(code, 3, label)
                self.assertEqual(json.loads(out)["scenario_id"], "IOP-P-DEC")


# --------------------------------------------------------------------------
# Erratum 5, E5-5 -- contract 7.1 is SCENARIO-INDEPENDENT
# --------------------------------------------------------------------------

class AuthenticatedWithheldIsScenarioIndependent(BundleCase):
    """The erratum removed an expected-tier oracle from the rule, so a test that
    still encodes the oracle is not a test of the new rule.

    The rule under test: ANY emitted frozen verdict carrying a non-empty
    `authenticated_withheld` channel makes the scenario MEASUREMENT_INVALID,
    REGARDLESS OF SCENARIO ID. The assertion below therefore ranges over ALL
    TWELVE registered ids -- an implementation that consulted any per-scenario
    expected-tier table would have to exempt at least one of them, and would
    fail here whichever partition it chose.
    """

    WITHHELD = ["producer-binding-absent"]

    def bundle_for(self, scenario_id, name):
        root = os.path.join(self.root, name)
        os.makedirs(root)
        if scenario_id in ev.SINGLE_ARTIFACT_FAMILY:
            family = ev.SINGLE_ARTIFACT_FAMILY[scenario_id]
            doc = {"decision": DECISION, "control": CONTROL,
                   "execution": EXECUTION, "effect": EFFECT}[family]
            return write_bundle(root, scenario_id, {"artifacts/a.json": doc})
        return write_bundle(root, scenario_id, four_artifacts())

    def withholding_stub(self, only_record=None):
        """A stub that withholds on every artifact, or on one named artifact."""

        class Withholding(StubVerifier):
            def __call__(self, request, flags):
                envelope = json.loads(request.decode("utf-8"))
                record_id = envelope["artifact"].get("record_id")
                self.calls.append((record_id, envelope, list(flags)))
                withheld = (AuthenticatedWithheldIsScenarioIndependent.WITHHELD
                            if only_record in (None, record_id) else [])
                body = verdict(record_id, klass="AIREP-Core",
                               auth_withheld=withheld)
                return 0, json.dumps(body).encode("utf-8"), b""

        return Withholding()

    def test_all_twelve_scenarios_are_measurement_invalid(self):
        seen = set()
        for index, scenario_id in enumerate(sorted(ev.SCENARIO_IDS)):
            with self.subTest(scenario_id=scenario_id):
                bundle = self.bundle_for(scenario_id, "w%d" % index)
                exc = self.nonmeasurement(bundle, self.withholding_stub())
                self.assertEqual(exc.reason, "authenticated-withheld")
                self.assertEqual(exc.status, "MEASUREMENT_INVALID")
                seen.add(scenario_id)
        self.assertEqual(seen, set(ev.SCENARIO_IDS))
        self.assertEqual(len(seen), 12)

    def test_no_level1_verdict_is_emitted_for_any_of_the_twelve(self):
        for index, scenario_id in enumerate(sorted(ev.SCENARIO_IDS)):
            with self.subTest(scenario_id=scenario_id):
                bundle = self.bundle_for(scenario_id, "x%d" % index)
                original = ev.invoke_frozen_verifier
                ev.invoke_frozen_verifier = self.withholding_stub()
                try:
                    code, out, _ = self.run_cli(bundle)
                finally:
                    ev.invoke_frozen_verifier = original
                self.assertEqual(code, 3)
                result = json.loads(out)
                self.assertEqual(result["measurement_status"],
                                 "MEASUREMENT_INVALID")
                self.assertIsNone(result["level1"])
                self.assertIsNone(result["predicates"])

    def test_a_single_withholding_artifact_invalidates_a_four_artifact_bundle(self):
        """The channel is per-verdict, not per-bundle: one withheld artifact out
        of four is enough, on a scenario whose Level-1 expectation is ACCEPT.
        """
        bundle = self.bundle_for("IOP-R-CLEAN", "one")
        exc = self.nonmeasurement(bundle, self.withholding_stub("d-effect"))
        self.assertEqual(exc.reason, "authenticated-withheld")
        self.assertEqual([w["artifact_path"] for w in exc.withheld_reasons],
                         ["artifacts/effect.json"])

    def test_the_withheld_reasons_are_reported_verbatim(self):
        bundle = self.bundle_for("IOP-B-EXE", "verbatim")
        exc = self.nonmeasurement(bundle, self.withholding_stub())
        # AD15-IR-16: verbatim, one entry per reason, never re-worded.
        self.assertEqual([w["reason"] for w in exc.withheld_reasons],
                         sorted(self.WITHHELD))
        for entry in exc.withheld_reasons:
            self.assertEqual(set(entry),
                             {"artifact_path", "channel", "reason"})
            self.assertEqual(entry["channel"], "authenticated_withheld")

    def test_the_evaluator_carries_no_expected_tier_table(self):
        """The structural half of E5-5, asserted rather than assumed: no
        per-scenario expected-outcome map exists in the module. `map_level1`
        takes only measured inputs, and the only scenario-keyed tables are the
        bundle-family composition (contract 5) and the contract-7.2 exit-1
        allowance -- neither of which is an expected TIER or an expected Level-1.
        """
        scenario_keyed = [name for name, value in vars(ev).items()
                          if isinstance(value, dict)
                          and set(value).issubset(ev.SCENARIO_IDS)
                          and value]
        self.assertEqual(scenario_keyed, ["SINGLE_ARTIFACT_FAMILY"])
        self.assertEqual(set(ev.SINGLE_ARTIFACT_FAMILY.values()),
                         {"decision", "control", "execution", "effect"})
        for level1 in (ev.ACCEPT, ev.REJECT, ev.RECONCILIATION_MISMATCH,
                       ev.INDEPENDENCE_NOT_ESTABLISHED):
            self.assertNotIn(level1, ev.SINGLE_ARTIFACT_FAMILY.values())


# --------------------------------------------------------------------------
# Erratum 6, E6-1 -- ruling `AD15-IR-9`: entry kind requires authoritative
# no-follow metadata. THE ONE BEHAVIOURAL CHANGE IN THIS LANE.
# --------------------------------------------------------------------------

class EntryKindNoFollowLookup(BundleCase):
    """`AD15-IR-9`, measured on a REAL filesystem state, not on a stubbed seam.

    `EntryInspectability` above already proves the CALLER maps an `OSError` from
    `entry_kind` to `bundle-entry-uninspectable` -- but it proves it by REPLACING
    `entry_kind` with a raiser. That measures the mapping and says nothing about
    whether the inspection this lane actually performs can ever fail. It cannot
    catch this defect, and it did not: the pre-ruling `entry_kind` answered from
    the `d_type` the directory read happened to carry, so on the filesystem state
    below it returned `(is_symlink=False, is_dir=False, is_file=True)` and raised
    NOTHING, while the peer lane's per-entry no-follow lookup failed `EACCES` and
    reported the reason. Same bundle, same kernel, two different reasons.

    So this class constructs the state instead: a directory INSIDE the bundle at
    mode `0o444` -- readable, so `readdir` succeeds and the entry NAME is
    obtained; not searchable, so any metadata lookup on the entry itself fails
    `EACCES`. That is exactly contract 8.2.2's first boundary row.

    The root is deliberately NOT the `0o444` directory: contract 5's identity
    boundary is a DIRECT READ of `DIR/manifest.json`, which needs traverse
    permission on the root, so a `0o444` ROOT would never establish identity and
    would exit 1 under `AD15-IR-8` -- a different rule, and not this one.

    A root-owned run defeats permission bits entirely, so it is SKIPPED there
    rather than reported as a pass.
    """

    WITNESS_KINDS = (False, False, True)

    def unsearchable_bundle(self, name):
        """A valid single-artifact bundle whose `artifacts/` directory is
        readable but not searchable.
        """
        root = os.path.join(self.root, name)
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        nested = os.path.join(bundle, "artifacts")
        # Restored before rmtree, and before any assertion can leave it locked.
        self.addCleanup(os.chmod, nested, 0o755)
        os.chmod(nested, 0o444)
        return bundle, nested

    def require_permission_bits(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("euid 0 bypasses permission bits, so a 0o444 "
                          "directory is still searchable and this filesystem "
                          "state cannot be constructed")

    def test_an_unsearchable_directory_makes_its_entries_uninspectable(self):
        """The discrimination. Reverting `entry_kind` to the enumeration-time
        hint makes this bundle report `bundle-file-unreadable` instead, because
        the entry is then wrongly CLASSIFIED as a regular file and the failure
        only surfaces later, when its bytes are read.
        """
        self.require_permission_bits()
        bundle, _ = self.unsearchable_bundle("ir9a")
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-entry-uninspectable")
        self.assertEqual(exc.status, "ERROR")

    def test_it_is_reported_at_exit_3_with_an_empty_artifacts_array(self):
        self.require_permission_bits()
        bundle, _ = self.unsearchable_bundle("ir9b")
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual(result["nonmeasurement"]["reason"],
                         "bundle-entry-uninspectable")
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])
        self.assertEqual(result["artifacts"], [])      # pre-invocation

    def test_no_frozen_verifier_is_invoked(self):
        self.require_permission_bits()
        bundle, _ = self.unsearchable_bundle("ir9c")
        stub = StubVerifier()
        with self.assertRaises(ev.NonMeasurement):
            self.evaluate(bundle, stub)
        self.assertEqual(stub.calls, [])

    def test_the_enumeration_time_hint_answers_without_raising_here(self):
        """The VACUITY GUARD, and the reason the test above discriminates.

        If `os.DirEntry` raised on this state, the superseded implementation
        would have reached `bundle-entry-uninspectable` too and the
        discrimination test would pass with and without the fix -- which is not
        a test (Erratum 4, method note). This asserts the hint does NOT raise
        here, so the discrimination is real on this filesystem. Where `d_type`
        is not populated the hint falls back to a stat and the state stops
        discriminating; that is reported as a SKIP, never as a pass.
        """
        self.require_permission_bits()
        _, nested = self.unsearchable_bundle("ir9d")
        with os.scandir(nested) as scan:
            entries = list(scan)
        self.assertEqual([e.name for e in entries], ["d.json"])
        entry = entries[0]
        try:
            hint = (entry.is_symlink(),
                    entry.is_dir(follow_symlinks=False),
                    entry.is_file(follow_symlinks=False))
        except OSError:
            self.skipTest("this filesystem does not populate d_type, so the "
                          "enumeration-time hint already performs a metadata "
                          "lookup and the AD15-IR-9 divergence is not "
                          "constructible here")
        self.assertEqual(hint, self.WITNESS_KINDS)

    def test_the_no_follow_lookup_on_the_same_entry_does_raise(self):
        """The other half of the guard: the lookup `AD15-IR-9` mandates DOES
        fail on the state the hint answered for, so the two are not equivalent.
        """
        self.require_permission_bits()
        _, nested = self.unsearchable_bundle("ir9e")
        with os.scandir(nested) as scan:
            entry = list(scan)[0]
        with self.assertRaises(OSError) as ctx:
            ev.entry_kind(entry)
        self.assertEqual(ctx.exception.errno, errno.EACCES)

    def test_a_symlink_is_still_observed_through_the_no_follow_lookup(self):
        """The lookup must not FOLLOW the final component: a symlink whose
        target is an ordinary file must still be seen as a symlink, or contract
        5's "symbolic links are forbidden anywhere under the bundle" would be
        silently satisfied by the target's kind.
        """
        root = os.path.join(self.root, "ir9f")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-P-DEC", {"artifacts/d.json": DECISION})
        os.symlink(os.path.join(bundle, "artifacts", "d.json"),
                   os.path.join(bundle, "artifacts", "link.json"))
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "manifest-invalid")
        self.assertIn("symbolic link", exc.detail)

    def test_ordinary_kinds_are_still_classified_correctly(self):
        """The change is to HOW the kind is established, not to WHAT the kinds
        are: an ordinary bundle still measures clean.
        """
        bundle = write_bundle(os.path.join(self.root, "ir9g"), "IOP-P-DEC",
                              {"artifacts/d.json": DECISION})
        manifest = ev.validate_manifest(
            *ev.load_manifest_identity(bundle)[:2],
            duplicates=ev.load_manifest_identity(bundle)[2])
        self.assertEqual(sorted(ev.stage_traversal(bundle, manifest)),
                         ["artifacts/d.json", "operator/bindings.json",
                          "operator/independence.json", "operator/revocation.json"])


# --------------------------------------------------------------------------
# Erratum 6, E6-2 -- ruling `AD15-IR-10`: run validity precedes tier withheld
# --------------------------------------------------------------------------

class RunValidityPrecedesTierWithheld(BundleCase):
    """Contract 7.1 is evaluated ONLY AFTER every artifact invocation has passed
    the 7.2 process- and result-shape guard.

    Both channels can be live on the same bundle: one artifact exits 0 carrying
    a non-empty `authenticated_withheld` channel while another produces a
    non-permitted exit. Both are pinned to exit 3, and the contract never said
    which `measurement_status` wins until `AD15-IR-10`. The ERROR wins: a
    verifier that misbehaved AS A PROCESS cannot be trusted to have produced a
    meaningful withheld channel either, so reporting MEASUREMENT_INVALID would
    attribute the failure to the tier when it belongs to the run.

    This lane already ordered the two that way. Contract 13 step 4 requires the
    ordering be MEASURED rather than left to hold by accident, which is what
    these cases do -- the withheld artifact is deliberately the FIRST one
    invoked, so an implementation that raised on withheld as it went would
    report `authenticated-withheld` here and fail.
    """

    WITHHELD = ["binding-absent"]

    def bundle(self, name):
        root = os.path.join(self.root, name)
        os.makedirs(root)
        return write_bundle(root, "IOP-R-CLEAN", four_artifacts())

    def both_live(self, bad_exit=2, bad_body=None):
        """`b-control` is invoked FIRST and withholds; `c-execution` is invoked
        LAST and misbehaves as a process.
        """
        return StubVerifier(by_record={
            "b-control": (0, verdict("b-control", klass="AIREP-Core",
                                     auth_withheld=self.WITHHELD)),
            "c-execution": (bad_exit, bad_body)})

    def test_the_error_outcome_is_reported_when_both_are_present(self):
        exc = self.nonmeasurement(self.bundle("ir10a"), self.both_live())
        self.assertEqual(exc.reason, "verifier-run-invalid")
        self.assertEqual(exc.status, "ERROR")

    def test_the_result_object_carries_error_not_measurement_invalid(self):
        code, out, _ = self.run_cli(self.bundle("ir10b"), stub=self.both_live())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual(result["nonmeasurement"]["reason"], "verifier-run-invalid")
        self.assertNotEqual(result["measurement_status"], "MEASUREMENT_INVALID")
        self.assertIsNone(result["level1"])
        self.assertIsNone(result["predicates"])

    def test_a_malformed_exit_0_result_also_precedes_the_withheld_channel(self):
        """The guard is process AND result shape. An exit-0 invocation carrying
        a wrong-shape result is `verifier-run-invalid` too, and it likewise wins
        over a withheld channel emitted by a different artifact.
        """
        stub = self.both_live(bad_exit=0, bad_body={"not": "a verdict"})
        exc = self.nonmeasurement(self.bundle("ir10c"), stub)
        self.assertEqual(exc.reason, "verifier-run-invalid")

    def test_a_frozen_exit_1_outside_the_7_2_conditions_also_wins(self):
        stub = self.both_live(bad_exit=1)
        exc = self.nonmeasurement(self.bundle("ir10d"), stub)
        self.assertEqual(exc.reason, "verifier-run-invalid")

    def test_withheld_alone_is_still_measurement_invalid(self):
        """The control case. Without it, `test_the_error_outcome...` would also
        pass an implementation that reported ERROR unconditionally, which is not
        the ruling.
        """
        stub = StubVerifier(by_record={
            "b-control": (0, verdict("b-control", klass="AIREP-Core",
                                     auth_withheld=self.WITHHELD))})
        exc = self.nonmeasurement(self.bundle("ir10e"), stub)
        self.assertEqual(exc.reason, "authenticated-withheld")
        self.assertEqual(exc.status, "MEASUREMENT_INVALID")

    def test_a_process_failure_alone_is_still_verifier_run_invalid(self):
        """The other control case: the ERROR branch is not an artefact of the
        withheld channel being present.
        """
        stub = StubVerifier(by_record={"c-execution": (2, None)})
        exc = self.nonmeasurement(self.bundle("ir10f"), stub)
        self.assertEqual(exc.reason, "verifier-run-invalid")

    def test_the_withheld_channel_is_still_reported_alongside_the_error(self):
        """Reporting the ERROR does not DISCARD what was observed: the run-level
        outcome wins, and the withheld reasons stay visible to a reader.
        """
        code, out, _ = self.run_cli(self.bundle("ir10g"), stub=self.both_live())
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual([e["verifier_exit_code"] for e in result["artifacts"]
                          if e["artifact_path"] == "artifacts/control.json"], [0])


# --------------------------------------------------------------------------
# Erratum 6, E6-3 -- ruling `AD15-IR-11`: a spawn failure produces no entry
# --------------------------------------------------------------------------

class SpawnFailureContributesNoEntry(BundleCase):
    """"Attempted" means a process attempt that produced a CONCRETE PROCESS
    RESULT.

    Contract 8.3.1 step 3 says `artifacts[]` carries an entry for each
    invocation actually attempted, while 8.3's field list makes
    `verifier_exit_code`, `verifier_result` and `verifier_stderr_digest`
    products of a process attempt. A spawn that fails is an attempt in the
    ordinary sense yet produces none of the three, so the two sentences could be
    read against each other. `AD15-IR-11` resolves it: on
    `verifier-not-invocable` the CURRENT artifact contributes NO entry, and
    entries for invocations that completed EARLIER in the same bundle are
    RETAINED.

    This lane already did that. Contract 13 step 4 requires it be tested
    anyway -- a rule that holds by accident is not tested.
    """

    def bundle(self, name):
        root = os.path.join(self.root, name)
        os.makedirs(root)
        return write_bundle(root, "IOP-R-CLEAN", four_artifacts())

    def spawn_fails_after(self, completed):
        """Complete `completed` invocations, then fail to spawn. Invocation
        order is manifest order: control, decision, effect, execution.
        """
        state = {"calls": 0}

        def invoke(request, flags):
            state["calls"] += 1
            if state["calls"] > completed:
                raise ev.NonMeasurement(
                    "verifier-not-invocable",
                    "frozen verifier could not be executed: synthetic spawn "
                    "failure on call %d" % state["calls"])
            record_id = json.loads(request.decode("utf-8"))["artifact"]["record_id"]
            return 0, json.dumps(verdict(record_id)).encode("utf-8"), b""

        return invoke

    def test_the_unspawnable_invocation_contributes_no_entry(self):
        exc = self.nonmeasurement(self.bundle("ir11a"), self.spawn_fails_after(1))
        self.assertEqual(exc.reason, "verifier-not-invocable")
        self.assertEqual([e["artifact_path"] for e in exc.artifacts],
                         ["artifacts/control.json"])

    def test_earlier_completed_entries_are_retained(self):
        exc = self.nonmeasurement(self.bundle("ir11b"), self.spawn_fails_after(3))
        self.assertEqual([e["artifact_path"] for e in exc.artifacts],
                         ["artifacts/control.json", "artifacts/decision.json",
                          "artifacts/effect.json"])

    def test_a_first_call_spawn_failure_yields_an_empty_array(self):
        exc = self.nonmeasurement(self.bundle("ir11c"), self.spawn_fails_after(0))
        self.assertEqual(exc.reason, "verifier-not-invocable")
        self.assertEqual(exc.artifacts, [])

    def test_no_entry_carries_a_fabricated_exit_code_or_digest(self):
        """The reason the ruling exists: no implementer invents an exit code, a
        verdict or a stderr digest for a process that never ran.
        """
        code, out, _ = self.run_cli(self.bundle("ir11d"),
                                    stub=self.spawn_fails_after(2))
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["measurement_status"], "ERROR")
        self.assertEqual(result["nonmeasurement"]["reason"], "verifier-not-invocable")
        self.assertEqual(len(result["artifacts"]), 2)
        for entry in result["artifacts"]:
            self.assertIsInstance(entry["verifier_exit_code"], int)
            self.assertIsInstance(entry["verifier_result"], dict)
            self.assertTrue(entry["verifier_stderr_digest"].startswith("sha256:"))
        self.assertNotIn("artifacts/effect.json",
                         [e["artifact_path"] for e in result["artifacts"]])

    def test_a_completed_invocation_that_fails_still_contributes_an_entry(self):
        """The boundary the ruling draws. A process that RAN and misbehaved
        produced a concrete result, so it DOES contribute an entry -- unlike one
        that never started. Without this, "no entry" could be read as covering
        every failed invocation.
        """
        stub = StubVerifier(default=(2, None))
        exc = self.nonmeasurement(self.bundle("ir11e"), stub)
        self.assertEqual(exc.reason, "verifier-run-invalid")
        # CORRECTED BY ``AD15-IR-12``: the entry IS contributed, and the
        # scenario aborts at that first fatal run rather than continuing.
        self.assertEqual(len(exc.artifacts), 1)

    def test_the_real_seam_raises_verifier_not_invocable_when_python_is_absent(self):
        """The mapping is exercised on the REAL subprocess seam, not only on a
        stub that raises the exception the test wants to see.
        """
        original = ev.sys.executable
        ev.sys.executable = os.path.join(self.root, "no such interpreter")
        self.addCleanup(setattr, ev.sys, "executable", original)
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.invoke_frozen_verifier(b"{}", [])
        self.assertEqual(ctx.exception.reason, "verifier-not-invocable")



# ==========================================================================
# Contract 8.7 -- THE FIFTEEN CANONICAL MANDATORY BLOCKS
#
# "The required block IDs are PINNED HERE, NOT DECLARED BY THE IMPLEMENTATION.
#  A registry a lane writes for itself is not a control: an implementer can
#  delete the block AND its own registry entry and still report `0 skipped`,
#  which is the exact failure this rule exists to catch."
#
# The tuple below is therefore a TRANSCRIPTION of the contract's closed set, not
# a derivation from the classes that follow. If a block class is deleted, its ID
# stays here, no execution record is produced for it, and the runner reports it
# as NOT MEASURED and exits non-zero. That is what makes an OMITTED block
# visible rather than invisible.
#
# A block EXECUTED when its assertions ran and their outcomes are counted --
# proved machine-readably by at least one assertion-counter increment AND a
# block-completion record carrying the ID. "A block that 'ran' without
# incrementing any counter asserted nothing."
#
# An UNKNOWN or DUPLICATE block ID makes the run NON-QUALIFYING: unknown because
# the set is closed, duplicate because two records under one ID make "did it
# run" unanswerable.
#
# This pins WHAT must be exercised, not HOW. The two lanes derive their test
# code independently from the same contract; sharing an ID vocabulary is not
# shared state and does not touch contract-4 isolation.
# ==========================================================================

MANDATORY_BLOCKS = (
    # E8: `AD15-IR-4` through `AD15-IR-8` had NO BLOCK AT ALL. The registry was
    # built during Erratum 7 and only ever covered the rulings that erratum
    # touched; nothing swept backwards. Five normative rulings -- including
    # `AD15-IR-8`'s `0o111` worked case, a MEASURED convergence in Erratum 5 --
    # could each be violated while every mandatory block reported green.
    "W1-BLK-IR4",
    "W1-BLK-IR5",
    "W1-BLK-IR6",
    "W1-BLK-IR7",
    "W1-BLK-IR8",
    "W1-BLK-IR9",
    "W1-BLK-IR10",
    "W1-BLK-IR11",
    "W1-BLK-IR12",
    "W1-BLK-IR13",
    "W1-BLK-IR14",
    "W1-BLK-IR15",
    "W1-BLK-IR16",
    "W1-BLK-IR17",
    "W1-BLK-JCS",
    "W1-BLK-LIVE",
    "W1-BLK-PARITY",
    "W1-BLK-ARTIFACT-REF",
    "W1-BLK-JSON-BYTES",
    "W1-BLK-PATH",
)


class BlockLedger:
    """Machine-readable execution record for the pinned blocks."""

    def __init__(self):
        self.assertions = {}
        self.completions = []

    def count(self, block_id):
        self.assertions[block_id] = self.assertions.get(block_id, 0) + 1

    def complete(self, block_id):
        self.completions.append(block_id)

    def unknown_ids(self):
        return sorted(set(self.completions) - set(MANDATORY_BLOCKS))

    def duplicate_ids(self):
        return sorted({b for b in self.completions
                       if self.completions.count(b) > 1})

    def executed(self, block_id):
        return (self.completions.count(block_id) == 1
                and self.assertions.get(block_id, 0) >= 1)


LEDGER = BlockLedger()


class BlockCase(BundleCase):
    """Base for a mandatory block. ``BLOCK`` carries the pinned ID.

    The counted assertion helpers are the counter increments the contract's
    execution criterion requires; ``tearDownClass`` emits the block-completion
    record. A class whose tests are all skipped still emits the completion
    record and increments nothing, so the block is reported NOT MEASURED rather
    than passed -- which is the whole point of requiring both signals.
    """

    BLOCK = None

    @classmethod
    def tearDownClass(cls):
        if cls.BLOCK is not None:
            LEDGER.complete(cls.BLOCK)

    def ck(self, condition, message=""):
        LEDGER.count(self.BLOCK)
        self.assertTrue(condition, message)

    def ck_eq(self, actual, expected, message=""):
        LEDGER.count(self.BLOCK)
        self.assertEqual(actual, expected, message)

    def ck_ne(self, actual, expected, message=""):
        LEDGER.count(self.BLOCK)
        self.assertNotEqual(actual, expected, message)

    def ck_in(self, needle, haystack, message=""):
        LEDGER.count(self.BLOCK)
        self.assertIn(needle, haystack, message)

    def ck_none(self, value, message=""):
        LEDGER.count(self.BLOCK)
        self.assertIsNone(value, message)


def _seam(case, name, replacement):
    """Temporarily replace a module-level seam for the duration of one test."""
    original = getattr(ev, name)
    setattr(ev, name, replacement)
    case.addCleanup(setattr, ev, name, original)
    return original


def single_bundle(case, sub, scenario="IOP-P-DEC", doc=None, **kwargs):
    root = os.path.join(case.root, sub)
    os.makedirs(root, exist_ok=True)
    return write_bundle(root, scenario,
                        {"artifacts/a.json": DECISION if doc is None else doc},
                        **kwargs)


def ordered_four():
    """Four artifacts whose ``record_id`` rank is the EXACT REVERSE of their
    ``artifact_path`` rank.

    Erratum 4 recorded that a prior ordering fixture MEASURED NOTHING because
    the remaining artifacts ordered identically under both candidate keys. A
    test that passes with and without the fix is not a test, so the two keys are
    made maximally hostile to each other here.
    """
    return {
        "artifacts/a.json": artifact("z-decision", "decision"),
        "artifacts/b.json": artifact(
            "y-control", "control",
            decision_ref={"record_id": "z-decision"},
            authorized_action_digest="sha256:" + "11" * 32),
        "artifacts/c.json": artifact(
            "x-execution", "execution",
            decision_ref={"record_id": "z-decision"},
            executed_action_digest="sha256:" + "11" * 32),
        "artifacts/d.json": artifact(
            "w-effect", "effect",
            decision_ref={"record_id": "z-decision"},
            execution_ref={"record_id": "x-execution"},
            observer_relationship="independent"),
    }


# --------------------------------------------------------------------------
# An INDEPENDENT RFC 8785 serializer, for W1-BLK-IR4's recomputation branch
#
# `W1-BLK-IR4` requires an "INDEPENDENT RECOMPUTATION of SHA-256 over the actual
# RFC 8785 canonical bytes, equal to the emitted `request_envelope_digest`".
# Recomputing with `ev.jcs` would recompute with the very code under test and
# would establish nothing, so the canonical bytes are produced a second time
# here, from the ruling's own definition.
#
# It is deliberately restricted to the value domain these fixtures use --
# objects, arrays, strings, integers, booleans and null. Anything outside that
# raises rather than guessing: a serializer that quietly widens its own domain
# would reintroduce exactly the divergence AD15-IR-20 closes. Floats are
# excluded on purpose; the fixtures carry none, and RFC 8785's number rule is
# the one part no two hand-written serializers should be assumed to agree on.
# --------------------------------------------------------------------------

_JCS_SHORT_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: "\\\"", 0x5C: "\\\\",
}


def _independent_jcs_string(text):
    buf = ["\""]
    for char in text:
        code = ord(char)
        if code in _JCS_SHORT_ESCAPES:
            buf.append(_JCS_SHORT_ESCAPES[code])
        elif code < 0x20:
            buf.append("\\u%04x" % code)
        else:
            buf.append(char)
    buf.append("\"")
    return "".join(buf)


def independent_jcs(value):
    """RFC 8785 canonical bytes, written independently of the evaluator's JCS."""
    out = []

    def emit(node):
        if node is None:
            out.append("null")
        elif node is True:
            out.append("true")
        elif node is False:
            out.append("false")
        elif isinstance(node, str):
            out.append(_independent_jcs_string(node))
        elif isinstance(node, int):
            out.append(str(node))
        elif isinstance(node, list):
            out.append("[")
            for index, item in enumerate(node):
                if index:
                    out.append(",")
                emit(item)
            out.append("]")
        elif isinstance(node, dict):
            out.append("{")
            # RFC 8785 sorts member names by their UTF-16 code units.
            for index, key in enumerate(
                    sorted(node, key=lambda k: k.encode("utf-16-be"))):
                if index:
                    out.append(",")
                out.append(_independent_jcs_string(key))
                out.append(":")
                emit(node[key])
            out.append("}")
        else:
            raise AssertionError(
                "value outside this serializer's declared domain: %r" % (node,))

    emit(value)
    return "".join(out).encode("utf-8")


# --------------------------------------------------------------------------
# W1-BLK-IR4 -- the LANE-LOCAL HALF of AD15-IR-4, and nothing else
#
# "Envelope built exactly per 5.1; REPEAT DETERMINISM on identical input;
#  INDEPENDENT RECOMPUTATION of SHA-256 over the actual RFC 8785 canonical
#  bytes, equal to the emitted `request_envelope_digest`; CONTROLLED MUTATIONS
#  that change the canonical bytes, proving the evaluator RE-HASHES rather than
#  carrying a digest forward. Asserts NO INJECTIVITY."
#
# E8-7 stripped "any envelope change moves it" from this block: that is an
# UNPROVABLE UNIVERSAL over an infinite input domain, and false as a contract
# invariant because SHA-256 is not injective. Nothing here quantifies over all
# inputs; the mutations are named, finite and checked one by one.
#
# The AGGREGATE branches -- the pair key, a mismatch making a run
# non-qualifying, a mismatch never reaching an evaluator exit code -- are
# `W1-AGG-D2` and are the HARNESS's. Contract 4 forbids a lane-local runner from
# seeing its peer, so they are NOT ATTEMPTED HERE. A single Python invocation
# has no access to the Node lane's digest: it cannot observe, let alone enforce,
# a property of a run it is not part of.
# --------------------------------------------------------------------------

class BlockIR4(BlockCase):
    BLOCK = "W1-BLK-IR4"

    def digests(self, bundle, stub=None):
        """`artifact_path` -> emitted `request_envelope_digest`."""
        entries = self.evaluate(bundle, stub or StubVerifier())["artifacts"]
        return {e["artifact_path"]: e["request_envelope_digest"] for e in entries}

    def test_the_envelope_is_built_exactly_per_5_1(self):
        """Closed: `artifact` as a parsed JSON VALUE, and `related_artifacts`
        the OTHER artifacts of the same bundle AND NO OTHERS.
        """
        root = os.path.join(self.root, "ir4-shape")
        os.makedirs(root)
        arts = four_artifacts()
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        self.ck_eq(len(stub.calls), 4)
        for _record_id, envelope, _flags in stub.calls:
            self.ck_eq(set(envelope), {"artifact", "related_artifacts"},
                       "the section-0 envelope is closed")
            self.ck_eq(len(envelope["related_artifacts"]), 3)
            self.ck(envelope["artifact"] not in envelope["related_artifacts"],
                    "the primary must not appear among its own related set")
            for related in envelope["related_artifacts"]:
                self.ck_in(related, list(arts.values()),
                           "related_artifacts carries a value from outside the bundle")

    def test_a_single_artifact_scenario_sends_the_empty_array(self):
        """"Not absent, not populated with unrelated artifacts."""
        bundle = single_bundle(self, "ir4-single")
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        _record_id, envelope, _flags = stub.calls[0]
        self.ck_in("related_artifacts", envelope)
        self.ck_eq(envelope["related_artifacts"], [])

    def test_repeat_determinism_on_identical_input(self):
        """Contract 8.4: identical bundle plus identical operator inputs gives
        byte-identical output across repeat runs. Two SEPARATELY MATERIALIZED
        bundles of the same content are used, so a cached digest inside one
        evaluation would not be what makes them agree.
        """
        first = write_bundle(os.path.join(self.root, "ir4-r1"), "IOP-R-CLEAN",
                             four_artifacts())
        second = write_bundle(os.path.join(self.root, "ir4-r2"), "IOP-R-CLEAN",
                              four_artifacts())
        self.ck_eq(self.digests(first), self.digests(second))
        self.ck_eq(self.digests(first), self.digests(first))

    def test_the_digest_is_sha256_over_the_actual_canonical_bytes(self):
        """The independent recomputation branch. The canonical bytes are
        rebuilt by `independent_jcs`, hashed here, and compared with what the
        evaluator EMITTED.
        """
        root = os.path.join(self.root, "ir4-recompute")
        os.makedirs(root)
        arts = four_artifacts()
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        emitted = self.digests(bundle)
        by_path = dict(arts)
        for path in sorted(by_path, key=lambda s: s.encode("utf-8")):
            related = [by_path[other]
                       for other in sorted(by_path, key=lambda s: s.encode("utf-8"))
                       if other != path]
            envelope = {"artifact": by_path[path], "related_artifacts": related}
            expected = "sha256:" + hashlib.sha256(
                independent_jcs(envelope)).hexdigest()
            self.ck_eq(emitted[path], expected,
                       "emitted digest is not SHA-256 over the canonical bytes "
                       "for %s" % path)

    def test_a_controlled_mutation_moves_the_digest(self):
        """"Controlled mutations that change the canonical bytes, PROVING THE
        EVALUATOR RE-HASHES rather than carrying a digest forward."

        Each mutation below is named and checked individually. This asserts
        nothing about mutations in general and CLAIMS NO INJECTIVITY (E8-7):
        SHA-256 is not injective, and "any envelope change moves the digest" is
        not provable and is not a contract invariant.
        """
        base = write_bundle(os.path.join(self.root, "ir4-m0"), "IOP-R-CLEAN",
                            four_artifacts())
        baseline = self.digests(base)
        mutations = {
            "a changed scalar in the primary":
                four_artifacts(decision={"sequence": 9}),
            "an added member in the primary":
                four_artifacts(decision={"iop_extra": "x"}),
            "a changed scalar in a RELATED artifact":
                four_artifacts(effect={"sequence": 7}),
        }
        for index, (label, arts) in enumerate(sorted(mutations.items())):
            root = os.path.join(self.root, "ir4-m-%d" % index)
            os.makedirs(root, exist_ok=True)
            moved = self.digests(write_bundle(root, "IOP-R-CLEAN", arts))
            self.ck_ne(moved["artifacts/decision.json"],
                       baseline["artifacts/decision.json"],
                       "the digest did not move for: %s" % label)

    def test_each_artifact_in_one_bundle_gets_its_own_digest(self):
        """The envelope is a function of the PRIMARY as well as the bundle, so a
        lane carrying one digest forward across the four invocations is caught.
        """
        bundle = write_bundle(os.path.join(self.root, "ir4-per"), "IOP-R-CLEAN",
                              four_artifacts())
        emitted = self.digests(bundle)
        self.ck_eq(len(set(emitted.values())), 4)

    def test_the_digest_is_the_pinned_encoding(self):
        bundle = single_bundle(self, "ir4-enc")
        digest = self.digests(bundle)["artifacts/a.json"]
        self.ck(digest.startswith("sha256:"), digest)
        self.ck_eq(len(digest), len("sha256:") + 64)
        self.ck_eq(digest[7:], digest[7:].lower())

    def test_the_lane_emits_only_its_own_digest(self):
        """Contract 8.2.1: "The PEER LANE's verifier digest does not appear in
        evaluator output at all." The aggregate comparison is the harness's.
        """
        bundle = single_bundle(self, "ir4-own")
        result = self.evaluate(bundle, StubVerifier())
        self.ck_eq(set(result["verifier_digests"]),
                   {"class_verifier", "class_verifier_contract"})


# --------------------------------------------------------------------------
# W1-BLK-IR5 -- `artifact_path` is the TOTAL result identity
#
# "artifacts[] ordered by it; artifact_ref null where no string record_id
#  exists; NO record_id EVER SYNTHESIZED; an artifact with a MISSING record_id
#  STILL REACHES FROZEN STAGE 0 rather than being refused; and semantic
#  reference resolution (R-A) still keys on record_id, NEVER on artifact_path."
# --------------------------------------------------------------------------

class BlockIR5(BlockCase):
    BLOCK = "W1-BLK-IR5"

    def test_artifacts_are_ordered_by_artifact_path_bytes(self):
        """The fixture makes `record_id` rank the EXACT REVERSE of
        `artifact_path` rank, so the assertion cannot pass under the wrong key.
        """
        root = os.path.join(self.root, "ir5-order")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        entries = self.evaluate(bundle, StubVerifier())["artifacts"]
        paths = [e["artifact_path"] for e in entries]
        self.ck_eq(paths, sorted(paths, key=lambda s: s.encode("utf-8")))
        refs = [e["artifact_ref"]["record_id"] for e in entries]
        self.ck_ne(refs, sorted(refs, key=lambda s: s.encode("utf-8")),
                   "the fixture failed to separate the two candidate keys")

    def test_artifact_path_is_present_on_every_entry(self):
        """It ALWAYS exists -- the manifest lists every file -- which is why it
        can be the total identity and `record_id` cannot.
        """
        root = os.path.join(self.root, "ir5-present")
        os.makedirs(root)
        arts = four_artifacts()
        del arts["artifacts/effect.json"]["record_id"]
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        for entry in self.evaluate(bundle, StubVerifier())["artifacts"]:
            self.ck(isinstance(entry["artifact_path"], str))
            self.ck(entry["artifact_path"])

    def test_artifact_ref_is_null_where_no_string_record_id_exists(self):
        for label, value in (("absent", ABSENT), ("non-string", 17)):
            doc = dict(DECISION)
            if value is ABSENT:
                doc.pop("record_id")
            else:
                doc["record_id"] = value
            bundle = single_bundle(self, "ir5-null-%s" % label,
                                   scenario="IOP-B-DEC", doc=doc)
            entry = self.evaluate(
                bundle, StubVerifier(default=(1, None)))["artifacts"][0]
            self.ck_none(entry["artifact_ref"], label)

    def test_no_record_id_is_ever_synthesized(self):
        """AD15-IR-5: never, for any reason. Neither the result object nor the
        envelope sent to the frozen verifier may gain one.
        """
        doc = {k: v for k, v in DECISION.items() if k != "record_id"}
        bundle = single_bundle(self, "ir5-synth", scenario="IOP-B-DEC", doc=doc)
        stub = StubVerifier(default=(1, None))
        result = self.evaluate(bundle, stub)
        self.ck("record_id" not in stub.calls[0][1]["artifact"],
                "a record_id was synthesized into the request envelope")
        self.ck("record_id" not in json.dumps(result["artifacts"][0]),
                "a record_id was synthesized into the result entry")

    def test_a_missing_record_id_still_reaches_frozen_stage_0(self):
        """"The consequence that matters": it is NOT converted into the
        evaluator's own preflight failure.
        """
        doc = {k: v for k, v in DECISION.items() if k != "record_id"}
        bundle = single_bundle(self, "ir5-stage0", scenario="IOP-B-DEC", doc=doc)
        stub = StubVerifier(default=(1, None))
        result = self.evaluate(bundle, stub)
        self.ck_eq(len(stub.calls), 1, "the artifact never reached the verifier")
        self.ck_eq(result["measurement_status"], "MEASURED")
        self.ck_eq(result["level1"], "REJECT")

    def test_r_a_still_keys_on_record_id_never_on_artifact_path(self):
        """AD15-IR-5: "the manifest path is HARNESS AND RESULT IDENTITY ONLY --
        it is not wire semantics -- and never participates in reference
        resolution." A reference naming a bundle PATH therefore resolves to
        nothing.
        """
        arts = four_artifacts(
            control={"decision_ref": {"record_id": "artifacts/decision.json"}})
        root = os.path.join(self.root, "ir5-ra")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-XREF", arts)
        result = self.evaluate(bundle, StubVerifier())
        self.ck_eq(result["predicates"]["R_A"], "FAIL")

    def test_r_a_resolves_a_genuine_record_id_reference(self):
        """The positive control: without it the test above would also pass on an
        evaluator whose R-A always failed.
        """
        root = os.path.join(self.root, "ir5-ra-ok")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts())
        result = self.evaluate(bundle, StubVerifier())
        self.ck_eq(result["predicates"]["R_A"], "PASS")

    def test_the_aggregate_pair_key_is_scenario_id_and_artifact_path(self):
        """Lane-local half: the two members the harness pairs on are both
        present and carry the pinned values. The COMPARISON is `W1-AGG-D2`'s.
        """
        root = os.path.join(self.root, "ir5-key")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts())
        result = self.evaluate(bundle, StubVerifier())
        self.ck_eq(result["scenario_id"], "IOP-R-CLEAN")
        self.ck_eq(sorted(e["artifact_path"] for e in result["artifacts"]),
                   ["artifacts/control.json", "artifacts/decision.json",
                    "artifacts/effect.json", "artifacts/execution.json"])


# --------------------------------------------------------------------------
# W1-BLK-IR6 -- `related_artifacts` ordering is `artifact_path` too
#
# "related_artifacts ordered by artifact_path, ON A FIXTURE WHERE `record_id`
#  ORDER IS THE REVERSE of `artifact_path` order; AND that the envelope stays
#  WELL-DEFINED when an artifact carries NO USABLE `record_id` at all -- the
#  case that made `record_id` ordering unusable."
#
# Erratum 4's method note applies directly: a prior ordering fixture MEASURED
# NOTHING because the remaining artifacts ordered identically under both
# candidate keys. `ordered_four()` makes the two keys maximally hostile.
# --------------------------------------------------------------------------

class BlockIR6(BlockCase):
    BLOCK = "W1-BLK-IR6"

    def envelopes(self, bundle, stub=None):
        stub = stub or StubVerifier()
        self.evaluate(bundle, stub)
        return [envelope for _record_id, envelope, _flags in stub.calls]

    def test_related_artifacts_are_ordered_by_artifact_path(self):
        root = os.path.join(self.root, "ir6-order")
        os.makedirs(root)
        arts = ordered_four()
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        by_value = {json.dumps(v, sort_keys=True): p for p, v in arts.items()}
        for envelope in self.envelopes(bundle):
            paths = [by_value[json.dumps(v, sort_keys=True)]
                     for v in envelope["related_artifacts"]]
            self.ck_eq(paths, sorted(paths, key=lambda s: s.encode("utf-8")))

    def test_the_record_id_order_is_the_reverse_so_the_key_is_discriminated(self):
        """Without this the fixture could order identically under both keys and
        the block would measure nothing.
        """
        root = os.path.join(self.root, "ir6-rev")
        os.makedirs(root)
        arts = ordered_four()
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        by_value = {json.dumps(v, sort_keys=True): p for p, v in arts.items()}
        checked = 0
        for envelope in self.envelopes(bundle):
            related = envelope["related_artifacts"]
            paths = [by_value[json.dumps(v, sort_keys=True)] for v in related]
            ids = [v["record_id"] for v in related]
            self.ck_eq(paths, sorted(paths, key=lambda s: s.encode("utf-8")))
            self.ck_ne(ids, sorted(ids, key=lambda s: s.encode("utf-8")),
                       "record_id order coincides here, so nothing is measured")
            checked += 1
        self.ck_eq(checked, 4)

    def test_the_envelope_is_well_defined_without_any_usable_record_id(self):
        """The case that made `record_id` ordering unusable: two isolated
        remediation contexts resolved it differently -- one sorted such an
        artifact under an empty key, the other REFUSED TO BUILD THE ENVELOPE.
        Both are superseded; the envelope is always defined.
        """
        root = os.path.join(self.root, "ir6-noid")
        os.makedirs(root)
        arts = ordered_four()
        del arts["artifacts/c.json"]["record_id"]
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)          # no NonMeasurement
        self.ck_eq(result["measurement_status"], "MEASURED")
        self.ck_eq(len(stub.calls), 4, "the unidentifiable artifact was skipped")
        for entry in result["artifacts"]:
            self.ck(entry["request_envelope_digest"].startswith("sha256:"),
                    "an envelope digest was not produced for %s"
                    % entry["artifact_path"])

    def test_the_unidentifiable_artifact_occupies_a_defined_slot(self):
        """It is ordered by its path like every other member -- so it appears at
        a FIXED index in every other artifact's related set.
        """
        root = os.path.join(self.root, "ir6-slot")
        os.makedirs(root)
        arts = ordered_four()
        del arts["artifacts/c.json"]["record_id"]
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        target = arts["artifacts/c.json"]
        seen = 0
        for envelope in self.envelopes(bundle):
            related = envelope["related_artifacts"]
            if target in related:
                # a.json, b.json, d.json are the other primaries; c.json sorts
                # third of four by path, so it is at index 2 of the remaining
                # three whenever the primary sorts before it, and index 1 when
                # the primary is d.json.
                self.ck_in(related.index(target), (1, 2))
                seen += 1
        self.ck_eq(seen, 3)

    def test_envelope_ordering_is_stable_across_repeat_runs(self):
        root = os.path.join(self.root, "ir6-stable")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        first = [e["related_artifacts"] for e in self.envelopes(bundle)]
        second = [e["related_artifacts"] for e in self.envelopes(bundle)]
        self.ck_eq(first, second)


# --------------------------------------------------------------------------
# W1-BLK-IR7 -- duplicate semantic IDs are NOT bundle-preflight invalidity
#
# "Discriminate INDEPENDENTLY: A. duplicate `record_id` with DISTINCT
#  `chain_id`; B. duplicate EXACT `(chain_id, record_id)`. Both MUST reach
#  frozen stage evaluation and MUST NOT be rejected merely for the duplicate.
#  AND a fixture with a REAL AMBIGUOUS LOOKUP, proving `R-A` FAILS CLOSED and
#  the evaluator DOES NOT PICK ONE. The test MUST NOT require the eventual
#  result to be `ACCEPT` -- the block proves absence of a preflight GATE, not
#  absence of a later reconciliation finding. Frozen batch `R-10` MUST NOT be
#  generalized into a bundle-level preflight."
#
# E8-9: the earlier block tested only branch A, so an evaluator that allowed the
# first and rejected the second passed all twenty blocks while violating the
# ruling. Its "is not rejected by the evaluator" wording was ALSO too broad --
# an exact duplicate tuple may legitimately fail `R-A` later.
# --------------------------------------------------------------------------

class BlockIR7(BlockCase):
    BLOCK = "W1-BLK-IR7"

    def duplicated(self, sub, chain_ids):
        """A four-artifact bundle whose Control and Execution share a
        `record_id`, with the two `chain_id` values supplied by the caller.
        """
        arts = four_artifacts(
            control={"record_id": "shared-id", "chain_id": chain_ids[0]},
            execution={"record_id": "shared-id", "chain_id": chain_ids[1]})
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        return write_bundle(root, "IOP-R-CLEAN", arts)

    def test_branch_a_duplicate_record_id_with_distinct_chain_id(self):
        """Branch A reaches frozen stage evaluation and is NOT rejected merely
        for the duplicate.
        """
        bundle = self.duplicated("ir7-a", ("chain-one", "chain-two"))
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)          # no preflight refusal
        self.ck_eq(len(stub.calls), 4,
                   "a preflight gate stopped the bundle before stage evaluation")
        self.ck_ne(result["measurement_status"], "ERROR")

    def test_branch_b_duplicate_exact_chain_id_and_record_id(self):
        """Branch B is the one E8-9 found untested. An evaluator that allowed
        branch A and rejected branch B passed every block while violating the
        ruling.
        """
        bundle = self.duplicated("ir7-b", ("chain-same", "chain-same"))
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)          # no preflight refusal
        self.ck_eq(len(stub.calls), 4,
                   "a preflight gate stopped the bundle before stage evaluation")
        self.ck_ne(result["measurement_status"], "ERROR")

    def test_neither_branch_produces_a_preflight_reason(self):
        """The ruling forbids a GATE, so the discriminating observation is that
        no `bundle-shape-invalid` / `manifest-invalid` reason is raised.
        """
        for label, chains in (("a", ("chain-one", "chain-two")),
                              ("b", ("chain-same", "chain-same"))):
            bundle = self.duplicated("ir7-none-%s" % label, chains)
            result = self.evaluate(bundle, StubVerifier())
            self.ck_none(result["nonmeasurement"],
                         "branch %s raised a preflight reason" % label)

    def test_a_real_ambiguous_lookup_fails_r_a_closed(self):
        """The evaluator NEVER PICKS ONE. Here the Effect's `execution_ref`
        matches TWO artifacts, so the lookup is genuinely ambiguous -- which is
        a RECONCILIATION FINDING, reached because there was no preflight gate.
        """
        arts = four_artifacts(
            control={"record_id": "c-execution"},     # collides with the Execution
            effect={"execution_ref": {"record_id": "c-execution"}})
        root = os.path.join(self.root, "ir7-ambig")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)
        self.ck_eq(len(stub.calls), 4, "the ambiguity was refused at preflight")
        self.ck_eq(result["predicates"]["R_A"], "FAIL",
                   "an ambiguous lookup did not fail closed")
        self.ck_eq(result["level1"], "RECONCILIATION_MISMATCH")

    def test_the_block_does_not_require_the_result_to_be_accept(self):
        """"The test MUST NOT require the eventual result to be `ACCEPT`." An
        exact duplicate tuple may perfectly properly fail `R-A` afterwards, so
        what is asserted is REACHABILITY, never the verdict.

        This case makes the distinction explicit: branch B reaches stage
        evaluation AND legitimately lands on a non-`ACCEPT` Level-1 value, and
        both facts are recorded without either being treated as a defect.
        """
        arts = four_artifacts(
            control={"record_id": "shared-id", "chain_id": "chain-same"},
            execution={"record_id": "shared-id", "chain_id": "chain-same"},
            effect={"execution_ref": {"record_id": "shared-id",
                                      "chain_id": "chain-same"}})
        root = os.path.join(self.root, "ir7-noaccept")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        stub = StubVerifier()
        result = self.evaluate(bundle, stub)
        self.ck_eq(len(stub.calls), 4)
        self.ck_in(result["level1"],
                   ("ACCEPT", "RECONCILIATION_MISMATCH",
                    "INDEPENDENCE_NOT_ESTABLISHED", "REJECT"),
                   "the block must accept any Level-1 outcome here")
        self.ck_eq(result["measurement_status"], "MEASURED")

    def test_frozen_r_10_is_not_generalized_into_a_bundle_preflight(self):
        """Frozen `R-10` makes a duplicate `(chain_id, record_id)` in the BATCH
        VERIFIER'S OWN emitted verdict set run-invalid. This evaluator submits
        each artifact as a SEPARATE REQUEST, so that batch invariant does not
        generalize -- and must not be widened into one.
        """
        bundle = self.duplicated("ir7-r10", ("chain-same", "chain-same"))
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        primaries = []
        for _record_id, envelope, _flags in stub.calls:
            self.ck_eq(set(envelope), {"artifact", "related_artifacts"},
                       "a request carried something other than one primary")
            primaries.append(json.dumps(envelope["artifact"], sort_keys=True))
        self.ck_eq(len(stub.calls), 4,
                   "a batch-level invariant was applied to separate requests")
        self.ck_eq(len(set(primaries)), 4,
                   "the four artifacts were not submitted as four separate "
                   "single-primary requests")


# --------------------------------------------------------------------------
# W1-BLK-IR8 -- identity establishment is MONOTONIC
#
# "Once the manifest is read, parsed and yields a registered `scenario_id`, NO
#  LATER filesystem, traversal or preflight failure unestablishes it -- with
#  EACH OF THE THREE CATEGORIES DISCRIMINATED SEPARATELY: a listed-file or
#  digest failure after identity, a traversal failure, and a NON-FILESYSTEM
#  preflight failure such as manifest structure, bundle shape, numeric preflight
#  or frozen-digest mismatch. 'More than one case' is not enough; two traversal
#  fixtures would leave two categories untested. Includes the `0o111` case as
#  `bundle-directory-unreadable` at exit 3, NEVER exit 1. A harness unable to
#  construct permission fixtures MAY skip that case, REPORTED AS A SKIP."
# --------------------------------------------------------------------------

class BlockIR8(BlockCase):
    BLOCK = "W1-BLK-IR8"

    def assert_result_bearing(self, bundle, expected_reason, stub=None):
        """Exit 3, ONE result object, naming the scenario -- never exit 1."""
        code, out, _err = self.run_cli(bundle, stub=stub or StubVerifier())
        self.ck_eq(code, 3, "identity was unestablished by a later failure")
        self.ck(out.strip(), "exit 3 emitted no result object")
        result = json.loads(out)
        self.ck_eq(result["scenario_id"], "IOP-R-CLEAN")
        self.ck_eq(result["nonmeasurement"]["reason"], expected_reason)
        self.ck_none(result["level1"])
        self.ck_none(result["predicates"])
        return result

    def four(self, sub, **kwargs):
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        return write_bundle(root, "IOP-R-CLEAN", four_artifacts(), **kwargs)

    # ---- CATEGORY 1: a listed-file or digest failure after identity ---------

    def test_category_1_a_missing_listed_file_is_result_bearing(self):
        bundle = self.four("ir8-c1a", drop_from_disk=("artifacts/effect.json",))
        self.assert_result_bearing(bundle, "bundle-file-missing")

    def test_category_1_a_digest_mismatch_is_result_bearing(self):
        def wrong(manifest):
            for entry in manifest["files"]:
                if entry["path"] == "artifacts/control.json":
                    entry["sha256"] = "0" * 64
            return manifest

        bundle = self.four("ir8-c1b", manifest_overrides=wrong)
        self.assert_result_bearing(bundle, "manifest-digest-mismatch")

    def test_category_1_an_unreadable_listed_file_is_result_bearing(self):
        bundle = self.four("ir8-c1c")
        real = ev.read_bundle_file

        def refusing(full_path):
            if full_path.endswith(os.path.join("artifacts", "decision.json")):
                raise OSError(errno.EACCES, "Permission denied", full_path)
            return real(full_path)

        _seam(self, "read_bundle_file", refusing)
        self.assert_result_bearing(bundle, "bundle-file-unreadable")

    # ---- CATEGORY 2: a traversal failure ------------------------------------

    def test_category_2_an_unenumerable_directory_is_result_bearing(self):
        """`bundle-directory-unreadable` says the layout COULD NOT BE MEASURED,
        as distinct from being WRONG -- and it is exit 3, not exit 1.
        """
        bundle = self.four("ir8-c2")
        _seam(self, "scan_directory",
              lambda path: (_ for _ in ()).throw(
                  OSError(errno.EACCES, "Permission denied", path)))
        self.assert_result_bearing(bundle, "bundle-directory-unreadable")

    def test_category_2_the_0o111_worked_case(self):
        """AD15-IR-8's worked case, verbatim: "bundle directory mode `0o111`.
        Traverse permission lets `open(DIR/manifest.json)` succeed while
        `readdir(DIR)` fails `EACCES`. The manifest read succeeded and yielded a
        registered `scenario_id`, so identity WAS established. The result is
        `bundle-directory-unreadable`, exit `3` -- NOT exit 1."

        A harness unable to construct permission fixtures MAY skip this case,
        and the skip is REPORTED AS A SKIP -- never counted as a pass.
        """
        bundle = self.four("ir8-0o111")
        if os.geteuid() == 0:
            self.skipTest("running as root: mode 0o111 does not deny readdir, "
                          "so the fixture cannot be constructed")
        try:
            os.chmod(bundle, 0o111)
        except OSError as exc:
            self.skipTest("cannot chmod the bundle directory: %s" % exc)
        self.addCleanup(os.chmod, bundle, 0o755)
        try:
            os.listdir(bundle)
        except OSError:
            pass
        else:
            self.skipTest("this filesystem still permits readdir at mode 0o111 "
                          "(no permission enforcement), so the worked case "
                          "cannot be constructed here")
        self.assert_result_bearing(bundle, "bundle-directory-unreadable")

    # ---- CATEGORY 3: a NON-FILESYSTEM preflight failure ---------------------

    def test_category_3_a_manifest_structure_violation_is_result_bearing(self):
        """Stage 4 -- the manifest is wrong on its OWN TERMS, and identity has
        already been established from it.
        """
        def unsorted(manifest):
            manifest["files"] = list(reversed(manifest["files"]))
            return manifest

        bundle = self.four("ir8-c3a", manifest_overrides=unsorted)
        self.assert_result_bearing(bundle, "manifest-invalid")

    def test_category_3_a_bundle_shape_violation_is_result_bearing(self):
        """Stage 9 -- an `IOP-R-*` scenario with the wrong artifact count."""
        root = os.path.join(self.root, "ir8-c3b")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN",
                              {"artifacts/a.json": DECISION})
        self.assert_result_bearing(bundle, "bundle-shape-invalid")

    def test_category_3_a_numeric_preflight_violation_is_result_bearing(self):
        """Stage 10 -- and its mandatory `json_pointer` survives too."""
        root = os.path.join(self.root, "ir8-c3c")
        os.makedirs(root)
        arts = four_artifacts(decision={"profiles": {"x": 10 ** 20}})
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)
        result = self.assert_result_bearing(bundle, "numeric-preflight-violation")
        self.ck_eq(result["nonmeasurement"]["json_pointer"], "/profiles/x")

    def test_category_3_a_frozen_digest_mismatch_is_result_bearing(self):
        """Stage 3 -- no filesystem property of the BUNDLE is involved at all,
        which is what makes this the third category rather than the first.
        """
        bundle = self.four("ir8-c3d")
        real = ev.read_frozen_file

        def tampered(path):
            return real(path) + b"\n# synthetic drift\n"

        _seam(self, "read_frozen_file", tampered)
        result = self.assert_result_bearing(bundle, "verifier-digest-mismatch")
        self.ck_eq(set(result["verifier_digests"]),
                   {"class_verifier", "class_verifier_contract"},
                   "step 5 retains the ACTUAL recomputed two-entry object")

    # ---- the monotonicity statement itself ---------------------------------

    def test_no_later_failure_returns_the_run_to_the_exit_1_band(self):
        """The exit-1 band is EXACTLY contract 5's direct-read identity
        boundary. Every category above must therefore be exit 3 -- the single
        assertion the three categories exist to support.
        """
        seen = []
        bundle = self.four("ir8-mono-a",
                           drop_from_disk=("artifacts/effect.json",))
        seen.append(self.run_cli(bundle, stub=StubVerifier())[0])

        bundle = self.four("ir8-mono-b")
        _seam(self, "scan_directory",
              lambda path: (_ for _ in ()).throw(
                  OSError(errno.EACCES, "Permission denied", path)))
        seen.append(self.run_cli(bundle, stub=StubVerifier())[0])

        root = os.path.join(self.root, "ir8-mono-c")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", {"artifacts/a.json": DECISION})
        seen.append(self.run_cli(bundle, stub=StubVerifier())[0])

        self.ck_eq(seen, [3, 3, 3], "a later failure unestablished identity")

    def test_identity_survives_into_the_emitted_scenario_id(self):
        """What monotonicity BUYS: the harness is told WHICH scenario failed."""
        bundle = self.four("ir8-name", drop_from_disk=("artifacts/effect.json",))
        code, out, _err = self.run_cli(bundle, stub=StubVerifier())
        self.ck_eq(code, 3)
        self.ck_eq(json.loads(out)["scenario_id"], "IOP-R-CLEAN")


# --------------------------------------------------------------------------
# W1-BLK-IR9 -- entry kind by authoritative no-follow lookup, discriminating
# against the enumeration-time hint
# --------------------------------------------------------------------------

class BlockIR9(BlockCase):
    BLOCK = "W1-BLK-IR9"

    class HintingEntry:
        """An ``os.DirEntry`` lookalike whose ENUMERATION-TIME HINTS all answer
        cleanly and never raise -- exactly what CPython's ``d_type``-backed
        ``os.DirEntry`` did on a directory at mode ``0o444``, and exactly what
        ``AD15-IR-9`` rules out as kind evidence.
        """

        def __init__(self, name, path):
            self.name = name
            self.path = path

        def is_symlink(self):
            return False

        def is_dir(self, follow_symlinks=True):
            return False

        def is_file(self, follow_symlinks=True):
            return True

    def test_kind_comes_from_a_separate_no_follow_lookup_not_the_hint(self):
        """The discrimination the ruling exists for. The hints say "an ordinary
        regular file"; the per-entry no-follow lookup fails. The reason MUST be
        ``bundle-entry-uninspectable``: a lane that trusted the hint would have
        proceeded, which is the MEASURED divergence E6-1 records.
        """
        bundle = single_bundle(self, "ir9-block")
        target = os.path.join(bundle, "artifacts", "a.json")
        entry = self.HintingEntry("a.json", target)

        def refuse(path, *a, **kw):
            if os.path.abspath(path) == os.path.abspath(target):
                raise OSError(errno.EACCES, "Permission denied", path)
            return real_lstat(path, *a, **kw)

        real_lstat = ev.os.lstat
        self.addCleanup(setattr, ev.os, "lstat", real_lstat)
        ev.os.lstat = refuse
        with self.assertRaises(OSError):
            ev.entry_kind(entry)
        self.ck(entry.is_file(), "the enumeration-time hint answered cleanly")
        self.ck_eq(entry.is_symlink(), False)
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-entry-uninspectable")
        self.ck_in("kind could not be determined", exc.detail)

    def test_the_lookup_is_performed_for_every_enumerated_entry(self):
        """Not once per directory, and not only for entries the hint calls
        ambiguous: EVERY entry gets its own metadata call.
        """
        bundle = single_bundle(self, "ir9-block-every")
        seen = []
        real_lstat = ev.os.lstat
        self.addCleanup(setattr, ev.os, "lstat", real_lstat)

        def recording(path, *a, **kw):
            seen.append(os.path.basename(path))
            return real_lstat(path, *a, **kw)

        ev.os.lstat = recording
        manifest = ev.validate_manifest(*ev.load_manifest_identity(bundle)[:2])
        ev.stage_traversal(bundle, manifest)
        for name in ("a.json", "bindings.json", "independence.json",
                     "revocation.json", "artifacts", "operator"):
            self.ck_in(name, seen,
                       "no no-follow lookup was performed for %r" % name)

    def test_a_symlink_is_observable_because_the_lookup_does_not_follow(self):
        bundle = single_bundle(self, "ir9-block-link")
        os.symlink(os.path.join(bundle, "artifacts", "a.json"),
                   os.path.join(bundle, "artifacts", "link.json"))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")
        self.ck_in("symbolic link", exc.detail)

    def test_an_ordinary_bundle_still_classifies_clean(self):
        bundle = single_bundle(self, "ir9-block-clean")
        manifest = ev.validate_manifest(*ev.load_manifest_identity(bundle)[:2])
        self.ck_eq(sorted(ev.stage_traversal(bundle, manifest)),
                   ["artifacts/a.json", "operator/bindings.json",
                    "operator/independence.json", "operator/revocation.json"])

    @unittest.skipIf(os.name != "posix", "POSIX permission bits")
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "euid 0 bypasses permission bits, so the state under test "
                     "cannot be constructed")
    def test_the_real_filesystem_state_the_ruling_was_measured_on(self):
        """The ``0o444`` case from the ruling's own evidence record: readable but
        not searchable. Skipped -- reported as a SKIP, never as a pass -- where
        euid 0 makes the state unconstructible.
        """
        bundle = single_bundle(self, "ir9-block-real")
        inner = os.path.join(bundle, "artifacts")
        os.chmod(inner, 0o444)
        self.addCleanup(os.chmod, inner, 0o755)
        exc = self.nonmeasurement(bundle)
        self.ck_in(exc.reason,
                   ("bundle-entry-uninspectable", "bundle-directory-unreadable"))


# --------------------------------------------------------------------------
# W1-BLK-IR10 -- run validity evaluated before tier withheld, on a bundle where
# BOTH are live
# --------------------------------------------------------------------------

class BlockIR10(BlockCase):
    BLOCK = "W1-BLK-IR10"

    def both_live(self):
        """``artifacts/a.json`` (``z-decision``) is FIRST in ``AD15-IR-12``
        order and exits 0 carrying a non-empty ``authenticated_withheld``
        channel -- so 7.1 is live. ``artifacts/b.json`` is SECOND and exits 2 --
        so 7.2 is live too, on the same bundle.

        The order matters: putting the fatal run first would abort before the
        withheld channel was ever observed, and the test would then prove the
        ordering by accident rather than by rule.
        """
        return StubVerifier(by_record={
            "z-decision": (0, verdict("z-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-binding-missing"])),
            "y-control": (2, None),
        }, default=(0, None))

    def test_the_error_outcome_is_reported_not_measurement_invalid(self):
        root = os.path.join(self.root, "ir10-block")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        exc = self.nonmeasurement(bundle, self.both_live())
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq(exc.status, "ERROR")
        self.ck_ne(exc.reason, "authenticated-withheld")
        self.ck_ne(exc.status, "MEASUREMENT_INVALID")

    def test_the_withheld_channel_really_was_live_on_that_bundle(self):
        """Without this the previous case could pass because the withheld
        channel was never populated at all, which would make the ordering
        untested rather than proved.
        """
        root = os.path.join(self.root, "ir10-block-b")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        exc = self.nonmeasurement(bundle, self.both_live())
        channels = [w["channel"] for w in exc.withheld_reasons]
        self.ck_in("authenticated_withheld", channels,
                   "the 7.1 condition was not live on this bundle")
        self.ck_eq([w["reason"] for w in exc.withheld_reasons],
                   ["producer-binding-missing"])

    def test_a_malformed_withheld_channel_is_never_laundered_into_accept(self):
        """Contract 7.1: "ANY EMITTED FROZEN-VERIFIER VERDICT carrying a
        non-empty ``authenticated_withheld`` channel makes the scenario
        `MEASUREMENT_INVALID`" -- and withheld "is the ABSENCE of a measurement
        … it must never be laundered into a positive Level-1 result".

        The channel here is non-empty but its elements are OBJECTS, not registry
        reason strings. Reading the 7.1 condition off the REPORTED
        ``withheld_reasons`` array -- which only carries string reasons -- made
        the array empty and the scenario came out ``MEASURED`` / ``ACCEPT``: the
        exact laundering 7.1 forbids, produced by testing a projection instead
        of the thing projected.

        Two independent gates now close it, and either alone is sufficient.
        """
        bundle = single_bundle(self, "ir10-block-e")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision", klass="AIREP-Core"),
                                   authenticated_withheld=[{"code": "x"}]))})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_ne(exc.reason, None)
        self.ck_in(exc.reason, ("verifier-run-invalid", "authenticated-withheld"))
        self.ck_ne(exc.status, "MEASURED")

    def test_the_frozen_shape_gate_refuses_a_non_string_reason(self):
        """The first of the two gates, isolated. Frozen contract 2 makes each
        channel a SORTED SET OF REGISTRY REASON STRINGS, so a non-string element
        is a wrong-shape verdict -- E2-2's case, ``verifier-run-invalid``.
        """
        for channel in ("authenticated_withheld", "witnessed_withheld",
                        "authenticated_failures"):
            bad = dict(verdict("a-decision"))
            bad[channel] = [17]
            self.ck(ev._wrong_shape(bad) is not None, channel)
        self.ck_none(ev._wrong_shape(verdict("a-decision")))

    def test_the_7_1_condition_reads_the_verdict_not_the_reported_array(self):
        """The second gate, isolated. ``any_authenticated_withheld`` DECIDES;
        ``withheld_reasons_from_entries`` REPORTS. A reporting projection can
        only ever be smaller than what it projects, so it must never be able to
        narrow a normative condition.
        """
        entries = [{"artifact_path": "artifacts/a.json",
                    "verifier_result": dict(verdict("a-decision"),
                                            authenticated_withheld=[{"code": "x"}])}]
        self.ck_eq(ev.any_authenticated_withheld(entries), True)
        self.ck_eq(ev.withheld_reasons_from_entries(entries), [],
                   "the reporting projection is deliberately narrower")

    def test_a_clean_exit_0_with_withheld_alone_is_measurement_invalid(self):
        """The other half of the ordering: with no process fault anywhere, 7.1
        still fires. A rule that always reported ERROR would pass the first case
        for the wrong reason.
        """
        root = os.path.join(self.root, "ir10-block-c")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, verdict("z-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-binding-missing"]))},
            default=(0, None))
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "authenticated-withheld")
        self.ck_eq(exc.status, "MEASUREMENT_INVALID")

    def test_a_withheld_exit_0_does_not_abort_the_remaining_artifacts(self):
        """``AD15-IR-12``: "a clean exit-0 verdict never aborts, EVEN when it
        carries a non-empty ``authenticated_withheld`` channel" -- under
        ``AD15-IR-10`` the remaining artifacts must still be evaluated for run
        validity before 7.1 is applied at all.
        """
        root = os.path.join(self.root, "ir10-block-d")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, verdict("z-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-binding-missing"]))},
            default=(0, None))
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(len(stub.calls), 4)
        self.ck_eq(len(exc.artifacts), 4)


# --------------------------------------------------------------------------
# W1-BLK-IR11 -- a spawn failure contributes no entry while earlier entries are
# retained
# --------------------------------------------------------------------------

class BlockIR11(BlockCase):
    BLOCK = "W1-BLK-IR11"

    def spawn_fails_on(self, path_suffix):
        def invoke(request, flags):
            envelope = json.loads(request.decode("utf-8"))
            if envelope["artifact"].get("record_id") == path_suffix:
                raise ev.NonMeasurement(
                    "verifier-not-invocable",
                    "frozen verifier could not be executed: synthetic")
            return 0, json.dumps(
                verdict(envelope["artifact"].get("record_id"))).encode("utf-8"), b""
        return invoke

    def test_the_failing_artifact_contributes_no_entry(self):
        root = os.path.join(self.root, "ir11-block")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        # AD15-IR-12 order is a,b,c,d -> record ids z,y,x,w. Fail on the SECOND.
        exc = self.nonmeasurement(bundle, self.spawn_fails_on("y-control"))
        self.ck_eq(exc.reason, "verifier-not-invocable")
        self.ck_eq([e["artifact_path"] for e in exc.artifacts],
                   ["artifacts/a.json"])

    def test_no_entry_carries_a_fabricated_exit_code_verdict_or_digest(self):
        root = os.path.join(self.root, "ir11-block-b")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        exc = self.nonmeasurement(bundle, self.spawn_fails_on("y-control"))
        self.ck_eq(len(exc.artifacts), 1)
        for entry in exc.artifacts:
            self.ck(isinstance(entry["verifier_exit_code"], int))
            self.ck(isinstance(entry["verifier_result"], dict))
        paths = [e["artifact_path"] for e in exc.artifacts]
        for absent in ("artifacts/b.json", "artifacts/c.json", "artifacts/d.json"):
            self.ck(absent not in paths,
                    "an entry was fabricated for %r" % absent)

    def test_a_first_call_spawn_failure_yields_an_empty_array(self):
        root = os.path.join(self.root, "ir11-block-c")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        exc = self.nonmeasurement(bundle, self.spawn_fails_on("z-decision"))
        self.ck_eq(exc.artifacts, [])

    def test_a_started_process_that_misbehaves_does_contribute_an_entry(self):
        """The boundary. A concrete process result exists, so the entry is owed
        -- unlike a process that never started.
        """
        root = os.path.join(self.root, "ir11-block-d")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        exc = self.nonmeasurement(bundle, StubVerifier(default=(2, None)))
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq([e["artifact_path"] for e in exc.artifacts],
                   ["artifacts/a.json"])

    def test_the_real_seam_maps_a_spawn_failure_to_verifier_not_invocable(self):
        original = ev.sys.executable
        ev.sys.executable = os.path.join(self.root, "no such interpreter")
        self.addCleanup(setattr, ev.sys, "executable", original)
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev.invoke_frozen_verifier(b"{}", [])
        self.ck_eq(ctx.exception.reason, "verifier-not-invocable")


# --------------------------------------------------------------------------
# W1-BLK-IR12 -- invocation order, and the abort at the first fatal run
# --------------------------------------------------------------------------

class BlockIR12(BlockCase):
    BLOCK = "W1-BLK-IR12"

    def four(self, sub, scenario="IOP-R-CLEAN"):
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        return write_bundle(root, scenario, ordered_four())

    def test_invocations_proceed_in_artifact_path_byte_order(self):
        """The fixture makes ``record_id`` rank the EXACT REVERSE of
        ``artifact_path`` rank, so the assertion cannot pass under the wrong
        key. Under ``artifact_path`` the call order is z, y, x, w; under
        ``record_id`` it would be w, x, y, z.
        """
        stub = StubVerifier()
        self.evaluate(self.four("ir12-order"), stub)
        self.ck_eq([call[0] for call in stub.calls],
                   ["z-decision", "y-control", "x-execution", "w-effect"])

    def test_the_result_entries_carry_the_same_order(self):
        result = self.evaluate(self.four("ir12-order-b"), StubVerifier())
        self.ck_eq([e["artifact_path"] for e in result["artifacts"]],
                   ["artifacts/a.json", "artifacts/b.json",
                    "artifacts/c.json", "artifacts/d.json"])

    def test_a_run_invalid_contributes_its_entry_then_aborts(self):
        """The worked case, now single-valued. ``[A]``, ``[C, D]`` and
        ``[A, C, D]`` were all conforming before this ruling.
        """
        stub = StubVerifier(by_record={"y-control": (2, None)}, default=(0, None))
        exc = self.nonmeasurement(self.four("ir12-abort"), stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq([e["artifact_path"] for e in exc.artifacts],
                   ["artifacts/a.json", "artifacts/b.json"])
        self.ck_eq([call[0] for call in stub.calls],
                   ["z-decision", "y-control"],
                   "the scenario did not abort at the first fatal run")

    def test_a_not_invocable_contributes_no_entry_then_aborts(self):
        def invoke(request, flags):
            envelope = json.loads(request.decode("utf-8"))
            if envelope["artifact"].get("record_id") == "y-control":
                raise ev.NonMeasurement("verifier-not-invocable", "synthetic")
            return 0, json.dumps(
                verdict(envelope["artifact"].get("record_id"))).encode("utf-8"), b""
        exc = self.nonmeasurement(self.four("ir12-abort-b"), invoke)
        self.ck_eq(exc.reason, "verifier-not-invocable")
        self.ck_eq([e["artifact_path"] for e in exc.artifacts],
                   ["artifacts/a.json"])

    def test_a_rejected_exit_0_shape_also_contributes_its_entry_then_aborts(self):
        """The correction to this lane: the pre-erratum decoder raised BEFORE
        the entry was appended, so a malformed ``exit 0`` produced no entry for
        a process that had plainly produced a concrete result.
        """
        stub = StubVerifier(by_record={"y-control": (0, b"not json at all")},
                            default=(0, None))
        exc = self.nonmeasurement(self.four("ir12-abort-c"), stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq([e["artifact_path"] for e in exc.artifacts],
                   ["artifacts/a.json", "artifacts/b.json"])
        self.ck_none(exc.artifacts[-1]["verifier_result"])

    def test_a_clean_exit_0_never_aborts(self):
        stub = StubVerifier()
        result = self.evaluate(self.four("ir12-noabort"), stub)
        self.ck_eq(result["measurement_status"], "MEASURED")
        self.ck_eq(len(stub.calls), 4)


# --------------------------------------------------------------------------
# W1-BLK-IR13 -- stage barriers on a multi-fault bundle, and the comparison key
# including the conditional `json_pointer` component
# --------------------------------------------------------------------------

def wrong_digest_for(*paths):
    def override(manifest):
        for entry in manifest["files"]:
            if entry["path"] in paths:
                entry["sha256"] = "0" * 64
        return manifest
    return override


class BlockIR13(BlockCase):
    BLOCK = "W1-BLK-IR13"

    #: A four-artifact bundle gives four listed artifact files plus three
    #: operator inputs, so several independent faults can be planted at once.
    def multi(self, sub, drop=(), unreadable=(), bad_digest=(), raw=None,
              vanish=()):
        """``vanish`` names files that are PRESENT ON DISK at stage 5 and give a
        DEFINITE ``ENOENT`` when stage 6 reads them -- the E8-2 case, which no
        permission fixture can construct portably.
        """
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        bundle = write_bundle(
            root, "IOP-R-CLEAN", four_artifacts(),
            drop_from_disk=drop, raw_files=raw,
            manifest_overrides=wrong_digest_for(*bad_digest) if bad_digest else None)
        if unreadable or vanish:
            real = ev.read_bundle_file

            def refusing(full_path):
                for rel in vanish:
                    if full_path.endswith(os.path.join(*rel.split("/"))):
                        raise OSError(errno.ENOENT,
                                      "No such file or directory", full_path)
                for rel in unreadable:
                    if full_path.endswith(os.path.join(*rel.split("/"))):
                        raise OSError(errno.EACCES, "Permission denied", full_path)
                return real(full_path)

            _seam(self, "read_bundle_file", refusing)
        return bundle

    # ---- E8-2: stage 6 carries TWO reasons, in that order -------------------

    def test_e8_2_a_definite_enoent_on_read_is_missing_not_unreadable(self):
        """E8-2, and the reason Erratum 8 exists. Both lanes' self-tests were
        entirely green -- 347 and 1683 checks, zero failures, zero skips -- and
        they still emitted DIFFERENT Class-1 ``nonmeasurement.reason`` values for
        the same filesystem state: a listed file PRESENT AT STAGE 5 and GONE
        BEFORE STAGE 6. One lane followed 8.2.2's boundary ("a definite
        ``ENOENT`` on read" is missing); the other followed 8.6's stage-6 row,
        which named only ``bundle-file-unreadable``.

        The file is on disk here, so stage 5's presence check passes and the
        divergence is reached at the read -- which is the whole point.
        """
        bundle = self.multi("ir13-e8-2-a", vanish=("artifacts/effect.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing",
                   "a definite ENOENT on READ was reported as unreadable")
        self.ck_in("artifacts/effect.json", exc.detail)

    def test_e8_2_missing_outranks_unreadable_within_stage_6(self):
        """"Where both are live within stage 6, ``bundle-file-missing``
        OUTRANKS ``bundle-file-unreadable``."

        Mechanism must beat path, so the fixture puts the ENOENT on the
        LATER-SORTING path: ``artifacts/effect.json`` sorts after
        ``artifacts/control.json``. A lane ordering by path alone reports
        ``bundle-file-unreadable`` here and fails.
        """
        bundle = self.multi("ir13-e8-2-b",
                            vanish=("artifacts/effect.json",),
                            unreadable=("artifacts/control.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_in("artifacts/effect.json", exc.detail)

    def test_e8_2_an_unreadable_file_alone_is_still_unreadable(self):
        """The acceptance control. Without it the two cases above would also
        pass on a lane that reported ``bundle-file-missing`` for EVERY stage-6
        failure, which says something false about the medium.
        """
        bundle = self.multi("ir13-e8-2-c",
                            unreadable=("artifacts/control.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-unreadable")
        self.ck_in("artifacts/control.json", exc.detail)

    def test_e8_2_stage_5_absence_still_outranks_a_stage_6_enoent(self):
        """The two mechanisms share a reason but not a stage. A file absent at
        stage 5 is reported over one that vanishes at stage 6, because the
        stage barrier is fixed before any within-stage rank applies.
        """
        bundle = self.multi("ir13-e8-2-d",
                            drop=("operator/revocation.json",),
                            vanish=("artifacts/decision.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_in("operator/revocation.json", exc.detail)

    def test_a_missing_file_outranks_an_unreadable_one_and_a_bad_digest(self):
        """Stage 5 before stage 6 before stage 7. The pre-erratum construction
        validated each listed path END-TO-END in manifest order, so this bundle
        reported whichever fault its first-listed path carried.
        """
        bundle = self.multi(
            "ir13-a",
            drop=("artifacts/effect.json",),
            unreadable=("artifacts/control.json",),
            bad_digest=("artifacts/decision.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_in("artifacts/effect.json", exc.detail)

    def test_the_presence_check_belongs_to_stage_5_not_to_the_read(self):
        """Stage 5 establishes PRESENCE over the whole bundle; stage 6 then
        reads. A lane that discovered absence only at open() time would report
        the same reason here for the wrong structural reason, so the barrier is
        bound by pairing an ABSENT file with an UNREADABLE one: stage 5's reason
        must win even though the read of the absent file never happens.
        """
        bundle = self.multi("ir13-p",
                            drop=("operator/revocation.json",),
                            unreadable=("artifacts/control.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_in("operator/revocation.json", exc.detail)

    def test_an_unreadable_file_outranks_a_bad_digest(self):
        bundle = self.multi(
            "ir13-b",
            unreadable=("artifacts/effect.json",),
            bad_digest=("artifacts/decision.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-unreadable")
        self.ck_in("artifacts/effect.json", exc.detail)

    def test_a_bad_digest_outranks_an_unparseable_document(self):
        """Stage 7 before stage 8: the digest of the LAST-ordered file
        disagrees while a DIFFERENT, earlier file will not parse. Reporting the
        parse failure would mean stage 8 had begun before stage 7 finished.
        """
        bundle = self.multi(
            "ir13-c",
            raw={"artifacts/decision.json": (b"{ not json", "artifact")},
            bad_digest=("operator/revocation.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-digest-mismatch")
        self.ck_in("operator/revocation.json", exc.detail)

    def test_within_a_stage_the_ascending_path_is_selected(self):
        """Two digest mismatches, same stage, same reason: the ascending-first
        path decides, not manifest iteration order and not discovery order.
        """
        bundle = self.multi("ir13-d",
                            bad_digest=("operator/revocation.json",
                                        "artifacts/control.json"))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-digest-mismatch")
        self.ck_in("artifacts/control.json", exc.detail)

    def test_the_stage_9_worked_case_is_single_valued(self):
        """Contract 8.6's own worked case: a manifest with TWO
        ``independence_policy`` files (``bundle-shape-invalid``) AND a
        ``--bindings`` flag pointing at the revocation file
        (``operator-input-assertion-mismatch``) reports
        ``bundle-shape-invalid`` -- the bundle's own composition is settled
        before any assertion an operator makes ABOUT it.
        """
        root = os.path.join(self.root, "ir13-e")
        os.makedirs(root)
        operator = dict(OPERATOR_INPUTS)
        operator["operator/independence2.json"] = ({"policy": "second"},
                                                   "independence_policy")
        bundle = write_bundle(root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                              operator=operator)
        exc = self.nonmeasurement(
            bundle, bindings=os.path.join(bundle, "operator", "revocation.json"))
        self.ck_eq(exc.reason, "bundle-shape-invalid")
        self.ck_ne(exc.reason, "operator-input-assertion-mismatch")

    def test_the_stage_9_mismatch_alone_is_still_reported(self):
        """Without this the previous case could pass because the assertion
        mismatch was never detectable at all.
        """
        bundle = single_bundle(self, "ir13-f")
        exc = self.nonmeasurement(
            bundle, bindings=os.path.join(bundle, "operator", "revocation.json"))
        self.ck_eq(exc.reason, "operator-input-assertion-mismatch")

    def test_the_json_pointer_component_orders_two_faults_in_one_file(self):
        """The CONDITIONAL FOURTH component of the comparison key. Two numbers
        in the same artifact both outside 5.1's envelope share a stage, a reason
        AND a path; ``numeric-preflight-violation`` is the one reason 8.2.2
        permits a ``json_pointer`` on, so the pointer is the only observable
        thing left to order them by.
        """
        root = os.path.join(self.root, "ir13-g")
        os.makedirs(root)
        raw = (b'{"airep_version":"0.2","artifact_type":"decision",'
               b'"chain_id":"c","record_id":"r","sequence":1,'
               b'"profiles":{"zeta":1e400,"alpha":1e400}}')
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (raw, "artifact")})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "numeric-preflight-violation")
        self.ck_eq(exc.json_pointer, "/profiles/alpha")

    def test_the_pointer_order_is_bytes_not_numeric_indices(self):
        """"Byte order, not numeric order: ``/a/10`` sorts before ``/a/9``
        because ``1`` precedes ``9`` as a byte. That is deliberate." A rule that
        compared array indices numerically would have to parse them, which
        invites the two lanes to disagree about what is an index.
        """
        root = os.path.join(self.root, "ir13-h")
        os.makedirs(root)
        slots = ["0"] * 11
        slots[9] = "1e400"
        slots[10] = "1e400"
        raw = (b'{"airep_version":"0.2","artifact_type":"decision",'
               b'"chain_id":"c","record_id":"r","sequence":1,'
               b'"profiles":{"a":[' + ",".join(slots).encode("ascii") + b']}}')
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (raw, "artifact")})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.json_pointer, "/profiles/a/10")

    def test_the_pointer_key_beats_traversal_order(self):
        """A depth-first walk over sorted member names yields pointers in
        ascending byte order for almost every document, so almost every fixture
        would pass under "the first one I encountered" too. This one cannot:
        the object member ``a`` sorts BEFORE ``a!`` (so traversal descends into
        ``a`` first), while the pointer ``/a!`` sorts BEFORE ``/a/b`` (because
        ``!`` precedes ``/`` as a byte). A test that passes with and without the
        fix is not a test.
        """
        root = os.path.join(self.root, "ir13-k")
        os.makedirs(root)
        raw = (b'{"airep_version":"0.2","artifact_type":"decision",'
               b'"chain_id":"c","record_id":"r","sequence":1,'
               b'"profiles":{"a":{"b":1e400},"a!":1e400}}')
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (raw, "artifact")})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.json_pointer, "/profiles/a!")
        self.ck_ne(exc.json_pointer, "/profiles/a/b")

    def test_the_pointer_is_rooted_at_the_file_never_at_the_envelope(self):
        """E7-19. The check happens before any envelope exists, and the two
        bases give different NORMATIVE strings for the same violation --
        ``/profiles/x`` against the artifact versus ``/artifact/profiles/x``
        against the envelope. ``json_pointer`` is a Class-1 field.
        """
        root = os.path.join(self.root, "ir13-i")
        os.makedirs(root)
        raw = (b'{"airep_version":"0.2","artifact_type":"decision",'
               b'"chain_id":"c","record_id":"r","sequence":1,'
               b'"profiles":{"x":1e400}}')
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (raw, "artifact")})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.json_pointer, "/profiles/x")
        self.ck(not exc.json_pointer.startswith("/artifact/"))

    def test_no_frozen_verifier_is_invoked_during_preflight(self):
        """Contract 8.3.1 rule 1: no frozen verifier is invoked until EVERY
        preflight stage has passed, so a preflight failure is a PRE-INVOCATION
        error carrying ``artifacts: []``.
        """
        bundle = self.multi("ir13-j", bad_digest=("artifacts/decision.json",))
        stub = StubVerifier()
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(stub.calls, [])
        self.ck_eq(exc.artifacts, [])



    # ---- branch 1: EVERY stage barrier at which two faults both apply ------

    def result_of(self, bundle, stub=None, extra=()):
        """The emitted result object, via the CLI, so the exit band is measured
        alongside the reason.
        """
        code, out, _err = self.run_cli(bundle, extra=extra,
                                       stub=stub or StubVerifier())
        return code, (json.loads(out) if out.strip() else None)

    def test_barrier_2_before_3_identity_beats_frozen_identity(self):
        """Stage 2 is the exit-1 band. A bundle with no root ``manifest.json``
        AND an unreadable frozen file yields exit 1 with EMPTY STDOUT -- the
        frozen-identity read never happens, because it is pinned to run
        IMMEDIATELY AFTER identity, not before it.
        """
        empty = os.path.join(self.root, "ir13-b23", "bundle")
        os.makedirs(empty)
        _seam(self, "read_frozen_file",
              lambda path: (_ for _ in ()).throw(
                  OSError(errno.EACCES, "Permission denied", path)))
        code, result = self.result_of(empty)
        self.ck_eq(code, 1)
        self.ck_none(result, "the exit-1 band emitted a result object")

    def test_barrier_3_before_4_frozen_digest_beats_manifest_structure(self):
        def unsorted(manifest):
            manifest["files"] = list(reversed(manifest["files"]))
            return manifest

        root = os.path.join(self.root, "ir13-b34")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts(),
                              manifest_overrides=unsorted)
        real = ev.read_frozen_file
        _seam(self, "read_frozen_file",
              lambda path: real(path) + b"\n# drift\n")
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "verifier-digest-mismatch")

    def test_barrier_4_before_5_manifest_closure_beats_a_missing_file(self):
        def bad_role(manifest):
            manifest["files"][0]["role"] = "not-a-role"
            return manifest

        root = os.path.join(self.root, "ir13-b45")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts(),
                              manifest_overrides=bad_role,
                              drop_from_disk=("artifacts/effect.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")

    def test_barrier_8_before_9_bad_json_beats_a_shape_violation(self):
        """An unparseable OPERATOR input (stage 8) on a bundle whose artifact
        count is also wrong for its scenario (stage 9).
        """
        root = os.path.join(self.root, "ir13-b89")
        os.makedirs(root)
        bundle = write_bundle(
            root, "IOP-R-CLEAN", {"artifacts/a.json": DECISION},
            raw_files={"operator/bindings.json": (b"{ not json", "bindings")},
            operator={"operator/independence.json":
                      ({"policy": "s"}, "independence_policy"),
                      "operator/revocation.json": ({"revoked": []}, "revocation")})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-json-invalid")

    def test_barrier_9_before_10_shape_beats_the_numeric_preflight(self):
        root = os.path.join(self.root, "ir13-b910")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN",
                              {"artifacts/a.json":
                               dict(DECISION, profiles={"x": 10 ** 20})})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-shape-invalid")

    def test_barrier_10_before_11_numeric_preflight_beats_any_invocation(self):
        """"NO FROZEN VERIFIER IS INVOKED UNTIL EVERY PREFLIGHT STAGE HAS
        PASSED", so a stage-10 failure is reported even though stage 11 would
        have failed too -- and the verifier is never called at all.
        """
        root = os.path.join(self.root, "ir13-b1011")
        os.makedirs(root)
        arts = four_artifacts(decision={"profiles": {"x": 10 ** 20}})
        bundle = write_bundle(root, "IOP-R-CLEAN", arts)

        def never_starts(request, flags):
            raise ev.NonMeasurement("verifier-not-invocable", "synthetic")

        exc = self.nonmeasurement(bundle, never_starts)
        self.ck_eq(exc.reason, "numeric-preflight-violation")
        self.ck_eq(exc.json_pointer, "/profiles/x")
        self.ck_eq(exc.artifacts, [])

    def test_barrier_11_before_12_run_validity_beats_tier_withheld(self):
        """``AD15-IR-10``: where an ERROR-class run invalidity and an
        ``authenticated_withheld`` channel both apply to one bundle, the ERROR
        outcome is reported. A verifier that misbehaved AS A PROCESS cannot be
        trusted to have produced a meaningful withheld channel either.
        """
        root = os.path.join(self.root, "ir13-b1112")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, verdict("z-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-binding-missing"])),
            "y-control": (2, None)})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_ne(exc.reason, "authenticated-withheld")

    # ---- branch 3: MECHANISM BEFORE PATH ----------------------------------

    def test_mechanism_beats_path_across_a_barrier(self):
        """An earlier-ranked reason on a LATER-SORTING path still wins. The
        missing file sorts last of the bundle's artifacts; the digest mismatch
        sorts first.
        """
        bundle = self.multi("ir13-mech",
                            drop=("artifacts/effect.json",),
                            bad_digest=("artifacts/control.json",))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_in("artifacts/effect.json", exc.detail)

    # ---- branch 5: same-reason selection does not move the projection ------

    def test_same_reason_selection_does_not_move_the_projection(self):
        """"Given two same-stage, same-reason failures, the 8.7 PROJECTION is
        identical whichever the evaluator selects."

        The block asserts that invariance ON THE PROJECTION ONLY. ``detail`` is
        Class 4 and MAY legitimately name whichever failure was selected, so
        requiring the whole emitted result to be identical would narrow the same
        freedom one level down (E8-14). The block NEVER asserts WHICH failure
        was chosen: ``AD15-IR-13`` says an evaluator MAY SELECT EITHER (E8-13).
        """
        one = self.multi("ir13-sel-1", drop=("artifacts/control.json",))
        two = self.multi("ir13-sel-2", drop=("artifacts/effect.json",))
        both = self.multi("ir13-sel-3",
                          drop=("artifacts/control.json", "artifacts/effect.json"))
        projections = []
        for bundle in (one, two, both):
            _code, result = self.result_of(bundle)
            projections.append(ev.projection_bytes(ev.normative_projection(result)))
        self.ck_eq(projections[0], projections[1],
                   "two same-reason selections moved the parity surface")
        self.ck_eq(projections[0], projections[2])

    def test_the_diagnostic_detail_may_name_either_selection(self):
        """The other half of E8-14: ``detail`` is Class 4, so a lane naming the
        selected path there is NOT a divergence. Asserted as PERMISSION, never
        as a requirement to pick one.
        """
        both = self.multi("ir13-sel-4",
                          drop=("artifacts/control.json", "artifacts/effect.json"))
        _code, result = self.result_of(both)
        detail = result["nonmeasurement"]["detail"]
        self.ck(any(name in detail for name in
                    ("artifacts/control.json", "artifacts/effect.json")),
                "detail named neither candidate")
        self.ck("detail" not in ev.normative_projection(result)
                .get("nonmeasurement", {}),
                "detail reached the parity surface")

    # ---- branch 6: stage 11's SEQUENTIAL exception -------------------------

    def test_stage_11_is_sequential_so_no_tie_break_arises(self):
        """"Artifact invocation is SEQUENTIAL in AD15-IR-12's order and STOPS AT
        THE FIRST FATAL RUN, so the reported reason is whichever fatal run is
        REACHED FIRST. No comparison between reasons arises."

        Both artifacts here are fatal, in DIFFERENT ways. The one that sorts
        first by ``artifact_path`` decides, and the second is never invoked.
        """
        root = os.path.join(self.root, "ir13-s11")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (2, None),                    # artifacts/a.json
            "y-control": (0, b"not json")})             # artifacts/b.json
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_in("artifacts/a.json", exc.detail)
        self.ck_eq(len(exc.artifacts), 1, "the scenario did not stop at the first")
        self.ck_eq(len(stub.calls), 1, "a later artifact was invoked anyway")

    # ---- branch 7: stage-4 manifest closure vs stage-5 filesystem closure ---

    def test_stage_4_manifest_closure_is_reported_before_the_disk_is_consulted(self):
        """"A manifest that is malformed ON ITS OWN TERMS is reported BEFORE THE
        DISK IS CONSULTED." Discriminated by making the disk unenumerable: a
        lane consulting the filesystem first would report
        ``bundle-directory-unreadable``.
        """
        def unknown_member(manifest):
            manifest["iop_unknown"] = True
            return manifest

        root = os.path.join(self.root, "ir13-s45a")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts(),
                              manifest_overrides=unknown_member)
        _seam(self, "scan_directory",
              lambda path: (_ for _ in ()).throw(
                  OSError(errno.EACCES, "Permission denied", path)))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")

    def test_stage_5_filesystem_closure_produces_the_same_reason(self):
        """The other side of the deliberate split: an UNLISTED entry on disk is
        also ``manifest-invalid``, but it is a stage-5 finding.
        """
        root = os.path.join(self.root, "ir13-s45b")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts(),
                              extra_disk_files={"artifacts/stray.json": b"{}"})
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")
        self.ck_in("stray.json", exc.detail)

    # ---- branch 8: DETERMINISTIC SORTED TRAVERSAL --------------------------

    def test_the_reported_failure_does_not_change_with_enumeration_order(self):
        """"``readdir`` order is unspecified and varies by filesystem, so a lane
        reporting the first failure in ENUMERATION ORDER is not deterministic.
        Every directory's entries are SORTED before that directory is inspected
        or descended into."

        Two unlisted entries are planted, and the OS enumeration is reversed on
        the second run. The reported failure must be identical.
        """
        seen = []
        for index, reverse in enumerate((False, True)):
            root = os.path.join(self.root, "ir13-trav-%d" % index)
            os.makedirs(root)
            bundle = write_bundle(
                root, "IOP-R-CLEAN", four_artifacts(),
                extra_disk_files={"artifacts/aaa-stray.json": b"{}",
                                  "artifacts/zzz-stray.json": b"{}"})
            real = ev.scan_directory
            _seam(self, "scan_directory",
                  lambda path, _r=reverse, _real=real:
                  list(reversed(_real(path))) if _r else _real(path))
            exc = self.nonmeasurement(bundle)
            seen.append((exc.reason, exc.detail))
        self.ck_eq(seen[0], seen[1],
                   "the reported failure moved with OS enumeration order")

    # ---- branches 9 and 10: the NAME KEY, and a non-UTF-8 directory name ----

    def test_a_non_utf8_directory_name_is_an_unlisted_entry(self):
        """"A manifest ``path`` is a JSON STRING, so NO SUCH ENTRY CAN EVER BE
        LISTED in ``files[]``. It is reported by stage 5's layout closure as
        ``manifest-invalid``, exactly as any other unlisted entry is."
        """
        root = os.path.join(self.root, "ir13-nonutf8")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts())
        raw = os.path.join(bundle.encode("utf-8"),
                           b"artifacts", b"\xff\xfe-stray.json")
        try:
            with open(raw, "wb") as handle:
                handle.write(b"{}")
        except (OSError, ValueError) as exc:
            self.skipTest("this filesystem rejects a non-UTF-8 entry name: %s"
                          % exc)
        self.addCleanup(lambda: os.path.exists(raw) and os.remove(raw))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")

    def test_the_name_key_applies_no_normalization(self):
        """"NFC or NFD conversion, case folding, locale-dependent mapping and
        any platform-specific name normalization are FORBIDDEN." Two entry names
        that are NFC/NFD variants of each other are BYTE-DISTINCT and must both
        be seen as distinct unlisted entries -- a normalizing key would collide
        them.
        """
        root = os.path.join(self.root, "ir13-nonorm")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts())
        composed = "é-stray.json"          # NFC
        decomposed = "é-stray.json"       # NFD
        target = os.path.join(bundle, "artifacts")
        try:
            for name in (composed, decomposed):
                with open(os.path.join(target, name), "wb") as handle:
                    handle.write(b"{}")
        except OSError as exc:
            self.skipTest("this filesystem cannot hold both NFC and NFD names: %s"
                          % exc)
        names = set(os.listdir(target))
        if not {composed, decomposed} <= names:
            self.skipTest("this filesystem normalizes entry names, so the two "
                          "byte-distinct names cannot coexist")
        self.ck_eq(len({composed, decomposed} & names), 2,
                   "the platform collapsed two byte-distinct names")
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")

    def test_the_lossless_raw_bytes_name_key_branch_is_not_reachable_here(self):
        """Branch 9 is explicitly PER-PLATFORM: "a lane whose API yields only
        LOSSLESS RAW BYTES cannot construct the Unicode-native branch, AND VICE
        VERSA; the unreachable branch is recorded NOT_MEASURED on that platform
        rather than skipped silently or counted as covered."

        Python's ``os.scandir`` yields ``str`` names, decoded with
        ``surrogateescape`` -- the UNICODE-NATIVE branch, which the two cases
        above exercise. The raw-bytes branch is therefore NOT REACHABLE from
        this API, and is recorded as a REPORTED SKIP rather than counted as
        covered.
        """
        sample = os.listdir(self.root)
        self.ck(all(isinstance(name, str) for name in sample) or not sample,
                "os.listdir returned a non-str name on this platform")
        self.skipTest("NOT_MEASURED on this platform: os.scandir yields "
                      "Unicode-native str names, so the lossless-raw-bytes "
                      "name-key branch cannot be constructed here")

    # ---- branch 11: a manifest path with an UNPAIRED SURROGATE at stage 4 ---

    def test_a_manifest_path_with_an_unpaired_surrogate_is_stage_4(self):
        """"Strict JSON admits an escape such as ``\\ud800`` with no pair, which
        does not encode to well-formed UTF-8 and so cannot denote any filesystem
        name. It FAILS ON THE MANIFEST'S OWN TERMS, BEFORE THE DISK IS
        CONSULTED."
        """
        root = os.path.join(self.root, "ir13-surrogate")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", four_artifacts())
        manifest_path = os.path.join(bundle, "manifest.json")
        with open(manifest_path, encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["files"][0]["path"] = "artifacts/PLACEHOLDER-bad.json"
        raw = json.dumps(doc).replace("PLACEHOLDER", "\\ud800").encode("utf-8")
        with open(manifest_path, "wb") as handle:
            handle.write(raw)
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "manifest-invalid")

    # ---- branch 12: internal-error stays OUTSIDE the order -----------------

    def test_internal_error_never_masks_an_already_determined_failure(self):
        """"A stage that has produced its failure HAS PRODUCED THE REPORTED
        REASON, and a later fault does not replace it."

        A stage-5 failure is planted, and a LATER stage is made to fault. The
        stage-5 reason must survive.
        """
        bundle = self.multi("ir13-ie", drop=("artifacts/effect.json",))
        _seam(self, "stage_json",
              lambda manifest, contents: (_ for _ in ()).throw(
                  RuntimeError("synthetic later-stage fault")))
        exc = self.nonmeasurement(bundle)
        self.ck_eq(exc.reason, "bundle-file-missing")
        self.ck_ne(exc.reason, "internal-error")

    def test_internal_error_is_still_reported_when_nothing_preceded_it(self):
        """It is NOT a stage: it is raised wherever an unexpected fault occurs
        AFTER identity is established, and it still produces a result object
        naming the scenario rather than a crash the harness has to infer.
        """
        bundle = self.multi("ir13-ie2")
        _seam(self, "stage_json",
              lambda manifest, contents: (_ for _ in ()).throw(
                  RuntimeError("synthetic fault with no earlier failure")))
        code, result = self.result_of(bundle)
        self.ck_eq(code, 3)
        self.ck_eq(result["nonmeasurement"]["reason"], "internal-error")
        self.ck_eq(result["scenario_id"], "IOP-R-CLEAN")

# --------------------------------------------------------------------------
# W1-BLK-IR14 -- a post-identity operator assertion mismatch is result-bearing
# at exit 3
# --------------------------------------------------------------------------

class BlockIR14(BlockCase):
    BLOCK = "W1-BLK-IR14"

    def test_the_mismatch_is_exit_3_with_a_result_object(self):
        bundle = single_bundle(self, "ir14-a")
        code, out, _ = self.run_cli(bundle, ["--bindings", "/elsewhere/b.json"],
                                    stub=StubVerifier())
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_eq(result["nonmeasurement"]["reason"],
                   "operator-input-assertion-mismatch")
        self.ck_eq(result["measurement_status"], "ERROR")
        self.ck_eq(result["scenario_id"], "IOP-P-DEC")
        self.ck_none(result["level1"])
        self.ck_none(result["predicates"])

    def test_the_reason_pairs_with_error_in_the_closed_registry(self):
        self.ck_eq(ev.REASON_STATUS["operator-input-assertion-mismatch"], "ERROR")

    def test_a_cli_syntax_error_remains_exit_2_with_empty_stdout(self):
        """The other side of the line the ruling draws: a syntax error is
        detectable BEFORE anything is read, so it keeps the exit-2 band.
        """
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                ev.main(["--no-such-option", "x"])
        self.ck_eq(ctx.exception.code, 2)
        self.ck_eq(out.getvalue(), "")

    def test_a_missing_bundle_argument_remains_exit_2(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ev.main([])
        self.ck_eq(code, 2)
        self.ck_eq(out.getvalue(), "")

    def test_a_consistent_flag_changes_nothing_that_is_measured(self):
        bundle = single_bundle(self, "ir14-b")
        plain = self.evaluate(bundle, StubVerifier())
        flagged = self.evaluate(
            bundle, StubVerifier(),
            bindings=os.path.join(bundle, "operator", "bindings.json"))
        self.ck_eq(ev.projection_bytes(plain), ev.projection_bytes(flagged))


# --------------------------------------------------------------------------
# W1-BLK-IR15 -- the three process outcomes, distinguished
# --------------------------------------------------------------------------

class BlockIR15(BlockCase):
    BLOCK = "W1-BLK-IR15"

    def test_row_1_the_process_never_started(self):
        bundle = single_bundle(self, "ir15-a")

        def never_starts(request, flags):
            raise ev.NonMeasurement("verifier-not-invocable", "synthetic")

        exc = self.nonmeasurement(bundle, never_starts)
        self.ck_eq(exc.reason, "verifier-not-invocable")
        self.ck_eq(exc.artifacts, [])

    def test_row_2_started_and_did_not_exit_normally(self):
        """A FULL entry in which exactly two measurements are missing.
        "Abnormal termination is the absence of an EXIT CODE, not of a process
        ATTEMPT", so this is emphatically not the ``AD15-IR-11`` shape.
        """
        bundle = single_bundle(self, "ir15-b")

        def killed(request, flags):
            return None, b"", b"Killed\n"

        exc = self.nonmeasurement(bundle, killed)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq(len(exc.artifacts), 1)
        entry = exc.artifacts[0]
        self.ck_eq(entry["artifact_path"], "artifacts/a.json")
        self.ck_eq(entry["artifact_ref"],
                   {"record_id": "a-decision", "chain_id": "chain-synthetic"})
        self.ck(entry["request_envelope_digest"].startswith("sha256:"))
        self.ck_none(entry["verifier_exit_code"])
        self.ck_none(entry["verifier_result"])
        self.ck_eq(entry["verifier_stderr_digest"],
                   "sha256:" + hexdigest(b"Killed\n"))

    def test_row_3_exited_normally(self):
        bundle = single_bundle(self, "ir15-c")
        entry = self.evaluate(bundle, StubVerifier())["artifacts"][0]
        self.ck_eq(entry["verifier_exit_code"], 0)
        self.ck(isinstance(entry["verifier_result"], dict))

    def test_row_3_exit_1_and_exit_2_both_emit_no_verdict(self):
        bundle = single_bundle(self, "ir15-d", scenario="IOP-B-DEC")
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.ck_eq(entry["verifier_exit_code"], 1)
        self.ck_none(entry["verifier_result"])
        exc = self.nonmeasurement(single_bundle(self, "ir15-e"),
                                  StubVerifier(default=(2, None)))
        self.ck_eq(exc.artifacts[0]["verifier_exit_code"], 2)
        self.ck_none(exc.artifacts[0]["verifier_result"])

    def test_no_signal_reaches_any_normative_field(self):
        """"No signal name, signal number or synthesized exit code appears in
        ANY normative field" -- not ``verifier_exit_code``, not
        ``verifier_result``, and not any other entry field or ``nonmeasurement``
        member EXCEPT ``detail``, which 8.7 places in Class 4.
        """
        bundle = single_bundle(self, "ir15-f")

        def killed(request, flags):
            return None, b"", b"SIGKILL\n"

        code, out, _ = self.run_cli(bundle, stub=killed)
        self.ck_eq(code, 3)
        result = json.loads(out)
        detail = result["nonmeasurement"].pop("detail")
        blob = json.dumps(result)
        for token in ("SIGKILL", "SIGSEGV", "signal", "-9", "9 ", "killed"):
            self.ck(token.lower() not in blob.lower(),
                    "%r reached a normative field: %s" % (token, blob))
        self.ck(isinstance(detail, str))

    def test_the_real_seam_translates_signal_death_to_a_null_exit_code(self):
        """The translation is measured on the REAL subprocess seam, not only on
        a stub that returns the value the test wants to see. CPython encodes
        POSIX signal death as a NEGATIVE returncode; that is a runtime
        convention, not a contract value.
        """
        completed = subprocess.CompletedProcess(args=[], returncode=-9,
                                                stdout=b"", stderr=b"boom")
        _seam(self, "subprocess", ev.subprocess)
        real_run = ev.subprocess.run
        self.addCleanup(setattr, ev.subprocess, "run", real_run)
        ev.subprocess.run = lambda *a, **kw: completed
        code, stdout, stderr = ev.invoke_frozen_verifier(b"{}", [])
        self.ck_none(code)
        self.ck_eq(stderr, b"boom")

    @unittest.skipIf(os.name != "posix", "POSIX signals")
    def test_a_genuinely_signal_killed_child_is_row_2(self):
        """End to end against a real child process that really dies by signal,
        so the translation is not merely asserted against a fabricated
        ``CompletedProcess``.
        """
        script = os.path.join(self.root, "suicide.py")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("import os, signal\n"
                         "os.kill(os.getpid(), signal.SIGKILL)\n")
        _seam(self, "frozen_verifier_path", lambda: script)
        code, stdout, stderr = ev.invoke_frozen_verifier(b"{}", [])
        self.ck_none(code, "a signal-killed child did not yield a null exit code")


# --------------------------------------------------------------------------
# W1-BLK-IR16 -- `withheld_reasons` present unconditionally as [], and the
# pinned entry shape and order
# --------------------------------------------------------------------------

class BlockIR16(BlockCase):
    BLOCK = "W1-BLK-IR16"

    def test_it_is_emitted_unconditionally_as_an_empty_array(self):
        bundle = single_bundle(self, "ir16-a")
        result = self.evaluate(bundle, StubVerifier())
        self.ck_eq(result["withheld_reasons"], [])

    def test_a_pre_invocation_error_still_carries_the_member(self):
        bundle = single_bundle(self, "ir16-b", drop_from_disk=("artifacts/a.json",))
        result = json.loads(self.run_cli(bundle)[1])
        self.ck_eq(result["withheld_reasons"], [])

    def test_the_entry_shape_is_exactly_three_members(self):
        bundle = single_bundle(self, "ir16-c")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   witnessed_withheld=["no-witness-supplied"]))})
        entries = self.evaluate(bundle, stub)["withheld_reasons"]
        self.ck_eq(len(entries), 1)
        self.ck_eq(set(entries[0]), {"artifact_path", "channel", "reason"})
        self.ck_eq(entries[0], {"artifact_path": "artifacts/a.json",
                                "channel": "witnessed_withheld",
                                "reason": "no-witness-supplied"})

    def test_the_channel_name_is_the_frozen_one_verbatim(self):
        bundle = single_bundle(self, "ir16-d")
        stub = StubVerifier(by_record={
            "a-decision": (0, verdict("a-decision", klass="AIREP-Core",
                                      auth_withheld=["producer-suite-unsupported"]))})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.withheld_reasons[0]["channel"], "authenticated_withheld")
        self.ck_eq(exc.withheld_reasons[0]["reason"], "producer-suite-unsupported")

    def test_the_array_is_ordered_by_path_then_channel_then_reason(self):
        root = os.path.join(self.root, "ir16-e")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, dict(verdict("z-decision"),
                                   witnessed_withheld=["zz-late", "aa-early"])),
            "y-control": (0, dict(verdict("y-control"),
                                  witnessed_withheld=["mm-middle"])),
        }, default=(0, None))
        result = self.evaluate(bundle, stub)
        self.ck_eq(
            [(w["artifact_path"], w["channel"], w["reason"])
             for w in result["withheld_reasons"]],
            [("artifacts/a.json", "witnessed_withheld", "aa-early"),
             ("artifacts/a.json", "witnessed_withheld", "zz-late"),
             ("artifacts/b.json", "witnessed_withheld", "mm-middle")])

    def test_both_channels_from_one_artifact_are_ordered_by_channel(self):
        bundle = single_bundle(self, "ir16-f")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(
                verdict("a-decision", klass="AIREP-Core",
                        auth_withheld=["producer-binding-missing"]),
                witnessed_withheld=["no-witness-supplied"]))})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq([w["channel"] for w in exc.withheld_reasons],
                   ["authenticated_withheld", "witnessed_withheld"])

    def test_no_reason_is_re_worded(self):
        bundle = single_bundle(self, "ir16-g")
        odd = "a-reason-string-this-evaluator-has-never-heard-of"
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   witnessed_withheld=[odd]))})
        result = self.evaluate(bundle, stub)
        self.ck_eq(result["withheld_reasons"][0]["reason"], odd)

    # ---- E8-1: the projection is of the verdicts ACTUALLY RETAINED ----------

    def test_e8_1_a_fatal_stage_11_retains_an_earlier_observed_channel(self):
        """E8-1. "On EVERY RESULT-BEARING PATH, ``withheld_reasons`` is the
        canonical projection of every accepted frozen-verifier verdict ACTUALLY
        RETAINED in ``artifacts[]`` before termination. A FATAL STAGE-11 RESULT
        DOES NOT ERASE WITHHELD CHANNELS ALREADY OBSERVED."

        ``ordered_four()`` invokes by ascending ``artifact_path``, so
        ``artifacts/a.json`` completes cleanly with a withheld channel and
        ``artifacts/b.json`` then exits 2, aborting the scenario. The first
        artifact's channel MUST survive into the emitted result.
        """
        root = os.path.join(self.root, "ir16-e8-1-a")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, dict(verdict("z-decision"),
                                   witnessed_withheld=["no-witness-supplied"])),
            "y-control": (2, None)})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq([(w["artifact_path"], w["channel"], w["reason"])
                    for w in exc.withheld_reasons],
                   [("artifacts/a.json", "witnessed_withheld",
                     "no-witness-supplied")],
                   "a fatal stage-11 result erased an already-observed channel")

    def test_e8_1_a_gate_rejected_output_contributes_no_withheld_reason(self):
        """"A MALFORMED OR GATE-REJECTED verifier output contributes NONE,
        because it is NOT AN ACCEPTED VERDICT."

        The rejected object here carries a populated ``authenticated_withheld``
        channel AND an ``artifact_ref`` the E8-3 gate refuses. A lane reading
        the channel off the rejected bytes would report it.
        """
        bundle = single_bundle(self, "ir16-e8-1-b")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(
                verdict("a-decision", klass="AIREP-Core",
                        auth_withheld=["producer-binding-missing"]),
                artifact_ref={"record_id": "r", "smuggled": 1}))})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_none(exc.artifacts[0]["verifier_result"])
        self.ck_eq(exc.withheld_reasons, [],
                   "a gate-rejected output contributed a withheld reason")

    def test_e8_1_a_malformed_output_contributes_no_withheld_reason(self):
        """The other half of the same sentence: stdout that does not parse is
        not an accepted verdict either, so it contributes nothing.
        """
        bundle = single_bundle(self, "ir16-e8-1-c")
        exc = self.nonmeasurement(
            bundle, StubVerifier(by_record={"a-decision": (0, b"not json")}))
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq(exc.withheld_reasons, [])

    def test_e8_1_empty_means_none_observed_not_none_exists(self):
        """"``[]`` means NO WITHHELD REASON WAS OBSERVED AMONG THE ACCEPTED
        VERDICTS ACTUALLY OBTAINED -- it says NOTHING about invocations never
        reached."

        A spawn failure on the FIRST artifact reaches no verdict at all, so the
        array is `[]` and `artifacts[]` is empty. The two are asserted together
        because it is their conjunction that makes the emptiness a MEASURED
        emptiness rather than a claim about the unreached three.
        """
        root = os.path.join(self.root, "ir16-e8-1-d")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())

        def never_starts(request, flags):
            raise ev.NonMeasurement("verifier-not-invocable", "synthetic")

        exc = self.nonmeasurement(bundle, never_starts)
        self.ck_eq(exc.reason, "verifier-not-invocable")
        self.ck_eq(exc.artifacts, [])
        self.ck_eq(exc.withheld_reasons, [])

    def test_e8_1_a_later_clean_verdicts_channel_is_also_retained(self):
        """The abort happens at the THIRD artifact here, so two earlier accepted
        verdicts must both be projected. A lane retaining only the most recent
        entry, or only the first, fails.
        """
        root = os.path.join(self.root, "ir16-e8-1-e")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        stub = StubVerifier(by_record={
            "z-decision": (0, dict(verdict("z-decision"),
                                   witnessed_withheld=["no-witness-supplied"])),
            "y-control": (0, dict(verdict("y-control", klass="AIREP-Core",
                                          auth_withheld=["producer-binding-missing"]))),
            "x-execution": (2, None)})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq([(w["artifact_path"], w["channel"], w["reason"])
                    for w in exc.withheld_reasons],
                   [("artifacts/a.json", "witnessed_withheld",
                     "no-witness-supplied"),
                    ("artifacts/b.json", "authenticated_withheld",
                     "producer-binding-missing")])
        self.ck_eq(len(exc.artifacts), 3,
                   "the aborting artifact must still contribute its entry")


# --------------------------------------------------------------------------
# W1-BLK-IR17 -- duplicate manifest members
# --------------------------------------------------------------------------

class BlockIR17(BlockCase):
    BLOCK = "W1-BLK-IR17"

    def manifest_bytes(self, body):
        def override(manifest):
            return body
        return override

    def bundle_with(self, sub, body):
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        return write_bundle(root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
                            manifest_overrides=self.manifest_bytes(body))

    def test_a_duplicate_top_level_scenario_id_is_the_exit_1_band(self):
        """Only a duplicate TOP-LEVEL ``scenario_id`` enters the exit-1 band: no
        registered ``scenario_id`` is DETERMINISTICALLY obtainable, which is
        already the fifth condition of contract 5's identity boundary.
        """
        bundle = self.bundle_with("ir17-a", (
            b'{"scenario_id": "IOP-P-CTL", "scenario_id": "IOP-P-DEC", '
            b'"manifest_version": "1", "files": []}'))
        code, out, _ = self.run_cli(bundle)
        self.ck_eq(code, 1)
        self.ck_eq(out, "")

    def test_neither_duplicate_value_is_taken_by_the_parser_default(self):
        """The two values are DIFFERENT registered ids, so a lane resolving the
        duplicate by last-wins would emit a result naming ``IOP-P-DEC`` and one
        resolving it first-wins would name ``IOP-P-CTL``. Neither appears.
        """
        bundle = self.bundle_with("ir17-b", (
            b'{"scenario_id": "IOP-P-CTL", "scenario_id": "IOP-P-DEC", '
            b'"manifest_version": "1", "files": []}'))
        code, out, err = self.run_cli(bundle)
        self.ck_eq(code, 1)
        self.ck(not out.strip(), "a result object named one of the duplicates")
        self.ck_in("deterministically", err)

    def test_a_nested_scenario_id_does_not_erase_a_valid_top_level_identity(self):
        """"Reading a nested ``scenario_id`` as identity-destroying would let a
        member buried in ``files[]`` suppress a result object the evaluator can
        perfectly well produce" -- the exit-1/exit-3 confusion ``AD15-IR-8``
        exists to prevent.
        """
        bundle = self.bundle_with("ir17-c", (
            b'{"scenario_id": "IOP-P-DEC", "manifest_version": "1", '
            b'"files": [{"path": "x.json", "role": "artifact", '
            b'"sha256": "' + b"0" * 64 + b'", '
            b'"scenario_id": "IOP-P-CTL", "scenario_id": "IOP-P-EXE"}]}'))
        code, out, _ = self.run_cli(bundle)
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_eq(result["scenario_id"], "IOP-P-DEC")
        self.ck_eq(result["nonmeasurement"]["reason"], "manifest-invalid")

    def test_any_other_duplicate_is_manifest_invalid_at_stage_4(self):
        bundle = self.bundle_with("ir17-d", (
            b'{"scenario_id": "IOP-P-DEC", "manifest_version": "9", '
            b'"manifest_version": "1", "files": []}'))
        code, out, _ = self.run_cli(bundle)
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_eq(result["nonmeasurement"]["reason"], "manifest-invalid")
        self.ck_in("manifest_version", result["nonmeasurement"]["detail"])

    def test_the_duplicate_is_refused_before_any_value_is_taken_from_it(self):
        """A duplicated ``manifest_version`` whose LAST value is the legal "1"
        must still be refused. A lane taking last-wins would see a conforming
        manifest and never report anything.
        """
        bundle = self.bundle_with("ir17-e", (
            b'{"scenario_id": "IOP-P-DEC", "manifest_version": "1", '
            b'"manifest_version": "1", "files": []}'))
        code, out, _ = self.run_cli(bundle)
        self.ck_eq(code, 3)
        self.ck_eq(json.loads(out)["nonmeasurement"]["reason"], "manifest-invalid")

    def test_a_duplicated_LEGAL_nested_member_is_also_refused(self):
        """The nested-``scenario_id`` case above is ALSO caught by ``files[]``
        entry closure, so on its own it does not bind the nested-duplicate
        detector. A duplicated ``path`` is a LEGAL member name repeated, so
        closure cannot catch it and only ``AD15-IR-17`` can.
        """
        bundle = self.bundle_with("ir17-f", (
            b'{"scenario_id": "IOP-P-DEC", "manifest_version": "1", '
            b'"files": [{"path": "a.json", "path": "a.json", '
            b'"role": "artifact", "sha256": "' + b"0" * 64 + b'"}]}'))
        code, out, _ = self.run_cli(bundle)
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_eq(result["nonmeasurement"]["reason"], "manifest-invalid")
        self.ck_in("repeats object member name", result["nonmeasurement"]["detail"])
        self.ck_in("path", result["nonmeasurement"]["detail"])

    def test_the_recorder_reports_nesting_not_merely_names(self):
        recorder = ev._DuplicateRecorder()
        doc = json.loads('{"a": 1, "a": 2, "b": {"c": 3, "c": 4}}',
                         object_pairs_hook=recorder)
        top, nested = recorder.split(doc)
        self.ck_eq(top, ["a"])
        self.ck_eq(nested, ["c"])

    def test_a_clean_manifest_records_no_duplicate(self):
        recorder = ev._DuplicateRecorder()
        json.loads('{"a": 1, "b": {"c": 3}}', object_pairs_hook=recorder)
        self.ck_eq(recorder.any_duplicate(), False)


# --------------------------------------------------------------------------
# W1-BLK-JCS -- the stage-8 canonicalization rules, that repair is refused, and
# the stage-8 / stage-10 boundary
# --------------------------------------------------------------------------

class BlockJCS(BlockCase):
    BLOCK = "W1-BLK-JCS"

    def raw_bundle(self, sub, raw, scenario="IOP-P-DEC"):
        root = os.path.join(self.root, sub)
        os.makedirs(root, exist_ok=True)
        return write_bundle(root, scenario, {},
                            raw_files={"artifacts/a.json": (raw, "artifact")})

    ARTIFACT_HEAD = (b'{"airep_version":"0.2","artifact_type":"decision",'
                     b'"chain_id":"c","record_id":"r","sequence":1,')

    def test_an_unpaired_surrogate_is_bundle_json_invalid_at_stage_8(self):
        """RFC 8785 requires strings to be valid Unicode. Strict JSON admits
        ``\ud800`` with no pair, so the document PARSES and still has no
        canonical form.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"x":"\\ud800"}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-a", raw))
        self.ck_eq(exc.reason, "bundle-json-invalid")
        self.ck_in("unpaired surrogate", exc.detail)

    def test_an_unpaired_surrogate_in_a_member_NAME_is_also_caught(self):
        raw = self.ARTIFACT_HEAD + b'"profiles":{"\\udfff":1}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-b", raw))
        self.ck_eq(exc.reason, "bundle-json-invalid")

    def test_a_surrogate_in_a_member_NAME_still_emits_a_result_object(self):
        """An unpaired surrogate can occur in a member NAME, so it reaches the
        POINTER and from there ``nonmeasurement.detail``. Interpolating it raw
        put a lone surrogate into the result object, which then had no UTF-8
        encoding at all -- and the process EXITED 1 WITH EMPTY STDOUT after
        bundle identity had been established.

        Contract 8.5 reserves exit 1 for identity-not-established AND ONLY THAT.
        Once identity exists the evaluator OWES a result object naming the
        scenario it failed on, whatever the bytes contained. This drives the
        real CLI so the emitted-bytes path is genuinely exercised.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"\udfff":1}}'
        code, out, _ = self.run_cli(self.raw_bundle("jcs-surrogate-name", raw),
                                    stub=StubVerifier())
        self.ck_eq(code, 3, "an established identity yielded no result object")
        self.ck(out.strip() != "", "stdout was empty at exit 3")
        result = json.loads(out)
        self.ck_eq(result["scenario_id"], "IOP-P-DEC")
        self.ck_eq(result["nonmeasurement"]["reason"], "bundle-json-invalid")

    def test_the_result_object_survives_a_surrogate_bearing_string(self):
        """The serializer half, asserted directly: the JSON VALUE round-trips
        unchanged, so only the serialization differs and 8.7's canonical-byte
        comparison is untouched.
        """
        obj = {"scenario_id": "IOP-P-DEC", "detail": "lone \udfff here"}
        text = ev.dump_json(obj)
        self.ck_eq(text.encode("utf-8").decode("utf-8"), text)
        self.ck_eq(json.loads(text), obj)

    def test_a_well_formed_surrogate_pair_is_accepted(self):
        """Without this the surrogate rule could be a blanket rejection of every
        escaped astral character, which would refuse conforming bundles.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"x":"\\ud83d\\ude00"}}'
        result = self.evaluate(self.raw_bundle("jcs-c", raw), StubVerifier())
        self.ck_eq(result["measurement_status"], "MEASURED")

    def test_a_duplicate_member_name_is_bundle_json_invalid_at_stage_8(self):
        """"Two lanes could canonicalize ``{"k":1}`` and ``{"k":2}`` from the
        same file and emit DIFFERENT ``request_envelope_digest`` values while
        both reporting success. That is the worst class of defect this contract
        can carry -- not a divergent error, but divergent evidence over
        identical input with no error raised."
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"k":1,"k":2}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-d", raw))
        self.ck_eq(exc.reason, "bundle-json-invalid")
        self.ck_in("repeats object member name", exc.detail)

    def test_repair_is_refused_no_envelope_is_ever_built(self):
        """Neither ``{"k":1}`` nor ``{"k":2}`` is taken, and no
        ``request_envelope_digest`` is produced from either.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"k":1,"k":2}}'
        stub = StubVerifier()
        exc = self.nonmeasurement(self.raw_bundle("jcs-e", raw), stub)
        self.ck_eq(stub.calls, [])
        self.ck_eq(exc.artifacts, [])
        self.ck(exc.json_pointer is None)

    def test_no_u_fffd_substitution_ever_happens(self):
        """Replacement decoding is forbidden. Malformed UTF-8 must be REFUSED,
        not repaired into a document carrying U+FFFD.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"x":"\xff\xfe bad"}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-f", raw))
        self.ck_eq(exc.reason, "bundle-json-invalid")
        self.ck("�" not in exc.detail, "the bytes were repaired, not refused")

    def test_a_non_json_literal_in_a_listed_file_is_stage_8(self):
        """``NaN``, ``Infinity`` and ``-Infinity`` are NOT JSON tokens, so a
        file carrying one is "not parseable JSON" and is ``bundle-json-invalid``
        at STAGE 8 -- with NO ``json_pointer``, which 8.2.2 permits for
        ``numeric-preflight-violation`` alone.

        Python's ``json`` accepts all three by default. Left to that default
        this lane reported ``numeric-preflight-violation`` WITH a pointer, where
        a strict parser reports ``bundle-json-invalid`` WITHOUT one -- and both
        members are Class-1 cross-lane equality fields inside the duty-6
        projection, so it is divergent evidence over identical bytes.
        """
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            raw = self.ARTIFACT_HEAD + b'"profiles":{"x":' + literal + b"}}"
            exc = self.nonmeasurement(
                self.raw_bundle("jcs-lit-%s" % literal.decode(), raw))
            self.ck_eq(exc.reason, "bundle-json-invalid", literal.decode())
            self.ck_none(exc.json_pointer, literal.decode())

    def test_the_non_json_literal_and_1e400_are_different_stages(self):
        """The pair, side by side. They look alike because CPython decodes both
        to ``inf``; they are different rules at different stages, and only one
        of them emits a locator.
        """
        strict = self.nonmeasurement(self.raw_bundle(
            "jcs-pair-a", self.ARTIFACT_HEAD + b'"profiles":{"x":NaN}}'))
        numeric = self.nonmeasurement(self.raw_bundle(
            "jcs-pair-b", self.ARTIFACT_HEAD + b'"profiles":{"x":1e400}}'))
        self.ck_eq(strict.reason, "bundle-json-invalid")
        self.ck_eq(numeric.reason, "numeric-preflight-violation")
        self.ck_none(strict.json_pointer)
        self.ck_eq(numeric.json_pointer, "/profiles/x")

    def test_1e400_is_a_stage_10_numeric_violation_with_its_pointer(self):
        """E7-33 / E7-21. Stage 8's canonicalizability question is the first two
        RFC 8785 rows AND NOTHING ELSE: "the numeric row is ALSO a
        canonicalization failure, and folding it into stage 8 would lose the
        ``json_pointer`` that 5.1 requires and 8.7 makes normative".
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"x":1e400}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-g", raw))
        self.ck_eq(exc.reason, "numeric-preflight-violation")
        self.ck_ne(exc.reason, "bundle-json-invalid")
        self.ck_eq(exc.json_pointer, "/profiles/x")

    def test_the_boundary_holds_when_both_faults_are_present(self):
        """A duplicate member (stage 8) AND a ``1e400`` (stage 10) in the SAME
        file reports the STAGE-8 reason -- the barrier, not the severity.
        """
        raw = self.ARTIFACT_HEAD + b'"profiles":{"k":1,"k":2,"n":1e400}}'
        exc = self.nonmeasurement(self.raw_bundle("jcs-h", raw))
        self.ck_eq(exc.reason, "bundle-json-invalid")

    def test_the_envelope_digest_is_over_jcs_canonical_bytes(self):
        artifacts = [ev.Artifact("artifacts/a.json", DECISION)]
        envelope = ev.build_envelope(artifacts[0], artifacts)
        self.ck_eq(ev.envelope_bytes(envelope), ev.jcs.canonicalize(envelope))
        reordered = {"related_artifacts": envelope["related_artifacts"],
                     "artifact": envelope["artifact"]}
        self.ck_eq(ev.envelope_bytes(reordered), ev.envelope_bytes(envelope),
                   "JCS did not normalize member order")


# --------------------------------------------------------------------------
# W1-BLK-LIVE -- the live frozen-verifier path, against the genuine frozen files
# --------------------------------------------------------------------------

class BlockLive(BlockCase):
    BLOCK = "W1-BLK-LIVE"

    def test_the_frozen_files_are_present_and_match_their_pins(self):
        digests, problem = ev.measure_frozen_digests()
        self.ck_none(problem, "the genuine frozen files did not match their pins")
        self.ck_eq(set(digests), {"class_verifier", "class_verifier_contract"})
        self.ck_eq(digests["class_verifier"],
                   "sha256:" + ev.FROZEN_VERIFIER_SHA256)
        self.ck_eq(digests["class_verifier_contract"],
                   "sha256:" + ev.FROZEN_CONTRACT_SHA256)

    def test_only_this_lane_s_verifier_is_ever_named(self):
        """Contract 3: crossing the lanes is forbidden, and 8.2.1: "the peer
        lane's verifier digest does not appear in evaluator output at all".
        """
        source = io.open(ev.__file__, encoding="utf-8").read()
        for peer in ("verifier_node", "class_verifier.mjs", "node_r2"):
            self.ck(peer not in source,
                    "this lane names peer material: %r" % peer)

    def test_the_real_subprocess_produces_a_concrete_process_result(self):
        artifacts = [ev.Artifact("artifacts/a.json", DECISION)]
        request = ev.envelope_bytes(ev.build_envelope(artifacts[0], artifacts))
        code, stdout, stderr = ev.invoke_frozen_verifier(request, [])
        self.ck(isinstance(code, int),
                "the genuine frozen verifier did not exit normally")
        self.ck_in(code, (0, 1, 2))

    def test_the_frozen_verifier_accepts_our_request_envelope(self):
        """Observing exit 1 proves nothing on its own -- contract 7.2 warns that
        a malformed REQUEST and a malformed ARTIFACT both exit 1. This asserts
        the frozen verifier got past request parsing to artifact evaluation, so
        an envelope bug cannot be scored as a successful detection. stderr is
        read here as TEST evidence only; the evaluator never parses it.
        """
        artifacts = [ev.Artifact("artifacts/a.json", DECISION)]
        request = ev.envelope_bytes(ev.build_envelope(artifacts[0], artifacts))
        code, stdout, stderr = ev.invoke_frozen_verifier(request, [])
        text = (stderr + stdout).decode("utf-8", "replace").lower()
        for complaint in ("unknown member", "unparseable", "unreadable",
                          "request envelope", "invalid request"):
            self.ck(complaint not in text,
                    "the frozen verifier rejected the ENVELOPE: %s" % text[:300])
        self.ck_in("schema", text)

    def test_the_whole_cli_runs_against_the_genuine_verifier(self):
        bundle = single_bundle(self, "live-cli")
        code, out, _ = self.run_cli(bundle)          # NO stub
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_none(ev.validate_result_shape(result),
                     "the live result object is not conforming")
        self.ck_eq(result["artifacts"][0]["verifier_exit_code"], 1)
        self.ck_eq(result["verifier_digests"]["class_verifier"],
                   "sha256:" + ev.FROZEN_VERIFIER_SHA256)

    def test_the_frozen_tree_is_never_written_to(self):
        before = {}
        for _key, path_of, _pin in ev.FROZEN_FILES:
            before[path_of()] = hexdigest(open(path_of(), "rb").read())
        artifacts = [ev.Artifact("artifacts/a.json", DECISION)]
        request = ev.envelope_bytes(ev.build_envelope(artifacts[0], artifacts))
        ev.invoke_frozen_verifier(request, [])
        for path, digest in before.items():
            self.ck_eq(hexdigest(open(path, "rb").read()), digest,
                       "the frozen tree was modified by an invocation")


# --------------------------------------------------------------------------
# W1-BLK-PARITY -- the 8.7 four-class model and the duty-6 projection
#
# PEER-SAFE BY CONSTRUCTION. The real cross-lane comparison is aggregate-harness
# duty 6, which sees both trees; contract 4 forbids a lane's runner from seeing
# its peer, so nothing here reads, imports or names peer material. What this
# lane proves ALONE is that the model SEPARATES THE CLASSES -- a property of the
# projection, not of the peer.
#
# NO INEQUALITY OF THE TWO LANES' STDERR DIGESTS IS ASSERTED. Both frozen
# verifiers write stderr only in their usage-error and invalid branches, so on a
# normal verdict path both streams are empty and both digests are SHA-256 of the
# empty byte string. Requiring them to differ would fail a CONFORMING pair --
# one of the three unsatisfiable rules this erratum removed.
# --------------------------------------------------------------------------

class BlockParity(BlockCase):
    BLOCK = "W1-BLK-PARITY"

    #: The four verdicts a field mutation can produce, per the contract.
    PROJECTION = "cross-lane projection failure"
    LANE_LOCAL = "lane-local pin failure"
    AUDIT = "audit-evidence failure"
    DIAGNOSTIC = "diagnostic-only"

    def measured(self):
        bundle = single_bundle(self, "parity-%d" % len(self.root))
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   witnessed_withheld=["no-witness-supplied"]))})
        return self.evaluate(bundle, stub)

    def errored(self):
        root = os.path.join(self.root, "parity-err")
        os.makedirs(root, exist_ok=True)
        raw = (b'{"airep_version":"0.2","artifact_type":"decision",'
               b'"chain_id":"c","record_id":"r","sequence":1,'
               b'"profiles":{"x":1e400}}')
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (raw, "artifact")})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        assert code == 3, code
        return json.loads(out)

    @staticmethod
    def clone(value):
        return json.loads(json.dumps(value))

    def classify(self, base, mutate):
        """Apply ``mutate`` to a clone and report which of the four classes the
        difference falls into. Recording the classification per field is what
        the block is required to produce.
        """
        other = self.clone(base)
        mutate(other)
        if ev.projection_bytes(other) != ev.projection_bytes(base):
            return self.PROJECTION
        if other.get("evaluator_version") != ev.EVALUATOR_VERSION:
            return self.LANE_LOCAL
        digests = other.get("verifier_digests") or {}
        if digests.get("class_verifier") not in (
                None, "sha256:" + ev.FROZEN_VERIFIER_SHA256):
            return self.LANE_LOCAL
        for index, entry in enumerate(other.get("artifacts") or []):
            original = base["artifacts"][index]
            if entry["verifier_stderr_digest"] != original["verifier_stderr_digest"]:
                return self.AUDIT
        return self.DIAGNOSTIC

    # ---- the two invariances the contract states explicitly ---------------

    def test_the_projection_is_invariant_under_class_3_substitution(self):
        base = self.measured()
        self.ck_eq(
            self.classify(base, lambda r: r["artifacts"][0].__setitem__(
                "verifier_stderr_digest", "sha256:" + "0" * 64)),
            self.AUDIT)

    def test_the_projection_is_invariant_under_class_2_substitution(self):
        base = self.measured()
        self.ck_eq(
            self.classify(base, lambda r: r["verifier_digests"].__setitem__(
                "class_verifier", "sha256:" + "1" * 64)),
            self.LANE_LOCAL)
        self.ck_eq(
            self.classify(base, lambda r: r.__setitem__(
                "evaluator_version", "0.0.0-not-this-lane")),
            self.LANE_LOCAL)

    def test_two_equal_stderr_digests_are_conforming(self):
        """The rule that was UNSATISFIABLE and was removed (E7-SR-4).

        REWRITTEN after adversarial review found the first version VACUOUS: it
        compared a deep JSON clone against its own source, so both assertions
        held by construction and the test passed with and without any
        stderr-digest handling at all. "A test that passes with and without the
        fix is not a test" -- the contract's own standard, applied to itself.

        The two results below are produced INDEPENDENTLY, from two separate
        bundles and two separate stub invocations. Both frozen verifiers write
        stderr only in their usage-error and invalid branches, so on a normal
        verdict path both streams are EMPTY and both digests are SHA-256 of the
        empty byte string -- which must be CONFORMING, not a failure.
        """
        first = self.measured()
        second = self.measured()
        empty = "sha256:" + hexdigest(b"")
        self.ck_eq(first["artifacts"][0]["verifier_stderr_digest"], empty)
        self.ck_eq(second["artifacts"][0]["verifier_stderr_digest"], empty)
        self.ck_eq(ev.projection_bytes(first), ev.projection_bytes(second),
                   "two independently produced conforming results disagree")

    def test_unequal_stderr_digests_are_ALSO_conforming(self):
        """The prohibition stated as the property that actually matters.

        Two lanes running two DIFFERENT programs may legitimately write
        different diagnostic stderr, so the model must accept BOTH equal and
        unequal digests. Asserting inequality would fail a conforming pair
        (both streams empty on a normal verdict); asserting equality would fail
        the equally conforming pair whose diagnostics differ. Class 3 is
        therefore compared against NEITHER: the projection must be blind to it
        in both directions, which is what these two results establish.

        A source-scan for forbidden assertions was the first attempt and was
        itself defective -- the scan pattern occurred in the scanning test, so
        it could never pass. This asserts the behaviour instead of the text.
        """
        bundle = single_bundle(self, "parity-stderr-differs")
        quiet = self.evaluate(bundle, StubVerifier(stderr=b""))
        noisy = self.evaluate(bundle, StubVerifier(stderr=b"different prose\n"))
        self.ck_ne(quiet["artifacts"][0]["verifier_stderr_digest"],
                   noisy["artifacts"][0]["verifier_stderr_digest"],
                   "the fixture did not actually produce differing digests")
        self.ck_eq(ev.projection_bytes(quiet), ev.projection_bytes(noisy),
                   "an audit-only difference moved the cross-lane projection")

    def test_a_nonzero_stderr_is_still_hashed_exactly(self):
        """Class 3 is AUDIT evidence, not decoration: the digest MUST equal
        SHA-256 over the EXACT captured stderr bytes. Without this the field
        could be a constant and every projection test would still pass.
        """
        bundle = single_bundle(self, "parity-stderr")
        noisy = b"diagnostic prose the evaluator must never parse\n"
        stub = StubVerifier(stderr=noisy)
        entry = self.evaluate(bundle, stub)["artifacts"][0]
        self.ck_eq(entry["verifier_stderr_digest"], "sha256:" + hexdigest(noisy))
        self.ck_ne(entry["verifier_stderr_digest"], "sha256:" + hexdigest(b""))

    def test_class_4_diagnostic_detail_does_not_move_the_projection(self):
        base = self.errored()
        self.ck_eq(
            self.classify(base, lambda r: r["nonmeasurement"].__setitem__(
                "detail", "entirely different human prose")),
            self.DIAGNOSTIC)

    # ---- every Class-1 field moves the projection --------------------------

    def test_a_scenario_id_mutation_is_detected(self):
        """"A mutation of ``scenario_id`` MUST be detected -- that is the field
        the earlier surface omitted entirely."
        """
        base = self.measured()
        self.ck_eq(
            self.classify(base, lambda r: r.__setitem__("scenario_id", "IOP-P-CTL")),
            self.PROJECTION)

    def test_every_class_1_field_moves_the_projection(self):
        measured = self.measured()
        errored = self.errored()
        cases = [
            (measured, "measurement_status",
             lambda r: r.__setitem__("measurement_status", "ERROR")),
            (measured, "level1", lambda r: r.__setitem__("level1", "REJECT")),
            (measured, "predicates",
             lambda r: r["predicates"].__setitem__("R_A", "FAIL")),
            (measured, "artifacts[].artifact_path",
             lambda r: r["artifacts"][0].__setitem__("artifact_path", "z.json")),
            (measured, "artifacts[].artifact_ref",
             lambda r: r["artifacts"][0].__setitem__(
                 "artifact_ref", {"record_id": "other"})),
            (measured, "artifacts[].request_envelope_digest",
             lambda r: r["artifacts"][0].__setitem__(
                 "request_envelope_digest", "sha256:" + "2" * 64)),
            (measured, "artifacts[].verifier_exit_code",
             lambda r: r["artifacts"][0].__setitem__("verifier_exit_code", 1)),
            (measured, "artifacts[].verifier_result",
             lambda r: r["artifacts"][0]["verifier_result"].__setitem__(
                 "class", "AIREP-Core")),
            (measured, "artifacts[] membership",
             lambda r: r["artifacts"].append(self.clone(r["artifacts"][0]))),
            (measured, "withheld_reasons",
             lambda r: r["withheld_reasons"].__setitem__(
                 0, dict(r["withheld_reasons"][0], reason="re-worded"))),
            (measured, "verifier_digests.class_verifier_contract",
             lambda r: r["verifier_digests"].__setitem__(
                 "class_verifier_contract", "sha256:" + "3" * 64)),
            (errored, "nonmeasurement.reason",
             lambda r: r["nonmeasurement"].__setitem__("reason", "internal-error")),
            (errored, "nonmeasurement.json_pointer",
             lambda r: r["nonmeasurement"].__setitem__("json_pointer", "/other")),
        ]
        record = {}
        for base, label, mutate in cases:
            record[label] = self.classify(base, mutate)
            self.ck_eq(record[label], self.PROJECTION,
                       "%s did not move the cross-lane projection" % label)
        # The classification record the block is required to produce.
        sys.stderr.write("W1-BLK-PARITY classification: %s\n"
                         % json.dumps(record, sort_keys=True))

    def test_the_complete_four_class_field_record(self):
        """"The block MUST then mutate EACH TOP-LEVEL AND NESTED RESULT FIELD
        INDIVIDUALLY and record, for each, whether the mutation causes
        cross-lane projection failure; causes lane-local pin failure; causes
        audit-evidence failure; or is legitimately diagnostic-only."

        Every member of the closed result set appears below exactly once, so the
        record is COMPLETE rather than a sample -- and the completeness is
        asserted against ``ev.RESULT_MEMBERS`` rather than eyeballed, so a
        member added later cannot quietly escape classification.

        Half of the model is the half a passing comparison never exercises: a
        Class-3 or Class-4 mutation MUST be shown NOT to move the projection.
        """
        measured = self.measured()
        errored = self.errored()
        cases = [
            ("scenario_id", measured, self.PROJECTION,
             lambda r: r.__setitem__("scenario_id", "IOP-P-CTL")),
            ("measurement_status", measured, self.PROJECTION,
             lambda r: r.__setitem__("measurement_status", "ERROR")),
            ("level1", measured, self.PROJECTION,
             lambda r: r.__setitem__("level1", "REJECT")),
            ("predicates.R_A", measured, self.PROJECTION,
             lambda r: r["predicates"].__setitem__("R_A", "FAIL")),
            ("predicates.R_B", measured, self.PROJECTION,
             lambda r: r["predicates"].__setitem__("R_B", "FAIL")),
            ("predicates.R_C", measured, self.PROJECTION,
             lambda r: r["predicates"].__setitem__("R_C", "FAIL")),
            ("nonmeasurement.reason", errored, self.PROJECTION,
             lambda r: r["nonmeasurement"].__setitem__("reason", "internal-error")),
            ("nonmeasurement.json_pointer", errored, self.PROJECTION,
             lambda r: r["nonmeasurement"].__setitem__("json_pointer", "/elsewhere")),
            ("nonmeasurement.detail", errored, self.DIAGNOSTIC,
             lambda r: r["nonmeasurement"].__setitem__("detail", "other prose")),
            ("artifacts (membership)", measured, self.PROJECTION,
             lambda r: r["artifacts"].append(self.clone(r["artifacts"][0]))),
            ("artifacts[].artifact_path", measured, self.PROJECTION,
             lambda r: r["artifacts"][0].__setitem__("artifact_path", "z.json")),
            ("artifacts[].artifact_ref", measured, self.PROJECTION,
             lambda r: r["artifacts"][0].__setitem__(
                 "artifact_ref", {"record_id": "other"})),
            ("artifacts[].request_envelope_digest", measured, self.PROJECTION,
             lambda r: r["artifacts"][0].__setitem__(
                 "request_envelope_digest", "sha256:" + "2" * 64)),
            ("artifacts[].verifier_exit_code", measured, self.PROJECTION,
             lambda r: r["artifacts"][0].__setitem__("verifier_exit_code", 1)),
            ("artifacts[].verifier_result", measured, self.PROJECTION,
             lambda r: r["artifacts"][0]["verifier_result"].__setitem__(
                 "class", "AIREP-Core")),
            ("artifacts[].verifier_stderr_digest", measured, self.AUDIT,
             lambda r: r["artifacts"][0].__setitem__(
                 "verifier_stderr_digest", "sha256:" + "0" * 64)),
            ("withheld_reasons", measured, self.PROJECTION,
             lambda r: r["withheld_reasons"].__setitem__(
                 0, dict(r["withheld_reasons"][0], reason="re-worded"))),
            ("verifier_digests.class_verifier", measured, self.LANE_LOCAL,
             lambda r: r["verifier_digests"].__setitem__(
                 "class_verifier", "sha256:" + "1" * 64)),
            ("verifier_digests.class_verifier_contract", measured, self.PROJECTION,
             lambda r: r["verifier_digests"].__setitem__(
                 "class_verifier_contract", "sha256:" + "3" * 64)),
            ("evaluator_version", measured, self.LANE_LOCAL,
             lambda r: r.__setitem__("evaluator_version", "0.0.0-not-this-lane")),
        ]
        record = {}
        for label, base, expected, mutate in cases:
            record[label] = self.classify(base, mutate)
            self.ck_eq(record[label], expected, label)
        covered = {label.split(".")[0].split(" ")[0].replace("[]", "")
                   for label in record}
        self.ck_eq(covered, set(ev.RESULT_MEMBERS),
                   "a closed result member was left unclassified")
        sys.stderr.write("W1-BLK-PARITY four-class field record: %s\n"
                         % json.dumps(record, sort_keys=True, indent=1))

    def test_artifacts_order_moves_the_projection(self):
        root = os.path.join(self.root, "parity-order")
        os.makedirs(root)
        bundle = write_bundle(root, "IOP-R-CLEAN", ordered_four())
        base = self.evaluate(bundle, StubVerifier())
        self.ck_eq(
            self.classify(base, lambda r: r["artifacts"].reverse()),
            self.PROJECTION)

    # ---- closed result member set -----------------------------------------

    def test_an_unknown_member_at_any_closed_level_is_invalid(self):
        base = self.measured()
        for mutate in (
                lambda r: r.__setitem__("smuggled", 1),
                lambda r: r["artifacts"][0].__setitem__("smuggled", 1),
                lambda r: r["verifier_digests"].__setitem__("smuggled", 1),
                lambda r: r["predicates"].__setitem__("R_D", "PASS"),
                lambda r: r["withheld_reasons"][0].__setitem__("smuggled", 1)):
            other = self.clone(base)
            mutate(other)
            self.ck(ev.validate_result_shape(other) is not None,
                    "an unknown member was tolerated at a closed level")

    def test_a_conforming_result_passes_the_shape_gate(self):
        self.ck_none(ev.validate_result_shape(self.measured()))
        self.ck_none(ev.validate_result_shape(self.errored()))

    def test_the_projection_removes_exactly_the_four_listed_things(self):
        base = self.errored()
        projected = ev.normative_projection(base)
        self.ck("evaluator_version" not in projected)
        self.ck("detail" not in projected["nonmeasurement"])
        self.ck("class_verifier" not in projected["verifier_digests"])
        self.ck_in("class_verifier_contract", projected["verifier_digests"])
        self.ck_eq(set(projected), set(ev.RESULT_MEMBERS) - {"evaluator_version"})

    def test_the_projection_is_compared_as_rfc_8785_bytes(self):
        base = self.measured()
        reordered = json.loads(json.dumps(base))
        reordered = {k: reordered[k] for k in reversed(list(reordered))}
        self.ck_eq(ev.projection_bytes(reordered), ev.projection_bytes(base),
                   "member order changed the canonical bytes")


# --------------------------------------------------------------------------
# W1-BLK-ARTIFACT-REF -- AD15-IR-18's complete projection-function value matrix,
# PLUS its three sources
#
# "Testing splits in two, because the full cross-product is UNBUILDABLE." The
# frozen ``common.schema.json`` makes ``record_id`` and ``chain_id`` BOTH
# REQUIRED STRINGS in ``artifact_core``, so an artifact carrying an absent,
# null, boolean or numeric ``record_id`` cannot pass stage-0 schema validation
# and can never produce an ``exit 0`` verdict. Only ``schema-invalid x Source A``
# is excluded; every other combination remains required, through Source B.
# --------------------------------------------------------------------------

#: The value matrix, exactly as the ruling lists it. ``ABSENT`` is a sentinel
#: because "absent" is not a JSON value.
ABSENT = object()
REF_VALUES = [
    ("absent", ABSENT),
    ("null", None),
    ("boolean", True),
    ("number", 17),
    ("empty string", ""),
    ("non-empty string", "v"),
]


class BlockArtifactRef(BlockCase):
    BLOCK = "W1-BLK-ARTIFACT-REF"

    @staticmethod
    def build(record_id, chain_id):
        doc = {"airep_version": "0.2"}
        if record_id is not ABSENT:
            doc["record_id"] = record_id
        if chain_id is not ABSENT:
            doc["chain_id"] = chain_id
        return doc

    # ---- projection-function tests: the FULL value matrix ------------------

    def test_the_projection_function_over_the_full_value_matrix(self):
        """Exercised DIRECTLY, with no requirement that the value could ever
        yield a frozen verdict.
        """
        for r_label, record_id in REF_VALUES:
            for c_label, chain_id in REF_VALUES:
                doc = self.build(record_id, chain_id)
                got = ev.artifact_ref_from_artifact(doc)
                if not isinstance(record_id, str):
                    expected = None
                else:
                    expected = {"record_id": record_id}
                    if isinstance(chain_id, str):
                        expected["chain_id"] = chain_id
                self.ck_eq(got, expected,
                           "record_id=%s chain_id=%s" % (r_label, c_label))

    def test_a_missing_or_non_string_chain_id_is_OMITTED_never_null(self):
        """Step 4. "An omitted member and a ``null`` member are different JSON
        values and therefore different RFC 8785 canonical bytes."
        """
        for _label, chain_id in REF_VALUES:
            if isinstance(chain_id, str):
                continue
            got = ev.artifact_ref_from_artifact(self.build("r", chain_id))
            self.ck_eq(got, {"record_id": "r"})
            self.ck("chain_id" not in got)

    def test_an_empty_string_remains_a_string(self):
        """Step 5. "The evaluator does not add a minLength rule absent from the
        frozen schema." This lane previously returned ``null`` here.
        """
        self.ck_eq(ev.artifact_ref_from_artifact(self.build("", "")),
                   {"record_id": "", "chain_id": ""})

    def test_the_function_is_total_over_every_json_value(self):
        """Step 1: a non-object returns null, whatever it is."""
        for value in (None, True, 17, 1.5, "a string", [], ["x"], []):
            self.ck_none(ev.artifact_ref_from_artifact(value))

    def test_nothing_is_coerced_normalized_or_synthesized(self):
        """Step 6. A ``record_id`` that only LOOKS numeric stays the string it
        was, and a decomposed string is not normalized into a composed one.
        """
        self.ck_eq(ev.artifact_ref_from_artifact({"record_id": "0017"}),
                   {"record_id": "0017"})
        decomposed = "é"
        self.ck_eq(ev.artifact_ref_from_artifact({"record_id": decomposed}),
                   {"record_id": decomposed})
        self.ck_eq(ev.artifact_ref_from_artifact({"record_id": "AbC"}),
                   {"record_id": "AbC"})

    # ---- Source A ----------------------------------------------------------

    def test_source_a_copies_the_verdict_artifact_ref_verbatim(self):
        """"Reachable only with a schema-valid artifact, so ``record_id`` and
        ``chain_id`` are strings by construction."
        """
        bundle = single_bundle(self, "ref-a")
        theirs = {"record_id": "from-the-verdict", "chain_id": "verdict-chain"}
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"), artifact_ref=theirs))})
        entry = self.evaluate(bundle, stub)["artifacts"][0]
        self.ck_eq(entry["artifact_ref"], theirs)
        self.ck_ne(entry["artifact_ref"],
                   ev.artifact_ref_from_artifact(DECISION),
                   "the preliminary projection was emitted on the exit-0 path")

    def test_source_a_negative_gate_an_extra_member_is_run_invalid(self):
        """The gate THIS contract adds. "The frozen contract permits the extra
        member; W1 does not, because ``artifact_ref`` is a Class-1 cross-lane
        equality field and an open nested object cannot be one."
        """
        bundle = single_bundle(self, "ref-b")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"), artifact_ref={
                "record_id": "r", "chain_id": "c", "smuggled": 1}))})
        exc = self.nonmeasurement(bundle, stub)
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_in("artifact_ref carries member(s) outside the closed set",
                   exc.detail)
        self.ck_eq(len(exc.artifacts), 1)
        self.ck_none(exc.artifacts[0]["verifier_result"],
                     "a verdict the gate refused was copied anyway")

    # ---- E8-3: the Source-A gate is REQUIRED, TYPED AND CLOSED -------------

    def rejected_by_the_gate(self, sub, artifact_ref, fragment):
        """Every E8-3 failure is ``verifier-run-invalid``, with NO REPAIR and NO
        COERCION -- and, the verdict not being an accepted one, Source A does
        not apply, so ``AD15-IR-18``'s SOURCE B governs the emitted
        ``artifact_ref`` and ``verifier_result`` is ``null``.
        """
        bundle = single_bundle(self, sub)
        body = dict(verdict("a-decision"))
        if artifact_ref is ABSENT:
            body.pop("artifact_ref")
        else:
            body["artifact_ref"] = artifact_ref
        exc = self.nonmeasurement(
            bundle, StubVerifier(by_record={"a-decision": (0, body)}))
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_in(fragment, exc.detail)
        self.ck_eq(len(exc.artifacts), 1)
        entry = exc.artifacts[0]
        self.ck_none(entry["verifier_result"],
                     "a verdict the gate refused was copied anyway")
        self.ck_eq(entry["artifact_ref"],
                   {"record_id": "a-decision", "chain_id": "chain-synthetic"},
                   "Source B did not govern a gate-rejected verdict")
        return entry

    def test_e8_3_an_absent_artifact_ref_is_run_invalid(self):
        """"An earlier draft rejected only an EXTRA MEMBER, which left an ABSENT
        or ``null`` ``artifact_ref`` ACCEPTED AND SILENTLY CONVERTED TO ``null``
        on the emitted entry. One lane read it that way and the other did not,
        ON A CLASS-1 FIELD."

        W1 requires presence ON ITS OWN AUTHORITY: frozen 6's enumerated shape
        gates do not include `artifact_ref` presence, so whether an omitted one
        is frozen-conforming is NOT SETTLED by the frozen text.
        `verifier-run-invalid` already covers a shape rejected by EITHER
        contract, so the case has both a reason and a defined outcome.
        """
        self.rejected_by_the_gate("ref-e83-absent", ABSENT,
                                  "required member 'artifact_ref' is absent")

    def test_e8_3_a_null_artifact_ref_is_run_invalid(self):
        self.rejected_by_the_gate("ref-e83-null", None,
                                  "artifact_ref is not an object")

    def test_e8_3_a_non_object_artifact_ref_is_run_invalid(self):
        self.rejected_by_the_gate("ref-e83-scalar", "a-decision",
                                  "artifact_ref is not an object")

    def test_e8_3_a_missing_record_id_is_run_invalid(self):
        self.rejected_by_the_gate("ref-e83-norec", {"chain_id": "c"},
                                  "artifact_ref carries no record_id")

    def test_e8_3_a_non_string_record_id_is_run_invalid(self):
        for label, value in (("null", None), ("boolean", True),
                             ("number", 17), ("object", {}), ("array", [])):
            self.rejected_by_the_gate(
                "ref-e83-rec-%s" % label, {"record_id": value},
                "artifact_ref.record_id is a")

    def test_e8_3_a_non_string_chain_id_is_run_invalid(self):
        for label, value in (("null", None), ("boolean", True),
                             ("number", 17), ("object", {}), ("array", [])):
            self.rejected_by_the_gate(
                "ref-e83-chain-%s" % label,
                {"record_id": "r", "chain_id": value},
                "artifact_ref.chain_id is present but is a")

    def test_e8_3_nothing_is_repaired_or_coerced(self):
        """"THERE IS NO REPAIR AND NO COERCION." A lane that stringified a
        numeric `record_id`, or dropped a null `chain_id` to satisfy the closed
        set, would emit an accepted verdict here instead of refusing.
        """
        entry = self.rejected_by_the_gate(
            "ref-e83-norepair", {"record_id": 17, "chain_id": None},
            "artifact_ref.record_id is a")
        self.ck_none(entry["verifier_result"])
        self.ck("17" not in json.dumps(entry["artifact_ref"]),
                "a numeric record_id was stringified into the emitted ref")

    def test_e8_4_a_gate_rejected_exit_0_has_code_0_and_a_null_result(self):
        """E8-4, exactly as pinned::

            verifier_exit_code = 0
            verifier_result    = null
            artifact_ref       = AD15-IR-18 Source-B preliminary projection
            reason             = verifier-run-invalid, and the scenario terminates

        "Stdout that parses is NOT A VERDICT until it has passed BOTH the frozen
        contract's shape rules AND this contract's gate." The rejected bytes may
        be kept as diagnostic evidence; they may NOT enter the normative
        ``verifier_result``, which is Class-1.
        """
        bundle = single_bundle(self, "ref-e84")
        exc = self.nonmeasurement(
            bundle,
            StubVerifier(by_record={"a-decision": (0, b'{"parses":"but is not a verdict"}')}))
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq(len(exc.artifacts), 1, "the scenario must terminate here")
        entry = exc.artifacts[0]
        self.ck_eq(entry["verifier_exit_code"], 0,
                   "the process exited normally, so the code is recorded verbatim")
        self.ck_none(entry["verifier_result"],
                     "a rejected exit-0 object entered the normative verdict field")
        self.ck_eq(entry["artifact_ref"],
                   {"record_id": "a-decision", "chain_id": "chain-synthetic"})
        self.ck("parses" not in json.dumps(entry),
                "the rejected bytes reached a normative field")

    def test_e8_4_the_gate_rejected_path_still_carries_the_full_entry(self):
        """It is NOT the ``AD15-IR-11`` shape: a concrete process result exists,
        so every field a process attempt produces is present.
        """
        bundle = single_bundle(self, "ref-e84-full")
        exc = self.nonmeasurement(
            bundle, StubVerifier(by_record={"a-decision": (0, b"[]")}))
        entry = exc.artifacts[0]
        self.ck_eq(set(entry),
                   {"artifact_path", "artifact_ref", "request_envelope_digest",
                    "verifier_exit_code", "verifier_result",
                    "verifier_stderr_digest"})
        self.ck(entry["request_envelope_digest"].startswith("sha256:"))
        self.ck(entry["verifier_stderr_digest"].startswith("sha256:"))

    def test_source_a_gate_accepts_record_id_only(self):
        """Without this the gate could be a blanket requirement for both
        members, which would reject a conforming frozen verdict.
        """
        bundle = single_bundle(self, "ref-c")
        stub = StubVerifier(by_record={
            "a-decision": (0, dict(verdict("a-decision"),
                                   artifact_ref={"record_id": "r"}))})
        entry = self.evaluate(bundle, stub)["artifacts"][0]
        self.ck_eq(entry["artifact_ref"], {"record_id": "r"})

    # ---- Source B: EVERY OTHER EMITTED ENTRY, on several distinct paths -----

    def source_b_paths(self, sub, doc, family="decision"):
        """Return an entry for the SAME artifact value on EVERY Source-B route
        the ruling names: qualifying ``exit 1``, NON-qualifying ``exit 1``,
        ``exit 2``, a GATE-REJECTED ``exit 0``, and ABNORMAL TERMINATION.

        Source B is defined BY EXCLUSION, not by a list of outcomes -- an
        outcome list is not exhaustive and invites exactly the error of
        declaring one outcome the only carrier of some value. All five routes
        are exercised because "a lane using the WRONG SOURCE ON ``exit 2``
        alone would otherwise pass": three of them is not enough.
        """
        scenario_ok = {"decision": "IOP-B-DEC", "control": "IOP-B-CTL",
                       "effect": "IOP-B-EFF"}[family]
        scenario_bad = {"decision": "IOP-P-DEC", "control": "IOP-P-CTL",
                        "effect": "IOP-P-EFF"}[family]
        qualifying = self.evaluate(
            single_bundle(self, sub + "-q", scenario=scenario_ok, doc=doc),
            StubVerifier(default=(1, None)))["artifacts"][0]
        non_qualifying = self.nonmeasurement(
            single_bundle(self, sub + "-n", scenario=scenario_bad, doc=doc),
            StubVerifier(default=(1, None))).artifacts[0]
        exit_2 = self.nonmeasurement(
            single_bundle(self, sub + "-2", scenario=scenario_bad, doc=doc),
            StubVerifier(default=(2, None))).artifacts[0]
        # A gate-rejected `exit 0`: stdout parses, but it is not a verdict
        # envelope, so the gate refuses it and Source B governs the ref.
        rejected_exit_0 = self.nonmeasurement(
            single_bundle(self, sub + "-r", scenario=scenario_bad, doc=doc),
            StubVerifier(default=(0, b'{"not":"a verdict"}'))).artifacts[0]
        abnormal = self.nonmeasurement(
            single_bundle(self, sub + "-a", scenario=scenario_bad, doc=doc),
            lambda request, flags: (None, b"", b"")).artifacts[0]
        return (qualifying, non_qualifying, exit_2, rejected_exit_0, abnormal)

    def test_source_b_carries_the_preliminary_projection_on_every_route(self):
        doc = dict(DECISION, record_id="a-decision")
        for entry in self.source_b_paths("ref-d", doc):
            self.ck_eq(entry["artifact_ref"],
                       {"record_id": "a-decision", "chain_id": "chain-synthetic"})

    def test_source_b_with_a_schema_invalid_record_id_on_every_route(self):
        """"These cells are reachable: stage-0 schema validity gates only the
        VERDICT, not the ENTRY." An earlier draft claimed the qualifying stage-0
        ``exit 1`` was the ONLY outcome that could carry an invalid ID; that was
        false and dropped reachable cells.
        """
        for _label, record_id in REF_VALUES:
            if isinstance(record_id, str):
                continue
            doc = dict(DECISION)
            if record_id is ABSENT:
                doc.pop("record_id")
            else:
                doc["record_id"] = record_id
            for entry in self.source_b_paths("ref-e-%s" % _label, doc):
                self.ck_none(entry["artifact_ref"],
                             "record_id=%s" % _label)

    def test_source_b_with_a_schema_invalid_chain_id_on_every_route(self):
        for _label, chain_id in REF_VALUES:
            if isinstance(chain_id, str):
                continue
            doc = dict(DECISION)
            if chain_id is ABSENT:
                doc.pop("chain_id")
            else:
                doc["chain_id"] = chain_id
            for entry in self.source_b_paths("ref-f-%s" % _label, doc):
                self.ck_eq(entry["artifact_ref"], {"record_id": "a-decision"},
                           "chain_id=%s" % _label)

    def test_source_b_includes_a_rejected_exit_0_shape(self):
        """Another Source-B path, named explicitly by the ruling: "exit 0 whose
        output the result-shape gate rejects".
        """
        bundle = single_bundle(self, "ref-g")
        exc = self.nonmeasurement(
            bundle, StubVerifier(by_record={"a-decision": (0, b"[]")}))
        self.ck_eq(exc.reason, "verifier-run-invalid")
        self.ck_eq(exc.artifacts[0]["artifact_ref"],
                   {"record_id": "a-decision", "chain_id": "chain-synthetic"})

    def test_source_b_includes_exit_2(self):
        bundle = single_bundle(self, "ref-h")
        exc = self.nonmeasurement(bundle, StubVerifier(default=(2, None)))
        self.ck_eq(exc.artifacts[0]["artifact_ref"],
                   {"record_id": "a-decision", "chain_id": "chain-synthetic"})

    # ---- Source C ----------------------------------------------------------

    def test_source_c_has_no_entry_and_therefore_no_artifact_ref(self):
        bundle = single_bundle(self, "ref-i")

        def never_starts(request, flags):
            raise ev.NonMeasurement("verifier-not-invocable", "synthetic")

        exc = self.nonmeasurement(bundle, never_starts)
        self.ck_eq(exc.artifacts, [])

    def test_source_c_covers_every_pre_invocation_failure(self):
        bundle = single_bundle(self, "ref-j", drop_from_disk=("artifacts/a.json",))
        exc = self.nonmeasurement(bundle, StubVerifier())
        self.ck_eq(exc.artifacts, [])

    def test_no_record_id_is_ever_synthesized_anywhere(self):
        doc = {k: v for k, v in DECISION.items() if k != "record_id"}
        bundle = single_bundle(self, "ref-k", scenario="IOP-B-DEC", doc=doc)
        stub = StubVerifier(default=(1, None))
        result = self.evaluate(bundle, stub)
        self.ck("record_id" not in stub.calls[0][1]["artifact"])
        self.ck_none(result["artifacts"][0]["artifact_ref"])


# --------------------------------------------------------------------------
# W1-BLK-JSON-BYTES -- AD15-IR-20, for BOTH the root manifest and a listed file
# --------------------------------------------------------------------------

#: The six byte-domain violations the block names, plus their labels.
def _json_bytes_cases(document_text):
    return [
        ("UTF-8 BOM", b"\xef\xbb\xbf" + document_text.encode("utf-8")),
        ("malformed UTF-8", document_text.encode("utf-8")[:-1] + b"\xff\xfe\x80"),
        ("UTF-16LE", document_text.encode("utf-16-le")),
        ("UTF-16BE", document_text.encode("utf-16-be")),
        ("UTF-32LE", document_text.encode("utf-32-le")),
        ("UTF-32BE", document_text.encode("utf-32-be")),
    ]


class BlockJsonBytes(BlockCase):
    BLOCK = "W1-BLK-JSON-BYTES"

    ARTIFACT_TEXT = ('{"airep_version":"0.2","artifact_type":"decision",'
                     '"chain_id":"c","record_id":"r","sequence":1}')

    def test_the_decoder_refuses_every_listed_encoding(self):
        for label, data in _json_bytes_cases(self.ARTIFACT_TEXT):
            with self.assertRaises(ev.JsonByteError, msg=label):
                ev.decode_json_bytes(data)
            LEDGER.count(self.BLOCK)

    def test_a_plain_utf8_document_is_accepted(self):
        """Without this the decoder could refuse everything, which would make
        the six rejections meaningless.
        """
        self.ck_eq(ev.decode_json_bytes(self.ARTIFACT_TEXT.encode("utf-8")),
                   self.ARTIFACT_TEXT)
        self.ck_eq(ev.decode_json_bytes('{"k":"ö"}'.encode("utf-8")), '{"k":"ö"}')

    def test_no_u_fffd_ever_appears(self):
        """"Replacement decoding with U+FFFD is FORBIDDEN." A lenient decoder
        would return a repaired string instead of raising.
        """
        for _label, data in _json_bytes_cases(self.ARTIFACT_TEXT):
            try:
                decoded = ev.decode_json_bytes(data)
            except ev.JsonByteError:
                LEDGER.count(self.BLOCK)
                continue
            self.ck("�" not in decoded, "bytes were repaired, not refused")

    # ---- the ROOT MANIFEST side: identity NOT established, exit 1 ----------

    def test_the_root_manifest_side_is_exit_1_with_empty_stdout(self):
        for label, data in _json_bytes_cases(
                '{"scenario_id":"IOP-P-DEC","manifest_version":"1","files":[]}'):
            root = os.path.join(self.root, "jb-m-%s" % label.replace(" ", "-"))
            os.makedirs(root, exist_ok=True)
            bundle = write_bundle(root, "IOP-P-DEC",
                                  {"artifacts/a.json": DECISION},
                                  manifest_overrides=lambda m, d=data: d)
            code, out, _ = self.run_cli(bundle)
            self.ck_eq(code, 1, label)
            self.ck_eq(out, "", label)

    # ---- the LISTED FILE side: bundle-json-invalid at stage 8, exit 3 ------

    def test_the_listed_file_side_is_bundle_json_invalid_at_exit_3(self):
        for label, data in _json_bytes_cases(self.ARTIFACT_TEXT):
            root = os.path.join(self.root, "jb-f-%s" % label.replace(" ", "-"))
            os.makedirs(root, exist_ok=True)
            bundle = write_bundle(root, "IOP-P-DEC", {},
                                  raw_files={"artifacts/a.json": (data, "artifact")})
            code, out, _ = self.run_cli(bundle, stub=StubVerifier())
            self.ck_eq(code, 3, label)
            result = json.loads(out)
            self.ck_eq(result["nonmeasurement"]["reason"], "bundle-json-invalid",
                       label)
            self.ck_eq(result["scenario_id"], "IOP-P-DEC", label)

    def test_an_operator_input_file_is_on_the_listed_side_too(self):
        """The rule names "every listed ARTIFACT AND OPERATOR-INPUT JSON file",
        so the operator inputs are not a separate, laxer surface.
        """
        root = os.path.join(self.root, "jb-op")
        os.makedirs(root)
        operator = {"operator/bindings.json": (b"\xef\xbb\xbf{}", "bindings"),
                    "operator/independence.json": ({"policy": "x"},
                                                   "independence_policy"),
                    "operator/revocation.json": ({"revoked": []}, "revocation")}
        bundle = write_bundle(
            root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
            operator={k: v for k, v in operator.items()
                      if not isinstance(v[0], bytes)},
            raw_files={"operator/bindings.json": (b"\xef\xbb\xbf{}", "bindings")})
        exc = self.nonmeasurement(bundle, StubVerifier())
        self.ck_eq(exc.reason, "bundle-json-invalid")
        self.ck_in("operator/bindings.json", exc.detail)

    def test_a_bom_before_an_OTHERWISE_VALID_document_is_still_refused(self):
        """The case a lenient runtime most often accepts silently. For
        malformed UTF-8 and the UTF-16/UTF-32 encodings the JSON parser would
        refuse the document anyway, so those cases cannot tell a BYTE-DOMAIN
        rule from a PARSER accident. A BOM in front of a document that is
        otherwise perfectly valid can: a lane that strips it MEASURES the
        bundle, and a lane that applies the rule refuses it.
        """
        root = os.path.join(self.root, "jb-bom-valid")
        os.makedirs(root)
        data = b"\xef\xbb\xbf" + self.ARTIFACT_TEXT.encode("utf-8")
        self.ck_eq(json.loads(data[3:].decode("utf-8"))["record_id"], "r",
                   "the document after the BOM is not otherwise valid")
        bundle = write_bundle(root, "IOP-P-DEC", {},
                              raw_files={"artifacts/a.json": (data, "artifact")})
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.ck_eq(code, 3, "a BOM was stripped and the bundle was measured")
        result = json.loads(out)
        self.ck_eq(result["nonmeasurement"]["reason"], "bundle-json-invalid")
        self.ck_in("BOM", result["nonmeasurement"]["detail"])

    def test_a_bom_before_an_OTHERWISE_VALID_manifest_is_still_refused(self):
        root = os.path.join(self.root, "jb-bom-manifest")
        os.makedirs(root)
        bundle = write_bundle(
            root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
            manifest_overrides=lambda m: (
                b"\xef\xbb\xbf" + json.dumps(m).encode("utf-8")))
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.ck_eq(code, 1, "a BOM was stripped and identity was established")
        self.ck_eq(out, "")

    def test_the_two_sides_of_the_identity_boundary_differ(self):
        """The same byte defect gives DIFFERENT outcomes by which file it is.
        That is the whole point of the ruling's assignment table.
        """
        root = os.path.join(self.root, "jb-both")
        os.makedirs(root)
        bom = b"\xef\xbb\xbf"
        manifest_bundle = write_bundle(
            os.path.join(root, "m"), "IOP-P-DEC", {"artifacts/a.json": DECISION},
            manifest_overrides=lambda m: bom + json.dumps(m).encode("utf-8"))
        file_bundle = write_bundle(
            os.path.join(root, "f"), "IOP-P-DEC", {},
            raw_files={"artifacts/a.json":
                       (bom + self.ARTIFACT_TEXT.encode("utf-8"), "artifact")})
        self.ck_eq(self.run_cli(manifest_bundle)[0], 1)
        self.ck_eq(self.run_cli(file_bundle, stub=StubVerifier())[0], 3)


# --------------------------------------------------------------------------
# W1-BLK-PATH -- AD15-IR-19, over the contract's own case list
# --------------------------------------------------------------------------

#: The case list exactly as the contract writes it.
PATH_REJECT_CASES = [
    ("empty path", ""),
    ("dot", "."),
    ("dot dot", ".."),
    ("leading ./", "./a.json"),
    ("interior /./", "a/./b.json"),
    ("interior /../", "a/../b.json"),
    ("doubled slash", "a//b.json"),
    ("leading slash", "/a.json"),
    ("trailing slash", "a.json/"),
    ("drive prefix", "C:artifact.json"),
    ("backslash", "a\\b.json"),
    ("control character", "a\x01b.json"),
    ("NUL", "a\x00b.json"),
    ("non-ASCII", "artefäct.json"),
    ("unpaired surrogate", "a\ud800.json"),
]

#: "valid canonical controls" -- the positive half, without which every
#: rejection above could be produced by a rule that refuses everything.
PATH_ACCEPT_CASES = [
    "a.json",
    "artifacts/decision.json",
    "a-b_c.1/d-e_f.2.json",
    "..a",
    "a..",
    "_",
    "-",
    "A/B/C",
    "0/1/2.json",
]


class BlockPath(BlockCase):
    BLOCK = "W1-BLK-PATH"

    def test_every_rejected_case_is_manifest_invalid(self):
        for label, path in PATH_REJECT_CASES:
            with self.assertRaises(ev.NonMeasurement, msg=label) as ctx:
                ev._validate_manifest_path(0, path)
            LEDGER.count(self.BLOCK)
            self.ck_eq(ctx.exception.reason, "manifest-invalid", label)

    def test_every_canonical_control_is_accepted(self):
        for path in PATH_ACCEPT_CASES:
            ev._validate_manifest_path(0, path)     # must not raise
            LEDGER.count(self.BLOCK)

    def test_the_root_manifest_name_is_still_excluded_from_files(self):
        with self.assertRaises(ev.NonMeasurement) as ctx:
            ev._validate_manifest_path(0, "manifest.json")
        self.ck_eq(ctx.exception.reason, "manifest-invalid")

    def test_no_path_is_ever_normalized_into_acceptance(self):
        """"A path is accepted only when its ORIGINAL JSON STRING already
        satisfies the canonical grammar." ``a/../b.json`` and ``./a.json`` both
        normalize to something legal, and both must still be REFUSED.
        """
        for path in ("a/../b.json", "./a.json", "a/./b.json"):
            self.ck_eq(os.path.normpath(path).replace(os.sep, "/") in
                       ("b.json", "a.json", "a/b.json"), True,
                       "%r does normalize to a legal path" % path)
            with self.assertRaises(ev.NonMeasurement):
                ev._validate_manifest_path(0, path)
            LEDGER.count(self.BLOCK)

    def test_the_grammar_is_reported_at_stage_4_before_the_disk_is_read(self):
        """"A violation is ``manifest-invalid`` at stage 4 -- a property of the
        manifest DOCUMENT, testable before the filesystem is consulted." The
        listed file does not exist on disk, and the reported reason is still the
        stage-4 one rather than ``bundle-file-missing``.
        """
        root = os.path.join(self.root, "path-stage4")
        os.makedirs(root)
        bundle = write_bundle(
            root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
            manifest_overrides=lambda m: dict(m, files=[
                {"path": "../escape.json", "role": "artifact",
                 "sha256": "0" * 64}]))
        code, out, _ = self.run_cli(bundle, stub=StubVerifier())
        self.ck_eq(code, 3)
        result = json.loads(out)
        self.ck_eq(result["nonmeasurement"]["reason"], "manifest-invalid")

    def test_a_duplicate_path_is_refused(self):
        root = os.path.join(self.root, "path-dup")
        os.makedirs(root)
        bundle = write_bundle(
            root, "IOP-P-DEC", {"artifacts/a.json": DECISION},
            manifest_overrides=lambda m: dict(m, files=[
                {"path": "a.json", "role": "artifact", "sha256": "0" * 64},
                {"path": "a.json", "role": "artifact", "sha256": "0" * 64}]))
        exc = self.nonmeasurement(bundle, StubVerifier())
        self.ck_eq(exc.reason, "manifest-invalid")
        self.ck_in("more than once", exc.detail)


# ==========================================================================
# Block-accounting runner (contract 8.7)
#
# "The summary distinguishes THREE STATES -- passed, failed, and NOT MEASURED --
#  and the default mode EXITS NON-ZERO if any pinned block is in the third."
#
# The lane self-test summary is DIAGNOSTIC and is not compared across lanes:
# "two lanes running different numbers of checks is expected: they are
# separately authored". The one thing the runners must agree on is whether every
# mandatory block executed, and that is a PER-LANE property.
# ==========================================================================

PASSED = "passed"
FAILED = "failed"
NOT_MEASURED = "not measured"


def block_states(result):
    """Classify every PINNED block. The registry is the contract's closed set,
    so a deleted block class leaves its ID here with no execution record and is
    reported NOT MEASURED -- which is what makes an omitted block visible.
    """
    failed = set()
    for test, _traceback in list(result.failures) + list(result.errors):
        block = getattr(test, "BLOCK", None)
        if block:
            failed.add(block)
    states = {}
    for block in MANDATORY_BLOCKS:
        if block in failed:
            states[block] = FAILED
        elif LEDGER.executed(block):
            states[block] = PASSED
        else:
            states[block] = NOT_MEASURED
    return states


def skips_by_block(result):
    out = {}
    for test, reason in result.skipped:
        block = getattr(test, "BLOCK", None)
        out.setdefault(block or "(unblocked)", []).append(reason)
    return out


def run_selftest(argv):
    allow_unmeasured = "--allow-unmeasured-blocks" in argv
    verbosity = 2 if "-v" in argv or "--verbose" in argv else 1
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=verbosity,
                                     stream=sys.stderr).run(suite)

    states = block_states(result)
    skips = skips_by_block(result)
    unknown = LEDGER.unknown_ids()
    duplicate = LEDGER.duplicate_ids()

    out = sys.stdout
    out.write("\n")
    out.write("PYTHON INTEROP EVALUATOR SELFTEST -- MANDATORY BLOCK ACCOUNTING\n")
    out.write("contract: INTEROP_REFERENCE_EVALUATOR_CONTRACT.md 8.7\n")
    out.write("evaluator_version: %s\n\n" % ev.EVALUATOR_VERSION)
    width = max(len(b) for b in MANDATORY_BLOCKS)
    for block in MANDATORY_BLOCKS:
        out.write("  %-*s  %-12s  assertions=%d  completions=%d%s\n" % (
            width, block, states[block],
            LEDGER.assertions.get(block, 0),
            LEDGER.completions.count(block),
            ("  skipped_tests=%d" % len(skips[block])) if block in skips else ""))
    counts = {PASSED: 0, FAILED: 0, NOT_MEASURED: 0}
    for state in states.values():
        counts[state] += 1
    out.write("\n  blocks: %d passed / %d failed / %d not measured (of %d pinned)\n"
              % (counts[PASSED], counts[FAILED], counts[NOT_MEASURED],
                 len(MANDATORY_BLOCKS)))
    # Diagnostic only -- never compared across lanes (contract 8.7).
    out.write("  tests (diagnostic): %d run / %d failed / %d errored / %d skipped\n"
              % (result.testsRun, len(result.failures), len(result.errors),
                 len(result.skipped)))
    for block, reasons in sorted(skips.items()):
        for reason in reasons:
            out.write("  SKIP  %s: %s\n" % (block, reason))
    if unknown:
        out.write("  NON-QUALIFYING: unknown block id(s): %s\n" % ", ".join(unknown))
    if duplicate:
        out.write("  NON-QUALIFYING: duplicate block id(s): %s\n"
                  % ", ".join(duplicate))

    qualifying = (not unknown and not duplicate
                  and counts[FAILED] == 0
                  and result.wasSuccessful())
    if counts[NOT_MEASURED]:
        if allow_unmeasured:
            out.write("  --allow-unmeasured-blocks: DEVELOPER MODE. The official "
                      "evidence command does not use this opt-in.\n")
        else:
            qualifying = False
    out.write("  run: %s\n" % ("QUALIFYING" if qualifying else "NON-QUALIFYING"))
    out.flush()
    return 0 if qualifying else 1


if __name__ == "__main__":
    sys.exit(run_selftest(sys.argv[1:]))
