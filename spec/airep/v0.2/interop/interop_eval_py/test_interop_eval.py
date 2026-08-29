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
import hashlib
import io
import json
import os
import shutil
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
            body = verdict(record_id)
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
        """
        out, err = io.StringIO(), io.StringIO()
        original = ev.invoke_frozen_verifier
        if stub is not None:
            ev.invoke_frozen_verifier = stub
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = ev.main(["--bundle", bundle] + list(extra))
        finally:
            ev.invoke_frozen_verifier = original
        return code, out.getvalue(), err.getvalue()

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
    """Contract 8.5: exit 1 is EXACTLY three conditions and no others."""

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
        so contract 8.5 leaves identity established; the violation is reported
        as manifest-invalid at exit 3 under Erratum 2's manifest-rule surface.
        Identity is taken last-wins, the shared default of both runtimes.
        """
        bundle = write_bundle(
            self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
            manifest_overrides=lambda m: (
                b'{"scenario_id": "IOP-P-CTL", "scenario_id": "IOP-P-DEC", '
                b'"manifest_version": "1", "files": []}'))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")   # last wins
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")
        self.assertIn("duplicate", result["nonmeasurement"]["detail"])

    def test_established_identity_never_falls_back_to_exit_1(self):
        """A structurally invalid manifest with a usable scenario_id is exit 3."""
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/d.json": DECISION},
                              manifest_overrides=lambda m: dict(m, surplus=1))
        code, out, _ = self.run_cli(bundle)
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertEqual(result["scenario_id"], "IOP-P-DEC")
        self.assertEqual(result["nonmeasurement"]["reason"], "manifest-invalid")


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
        manifest-invalid, and 8.5 pins exit 1 to three conditions of which
        "present but a link" is not one. Identity is established from the
        target, then the symlink is reported against the named scenario.
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

    def test_related_artifacts_are_the_other_three_sorted_by_record_id(self):
        bundle = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        stub = StubVerifier()
        self.evaluate(bundle, stub)
        for record_id, envelope, _ in stub.calls:
            related = [a["record_id"] for a in envelope["related_artifacts"]]
            self.assertEqual(len(related), 3)
            self.assertNotIn(record_id, related)
            self.assertEqual(related, sorted(related, key=lambda s: s.encode("utf-8")))

    def test_digest_is_a_function_of_the_bundle_not_of_manifest_order(self):
        """files[] order cannot change the envelope; only its sort rule is pinned."""
        bundle_a = write_bundle(self.root, "IOP-R-CLEAN", four_artifacts())
        first = self.evaluate(bundle_a)
        root_b = tempfile.mkdtemp(prefix="airep interop test ")
        self.addCleanup(shutil.rmtree, root_b, ignore_errors=True)
        bundle_b = write_bundle(root_b, "IOP-R-CLEAN", four_artifacts())
        second = self.evaluate(bundle_b)
        self.assertEqual([e["request_envelope_digest"] for e in first["artifacts"]],
                         [e["request_envelope_digest"] for e in second["artifacts"]])

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
        self.assertEqual(exc.withheld_reasons[0]["authenticated_withheld"],
                         ["producer-binding-absent"])
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
        self.assertEqual(result["withheld_reasons"][0]["witnessed_withheld"],
                         ["head-witness-absent"])


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
        doc = {k: v for k, v in DECISION.items() if k != "chain_id"}
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle)["artifacts"][0]
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
        self.assertEqual(len(ctx.exception.artifacts), 4)

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
            "bundle-json-invalid", "bundle-shape-invalid",
            "numeric-preflight-violation", "verifier-digest-mismatch",
            "verifier-not-invocable", "verifier-run-invalid", "internal-error",
            "authenticated-withheld"})

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

    def test_inconsistent_operator_flag_is_a_usage_error(self):
        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        code, out, _ = self.run_cli(bundle, ["--bindings", "/elsewhere/b.json"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

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

    def test_exit_0_with_a_wrong_shape_result(self):
        exc = self.abnormal(StubVerifier(default=(0, b'["not", "an", "object"]')))
        self.assertIn("single expected verdict object", exc.detail)

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
        be spawned or executed AT ALL. A process that ran and misbehaved is not
        it.
        """
        def cannot_spawn(request, flags):
            raise ev.NonMeasurement(
                "verifier-not-invocable",
                "frozen verifier could not be executed: [Errno 2] no such file")

        bundle = write_bundle(self.root, "IOP-P-DEC", {"artifacts/a.json": DECISION})
        exc = self.nonmeasurement(bundle, cannot_spawn)
        self.assertEqual(exc.reason, "verifier-not-invocable")
        self.assertEqual(exc.artifacts, [])       # nothing was ever attempted

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

    def test_an_empty_record_id_is_not_usable(self):
        doc = dict(DECISION, record_id="")
        bundle = write_bundle(self.root, "IOP-B-DEC", {"artifacts/a.json": doc})
        entry = self.evaluate(bundle,
                              StubVerifier(default=(1, None)))["artifacts"][0]
        self.assertIsNone(entry["artifact_ref"])

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

    def test_multi_artifact_bundle_without_record_id_fails_closed(self):
        """Recorded ambiguity A6. Contract 5.1 orders related_artifacts by
        record_id, so such a bundle has no defined envelope. No order is chosen.
        """
        arts = four_artifacts()
        del arts["artifacts/effect.json"]["record_id"]
        bundle = write_bundle(self.root, "IOP-R-CLEAN", arts)
        exc = self.nonmeasurement(bundle)
        self.assertEqual(exc.reason, "bundle-shape-invalid")
        self.assertIn("artifacts/effect.json", exc.detail)
        self.assertEqual(exc.artifacts, [])       # failed in preflight

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
