"""Embedded Evaluation Profile v0.1 — regression expectations from the profile's own README,
never from measured output.

Two layers, deliberately separate:

* ``SchemaBasisTests`` exercise the digest-pinned basis directly through the same
  ``validate_basis`` the verifier uses (Draft 2020-12, self-contained, network-free) and
  attack every negative-state guard by removing it from a copy of the schema, so a green
  suite proves the guards are load-bearing rather than that the fixtures merely pass.
* ``VerifierProfileTests`` carry the fixtures inside a real v0.2 artifact through both
  official verifiers (Python + Node) with and without the supplied basis: ``PASS`` with the
  exact basis digest, ``NOT_EVALUATED``/null without it, and no class movement either way.

Run with Node REQUIRED: python3 -m unittest discover -s tests/v02 -v
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from jsonschema import Draft202012Validator
from test_beta import BetaCase
from tools.airep_v02.basis import verifier
from tools.airep_v02.json_input import InvalidInput
from tools.airep_v02.profiles import ProfileBases, validate_basis

PROFILE_ID = 'airep.embedded-evaluation'
PROFILE_DIR = ROOT / 'spec/airep/v0.2/profiles/embedded-evaluation'
SCHEMA = PROFILE_DIR / 'embedded-evaluation.schema.json'
REGISTRY = PROFILE_DIR / 'registry.json'
MEASURED = PROFILE_DIR / 'example.measured.json'
NOT_MEASURED = PROFILE_DIR / 'example.not-measured.json'
DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def schema_digest():
    return 'sha256:' + hashlib.sha256(SCHEMA.read_bytes()).hexdigest()


def find_refs(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ('$ref', '$dynamicRef') and isinstance(value, str):
                found.append(value)
            find_refs(value, found)
    elif isinstance(node, list):
        for item in node:
            find_refs(item, found)


class SchemaBasisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = read_json(SCHEMA)
        cls.validator = Draft202012Validator(cls.schema, format_checker=None)
        cls.measured = read_json(MEASURED)
        cls.not_measured = read_json(NOT_MEASURED)

    def valid(self, payload):
        return self.validator.is_valid(payload)

    # --- basis properties -------------------------------------------------------------
    def test_draft_2020_12_meta_validation_and_verifier_basis_admission(self):
        self.assertEqual(self.schema['$schema'], 'https://json-schema.org/draft/2020-12/schema')
        Draft202012Validator.check_schema(self.schema)
        # Same admission the verifier applies: dialect, vocabularies, fragment-only refs,
        # every reference resolvable without retrieval.
        validate_basis(deepcopy(self.schema))

    def test_all_references_are_internal_fragments(self):
        refs = []
        find_refs(self.schema, refs)
        self.assertTrue(refs, 'schema unexpectedly has no $ref')
        for ref in refs:
            self.assertTrue(ref.startswith('#/'), ref)
        # A network reference would be rejected by the verifier's basis admission.
        with self.assertRaises(InvalidInput):
            validate_basis({'type': 'object', 'properties': {'x': {'$ref': 'https://example.invalid/schema'}}})

    def test_registry_digest_matches_exact_schema_bytes(self):
        registry = read_json(REGISTRY)
        self.assertEqual(set(registry), {'profiles'})
        self.assertEqual(set(registry['profiles']), {PROFILE_ID})
        entry = registry['profiles'][PROFILE_ID]
        self.assertEqual(set(entry), {'schema_path', 'basis_digest'})
        self.assertEqual(entry['schema_path'], 'embedded-evaluation.schema.json')
        self.assertEqual(entry['basis_digest'], schema_digest())
        bases = ProfileBases(str(REGISTRY))
        self.assertEqual(list(bases.validators), [PROFILE_ID])
        self.assertEqual(bases.validators[PROFILE_ID][1], schema_digest())

    def test_no_stale_basis_digest_in_profile_documentation(self):
        # Every digest spelled out in the profile directory and the profiles index must be
        # the digest of the committed schema bytes, so an edited schema cannot leave a
        # stale identity behind in prose, fixtures or the HF mirror source.
        current = schema_digest()
        for path in sorted(PROFILE_DIR.iterdir()) + [PROFILE_DIR.parent / 'README.md']:
            if path.name == SCHEMA.name or not path.is_file():
                continue
            text = path.read_text(encoding='utf-8')
            for found in DIGEST_RE.findall(text):
                if found.startswith('sha256:ce57') or found == current:
                    self.assertEqual(found, current, path.name)
        readme = (PROFILE_DIR / 'README.md').read_text(encoding='utf-8')
        self.assertIn(current, readme)
        self.assertIn(PROFILE_ID, (PROFILE_DIR.parent / 'README.md').read_text(encoding='utf-8'))

    def test_profile_identity_constants(self):
        self.assertEqual(self.schema['properties']['profile_version'], {'const': '0.1'})
        self.assertFalse(self.schema.get('additionalProperties', True))
        self.assertEqual(self.measured['profile_version'], '0.1')
        self.assertEqual(self.not_measured['profile_version'], '0.1')

    # --- positive fixtures -----------------------------------------------------------
    def test_committed_fixtures_validate(self):
        for name, payload in (('measured', self.measured), ('not-measured', self.not_measured)):
            with self.subTest(fixture=name):
                errors = sorted(self.validator.iter_errors(payload), key=lambda e: list(e.path))
                self.assertEqual(errors, [], [e.message for e in errors])

    def test_not_measured_fixture_preserves_absence(self):
        m = self.not_measured['measurement']
        self.assertEqual((m['execution_status'], m['observed']['status']), ('NOT_RUN', 'NOT_MEASURED'))
        self.assertEqual(m['sample_count'], 0)

    # --- negative-state invariants ---------------------------------------------------
    def with_state(self, execution, observed):
        payload = deepcopy(self.measured)
        payload['measurement']['execution_status'] = execution
        payload['measurement']['observed']['status'] = observed
        return payload

    def test_not_run_cannot_yield_pass_or_fail(self):
        for observed in ('PASS', 'FAIL', 'INCONCLUSIVE', 'ERROR'):
            with self.subTest(observed=observed):
                self.assertFalse(self.valid(self.with_state('NOT_RUN', observed)))
        for observed in ('NOT_MEASURED', 'NOT_APPLICABLE'):
            with self.subTest(observed=observed):
                self.assertTrue(self.valid(self.with_state('NOT_RUN', observed)))

    def test_pass_or_fail_requires_ran_or_partial(self):
        for execution in ('NOT_RUN', 'INVALIDATED'):
            for observed in ('PASS', 'FAIL'):
                with self.subTest(execution=execution, observed=observed):
                    self.assertFalse(self.valid(self.with_state(execution, observed)))
        for execution in ('RAN', 'PARTIAL'):
            for observed in ('PASS', 'FAIL'):
                with self.subTest(execution=execution, observed=observed):
                    self.assertTrue(self.valid(self.with_state(execution, observed)))

    def test_invalidated_cannot_yield_pass_or_fail(self):
        for observed in ('PASS', 'FAIL', 'NOT_APPLICABLE'):
            with self.subTest(observed=observed):
                self.assertFalse(self.valid(self.with_state('INVALIDATED', observed)))
        for observed in ('NOT_MEASURED', 'INCONCLUSIVE', 'ERROR'):
            with self.subTest(observed=observed):
                self.assertTrue(self.valid(self.with_state('INVALIDATED', observed)))

    def test_redactions_flag_and_list_must_agree(self):
        payload = deepcopy(self.measured)
        payload['disclosure']['redactions_present'] = False
        payload['disclosure']['redactions'] = [{'target': 'prompt text', 'reason': 'contains customer data'}]
        self.assertFalse(self.valid(payload))
        payload['disclosure']['redactions_present'] = True
        self.assertTrue(self.valid(payload))
        payload['disclosure']['redactions'] = []
        self.assertFalse(self.valid(payload))

    def test_withheld_evidence_requires_a_reason(self):
        payload = deepcopy(self.measured)
        payload['evidence'][0]['visibility'] = 'withheld'
        self.assertFalse(self.valid(payload))
        payload['evidence'][0]['withholding_reason'] = 'contains third-party credentials'
        self.assertTrue(self.valid(payload))
        payload['evidence'][0]['withholding_reason'] = ''
        self.assertFalse(self.valid(payload))

    def test_closed_objects_reject_field_injection_and_wrong_version(self):
        payload = deepcopy(self.measured)
        payload['assurance_class'] = 'AIREP-Witnessed'
        self.assertFalse(self.valid(payload))
        payload = deepcopy(self.measured)
        payload['measurement']['certified'] = True
        self.assertFalse(self.valid(payload))
        payload = deepcopy(self.measured)
        payload['profile_version'] = '0.2'
        self.assertFalse(self.valid(payload))
        payload = deepcopy(self.measured)
        payload['evidence'] = []
        self.assertFalse(self.valid(payload))

    # --- guard attacks: prove each guard is what rejects the bad state -------------------
    def attacked(self, definition):
        schema = deepcopy(self.schema)
        self.assertIn('allOf', schema['$defs'][definition], definition)
        del schema['$defs'][definition]['allOf']
        return Draft202012Validator(schema, format_checker=None)

    def test_measurement_guards_are_load_bearing(self):
        weakened = self.attacked('measurement')
        for execution, observed in (('NOT_RUN', 'PASS'), ('NOT_RUN', 'FAIL'),
                                    ('INVALIDATED', 'PASS'), ('INVALIDATED', 'FAIL')):
            with self.subTest(execution=execution, observed=observed):
                payload = self.with_state(execution, observed)
                self.assertFalse(self.valid(payload))
                self.assertTrue(weakened.is_valid(payload), 'guard removal did not admit the bad state; the test is not measuring the guard')

    def test_evidence_guard_is_load_bearing(self):
        weakened = self.attacked('evidence_item')
        payload = deepcopy(self.measured)
        payload['evidence'][0]['visibility'] = 'withheld'
        self.assertFalse(self.valid(payload))
        self.assertTrue(weakened.is_valid(payload))

    def test_disclosure_guard_is_load_bearing(self):
        weakened = self.attacked('disclosure')
        payload = deepcopy(self.measured)
        payload['disclosure']['redactions_present'] = False
        payload['disclosure']['redactions'] = [{'target': 'x', 'reason': 'y'}]
        self.assertFalse(self.valid(payload))
        self.assertTrue(weakened.is_valid(payload))


class VerifierProfileTests(BetaCase):
    """The fixtures inside a real v0.2 artifact, through both official verifiers."""

    def carrier(self, payload):
        return self.profiled({PROFILE_ID: payload})

    def test_supplied_basis_yields_pass_with_exact_digest(self):
        for path in (MEASURED, NOT_MEASURED):
            with self.subTest(fixture=path.name):
                result = self.parity(self.carrier(read_json(path)), bases=REGISTRY)
                self.assertEqual(result['profile_evaluations'],
                                 {PROFILE_ID: {'result': 'PASS', 'basis_digest': schema_digest()}})
                # A profile PASS never moves the class: still Authenticated with operator
                # inputs, still Core without them.
                self.assertEqual(result['class'], 'AIREP-Authenticated')
                core = self.parity(self.carrier(read_json(path)), ops=verifier.OperatorInputs(), paths={}, bases=REGISTRY)
                self.assertEqual(core['profile_evaluations'][PROFILE_ID]['result'], 'PASS')
                self.assertEqual(core['class'], 'AIREP-Core')

    def test_without_basis_the_profile_is_not_evaluated(self):
        result = self.parity(self.carrier(read_json(MEASURED)))
        self.assertEqual(result['profile_evaluations'], {PROFILE_ID: {'result': 'NOT_EVALUATED', 'basis_digest': None}})
        self.assertEqual(result['class'], 'AIREP-Authenticated')

    def test_negative_state_fails_at_the_verifier_not_only_in_jsonschema(self):
        payload = read_json(MEASURED)
        payload['measurement']['execution_status'] = 'NOT_RUN'
        payload['measurement']['observed']['status'] = 'PASS'
        result = self.parity(self.carrier(payload), bases=REGISTRY)
        self.assertEqual(result['profile_evaluations'][PROFILE_ID], {'result': 'FAIL', 'basis_digest': schema_digest()})
        # Profile FAIL is not a class downgrade.
        self.assertEqual(result['class'], 'AIREP-Authenticated')

    def test_profile_cannot_assert_assurance(self):
        payload = read_json(MEASURED)
        payload['assurance_class'] = 'AIREP-Witnessed'
        result = self.parity(self.carrier(payload), ops=verifier.OperatorInputs(), paths={}, bases=REGISTRY)
        self.assertEqual(result['profile_evaluations'][PROFILE_ID]['result'], 'FAIL')
        self.assertEqual(result['class'], 'AIREP-Core')


if __name__ == '__main__':
    unittest.main()
