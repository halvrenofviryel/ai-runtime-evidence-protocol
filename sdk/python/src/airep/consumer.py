"""Versioned local policy alongside unchanged native reconciliation results."""
from ._native import digest_bytes
from ._native.reconcile import reconcile
from .io import bounded_loads, encoded, artifacts as admit_artifacts, check_bundle_sequences
from .mapping import BASIS, identity, project


def consume(raw, *, ops, expected_identity):
    bundle = bounded_loads(raw)
    check_bundle_sequences(raw)
    identity(expected_identity)
    if (type(bundle) is not dict or set(bundle) != {'format', 'basis', 'identity', 'producer', 'sources', 'artifacts'}
            or bundle['format'] != 'airep-sdk-hook-v1' or bundle['basis'] != BASIS):
        raise ValueError('unknown or malformed SDK mapping basis')
    identity(bundle['identity'])
    if type(bundle['producer']) is not str or not bundle['producer'] or len(bundle['producer']) > 256:
        raise ValueError('bounded producer identity required')
    native = reconcile(admit_artifacts(encoded(bundle['artifacts'])), ops=ops)
    scope_match = bundle['identity'] == expected_identity
    errors = []
    try:
        if type(bundle['sources']) is not list or any(type(s) is not str for s in bundle['sources']):
            raise ValueError('exact source strings required')
        expected, observation = project([s.encode() for s in bundle['sources']], bundle['identity'], bundle['producer'])
        if len(expected) != len(bundle['artifacts']):
            raise ValueError('source projection and artifact inventory differ')
        core = {'airep_version', 'artifact_type', 'chain_id', 'record_id', 'sequence', 'subject', 'scope', 'integrity', 'timestamp'}
        for row, actual in zip(expected, bundle['artifacts']):
            if (actual['artifact_type'] != row['family'] or actual['record_id'] != bundle['identity']['run_id'] + '.' + row['name'] or
                    actual['chain_id'] != bundle['identity']['run_id'] + '.chain' or actual['subject']['producer'] != bundle['producer'] or
                    actual['subject']['timestamp_utc'] != row['timestamp'] or
                    {k: v for k, v in actual.items() if k not in core} != row['payload']):
                raise ValueError('signed artifact/source projection differs')
        if any(r['admission'] != 'SATISFIED' or r['class_result']['authenticated_failures'] or
               r['class_result']['authenticated_withheld'] for r in native['records']):
            raise ValueError('artifact authentication not established by supplied operator trust')
        # Native failure (e.g. failed execution) remains visible, never upgraded.
    except (ValueError, TypeError, KeyError) as exc:
        errors.append(str(exc))
        observation = {'receipt': 'INDETERMINATE', 'execution': 'INDETERMINATE', 'effect': 'INDETERMINATE', 'window': None}
    if not scope_match:
        observation = {'receipt': 'MISSING', 'execution': 'MISSING', 'effect': 'MISSING', 'window': None}
    match = (scope_match and not errors and observation['receipt'] == 'RECEIVED' and
             observation['execution'] == 'PAUSED_REPORTED' and observation['effect'] == 'QUIESCENT_REPORTED' and
             not native['summary']['counts']['FAILURE'] and not native['summary']['counts']['INDETERMINATE'])
    return {'format': 'airep-sdk-consumer-result-v1', 'evaluation_completed': True,
            'native': native, 'consumer': {'policy': 'airep-sdk-local-pause-samples-v1', 'basis': BASIS,
            'input_digest': digest_bytes(raw.encode() if isinstance(raw, str) else raw),
            'identity_matches_query': scope_match, 'observation': observation, 'errors': errors,
            'policy_result': 'MATCH' if match else 'NO_MATCH',
            'qualification': 'First-party same-host reports and bounded samples; no independent or continuous enforcement.'}}
