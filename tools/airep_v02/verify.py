"""Beta admission + r3 profile adapter around the preserved r1 class engine.

The old command remains available for historical reproduction. New results are
beta regression evidence, not retroactive changes to r1 measurements.
"""
from .basis import SCHEMAS, verifier
from .json_input import loads, dumps, check_core_number_bounds
from .profiles import ProfileBases


def operator_inputs(*, bindings=None, independence_policy=None, revocation=None,
                    now=None, freshness_window=None):
    return verifier.build_ops(bindings, independence_policy, revocation, now, freshness_window)


def evaluate_request(raw, *, ops=None, profile_bases=None):
    # Preserve raw witness numeric tokens for the frozen lexical checks.
    if not isinstance(raw, (bytes, str)):
        raw = dumps(raw)
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    request = loads(raw)
    check_core_number_bounds(raw, request=True)
    verdict = verifier.evaluate(request, ops or verifier.OperatorInputs(), SCHEMAS,
                                verifier.claim_numeric_lexemes(raw))
    artifact = request['artifact']
    if artifact['artifact_type'] == 'effect' and artifact['observer_relationship'] == 'independent':
        candidates = [artifact] + request.get('related_artifacts', [])
        ref = artifact['execution_ref']
        matches = [a for a in candidates if a.get('record_id') == ref['record_id']]
        # An authenticated Decision is not an Execution. Global identity remains
        # unique even when a chain qualifier is supplied. The r1 adapter did not
        # enforce these two prerequisites on its observer path.
        if (len(matches) != 1 or matches[0].get('artifact_type') != 'execution'
                or ('chain_id' in ref and ref['chain_id'] != matches[0].get('chain_id'))):
            verdict['observer_assessment'] = 'unknown'
    bases = profile_bases or ProfileBases()
    verdict['profile_evaluations'] = bases.evaluate(artifact)
    verdict['evidence']['profile_bases_digest'] = bases.digest
    return verdict
