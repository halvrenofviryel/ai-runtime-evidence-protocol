"""NON-NORMATIVE rendering of existing beta reconciliation, not claim adjudication."""
from copy import deepcopy
import json

from .reconcile import reconcile


NOTICE = (
    'Derived explanatory view; NON-NORMATIVE rendering labels, not a new AIREP '
    'artifact family, conformance layer, assurance class or claim-support policy.'
)
LIMITS = [
    'SATISFIED means the named predicate holds over supplied reports, not event truth.',
    'MISSING means evidence is absent from this set, not that the event did not happen; '
    'missing receiver evidence is not proof of non-delivery.',
    'NOT_EVALUATED remains not evaluated; INDETERMINATE remains unresolved.',
    'Integrity and signature checks do not establish event truth or policy correctness.',
    'The structural summary is separate from support for a relying-party claim.',
    'Supplied records do not establish full-population, target-window or total-history coverage.',
]
CLAIMS = {
    'issuer_dispatch': 'control_issuer_dispatch_reported',
    'receiver_receipt': 'receiver_receipt_reported',
    'execution_evidence': 'execution_report_supplied',
    'execution_outcome': 'execution_outcome_reported',
    'effect_evidence': 'control_effect_observation_report_supplied',
    'intended_target_coverage': 'intended_target_coverage_evaluated',
}


def explain(artifacts, *, ops=None, profile_bases=None):
    """Reconcile original inputs once; preserve every native check and class result.

    No saved-report parser: artifacts use the existing admission and operator-input
    paths. No inference of enforcement, causation or consumer-specific claim support.
    """
    report = reconcile(artifacts, ops=ops, profile_bases=profile_bases)
    contexts = []
    for record in report['records']:
        if record['admission'] != 'SATISFIED':
            continue
        artifact = artifacts[record['input_index']]
        contexts.append({
            'input_index': record['input_index'],
            'artifact_ref': record['artifact_ref'],
            'artifact_type': artifact['artifact_type'],
            'scope': artifact['scope'],
            'reported_timestamp_utc': artifact['subject']['timestamp_utc'],
        })

    def row(claim, source, status, basis, references, subject, limitations):
        # Keep ambiguous occurrences, rather than selecting one record by ID.
        matching = [c for c in contexts if c['artifact_ref'] in references
                    or c['artifact_ref'] == subject
                    or c['artifact_ref'] == subject.get('decision_ref')]
        return {
            'claim': claim,
            'source': source,
            'source_check': None,
            'source_status': status,
            'explanatory_status': None,
            'basis': basis,
            'source_artifact_references': references,
            'context': {'subject': subject, 'artifact_input_indexes': [c['input_index'] for c in matching],
                        'population': report['scope'], 'target_window': None},
            'limitations': limitations,
        }

    matrix = [row(
        'aggregate_structural_reconciliation', '/summary/status', report['summary']['status'],
        'Existing reconciler summary over all native checks; counts retained in source_summary.',
        [], {}, ['No global PASS boolean or lifecycle assurance class; no relying-party claim established.'],
    )]
    for index, check in enumerate(report['checks']):
        claim = CLAIMS.get(check['check'], check['check'])
        is_decision = any(c['artifact_type'] == 'decision' and c['artifact_ref'] == check['subject']
                          for c in contexts)
        if is_decision and check['check'] == 'artifact_admission':
            claim = 'decision_recorded_and_integrity_checked'
        elif is_decision and check['check'] == 'record_authentication':
            claim = 'decision_authentication_checked'
        limitations = ['All view-level limitations apply; class reasons remain in record_assurance.']
        if check['check'] in ('execution_evidence', 'execution_outcome', 'toctou'):
            limitations.append('Execution presence, reported outcome and digest equality are distinct; '
                               'none independently establishes enforcement or effect.')
        if check['check'] == 'effect_evidence':
            limitations.append('An Effect reports observed state; binding alone does not prove '
                               'causation, desired effect or independent corroboration. '
                               'See effect_binding and observer_relationship checks.')
        item = row(claim, '/checks/' + str(index), check['state'], check['detail'],
                   check['evidence'], check['subject'], limitations)
        item['source_check'] = check['check']
        matrix.append(item)

    for claim, basis in (
        ('enforcement_observed', 'The beta reconciler has no separate enforcement predicate. '
         'Execution outcomes and TOCTOU comparisons are retained without interpreting them as enforcement.'),
        ('relying_party_claim_support', 'No relying-party claim or acceptance policy is evaluated '
         'by this reconciler. Native checks and per-record class reasons qualify any downstream use.'),
    ):
        item = row(claim, None, None, basis, [], {},
                   ['Not established by this view; this is not a negative finding about the event or claim.'])
        item['explanatory_status'] = 'NOT_EVALUATED'
        matrix.append(item)

    return deepcopy({
        'notice': NOTICE,
        'source_reconciliation_version': report['reconciliation_version'],
        'source_summary': report['summary'],
        'scope': report['scope'],
        'limitations': LIMITS,
        'context_notes': [
            'artifact_input_indexes refer to supplied input occurrences; artifact_context retains declared scope.',
            'Reported timestamps are not verified event times or an intended target window; '
            'null target_window means no evaluated target window is available.',
            'source uses JSON pointers into the equivalent reconcile output; null means no native predicate. '
            'A null source_status is not a native state. Only these unavailable predicates use the '
            'NON-NORMATIVE explanatory_status NOT_EVALUATED.',
        ],
        'claim_matrix': matrix,
        'artifact_context': contexts,
        'record_assurance': report['records'],
    })


def render_text(view):
    """Render every field of the same view used by --json; escape report text.

    JSON-encoded field values keep embedded newlines/control characters from
    masquerading as another row or status in terminal output.
    """
    def value(item):
        return json.dumps(item, ensure_ascii=True, sort_keys=True, allow_nan=False)

    lines = ['AIREP derived explanatory view (NON-NORMATIVE)']
    for key, item in view.items():
        if key == 'claim_matrix':
            lines.append('\nclaim_matrix:')
            for number, entry in enumerate(item, 1):
                lines.append(f'  [{number}]')
                lines.extend(f'    {field}: {value(content)}' for field, content in entry.items())
        elif key in ('artifact_context', 'record_assurance'):
            lines.append('\n' + key + ':')
            lines.extend('  ' + value(entry) for entry in item)
        else:
            lines.append(key + ': ' + value(item))
    return '\n'.join(lines) + '\n'
