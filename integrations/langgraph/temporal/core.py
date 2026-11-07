"""Local, bounded temporal consumer. Native AIREP verdicts remain untouched."""
from collections import defaultdict
from pathlib import Path
from tools.airep_v02.basis import verifier

from tools.airep_v02.json_input import loads
from tools.airep_v02.producer import digest_bytes, check_core
from tools.airep_v02.verify import evaluate_request

CONTRACT_BYTES = Path(__file__).with_name('CONTRACT.json').read_bytes()
BASIS = digest_bytes(CONTRACT_BYTES)
IDENTITY = tuple(loads(CONTRACT_BYTES)['identity'])
STATES = {'receipt': {'RECEIVED'}, 'execution': {'PAUSED', 'CONTINUED'},
          'effect': {'QUIESCENT', 'CONTINUED'}}
REQUIRED = {'basis_digest', 'identity', 'event_id', 'kind', 'status', 'source_actor',
            'boundary', 'predicate_id', 'source_ref', 'source_hash', 'clock_id', 'event_time',
            'observed_time', 'window', 'observer_relationship'}
MAX_BYTES = 131072


class AuthenticationFailure(ValueError):
    def __init__(self, native):
        super().__init__('native artifact authentication not established')
        self.native = native


def tick(value):
    return type(value) is int and 0 <= value <= 9007199254740991


def identity(value):
    if (type(value) is not dict or set(value) != set(IDENTITY)
        or any(type(v) is not str or not v or len(v) > 256 for v in value.values())):
        raise ValueError('exact, nonempty identity fields required')
    return tuple(value[k] for k in IDENTITY)


def window(value):
    if type(value) is not list or len(value) != 2 or not all(tick(v) for v in value) or value[0] > value[1]:
        raise ValueError('explicit ordered window required')
    return tuple(value)


def admit(delivery, sources, ops, *, source_policy=None):
    basis = BASIS if source_policy is None else source_policy.basis
    raw = delivery['event_bytes']
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError('bounded exact event bytes required')
    event = loads(raw)
    if type(event) is not dict or set(event) - REQUIRED - {'supersedes', 'revision_reason'} or REQUIRED - set(event):
        raise ValueError('closed event contract violated')
    identity(event['identity'])
    if event['basis_digest'] != basis:
        raise ValueError('unaccepted interpretation basis')
    if any(type(event[k]) is not str or not event[k] or len(event[k]) > 1024
           for k in ('event_id', 'source_actor', 'boundary', 'predicate_id', 'source_ref', 'clock_id')):
        raise ValueError('nonempty source metadata required')
    if event['kind'] not in STATES or event['status'] not in STATES[event['kind']]:
        raise ValueError('kind/status mismatch')
    if (not tick(event['event_time']) or not tick(event['observed_time'])
        or event['event_time'] > event['observed_time'] or not tick(delivery['arrival_time'])):
        raise ValueError('explicit event/observation/arrival ticks required')
    if window(event['window'])[1] > event['observed_time']:
        raise ValueError('observation precedes its claimed window')
    if event['observer_relationship'] != 'same_executor':
        raise ValueError('this local contract does not establish independence')
    if ('supersedes' in event) != ('revision_reason' in event):
        raise ValueError('revision reference and reason required together')
    if 'supersedes' in event and any(type(event[k]) is not str or not event[k]
                                    for k in ('supersedes', 'revision_reason')):
        raise ValueError('nonempty revision metadata required')
    source = sources.get(event['source_ref'])
    if type(source) is not bytes or len(source) > MAX_BYTES or digest_bytes(source) != event['source_hash']:
        raise ValueError('source bytes missing or hash mismatch')
    projection = {k: v for k, v in event.items() if k not in ('basis_digest', 'source_ref', 'source_hash')}
    source_projection = loads(source) if source_policy is None else source_policy.project(source)
    if source_projection != projection:
        raise ValueError('source-to-event identity/state projection mismatch')
    artifact = delivery['artifact']
    # Decisions record test reports under an explicit source policy. They are
    # not substituted for the native Control/Execution/Effect lifecycle.
    if artifact['artifact_type'] != 'decision':
        raise ValueError('temporal test report must be a Decision')
    check_core(artifact)
    native = evaluate_request({'artifact': artifact, 'related_artifacts': []}, ops=ops)
    if native['authenticated_failures'] or native['authenticated_withheld']:
        raise AuthenticationFailure(native)
    pointers = [p for p in artifact.get('evidence', []) if p.get('ref') == delivery['event_ref']]
    if len(pointers) != 1 or pointers[0].get('content_hash') != digest_bytes(raw):
        raise ValueError('exact event reference/hash not bound by signed artifact')
    if (artifact['subject']['producer'] != event['source_actor']
        or artifact['input']['input_ref'] != event['source_ref']
        or artifact['input']['input_digest'] != event['source_hash']
        or artifact['output']['result_ref'] != delivery['event_ref']
        or artifact['output']['result_digest'] != digest_bytes(raw)
        or basis not in artifact['claim']['basis']):
        raise ValueError('signed actor/source/basis binding mismatch')
    return {'event': event, 'event_hash': digest_bytes(raw), 'arrival_time': delivery['arrival_time'],
            'artifact_ref': {'chain_id': artifact['chain_id'], 'record_id': artifact['record_id']},
            'native_verification': native}


def evaluate(deliveries, query, sources, ops, *, revision_authorities=(), source_policy=None):
    wanted = identity(query['identity'])
    target_window = window(query['window'])
    if (not tick(query['cutoff']) or query['cutoff'] < target_window[1]
        or any(type(query[k]) is not str or not query[k] for k in ('clock_id', 'boundary', 'predicate_id'))):
        raise ValueError('explicit accepted clock and cutoff covering window required')
    if len(deliveries) > 1000:
        raise ValueError('bounded report inventory exceeded')
    history, errors, grouped = [], [], defaultdict(list)
    for index, delivery in enumerate(deliveries):
        try:
            row = admit(delivery, sources, ops, source_policy=source_policy)
            e = row['event']
            grouped[(identity(e['identity']), e['event_id'])].append(row)
        except (ValueError, TypeError, KeyError, RecursionError, verifier.RunInvalid) as exc:
            error = {'input_index': index, 'reason': str(exc)}
            if isinstance(exc, AuthenticationFailure):
                error['native_verification'] = exc.native
            errors.append(error)
    conflict = False
    duplicates = 0
    for key in sorted(grouped):
        rows = grouped[key]
        by_hash = defaultdict(list)
        for row in rows:
            by_hash[row['event_hash']].append(row)
        unique = {h: min(items, key=lambda r: (r['artifact_ref']['chain_id'], r['artifact_ref']['record_id']))
                  for h, items in by_hash.items()}
        duplicates += len(rows) - len(unique)
        for h in sorted(unique):
            row = unique[h]
            # Arrival metadata is local transport history, not source ordering.
            row['arrivals'] = sorted(r['arrival_time'] for r in rows if r['event_hash'] == h)
            reports = {tuple(sorted(r['artifact_ref'].items())): r['native_verification'] for r in by_hash[h]}
            row['bound_reports'] = [{'artifact_ref': dict(ref), 'native_verification': reports[ref]}
                                    for ref in sorted(reports)]
            row['arrival_time'] = row['arrivals'][0]
            row['identity_conflict'] = len(unique) > 1
            row['in_query_identity'] = key[0] == wanted
            history.append(row)
        conflict |= key[0] == wanted and len(unique) > 1
    relevant = [r for r in history if r['in_query_identity']
                and r['event']['boundary'] == query['boundary']
                and r['event']['predicate_id'] == query['predicate_id']]
    wrong_clock = any(r['event']['clock_id'] != query['clock_id'] for r in relevant)
    selected = [r for r in relevant if r['event']['clock_id'] == query['clock_id']
                and r['event']['event_time'] <= query['cutoff']
                and r['event']['observed_time'] <= query['cutoff']]
    by_id = {r['event']['event_id']: r for r in selected}
    superseded, revision_errors = set(), []
    for row in selected:
        e = row['event']
        if 'supersedes' not in e:
            continue
        prior = by_id.get(e['supersedes'])
        old = prior['event'] if prior else {}
        valid = (prior is not None and e['source_actor'] in revision_authorities
                 and all(e[k] == old[k] for k in ('identity', 'kind', 'window', 'clock_id', 'source_actor', 'boundary', 'predicate_id'))
                 and e['event_time'] > old['event_time'] and e['observed_time'] >= old['observed_time'])
        if valid:
            superseded.add(e['supersedes'])
        else:
            revision_errors.append(e['event_id'])
    for row in history:
        row['superseded'] = row['in_query_identity'] and row['event']['event_id'] in superseded
    active = [r for r in selected if r['event']['event_id'] not in superseded]
    stages = {}
    for kind in STATES:
        rows = [r for r in active if r['event']['kind'] == kind]
        if kind == 'effect':
            rows = [r for r in rows if window(r['event']['window']) == target_window]
        elif rows:
            latest = max(r['event']['event_time'] for r in rows)
            rows = [r for r in rows if r['event']['event_time'] == latest]
        statuses = {r['event']['status'] for r in rows}
        status = 'MISSING' if not rows else next(iter(statuses)) + '_REPORTED' if len(statuses) == 1 else 'INDETERMINATE'
        if errors or conflict or wrong_clock or revision_errors:
            status = 'INDETERMINATE'
        stages[kind] = {'status': status, 'event_ids': sorted(r['event']['event_id'] for r in rows)}
    return {'policy': 'local-temporal-consumer-v1' if source_policy is None else source_policy.name,
            'basis_digest': BASIS if source_policy is None else source_policy.basis, 'query': query,
            'stages': stages, 'history': history, 'binding_errors': errors,
            'identity_conflict': conflict, 'ordering_unestablished': wrong_clock,
            'revision_errors': revision_errors, 'duplicate_deliveries': duplicates,
            'limits': (['Authored fixture reports; no independently observed enforcement.',
                       'Effect result is bounded to the requested window and supplied inventory.',
                       'Native verifier results are retained; this policy does not upgrade them.',
                       'No durable restart, independent observer, or production adapter tested here.']
                       if source_policy is None else list(source_policy.limits))}
