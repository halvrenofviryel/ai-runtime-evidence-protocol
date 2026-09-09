"""Mechanical evidence-set reconciliation; see v0.2/RECONCILIATION.md."""
from collections import defaultdict

from .basis import verifier

from .producer import GENESIS, check_core, reference
from .verify import evaluate_request

STATES = ('SATISFIED', 'FAILURE', 'MISSING', 'NOT_EVALUATED', 'INDETERMINATE')


def reconcile(artifacts, *, ops=None, profile_bases=None):
    if not isinstance(artifacts, list):
        raise ValueError('reconciliation input must be an array of artifacts')
    checks, records, admitted = [], [], []

    def add(name, subject, state, detail, evidence=()):
        checks.append({'check':name, 'subject':subject, 'state':state,
                       'detail':detail, 'evidence':[reference(a) for a in sorted(evidence,
                            key=lambda a:(a['chain_id'].encode('utf-8'),a['record_id'].encode('utf-8')))]})

    for index, artifact in enumerate(artifacts):
        subject = {'input_index':index}
        try:
            doc = check_core(artifact)
        except (ValueError, TypeError, KeyError, RecursionError, verifier.RunInvalid) as exc:
            add('artifact_admission', subject, 'FAILURE', str(exc))
            records.append({'input_index':index, 'admission':'FAILURE', 'class_result':None})
            continue
        admitted.append(doc)
        add('artifact_admission', reference(doc), 'SATISFIED', 'Family schema and tagged hash verified.', [doc])
        records.append({'input_index':index, 'artifact_ref':reference(doc), 'admission':'SATISFIED', 'class_result':None})

    by_id = defaultdict(list)
    for doc in admitted:
        by_id[doc['record_id']].append(doc)
    for rid, entries in sorted(by_id.items()):
        add('record_identity', {'record_id':rid}, 'SATISFIED' if len(entries)==1 else 'INDETERMINATE',
            'Unique global record identity.' if len(entries)==1 else 'Duplicate global identity; no winner selected.', entries)

    # Class verification is independently visible for every admitted occurrence.
    for item in records:
        if item['admission'] != 'SATISFIED':
            continue
        doc = artifacts[item['input_index']]
        # admitted contains normalized copies, so omit exactly this occurrence.
        related = list(admitted)
        related.remove(check_core(doc))
        verdict = evaluate_request({'artifact':doc, 'related_artifacts':related}, ops=ops, profile_bases=profile_bases)
        item['class_result'] = verdict
        state = ('FAILURE' if verdict['authenticated_failures'] else
                 'NOT_EVALUATED' if verdict['authenticated_withheld'] else 'SATISFIED')
        add('record_authentication', reference(doc), state,
            'Class result retained separately; authentication does not establish report truth.', [doc])
    unique = [a for a in admitted if len(by_id[a['record_id']]) == 1]
    classes = {r['artifact_ref']['record_id']:r['class_result'] for r in records if r['admission']=='SATISFIED'}

    def resolve(ref, family, source, check):
        matches = by_id.get(ref['record_id'], [])
        if not matches:
            add(check, reference(source), 'MISSING', 'Referenced artifact is absent from admitted evidence.')
            return None
        if len(matches) != 1:
            add(check, reference(source), 'INDETERMINATE', 'Reference has ambiguous global identity.', matches)
            return None
        target = matches[0]
        if ('chain_id' in ref and target['chain_id'] != ref['chain_id']) or target['artifact_type'] != family:
            add(check, reference(source), 'FAILURE', 'Reference resolves to the wrong chain or artifact family.', [source, target])
            return None
        add(check, reference(source), 'SATISFIED', 'Exact reference resolved to ' + family + '.', [source, target])
        return target

    chains = defaultdict(list)
    for doc in admitted:
        chains[doc['chain_id']].append(doc)
    for cid, chain in sorted(chains.items()):
        seqs = defaultdict(list)
        for doc in chain:
            seqs[doc['sequence']].append(doc)
        for seq, docs in sorted(seqs.items()):
            subject = {'chain_id':cid, 'sequence':seq}
            if len(docs) != 1:
                add('chain_position', subject, 'INDETERMINATE', 'Multiple records occupy one chain position.', docs)
                add('chain_link', subject, 'NOT_EVALUATED', 'Ambiguous chain position.')
                continue
            doc = docs[0]
            prior = doc['integrity']['previous']
            matches = [a for a in chain if a['integrity']['current']==prior]
            if prior == GENESIS:
                add('chain_link', subject, 'FAILURE' if any(s < seq for s in seqs) else 'SATISFIED',
                    'Genesis cannot restart a chain after an earlier supplied record.', docs)
            elif len(matches)==1:
                previous = matches[0]
                valid = previous['sequence'] < seq and not any(previous['sequence'] < s < seq for s in seqs)
                add('chain_link', subject, 'SATISFIED' if valid else 'FAILURE',
                    'Resolved hash link must increase sequence without skipping a supplied record.', [previous,doc])
            elif len(matches)>1:
                add('chain_link', subject, 'NOT_EVALUATED', 'Ambiguous predecessor digest.')
            elif seq == 0:
                add('chain_link', subject, 'FAILURE', 'A non-genesis record at sequence zero has no possible earlier position.', docs)
            elif seq-1 not in seqs:
                add('chain_predecessor', subject, 'MISSING', 'Preceding chain position not supplied.')
                add('chain_link', subject, 'NOT_EVALUATED', 'No predecessor to compare.')
            elif len(seqs[seq-1]) != 1:
                add('chain_link', subject, 'NOT_EVALUATED', 'Ambiguous predecessor.')
            else:
                previous = seqs[seq-1][0]
                add('chain_link', subject, 'FAILURE',
                    'Compared against the supplied immediate predecessor.', [previous, doc])

    decisions, groups, effects = {}, defaultdict(list), []
    decision_for = {}
    for doc in unique:
        if doc['artifact_type'] == 'decision':
            decisions[doc['record_id']] = doc
            continue
        decision = resolve(doc['decision_ref'], 'decision', doc, 'decision_reference')
        if decision is not None:
            decision_for[doc['record_id']] = decision['record_id']
        else:
            add('decision_correlation', reference(doc), 'NOT_EVALUATED', 'Decision prerequisite unresolved.')
        if doc['artifact_type'] == 'effect':
            effects.append(doc)
        elif decision is not None:
            groups[(decision['record_id'], doc['instruction_id'])].append(doc)

    for rid, decision in sorted(decisions.items()):
        has_instruction = any(key[0] == rid for key in groups)
        add('instruction_evidence', reference(decision), 'SATISFIED' if has_instruction else 'MISSING',
            'At least one instruction is reported.' if has_instruction else 'No control/execution instruction evidence supplied.', [decision])
    for (did, iid), group in sorted(groups.items()):
        subject = {'decision_ref':reference(decisions[did]), 'instruction_id':iid}
        controls = [a for a in group if a['artifact_type']=='control']
        executions = [a for a in group if a['artifact_type']=='execution']
        digests = {a['instruction_digest'] for a in group}
        add('instruction_digest_agreement', subject, 'SATISFIED' if len(digests)==1 else 'FAILURE',
            'All evidence for this decision/instruction must bind the same instruction bytes.', group)
        for control in controls:
            event, side = control['control_event'], control['boundary_side']
            if (event=='dispatched' and side!='issuer') or (event=='received' and side!='receiver'):
                add('control_boundary', reference(control), 'FAILURE', 'Side cannot report the named boundary event.', [control])
        dispatch = [a for a in controls if a['control_event']=='dispatched' and a['boundary_side']=='issuer']
        receipt = [a for a in controls if a['control_event']=='received' and a['boundary_side']=='receiver']
        failed = [a for a in controls if a['control_event']=='delivery_failed']
        for name, observed in [('issuer_dispatch', dispatch), ('receiver_receipt', receipt), ('execution_evidence', executions)]:
            add(name, subject, 'SATISFIED' if observed else 'MISSING',
                'Matching evidence reports this stage.' if observed else 'No matching evidence supplied; event absence is not established.', observed)
        if failed:
            add('delivery_failure_report', subject, 'FAILURE', 'Explicit delivery_failed evidence is present.', failed)
            if receipt:
                add('delivery_outcome', subject, 'INDETERMINATE', 'Failure and receipt both reported; attempt history not established.', failed+receipt)
        for execution in executions:
            add('execution_outcome', reference(execution), 'SATISFIED' if execution['execution_event']=='executed' else 'FAILURE',
                'Reported execution_event: ' + execution['execution_event'], [execution])
        if len({a['execution_event'] for a in executions}) > 1:
            add('execution_outcomes', subject, 'INDETERMINATE', 'Multiple execution outcomes; no attempt selected.', executions)
        if controls:
            add('authorization_agreement', subject, 'SATISFIED' if len({a['authorized_action_digest'] for a in controls})==1 else 'FAILURE',
                'All Control authorization digests compared.', controls)
        if not controls or not executions:
            add('toctou', subject, 'NOT_EVALUATED', 'Both Control and Execution evidence are required.')
            add('execution_instruction_binding', subject, 'NOT_EVALUATED', 'Both Control and Execution evidence are required.')
        else:
            add('execution_instruction_binding', subject, 'SATISFIED' if len(digests)==1 else 'FAILURE',
                'Decision and instruction IDs resolve; instruction digests compared.', group)
            equal = all(c['authorized_action_digest']==e['executed_action_digest'] for c in controls for e in executions)
            add('toctou', subject, 'SATISFIED' if equal else 'FAILURE',
                'Compared authorized_action_digest with executed_action_digest for every applicable pair.', group)

    bound_effects = defaultdict(list)
    for effect in effects:
        execution = resolve(effect['execution_ref'], 'execution', effect, 'execution_reference')
        if execution is None or effect['record_id'] not in decision_for or execution['record_id'] not in decision_for:
            add('effect_binding', reference(effect), 'NOT_EVALUATED', 'Execution or Decision prerequisite unresolved.')
        elif decision_for[effect['record_id']] != decision_for[execution['record_id']]:
            add('effect_binding', reference(effect), 'FAILURE', 'Effect and Execution refer to different Decisions.', [effect, execution])
        else:
            add('effect_binding', reference(effect), 'SATISFIED', 'Effect binds this Execution and the same Decision.', [effect, execution])
            bound_effects[execution['record_id']].append(effect)
        declared = effect['observer_relationship']
        effective = classes[effect['record_id']]['observer_assessment']
        add('observer_relationship', reference(effect), 'INDETERMINATE' if declared=='independent' and effective!='independent' else
            'INDETERMINATE' if effective=='unknown' else 'SATISFIED',
            'Declared: ' + declared + '; effective: ' + effective + ('; no independent corroboration.' if effective=='same_executor' else '.'), [effect])
    for execution in unique:
        if execution['artifact_type']=='execution':
            matched = bound_effects[execution['record_id']]
            add('effect_evidence', reference(execution), 'SATISFIED' if matched else 'MISSING',
                'Bound Effect report supplied.' if matched else 'No bound Effect evidence; effect occurrence is unknown.', matched)
    if not artifacts:
        add('evidence_set', {}, 'MISSING', 'Empty supplied evidence set.')
    add('intended_target_coverage', {}, 'NOT_EVALUATED', 'No intended-target inventory supplied; total lifecycle completeness is not established.')
    counts = {state:sum(c['state']==state for c in checks) for state in STATES}
    status = 'FAILURE' if counts['FAILURE'] else 'INCOMPLETE' if any(counts[s] for s in STATES[2:]) else 'SATISFIED'
    return {'reconciliation_version':'0.2-beta.1', 'scope':'Supplied evidence reports only; no truth or total-history assurance.',
            'summary':{'status':status, 'counts':counts}, 'records':records, 'checks':checks}
