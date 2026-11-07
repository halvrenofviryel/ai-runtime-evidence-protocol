import copy
import json
from pathlib import Path
import tempfile
import unittest

from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads
from integrations.langgraph.boundaries.binding import Writer, CONTRACT, ACTORS, authenticate
from integrations.langgraph.boundaries.consumer import project, evaluate, OPS
from integrations.langgraph.boundaries.observer import project as observer_project
from integrations.langgraph.boundaries.report import make_inputs, replay


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='airep-boundary-tests-')
        cls.root = Path(cls.scratch.name)
        cls.inputs = make_inputs(cls.root)
        cls.views = replay(cls.inputs)

    @classmethod
    def tearDownClass(cls): cls.scratch.cleanup()

    def setUp(self):
        self.writer = Writer('controller')
        self.case = self.inputs['cases'][0]
        self.source = loads(self.case['delivery']['source_bytes'].encode())
        self.intent = copy.deepcopy(self.case['intent'])
        self.observer_trust = copy.deepcopy(self.case['observer_trust'])

    def result(self, source=None, *, intent=None, scope=None, projection=None, observer_trust=None):
        source = self.source if source is None else source
        mapped = loads(self.case['delivery']['projection_bytes'].encode()) if projection is None else projection
        delivery = self.writer.sign(source, mapped, scope=scope)
        return evaluate(delivery, self.intent if intent is None else intent, self.writer.trust,
                        self.observer_trust if observer_trust is None else observer_trust)

    def change_message(self, peer, kind, mutate):
        for row in self.source['schedule']:
            message = loads(bytes.fromhex(row['message_hex']))
            if row['peer']==peer and message.get('kind')==kind:
                mutate(message); row['message_hex']=encoded(message).hex(); return
        raise AssertionError('message not found')

    def test_T12_positive_two_targets_have_exact_denominator(self):
        result = self.views[0]['evaluation']['result']
        self.assertEqual(result['intended_target_count'], 2)
        self.assertEqual(result['bounded_pause_count'], 2)
        self.assertEqual(result['aggregate'], 'ALL_TARGETS_BOUNDED_PAUSE')
        self.assertEqual({t['target_id'] for t in result['targets']},{'A','B'})
        for t in result['targets']:
            self.assertEqual(t['stages'], {'receipt':'RECEIVED_REPORTED','execution':'PAUSED_REPORTED','effect':'QUIESCENT_REPORTED'})

    def test_T12_unknown_target_remains_present_and_partial(self):
        result = self.views[1]['evaluation']['result']; a,b = result['targets']
        self.assertEqual((result['aggregate'],result['bounded_pause_count'],result['intended_target_count']),('PARTIAL',1,2))
        self.assertEqual(b['stages'],dict.fromkeys(('receipt','execution','effect'),'MISSING'))
        self.assertTrue(b['cleanup']['forced']); self.assertFalse(b['bounded_pause'])
        self.assertTrue(a['bounded_pause'])
        self.assertTrue((self.root/'one_unknown/B/request.json').exists())
        self.assertTrue(any(r['event']['kind']=='ready' for r in b['history']))

    def test_T12_source_cannot_shrink_expected_intent(self):
        self.source['intent']['targets']=['A']
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_T12_omitted_replaced_or_duplicate_expected_targets_do_not_pass(self):
        for targets in (['A'],['A','A'],['A','C'],[]):
            intent=copy.deepcopy(self.intent);intent['targets']=targets
            with self.subTest(targets=targets): self.assertEqual(self.result(intent=intent)['admission'],'NO_MATCH')

    def test_target_identity_cannot_be_borrowed(self):
        self.change_message('B','ready',lambda m:m['identity'].update(target_id='A'))
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_receipt_requires_exact_command_bytes(self):
        self.change_message('A','receipt',lambda m:m['data'].update(command_hex=encoded({'op':'pause','identity':{'target_id':'B'}}).hex()))
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_native_pause_requires_matching_checkpoint_interrupt(self):
        self.change_message('A','native_paused',lambda m:m['data'].update(checkpoint_interrupts=[]))
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_T13_real_inflight_effect_commits_after_native_pause(self):
        result=self.views[2]['evaluation']['result']; t=result['targets'][0]
        self.assertEqual(result['aggregate'],'EFFECT_CONTINUED')
        self.assertEqual(t['stages']['execution'],'PAUSED_REPORTED')
        self.assertEqual(t['stages']['effect'],'CONTINUED_REPORTED')
        self.assertTrue(t['effect_commit_after_native_pause'])
        b=t['barriers'];order=[b[k] for k in ('inflight','receipt','pause','release','commit','cleanup')]
        self.assertEqual(order,sorted(set(order)))
        data=(self.root/'inflight/A/effects.jsonl').read_bytes()
        self.assertEqual(len(data.splitlines()),1)
        self.assertEqual(t['observer']['projection']['after_count'],1)
        self.assertEqual(t['observer']['projection']['before_count'],0)

    def test_T13_timeout_cleanup_never_counts_as_success(self):
        result=self.views[3]['evaluation']['result'];t=result['targets'][0]
        self.assertEqual(result['aggregate'],'CLEANUP_TERMINATED')
        self.assertTrue(t['cleanup']['forced']);self.assertNotEqual(t['cleanup']['exitcode'],0)
        self.assertFalse(t['bounded_pause']);self.assertFalse(t['effect_commit_after_native_pause'])
        self.assertEqual(t['stages']['execution'],'CONTINUED_REPORTED')
        self.assertEqual(t['stages']['effect'],'CONTINUED_REPORTED')
        self.assertLess(t['observer']['end_seq'],t['barriers']['cleanup'])

    def test_cleanup_sign_or_boolean_cannot_be_relabelled(self):
        case=self.inputs['cases'][3];source=loads(case['delivery']['source_bytes'].encode())
        for row in source['schedule']:
            if row['peer']=='A' and row['direction']=='cleanup':
                m=loads(bytes.fromhex(row['message_hex']));m['forced']=False;row['message_hex']=encoded(m).hex()
        self.assertEqual(self.result(source,intent=case['intent'],observer_trust=case['observer_trust'])['admission'],'NO_MATCH')

    def test_T14_actual_os_denials_owner_integrity_and_positive_write(self):
        executors=0
        for v in self.views[:4]:
            result=v['evaluation']['result']
            self.assertTrue(result['observer_owner_check']['owner_can_write'])
            for t in result['targets']:
                executors+=1;self.assertEqual(t['authority'],'TESTED_PATHS_RESTRICTED')
                p=t['authority_probe'];self.assertEqual({a['operation'] for a in p['attempts']},OPS)
                allowed={a['operation'] for a in p['attempts'] if a['allowed']}
                self.assertEqual(allowed,{'own_business_write'})
                self.assertIn('ro',p['observer_mount_options'][0].split(','))
                self.assertEqual(p['cap_eff'],'0000000000000000');self.assertEqual(p['no_new_privs'],'1')
        self.assertEqual(executors,6)
        self.assertEqual(self.inputs['unconfined_canary_control'],{'key_read':True,'record_write':True,'record_chmod':True})

    def test_T14_private_keys_are_removed_and_observer_really_writes(self):
        self.assertEqual(list(self.root.rglob('signing.key')),[])
        self.assertEqual(list(self.root.rglob('private')),[])
        for scenario in ('both_paused','one_unknown','inflight','timeout'):
            public=self.root/scenario/'observer/public'
            self.assertTrue((public/'record.json').exists());self.assertTrue((public/'effect-A.json').exists())
            self.assertEqual((public/'owner-write-check.json').read_bytes(),b'{}\n')

    def test_T14_failed_authority_does_not_upgrade_to_independence(self):
        result=self.views[4]['evaluation']
        self.assertEqual(result['admission'],'MATCH')
        self.assertEqual(result['result']['aggregate'],'BOUNDARY_NOT_ESTABLISHED')
        self.assertEqual(result['result']['targets'][0]['authority'],'BOUNDARY_NOT_ESTABLISHED')
        self.assertIn('same-host', ' '.join(result['result']['limits']))

    def test_T14_owner_side_mutation_prevents_authority_claim(self):
        self.change_message('observer','owner_check',lambda m:m.update(record_hash='sha256:'+'0'*64))
        mapped=project(self.source,self.intent,self.observer_trust)
        result=self.result(projection=mapped)
        self.assertEqual(result['result']['aggregate'],'BOUNDARY_NOT_ESTABLISHED')

    def test_T14_missing_probe_is_not_silently_assumed_passed(self):
        self.change_message('A','authority_probe',lambda m:m['data']['attempts'].pop())
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_T14_same_role_key_is_not_accepted(self):
        self.observer_trust['bindings']['bindings'][ACTORS['observer']]['public_key_hex']=self.writer.trust['bindings']['bindings'][ACTORS['controller']]['public_key_hex']
        self.assertIn('distinct',self.result()['errors'][0])

    def test_R3_valid_signature_with_stronger_scope_is_rejected(self):
        scope=copy.deepcopy(CONTRACT['scope']);scope['covers'].append('Independent permanent enforcement')
        result=self.result(scope=scope)
        self.assertEqual(result['admission'],'NO_MATCH')
        self.assertEqual(result['native']['class'],'AIREP-Authenticated')

    def test_R3_each_missing_limitation_is_rejected(self):
        for i in range(len(CONTRACT['scope']['does_not_cover'])):
            scope=copy.deepcopy(CONTRACT['scope']);del scope['does_not_cover'][i]
            self.assertEqual(self.result(scope=scope)['admission'],'NO_MATCH')

    def test_tampered_source_or_projection_bytes_are_rejected(self):
        for field in ('source_bytes','projection_bytes'):
            d=copy.deepcopy(self.case['delivery']);d[field]+=' '
            r=evaluate(d,self.intent,self.inputs['controller_trust'],self.observer_trust)
            self.assertEqual(r['admission'],'NO_MATCH')

    def test_missing_controller_trust_retains_native_withholding(self):
        trust=copy.deepcopy(self.inputs['controller_trust']);trust['revocation']=None
        r=evaluate(self.case['delivery'],self.intent,trust,self.observer_trust)
        self.assertEqual(r['admission'],'NO_MATCH')
        self.assertTrue(r['failed_authentication']['authenticated_withheld'])

    def test_duplicate_nonce_and_reversed_controller_ticks_are_rejected(self):
        original=copy.deepcopy(self.source)
        starts=[]
        for row in self.source['schedule']:
            m=loads(bytes.fromhex(row['message_hex']))
            if row['peer']=='observer' and m.get('op')=='start': starts.append((row,m))
        starts[1][1]['nonce']=starts[0][1]['nonce'];starts[1][0]['message_hex']=encoded(starts[1][1]).hex()
        self.assertEqual(self.result()['admission'],'NO_MATCH')
        self.source=original;self.source['schedule'][3]['tick']=0
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_signed_observer_wrong_nonce_identity_or_projection_cannot_pass(self):
        for field in ('nonce','identity','projection','scope'):
            with self.subTest(field=field):
                self.source=loads(self.case['delivery']['source_bytes'].encode()); writer=Writer('observer')
                for row in self.source['schedule']:
                    m=loads(bytes.fromhex(row['message_hex']))
                    if row['peer']=='observer' and m.get('kind')=='ready': m['trust']=writer.trust
                    elif row['peer']=='observer' and m.get('kind')=='observation':
                        raw=loads(m['delivery']['source_bytes'].encode());mapped=observer_project(raw);scope=None
                        if raw['identity']['target_id']=='A':
                            if field=='nonce': raw['nonce']='old-window';mapped=observer_project(raw)
                            elif field=='identity': raw['identity']['runtime_epoch']='old-epoch';mapped=observer_project(raw)
                            elif field=='projection': mapped['status']='CONTINUED_REPORTED'
                            else: scope=copy.deepcopy(CONTRACT['scope']);scope['does_not_cover']=[]
                        m['delivery']=writer.sign(raw,mapped,scope=scope)
                    row['message_hex']=encoded(m).hex()
                self.assertEqual(self.result(observer_trust=writer.trust)['admission'],'NO_MATCH')

    def test_observer_samples_cannot_replace_append_history_or_cross_target(self):
        t=self.views[2]['evaluation']['result']['targets'][0]
        source=copy.deepcopy(t['observer']['source']);row=loads(bytes.fromhex(source['after']['bytes_hex']).splitlines()[0])
        row['identity']['target_id']='B';source['after']['bytes_hex']=encoded(row).hex()
        with self.assertRaises(ValueError): observer_project(source)
        source=copy.deepcopy(t['observer']['source']);source['before']['end']=source['after']['end']+1
        with self.assertRaises(ValueError): observer_project(source)

    def test_replay_preserves_all_six_native_and_local_results(self):
        self.assertEqual(self.views,replay(loads(encoded(self.inputs))))
        self.assertEqual(len(self.views),6)
        for v in self.views[:5]: self.assertEqual(v['evaluation']['native']['class'],'AIREP-Authenticated')

    def test_public_observer_delivery_is_exactly_captured_and_authenticated(self):
        for case in self.inputs['cases'][:4]:
            source=loads(case['delivery']['source_bytes'].encode())
            for row in source['schedule']:
                m=loads(bytes.fromhex(row['message_hex']))
                if row['peer']=='observer' and m.get('kind')=='observation':
                    raw,mapped,native=authenticate(m['delivery'],case['observer_trust'],'observer')
                    self.assertEqual(mapped,observer_project(raw))
                    p=self.root/case['label']/'observer/public'/('effect-'+raw['identity']['target_id']+'.json')
                    self.assertEqual(p.read_bytes(),encoded(m['delivery']))

    def test_os_authority_never_upgrades_native_observer_assessment(self):
        for view in self.views[:4]:
            result=view['evaluation']
            self.assertEqual(result['native']['class'],'AIREP-Authenticated')
            self.assertEqual(result['native']['observer_assessment'],'not_applicable')
            for native in result['result']['observer_native']:
                self.assertEqual(native['class'],'AIREP-Authenticated')
                self.assertEqual(native['observer_assessment'],'not_applicable')
                self.assertIn('no-witness-supplied',native['witnessed_withheld'])
