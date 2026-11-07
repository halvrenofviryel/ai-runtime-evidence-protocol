import copy
from pathlib import Path
import tempfile
import unittest
from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads
from integrations.langgraph.multitarget.binding import Writer, CONTRACT, BASIS, ACTORS, authenticate
from integrations.langgraph.multitarget.consumer import project, project_node, evaluate, intent_check
from integrations.langgraph.multitarget.report import make_inputs, replay


class MultiTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch=tempfile.TemporaryDirectory(prefix='airep-k7-tests-'); cls.root=Path(cls.scratch.name)
        cls.inputs=make_inputs(cls.root); cls.views=replay(cls.inputs)

    @classmethod
    def tearDownClass(cls): cls.scratch.cleanup()

    def setUp(self):
        self.writer=Writer('controller'); self.select('chain_all')

    def select(self,name):
        self.case=next(c for c in self.inputs['cases'] if c['label']==name)
        self.source=loads(self.case['delivery']['source_bytes'].encode())
        self.intent=copy.deepcopy(self.case['intent']); self.trusts=copy.deepcopy(self.case['node_trust'])
        self.mapped=loads(self.case['delivery']['projection_bytes'].encode())

    def result(self,*,scope=None):
        return evaluate(self.writer.sign(self.source,self.mapped,scope=scope),self.intent,self.writer.trust,self.trusts)

    def node(self,target): return loads(self.source['nodes'][target]['source_bytes'].encode())

    def sign_node(self,target,node,mapped=None):
        writer=Writer(target); self.trusts[target]=writer.trust
        if mapped is None: mapped=project_node(node,self.intent,target)
        self.source['nodes'][target]=writer.sign(node,mapped)

    def view(self,name): return next(v['evaluation'] for v in self.views if v['label']==name)

    def test_two_topologies_measure_three_target_positive_controls(self):
        for name in ('fanout_all','chain_all'):
            r=self.view(name)['result']
            self.assertEqual((r['bounded_pause_count'],r['intended_target_count']),(3,3))
            self.assertEqual(r['aggregate'],'ALL_ENUMERATED_TARGETS_BOUNDED_PAUSE')
            self.assertTrue(all(t['execution']=='PAUSED_REPORTED' and t['effect']=='QUIESCENT_REPORTED' for t in r['targets']))

    def test_real_processes_business_files_and_direct_worker_delegation(self):
        for case in self.inputs['cases'][:6]:
            self.select(case['label']); r=self.mapped
            self.assertEqual(len({t['node']['pid'] for t in r['targets']}),3)
            self.assertEqual(loads((self.root/case['label']/'intent-before-dispatch.json').read_bytes()),self.intent)
            for t in r['targets']:
                raw=(self.root/case['label']/t['target_id']/'effects.jsonl').read_bytes()
                self.assertTrue(raw.startswith(bytes.fromhex(t['observation']['after']['bytes_hex'])))
            if case['label']=='chain_all':
                self.assertEqual([e['data']['command_hex'] for e in self.source['events'] if e['kind']=='send'],
                                 [r['targets'][0]['attempts'][0]['command_hex']])
                self.assertEqual([t['attempts'][0]['command']['sender'] for t in r['targets']],['controller','A','B'])

    def test_unreachable_target_remains_in_denominator_and_continues(self):
        for name in ('fanout_unknown','chain_unknown'):
            r=self.view(name)['result']; c=r['targets'][2]
            self.assertEqual((r['bounded_pause_count'],r['intended_target_count']),(2,3))
            self.assertEqual((c['receipt'],c['execution'],c['effect'],c['transport']),
                             ('MISSING','UNKNOWN','CONTINUED_REPORTED','TRANSPORT_UNKNOWN'))
            self.assertTrue(c['cleanup']['forced']); self.assertFalse(c['bounded_pause'])

    def test_refusal_blocks_next_hop_without_hiding_target(self):
        r=self.view('chain_refused')['result']; a,b,c=r['targets']
        self.assertEqual(r['bounded_pause_count'],1)
        self.assertEqual((b['receipt'],b['execution'],b['effect']),('RECEIVED_REPORTED','REFUSED','CONTINUED_REPORTED'))
        self.assertEqual((c['execution'],c['transport'],c['delivery_attempt_count']),('UNKNOWN','NOT_ATTEMPTED',0))
        self.assertEqual(c['effect'],'CONTINUED_REPORTED')

    def test_lost_reply_retry_retains_failure_receipt_and_one_native_pause(self):
        r=self.view('chain_retry')['result']; c=r['targets'][2]
        self.assertEqual((r['intended_target_count'],r['delivery_attempt_count']),(3,4))
        self.assertEqual((c['delivery_attempt_count'],c['native_pause_count']),(2,1))
        first,second=c['attempts']; self.assertEqual(first['transport']['status'],'TRANSPORT_UNKNOWN')
        self.assertEqual(first['transport']['error'],'EOFError'); self.assertEqual(second['transport']['status'],'RESPONSE')
        self.assertEqual(first['command']['identity'],second['command']['identity'])
        self.assertNotEqual(first['command']['delivery_attempt_id'],second['command']['delivery_attempt_id'])
        self.assertTrue(c['node']['receipts'][0]['reply']['dropped'])
        self.assertFalse(c['node']['receipts'][0]['duplicate']); self.assertTrue(c['node']['receipts'][1]['duplicate'])

    def test_all_sender_receiver_bytes_are_exactly_correlated(self):
        for view in self.views[:6]:
            r=view['evaluation']['result']
            for t in r['targets']:
                incoming={x['command']['delivery_attempt_id']:x for x in t['node']['receipts']}
                for a in t['attempts']:
                    if a['command']['delivery_attempt_id'] in incoming:
                        self.assertEqual(a['command_hex'],incoming[a['command']['delivery_attempt_id']]['command_hex'])

    def test_signed_gateways_cannot_launder_refusal_or_unknown(self):
        for name in ('gateway_refusal_laundering','gateway_unknown_laundering'):
            e=self.view(name); self.assertEqual(e['admission'],'NO_MATCH')
            self.assertEqual(e['native']['class'],'AIREP-Authenticated')
            self.assertIn('gateway changed receiver response or fabricated success',e['errors'])
            case=next(c for c in self.inputs['cases'] if c['label']==name)
            source=loads(case['delivery']['source_bytes'].encode())
            for t in ('A','B','C'):
                raw,mapped,native=authenticate(source['nodes'][t],case['node_trust'][t],t)
                self.assertEqual(native['class'],'AIREP-Authenticated')
                self.assertEqual(mapped,project_node(raw,case['intent'],t))

    def test_native_coverage_and_reconciliation_are_not_upgraded(self):
        for view in self.views[:6]:
            e=view['evaluation']; native=e['native_reconciliation']
            self.assertEqual(native['summary']['status'],'INCOMPLETE')
            self.assertEqual([c['state'] for c in native['checks'] if c['check']=='intended_target_coverage'],['NOT_EVALUATED'])
            self.assertEqual(e['native']['observer_assessment'],'not_applicable')
            self.assertIn('no-witness-supplied',e['native']['witnessed_withheld'])

    def test_consumer_expected_inventory_cannot_be_narrowed_duplicated_or_replaced(self):
        for targets in (['A','B'],['A','B','B'],['A','B','D'],[]):
            self.intent['targets']=targets; self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_source_inventory_or_topology_cannot_override_external_intent(self):
        self.source['intent']['children']['B']=[]
        self.assertIn('expected intent mismatch',self.result()['errors'])

    def test_topology_cycles_and_wrong_parent_edges_are_rejected(self):
        self.intent['children']['C']=['A']
        with self.assertRaisesRegex(ValueError,'acyclic'): intent_check(self.intent)
        self.select('chain_all'); node=self.node('B')
        send=next(e for e in node['events'] if e['kind']=='send')
        command=loads(bytes.fromhex(send['data']['command_hex']));command['parent_delivery_attempt_id']='another-request'
        send['data']['command_hex']=encoded(command).hex()
        with self.assertRaisesRegex(ValueError,'descend'): project_node(node,self.intent,'B')

    def test_borrowed_epoch_control_checkpoint_or_target_is_rejected(self):
        for field in ('runtime_epoch','control_id','checkpoint_id','target_id'):
            node=self.node('A'); node['identity'][field]='borrowed'
            mapped=loads(self.source['nodes']['A']['projection_bytes'].encode());self.sign_node('A',node,mapped)
            self.assertEqual(self.result()['admission'],'NO_MATCH'); self.select('chain_all')

    def test_omitted_signed_target_report_is_rejected(self):
        del self.source['nodes']['C'];self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_lost_reply_cannot_be_relabelled_as_no_receipt(self):
        self.select('chain_retry'); node=self.node('C')
        node['events']=[e for e in node['events'] if e['kind'] not in ('receipt','native_paused','reply')]
        self.sign_node('C',node)
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_failed_first_send_cannot_be_dropped_while_receiver_history_survives(self):
        self.select('chain_retry'); node=self.node('B'); removed=False;events=[]
        for e in node['events']:
            if not removed and e['kind']=='send': removed=True;continue
            if e['kind']=='transport' and e['data']['status']=='TRANSPORT_UNKNOWN':continue
            if e['kind']=='reply':
                reply=loads(bytes.fromhex(e['data']['response_hex']));reply['children']=reply['children'][1:]
                e['data']['response_hex']=encoded(reply).hex()
            events.append(e)
        node['events']=events
        for i,e in enumerate(events,1):e['seq']=i
        self.sign_node('B',node);self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_native_pause_requires_matching_runtime_checkpoint_interrupt(self):
        node=self.node('A'); event=next(e for e in node['events'] if e['kind']=='native_paused')
        event['data']['checkpoint_interrupts']=[]
        with self.assertRaisesRegex(ValueError,'native interrupt'): project_node(node,self.intent,'A')

    def test_second_execution_on_retry_is_not_idempotent(self):
        self.select('chain_retry'); node=self.node('C')
        native=copy.deepcopy(next(e for e in node['events'] if e['kind']=='native_paused'))
        index=[i for i,e in enumerate(node['events']) if e['kind']=='receipt'][1]+1
        native['tick']=node['events'][index-1]['tick'];node['events'].insert(index,native)
        for i,e in enumerate(node['events'],1):e['seq']=i
        with self.assertRaisesRegex(ValueError,'repeated native'):project_node(node,self.intent,'C')

    def test_observation_identity_window_and_append_replacement_are_rejected(self):
        for mode in ('identity','window','replace'):
            self.select('chain_all');obs=self.source['observations']['A']
            if mode=='identity':obs['identity']['runtime_epoch']='old'
            elif mode=='window':obs['after']['start']=obs['before']['start']
            else:
                rows=bytes.fromhex(obs['after']['bytes_hex']).splitlines();obs['after']['bytes_hex']=(rows[0]+b'\n').hex()
            self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_cleanup_cannot_be_relabelled_as_success_or_before_observation(self):
        self.select('fanout_unknown');self.source['cleanup']['C']['forced']=False
        self.assertEqual(self.result()['admission'],'NO_MATCH')
        self.select('chain_all');self.source['cleanup']['A']['tick']=0
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_event_order_and_duplicate_delivery_id_rejected(self):
        self.source['events'][1]['tick']=0;self.assertEqual(self.result()['admission'],'NO_MATCH')
        self.select('chain_retry');node=self.node('C');receipts=[e for e in node['events'] if e['kind']=='receipt']
        receipts[1]['data']=receipts[0]['data']
        with self.assertRaisesRegex(ValueError,'duplicate delivery'):project_node(node,self.intent,'C')

    def test_signed_scope_expansion_or_missing_exclusion_is_rejected(self):
        scopes=[];expanded=copy.deepcopy(CONTRACT['scope']);expanded['covers'].append('permanent stop');scopes.append(expanded)
        for i in range(len(CONTRACT['scope']['does_not_cover'])):
            scope=copy.deepcopy(CONTRACT['scope']);del scope['does_not_cover'][i];scopes.append(scope)
        for scope in scopes:
            e=self.result(scope=scope);self.assertEqual(e['admission'],'NO_MATCH');self.assertEqual(e['native']['class'],'AIREP-Authenticated')

    def test_raw_source_or_projection_byte_tamper_is_rejected(self):
        for field in ('source_bytes','projection_bytes'):
            delivery=copy.deepcopy(self.case['delivery']);delivery[field]+=' '
            e=evaluate(delivery,self.intent,self.inputs['controller_trust'],self.trusts)
            self.assertEqual(e['admission'],'NO_MATCH')

    def test_signed_mapping_cannot_override_source_semantics(self):
        self.mapped['bounded_pause_count']=99
        self.assertIn('controller source projection mismatch',self.result()['errors'])

    def test_missing_trust_or_shared_role_key_is_rejected(self):
        self.trusts['B']['revocation']=None;self.assertEqual(self.result()['admission'],'NO_MATCH')
        self.select('chain_all')
        self.trusts['B']['bindings']['bindings'][ACTORS['B']]['public_key_hex']=self.trusts['A']['bindings']['bindings'][ACTORS['A']]['public_key_hex']
        self.assertIn('distinct role keys required',self.result()['errors'])

    def test_exported_node_reports_match_actual_capture_files(self):
        for case in self.inputs['cases'][:6]:
            source=loads(case['delivery']['source_bytes'].encode())
            for target in ('A','B','C'):
                self.assertEqual((self.root/case['label']/target/'delivery.json').read_bytes(),encoded(source['nodes'][target]))
        self.assertFalse(list(self.root.rglob('*.key')))

    def test_exact_saved_input_replay_preserves_native_and_local_results(self):
        self.assertEqual(self.views,replay(loads(encoded(self.inputs))))
        self.assertEqual(len(self.views),9)

    def test_wrong_basis_package_is_not_silently_reinterpreted(self):
        inputs=copy.deepcopy(self.inputs);inputs['basis_digest']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError,'basis'): replay(inputs)

    def test_closed_contract_rejects_extra_claims_and_wrong_types(self):
        self.source['complete_execution_paths']=True;self.assertEqual(self.result()['admission'],'NO_MATCH')
        self.select('chain_all');self.source['cleanup']['A']['exitcode']=False
        self.assertEqual(self.result()['admission'],'NO_MATCH')

    def test_boolean_reply_cannot_be_replaced_by_integer(self):
        node=self.node('A');event=next(e for e in node['events'] if e['kind']=='reply')
        reply=loads(bytes.fromhex(event['data']['response_hex']));reply['duplicate']=0
        event['data']['response_hex']=encoded(reply).hex()
        with self.assertRaisesRegex(ValueError,'typed reply'):project_node(node,self.intent,'A')
