"""Beta regression expectations from normative clauses, never from measured output.

Run with Node REQUIRED: python3 -m unittest discover -s tests/v02 -v
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from examples.v02.run_lifecycle import lifecycle, policy, key_for, TIME, VARIANTS
from tools.airep_v02 import Chain, digest_json, digest_bytes, reference
from tools.airep_v02.basis import verifier, SCHEMAS, CV
from tools.airep_v02.json_input import loads, dumps, InvalidInput
from tools.airep_v02.profiles import ProfileBases
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.verify import evaluate_request, operator_inputs


def resign(record, key=None):
    record = deepcopy(record)
    key = key or key_for(record['subject']['producer'].split('.')[-1])
    record['integrity']['current'] = verifier.compute_current(record)
    record['integrity']['signature']['value'] = key.sign(verifier.record_sig_preimage(
        record['airep_version'], record['artifact_type'], 'ed25519', record['integrity']['current'])).hex()
    return record


def states(result, name):
    return [c['state'] for c in result['checks'] if c['check']==name]


class BetaCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('node'):
            raise AssertionError('Node is required; cross-runtime checks cannot be skipped')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='airep beta test ')
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.docs, self.payloads = lifecycle()
        self.bindings, self.revocation, self.independence = policy()
        self.paths = {}
        for name, value in [('bindings',self.bindings), ('revocation',self.revocation), ('independence-policy',self.independence)]:
            self.paths[name] = self.put(name+'.json', dumps(value))
        self.ops = operator_inputs(**{k.replace('-','_'):v for k,v in self.paths.items()})

    def put(self, name, raw):
        path = self.dir/name
        path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        return str(path)

    def request(self, index=0, docs=None):
        docs = self.docs if docs is None else docs
        return {'artifact':docs[index], 'related_artifacts':docs[:index]+docs[index+1:]}

    def node(self, request, *, paths=None, bases=None):
        raw = request if isinstance(request, (str,bytes)) else dumps(request)
        filename = self.put('request.json', raw)
        args = ['node', str(ROOT/'tools/airep_v02/verify_node.mjs'), '--request', filename]
        for k,v in (self.paths if paths is None else paths).items():
            args.extend(['--'+k, str(v)])
        if bases is not None:
            args.extend(['--profile-bases',str(bases)])
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)

    def parity(self, request, *, ops=None, paths=None, bases=None):
        py = evaluate_request(request, ops=self.ops if ops is None else ops, profile_bases=ProfileBases(bases))
        nd = self.node(request, paths=paths, bases=bases)
        self.assertEqual(nd.returncode, 0, nd.stderr)
        self.assertEqual(py, json.loads(nd.stdout))
        # The explicit profile ordering is part of r3's observable contract.
        self.assertEqual(list(py['profile_evaluations']), list(json.loads(nd.stdout)['profile_evaluations']))
        return py

    def profile_basis(self, schema, name='test.beta', raw=None):
        raw = dumps(schema) if raw is None else raw
        self.put('schema.json',raw)
        body = raw.encode() if isinstance(raw,str) else raw
        return self.put('bases.json',dumps({'profiles':{name:{'schema_path':'schema.json','basis_digest':digest_bytes(body)}}}))

    def profiled(self, profiles):
        doc = deepcopy(self.docs[0]); doc['profiles']=profiles
        return {'artifact':resign(doc)}


class ProducerTests(BetaCase):
    def test_four_families_authenticated_and_core(self):
        for i in range(5):
            with self.subTest(family=self.docs[i]['artifact_type']):
                result = self.parity(self.request(i))
                self.assertEqual(result['class'],'AIREP-Authenticated')
                self.assertEqual(result['witnessed_withheld'],['no-witness-supplied'])
                core = self.parity(self.request(i), ops=verifier.OperatorInputs(), paths={})
                self.assertEqual(core['class'],'AIREP-Core')
                self.assertEqual(core['authenticated_withheld'],['producer-binding-missing'])

    def test_witness_all_families_and_no_truth_class(self):
        wkey = key_for('observer')
        self.bindings['bindings']['demo.witness'] = dict(self.bindings['bindings']['demo.observer'], role='witness', subject_identity='demo.witness')
        self.bindings['witness_bindings']['demo.witness'] = 'demo.witness'
        self.revocation['bindings']['demo.witness']={'state':'active'}
        # Use governor to emit each head: witness identity and key must differ.
        self.independence['independent_pairs'].append({'a':'demo.governor','b':'demo.witness'})
        for name,value in [('bindings',self.bindings),('revocation',self.revocation),('independence-policy',self.independence)]:
            self.put(name+'.json',dumps(value))
        paths = dict(self.paths, now=TIME, **{'freshness-window':'60'})
        ops = operator_inputs(**{k.replace('-','_'):v for k,v in paths.items()})
        for family, payload in [('decision','decision'),('control','dispatch'),('execution','execution'),('effect','effect')]:
            with self.subTest(family=family):
                a = Chain(key_for('governor'),'demo.governor').emit(family,self.payloads[payload],timestamp=TIME)
                claim = {'chain_id':a['chain_id'],'sequence':0,'current':a['integrity']['current'],'length':1,'witnessed_at':TIME}
                request = {'artifact':a, 'head_witness':{'head_ref':reference(a),'witness_id':'demo.witness','claim':claim,
                    'signature':{'alg':'ed25519','value':wkey.sign(verifier.witness_sig_preimage('0.2','ed25519',claim)).hex()}}}
                self.assertEqual(self.parity(request,ops=ops,paths=paths)['class'],'AIREP-Witnessed')
                request['head_witness']['claim']['witnessed_at']='2000-01-01T00:00:00Z'
                self.assertNotEqual(self.parity(request,ops=ops,paths=paths)['class'],'AIREP-Witnessed')

    def test_deterministic_fixtures_reproduce_exactly(self):
        for name in VARIANTS:
            actual,_ = lifecycle(name)
            self.assertEqual(dumps(actual),(ROOT/'examples/v02/fixtures'/f'{name}.json').read_text())

    def test_chain_cursor_and_resume_and_mutation_isolation(self):
        c = Chain(key_for('governor'),'demo.governor',chain_id='test.chain')
        first = c.emit_decision(self.payloads['decision'],record_id='test.one',timestamp=TIME)
        original = deepcopy(first)
        first['scope']['covers'].append('caller mutation')
        second = c.emit_control(self.payloads['dispatch'],record_id='test.two',timestamp=TIME)
        self.assertEqual(second['sequence'],1)
        self.assertEqual(second['integrity']['previous'],original['integrity']['current'])
        resumed = Chain(key_for('governor'),'demo.governor',previous=second)
        third = resumed.emit_control(self.payloads['receipt'],timestamp=TIME)
        self.assertEqual(third['sequence'],2)
        with self.assertRaises(ValueError):
            Chain(key_for('governor'),'demo.governor',previous=second,chain_id='wrong')
        with self.assertRaises(ValueError):
            Chain(key_for('governor'),'demo.governor',previous=first)

    def test_rejected_emission_does_not_consume_position(self):
        c=Chain(key_for('governor'),'demo.governor')
        for payload in [{},dict(self.payloads['decision'],sequence=99),dict(self.payloads['decision'],surprise=True)]:
            with self.assertRaises((ValueError,verifier.RunInvalid)):
                c.emit_decision(payload)
        a=c.emit_decision(self.payloads['decision'],record_id='test.one',timestamp=TIME)
        self.assertEqual(a['sequence'],0)
        with self.assertRaises(ValueError):
            c.emit_decision(self.payloads['decision'],record_id='test.one')
        with self.assertRaises(ValueError):
            c.emit_decision(self.payloads['decision'],timestamp='2026-02-30T00:00:00Z')

    def test_body_type_version_and_signature_tampering(self):
        for index in (0,1,3,4):
            for mutation in ('body','type','version','malformed','wrong-key','wrong-domain','wrong-version-tag'):
                with self.subTest(index=index,mutation=mutation):
                    a=deepcopy(self.docs[index]); family=a['artifact_type']
                    if mutation=='body': a['scope']['covers'].append('tamper')
                    if mutation=='type': a['artifact_type']='effect' if family!='effect' else 'decision'
                    if mutation=='version': a['airep_version']='0.3'
                    if mutation=='malformed': a['integrity']['signature']['value']='abc'
                    if mutation=='wrong-key': a=resign(a,key_for('observer') if family!='effect' else key_for('governor'))
                    if mutation=='wrong-domain':
                        tag='decision' if family!='decision' else 'effect'
                        a['integrity']['signature']['value']=key_for(a['subject']['producer'].split('.')[-1]).sign(verifier.record_sig_preimage('0.2',tag,'ed25519',a['integrity']['current'])).hex()
                    if mutation=='wrong-version-tag':
                        a['integrity']['signature']['value']=key_for(a['subject']['producer'].split('.')[-1]).sign(('AIREP/0.3/sig/'+family+'\ned25519\n'+a['integrity']['current']).encode()).hex()
                    if mutation in ('wrong-key','wrong-domain','wrong-version-tag'):
                        v=self.parity({'artifact':a})
                        self.assertEqual(v['class'],'AIREP-Core')
                        self.assertEqual(v['authenticated_failures'],['producer-signature-invalid'])
                    else:
                        with self.assertRaises((ValueError,verifier.RunInvalid)):
                            evaluate_request({'artifact':a},ops=self.ops)
                        nd=self.node({'artifact':a}); self.assertEqual(nd.returncode,1,nd.stderr); self.assertEqual(nd.stdout,'')

    def test_wire_alg_never_selects_suite(self):
        for i in (0,1,3,4):
            r=self.request(i); r=deepcopy(r); r['artifact']['integrity']['signature']['alg']='hmac-sha256'
            v=self.parity(r)
            self.assertEqual(v['class'],'AIREP-Authenticated')
            self.assertIn('wire-alg-mismatch',v['authenticated_caveats'])

    def test_cli_every_emitter_and_verify_reconcile_negative(self):
        key=self.put('key.json',dumps({'seed_hex':'01'*32}))
        chain=[]
        for family,payload in [('decision','decision'),('control','dispatch'),('control','receipt'),('execution','execution'),('effect','effect')]:
            p=self.put('payload.json',dumps(self.payloads[payload])); out=str(self.dir/(payload+'.json'))
            cmd=[sys.executable,'-m','tools.airep_v02','emit-'+family,'--key',key,'--producer','demo.governor','--payload',p,
                 '--record-id','demo.'+payload,'--timestamp',TIME,'--out',out]
            if chain: cmd+=['--previous',str(self.dir/(('decision','dispatch','receipt','execution')[len(chain)-1]+'.json'))]
            else: cmd+=['--chain-id','demo.cli-chain']
            run=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            chain.append(read_json(out))
        inp=self.put('batch.json',dumps(chain))
        run=subprocess.run([sys.executable,'-m','tools.airep_v02','verify','--input',inp],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr); self.assertEqual(len(json.loads(run.stdout)['verdicts']),5)
        negative=self.put('negative.json',dumps(lifecycle('no-receipt')[0]))
        run=subprocess.run([sys.executable,'-m','tools.airep_v02','reconcile','--input',negative],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr); self.assertIn('MISSING',states(json.loads(run.stdout),'receiver_receipt'))

    def test_cli_invalid_input_emits_no_partial_results_or_traceback(self):
        docs=deepcopy(self.docs); del docs[3]['instruction_digest']
        inp=self.put('invalid.json',dumps(docs)); out=str(self.dir/'out.json')
        run=subprocess.run([sys.executable,'-m','tools.airep_v02','verify','--input',inp,'--out',out],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,1); self.assertFalse(Path(out).exists()); self.assertNotIn('Traceback',run.stderr)

    def test_keygen_file_permissions_and_no_overwrite(self):
        out=str(self.dir/'fresh-key.json')
        cmd=[sys.executable,'-m','tools.airep_v02','keygen','--out',out]
        first=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(first.returncode,0,first.stderr); before=Path(out).read_bytes()
        self.assertEqual(Path(out).stat().st_mode & 0o777,0o600)
        second=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(second.returncode,1); self.assertEqual(Path(out).read_bytes(),before)

    def test_request_out_usage_and_batch_duplicate_fail_closed(self):
        req=self.put('request.json',dumps(self.request())); out=self.put('existing.json','unchanged')
        run=subprocess.run([sys.executable,'-m','tools.airep_v02','verify','--request',req,'--out',out],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,2); self.assertEqual(Path(out).read_text(),'unchanged'); self.assertEqual(run.stdout,'')
        duplicate=self.put('duplicate.json',dumps([self.docs[0],self.docs[0]]))
        run=subprocess.run([sys.executable,'-m','tools.airep_v02','verify','--input',duplicate],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(run.returncode,1); self.assertEqual(run.stdout,'')

    def test_clone_location_with_spaces(self):
        clone=self.dir/'a clone with spaces'
        for rel in ('tools/airep_v02','spec/airep/v0.2/schemas'):
            shutil.copytree(ROOT/rel,clone/rel,ignore=shutil.ignore_patterns('__pycache__'))
        for rel in ('spec/airep/v0.2/class-verification/verifier_py/class_verifier.py',
                    'spec/airep/v0.2/class-verification/verifier_node_r2/class_verifier.mjs',
                    'spec/airep/v0.1/conformance/jcs.py'):
            p=clone/rel; p.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/rel,p)
        (clone/'spec/airep/v0.2/class-verification/verifier_node_r2/node_modules').symlink_to(CV/'verifier_node_r2/node_modules')
        req=self.put('portable-request.json',dumps(self.request()))
        for command in ([sys.executable,'-m','tools.airep_v02','verify'],['node','tools/airep_v02/verify_node.mjs']):
            run=subprocess.run(command+['--request',req],cwd=clone,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr); self.assertEqual(json.loads(run.stdout)['class'],'AIREP-Core')


def read_json(path):
    return loads(Path(path).read_bytes())


class ReconciliationTests(BetaCase):
    def test_complete_lifecycle_keeps_unknown_total_coverage(self):
        r=reconcile(self.docs,ops=self.ops)
        for name in ('decision_reference','issuer_dispatch','receiver_receipt','execution_instruction_binding','toctou','execution_reference','effect_binding','effect_evidence','observer_relationship','chain_link'):
            self.assertTrue(states(r,name)); self.assertEqual(set(states(r,name)),{'SATISFIED'},name)
        self.assertEqual(r['summary']['counts']['FAILURE'],0)
        self.assertEqual(r['summary']['status'],'INCOMPLETE')
        self.assertEqual(states(r,'intended_target_coverage'),['NOT_EVALUATED'])

    def test_required_failure_variants(self):
        expected={'no-receipt':('receiver_receipt','MISSING'),'no-execution':('execution_evidence','MISSING'),
                  'toctou-mismatch':('toctou','FAILURE'),'no-effect':('effect_evidence','MISSING'),
                  'same-executor':('observer_relationship','SATISFIED'),'unproven-independent':('observer_relationship','INDETERMINATE')}
        for variant,(check,state) in expected.items():
            with self.subTest(variant=variant):
                ops=self.ops if variant!='unproven-independent' else operator_inputs(bindings=self.paths['bindings'],revocation=self.paths['revocation'])
                r=reconcile(lifecycle(variant)[0],ops=ops)
                self.assertIn(state,states(r,check))
                if variant in ('no-receipt','no-execution','no-effect'):
                    self.assertNotIn('FAILURE',states(r,'execution_outcome'))
        for family in ('decision','control','execution','effect'):
            r=reconcile(lifecycle('broken-'+family)[0],ops=self.ops)
            self.assertIn('FAILURE',states(r,'artifact_admission'))

    def test_unresolved_wrong_family_wrong_chain_references(self):
        for key,ref,expected in [('decision_ref',{'record_id':'absent'},'MISSING'),
                ('decision_ref',reference(self.docs[3]),'FAILURE'),
                ('decision_ref',{'record_id':'demo.decision','chain_id':'wrong'},'FAILURE'),
                ('execution_ref',{'record_id':'absent'},'MISSING'),
                ('execution_ref',reference(self.docs[0]),'FAILURE')]:
            with self.subTest(key=key,ref=ref):
                docs=deepcopy(self.docs); docs[-1][key]=ref; docs[-1]=resign(docs[-1])
                r=reconcile(docs,ops=self.ops)
                self.assertIn(expected,states(r,'execution_reference' if key=='execution_ref' else 'decision_reference'))
                self.assertIn('MISSING',states(r,'effect_evidence'))

    def test_wrong_decision_and_instruction_digest(self):
        docs=deepcopy(self.docs); docs[2]['instruction_digest']='sha256:'+'a'*64; docs[2]=resign(docs[2])
        r=reconcile(docs,ops=self.ops)
        self.assertIn('FAILURE',states(r,'instruction_digest_agreement'))
        docs=deepcopy(self.docs); another=deepcopy(docs[0]); another['record_id']='demo.other'; another['chain_id']='demo.other-chain'; another=resign(another)
        docs[-1]['decision_ref']=reference(another); docs[-1]=resign(docs[-1]); docs.append(another)
        self.assertIn('FAILURE',states(reconcile(docs,ops=self.ops),'effect_binding'))

    def test_broken_previous_vs_missing_predecessor(self):
        docs=deepcopy(self.docs); docs[1]['integrity']['previous']='sha256:'+'b'*64; docs[1]=resign(docs[1])
        self.assertIn('FAILURE',states(reconcile(docs,ops=self.ops),'chain_link'))
        r=reconcile(self.docs[1:],ops=self.ops)
        self.assertIn('MISSING',states(r,'chain_predecessor')); self.assertIn('NOT_EVALUATED',states(r,'chain_link'))

    def test_monotonic_sequence_does_not_invent_a_contiguous_wire_rule(self):
        docs=deepcopy(self.docs); docs[1]['sequence']=7; docs[1]=resign(docs[1])
        r=reconcile(docs,ops=self.ops)
        self.assertEqual(set(states(r,'chain_link')),{'SATISFIED'})

    def test_duplicate_global_identity_is_never_resolved_by_chain(self):
        docs=deepcopy(self.docs); duplicate=deepcopy(docs[0]); duplicate['chain_id']='demo.another'; duplicate=resign(duplicate); docs.append(duplicate)
        r=reconcile(docs,ops=self.ops)
        self.assertIn('INDETERMINATE',states(r,'record_identity')); self.assertNotIn('SATISFIED',states(r,'decision_reference'))
        r=reconcile(self.docs+[deepcopy(self.docs[0])],ops=self.ops)
        self.assertIn('INDETERMINATE',states(r,'chain_position'))

    def test_wrong_boundary_and_explicit_failed_suppressed_outcomes(self):
        for event in ('failed','suppressed'):
            docs=deepcopy(self.docs); docs[3]['execution_event']=event; docs[3]=resign(docs[3])
            self.assertIn('FAILURE',states(reconcile(docs,ops=self.ops),'execution_outcome'))
        docs=deepcopy(self.docs); docs[2]['boundary_side']='issuer'; docs[2]=resign(docs[2])
        r=reconcile(docs,ops=self.ops); self.assertIn('FAILURE',states(r,'control_boundary')); self.assertIn('MISSING',states(r,'receiver_receipt'))
        docs=deepcopy(self.docs); failed=deepcopy(docs[1]); failed['record_id']='demo.failure'; failed['chain_id']='demo.failure-chain'; failed['sequence']=0
        failed['integrity']['previous']='sha256:'+'0'*64; failed['control_event']='delivery_failed'; docs.append(resign(failed))
        r=reconcile(docs,ops=self.ops); self.assertIn('FAILURE',states(r,'delivery_failure_report')); self.assertIn('INDETERMINATE',states(r,'delivery_outcome'))

    def test_multiple_executions_effect_for_one_cannot_hide_other(self):
        docs=deepcopy(self.docs); second=deepcopy(docs[3]); second['record_id']='demo.second-execution'; second['chain_id']='demo.second-chain'
        second['sequence']=0; second['integrity']['previous']='sha256:'+'0'*64; docs.append(resign(second))
        self.assertCountEqual(states(reconcile(docs,ops=self.ops),'effect_evidence'),['SATISFIED','MISSING'])

    def test_multiple_instructions_and_partial_observation(self):
        docs=deepcopy(self.docs); second=deepcopy(docs[1]); second['instruction_id']='demo.second-instruction'; second['record_id']='demo.second-dispatch'
        second['chain_id']='demo.second-chain'; second['sequence']=0; second['integrity']['previous']='sha256:'+'0'*64; docs.append(resign(second))
        r=reconcile(docs,ops=self.ops); self.assertCountEqual(states(r,'receiver_receipt'),['SATISFIED','MISSING'])

    def test_empty_malformed_and_core_only_are_not_success(self):
        self.assertEqual(states(reconcile([]),'evidence_set'),['MISSING'])
        r=reconcile([None, {}, 7]+self.docs,ops=self.ops)
        self.assertEqual(states(r,'artifact_admission').count('FAILURE'),3)
        self.assertEqual(set(states(reconcile(self.docs),'record_authentication')),{'NOT_EVALUATED'})

    def test_permutation_does_not_select_a_different_outcome(self):
        a=reconcile(self.docs,ops=self.ops); b=reconcile(list(reversed(self.docs)),ops=self.ops)
        self.assertEqual(a['summary'],b['summary'])
        self.assertEqual(sorted(map(lambda x:json.dumps(x,sort_keys=True),a['checks'])), sorted(map(lambda x:json.dumps(x,sort_keys=True),b['checks'])))

    def test_observer_requires_execution_family_and_unique_identity(self):
        # Reproduce the old observer gate's wrong-family acceptance using an
        # authentic Decision signed by the executor, which is still no Execution.
        fake=Chain(key_for('executor'),'demo.executor',chain_id='demo.fake').emit_decision(self.payloads['decision'],record_id='demo.fake-execution',timestamp=TIME)
        effect=deepcopy(self.docs[-1]); effect['execution_ref']=reference(fake); effect=resign(effect)
        v=self.parity({'artifact':effect,'related_artifacts':[fake]})
        self.assertEqual(v['class'],'AIREP-Authenticated'); self.assertEqual(v['observer_assessment'],'unknown')
        duplicate=deepcopy(self.docs[3]); duplicate['chain_id']='demo.duplicate'; duplicate=resign(duplicate)
        v=self.parity({'artifact':self.docs[-1],'related_artifacts':[self.docs[3],duplicate]})
        self.assertEqual(v['observer_assessment'],'unknown')

    def test_independence_requires_identity_key_policy_and_authentication(self):
        for mutation in ('same-identity','same-key','missing-policy','denied','revoked-executor','bad-effect-signature'):
            with self.subTest(mutation=mutation):
                bindings,rev,ind=policy(); docs=deepcopy(self.docs)
                if mutation=='same-identity': bindings['bindings']['demo.observer']['subject_identity']='demo.executor'
                if mutation=='same-key':
                    bindings['bindings']['demo.observer']['public_key_hex']=bindings['bindings']['demo.executor']['public_key_hex']
                    docs[-1]=resign(docs[-1],key_for('executor'))
                if mutation=='missing-policy': ind['independent_pairs']=[]
                if mutation=='denied': ind={'independent_pairs':[],'non_independent_pairs':[{'a':'demo.executor','b':'demo.observer'}]}
                if mutation=='revoked-executor': rev['bindings']['demo.executor']['state']='revoked'
                if mutation=='bad-effect-signature': docs[-1]=resign(docs[-1],key_for('governor'))
                for name,val in [('bindings',bindings),('revocation',rev),('independence-policy',ind)]: self.put(name+'.json',dumps(val))
                ops=operator_inputs(**{k.replace('-','_'):v for k,v in self.paths.items()})
                self.assertEqual(self.parity(self.request(4,docs),ops=ops)['observer_assessment'],'unknown')


class AdmissionAndProfileTests(BetaCase):
    def test_raw_json_boundary_in_both_runtimes(self):
        base=dumps(self.request())
        bad=[base.replace('"artifact": {','"artifact": {"record_id":"shadow",',1),
             base.replace('"artifact": {','"artifact": {"record\\u005fid":"shadow",',1),
             '\ufeff'+base, base.replace('Local owner','\\ud800'), base.replace('Local owner','\\uffff'),
             base.replace('"sequence": 0','"sequence": 1e400',1), b'\xff'+base.encode(), base+' true']
        for raw in bad:
            with self.subTest(raw=str(raw)[:60]):
                with self.assertRaises(InvalidInput): evaluate_request(raw,ops=self.ops)
                n=self.node(raw); self.assertEqual(n.returncode,1,n.stderr); self.assertEqual(n.stdout,'')

    def test_binary64_rounding_supplementary_unicode_and_safe_sequence(self):
        request=self.profiled({'test.numbers':{'n':9007199254740992.0,'tiny':1e-27,'big':1e23,'zero':-0.0,'unicode':'😀'}})
        raw=dumps(request).replace('9007199254740992.0','9007199254740993').replace('😀','\\ud83d\\ude00')
        self.assertEqual(self.parity(raw)['class'],'AIREP-Authenticated')
        raw=dumps(request).replace('"sequence": 0','"sequence": 9007199254740993',1)
        with self.assertRaises((ValueError,verifier.RunInvalid)): evaluate_request(raw,ops=self.ops)
        self.assertEqual(self.node(raw).returncode,1)

    def test_jcs_binary64_cross_language_sample(self):
        # Fixed bit patterns exercise the whole finite double domain, not only
        # convenient decimal/integer examples. This is bounded regression data,
        # not a proof of JCS over every binary64 value.
        import math
        rng=random.Random(8785)
        values=[struct.unpack('>d',rng.getrandbits(64).to_bytes(8,'big'))[0] for _ in range(4096)]
        values=[v for v in values if math.isfinite(v)]
        payload=self.put('numbers.json',json.dumps(values))
        run=subprocess.run(['node','-e','const fs=require("node:fs"); process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(process.argv[1],"utf8"))))',payload],capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(verifier.jcs.canonicalize(values),run.stdout)

    def test_raw_sequence_bounds_survive_rounding(self):
        for sequence,token in [(9007199254740991,'9007199254740991.1'),(0,'-1e-400')]:
            a=deepcopy(self.docs[0]); a['sequence']=sequence; a=resign(a)
            raw=dumps({'artifact':a}).replace('"sequence": '+str(sequence),'"sequence": '+token)
            with self.assertRaises(InvalidInput): evaluate_request(raw)
            self.assertEqual(self.node(raw).returncode,1)
        for token in ('-0','0.0','0e400','1e-400'):
            raw=dumps({'artifact':self.docs[0]}).replace('"sequence": 0','"sequence": '+token)
            self.assertEqual(self.parity(raw)['class'],'AIREP-Authenticated')

    def test_committed_test_profile_and_registry_symlink_root(self):
        basis=ROOT/'examples/v02/profile-basis/registry.json'
        r=self.parity(self.profiled({'airep.test-profile':{'sample':1}}),bases=basis)
        self.assertEqual(r['profile_evaluations']['airep.test-profile']['result'],'PASS')
        # The registry's resolved parent, not the symlink's directory, owns paths.
        link=self.dir/'linked-registry.json'; link.symlink_to(basis)
        self.assertEqual(self.parity(self.profiled({'airep.test-profile':{'sample':1}}),bases=link),r)

    def test_profiles_known_unknown_fail_and_format_annotation(self):
        schema={'type':'object','properties':{'n':{'type':'integer'},'email':{'type':'string','format':'email'}},'required':['n']}
        basis=self.profile_basis(schema)
        for value,want in [({'n':1,'email':'not an email'},'PASS'),({'n':'bad'},'FAIL')]:
            r=self.parity(self.profiled({'test.beta':value,'test.unknown':{'claims':'authenticated'}}),bases=basis)
            self.assertEqual(r['profile_evaluations']['test.beta']['result'],want)
            self.assertEqual(r['profile_evaluations']['test.unknown'],{'result':'NOT_EVALUATED','basis_digest':None})
            self.assertEqual(r['class'],'AIREP-Authenticated')

    def test_unknown_profile_cannot_raise_class_or_erase_withheld(self):
        r=self.parity(self.profiled({'test.unknown':{'class':'AIREP-Witnessed','trusted':True}}),ops=verifier.OperatorInputs(),paths={})
        self.assertEqual(r['class'],'AIREP-Core'); self.assertEqual(r['authenticated_withheld'],['producer-binding-missing'])

    def test_self_revocation_caveat_does_not_require_generic_basis(self):
        r=self.parity(self.profiled({'airep.key-trust':{'revocation':{'revoked':True}}}))
        self.assertEqual(r['class'],'AIREP-Authenticated')
        self.assertEqual(r['authenticated_caveats'],['producer-key-self-revoked'])
        self.assertEqual(r['profile_evaluations']['airep.key-trust']['result'],'NOT_EVALUATED')

    def test_profile_fragment_refs_and_unknown_annotations(self):
        basis=self.profile_basis({'$defs':{'x':{'type':'integer'}},'type':'object','properties':{'n':{'$ref':'#/$defs/x'}},
                                  'test-annotation':{'$ref':'https://example.invalid/not-a-dependency'}})
        self.assertEqual(self.parity(self.profiled({'test.beta':{'n':4}}),bases=basis)['profile_evaluations']['test.beta']['result'],'PASS')

    def test_unusable_basis_invalidates_run_without_partial_output(self):
        bad=[{'$ref':'other.json'}, {'$ref':'/absolute.json'}, {'$ref':'file:///tmp/other.json'},
             {'$ref':'https://example.invalid/schema'}, {'$schema':'http://json-schema.org/draft-07/schema#'},
             {'$vocabulary':{'https://example.invalid/vocab':True}}, {'$defs':{'unused':{'$ref':'#/absent'}}},
             {'properties':{'n':{'type':'not-a-type'}}}]
        for schema in bad:
            with self.subTest(schema=schema):
                basis=self.profile_basis(schema)
                with self.assertRaises(InvalidInput): ProfileBases(basis)
                n=self.node(self.profiled({'test.beta':{'n':1}}),bases=basis)
                self.assertEqual(n.returncode,1,n.stderr); self.assertEqual(n.stdout,'')
        for raw in ['{"properties":{"x":{"type":"string","type":"integer"}}}', '{"type":"object","type":"string"}']:
            basis=self.profile_basis({},raw=raw)
            with self.assertRaises(InvalidInput): ProfileBases(basis)
            self.assertEqual(self.node(self.profiled({'test.beta':{}}),bases=basis).returncode,1)

    def test_registry_duplicates_digest_substitution_and_containment(self):
        basis=self.profile_basis({'type':'object'})
        original=Path(basis).read_bytes()
        for mutate in ('digest','duplicate','symlink','absolute'):
            with self.subTest(mutate=mutate):
                Path(basis).write_bytes(original)
                doc=read_json(basis)
                if mutate=='digest': doc['profiles']['test.beta']['basis_digest']='sha256:'+'0'*64
                if mutate=='absolute': doc['profiles']['test.beta']['schema_path']=str(self.dir/'schema.json')
                if mutate=='symlink':
                    link=self.dir/'escape.json'; link.symlink_to(ROOT/'spec/airep/v0.2/schemas/common.schema.json')
                    doc['profiles']['test.beta']['schema_path']='escape.json'
                    doc['profiles']['test.beta']['basis_digest']=digest_bytes(link.read_bytes())
                raw=dumps(doc) if mutate!='duplicate' else '{"profiles":{},"profiles":{}}'
                Path(basis).write_text(raw)
                with self.assertRaises(InvalidInput): ProfileBases(basis)
                n=self.node(self.request(),bases=basis); self.assertEqual(n.returncode,1,n.stderr); self.assertEqual(n.stdout,'')

    def test_profile_identity_digest_and_order_are_not_substituted(self):
        basis=self.profile_basis({'type':'object'}, name='test.a')
        req=self.profiled({'test.z':{},'test.b':{},'test.a':{}})
        first=self.parity(req,bases=basis)
        self.assertEqual(list(first['profile_evaluations']),['test.a','test.b','test.z'])
        self.assertEqual(first['profile_evaluations']['test.b']['result'],'NOT_EVALUATED')
        basis=self.profile_basis({'type':'object','required':['absent']}, name='test.a')
        second=self.parity(req,bases=basis)
        self.assertNotEqual(first['profile_evaluations']['test.a']['basis_digest'],second['profile_evaluations']['test.a']['basis_digest'])
        self.assertEqual(second['profile_evaluations']['test.a']['result'],'FAIL')

    def test_historical_sixty_cases_through_beta_adapters(self):
        corpus=CV/'corpus'
        for case in read_json(corpus/'case_index.json'):
            with self.subTest(case=case['case_id']):
                files=case['files']; paths={flag:str(corpus/files[field]) for flag,field in [('bindings','bindings'),('revocation','revocation'),('independence-policy','independence')] if field in files}
                if 'clock' in files:
                    clock=read_json(corpus/files['clock'])
                    if 'now' in clock: paths['now']=clock['now']
                    if 'freshness_window_seconds' in clock: paths['freshness-window']=str(clock['freshness_window_seconds'])
                ops=operator_inputs(**{k.replace('-','_'):v for k,v in paths.items()})
                r=self.parity((corpus/files['request']).read_bytes(),ops=ops,paths=paths)
                expected=read_json(corpus/'cases'/case['case_id']/'expected.json')
                for key,val in expected.items(): self.assertEqual(r[key],val,(case['case_id'],key))


if __name__=='__main__':
    unittest.main()
