"""Offline conformance for the planning-only V12 evidence graph.

These probes never execute a task.  They prove that a future replay implementation
has no ambient-path or ambient-package choice in either golden envelope.
"""
import base64, copy, hashlib, json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, RefResolver

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / 'schemas/m0-2-decision-evidence-envelope.v12.schema.json'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def digest_record(value, key):
    value = copy.deepcopy(value); value.pop(key, None)
    return hashlib.sha256(canonical(value)).hexdigest()
def validator():
    schema = json.loads(SCHEMA.read_text())
    return Draft202012Validator(schema, resolver=RefResolver(SCHEMA.resolve().as_uri(), schema))

class V12Conformance(unittest.TestCase):
    names = ('m0-2-v12-dispatch.json', 'm0-2-v12-deny.json')
    def load(self, name):
        return json.loads((ROOT / 'tests/fixtures' / name).read_text())
    def fail_graph(self, value):
        """Resolve every retained edge; false is an intentional negative result."""
        artifacts = {x['artifact_id']: x for x in value['artifacts']}
        blobs = {x['blob_id']: x for x in value['blobs']}
        if len(artifacts) != len(value['artifacts']) or len(blobs) != len(value['blobs']): return False
        def blob(blob_id):
            x=blobs.get(blob_id)
            if not x: return None
            try: raw=base64.b64decode(x['content_base64'], validate=True)
            except Exception: return None
            return x if (len(raw)==x['byte_length'] and hashlib.sha256(raw).hexdigest()==x['digest']==x['blob_id']) else None
        def file(artifact_id):
            x=artifacts.get(artifact_id)
            return x if x and x['kind']=='FILE' and x['raw_sha256']==x['blob_id'] and blob(x['blob_id']) else None
        # tagged artifact variants are independently retained and exactly digest-bound.
        for x in artifacts.values():
            if x['kind']=='FILE' and not file(x['artifact_id']): return False
            if x['kind']=='ABSENT' and x['absence_assertion_sha256'] != digest_record(x, 'absence_assertion_sha256'): return False
            if x['kind']=='DIRECTORY':
                if x['inventory_sha256'] != hashlib.sha256(canonical(x['members'])).hexdigest(): return False
                paths=[]
                for m in x['members']:
                    f=file(m['artifact_id'])
                    if not f or f['raw_sha256'] != m['raw_sha256'] or m['relative_path'] in paths: return False
                    paths.append(m['relative_path'])
        # exact canonical input/source binding; currentness is deliberately excluded.
        h=value['historical_input']; sm=value['source_manifest']
        direct={h['task']['artifact_id'],h['assignment']['artifact_id'],h['handoff']['artifact_id'],h['project']['artifact_id']}
        for d in h['dependencies']: direct |= {d['task']['artifact_id'],d['completion']['artifact_id']}
        direct |= {x['artifact_id'] for x in h['capabilities']}
        if set(sm['source_artifact_ids']) != direct or set(sm['inventory_ids']) != {h['stop_inventory_id']} or h['stop_inventory_id'] not in artifacts: return False
        if sm['canonical_input_sha256'] != hashlib.sha256(canonical(h)).hexdigest() or sm['source_set_sha256'] != digest_record(sm,'source_set_sha256'): return False
        if value['git_observation']['observation_id'] != h['git_observation_id'] or value['git_observation']['repository_id'] != h['repository_id'] or value['git_observation']['observation_sha256'] != digest_record(value['git_observation'],'observation_sha256'): return False
        # Engine is the unique owner of manifests and closure, never path-selected.
        e=value['engine_distribution']; im=value['import_manifest']; vm=value['validation_manifest']; cl=value['dependency_closure']
        if e['distribution_sha256'] != digest_record(e,'distribution_sha256'): return False
        if (e['import_manifest_id'],e['validation_manifest_id'],e['closure_id'],e['closure_sha256']) != (im['manifest_id'],vm['manifest_id'],cl['closure_id'],cl['closure_sha256']): return False
        closure=json.loads((ROOT/'docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v4.json').read_text())
        if cl['version'] != closure['version'] or cl['closure_sha256'] != closure['closure_sha256'] or digest_record(closure,'closure_sha256') != cl['closure_sha256']: return False
        if e['interpreter']['implementation'] != 'CPython' or not e['interpreter']['version']: return False
        if e['environment'] != {'PYTHONHASHSEED':'0','LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONIOENCODING':'utf-8'} or not safe_path(e['working_directory']): return False
        if set(e['local_artifact_ids']) != {'engine','launcher','clock-shim','git-shim','orchestration','validate','data-integrity'}: return False
        if any(not file(a) for a in e['local_artifact_ids']): return False
        if im['digest'] != digest_record(im,'digest') or vm['digest'] != digest_record(vm,'digest'): return False
        for x in im['local_modules']:
            f=file(x['artifact_id'])
            if not f or f['raw_sha256'] != x['sha256'] or not safe_path(x['replay_path']): return False
        packages={x['distribution_id']:x for x in e['packages']}
        if len(packages)!=len(e['packages']) or set(x['name'] for x in packages.values()) != set(closure['packages']): return False
        for x in im['external_imports']:
            if x['distribution_id'] not in packages: return False
        if vm['validator_distribution_id'] not in packages: return False
        for p in packages.values():
            if not blob(p['blob_id']) or p['sha256'] != p['blob_id'] or p['python'] != 'CPython 3.13' or p['platform'] != 'fixture-platform': return False
        for x in vm['schemas']:
            f=file(x['artifact_id'])
            if not f or f['raw_sha256'] != x['sha256'] or not safe_path(x['replay_path']): return False
            if any(ref not in {s['schema_id'] for s in vm['schemas']} for ref in x['references']): return False
        raw={k:value['raw_evidence'][k] for k in ('decision','decision_id','task_id','reason','execution_adapter')}
        if raw['decision']=='DISPATCH': raw['operation']=value['raw_evidence']['operation']
        b=canonical(raw); re=value['raw_evidence']
        if base64.b64decode(re['bytes_base64'],validate=True)!=b or re['byte_length']!=len(b) or re['sha256']!=hashlib.sha256(b).hexdigest(): return False
        normalized_expected = dict(raw)
        if raw['decision'] == 'DENY': normalized_expected['operation'] = None
        if value['normalized_output'] != normalized_expected: return False
        if value['envelope_sha256'] != digest_record(value,'envelope_sha256'): return False
        return True

    def test_golden_dispatch_and_deny_validate(self):
        check=validator()
        for name in self.names: self.assertFalse(list(check.iter_errors(self.load(name))))
    def test_complete_root_graph_resolves_without_ambient_runtime(self):
        for name in self.names: self.assertTrue(self.fail_graph(self.load(name)), name)
    def test_raw_deny_has_no_operation(self):
        v=self.load('m0-2-v12-deny.json'); self.assertNotIn('operation',v['raw_evidence']); self.assertIsNone(v['normalized_output']['operation'])
    def test_currentness_is_separate_and_stale_mutations_preserve_history(self):
        v=self.load('m0-2-v12-dispatch.json'); historical=canonical(v['historical_input'])
        for key in ('runtime','scheduler','dispatch','fence','assignment','handoff','claim'):
            m=copy.deepcopy(v);m['currentness_binding']['generations'][key]+=1
            self.assertEqual(historical,canonical(m['historical_input']));self.assertFalse(self.fail_graph(m))
        for key in ('claim_state','fence'):
            m=copy.deepcopy(v);m['currentness_binding'][key]='STALE' if key=='claim_state' else 2
            self.assertEqual(historical,canonical(m['historical_input']));self.assertFalse(self.fail_graph(m))
    def test_digest_and_graph_mutations_are_rejected(self):
        v=self.load('m0-2-v12-dispatch.json')
        mutations=[lambda x:x['engine_distribution'].__setitem__('closure_id','wrong'),lambda x:x['engine_distribution'].__setitem__('closure_sha256','0'*64),lambda x:x['import_manifest'].__setitem__('manifest_id','wrong'),lambda x:x['validation_manifest'].__setitem__('digest','0'*64),lambda x:x['git_observation'].__setitem__('origin_url','changed'),lambda x:x['source_manifest'].__setitem__('source_artifact_ids',['task']),lambda x:x['artifacts'][0].__setitem__('raw_sha256','0'*64),lambda x:x['blobs'][0].__setitem__('byte_length',999),lambda x:x['raw_evidence'].__setitem__('reason','changed'),lambda x:x['normalized_output'].__setitem__('reason','changed')]
        for mutate in mutations:
            m=copy.deepcopy(v);mutate(m);self.assertFalse(self.fail_graph(m))
    def test_verification_result_v3_fails_closed_for_unsafe_allow(self):
        result_schema = json.loads((ROOT / 'schemas/m0-2-decision-evidence-verification-result.v3.schema.json').read_text())
        check = Draft202012Validator(result_schema)
        safe = {'historical_status':'VALID','currentness_status':'CURRENT','runtime_compatible':True,'verifier_status':'PASS','generation_match':True,'authorizing_use':'ALLOW','reason_code':'NONE'}
        unsafe = dict(safe, generation_match=False)
        self.assertFalse(list(check.iter_errors(safe)))
        self.assertTrue(list(check.iter_errors(unsafe)))

    def test_schema_rejects_sealed_environment_and_workdir_violations(self):
        check=validator();v=self.load('m0-2-v12-dispatch.json')
        for field,value in [('working_directory','../escape'),('working_directory','/absolute'),('working_directory','a//b'),('environment',{'TZ':'UTC'})]:
            m=copy.deepcopy(v);m['engine_distribution'][field]=value;self.assertTrue(list(check.iter_errors(m)))

def safe_path(path):
    if not path or path.startswith(('/', '.')) or '//' in path or ':' in path or '://' in path: return False
    return all(p not in ('','.','..') for p in path.split('/'))
