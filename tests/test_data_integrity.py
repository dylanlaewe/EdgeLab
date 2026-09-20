"""Data acceptance controls; all fixtures synthetic, no access authorization."""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from jsonschema import ValidationError
from src.edgelab.validate import ROOT, read, validate_record, validate_repository
from src.edgelab.data_integrity import (
    INITIAL_BASELINE, DATA_LOCATIONS, blob, canonical, digest, exact,
    membership_digest, sample_keys, validate_data, registry_checks, quarantine,
    verify_history, history_inventory, verify_checkpoint,
)

NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
T = '2026-09-19T10:00:00Z'


class DataIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for folder in ('schemas', 'portfolio'):
            shutil.copytree(ROOT / folder, self.root / folder)
        self.records = {}
        self.source = dict(schema_version=1, id='SRC', version=1, name='Synthetic',
                           source_type='synthetic', url='https://example.invalid',
                           access_status='UNKNOWN', access_evidence=[], terms_checked_at=None,
                           allowed_uses=[], restrictions=[], cost=None, rate_limits=None,
                           history_coverage=None, timestamp_quality=None, reliability=None,
                           automation_feasibility=None, research_value='Fixture only', unknowns=[])
        self.source_ref = self.put('source', self.source)
        self.raw = self.content('data/raw/raw.json', {'value': 3})
        self.code = self.content('data/raw/parser.py', 'import json,sys\nprint(json.load(sys.stdin)["value"])\n', 'text/x-python')
        self.normalizer = self.content('data/raw/normalizer.py', 'import json,sys\nprint(json.dumps(json.load(sys.stdin)))\n', 'text/x-python')
        self.config = self.content('data/raw/config.json', {})
        self.availability = self.base('availability', 'AV', observed_at=T, available_at=T,
                                      basis='contemporaneous_capture', evidence=self.raw, source_ref=self.source_ref)
        ar = self.put('availability', self.availability)
        self.observation = self.base('observation', 'OBS', source_ref=self.source_ref,
             source_url=self.source['url'], retrieved_at=T, publication_at=T, event_at=None,
             corrected_at=None, unknown_reason='Synthetic event has no scheduled time',
             available_at=T, availability_ref=ar, role='decision', observation_type='observed_fact',
             raw=self.raw, parser=self.code, parser_version='synthetic-parser-v1',
             normalizer=self.normalizer, normalizer_version='identity-v1', config=self.config,
             value=3, inference_method=None)
        obs = self.put('observation', self.observation)
        self.feature = self.base('feature', 'F', parents=[obs], available_at=T, role='decision',
                                join_policy='as_of', transform=self.normalizer, transform_version='identity-v1',
                                config=self.config, value=3)
        fr = self.put('feature', self.feature)
        self.membership = self.base('membership', 'POP', samples=[{'namespace':'synthetic-v1', 'event_id':'event-1', 'outcome_id':'target-1'}], membership_sha256='0'*64)
        self.membership['membership_sha256'] = membership_digest(self.membership)
        mr = self.put('membership', self.membership)
        self.manifest = self.base('manifest', 'D', inputs=[fr], membership_ref=mr,
              decision_at='2026-09-19T11:00:00Z', purpose='decision',
              snapshot=self.content('data/raw/snapshot.json', [{'sample':self.membership['samples'][0], 'value':3}]),
              row_count=1, quality_report=self.content('data/raw/quality.json', {'synthetic':True}), parent_manifests=[])
        self.put('manifest', self.manifest)

    def base(self, kind, ident, **fields):
        return dict(schema_version=1, id=ident, version=1, kind=kind, created_at=T, supersedes=None, **fields)

    def content(self, path, value, media='application/json'):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, sort_keys=True) if media == 'application/json' else value)
        return {'path':path, 'sha256':digest(p.read_bytes()), 'media_type':media}

    def put(self, kind, record):
        folder = 'data/sources' if kind == 'source' else DATA_LOCATIONS[kind].split('/*')[0]
        path = f"{folder}/{record['id']}.v{record['version']}.json"
        self.content(path, record)
        self.records[path] = (kind, record)
        return dict(path=path, kind=kind, id=record['id'], version=record['version'], sha256=digest((self.root/path).read_bytes()))

    def check(self, kind, record):
        validate_data(self.root, kind, record, now=NOW)

    def deny(self, kind, record, message=None):
        with self.assertRaisesRegex((ValueError, ValidationError), message or '.'):
            self.check(kind, record)

    def test_positive_reconstruction_and_registry(self):
        self.check('manifest', self.manifest)
        self.assertEqual(validate_repository(self.root, now=NOW), 8)
        registry_checks(self.root, self.records)
        # Execute only these test-authored programs, not arbitrary evidence commands.
        parsed = subprocess.check_output([str(ROOT/'.venv/bin/python'), str(self.root/'data/raw/parser.py')], input=blob(self.root, self.raw))
        normalized = subprocess.check_output([str(ROOT/'.venv/bin/python'), str(self.root/'data/raw/normalizer.py')], input=parsed)
        self.assertEqual(json.loads(normalized), self.observation['value'])
        self.assertEqual(json.loads(blob(self.root, self.manifest['snapshot']))[0]['value'], json.loads(normalized))

    def test_missing_mutated_wrong_type_and_identity(self):
        self.check('manifest', self.manifest)
        p = self.root / self.raw['path']; original = p.read_bytes()
        p.write_text('{}')
        self.deny('manifest', self.manifest, 'digest mismatch')
        p.unlink()
        self.deny('manifest', self.manifest, 'Missing')
        p.write_bytes(original)
        for change, error in [({'kind':'membership'}, 'Wrong reference type'), ({'id':'OTHER'}, 'identity mismatch')]:
            r = copy.deepcopy(self.manifest); r['inputs'][0].update(change)
            self.deny('manifest', r, error)

    def manifest_for(self, observation):
        r = copy.deepcopy(self.manifest)
        r['inputs'] = [self.put('observation', observation)]
        return r

    def test_unknown_late_and_later_corrections(self):
        self.check('manifest', self.manifest)
        r = copy.deepcopy(self.observation); r.update(available_at=None, availability_ref=None)
        self.deny('manifest', self.manifest_for(r), 'Unknown or late')
        a = copy.deepcopy(self.availability); a.update(available_at='2026-09-19T12:00:00Z', observed_at='2026-09-19T12:00:00Z')
        r = copy.deepcopy(self.observation); r.update(available_at=a['available_at'], availability_ref=self.put('availability', a))
        self.deny('manifest', self.manifest_for(r), 'Unknown or late')
        r = copy.deepcopy(self.observation); r['corrected_at']='2026-09-19T12:00:00Z'
        self.put('availability', self.availability)
        self.deny('observation', r, 'Later publication/correction')

    def test_availability_requires_content_and_no_backdating_capture(self):
        self.check('availability', self.availability)
        r = copy.deepcopy(self.availability); r['available_at']='2026-09-18T10:00:00Z'
        self.deny('availability', r, 'Capture cannot establish earlier')
        r = copy.deepcopy(self.observation); r['availability_ref']=None
        self.deny('observation', r, 'needs evidence')
        r = copy.deepcopy(self.observation); r['raw']=self.content('data/raw/other.json', {'value':9})
        self.deny('observation', r, 'Availability raw content mismatch')

    def test_evaluation_and_feature_time_leakage(self):
        self.check('manifest', self.manifest)
        for kind in ('closing_price','settled_outcome'):
            r = copy.deepcopy(self.observation); r['observation_type']=kind
            self.deny('observation', r, 'Evaluation leakage')
            r['role']='evaluation'; obs=self.put('observation', r)
            f=copy.deepcopy(self.feature); f['parents']=[obs]
            self.deny('feature', f, 'Evaluation leakage')
            self.deny('manifest', self.manifest_for(r), 'Evaluation leakage')
        self.put('observation', self.observation)
        f=copy.deepcopy(self.feature); f['available_at']='2026-09-19T09:00:00Z'
        self.deny('feature', f, 'latest input')

    def test_membership_renaming_and_partial_overlap(self):
        self.check('membership', self.membership)
        renamed={**self.membership,'id':'RENAMED'}
        self.check('membership', renamed)
        self.assertEqual(sample_keys(renamed), sample_keys(self.membership))
        self.assertEqual(membership_digest(renamed), membership_digest(self.membership))
        r=copy.deepcopy(renamed); r['samples'].append({'namespace':'synthetic-v1','event_id':'event-2','outcome_id':'target-2'})
        r['membership_sha256']=membership_digest(r); self.check('membership', r)
        self.assertEqual(len(sample_keys(r) & sample_keys(self.membership)),1)
        r['samples'][0]['event_id']='changed'
        self.deny('membership',r,'Membership digest mismatch')

    def test_snapshot_mutation_even_with_new_digest(self):
        r=copy.deepcopy(self.manifest)
        r['snapshot']=self.content('data/raw/wrong.json',[{'sample':self.membership['samples'][0], 'value':999}])
        self.deny('manifest',r,'not reconstructible')
        r=copy.deepcopy(self.manifest); r['row_count']=2
        self.deny('manifest',r,'count mismatch')

    def test_correction_preserves_original(self):
        old=self.put('observation',self.observation)
        old_av=self.put('availability',self.availability)
        raw=self.content('data/raw/corrected.json',{'value':4})
        later='2026-09-19T12:00:00Z'
        av={**self.availability,'version':2,'supersedes':old_av,'created_at':later,
            'available_at':later,'observed_at':later,'evidence':raw}
        corrected={**self.observation,'version':2,'supersedes':old,'created_at':later,
                   'raw':raw,'value':4,'available_at':later,'corrected_at':later,
                   'retrieved_at':later,'availability_ref':self.put('availability',av)}
        self.check('observation',corrected)
        self.put('observation',corrected); registry_checks(self.root,self.records)
        self.assertEqual(read(self.root/old['path']),self.observation)
        self.assertEqual(read(self.root/old_av['path']),self.availability)
        r=self.manifest_for(corrected)
        r['snapshot']=self.content('data/raw/corrected-snapshot.json',[{'sample':self.membership['samples'][0],'value':4}])
        self.deny('manifest',r,'Unknown or late')
        r['decision_at']=later; self.check('manifest',r)
        corrected['supersedes']=None
        self.deny('observation',corrected,'requires predecessor')

    def test_reference_escape_and_alias(self):
        r=copy.deepcopy(self.raw)
        for path in ('../outside','data/raw/../raw/raw.json',str(self.root/'data/raw/raw.json')):
            r['path']=path
            with self.assertRaises(ValueError): blob(self.root,r)
        (self.root/'data/raw/link.json').symlink_to(self.root/'data/raw/raw.json')
        r['path']='data/raw/link.json'
        with self.assertRaisesRegex(ValueError,'Aliased'): blob(self.root,r)

    def test_identifier_filename_gaps_orphans_cycles(self):
        registry_checks(self.root,self.records)
        for field,value in [('id','../bad'),('version',99)]:
            records=copy.deepcopy(self.records); records['data/sources/SRC.v1.json'][1][field]=value
            with self.assertRaises(ValueError): registry_checks(self.root,records)
        for graph in ({'a':{'missing'}},{'a':{'a'}},{'a':{'b'},'b':{'a'}}):
            with self.assertRaises(ValueError): quarantine(graph,{'kind':'global','targets':[]})

    def test_transitive_global_and_retained_quarantine(self):
        graph={'obs':set(),'feature':{'obs'},'dataset':{'feature'},'experiment':{'dataset'},'unrelated':set()}
        self.assertEqual(quarantine(graph,{'kind':'records','targets':['obs']}),set(graph)-{'unrelated'})
        self.assertEqual(quarantine(graph,{'kind':'global','targets':[]}),set(graph))
        self.assertIn('experiment',quarantine(graph,{'kind':'records','targets':['unrelated']},{'dataset'}))
        for scope in ({},{'kind':'records','targets':['unknown']},{'kind':'records','targets':[]}):
            with self.assertRaises(ValueError): quarantine(graph,scope)

    def test_permission_evidence_valid_denied_expired_wrong_uses_and_future(self):
        terms=self.content('data/raw/terms.txt','Synthetic permission only','text/plain')
        p=self.base('permission','PERM',source_id='SRC',source_version=1,source_url=self.source['url'],
                    reviewed_at=T,valid_until='2026-10-01T00:00:00Z',allowed_uses=['synthetic_test'],terms=terms,decision='PERMITTED',reviewer='test-only')
        ref=self.put('permission',p)
        source={**self.source,'access_status':'PERMITTED','access_evidence':[ref['path']],'allowed_uses':['synthetic_test'],'terms_checked_at':T}
        validate_record('source',source,self.root,now=NOW)
        for update in ({'decision':'UNVERIFIED'},{'decision':'DENIED'},{'valid_until':'2026-09-20T00:00:00Z'}, {'source_id':'OTHER'},{'allowed_uses':['other']},{'reviewed_at':'2999-01-01T00:00:00Z'}):
            self.put('permission',{**p,**update})
            with self.assertRaises(ValueError): validate_record('source',source,self.root,now=NOW)
        self.put('permission',p)
        (self.root/terms['path']).write_text('Changed terms')
        with self.assertRaisesRegex(ValueError,'digest mismatch'): validate_record('source',source,self.root,now=NOW)

    def test_clock_and_project_state(self):
        bank=read(self.root/'portfolio/bankroll.json')
        validate_record('bankroll',{**bank,'as_of':'1900-01-01T00:00:00Z'},self.root,now=NOW)
        with self.assertRaisesRegex(ValueError,'Future completed'): validate_record('bankroll',{**bank,'as_of':'2999-01-01T00:00:00Z'},self.root,now=NOW)
        r=copy.deepcopy(self.observation); r['event_at']='2999-01-01T00:00:00Z'
        self.check('observation',r) # scheduled event, not completed fact
        state=read(ROOT/'docs/project-state.json'); validate_record('project-state',state,self.root,now=NOW)
        for update in ({'live_status':'UNLOCKED'},{'active_strategies':-1}):
            with self.assertRaises(ValidationError): validate_record('project-state',{**state,**update},self.root,now=NOW)

    def test_new_schema_required_fields_and_versions(self):
        permission=self.base('permission','P',source_id='SRC',source_version=1,source_url=self.source['url'],
                             reviewed_at=T,valid_until='2026-10-01T00:00:00Z',allowed_uses=[],
                             terms=self.content('data/raw/terms.txt','synthetic','text/plain'),decision='UNVERIFIED',reviewer='synthetic')
        for kind,r in [('permission',permission),*[(k,r) for k,r in self.records.values() if k != 'source']]:
            self.check(kind,r)
            for field in r:
                with self.subTest(kind=kind,field=field):
                    bad=copy.deepcopy(r); del bad[field]; self.deny(kind,bad)
            self.deny(kind,{**r,'schema_version':2})
            self.deny(kind,{**r,'unexpected':True})

    def test_frozen_synthetic_fixture(self):
        shutil.rmtree(self.root/'data')
        shutil.copytree(ROOT/'tests/fixtures/data-integrity/data',self.root/'data')
        self.assertEqual(validate_repository(self.root,now=NOW),8)

    def test_legacy_supersession_and_handoff_graph(self):
        audit=read(ROOT/'reports/audit/A-M0-002.v1.json')
        audit.update(id='A',version=1,supersedes=None)
        records={'reports/audit/A.v1.json':('audit',audit)}
        registry_checks(self.root,records)
        for target in ('reports/audit/A.v1.json','missing'):
            bad=copy.deepcopy(records); bad['reports/audit/A.v1.json'][1]['supersedes']=target
            with self.assertRaisesRegex(ValueError,'supersession|Supersession'):
                registry_checks(self.root,bad)
        corrected={**audit,'version':2,'supersedes':'reports/audit/A.v1.json'}
        records['reports/audit/A.v2.json']=('audit',corrected)
        registry_checks(self.root,records)
        gap={'reports/audit/A.v2.json':('audit',{**corrected,'supersedes':None})}
        with self.assertRaises(ValueError): registry_checks(self.root,gap)
        h=read(ROOT/'docs/handoffs/H-M0-003.v2.json'); h.update(id='H',version=1,depends_on=[])
        records={'docs/handoffs/H.v1.json':('handoff',h)}
        registry_checks(self.root,records)
        with self.assertRaisesRegex(ValueError,'Version gap'):
            registry_checks(self.root,{'docs/handoffs/H.v2.json':('handoff',{**h,'version':2})})
        for dependencies in (['missing'],['H']):
            with self.assertRaisesRegex(ValueError,'Orphan|cycle'):
                registry_checks(self.root,{'docs/handoffs/H.v1.json':('handoff',{**h,'depends_on':dependencies})})

    def test_manifest_orphan_and_blob_type(self):
        self.check('manifest',self.manifest)
        r=copy.deepcopy(self.manifest)
        r['parent_manifests']=[{**self.put('manifest',self.manifest),'path':'data/derived/missing.v1.json'}]
        self.deny('manifest',r,'Missing')
        r=copy.deepcopy(self.observation); r['parser']['media_type']='application/json'
        self.deny('observation',r,'Wrong code type')
        (self.root/'nonfinite.json').write_text('{"value": NaN}')
        with self.assertRaisesRegex(ValueError,'Nonfinite'): read(self.root/'nonfinite.json')

    def test_history_preservation_and_checkpoint_boundary(self):
        def git(*args): return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.DEVNULL).decode().strip()
        self.content('research/experiments/FAILED.v1.json',{'result':'REJECTED','synthetic':True})
        git('init'); git('add','.'); git('-c','user.name=Synthetic','-c','user.email=test@example.invalid','commit','-m','Fixture')
        baseline=git('rev-parse','HEAD'); inventory=verify_history(self.root,baseline)
        checkpoint={'baseline':baseline,'inventory':inventory,'predecessor_sha256':'1'*64}
        verify_checkpoint(self.root,checkpoint,digest(canonical(checkpoint)),'1'*64)
        with self.assertRaises(ValueError): verify_checkpoint(self.root,checkpoint,'0'*64,'1'*64)
        with self.assertRaises(ValueError): verify_checkpoint(self.root,checkpoint,digest(canonical(checkpoint)),'2'*64)
        for invalid in (None,'HEAD','main'):
            with self.assertRaises(ValueError): verify_history(self.root,invalid)
        failed=self.root/'research/experiments/FAILED.v1.json'; failed_bytes=failed.read_bytes(); failed.unlink()
        with self.assertRaises(ValueError): verify_history(self.root,baseline)
        failed.write_bytes(failed_bytes)
        path=self.root/self.raw['path']; data=path.read_bytes(); path.write_text('{}')
        with self.assertRaisesRegex(ValueError,'Published history mutated'): verify_history(self.root,baseline)
        path.unlink()
        with self.assertRaises(ValueError): verify_history(self.root,baseline)
        path.write_bytes(data)
        self.put('observation',{**self.observation,'version':2,'supersedes':self.put('observation',self.observation)})
        verify_history(self.root,baseline)
        with self.assertRaisesRegex(ValueError,'replacement'): verify_history(self.root,baseline,{})


if __name__ == '__main__': unittest.main()
