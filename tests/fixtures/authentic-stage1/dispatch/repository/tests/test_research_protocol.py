"""Research H05 contracts: synthetic evidence only, no scientific approval."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from jsonschema import ValidationError
from src.edgelab.validate import ROOT, LOCATIONS, read, validate_repository
from src.edgelab.data_integrity import digest, membership_digest, sample_keys, validate_data
from src.edgelab.research_protocol import validate_research, check_confirmation_contract
import test_foundation as foundation
from test_data_integrity import NOW

FREEZE = '2026-09-19T12:00:00Z'
ACCESS = '2026-09-19T13:00:00Z'
EARLY = '2026-09-19T11:00:00Z'


class ResearchProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for folder in ('schemas', 'portfolio'):
            shutil.copytree(ROOT / folder, self.root / folder)
        self.hypothesis = foundation.FoundationTests().fixture('hypothesis')
        self.hypothesis.update(id='H', registered_at=FREEZE, unresolved_thresholds=[])
        href = self.put('hypothesis', self.hypothesis)
        self.fresh = self.membership('FRESH', ['fresh-1', 'fresh-2'])
        self.explored = self.membership('EXPLORED', ['old-1', 'old-2'])
        self.old = self.exposure('OLD', self.explored, 'EXAMINED', 'EXPLORATORY', EARLY)
        self.custody = self.exposure('CUSTODY', self.fresh, 'UNEXAMINED', 'HOLDOUT_CUSTODY', FREEZE)
        self.registration = self.base('preregistration', 'REG', hypothesis_ref=href,
            frozen_at=FREEZE, holdout_ref=self.put('exposure', self.custody),
            exploratory_ancestors=[self.put('exposure', self.old)],
            thresholds=[{'metric':'synthetic_identity_error','operator':'==','value':'0',
                         'rationale':'Fixture equality only; not a statistical or profit threshold'}],
            analysis_plan=self.blob('research/evidence/plan.json', {'procedure':'Synthetic equality; two fresh samples, no fitted strategy'}),
            scope='SYNTHETIC_PROTOCOL_ONLY')
        self.regref = self.put('preregistration', self.registration)
        self.pin = self.regref['sha256']
        self.access = self.exposure('ACCESS', self.fresh, 'EXAMINED', 'CONFIRMATORY_ACCESS', ACCESS)
        self.accessref = self.put('exposure', self.access)
        self.check()

    def base(self, kind, ident, **fields):
        return dict(schema_version=1, id=ident, version=1, kind=kind,
                    created_at=FREEZE, supersedes=None, **fields)

    def write(self, path, record):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(record, indent=2)+'\n')
        return digest(p.read_bytes())

    def blob(self, path, record):
        return dict(path=path, sha256=self.write(path, record), media_type='application/json')

    def put(self, kind, record):
        folder = 'data/membership' if kind == 'membership' else LOCATIONS[kind].split('/*')[0]
        path = f"{folder}/{record['id']}.v{record['version']}.json"
        return dict(path=path, kind=kind, id=record['id'], version=record['version'], sha256=self.write(path,record))

    def membership(self, ident, outcomes):
        r = self.base('membership', ident, samples=[{'namespace':'synthetic-research-v1','event_id':o,'outcome_id':'target'} for o in outcomes], membership_sha256='0'*64)
        r['created_at'] = EARLY
        r['membership_sha256'] = membership_digest(r)
        return self.put('membership',r)

    def exposure(self, ident, membership, status, purpose, at):
        r = self.base('exposure',ident, actor='synthetic-custodian', membership_ref=membership,
            status=status,purpose=purpose,first_results_access_at=at if status=='EXAMINED' else None,
            coverage_through=at,evidence=self.blob(f'research/evidence/{ident}.json',{'synthetic':True,'observation':status}),
            ancestors=[],unknown_reason=None)
        r['created_at'] = at
        return r

    def check(self, **kwargs):
        args=dict(frozen_sha256=self.pin,access_ref=self.accessref,disclosure_refs=[],now=NOW)
        args.update(kwargs)
        return check_confirmation_contract(self.root,self.regref,**args)

    def registration_check(self,r):
        validate_research(self.root,'preregistration',r,now=NOW)

    def test_fresh_holdout_positive_and_repository(self):
        result=self.check()
        self.assertFalse(result['operational_authorization'])
        self.assertEqual(result['contract_status'],'CONSISTENT_SUPPLIED_EVIDENCE')
        self.assertEqual(result['membership_sha256'],read(self.root/self.fresh['path'])['membership_sha256'])
        self.assertEqual(validate_repository(self.root,now=NOW),9)

    def test_identical_renamed_partial_overlap_rejected(self):
        for name,keys in [('IDENTICAL',['fresh-1','fresh-2']),('RENAMED',['fresh-2','fresh-1']),('PARTIAL',['old-1','fresh-1'])]:
            with self.subTest(name=name):
                membership=self.fresh if name=='IDENTICAL' else self.membership(name,keys)
                exposure=self.exposure(name,membership,'EXAMINED','EXPLORATORY',EARLY)
                ref=self.put('exposure',exposure)
                with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
                    self.registration_check({**self.registration,'exploratory_ancestors':[ref]})
                with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
                    self.check(disclosure_refs=[ref])

    def test_nested_ancestry_and_correction_cannot_hide_overlap(self):
        contaminated=self.exposure('CONTAMINATED',self.fresh,'EXAMINED','EXPLORATORY',EARLY)
        cr=self.put('exposure',contaminated)
        wrapper={**self.old,'id':'WRAPPER','ancestors':[cr]}
        ref=self.put('exposure',wrapper)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            self.check(disclosure_refs=[ref])
        corrected={**contaminated,'version':2,'supersedes':cr,'membership_ref':self.explored}
        ref=self.put('exposure',corrected)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            self.check(disclosure_refs=[ref])

    def test_unknown_exposure_recordable_but_ineligible(self):
        unknown={**self.old,'id':'UNKNOWN','status':'UNKNOWN','first_results_access_at':None,'unknown_reason':'Missing custody log'}
        ref=self.put('exposure',unknown)
        validate_research(self.root,'exposure',unknown,now=NOW)
        with self.assertRaisesRegex(ValueError,'Unknown exposure blocks'):
            self.check(disclosure_refs=[ref])
        with self.assertRaisesRegex(ValueError,'Unknown exposure blocks'):
            self.registration_check({**self.registration,'exploratory_ancestors':[ref]})

    def test_missing_unknown_stale_and_retrospective_holdout(self):
        cases=[({'status':'UNKNOWN','unknown_reason':'No evidence'},'known unexamined'),
               ({'coverage_through':EARLY},'custody must cover'),
               ({'created_at':ACCESS,'coverage_through':ACCESS},'custody must cover')]
        for changes,message in cases:
            r=copy.deepcopy(self.registration)
            r['holdout_ref']=self.put('exposure',{**self.custody,**changes})
            with self.assertRaisesRegex(ValueError,message): self.registration_check(r)
        (self.root/self.custody['evidence']['path']).unlink()
        with self.assertRaisesRegex(ValueError,'Missing'): self.registration_check(r)

    def test_first_access_before_equal_after_freeze(self):
        for when in (EARLY,FREEZE):
            r={**self.access,'first_results_access_at':when}
            with self.assertRaisesRegex(ValueError,'strictly follow freeze'):
                self.check(access_ref=self.put('exposure',r))
        self.check(access_ref=self.put('exposure',self.access))

    def test_unknown_or_wrong_purpose_access_denied(self):
        for changes in ({'status':'UNKNOWN','first_results_access_at':None,'unknown_reason':'Unknown'},
                        {'purpose':'EXPLORATORY'}):
            with self.assertRaisesRegex(ValueError,'Known confirmatory first-access'):
                self.check(access_ref=self.put('exposure',{**self.access,**changes}))

    def test_exact_membership_not_dataset_label(self):
        fresh=read(self.root/self.fresh['path'])
        renamed={**fresh,'id':'RENAMED'}
        ref=self.put('membership',renamed)
        self.assertEqual(sample_keys(fresh),sample_keys(renamed))
        with self.assertRaisesRegex(ValueError,'Exact holdout membership reference'):
            self.check(access_ref=self.put('exposure',{**self.access,'membership_ref':ref}))

    def test_mutated_hypothesis_threshold_plan_and_freeze_pin(self):
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check(frozen_sha256=None)
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check(frozen_sha256='0'*64)
        original=copy.deepcopy(self.registration)
        r=copy.deepcopy(original); r['thresholds'][0]['value']='1'
        self.regref=self.put('preregistration',r)
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check()
        self.regref=self.put('preregistration',original)
        self.put('hypothesis',{**self.hypothesis,'rejection_criteria':['Changed after results']})
        with self.assertRaisesRegex(ValueError,'Content digest mismatch'): self.check()
        self.put('hypothesis',self.hypothesis)
        (self.root/original['analysis_plan']['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError,'Content digest mismatch'): self.check()

    def test_rehashed_hypothesis_change_still_breaks_freeze(self):
        href=self.put('hypothesis',{**self.hypothesis,'rejection_criteria':['Changed']})
        self.regref=self.put('preregistration',{**self.registration,'hypothesis_ref':href})
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check()

    def test_retroactive_hypothesis_and_unresolved_thresholds(self):
        for changes,reason in [({'registered_at':ACCESS},'Retroactive'),({'unresolved_thresholds':['TBD']},'Unresolved thresholds')]:
            href=self.put('hypothesis',{**self.hypothesis,**changes})
            with self.assertRaisesRegex(ValueError,reason):
                self.registration_check({**self.registration,'hypothesis_ref':href})

    def test_wrong_type_identity_digest_membership_and_missing_refs(self):
        for changes,reason in [({'kind':'hypothesis'},'Wrong reference type'),({'id':'WRONG'},'identity mismatch'),({'sha256':'0'*64},'digest mismatch'),({'path':'data/membership/MISSING.v1.json'},'Missing')]:
            r={**self.custody,'membership_ref':{**self.fresh,**changes}}
            with self.assertRaisesRegex(ValueError,reason): validate_research(self.root,'exposure',r,now=NOW)
        r=read(self.root/self.fresh['path']); r['membership_sha256']='0'*64
        ref=self.put('membership',r)
        with self.assertRaisesRegex(ValueError,'Membership digest mismatch'):
            validate_research(self.root,'exposure',{**self.custody,'membership_ref':ref},now=NOW)

    def test_exposure_order_and_missing_first_access(self):
        for changes,reason in [({'first_results_access_at':None},'requires first access'),
                               ({'coverage_through':ACCESS},'coverage exceeds'),
                               ({'created_at':'2999-01-01T00:00:00Z'},'Future completed')]:
            with self.assertRaisesRegex(ValueError,reason):
                validate_research(self.root,'exposure',{**self.old,**changes},now=NOW)

    def test_versioned_registration_preserves_prior_without_reusing_pin(self):
        r={**self.registration,'version':2,'supersedes':self.regref}
        prior=self.regref
        self.regref=self.put('preregistration',r)
        self.registration_check(r)
        self.assertEqual(read(self.root/prior['path']),self.registration)
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check()
        # A new verifier pin can check a new version; it does not make old outcomes fresh.
        self.check(frozen_sha256=self.regref['sha256'])

    def test_required_fields_and_extra_properties(self):
        for kind,r in [('exposure',self.old),('preregistration',self.registration)]:
            for field in r:
                with self.subTest(kind=kind,field=field):
                    bad=copy.deepcopy(r); del bad[field]
                    with self.assertRaises(ValidationError): validate_research(self.root,kind,bad,now=NOW)
            with self.assertRaises(ValidationError): validate_research(self.root,kind,{**r,'approval':True},now=NOW)

    def test_repository_rejects_targeted_overlap(self):
        overlap=self.exposure('OVERLAP',self.fresh,'EXAMINED','EXPLORATORY',EARLY)
        ref=self.put('exposure',overlap)
        self.put('preregistration',{**self.registration,'exploratory_ancestors':[ref]})
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            validate_repository(self.root,now=NOW)

    def test_first_access_cannot_hide_prior_access_ancestor(self):
        prior=self.exposure('PRIOR',self.fresh,'EXAMINED','EXPLORATORY',EARLY)
        ref=self.put('exposure',prior)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            self.check(access_ref=self.put('exposure',{**self.access,'ancestors':[ref]}))

    def test_exposure_cannot_precede_membership_binding(self):
        members=read(self.root/self.fresh['path']); members['created_at']=ACCESS
        ref=self.put('membership',members)
        with self.assertRaisesRegex(ValueError,'predates membership binding'):
            validate_research(self.root,'exposure',{**self.custody,'membership_ref':ref},now=NOW)

    def test_missing_predecessor_and_mutated_custody_evidence(self):
        with self.assertRaisesRegex(ValueError,'requires predecessor'):
            self.registration_check({**self.registration,'version':2})
        (self.root/self.custody['evidence']['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError,'Content digest mismatch'): self.check()

    def test_frozen_fixture_positive(self):
        for folder in ('research','data'):
            shutil.rmtree(self.root/folder,ignore_errors=True)
            shutil.copytree(ROOT/'tests/fixtures/research-protocol'/folder,self.root/folder)
        refs=read(ROOT/'tests/fixtures/research-protocol/cases.json')
        result=check_confirmation_contract(self.root,refs['registration_ref'],frozen_sha256=refs['registration_ref']['sha256'],access_ref=refs['access_ref'],disclosure_refs=[],now=NOW)
        self.assertFalse(result['operational_authorization'])
        for ref in refs['contamination_refs']:
            with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
                check_confirmation_contract(self.root,refs['registration_ref'],frozen_sha256=refs['registration_ref']['sha256'],access_ref=refs['access_ref'],disclosure_refs=[ref],now=NOW)


if __name__ == '__main__': unittest.main()
