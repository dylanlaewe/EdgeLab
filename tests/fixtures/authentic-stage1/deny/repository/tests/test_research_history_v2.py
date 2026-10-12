"""R01 owner successors; real Git checkpoints in isolated synthetic roots only."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from src.edgelab.validate import ROOT, read, validate_record, validate_repository
from jsonschema import ValidationError
from src.edgelab.data_integrity import digest, history_inventory, sample_keys
from src.edgelab.research_protocol import check_confirmation_contract, validate_research
import test_research_protocol as legacy

NOW, FREEZE, EARLY, ACCESS = legacy.NOW, legacy.FREEZE, legacy.EARLY, legacy.ACCESS


class ResearchHistoryV2Tests(unittest.TestCase):
    # Reuse only fixture-writing utilities, not published tests or their setUp.
    base = legacy.ResearchProtocolTests.base
    write = legacy.ResearchProtocolTests.write
    blob = legacy.ResearchProtocolTests.blob
    put = legacy.ResearchProtocolTests.put
    membership = legacy.ResearchProtocolTests.membership
    exposure = legacy.ResearchProtocolTests.exposure

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for folder in ('schemas', 'portfolio'):
            shutil.copytree(ROOT/folder, self.root/folder)
        source = ROOT/'tests/fixtures/research-protocol'
        for folder in ('research', 'data'):
            shutil.copytree(source/folder, self.root/folder)
        cases = read(source/'cases.json')
        # These are negative cases in the archived fixture, not fresh history.
        for ref in cases['contamination_refs']:
            (self.root/ref['path']).unlink()
        self.regref, self.accessref = cases['registration_ref'], cases['access_ref']
        self.registration = read(self.root/self.regref['path'])
        self.access = read(self.root/self.accessref['path'])
        self.custody = read(self.root/self.registration['holdout_ref']['path'])
        self.old = read(self.root/self.registration['exploratory_ancestors'][0]['path'])
        self.fresh, self.explored = self.custody['membership_ref'], self.old['membership_ref']
        self.pin = self.regref['sha256']
        self.git('init', '-q')
        self.checkpoint()
        self.check()

    def git(self, *args):
        return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.PIPE).decode().strip()

    def checkpoint(self, exclude_access=True):
        # Test-only external-verifier stand-in. Production never auto-accepts HEAD.
        p=self.root/self.accessref['path']; data=p.read_bytes()
        if exclude_access: p.unlink()
        self.git('add','.')
        self.git('-c','user.name=Synthetic verifier','-c','user.email=test@example.invalid',
                 'commit','-q','--allow-empty','-m','Synthetic verifier checkpoint')
        self.baseline=self.git('rev-parse','HEAD')
        self.inventory=history_inventory(self.root,self.baseline)
        if exclude_access: p.write_bytes(data)

    def check(self, **kwargs):
        args=dict(frozen_sha256=self.pin,access_ref=self.accessref,disclosure_refs=[],
                  history_baseline=self.baseline,history_inventory=self.inventory,now=NOW)
        args.update(kwargs)
        return check_confirmation_contract(self.root,self.regref,**args)

    def candidate(self, member, *, version=2, ident='REG', ancestors=None, predecessor=None):
        custody=self.exposure(f'CUSTODYNEW{ident}{version}',member,'UNEXAMINED','HOLDOUT_CUSTODY',FREEZE)
        r={**self.registration,'id':ident,'version':version,
           'supersedes':self.regref if predecessor is None and version>1 else predecessor,
           'holdout_ref':self.put('exposure',custody),'exploratory_ancestors':ancestors or []}
        self.regref=self.put('preregistration',r);self.pin=self.regref['sha256']
        self.accessref=self.put('exposure',{**self.access,'membership_ref':member})
        self.checkpoint()
        return r

    def test_fresh_checkpoint_and_disjoint_v2_positive(self):
        prior=(self.root/self.regref['path']).read_bytes()
        member=self.membership('FRESHNEW',['new-1','new-2'])
        r=self.candidate(member)
        validate_research(self.root,'preregistration',r,now=NOW)
        result=self.check()
        self.assertEqual(result['contract_status'],'CONSISTENT_AUTHORITATIVE_RESEARCH_EVIDENCE')
        self.assertFalse(result['operational_authorization'])
        self.assertEqual(result['history_completeness'],'VERIFIED_RESEARCH_REGISTRIES_ONLY')
        self.assertEqual((self.root/'research/preregistrations/REG.v1.json').read_bytes(),prior)
        self.assertIn('research/exposures/OLD.v1.json',result['research_record_hashes'])

    def test_R01_exact_prior_registration_attack_rejected_at_semantic_surface(self):
        r=self.candidate(self.explored)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            validate_research(self.root,'preregistration',r,now=NOW)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'): self.check()

    def test_multiple_predecessors_carry_disclosure_to_current_holdout(self):
        r2=self.candidate(self.membership('SECOND',['second']))
        self.check()
        r3=self.candidate(self.explored,version=3)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'):
            validate_research(self.root,'preregistration',r3,now=NOW)
        self.assertEqual(r3['supersedes']['version'],2)
        self.assertEqual(r2['supersedes']['version'],1)

    def test_renamed_reordered_canonical_equivalent_prior_membership(self):
        member=self.membership('REPACKAGED',['old-2','old-1'])
        self.assertEqual(sample_keys(read(self.root/member['path'])),
                         sample_keys(read(self.root/self.explored['path'])))
        self.candidate(member)
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'): self.check()

    def test_partial_overlap_prior_registration(self):
        self.candidate(self.membership('PARTIALNEW',['new-1','old-1']))
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps'): self.check()

    def test_new_id_and_no_prior_registration_reference_cannot_erase_history(self):
        self.candidate(self.explored,version=1,ident='UNRELATED')
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()

    def test_standalone_omitted_exposure_found_without_disclosure_argument(self):
        hidden=self.exposure('HIDDEN',self.fresh,'EXAMINED','EXPLORATORY',EARLY)
        self.put('exposure',hidden)
        # Added after checkpoint, not mentioned in candidate or disclosure_refs.
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()

    def test_accepted_unrelated_exposure_found_without_candidate_ancestry(self):
        self.put('exposure',self.exposure('UNRELATED',self.fresh,'EXAMINED','EXPLORATORY',EARLY))
        self.checkpoint()
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()

    def test_repackaged_exposure_correction_cannot_hide_original(self):
        hidden=self.exposure('HIDDEN',self.fresh,'EXAMINED','EXPLORATORY',EARLY)
        prior=self.put('exposure',hidden)
        self.put('exposure',{**hidden,'version':2,'supersedes':prior,'membership_ref':self.explored})
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()

    def test_altered_current_ancestry_cannot_hide_accepted_old_evidence(self):
        # New ID avoids version-chain disclosure; global authoritative scan still sees OLD.
        harmless=self.exposure('HARMLESS',self.fresh,'UNEXAMINED','HOLDOUT_CUSTODY',FREEZE)
        self.candidate(self.explored,version=1,ident='OTHER',ancestors=[self.put('exposure',harmless)])
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()

    def test_unknown_standalone_history_fails_closed(self):
        unknown={**self.old,'id':'UNKNOWN','status':'UNKNOWN',
                 'first_results_access_at':None,'unknown_reason':'Uncertain scope of prior access'}
        self.put('exposure',unknown)
        with self.assertRaisesRegex(ValueError,'Unknown exposure blocks authoritative'): self.check()

    def test_unknown_prior_registration_disclosure_denies(self):
        unknown={**self.old,'id':'UNKNOWN','status':'UNKNOWN','first_results_access_at':None,'unknown_reason':'Missing log'}
        # An invalid prior registration cannot become valid through supersession.
        prior={**self.registration,'id':'PRIOR','exploratory_ancestors':[self.put('exposure',unknown)]}
        pr=self.put('preregistration',prior)
        r={**prior,'version':2,'supersedes':pr,'exploratory_ancestors':[]}
        with self.assertRaisesRegex(ValueError,'Unknown exposure blocks'):
            validate_research(self.root,'preregistration',r,now=NOW)

    def test_missing_baseline_inventory_or_wrong_inventory_denies(self):
        for args in ({'history_baseline':None},{'history_inventory':None},
                     {'history_inventory':{}},{'history_baseline':'HEAD'}):
            with self.subTest(args=args),self.assertRaisesRegex(ValueError,'history requires|inventory mismatch|full baseline'):
                self.check(**args)

    def test_deletion_of_accepted_exposure_or_prior_registration_denies(self):
        for ref in [self.registration['exploratory_ancestors'][0],self.regref]:
            p=self.root/ref['path'];data=p.read_bytes();p.unlink()
            with self.assertRaisesRegex(ValueError,'Missing'): self.check()
            p.write_bytes(data)

    def test_omitted_accepted_unreferenced_exposure_cannot_be_deleted(self):
        ref=self.put('exposure',self.exposure('UNRELATED',self.explored,'EXAMINED','EXPLORATORY',EARLY))
        self.checkpoint();self.check()
        (self.root/ref['path']).unlink()
        with self.assertRaisesRegex(ValueError,'Missing'): self.check()

    def test_rewrite_and_rehash_unreferenced_accepted_history_denies(self):
        old=self.exposure('UNRELATED',self.explored,'EXAMINED','EXPLORATORY',EARLY)
        self.put('exposure',old);self.checkpoint();self.check()
        self.put('exposure',{**old,'membership_ref':self.fresh})
        with self.assertRaisesRegex(ValueError,'Published history mutated'): self.check()

    def test_uncheckpointed_registration_cannot_supply_own_new_pin(self):
        r={**self.registration,'id':'NEW'}
        self.regref=self.put('preregistration',r);self.pin=self.regref['sha256']
        with self.assertRaisesRegex(ValueError,'absent from authoritative checkpoint'): self.check()

    def test_historical_access_cannot_be_exempted_as_new_access(self):
        self.checkpoint(exclude_access=False)
        with self.assertRaisesRegex(ValueError,'already in authoritative history'): self.check()

    def test_prior_confirmatory_access_contaminates_but_fresh_holdout_survives(self):
        self.put('exposure',{**self.access,'id':'PRIORACCESS'})
        with self.assertRaisesRegex(ValueError,'Examined membership overlaps authoritative'): self.check()
        self.candidate(self.membership('NEW',['new-1']))
        self.assertFalse(self.check()['operational_authorization'])

    def test_wrong_type_missing_predecessor_and_version_gap(self):
        for changes,reason in [({'version':2},'requires predecessor'),
                               ({'version':2,'supersedes':self.registration['holdout_ref']},'Wrong reference type'),
                               ({'version':3,'supersedes':self.regref},'exact predecessor')]:
            with self.assertRaisesRegex(ValueError,reason):
                validate_research(self.root,'preregistration',{**self.registration,**changes},now=NOW)

    def test_freeze_pin_times_membership_and_content_invariants_retained(self):
        with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check(frozen_sha256='0'*64)
        for at in (EARLY,FREEZE):
            ref=self.put('exposure',{**self.access,'first_results_access_at':at})
            with self.assertRaisesRegex(ValueError,'strictly follow freeze'): self.check(access_ref=ref)
        self.accessref=self.put('exposure',self.access)
        equal=self.membership('EQUAL',['fresh-2','fresh-1'])
        ref=self.put('exposure',{**self.access,'membership_ref':equal})
        with self.assertRaisesRegex(ValueError,'Exact holdout membership'): self.check(access_ref=ref)
        self.accessref=self.put('exposure',self.access)
        (self.root/self.custody['evidence']['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError,'Content digest mismatch'): self.check()

    def test_future_malformed_untyped_and_misplaced_local_evidence_denies(self):
        p=self.root/'research/elsewhere/EXPOSURE.json'
        self.write(p.relative_to(self.root).as_posix(),self.old)
        with self.assertRaisesRegex(ValueError,'Misplaced'): self.check()
        p.unlink()
        p=self.root/'research/exposures/invalid.txt';p.write_text('unknown')
        with self.assertRaisesRegex(ValueError,'Unrecognized'): self.check()
        p.unlink()
        ref=self.put('exposure',{**self.old,'id':'FUTURE','created_at':'2999-01-01T00:00:00Z'})
        with self.assertRaisesRegex(ValueError,'Future completed'): self.check()
        (self.root/ref['path']).write_text('{bad')
        with self.assertRaises(ValueError): self.check()

    def test_nested_registry_and_symlink_evidence_cannot_be_ignored(self):
        p=self.root/'research/exposures/nested/OLD.v1.json'
        self.write(p.relative_to(self.root).as_posix(),self.old)
        with self.assertRaisesRegex(ValueError,'Misplaced'): self.check()
        p.unlink()
        p=self.root/'research/exposures/alias.json';p.symlink_to(self.root/self.accessref['path'])
        with self.assertRaisesRegex(ValueError,'Aliased'): self.check()

    def test_threshold_hypothesis_plan_and_custody_rehash_cannot_evade_pins(self):
        original_files={p:p.read_bytes() for p in self.root.rglob('*.json')}
        original_ref=copy.deepcopy(self.regref)
        for target in ('threshold','hypothesis','plan','custody'):
            with self.subTest(target=target):
                reg=copy.deepcopy(self.registration)
                if target=='threshold': reg['thresholds'][0]['value']='99'
                elif target=='hypothesis':
                    h=read(self.root/reg['hypothesis_ref']['path']);h['rejection_criteria']=['changed']
                    reg['hypothesis_ref']=self.put('hypothesis',h)
                elif target=='plan':
                    reg['analysis_plan']=self.blob(reg['analysis_plan']['path'],{'changed':True})
                else:
                    c={**self.custody,'evidence':self.blob(self.custody['evidence']['path'],{'changed':True})}
                    reg['holdout_ref']=self.put('exposure',c)
                self.regref=self.put('preregistration',reg)
                with self.assertRaisesRegex(ValueError,'Verifier-held'): self.check()
                with self.assertRaisesRegex(ValueError,'Published history mutated'):
                    self.check(frozen_sha256=self.regref['sha256'])
                for p,data in original_files.items(): p.write_bytes(data)
                self.regref=copy.deepcopy(original_ref)
        self.check()

    def test_schema_successor_checks_valid_nested_records(self):
        for kind, record in [('exposure',self.old),('preregistration',self.registration)]:
            validate_record(kind,record,self.root,now=NOW)
            for field in record:
                bad=copy.deepcopy(record);del bad[field]
                with self.subTest(kind=kind,field=field),self.assertRaises(ValidationError):
                    validate_record(kind,bad,self.root,now=NOW)
            for changes in ({'schema_version':2},{'unexpected':True}):
                with self.assertRaises(ValidationError):
                    validate_record(kind,{**record,**changes},self.root,now=NOW)

    def test_cycle_guard_and_late_ancestor_invariants(self):
        with self.assertRaisesRegex(ValueError,'Research dependency cycle'):
            validate_research(self.root,'preregistration',self.registration,now=NOW,
                             stack=(('preregistration','REG',1),))
        late=self.exposure('LATE',self.explored,'EXAMINED','EXPLORATORY',ACCESS)
        with self.assertRaisesRegex(ValueError,'ancestor recorded later'):
            validate_research(self.root,'exposure',{**self.old,'ancestors':[self.put('exposure',late)]},now=NOW)

    def test_structural_validation_is_not_freshness_authorization(self):
        validate_repository(self.root,now=NOW)
        with self.assertRaisesRegex(ValueError,'Authoritative history requires'):
            self.check(history_baseline=None,history_inventory=None)


if __name__=='__main__': unittest.main()
