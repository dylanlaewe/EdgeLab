"""H-M0-012 semantic successors. Prior tests are preserved, not monkeypatched.

Synthetic verifier checkpoints are prerequisites, not real trust attestations.
Explicit acceptance tests describe trust boundaries, never operational approval.
"""
import copy
import unittest
from jsonschema import ValidationError
import test_research_history_v2 as owner
from src.edgelab.validate import read, validate_record, validate_repository
from src.edgelab.data_integrity import history_inventory, sample_keys
from src.edgelab.research_protocol import validate_research


class SkepticHistoryV4Tests(unittest.TestCase):
    def setUp(self):
        self.f = owner.ResearchHistoryV2Tests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root

    def fresh_fixture(self):
        f = owner.ResearchHistoryV2Tests(); f.setUp(); self.addCleanup(f.doCleanups)
        return f

    def test_v4_positive_fresh_and_multiple_disjoint_versions_no_authorization(self):
        for version in (2, 3):
            self.f.candidate(self.f.membership(f'NEW{version}', [f'fresh-{version}-a']), version=version)
            result = self.f.check()
            self.assertEqual(result['contract_status'], 'CONSISTENT_AUTHORITATIVE_RESEARCH_EVIDENCE')
            self.assertIs(result['operational_authorization'], False)
            self.assertEqual(result['history_completeness'], 'VERIFIED_RESEARCH_REGISTRIES_ONLY')

    def test_v4_prior_registration_multi_hop_same_renamed_partial_denied(self):
        for labels in (['old-1','old-2'], ['old-2','old-1'], ['old-1','new-9']):
            with self.subTest(labels=labels):
                f = self.fresh_fixture()
                f.candidate(f.membership('MIDDLE', ['middle']))
                f.check()
                f.candidate(f.membership('PACKAGE', labels), version=3)
                with self.assertRaisesRegex(ValueError, 'Examined membership overlaps'):
                    f.check()

    def test_v4_new_id_omitted_predecessor_and_altered_ancestry_denied(self):
        f = self.f
        harmless = f.put('exposure', f.exposure('HARMLESS', f.fresh, 'UNEXAMINED', 'HOLDOUT_CUSTODY', owner.FREEZE))
        f.candidate(f.membership('RELABEL', ['old-2']), version=1, ident='UNLINKED', ancestors=[harmless])
        with self.assertRaisesRegex(ValueError, 'overlaps authoritative'):
            f.check(disclosure_refs=[])

    def test_v4_accepted_and_current_standalone_repackaged_exposure_denied(self):
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                f = self.fresh_fixture()
                members = f.membership('OTHERLABEL', ['fresh-2','fresh-1'])
                self.assertEqual(sample_keys(read(f.root / members['path'])), sample_keys(read(f.root / f.fresh['path'])))
                r = f.exposure('UNRELATED', members, 'EXAMINED', 'EXPLORATORY', owner.EARLY)
                prior = f.put('exposure', r)
                f.put('exposure', {**r, 'version': 2, 'supersedes': prior, 'membership_ref': f.explored})
                if accepted: f.checkpoint()
                with self.assertRaisesRegex(ValueError, 'overlaps authoritative'):
                    f.check(disclosure_refs=[])

    def test_v4_missing_malformed_partial_and_inconsistent_checkpoint_denied(self):
        partial = dict(self.f.inventory); partial.pop('research/exposures/OLD.v1.json')
        cases = [{'history_baseline': None}, {'history_inventory': None},
                 {'history_baseline': 'HEAD'}, {'history_baseline': 'not-a-sha'},
                 {'history_inventory': partial}, {'history_inventory': {'invented': '0'*64}}]
        for args in cases:
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'history requires|full baseline|inventory mismatch'):
                self.f.check(**args)

    def test_v4_checkpoint_missing_current_registration_denied(self):
        oldbase, oldinv = self.f.baseline, self.f.inventory
        self.f.candidate(self.f.membership('DISJOINT', ['new']), ident='NEW', version=1)
        with self.assertRaisesRegex(ValueError, 'absent from authoritative checkpoint'):
            self.f.check(history_baseline=oldbase, history_inventory=oldinv)

    def test_v4_accepted_standalone_delete_rewrite_relocate_denied(self):
        for action in ('delete', 'rewrite', 'relocate'):
            with self.subTest(action=action):
                f = self.fresh_fixture()
                r = f.exposure('UNREFERENCED', f.explored, 'EXAMINED', 'EXPLORATORY', owner.EARLY)
                ref = f.put('exposure', r); f.checkpoint(); f.check()
                p = f.root / ref['path']
                if action == 'rewrite': f.put('exposure', {**r, 'actor': 'rewritten'})
                elif action == 'delete': p.unlink()
                else: p.rename(f.root/'research/relocated.json')
                with self.assertRaisesRegex(ValueError, 'Missing|Published history mutated'):
                    f.check()

    def test_v4_stale_verifier_checkpoint_cannot_prove_latest_acceptance(self):
        # Deliberately violate verifier currency assumption: the API has no
        # independently supplied latest-checkpoint head against which to compare.
        f = self.f; oldbase, oldinv = f.baseline, dict(f.inventory)
        ref = f.put('exposure', f.exposure('LATERACCEPTED', f.fresh, 'EXAMINED', 'EXPLORATORY', owner.EARLY))
        f.checkpoint()
        with self.assertRaisesRegex(ValueError, 'overlaps authoritative'): f.check()
        # Old checkpoint still catches the CURRENT addition while it is present.
        with self.assertRaisesRegex(ValueError, 'overlaps authoritative'):
            f.check(history_baseline=oldbase, history_inventory=oldinv)
        (f.root/ref['path']).unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'): f.check()
        result = f.check(history_baseline=oldbase, history_inventory=oldinv)
        self.assertFalse(result['operational_authorization'])
        self.assertEqual(result['history_baseline'], oldbase)

    def test_v4_misplaced_nested_untyped_and_malformed_evidence_denied(self):
        for path, value in [('research/elsewhere/HIDDEN.json', self.f.old),
                            ('research/exposures/nested/HIDDEN.json', self.f.old),
                            ('research/exposures/untyped.json', {}),
                            ('research/exposures/not-json.txt', 'opaque')]:
            with self.subTest(path=path):
                f = self.fresh_fixture(); f.write(path, value)
                with self.assertRaisesRegex(ValueError, 'Misplaced|Unrecognized'):
                    f.check()
        p = self.root/'research/exposures/broken.json'; p.write_text('{bad')
        with self.assertRaises(ValueError): self.f.check()

    def test_v4_proposed_access_cannot_exempt_accepted_access_or_ancestry(self):
        self.f.checkpoint(exclude_access=False)
        with self.assertRaisesRegex(ValueError, 'already in authoritative history'): self.f.check()
        f = self.fresh_fixture()
        ancestor = f.put('exposure', f.exposure('PRIOR', f.fresh, 'EXAMINED', 'EXPLORATORY', owner.EARLY))
        access = f.put('exposure', {**f.access, 'ancestors': [ancestor]})
        with self.assertRaisesRegex(ValueError, 'Examined membership overlaps'): f.check(access_ref=access)

    def test_v4_first_access_exact_binding_retroactive_freeze_and_unknowns(self):
        for at in (owner.EARLY, owner.FREEZE):
            ref = self.f.put('exposure', {**self.f.access, 'first_results_access_at': at})
            with self.assertRaisesRegex(ValueError, 'strictly follow freeze'): self.f.check(access_ref=ref)
        self.f.accessref = self.f.put('exposure', self.f.access)
        ref = self.f.put('exposure', {**self.f.access, 'membership_ref': self.f.membership('EQUAL', ['fresh-1','fresh-2'])})
        with self.assertRaisesRegex(ValueError, 'Exact holdout membership'): self.f.check(access_ref=ref)
        self.f.accessref = self.f.put('exposure', self.f.access)
        unknown = {**self.f.old, 'id': 'UNKNOWN', 'status': 'UNKNOWN', 'first_results_access_at': None, 'unknown_reason': 'No custody'}
        self.f.put('exposure', unknown)
        with self.assertRaisesRegex(ValueError, 'Unknown exposure'): self.f.check()
        f = self.fresh_fixture()
        late = {**f.custody, 'created_at': owner.ACCESS, 'coverage_through': owner.ACCESS}
        with self.assertRaisesRegex(ValueError, 'custody must cover'):
            validate_research(f.root, 'preregistration', {**f.registration, 'holdout_ref': f.put('exposure', late)}, now=owner.NOW)

    def test_v4_rehashed_threshold_hypothesis_plan_custody_cannot_replace_pins(self):
        for target in ('threshold','hypothesis','plan','custody'):
            with self.subTest(target=target):
                f = self.fresh_fixture(); reg = copy.deepcopy(f.registration)
                if target == 'threshold': reg['thresholds'][0]['value'] = '99'
                elif target == 'hypothesis':
                    h = read(f.root/reg['hypothesis_ref']['path']); h['rejection_criteria'] = ['new']
                    reg['hypothesis_ref'] = f.put('hypothesis', h)
                elif target == 'plan': reg['analysis_plan'] = f.blob(reg['analysis_plan']['path'], {'new': True})
                else:
                    reg['holdout_ref'] = f.put('exposure', {**f.custody, 'evidence': f.blob(f.custody['evidence']['path'], {'new': True})})
                f.regref = f.put('preregistration', reg)
                with self.assertRaisesRegex(ValueError, 'Verifier-held'): f.check()
                with self.assertRaisesRegex(ValueError, 'Published history mutated'):
                    f.check(frozen_sha256=f.regref['sha256'])

    def test_v4_schema_version_predecessor_and_exposure_order_successors(self):
        for kind, record in [('exposure', self.f.old), ('preregistration', self.f.registration)]:
            validate_research(self.root, kind, record, now=owner.NOW)
            for field in record:
                r = dict(record); del r[field]
                with self.subTest(kind=kind, field=field), self.assertRaises(ValidationError):
                    validate_research(self.root, kind, r, now=owner.NOW)
            for updates in ({'schema_version': 2}, {'approval': True}):
                with self.assertRaises(ValidationError): validate_record(kind, {**record, **updates}, self.root, now=owner.NOW)
        for updates, error in [({'version': 2}, 'requires predecessor'),
                               ({'version': 3, 'supersedes': self.f.regref}, 'exact predecessor')]:
            with self.assertRaisesRegex(ValueError, error):
                validate_research(self.root, 'preregistration', {**self.f.registration, **updates}, now=owner.NOW)
        with self.assertRaisesRegex(ValueError, 'requires first access'):
            validate_research(self.root, 'exposure', {**self.f.old, 'first_results_access_at': None}, now=owner.NOW)

    def test_v4_legacy_temporal_threshold_reference_and_access_family(self):
        f = self.f
        for updates, reason in [({'registered_at': owner.ACCESS}, 'Retroactive'),
                                ({'unresolved_thresholds': ['unknown']}, 'Unresolved thresholds')]:
            hypothesis = read(f.root/f.registration['hypothesis_ref']['path'])
            original = (f.root/f.registration['hypothesis_ref']['path']).read_bytes()
            ref = f.put('hypothesis', {**hypothesis, **updates})
            with self.assertRaisesRegex(ValueError, reason):
                validate_research(f.root, 'preregistration', {**f.registration, 'hypothesis_ref': ref}, now=owner.NOW)
            (f.root/f.registration['hypothesis_ref']['path']).write_bytes(original)
        for changes, reason in [({'kind': 'hypothesis'}, 'Wrong reference type'),
                                ({'id': 'WRONG'}, 'identity mismatch'),
                                ({'sha256': '0'*64}, 'digest mismatch')]:
            with self.assertRaisesRegex(ValueError, reason):
                validate_research(f.root, 'exposure', {**f.custody, 'membership_ref': {**f.fresh, **changes}}, now=owner.NOW)
        for changes, reason in [({'coverage_through': owner.ACCESS}, 'coverage exceeds'),
                                ({'created_at': '2999-01-01T00:00:00Z'}, 'Future completed')]:
            with self.assertRaisesRegex(ValueError, reason):
                validate_research(f.root, 'exposure', {**f.old, **changes}, now=owner.NOW)
        members = read(f.root/f.fresh['path'])
        ref = f.put('membership', {**members, 'id': 'LATE', 'created_at': owner.ACCESS})
        with self.assertRaisesRegex(ValueError, 'predates membership binding'):
            validate_research(f.root, 'exposure', {**f.custody, 'membership_ref': ref}, now=owner.NOW)
        for changes in ({'purpose': 'EXPLORATORY'}, {'status': 'UNKNOWN', 'first_results_access_at': None, 'unknown_reason': 'unknown'}):
            ref = f.put('exposure', {**f.access, **changes})
            with self.assertRaisesRegex(ValueError, 'Known confirmatory first-access'):
                f.check(access_ref=ref)
        f.accessref = f.put('exposure', f.access)
        self.assertFalse(f.check()['operational_authorization'])

    def test_v4_structure_only_api_is_not_authoritative_freshness(self):
        self.f.put('exposure', self.f.exposure('OMITTED', self.f.fresh, 'EXAMINED', 'EXPLORATORY', owner.EARLY))
        self.assertIsInstance(validate_repository(self.root, now=owner.NOW), int)
        with self.assertRaisesRegex(ValueError, 'history requires'):
            self.f.check(history_baseline=None, history_inventory=None)
        with self.assertRaisesRegex(ValueError, 'overlaps authoritative'): self.f.check()


if __name__ == '__main__': unittest.main()
