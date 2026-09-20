"""Independent H-M0-010 probes; all prior suites remain byte-preserved.

Acceptance probes explicitly characterize gaps/trust limits, never authorization.
"""
import copy
import unittest
from jsonschema import ValidationError
import test_research_protocol as research
import test_skeptic_adversarial as historical
from src.edgelab.validate import LOCATIONS, validate_record, validate_repository, read
from src.edgelab.research_protocol import validate_research


class ResearchSemanticV3Tests(unittest.TestCase):
    def setUp(self):
        self.f = research.ResearchProtocolTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root

    def test_v3_legacy_schema_attack_with_valid_current_prerequisites(self):
        old = historical.SkepticAdversarialTests()
        old.setUp()
        self.addCleanup(old.doCleanups)
        for kind in LOCATIONS:
            if kind in ('exposure', 'preregistration'):
                record = self.f.old if kind == 'exposure' else self.f.registration
                root = self.root
            else:
                record, root = old.fixture(kind), old.root
            validate_record(kind, record, root, now=research.NOW)
            for field in record:
                with self.subTest(kind=kind, missing=field):
                    r = copy.deepcopy(record); del r[field]
                    with self.assertRaises(ValidationError):
                        validate_record(kind, r, root, now=research.NOW)
            for update in ({'unexpected': True}, {'schema_version': 2}):
                with self.assertRaises(ValidationError):
                    validate_record(kind, {**record, **update}, root, now=research.NOW)

    def test_v3_fresh_holdout_is_consistency_only(self):
        result = self.f.check()
        self.assertEqual(result['contract_status'], 'CONSISTENT_SUPPLIED_EVIDENCE')
        self.assertIs(result['operational_authorization'], False)
        self.assertEqual(result['history_completeness'], 'CALLER_MUST_ESTABLISH')
        validate_repository(self.root, now=research.NOW)

    def test_v3_same_renamed_partial_and_versioned_exposure_rejected(self):
        for name, outcomes in [('SAME', ['fresh-1','fresh-2']), ('RENAMED', ['fresh-2','fresh-1']),
                               ('PARTIAL', ['old-1','fresh-1'])]:
            with self.subTest(name=name):
                member = self.f.membership(name, outcomes)
                exposed = self.f.exposure(name, member, 'EXAMINED', 'EXPLORATORY', research.EARLY)
                prior = self.f.put('exposure', exposed)
                # Repackage as a disjoint correction, preserving valid predecessor.
                wrapper = {**exposed, 'version': 2, 'supersedes': prior, 'membership_ref': self.f.explored}
                ref = self.f.put('exposure', wrapper)
                with self.assertRaisesRegex(ValueError, 'Examined membership overlaps'):
                    self.f.check(disclosure_refs=[ref])

    def test_v3_access_order_and_retroactive_custody_rejected(self):
        for at in (research.EARLY, research.FREEZE):
            with self.assertRaisesRegex(ValueError, 'strictly follow freeze'):
                self.f.check(access_ref=self.f.put('exposure', {**self.f.access, 'first_results_access_at': at}))
        self.f.accessref = self.f.put('exposure', self.f.access)
        late = {**self.f.custody, 'created_at': research.ACCESS, 'coverage_through': research.ACCESS}
        reg = {**self.f.registration, 'holdout_ref': self.f.put('exposure', late)}
        with self.assertRaisesRegex(ValueError, 'custody must cover'):
            validate_research(self.root, 'preregistration', reg, now=research.NOW)

    def test_v3_frozen_threshold_hypothesis_plan_and_custody_rehash_rejected(self):
        # Every attack starts from a fresh positive helper; retain the original external pin.
        for target in ('threshold', 'hypothesis', 'plan', 'custody'):
            with self.subTest(target=target):
                f = research.ResearchProtocolTests(); f.setUp(); self.addCleanup(f.doCleanups)
                reg = copy.deepcopy(f.registration)
                if target == 'threshold': reg['thresholds'][0]['value'] = '99'
                elif target == 'hypothesis':
                    reg['hypothesis_ref'] = f.put('hypothesis', {**f.hypothesis, 'rejection_criteria': ['changed']})
                elif target == 'plan': reg['analysis_plan'] = f.blob('research/evidence/plan.json', {'changed': True})
                else:
                    custody = {**f.custody, 'evidence': f.blob('research/evidence/CUSTODY.json', {'changed': True})}
                    reg['holdout_ref'] = f.put('exposure', custody)
                f.regref = f.put('preregistration', reg)
                with self.assertRaisesRegex(ValueError, 'Verifier-held'):
                    f.check()

    def test_v3_unknown_and_missing_evidence_rejected(self):
        unknown = {**self.f.old, 'id': 'UNKNOWN', 'status': 'UNKNOWN',
                   'first_results_access_at': None, 'unknown_reason': 'No custody evidence'}
        with self.assertRaisesRegex(ValueError, 'Unknown exposure blocks'):
            self.f.check(disclosure_refs=[self.f.put('exposure', unknown)])
        (self.root / self.f.custody['evidence']['path']).unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.f.check()

    def test_v3_exact_membership_binding_rejects_same_samples_other_reference(self):
        members = read(self.root / self.f.fresh['path'])
        ref = self.f.put('membership', {**members, 'id': 'OTHER'})
        with self.assertRaisesRegex(ValueError, 'Exact holdout membership reference'):
            self.f.check(access_ref=self.f.put('exposure', {**self.f.access, 'membership_ref': ref}))

    def test_v3_omitted_exposure_still_accepted_until_caller_discloses(self):
        hidden = self.f.exposure('HIDDEN', self.f.fresh, 'EXAMINED', 'EXPLORATORY', research.EARLY)
        ref = self.f.put('exposure', hidden)
        validate_repository(self.root, now=research.NOW)
        self.assertFalse(self.f.check()['operational_authorization'])
        with self.assertRaisesRegex(ValueError, 'Examined membership overlaps'):
            self.f.check(disclosure_refs=[ref])

    def test_v3_prior_registration_ancestry_not_carried_to_new_holdout(self):
        # REG.v1 already discloses OLD as examined. A valid correction selects
        # that known explored population as its holdout and drops the disclosure.
        custody = self.f.exposure('NEWCUSTODY', self.f.explored, 'UNEXAMINED', 'HOLDOUT_CUSTODY', research.FREEZE)
        r = {**self.f.registration, 'version': 2, 'supersedes': self.f.regref,
             'holdout_ref': self.f.put('exposure', custody), 'exploratory_ancestors': []}
        self.f.regref = self.f.put('preregistration', r)
        access = {**self.f.access, 'membership_ref': self.f.explored}
        self.f.accessref = self.f.put('exposure', access)
        validate_repository(self.root, now=research.NOW)
        result = self.f.check(frozen_sha256=self.f.regref['sha256'])
        self.assertEqual(result['contract_status'], 'CONSISTENT_SUPPLIED_EVIDENCE')
        self.assertFalse(result['operational_authorization'])
        with self.assertRaisesRegex(ValueError, 'Examined membership overlaps'):
            self.f.check(frozen_sha256=self.f.regref['sha256'], disclosure_refs=[self.f.put('exposure', self.f.old)])

    def test_v3_candidate_pin_does_not_authenticate_freeze(self):
        changed = copy.deepcopy(self.f.registration)
        changed['thresholds'][0]['value'] = '99'
        self.f.regref = self.f.put('preregistration', changed)
        with self.assertRaisesRegex(ValueError, 'Verifier-held'):
            self.f.check()
        # Supplying the attacker's new digest defeats the trust assumption, not hashing.
        self.assertFalse(self.f.check(frozen_sha256=self.f.regref['sha256'])['operational_authorization'])


if __name__ == '__main__': unittest.main()
