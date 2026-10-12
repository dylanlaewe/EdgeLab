"""Independent Skeptic v6 successors for Quant Q01/Q02 remediation."""
import copy
import unittest

from jsonschema import ValidationError

import test_quant_protocol as owner
from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import (
    assess_confirmation,
    claim_identity,
    commitment_digest,
    commit_confirmation_claim,
    verify_authority_commitment,
)
from src.edgelab.validate import read


class SkepticQuantV6Tests(unittest.TestCase):
    def setUp(self):
        self.q = owner.QuantProtocolTests(
            methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
        self.q.setUp()
        self.addCleanup(self.q.doCleanups)

    def _fresh_case(self):
        case = owner.QuantProtocolTests(
            methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def _install_timed_failed_overlap(self, case, started_at, *, created_at='2026-09-19T13:09:00Z'):
        prior_holdout = case.f.membership('TIMEDPRIORHOLDOUT', ['timed-prior-holdout'])
        custody = case.f.exposure(
            'TIMEDPRIORCUSTODY', prior_holdout, 'UNEXAMINED',
            'HOLDOUT_CUSTODY', owner.FREEZE)
        custody_ref = case.f.put('exposure', custody)
        registration = {
            **case.f.registration,
            'id': 'TIMEDPRIORREG',
            'holdout_ref': custody_ref,
        }
        registration_ref = case.f.put('preregistration', registration)
        splits = copy.deepcopy(case.splits)
        splits['train'] = case.splits['holdout']
        splits['holdout'] = [case._manifest('timedpriorholdout', prior_holdout)]
        protocol = {
            **read(case.root / case.protocol_ref['path']),
            'id': 'TIMEDPRIORQP',
            'preregistration_ref': registration_ref,
            'splits': splits,
        }
        protocol_ref = case.put('quant-protocol', protocol)
        trial = {
            **read(case.root / case.trial_ref['path']),
            'id': 'TIMEDPRIORTRIAL',
            'protocol_ref': protocol_ref,
            'preregistration_ref': registration_ref,
            'attempt_ordinal': 1,
            'started_at': started_at,
            'completed_at': '2026-09-19T13:05:00Z',
            'created_at': created_at,
            'status': 'FAILED',
            'failure_reason': 'Timing-boundary adversarial trial.',
            'actual_splits': splits,
            'results_access_ref': None,
            'outputs': [],
            'metrics': None,
        }
        trial_ref = case.put('trial', trial)
        case._replace_inventory_and_reproduction([trial_ref])
        return trial_ref

    def _assessment_and_commitment(self):
        return commit_confirmation_claim(
            self.q.root, self.q.request, self.q.authority,
            self.q.runner, now=owner.NOW)

    def test_Q01_exact_overlap_rejected_in_every_prior_split_role(self):
        for role in ('train', 'validation', 'test', 'holdout'):
            with self.subTest(role=role):
                case = self._fresh_case()
                case._install_prior_consumption(role)
                with self.assertRaisesRegex(ValueError, f'{role} split'):
                    assess_confirmation(
                        case.root, case.request, case.authority,
                        case.runner, now=owner.NOW)

    def test_Q01_packaging_and_identity_variants_rejected(self):
        for variant in ('renamed', 'reordered', 'partial', 'versioned'):
            with self.subTest(variant=variant):
                case = self._fresh_case()
                case._install_prior_consumption('train', variant=variant)
                with self.assertRaisesRegex(ValueError, 'train split'):
                    assess_confirmation(
                        case.root, case.request, case.authority,
                        case.runner, now=owner.NOW)

    def test_Q01_failed_cancelled_attempted_and_missing_access_fail_closed(self):
        for status in ('FAILED', 'CANCELLED', 'ATTEMPTED'):
            with self.subTest(status=status):
                case = self._fresh_case()
                ref = case._install_prior_consumption('validation', status=status)
                self.assertIsNone(read(case.root / ref['path'])['results_access_ref'])
                with self.assertRaisesRegex(ValueError, 'validation split'):
                    assess_confirmation(
                        case.root, case.request, case.authority,
                        case.runner, now=owner.NOW)

    def test_Q01_timing_before_equal_and_after_first_access(self):
        for started_at, rejected in (
            ('2026-09-19T12:59:59Z', True),
            (owner.ACCESS, True),
            ('2026-09-19T13:00:01Z', False),
        ):
            with self.subTest(started_at=started_at):
                case = self._fresh_case()
                self._install_timed_failed_overlap(case, started_at)
                if rejected:
                    with self.assertRaisesRegex(ValueError, 'train split'):
                        assess_confirmation(
                            case.root, case.request, case.authority,
                            case.runner, now=owner.NOW)
                else:
                    result = assess_confirmation(
                        case.root, case.request, case.authority,
                        case.runner, now=owner.NOW)
                    self.assertEqual(result['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')

    def test_Q01_later_created_record_with_prior_start_fails_closed(self):
        self._install_timed_failed_overlap(
            self.q, '2026-09-19T12:59:59Z', created_at='2026-09-19T13:09:00Z')
        with self.assertRaisesRegex(ValueError, 'train split'):
            assess_confirmation(
                self.q.root, self.q.request, self.q.authority,
                self.q.runner, now=owner.NOW)

    def test_Q01_omitted_trial_and_older_inventory_or_state_rejected(self):
        old_state = copy.deepcopy(self.q.state)
        old_inventory = copy.deepcopy(self.q.inventory_ref)
        old_reproduction = copy.deepcopy(self.q.reproduction_ref)
        self.q._install_prior_consumption('train')

        omitted = copy.deepcopy(self.q.request)
        omitted['trial_inventory_ref'] = old_inventory
        omitted['reproduction_ref'] = old_reproduction
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            assess_confirmation(
                self.q.root, omitted, self.q.authority,
                self.q.runner, now=owner.NOW)

        stale = copy.deepcopy(self.q.request)
        stale['expected_current_state_sha256'] = old_state['state_sha256']
        with self.assertRaisesRegex(ValueError, 'Stale or substituted'):
            assess_confirmation(
                self.q.root, stale, self.q.authority,
                self.q.runner, now=owner.NOW)

    def test_Q01_fresh_and_unrelated_reuse_positive_remain_non_authorizing(self):
        for add_unrelated_reuse in (False, True):
            with self.subTest(add_unrelated_reuse=add_unrelated_reuse):
                case = self._fresh_case()
                if add_unrelated_reuse:
                    case._install_prior_consumption('train', variant='nonholdout')
                assessment = assess_confirmation(
                    case.root, case.request, case.authority,
                    case.runner, now=owner.NOW)
                self.assertTrue(assessment['scientific_integrity_eligible'])
                for field in (
                    'operational_authorization', 'paper_authorization',
                    'live_authorization', 'risk_approval',
                ):
                    self.assertIs(assessment[field], False)

    def test_Q02_core_assessment_state_experiment_claim_and_authority_bindings(self):
        assessment, commitment = self._assessment_and_commitment()
        changes = {
            'authority_id': 'substituted-authority',
            'generation': commitment['generation'] + 1,
            'assessment_sha256': '0' * 64,
            'current_state_sha256': '1' * 64,
            'experiment_identity_sha256': '2' * 64,
            'claim_identity_sha256': '3' * 64,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                altered = {**commitment, field: value}
                altered['commitment_sha256'] = commitment_digest(altered)
                with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW)

        changed_claim = copy.deepcopy(assessment)
        changed_claim['trial_ref']['id'] = 'SUBSTITUTED-TRIAL'
        changed_claim['assessment_sha256'] = digest(canonical({
            key: value for key, value in changed_claim.items()
            if key != 'assessment_sha256'
        }))
        self.assertNotEqual(claim_identity(changed_claim), commitment['claim_identity_sha256'])
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            verify_authority_commitment(
                self.q.root, changed_claim, commitment, now=owner.NOW)

    def test_Q02_malformed_missing_extra_and_unrehashed_content_rejected(self):
        assessment, commitment = self._assessment_and_commitment()
        with self.assertRaisesRegex(ValueError, 'structured record'):
            verify_authority_commitment(
                self.q.root, assessment, 'opaque', now=owner.NOW)
        for field in commitment:
            with self.subTest(missing=field):
                altered = copy.deepcopy(commitment)
                del altered[field]
                with self.assertRaises(ValidationError):
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW)
        with self.assertRaises(ValidationError):
            verify_authority_commitment(
                self.q.root, assessment, {**commitment, 'extra': True}, now=owner.NOW)
        for field, value in (
            ('commitment_id', 'altered-id'),
            ('committed_at', '2026-09-19T13:09:59Z'),
            ('limitations', ['altered limitation']),
        ):
            with self.subTest(unrehashed=field):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    verify_authority_commitment(
                        self.q.root, assessment,
                        {**commitment, field: value}, now=owner.NOW)

    def test_Q02_future_commitment_time_is_accepted_after_rehash(self):
        assessment, commitment = self._assessment_and_commitment()
        future = {**commitment, 'committed_at': '2999-01-01T00:00:00Z'}
        future['commitment_sha256'] = commitment_digest(future)
        self.assertEqual(
            verify_authority_commitment(
                self.q.root, assessment, future, now=owner.NOW),
            future,
        )

    def test_Q02_id_time_and_limitations_are_content_bound_not_authenticated(self):
        assessment, commitment = self._assessment_and_commitment()
        for field, value in (
            ('commitment_id', 'attacker-selected-id'),
            ('committed_at', '2026-09-19T13:09:59Z'),
            ('limitations', ['attacker-selected limitation']),
        ):
            with self.subTest(recomputed=field):
                altered = {**commitment, field: value}
                altered['commitment_sha256'] = commitment_digest(altered)
                self.assertEqual(
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW),
                    altered,
                )

    def test_Q02_duplicate_replay_same_claim_is_not_a_local_uniqueness_check(self):
        assessment, commitment = self._assessment_and_commitment()
        first = verify_authority_commitment(
            self.q.root, assessment, commitment, now=owner.NOW)
        second = verify_authority_commitment(
            self.q.root, assessment, commitment, now=owner.NOW)
        self.assertEqual(first, second)

    def test_Q02_fully_self_consistent_forgery_is_not_authentication(self):
        assessment, commitment = self._assessment_and_commitment()
        forged_assessment = copy.deepcopy(assessment)
        forged_assessment.update(
            authority_id='forged-authority',
            authority_generation=99,
            current_state_sha256='4' * 64,
        )
        forged_assessment['assessment_sha256'] = digest(canonical({
            key: value for key, value in forged_assessment.items()
            if key != 'assessment_sha256'
        }))
        forged = {
            **commitment,
            'authority_id': forged_assessment['authority_id'],
            'generation': forged_assessment['authority_generation'],
            'commitment_id': 'forged-commitment',
            'assessment_sha256': forged_assessment['assessment_sha256'],
            'current_state_sha256': forged_assessment['current_state_sha256'],
            'experiment_identity_sha256': forged_assessment['experiment_identity_sha256'],
            'claim_identity_sha256': claim_identity(forged_assessment),
            'limitations': ['Self-consistent content is not authenticated authority evidence.'],
        }
        forged['commitment_sha256'] = commitment_digest(forged)
        self.assertEqual(
            verify_authority_commitment(
                self.q.root, forged_assessment, forged, now=owner.NOW),
            forged,
        )


if __name__ == '__main__':
    unittest.main()
