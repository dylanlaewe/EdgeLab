"""Independent Skeptic v7 re-review probes for Quant Q03 only."""
import copy
import unittest

from jsonschema import ValidationError

import test_quant_protocol as owner
from src.edgelab.quant_protocol import (
    assess_confirmation,
    commitment_digest,
    commit_confirmation_claim,
    verify_authority_commitment,
)


class SkepticQuantV7Tests(unittest.TestCase):
    def setUp(self):
        self.q = owner.QuantProtocolTests(
            methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
        self.q.setUp()
        self.addCleanup(self.q.doCleanups)

    def _assessment_and_commitment(self):
        return commit_confirmation_claim(
            self.q.root, self.q.request, self.q.authority,
            self.q.runner, now=owner.NOW)

    @staticmethod
    def _rehash(commitment, committed_at):
        altered = {**commitment, 'committed_at': committed_at}
        altered['commitment_sha256'] = commitment_digest(altered)
        return altered

    def test_Q03_required_attack_matrix(self):
        assessment, commitment = self._assessment_and_commitment()
        self.assertEqual(
            verify_authority_commitment(
                self.q.root, assessment, commitment, now=owner.NOW),
            commitment,
        )

        malformed = self._rehash(commitment, 'not-a-timestamp')
        with self.assertRaises(ValidationError):
            verify_authority_commitment(
                self.q.root, assessment, malformed, now=owner.NOW)

        future = self._rehash(commitment, '2999-01-01T00:00:00Z')
        with self.assertRaisesRegex(ValueError, 'Future completed fact: committed_at'):
            verify_authority_commitment(
                self.q.root, assessment, future, now=owner.NOW)

        altered_without_rehash = {
            **commitment, 'committed_at': '2026-09-19T13:09:59Z'}
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            verify_authority_commitment(
                self.q.root, assessment, altered_without_rehash, now=owner.NOW)

    def test_Q03_exact_boundary_offsets_fraction_and_case_follow_existing_policy(self):
        assessment, commitment = self._assessment_and_commitment()
        accepted = (
            '2026-09-21T00:00:00Z',
            '2026-09-20T20:00:00-04:00',
            '2026-09-20T23:59:59.999999Z',
            '2026-09-19t13:10:00z',
        )
        for timestamp in accepted:
            with self.subTest(accepted=timestamp):
                altered = self._rehash(commitment, timestamp)
                self.assertEqual(
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW),
                    altered,
                )

        rejected = (
            '2026-09-21T00:00:00.000001Z',
            '2026-09-20T20:00:00.000001-04:00',
        )
        for timestamp in rejected:
            with self.subTest(rejected=timestamp):
                altered = self._rehash(commitment, timestamp)
                with self.assertRaisesRegex(
                        ValueError, 'Future completed fact: committed_at'):
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW)

    def test_Q03_omission_types_and_malformed_parseable_forms_rejected(self):
        assessment, commitment = self._assessment_and_commitment()
        omitted = copy.deepcopy(commitment)
        del omitted['committed_at']
        omitted['commitment_sha256'] = commitment_digest(omitted)
        with self.assertRaises(ValidationError):
            verify_authority_commitment(
                self.q.root, assessment, omitted, now=owner.NOW)

        for value in (None, 0, ['2026-09-19T13:10:00Z']):
            with self.subTest(alternate_type=value):
                altered = self._rehash(commitment, value)
                with self.assertRaises(ValidationError):
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW)

        # These strings are accepted by broad ISO parsers, but not by the
        # repository's existing RFC 3339-like date-time contract.
        for value in ('2026-09-21', '2026-09-21 00:00:00+00:00'):
            with self.subTest(malformed_but_parseable=value):
                altered = self._rehash(commitment, value)
                with self.assertRaises(ValidationError):
                    verify_authority_commitment(
                        self.q.root, assessment, altered, now=owner.NOW)

        invalid_calendar = self._rehash(commitment, '2026-02-30T00:00:00Z')
        with self.assertRaises(ValidationError):
            verify_authority_commitment(
                self.q.root, assessment, invalid_calendar, now=owner.NOW)

    def test_Q03_full_commit_path_rejects_rehashed_future_authority_response(self):
        class FutureAuthority(owner.SyntheticAuthority):
            def commit_if_current(self, expected_state_sha256, assessment):
                commitment = super().commit_if_current(
                    expected_state_sha256, assessment)
                commitment['committed_at'] = '2999-01-01T00:00:00Z'
                commitment['commitment_sha256'] = commitment_digest(commitment)
                return commitment

        with self.assertRaisesRegex(ValueError, 'Future completed fact: committed_at'):
            commit_confirmation_claim(
                self.q.root, self.q.request, FutureAuthority(self.q.state),
                self.q.runner, now=owner.NOW)

    def test_Q03_regression_Q01_prior_split_contamination_still_rejected(self):
        self.q._install_prior_consumption('train')
        with self.assertRaisesRegex(ValueError, 'train split'):
            assess_confirmation(
                self.q.root, self.q.request, self.q.authority,
                self.q.runner, now=owner.NOW)

    def test_Q03_regression_structured_binding_and_non_authorization_hold(self):
        assessment, commitment = self._assessment_and_commitment()
        altered = {**commitment, 'current_state_sha256': '1' * 64}
        altered['commitment_sha256'] = commitment_digest(altered)
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            verify_authority_commitment(
                self.q.root, assessment, altered, now=owner.NOW)

        self.assertEqual(commitment['assessment_sha256'], assessment['assessment_sha256'])
        for field in (
            'operational_authorization', 'paper_authorization',
            'live_authorization', 'risk_approval',
        ):
            self.assertIs(assessment[field], False)


if __name__ == '__main__':
    unittest.main()
