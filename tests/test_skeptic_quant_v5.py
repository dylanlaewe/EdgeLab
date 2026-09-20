"""Skeptic v5 successors for the bounded M0 Quant confirmation gate.

These probes preserve the owner suite and construct current-schema evidence that
reaches the prior-use, authority, reproduction, and Risk-facing interfaces.
"""
import copy
import json
import unittest

import test_quant_protocol as owner
from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import (
    assess_confirmation,
    commit_confirmation_claim,
    experiment_identity,
)
from src.edgelab.validate import read


class SkepticQuantV5Tests(unittest.TestCase):
    def setUp(self):
        self.q = owner.QuantProtocolTests(
            methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
        self.q.setUp()
        self.addCleanup(self.q.doCleanups)

    def _replace_inventory_and_reproduction(self, extra_refs):
        q = self.q
        prior_inventory = read(q.root / q.inventory_ref['path'])
        refs = [q.failed_ref, q.trial_ref, q.cancelled_ref, q.attempted_ref, *extra_refs]
        counts = {'ATTEMPTED': 0, 'SUCCEEDED': 0, 'FAILED': 0, 'CANCELLED': 0}
        for ref in refs:
            counts[read(q.root / ref['path'])['status']] += 1
        inventory = {
            **prior_inventory,
            'version': 2,
            'supersedes': q.inventory_ref,
            'trials': refs,
            'trial_registry_sha256': digest(canonical(
                {ref['path']: ref['sha256'] for ref in refs})),
            'status_counts': counts,
        }
        inventory_ref = q.put('trial-inventory', inventory)
        reproduction = read(q.root / q.reproduction_ref['path'])
        reproduction.update(
            version=2,
            supersedes=q.reproduction_ref,
            experiment_identity_sha256=experiment_identity(
                q.protocol_ref,
                q.trial_ref,
                read(q.root / q.trial_ref['path']),
                inventory_ref,
            ),
        )
        reproduction_ref = q.put('reproduction', reproduction)
        old_state = copy.deepcopy(q.state)
        q._accept_current(predecessor=old_state)
        q.request.update(
            trial_inventory_ref=inventory_ref,
            reproduction_ref=reproduction_ref,
            expected_current_state_sha256=q.state['state_sha256'],
        )

    def _install_prior_examined_trial(self, contaminated_role, *, repackaged_partial=False):
        """Add a valid prior trial that used today's holdout in one split role."""
        q = self.q
        prior_holdout = q.f.membership('PRIORHOLDOUT', ['prior-holdout-1'])
        prior_custody = q.f.exposure(
            'PRIORCUSTODY', prior_holdout, 'UNEXAMINED', 'HOLDOUT_CUSTODY', owner.FREEZE)
        prior_custody_ref = q.f.put('exposure', prior_custody)
        prior_registration = {
            **q.f.registration,
            'id': 'PRIORREG',
            'holdout_ref': prior_custody_ref,
        }
        prior_registration_ref = q.f.put('preregistration', prior_registration)
        prior_access = q.f.exposure(
            'PRIORACCESS', prior_holdout, 'EXAMINED', 'CONFIRMATORY_ACCESS', owner.ACCESS)
        prior_access_ref = q.f.put('exposure', prior_access)
        prior_holdout_manifest = q._manifest('priorholdout', prior_holdout)

        prior_splits = copy.deepcopy(q.splits)
        prior_splits['holdout'] = [prior_holdout_manifest]
        if contaminated_role == 'train':
            if repackaged_partial:
                partial = q.f.membership(
                    'REPACKAGEDPARTIAL', ['prior-train-unique', 'fresh-2'])
                prior_splits['train'] = [q._manifest('repackagedpartial', partial)]
            else:
                prior_splits['train'] = q.splits['holdout']
        elif contaminated_role == 'validation':
            prior_splits['validation'] = q.splits['holdout']
        elif contaminated_role == 'test':
            prior_splits['test'] = q.splits['holdout']
        else:
            raise AssertionError('unsupported role')

        protocol = read(q.root / q.protocol_ref['path'])
        prior_protocol = {
            **protocol,
            'id': f'PRIORQP{contaminated_role.upper()}',
            'preregistration_ref': prior_registration_ref,
            'splits': prior_splits,
        }
        prior_protocol_ref = q.put('quant-protocol', prior_protocol)
        trial = read(q.root / q.trial_ref['path'])
        prior_trial = {
            **trial,
            'id': f'PRIOR{contaminated_role.upper()}',
            'protocol_ref': prior_protocol_ref,
            'preregistration_ref': prior_registration_ref,
            'attempt_ordinal': 1,
            'actual_splits': prior_splits,
            'results_access_ref': prior_access_ref,
        }
        prior_trial_ref = q.put('trial', prior_trial)
        self._replace_inventory_and_reproduction([prior_trial_ref])
        return prior_trial_ref

    def test_Q01_prior_training_use_of_current_holdout_is_accepted(self):
        self._install_prior_examined_trial('train')
        assessment = assess_confirmation(
            self.q.root, self.q.request, self.q.authority, self.q.runner, now=owner.NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')

    def test_Q01_prior_validation_use_of_current_holdout_is_accepted(self):
        self._install_prior_examined_trial('validation')
        assessment = assess_confirmation(
            self.q.root, self.q.request, self.q.authority, self.q.runner, now=owner.NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')

    def test_Q01_renamed_partial_prior_training_use_is_accepted(self):
        self._install_prior_examined_trial('train', repackaged_partial=True)
        assessment = assess_confirmation(
            self.q.root, self.q.request, self.q.authority, self.q.runner, now=owner.NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')

    def test_Q01_negative_control_prior_test_use_is_rejected(self):
        self._install_prior_examined_trial('test')
        with self.assertRaisesRegex(ValueError, 'Prior/repeated trial'):
            assess_confirmation(
                self.q.root, self.q.request, self.q.authority, self.q.runner, now=owner.NOW)

    def test_trusted_reproducer_can_echo_bound_bytes_without_executing(self):
        calls = []

        def echo_only(root, protocol_ref, trial_ref):
            calls.append((protocol_ref, trial_ref))
            return {
                'outputs': {'predictions': self.q.output_bytes},
                'metrics': self.q.metrics_bytes,
            }

        assessment = assess_confirmation(
            self.q.root, self.q.request, self.q.authority, echo_only, now=owner.NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')
        self.assertEqual(calls, [(self.q.protocol_ref, self.q.trial_ref)])

    def test_dishonest_authority_can_return_replayed_token_and_commit_other_bytes(self):
        class DishonestAuthority:
            def __init__(self, state):
                self.state = copy.deepcopy(state)
                self.committed = []

            def current_state(self):
                return copy.deepcopy(self.state)

            def commit_if_current(self, expected_state_sha256, assessment):
                self.committed.append({'different': True})
                return 'replayed-token'

        authority = DishonestAuthority(self.q.state)
        first, token1 = commit_confirmation_claim(
            self.q.root, self.q.request, authority, self.q.runner, now=owner.NOW)
        second, token2 = commit_confirmation_claim(
            self.q.root, self.q.request, authority, self.q.runner, now=owner.NOW)
        self.assertEqual(token1, token2)
        self.assertEqual(authority.committed, [{'different': True}, {'different': True}])
        self.assertEqual(first['assessment_sha256'], second['assessment_sha256'])

    def test_positive_assessment_digest_binds_non_authorized_risk_payload(self):
        assessment, token = commit_confirmation_claim(
            self.q.root, self.q.request, self.q.authority, self.q.runner, now=owner.NOW)
        supplied_digest = assessment.pop('assessment_sha256')
        self.assertEqual(supplied_digest, digest(canonical(assessment)))
        for field in (
            'operational_authorization', 'paper_authorization',
            'live_authorization', 'risk_approval',
        ):
            self.assertIs(assessment[field], False)
        self.assertEqual(token, 'synthetic-commit-1')
        self.assertNotIn(token, json.dumps(assessment, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
