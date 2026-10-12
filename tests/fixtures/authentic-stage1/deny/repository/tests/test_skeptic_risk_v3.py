"""Focused independent successor probes for Risk SR07 and SR08."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from jsonschema import ValidationError

import test_risk_controls as owner
from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import claim_identity, commitment_digest
from src.edgelab.risk_controls import (
    JsonAuthorizationStore,
    JsonReplayStore,
    assemble_authoritative_decision,
    history_head,
    replay_ledger,
    validate_authorization_token,
    verify_execution_token,
)
from src.edgelab.validate import ROOT


class SkepticRiskV3Tests(unittest.TestCase):
    def setUp(self):
        self.o = owner.RiskControlTests()

    @staticmethod
    def _stores(directory: str):
        replay_path = Path(directory) / 'replay.json'
        JsonReplayStore.initialize(
            replay_path, policy_id='POLICY-1', policy_generation=7,
            authority_generations={'AUTH-1': 3})
        authorization_path = Path(directory) / 'authorization.json'
        JsonAuthorizationStore.initialize(
            authorization_path, authority_id='RISK-STATE-1', generation=4)
        return (JsonReplayStore(replay_path),
                JsonAuthorizationStore(authorization_path))

    def _assemble(self, root, action, state, directory):
        replay, authorization = self._stores(directory)
        return assemble_authoritative_decision(
            root, action,
            authority=owner.StaticRiskAuthority(state, action),
            policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            scientific_replay_store=replay,
            authorization_store=authorization, now=owner.NOW)

    @staticmethod
    def _bind_state_to_action(state: dict, action: dict) -> None:
        state['action_sha256'] = action['action_sha256']
        state['exposure']['request']['action_sha256'] = action['action_sha256']
        owner.seal(state['exposure']['request'], 'position_sha256')
        owner.seal(state, 'state_sha256')

    @staticmethod
    def _change_assessment_experiment(assessment: dict, experiment: str) -> None:
        assessment['experiment_identity_sha256'] = experiment
        assessment['assessment_sha256'] = digest(canonical({
            key: value for key, value in assessment.items()
            if key != 'assessment_sha256'}))

    @staticmethod
    def _change_commitment_experiment(
            commitment: dict, assessment: dict, experiment: str) -> None:
        commitment['assessment_sha256'] = assessment['assessment_sha256']
        commitment['experiment_identity_sha256'] = experiment
        commitment['claim_identity_sha256'] = claim_identity(assessment)
        commitment['commitment_sha256'] = commitment_digest(commitment)

    def test_SR07_assessment_commitment_and_current_science_mismatches_reject(self):
        experiment_b = '9' * 64
        for variant in ('current_state', 'assessment', 'commitment'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = self.o.synthetic_root(directory)
                action, state = self.o.new_exposure_state(root)
                action['experiment_identity_sha256'] = experiment_b
                owner.seal(action, 'action_sha256')
                science = state['scientific']
                if variant == 'current_state':
                    # Exact A assessment/commitment and current-science tuple
                    # are presented against an exact B action.
                    pass
                elif variant == 'assessment':
                    # The wrapper claims B, but the assessment and commitment
                    # remain exact A evidence.
                    science['experiment_identity_sha256'] = experiment_b
                else:
                    # The wrapper and assessment claim B, while the exact
                    # commitment remains A.
                    science['experiment_identity_sha256'] = experiment_b
                    self._change_assessment_experiment(
                        science['assessment'], experiment_b)
                self._bind_state_to_action(state, action)
                replay, authorization = self._stores(directory)
                with self.assertRaisesRegex(
                        ValueError, 'another strategy or experiment'):
                    assemble_authoritative_decision(
                        root, action,
                        authority=owner.StaticRiskAuthority(state, action),
                        policy=self.o.policy(),
                        expected_policy_source='synthetic-verifier://risk-tests',
                        scientific_replay_store=replay,
                        authorization_store=authorization, now=owner.NOW)

    def test_SR07_fully_recomputed_B_science_cannot_authorize_exact_A_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            experiment_b = '9' * 64
            science = state['scientific']
            self._change_assessment_experiment(
                science['assessment'], experiment_b)
            self._change_commitment_experiment(
                science['commitment'], science['assessment'], experiment_b)
            science['experiment_identity_sha256'] = experiment_b
            owner.seal(state, 'state_sha256')
            replay, authorization = self._stores(directory)
            with self.assertRaisesRegex(
                    ValueError, 'another strategy or experiment'):
                assemble_authoritative_decision(
                    root, action,
                    authority=owner.StaticRiskAuthority(state, action),
                    policy=self.o.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    scientific_replay_store=replay,
                    authorization_store=authorization, now=owner.NOW)

    def test_SR07_missing_malformed_and_stale_digest_experiment_reject(self):
        for mutation in ('missing', 'malformed', 'stale_digest'):
            action = self.o.action()
            if mutation == 'missing':
                del action['experiment_identity_sha256']
                owner.seal(action, 'action_sha256')
            elif mutation == 'malformed':
                action['experiment_identity_sha256'] = 'not-a-sha256'
                owner.seal(action, 'action_sha256')
            else:
                action['experiment_identity_sha256'] = '9' * 64
            with self.subTest(mutation=mutation):
                if mutation == 'stale_digest':
                    with self.assertRaisesRegex(ValueError, 'Action digest'):
                        assemble_authoritative_decision(
                            ROOT, action, authority=None,
                            policy=self.o.policy(),
                            expected_policy_source='synthetic-verifier://risk-tests',
                            scientific_replay_store=None,
                            authorization_store=None, now=owner.NOW)
                else:
                    with self.assertRaises(ValidationError):
                        assemble_authoritative_decision(
                            ROOT, action, authority=None,
                            policy=self.o.policy(),
                            expected_policy_source='synthetic-verifier://risk-tests',
                            scientific_replay_store=None,
                            authorization_store=None, now=owner.NOW)

    def test_SR07_exact_positive_and_issued_token_resists_experiment_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            replay, authorization = self._stores(directory)
            decision, token, returned = assemble_authoritative_decision(
                root, action,
                authority=owner.StaticRiskAuthority(state, action),
                policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=replay,
                authorization_store=authorization, now=owner.NOW)
            assert token is not None
            experiment = action['experiment_identity_sha256']
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertEqual(experiment, decision['experiment_identity_sha256'])
            self.assertEqual(experiment, token['experiment_identity_sha256'])
            self.assertEqual(
                state['scientific']['assessment']['assessment_sha256'],
                token['scientific_assessment_sha256'])
            self.assertEqual(
                state['scientific']['commitment']['commitment_sha256'],
                token['scientific_commitment_sha256'])

            action_b = copy.deepcopy(action)
            action_b['experiment_identity_sha256'] = '9' * 64
            owner.seal(action_b, 'action_sha256')
            with self.assertRaisesRegex(ValueError, 'decision binding'):
                validate_authorization_token(
                    root, token, action=action_b, decision=decision,
                    current_state=returned,
                    kill_state={'state': 'DISENGAGED', 'generation': 2},
                    now=owner.NOW)

            changed_state = copy.deepcopy(returned)
            changed_state['scientific']['experiment_identity_sha256'] = '9' * 64
            owner.seal(changed_state, 'state_sha256')
            with self.assertRaisesRegex(ValueError, 'current_state_sha256'):
                validate_authorization_token(
                    root, token, action=action, decision=decision,
                    current_state=changed_state,
                    kill_state={'state': 'DISENGAGED', 'generation': 2},
                    now=owner.NOW)

            # A caller can make a self-consistent structural B wrapper because
            # tokens are hashes, not signatures. It is not the issued token and
            # therefore cannot pass the trusted-store execution boundary.
            decision_b = copy.deepcopy(decision)
            decision_b['action_sha256'] = action_b['action_sha256']
            decision_b['experiment_identity_sha256'] = '9' * 64
            owner.seal(decision_b, 'decision_sha256')
            token_b = copy.deepcopy(token)
            token_b['action_sha256'] = action_b['action_sha256']
            token_b['experiment_identity_sha256'] = '9' * 64
            token_b['decision_sha256'] = decision_b['decision_sha256']
            owner.seal(token_b, 'token_sha256')
            validate_authorization_token(
                root, token_b, action=action_b, decision=decision_b,
                current_state=returned,
                kill_state={'state': 'DISENGAGED', 'generation': 2},
                now=owner.NOW)
            with self.assertRaisesRegex(ValueError, 'not durably issued'):
                verify_execution_token(
                    root, token_b, action=action_b, decision=decision_b,
                    current_state=returned,
                    kill_state={'state': 'DISENGAGED', 'generation': 2},
                    authorization_store=authorization, now=owner.NOW)

            verify_execution_token(
                root, token, action=action, decision=decision,
                current_state=returned,
                kill_state={'state': 'DISENGAGED', 'generation': 2},
                authorization_store=authorization, now=owner.NOW)
            with self.assertRaisesRegex(ValueError, 'already consumed'):
                verify_execution_token(
                    root, token, action=action, decision=decision,
                    current_state=returned,
                    kill_state={'state': 'DISENGAGED', 'generation': 2},
                    authorization_store=authorization, now=owner.NOW)

    def _opening_and_reserve(self):
        opening = self.o.ledger_event(1, 'OPENING', amount=10000)
        action = self.o.action()
        binding = self.o.economic_binding(action)
        reserve = self.o.ledger_event(
            2, 'RESERVE', previous=opening['event_sha256'], amount=500,
            reservation='R-1', binding=binding)
        return opening, reserve, action, binding

    def test_SR08_wrapper_alias_version_and_bound_field_duplicates_reject(self):
        opening, reserve, _, original = self._opening_and_reserve()
        variants = {
            'reservation_wrapper': {},
            'action_wrapper': {'action_id': 'ACTION-2',
                               'action_sha256': 'f' * 64},
            'authorization_wrapper': {'authorization_sha256': '1' * 64},
            'event_alias': {'event_identity_sha256': '2' * 64},
            'market_alias': {'market_identity_sha256': '3' * 64},
            'selection_alias': {'selection_identity_sha256': '4' * 64},
            'amount': {'amount_minor': 600},
            'strategy': {'strategy_id': 'STRAT-2'},
            'strategy_version': {'strategy_version': 2},
            'experiment': {'experiment_identity_sha256': '5' * 64},
        }
        for label, changes in variants.items():
            binding = copy.deepcopy(original)
            amount = changes.pop('amount_minor', 500)
            binding.update(changes)
            if label != 'action_wrapper':
                binding['action_id'] = 'ACTION-' + label
                binding['action_sha256'] = digest(label.encode())
            binding['authorization_sha256'] = digest(
                ('authorization-' + label).encode())
            duplicate = self.o.ledger_event(
                3, 'RESERVE', previous=reserve['event_sha256'], amount=amount,
                reservation='R-' + label, binding=binding)
            events = [opening, reserve, duplicate]
            with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError, 'duplicate reservation'):
                replay_ledger(
                    ROOT, events, account='PAPER',
                    expected_opening_minor=10000,
                    current_head=history_head(
                        events, digest_field='event_sha256'), now=owner.NOW)

        versioned = copy.deepcopy(reserve)
        versioned.update({
            'schema_version': 2, 'event_id': 'PAPER-3-RESERVE-V2',
            'sequence': 3, 'reservation_id': 'R-V2',
            'previous_event_sha256': reserve['event_sha256']})
        owner.seal(versioned, 'event_sha256')
        with self.assertRaises(ValidationError):
            replay_ledger(
                ROOT, [opening, reserve, versioned], account='PAPER',
                expected_opening_minor=10000,
                current_head=history_head(
                    [opening, reserve, versioned],
                    digest_field='event_sha256'), now=owner.NOW)

        cross_account = copy.deepcopy(reserve)
        cross_account.update({
            'event_id': 'LIVE-3-RESERVE', 'sequence': 3, 'account': 'LIVE',
            'reservation_id': 'R-LIVE',
            'previous_event_sha256': reserve['event_sha256']})
        owner.seal(cross_account, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'account'):
            replay_ledger(
                ROOT, [opening, reserve, cross_account], account='PAPER',
                expected_opening_minor=10000,
                current_head=history_head(
                    [opening, reserve, cross_account],
                    digest_field='event_sha256'), now=owner.NOW)

    def test_SR08_release_settle_and_consumed_liability_recreation_reject(self):
        opening, reserve, action, binding = self._opening_and_reserve()
        wrapper_action = self.o.action(
            action_id='ACTION-WRAPPER', position_id=action['position_id'])
        wrapper_binding = self.o.economic_binding(wrapper_action)
        wrapper_binding['authorization_sha256'] = '1' * 64

        release = self.o.ledger_event(
            3, 'RELEASE', previous=reserve['event_sha256'], amount=500,
            reservation='R-1', binding=binding)
        release['liability_identity_sha256'] = reserve['liability_identity_sha256']
        release['economic_identity_sha256'] = reserve['economic_identity_sha256']
        owner.seal(release, 'event_sha256')
        after_release = self.o.ledger_event(
            4, 'RESERVE', previous=release['event_sha256'], amount=500,
            reservation='R-AFTER-RELEASE', binding=wrapper_binding)
        released = [opening, reserve, release, after_release]
        with self.assertRaisesRegex(ValueError, 'duplicate reservation'):
            replay_ledger(
                ROOT, released, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(
                    released, digest_field='event_sha256'), now=owner.NOW)

        alternate_settle = self.o.ledger_event(
            4, 'SETTLE', previous=release['event_sha256'], amount=500,
            reservation='R-1', settlement='S-ALT', returned=900,
            binding=wrapper_binding)
        after_release_settle = [opening, reserve, release, alternate_settle]
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay_ledger(
                ROOT, after_release_settle, account='PAPER',
                expected_opening_minor=10000,
                current_head=history_head(
                    after_release_settle, digest_field='event_sha256'),
                now=owner.NOW)

        settlement = self.o.ledger_event(
            3, 'SETTLE', previous=reserve['event_sha256'], amount=500,
            reservation='R-1', settlement='S-1', returned=900,
            binding=binding)
        settlement['liability_identity_sha256'] = (
            reserve['liability_identity_sha256'])
        settlement['economic_identity_sha256'] = reserve['economic_identity_sha256']
        owner.seal(settlement, 'event_sha256')
        after_settlement = self.o.ledger_event(
            4, 'RESERVE', previous=settlement['event_sha256'], amount=500,
            reservation='R-AFTER-SETTLE', binding=wrapper_binding)
        settled = [opening, reserve, settlement, after_settlement]
        with self.assertRaisesRegex(ValueError, 'duplicate reservation'):
            replay_ledger(
                ROOT, settled, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(
                    settled, digest_field='event_sha256'), now=owner.NOW)

        second_settlement = copy.deepcopy(settlement)
        second_settlement.update({
            'event_id': 'PAPER-4-SETTLE-ALT', 'sequence': 4,
            'settlement_id': 'S-2',
            'previous_event_sha256': settlement['event_sha256']})
        owner.seal(second_settlement, 'event_sha256')
        doubled = [opening, reserve, settlement, second_settlement]
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay_ledger(
                ROOT, doubled, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(
                    doubled, digest_field='event_sha256'), now=owner.NOW)

    def test_SR07_SR08_cross_layer_experiment_liability_chain_rejects(self):
        opening, reserve, action, binding = self._opening_and_reserve()
        experiment_b = '9' * 64
        changed = copy.deepcopy(binding)
        changed['action_id'] = 'ACTION-B'
        changed['action_sha256'] = 'f' * 64
        changed['authorization_sha256'] = '1' * 64
        changed['experiment_identity_sha256'] = experiment_b
        b_reserve = self.o.ledger_event(
            3, 'RESERVE', previous=reserve['event_sha256'], amount=500,
            reservation='R-B', binding=changed)
        attack = [opening, reserve, b_reserve]
        self.assertNotEqual(
            reserve['liability_identity_sha256'],
            b_reserve['liability_identity_sha256'])
        with self.assertRaisesRegex(ValueError, 'duplicate reservation'):
            replay_ledger(
                ROOT, attack, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(
                    attack, digest_field='event_sha256'), now=owner.NOW)

        retained_liability = copy.deepcopy(b_reserve)
        retained_liability['liability_identity_sha256'] = (
            reserve['liability_identity_sha256'])
        owner.seal(retained_liability, 'event_sha256')
        retained = [opening, reserve, retained_liability]
        with self.assertRaisesRegex(ValueError, 'semantic liability'):
            replay_ledger(
                ROOT, retained, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(
                    retained, digest_field='event_sha256'), now=owner.NOW)

        settlement_action = self.o.action(
            action_type='SETTLEMENT', amount=500,
            experiment_identity_sha256=experiment_b,
            related=reserve['action_sha256'], reservation='R-1')
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            _, state = self.o.settlement_state(root)
            state['action_sha256'] = settlement_action['action_sha256']
            owner.seal(state, 'state_sha256')
            authorization_path = Path(directory) / 'authorization.json'
            JsonAuthorizationStore.initialize(
                authorization_path, authority_id='RISK-STATE-1', generation=4)
            decision, token, _ = assemble_authoritative_decision(
                root, settlement_action,
                authority=owner.StaticRiskAuthority(
                    state, settlement_action),
                policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None,
                authorization_store=JsonAuthorizationStore(
                    authorization_path), now=owner.NOW)
            self.assertEqual(decision['verdict'], 'DENIED')
            self.assertIn(
                'SETTLEMENT_RESERVATION_BINDING_INVALID', decision['reasons'])
            self.assertIsNone(token)

    def test_SR08_distinct_positions_reserve_independently(self):
        opening = self.o.ledger_event(1, 'OPENING', amount=10000)
        first_action = self.o.action()
        first = self.o.ledger_event(
            2, 'RESERVE', previous=opening['event_sha256'], amount=500,
            reservation='R-1', binding=self.o.economic_binding(first_action))
        second_action = self.o.action(
            action_id='ACTION-2', position_id='POSITION-2')
        second_binding = self.o.economic_binding(second_action)
        second_binding['authorization_sha256'] = '1' * 64
        second = self.o.ledger_event(
            3, 'RESERVE', previous=first['event_sha256'], amount=500,
            reservation='R-2', binding=second_binding)
        events = [opening, first, second]
        result = replay_ledger(
            ROOT, events, account='PAPER', expected_opening_minor=10000,
            current_head=history_head(events, digest_field='event_sha256'),
            now=owner.NOW)
        self.assertNotEqual(
            first['liability_identity_sha256'],
            second['liability_identity_sha256'])
        self.assertEqual(result['reserved_minor'], 1000)
        self.assertEqual(result['open_reservations'], ['R-1', 'R-2'])

    def test_positive_paper_and_actual_M0_live_separation_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            decision, token, _ = self._assemble(root, action, state, directory)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertTrue(decision['paper_eligible'])
            self.assertFalse(decision['live_eligible'])
            self.assertIsNotNone(token)

        action, state = self.o.m0_live_state()
        decision, token, _ = assemble_authoritative_decision(
            ROOT, action,
            authority=owner.StaticRiskAuthority(state, action),
            policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            scientific_replay_store=None, authorization_store=None,
            now=owner.NOW)
        self.assertEqual(decision['verdict'], 'DENIED')
        self.assertFalse(decision['live_eligible'])
        self.assertFalse(decision['capital_available'])
        self.assertIsNone(token)


if __name__ == '__main__':
    unittest.main()
