"""Independent valid-prerequisite successor probes for Risk SR01--SR06."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

import test_risk_controls as owner
from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import claim_identity, commitment_digest
from src.edgelab.risk_controls import (
    JsonAuthorizationStore,
    JsonReplayStore,
    assemble_authoritative_decision,
    evaluate_exposure,
    evaluate_stop_snapshot,
    history_head,
    replay_kill_switch,
    replay_ledger,
    replay_lifecycle,
    risk_decision,
    validate_authorization_token,
    verify_execution_token,
)
from src.edgelab.validate import ROOT


class SkepticRiskV2Tests(unittest.TestCase):
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

    def test_SR01_legacy_assertions_missing_authority_and_fixed_state_substitution_deny(self):
        forged = risk_decision(
            ROOT, decision_id='FORGED', decided_at='2026-09-28T00:00:00Z',
            action='NEW_EXPOSURE', environment='LIVE',
            scientific={'scientific_integrity_consistent': True},
            lifecycle={'lifecycle_eligible': True}, stop={'decision': 'ALLOW'},
            ledger={'reconciled': True}, exposure={'decision': 'ALLOW'},
            kill={'state': 'DISENGAGED'}, capital_deployable_minor=100000,
            live_status='UNLOCKED', individual_authorization_current=True,
            phase='M1')
        self.assertEqual(forged['verdict'], 'DENIED')

        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            replay, authorization = self._stores(directory)
            with self.assertRaisesRegex(ValueError, 'authority'):
                assemble_authoritative_decision(
                    root, action, authority=None, policy=self.o.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    scientific_replay_store=replay,
                    authorization_store=authorization, now=owner.NOW)

            substituted = copy.deepcopy(state)
            substituted['project_state']['path'] = 'portfolio/bankroll.json'
            owner.seal(substituted, 'state_sha256')
            with self.assertRaisesRegex(ValueError, 'fixed-state'):
                assemble_authoritative_decision(
                    root, action,
                    authority=owner.StaticRiskAuthority(substituted, action),
                    policy=self.o.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    scientific_replay_store=replay,
                    authorization_store=authorization, now=owner.NOW)

    def test_SR01_different_experiment_can_authorize_same_strategy_version(self):
        """Characterize SR07: experiment identity is absent from action/token."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            original_experiment = state['scientific']['experiment_identity_sha256']
            other_experiment = '9' * 64
            self.assertNotEqual(original_experiment, other_experiment)

            assessment = state['scientific']['assessment']
            commitment = state['scientific']['commitment']
            assessment['experiment_identity_sha256'] = other_experiment
            assessment['assessment_sha256'] = digest(canonical({
                key: value for key, value in assessment.items()
                if key != 'assessment_sha256'}))
            commitment['assessment_sha256'] = assessment['assessment_sha256']
            commitment['experiment_identity_sha256'] = other_experiment
            commitment['claim_identity_sha256'] = claim_identity(assessment)
            commitment['commitment_sha256'] = commitment_digest(commitment)
            state['scientific']['experiment_identity_sha256'] = other_experiment
            owner.seal(state, 'state_sha256')

            decision, token, _ = self._assemble(
                root, action, state, directory)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertTrue(decision['execution_authorized'])
            self.assertIsNotNone(token)
            self.assertNotIn('experiment_identity_sha256', action)
            self.assertNotIn('experiment_identity_sha256', token)

    def test_SR01_exact_action_token_rejects_mutation_and_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.settlement_state(root)
            authorization_path = Path(directory) / 'authorization.json'
            JsonAuthorizationStore.initialize(
                authorization_path, authority_id='RISK-STATE-1', generation=4)
            authorization = JsonAuthorizationStore(authorization_path)
            decision, token, returned = assemble_authoritative_decision(
                root, action,
                authority=owner.StaticRiskAuthority(state, action),
                policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None,
                authorization_store=authorization, now=owner.NOW)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            assert token is not None

            for field, value in (
                    ('action_id', 'OTHER'), ('amount_minor', 499),
                    ('environment', 'LIVE'), ('strategy_version', 2),
                    ('event_identity_sha256', '1' * 64),
                    ('market_identity_sha256', '2' * 64),
                    ('selection_identity_sha256', '3' * 64),
                    ('position_id', 'OTHER-POSITION'),
                    ('reservation_id', 'OTHER-RESERVATION')):
                changed = copy.deepcopy(action)
                changed[field] = value
                owner.seal(changed, 'action_sha256')
                with self.subTest(field=field), self.assertRaisesRegex(
                        ValueError, 'binding'):
                    validate_authorization_token(
                        root, token, action=changed, decision=decision,
                        current_state=returned,
                        kill_state={'state': 'ENGAGED', 'generation': 1},
                        now=owner.NOW)

            verify_execution_token(
                root, token, action=action, decision=decision,
                current_state=returned,
                kill_state={'state': 'ENGAGED', 'generation': 1},
                authorization_store=authorization, now=owner.NOW)
            with self.assertRaisesRegex(ValueError, 'already consumed'):
                verify_execution_token(
                    root, token, action=action, decision=decision,
                    current_state=returned,
                    kill_state={'state': 'ENGAGED', 'generation': 1},
                    authorization_store=authorization, now=owner.NOW)

    def test_SR02_lifecycle_ledger_and_kill_valid_prefixes_reject(self):
        lifecycle, approvals = self.o.lifecycle()
        terminal = copy.deepcopy(lifecycle[-1])
        terminal.update({
            'event_id': 'LE-9', 'sequence': 9,
            'from_state': 'PAPER_TRADING', 'to_state': 'REJECTED',
            'occurred_at': '2026-09-27T09:00:00Z', 'approval_ids': [],
            'trigger_refs': [],
            'previous_event_sha256': lifecycle[-1]['event_sha256']})
        owner.seal(terminal, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_lifecycle(
                ROOT, lifecycle, approvals, policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'},
                scientific_evidence=self.o.scientific_result(),
                current_head=history_head(
                    [*lifecycle, terminal], digest_field='event_sha256'),
                now=owner.NOW)

        ledger = self.o.ledger()
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_ledger(
                ROOT, ledger[:2], account='PAPER',
                expected_opening_minor=10000,
                current_head=history_head(ledger, digest_field='event_sha256'),
                now=owner.NOW)

        initial = self.o.kill_event(1, 'INITIAL_ENGAGE', 1)
        reset = self.o.kill_event(
            2, 'RESET', 2, previous=initial['event_sha256'], phase='M1')
        trigger = self.o.kill_event(
            3, 'TRIGGER', 3, previous=reset['event_sha256'], phase='M1',
            trigger='APPLICABLE_STOP')
        approval = self.o.attestation(
            identifier='RISK-A', alias='risk@example', role='06_RISK',
            subject_type='KILL_SWITCH_RESET', subject_id=reset['event_id'],
            subject_sha=reset['event_sha256'], scope='KILL_RESET')
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_kill_switch(
                ROOT, [initial, reset], policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                attestations=[approval], stop_decision={'decision': 'ALLOW'},
                health_ok=True,
                current_head=history_head(
                    [initial, reset, trigger], digest_field='event_sha256'),
                now=owner.NOW)

    def test_SR03_and_SR04_conflicted_authority_and_stop_relabel_reject(self):
        events, approvals = self.o.lifecycle()
        conflicted = self.o.policy()
        conflicted['actors'][3]['conflicts'] = ['risk']
        conflicted['actors'][4]['conflicts'] = ['skeptic']
        with self.assertRaisesRegex(ValueError, 'conflict'):
            replay_lifecycle(
                ROOT, events, approvals, policy=conflicted,
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'},
                scientific_evidence=self.o.scientific_result(),
                current_head=history_head(events, digest_field='event_sha256'),
                now=owner.NOW)

        action = self.o.action()
        snapshot = self.o.stop_snapshot()
        result = evaluate_stop_snapshot(
            ROOT, snapshot, action=action,
            dependency_graph=self.o.action_graph(action),
            stop_policy=self.o.stop_policy(),
            current_head=self.o.stop_head(snapshot), now=owner.NOW)
        self.assertEqual(result['decision'], 'DENY')
        omitted = copy.deepcopy(snapshot)
        omitted['stops'] = []
        with self.assertRaisesRegex(ValueError, 'inventory'):
            evaluate_stop_snapshot(
                ROOT, omitted, action=action,
                dependency_graph=self.o.action_graph(action),
                stop_policy=self.o.stop_policy(),
                current_head=self.o.stop_head(snapshot), now=owner.NOW)

    def test_SR05_pending_open_alias_versions_aggregate_and_unknown_denies(self):
        identities = self.o.identities()
        version_two = []
        for identity in identities:
            newer = copy.deepcopy(identity)
            newer['version'] = 2
            newer['aliases'] = ['renamed-' + identity['canonical_id']]
            owner.seal(newer, 'identity_sha256')
            version_two.append(newer)
        pending = self.o.position('PENDING', 400, status='PENDING')
        opened = self.o.position('OPEN', 400, status='OPEN')
        request = self.o.position('REQUEST', 300, status='PENDING')
        for field, namespace in (
                ('strategy_identity_sha256', 'strategy'),
                ('source_identity_sha256', 'source'),
                ('event_identity_sha256', 'event'),
                ('market_identity_sha256', 'market'),
                ('selection_identity_sha256', 'selection')):
            request[field] = next(
                item['identity_sha256'] for item in version_two
                if item['namespace'] == namespace)
        owner.seal(request, 'position_sha256')
        limits = self.o.limits(1000)
        limits['daily_exposure_minor'] = 5000
        result = evaluate_exposure(
            ROOT, [pending, opened], request, environment='PAPER', limits=limits,
            current_head=history_head(
                [pending, opened], digest_field='position_sha256'),
            canonical_identities=[*identities, *version_two])
        self.assertEqual(result['decision'], 'DENY')
        self.assertEqual(result['checks_minor']['event_exposure_minor'], 1100)

        unknown = copy.deepcopy([*identities, *version_two])
        unknown[-3]['status'] = 'UNKNOWN'
        owner.seal(unknown[-3], 'identity_sha256')
        request['event_identity_sha256'] = unknown[-3]['identity_sha256']
        owner.seal(request, 'position_sha256')
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            evaluate_exposure(
                ROOT, [], request, environment='PAPER',
                limits=self.o.limits(5000),
                current_head=history_head([], digest_field='position_sha256'),
                canonical_identities=unknown)

    def test_SR06_exact_settlement_mutations_and_release_then_settle_reject(self):
        events = self.o.ledger()
        for field, value in (
                ('amount_minor', 501), ('action_id', 'OTHER'),
                ('position_id', 'OTHER-POSITION'), ('strategy_version', 2),
                ('event_identity_sha256', 'f' * 64),
                ('market_identity_sha256', '1' * 64),
                ('selection_identity_sha256', '2' * 64),
                ('authorization_sha256', '3' * 64)):
            changed = copy.deepcopy(events)
            changed[2][field] = value
            owner.seal(changed[2], 'event_sha256')
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, 'settlement'):
                replay_ledger(
                    ROOT, changed, account='PAPER',
                    expected_opening_minor=10000,
                    current_head=history_head(
                        changed, digest_field='event_sha256'), now=owner.NOW)

        opening, reservation = copy.deepcopy(events[:2])
        binding = self.o.economic_binding()
        release = self.o.ledger_event(
            3, 'RELEASE', previous=reservation['event_sha256'], amount=500,
            reservation='R-1', binding=binding)
        release['economic_identity_sha256'] = reservation['economic_identity_sha256']
        owner.seal(release, 'event_sha256')
        settlement = self.o.ledger_event(
            4, 'SETTLE', previous=release['event_sha256'], amount=500,
            reservation='R-1', settlement='S-2', returned=900,
            binding=binding)
        settlement['economic_identity_sha256'] = reservation['economic_identity_sha256']
        owner.seal(settlement, 'event_sha256')
        attack = [opening, reservation, release, settlement]
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay_ledger(
                ROOT, attack, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(attack, digest_field='event_sha256'),
                now=owner.NOW)

    def test_SR06_same_liability_under_new_wrapper_is_reserved_twice(self):
        """Characterize SR08: reservation idempotency is action-digest based."""
        opening = self.o.ledger_event(1, 'OPENING', amount=10000)
        first_binding = self.o.economic_binding()
        first = self.o.ledger_event(
            2, 'RESERVE', previous=opening['event_sha256'], amount=500,
            reservation='R-1', binding=first_binding)
        second_binding = copy.deepcopy(first_binding)
        second_binding.update({
            'action_id': 'ACTION-2', 'action_sha256': 'f' * 64,
            'authorization_sha256': '1' * 64})
        second = self.o.ledger_event(
            3, 'RESERVE', previous=first['event_sha256'], amount=500,
            reservation='R-2', binding=second_binding)
        events = [opening, first, second]
        result = replay_ledger(
            ROOT, events, account='PAPER', expected_opening_minor=10000,
            current_head=history_head(events, digest_field='event_sha256'),
            now=owner.NOW)
        self.assertEqual(first['position_id'], second['position_id'])
        self.assertEqual(first['strategy_identity_sha256'],
                         second['strategy_identity_sha256'])
        self.assertEqual(first['event_identity_sha256'],
                         second['event_identity_sha256'])
        self.assertEqual(first['market_identity_sha256'],
                         second['market_identity_sha256'])
        self.assertEqual(first['selection_identity_sha256'],
                         second['selection_identity_sha256'])
        self.assertEqual(result['reserved_minor'], 1000)
        self.assertEqual(result['liability_minor'], 1000)
        self.assertEqual(result['open_reservations'], ['R-1', 'R-2'])

    def test_positive_paper_and_neutral_settlement_work_but_actual_M0_live_denies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.o.synthetic_root(directory)
            action, state = self.o.new_exposure_state(root)
            decision, token, _ = self._assemble(root, action, state, directory)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertTrue(decision['scientific_consistent'])
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

        self.assertTrue(owner.settlement_allowed_while_engaged(
            adds_exposure=False, reservation_exists=True))

    def test_actual_M0_live_new_exposure_fails_closed_on_authoritative_zero_limits(self):
        action = self.o.action(environment='LIVE')
        opening = self.o.ledger_event(
            1, 'OPENING', amount=0, account='LIVE')
        ledger_events = [opening]
        ledger_state = replay_ledger(
            ROOT, ledger_events, account='LIVE', expected_opening_minor=0,
            current_head=history_head(
                ledger_events, digest_field='event_sha256'), now=owner.NOW)
        snapshot = owner.seal({
            'schema_version': 1, **ledger_state,
            'as_of': '2026-09-27T23:50:00Z',
            'valid_until': '2026-09-28T00:10:00Z'}, 'snapshot_sha256')
        stop_snapshot = self.o.stop_snapshot()
        kill_events = [self.o.kill_event(1, 'INITIAL_ENGAGE', 1)]
        lifecycle_events, lifecycle_approvals = self.o.lifecycle()
        assessment, commitment = self.o.assessment_commitment()
        request = self.o.position(
            'POSITION-1', 500, environment='LIVE', status='PENDING')
        request['action_sha256'] = action['action_sha256']
        owner.seal(request, 'position_sha256')
        state = {
            'schema_version': 1, 'authority_id': 'RISK-STATE-1',
            'generation': 4, 'decision_id': 'M0-LIVE-NEW-EXPOSURE',
            'generated_at': '2026-09-27T23:59:00Z',
            'valid_until': '2026-09-28T00:06:00Z',
            'action_sha256': action['action_sha256'], 'phase': 'M0',
            'project_state': {
                'path': 'docs/project-state.json',
                'sha256': digest((ROOT / 'docs/project-state.json').read_bytes())},
            'bankroll': {
                'path': 'portfolio/bankroll.json',
                'sha256': digest((ROOT / 'portfolio/bankroll.json').read_bytes())},
            'risk_policy': {
                'path': 'portfolio/risk-policy.json',
                'sha256': digest((ROOT / 'portfolio/risk-policy.json').read_bytes())},
            'scientific': {
                'assessment': assessment, 'commitment': commitment,
                'assessment_author_ids': ['research'],
                'strategy_id': 'STRAT-1', 'strategy_version': 1,
                'experiment_identity_sha256':
                    assessment['experiment_identity_sha256']},
            'lifecycle': {
                'events': lifecycle_events,
                'attestations': lifecycle_approvals,
                'head': history_head(
                    lifecycle_events, digest_field='event_sha256')},
            'stop': {
                'snapshot': stop_snapshot, 'policy': self.o.stop_policy(),
                'head': self.o.stop_head(stop_snapshot),
                'dependency_graph': {
                    key: [] for key in self.o.action_graph(action)}},
            'ledger': {
                'events': ledger_events, 'snapshot': snapshot,
                'head': history_head(
                    ledger_events, digest_field='event_sha256'),
                'opening_minor': 0},
            'exposure': {
                'positions': [],
                'head': history_head([], digest_field='position_sha256'),
                'canonical_identities': self.o.identities(),
                'limits': self.o.limits(0), 'request': request},
            'kill': {
                'events': kill_events, 'attestations': [],
                'head': history_head(
                    kill_events, digest_field='event_sha256'),
                'health_ok': True}}
        owner.seal(state, 'state_sha256')
        with tempfile.TemporaryDirectory() as directory:
            replay, authorization = self._stores(directory)
            with self.assertRaisesRegex(
                    ValueError, 'Unresolved live exposure limits deny'):
                assemble_authoritative_decision(
                    ROOT, action,
                    authority=owner.StaticRiskAuthority(state, action),
                    policy=self.o.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    scientific_replay_store=replay,
                    authorization_store=authorization, now=owner.NOW)


if __name__ == '__main__':
    unittest.main()
