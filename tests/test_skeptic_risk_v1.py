"""Independent Skeptic attacks against the bounded M0 Risk controls."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from jsonschema import ValidationError

import test_risk_controls as owner
from src.edgelab.data_integrity import canonical, digest
from src.edgelab.risk_controls import (
    JsonReplayStore,
    consume_scientific_commitment,
    evaluate_exposure,
    evaluate_stop_snapshot,
    reconcile_ledger,
    replay_kill_switch,
    replay_ledger,
    replay_lifecycle,
    risk_decision,
    settlement_allowed_while_engaged,
    transition_subject,
    validate_stop_clearance,
    validate_trust_policy,
    verify_attestation,
    verify_execution_token,
)
from src.edgelab.validate import ROOT, read


class SkepticRiskV1Tests(unittest.TestCase):
    def setUp(self):
        self.o = owner.RiskControlTests()

    def _replay_path(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'replay.json'
        JsonReplayStore.initialize(
            path, policy_id='POLICY-1', policy_generation=7,
            authority_generations={'AUTH-1': 3})
        return path

    def _positive_decision_arguments(self, environment='PAPER'):
        return dict(
            decision_id='SKEPTIC-FORGED-DECISION',
            decided_at='2026-09-28T00:00:00Z', action='NEW_EXPOSURE',
            environment=environment,
            scientific={'scientific_integrity_consistent': True},
            lifecycle={'lifecycle_eligible': True},
            stop={'decision': 'ALLOW'}, ledger={'reconciled': True},
            exposure={'decision': 'ALLOW'}, kill={'state': 'DISENGAGED'},
            capital_deployable_minor=1000, live_status='UNLOCKED',
            individual_authorization_current=True,
        )

    def test_R01_decision_accepts_unbound_assertions_and_phase_substitution(self):
        paper = risk_decision(
            ROOT, **self._positive_decision_arguments(), phase='M0')
        self.assertEqual((paper['verdict'], paper['execution_authorized']),
                         ('AUTHORIZED', True))

        live = risk_decision(
            ROOT, **self._positive_decision_arguments('LIVE'), phase='M1')
        self.assertEqual((live['verdict'], live['execution_authorized']),
                         ('AUTHORIZED', True))
        self.assertTrue(live['capital_available'])
        self.assertTrue(live['live_eligible'])

    def test_R01_execution_token_has_no_action_subject_or_amount_binding(self):
        kill_state = {'state': 'DISENGAGED', 'generation': 9}
        token = {'kill_generation': 9, 'controls_sha256': owner.SHA}
        self.assertIsNone(verify_execution_token(
            token, kill_state=kill_state,
            current_controls_sha256=owner.SHA))
        # The same object verifies again because no action, amount, strategy,
        # event, environment, identity, expiry, token ID, or consumption state
        # exists in this interface.
        self.assertIsNone(verify_execution_token(
            token, kill_state=kill_state,
            current_controls_sha256=owner.SHA))

    def test_R02_lifecycle_accepts_unconsumed_science_and_unbound_stop_allow(self):
        events, approvals = self.o.lifecycle()
        result = replay_lifecycle(
            ROOT, events, approvals, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence={'scientific_integrity_consistent': True},
            now=owner.NOW)
        self.assertEqual(result['state'], 'PAPER_TRADING')
        self.assertTrue(result['paper_eligible'])

    def test_R02_lifecycle_prefix_rollback_restores_terminal_strategy(self):
        events, approvals = self.o.lifecycle()
        terminal = copy.deepcopy(events[-1])
        terminal.update({
            'event_id': 'LE-9', 'sequence': 9,
            'occurred_at': '2026-09-27T09:00:00Z',
            'from_state': 'PAPER_TRADING', 'to_state': 'REJECTED',
            'approval_ids': [], 'trigger_refs': [],
            'previous_event_sha256': events[-1]['event_sha256'],
        })
        owner.seal(terminal, 'event_sha256')
        full = replay_lifecycle(
            ROOT, [*events, terminal], approvals, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence={'scientific_integrity_consistent': True},
            now=owner.NOW)
        rolled_back = replay_lifecycle(
            ROOT, events, approvals, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence={'scientific_integrity_consistent': True},
            now=owner.NOW)
        self.assertEqual(full['state'], 'REJECTED')
        self.assertEqual(rolled_back['state'], 'PAPER_TRADING')
        self.assertTrue(rolled_back['lifecycle_eligible'])

    def test_R03_conflicted_approvers_are_counted_as_independent(self):
        policy = self.o.policy()
        actors = {actor['actor_id']: actor for actor in policy['actors']}
        actors['skeptic']['conflicts'] = ['risk']
        actors['risk']['conflicts'] = ['skeptic']
        events, approvals = self.o.lifecycle(through='PAPER_ELIGIBLE')
        result = replay_lifecycle(
            ROOT, events, approvals, policy=policy,
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence={'scientific_integrity_consistent': True},
            now=owner.NOW)
        self.assertEqual(result['state'], 'PAPER_ELIGIBLE')
        self.assertTrue(result['paper_eligible'])

    def test_R04_revoked_scientific_authority_is_accepted(self):
        assessment, commitment = self.o.assessment_commitment()
        policy = self.o.policy()
        actors = {actor['actor_id']: actor for actor in policy['actors']}
        actors['quant']['revoked_at'] = '2026-09-27T23:00:00Z'
        actors['risk']['authorities'] = [
            {'authority_id': 'OTHER-AUTHORITY', 'generation': 1}]
        result = consume_scientific_commitment(
            ROOT, assessment, commitment, policy=policy,
            expected_policy_source='synthetic-verifier://risk-tests',
            replay_store=JsonReplayStore(self._replay_path()), now=owner.NOW)
        self.assertEqual(result['status'], 'SCIENTIFIC_EVIDENCE_CONSUMED')
        self.assertEqual(result['authority_actor_id'], 'quant')

    def test_R04_omitted_authorship_inventory_accepts_self_issued_science(self):
        assessment, commitment = self.o.assessment_commitment()
        result = consume_scientific_commitment(
            ROOT, assessment, commitment, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            replay_store=JsonReplayStore(self._replay_path()),
            assessment_author_ids=None, now=owner.NOW)
        self.assertEqual(result['authority_actor_id'], 'quant')

    def test_authority_alias_source_role_scope_and_generation_defenses_hold(self):
        policy = self.o.policy()
        collision = copy.deepcopy(policy)
        collision['actors'][2]['aliases'].append('research@example')
        with self.assertRaisesRegex(ValueError, 'Alias maps'):
            validate_trust_policy(
                ROOT, collision,
                expected_source='synthetic-verifier://risk-tests', now=owner.NOW)
        with self.assertRaisesRegex(ValueError, 'verifier-selected source'):
            validate_trust_policy(
                ROOT, policy, expected_source='different-source', now=owner.NOW)

        attestation = self.o.attestation(
            identifier='AUTH-DEFENSE', alias='data@example', role='01_DATA',
            subject_type='LIFECYCLE_TRANSITION', subject_id='SUBJECT',
            subject_sha=owner.SHA, scope='LIFECYCLE_APPROVE')
        with self.assertRaisesRegex(ValueError, 'role or scope'):
            verify_attestation(
                ROOT, attestation, policy,
                expected_subject_type='LIFECYCLE_TRANSITION',
                expected_subject_id='SUBJECT', expected_subject_sha256=owner.SHA,
                required_role='06_RISK', required_scope='LIFECYCLE_APPROVE',
                now=owner.NOW)
        stale = {**attestation, 'policy_generation': 6}
        owner.seal(stale, 'attestation_sha256')
        with self.assertRaisesRegex(ValueError, 'stale|substituted'):
            verify_attestation(
                ROOT, stale, policy,
                expected_subject_type='LIFECYCLE_TRANSITION',
                expected_subject_id='SUBJECT', expected_subject_sha256=owner.SHA,
                required_role='01_DATA', required_scope='LIFECYCLE_APPROVE',
                now=owner.NOW)

    def test_replay_store_persists_id_and_digest_uniqueness_across_reload(self):
        assessment, commitment = self.o.assessment_commitment()
        path = self._replay_path()
        consume_scientific_commitment(
            ROOT, assessment, commitment, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            replay_store=JsonReplayStore(path), now=owner.NOW)
        with self.assertRaisesRegex(ValueError, 'replay|duplicate'):
            consume_scientific_commitment(
                ROOT, assessment, commitment, policy=self.o.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                replay_store=JsonReplayStore(path), now=owner.NOW)

    def test_replay_store_serializes_local_double_consumption(self):
        assessment, commitment = self.o.assessment_commitment()
        path = self._replay_path()

        def consume():
            try:
                result = consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=self.o.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path), now=owner.NOW)
                return result['status']
            except ValueError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: consume(), range(2)))
        self.assertEqual(outcomes.count('SCIENTIFIC_EVIDENCE_CONSUMED'), 1)
        self.assertEqual(sum('replay' in item or 'duplicate' in item
                             for item in outcomes), 1)

    def test_replay_store_rollback_is_possible_to_host_that_can_replace_state(self):
        assessment, commitment = self.o.assessment_commitment()
        path = self._replay_path()
        pristine = path.read_bytes()
        first = consume_scientific_commitment(
            ROOT, assessment, commitment, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            replay_store=JsonReplayStore(path), now=owner.NOW)
        path.write_bytes(pristine)
        second = consume_scientific_commitment(
            ROOT, assessment, commitment, policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            replay_store=JsonReplayStore(path), now=owner.NOW)
        self.assertEqual(first['commitment_receipt']['commitment_id'],
                         second['commitment_receipt']['commitment_id'])

    def test_R05_real_open_stop_can_be_relabeled_to_nonapplicable_action(self):
        snapshot = self.o.stop_snapshot()
        snapshot['stops'][0]['actions'] = ['UNRELATED_ACTION']
        decision = evaluate_stop_snapshot(
            ROOT, snapshot, action='NEW_EXPOSURE', targets={'strategy:1'},
            dependency_graph={'strategy:1': set()},
            expected_stop_refs={'reports/stops/STOP-M0-001.v1.json'},
            now=owner.NOW)
        self.assertEqual(decision['decision'], 'ALLOW')

    def test_R05_future_fake_clearance_self_selects_only_friendly_role(self):
        stop = read(ROOT / 'reports/stops/STOP-M0-001.v1.json')
        resolution = owner.seal({
            'schema_version': 1, 'event_id': 'SKEPTIC-FAKE-CLEAR',
            'stop_id': stop['id'], 'stop_version': stop['version'],
            'stop_sha256': digest(canonical(stop)),
            'occurred_at': '2999-01-01T00:00:00Z',
            'acknowledged': True, 'remediation_evidence': [owner.SHA],
            'descendants_revalidated': True,
            'required_roles': ['03_RESEARCH'], 'capital_implicated': False,
            'remediation_author_actor_ids': ['data'],
        }, 'event_sha256')
        approval = self.o.attestation(
            identifier='FRIENDLY-CLEAR', alias='research@example',
            role='03_RESEARCH', subject_type='STOP_RESOLUTION',
            subject_id=resolution['event_id'],
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR')
        result = validate_stop_clearance(
            ROOT, stop, resolution, [approval], policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            now=owner.NOW)
        self.assertTrue(result['clearance_eligible'])

    def test_stop_dependency_propagation_and_content_binding_hold(self):
        snapshot = self.o.stop_snapshot()
        snapshot['stops'][0]['scope'] = {
            'kind': 'records', 'targets': ['dataset:contaminated']}
        decision = evaluate_stop_snapshot(
            ROOT, snapshot, action='NEW_EXPOSURE', targets={'strategy:dependent'},
            dependency_graph={
                'dataset:contaminated': set(),
                'strategy:dependent': {'dataset:contaminated'},
            },
            expected_stop_refs={'reports/stops/STOP-M0-001.v1.json'},
            now=owner.NOW)
        self.assertEqual(decision['decision'], 'DENY')
        changed = copy.deepcopy(snapshot)
        changed['stops'][0]['stop_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            evaluate_stop_snapshot(
                ROOT, changed, action='NEW_EXPOSURE',
                targets={'strategy:dependent'},
                dependency_graph={
                    'dataset:contaminated': set(),
                    'strategy:dependent': {'dataset:contaminated'},
                },
                expected_stop_refs={'reports/stops/STOP-M0-001.v1.json'},
                now=owner.NOW)

    def test_R06_truncated_ledger_prefix_reconciles_as_current(self):
        full = self.o.ledger()
        full_state = replay_ledger(
            ROOT, full, account='PAPER', expected_opening_minor=10000,
            now=owner.NOW)
        prefix = full[:2]
        prefix_state = replay_ledger(
            ROOT, prefix, account='PAPER', expected_opening_minor=10000,
            now=owner.NOW)
        snapshot = owner.seal({
            'schema_version': 1, **prefix_state,
            'as_of': '2026-09-27T23:50:00Z',
            'valid_until': '2026-09-28T00:10:00Z',
        }, 'snapshot_sha256')
        accepted = reconcile_ledger(
            ROOT, prefix, snapshot, account='PAPER',
            expected_opening_minor=10000, now=owner.NOW)
        self.assertTrue(accepted['reconciled'])
        self.assertNotEqual(accepted['last_event_sha256'],
                            full_state['last_event_sha256'])

    def test_R06_reservation_and_settlement_have_no_action_binding(self):
        event = self.o.ledger()[1]
        self.assertNotIn('action_id', event)
        self.assertNotIn('position_id', event)
        self.assertNotIn('strategy_id', event)
        self.assertNotIn('environment_subject_sha256', event)

    def test_R07_pending_exposures_are_excluded_from_aggregation(self):
        existing = {**self.o.position('PENDING-1', 600), 'status': 'PENDING'}
        request = {**self.o.position('PENDING-2', 600), 'status': 'PENDING'}
        limits = self.o.limits(1000)
        limits['daily_exposure_minor'] = 5000
        result = evaluate_exposure(
            ROOT, [existing], request, environment='PAPER', limits=limits)
        self.assertEqual(result['decision'], 'ALLOW')
        self.assertEqual(result['checks_minor']['event_exposure_minor'], 600)

    def test_R07_cosmetic_identity_renaming_bypasses_shared_risk_limits(self):
        existing = self.o.position('OPEN-1', 600)
        request = self.o.position(
            'OPEN-2', 600, source='SRC-ALIAS', event='EV-ALIAS',
            selection='HOME')
        request['strategy_id'] = 'STRAT-ALIAS'
        request['market_id'] = 'MKT-ALIAS'
        request['correlation_keys'] = [
            'event:EV-ALIAS', 'strategy:STRAT-ALIAS',
            'source:SRC-ALIAS', 'market:MKT-ALIAS',
            'selection:EV-ALIAS:HOME',
        ]
        limits = self.o.limits(1000)
        limits['daily_exposure_minor'] = 5000
        result = evaluate_exposure(
            ROOT, [existing], request, environment='PAPER', limits=limits)
        self.assertEqual(result['decision'], 'ALLOW')
        self.assertNotIn('event_exposure_minor', result['breaches'])
        self.assertNotIn('correlated_exposure_minor', result['breaches'])

    def test_exposure_missing_keys_cross_environment_and_unresolved_live_deny(self):
        request = self.o.position('REQUEST', 100)
        missing = copy.deepcopy(request)
        missing['correlation_keys'].remove('event:EV-1')
        with self.assertRaises(ValidationError):
            evaluate_exposure(
                ROOT, [], missing, environment='PAPER', limits=self.o.limits())
        with self.assertRaisesRegex(ValueError, 'Mixed environment'):
            evaluate_exposure(
                ROOT, [], request, environment='LIVE', limits=self.o.limits())
        live = {**request, 'environment': 'LIVE'}
        limits = self.o.limits()
        limits['position_minor'] = None
        with self.assertRaisesRegex(ValueError, 'Unresolved live'):
            evaluate_exposure(
                ROOT, [], live, environment='LIVE', limits=limits)

    def test_R08_kill_history_prefix_reenables_stale_execution_token(self):
        initial = self.o.kill_event(1, 'INITIAL_ENGAGE', 1)
        reset = self.o.kill_event(
            2, 'RESET', 2, previous=initial['event_sha256'], phase='M1')
        approval = self.o.attestation(
            identifier='RISK-A', alias='risk@example', role='06_RISK',
            subject_type='KILL_SWITCH_RESET', subject_id=reset['event_id'],
            subject_sha=reset['event_sha256'], scope='KILL_RESET')
        trigger = self.o.kill_event(
            3, 'TRIGGER', 3, previous=reset['event_sha256'], phase='M1',
            trigger='APPLICABLE_STOP')
        arguments = dict(
            policy=self.o.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            attestations=[approval], stop_decision={'decision': 'ALLOW'},
            health_ok=True, now=owner.NOW)
        current = replay_kill_switch(ROOT, [initial, reset, trigger], **arguments)
        rolled_back = replay_kill_switch(ROOT, [initial, reset], **arguments)
        self.assertEqual(current['state'], 'ENGAGED')
        self.assertEqual(rolled_back['state'], 'DISENGAGED')
        token = {'kill_generation': 2, 'controls_sha256': owner.SHA}
        self.assertIsNone(verify_execution_token(
            token, kill_state=rolled_back,
            current_controls_sha256=owner.SHA))

    def test_positive_current_locked_path_and_neutral_settlement(self):
        denied = risk_decision(
            ROOT, **self._positive_decision_arguments('LIVE'), phase='M0')
        self.assertFalse(denied['execution_authorized'])
        self.assertIn('LIVE_UNAVAILABLE_IN_M0', denied['reasons'])
        self.assertTrue(settlement_allowed_while_engaged(
            adds_exposure=False, reservation_exists=True))
        self.assertFalse(settlement_allowed_while_engaged(
            adds_exposure=True, reservation_exists=True))


if __name__ == '__main__':
    unittest.main()
