"""Bounded synthetic Risk controls; no record here authorizes operations."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import claim_identity, commitment_digest
from src.edgelab.risk_controls import (
    JsonReplayStore, consume_scientific_commitment, evaluate_exposure,
    evaluate_stop_snapshot, kill_event_sha, ledger_event_sha,
    reconcile_ledger, replay_kill_switch, replay_ledger, replay_lifecycle,
    risk_decision, settlement_allowed_while_engaged, transition_subject,
    validate_stop_clearance, validate_trust_policy, verify_attestation,
    verify_execution_token,
)
from src.edgelab.validate import ROOT, read


NOW = datetime(2026, 9, 28, 0, 0, tzinfo=timezone.utc)
SHA = 'a' * 64


def seal(record: dict, field: str) -> dict:
    record[field] = digest(canonical({k: v for k, v in record.items() if k != field}))
    return record


class RiskControlTests(unittest.TestCase):
    def policy(self) -> dict:
        actors = []
        definitions = [
            ('research', 'research@example', ['03_RESEARCH'], []),
            ('data', 'data@example', ['01_DATA'], []),
            ('quant', 'quant@example', ['04_QUANT'], [{'authority_id': 'AUTH-1', 'generation': 3}]),
            ('skeptic', 'skeptic@example', ['05_SKEPTIC'], []),
            ('risk', 'risk@example', ['06_RISK'], []),
        ]
        for actor_id, alias, roles, authorities in definitions:
            scopes = ['LIFECYCLE_PROPOSE', 'LIFECYCLE_APPROVE', 'STOP_CLEAR']
            if actor_id == 'quant':
                scopes.append('SCIENTIFIC_COMMITMENT')
            if actor_id == 'risk':
                scopes.append('KILL_RESET')
            actors.append({
                'actor_id': actor_id, 'aliases': [alias], 'roles': roles,
                'scopes': scopes, 'authorities': authorities,
                'conflicts': [], 'revoked_at': None,
            })
        return {
            'schema_version': 1, 'policy_id': 'POLICY-1', 'generation': 7,
            'controller_id': 'external-test-controller',
            'controller_authentication': 'VERIFIED_EXTERNAL',
            'source': 'synthetic-verifier://risk-tests',
            'valid_from': '2026-09-27T00:00:00Z',
            'valid_until': '2026-09-29T00:00:00Z', 'actors': actors,
        }

    def assessment_commitment(self) -> tuple[dict, dict]:
        ref = {'path': 'x', 'kind': 'synthetic', 'id': 'x', 'version': 1,
               'sha256': SHA}
        assessment = {
            'schema_version': 1, 'status': 'SCIENTIFIC_INTEGRITY_CONSISTENT',
            'scientific_integrity_eligible': True,
            'operational_authorization': False, 'paper_authorization': False,
            'live_authorization': False, 'risk_approval': False,
            'protocol_ref': ref, 'preregistration_ref': ref, 'trial_ref': ref,
            'trial_inventory_ref': ref, 'reproduction_ref': ref,
            'results_access_ref': ref, 'authority_id': 'AUTH-1',
            'authority_generation': 3, 'current_state_sha256': 'b' * 64,
            'experiment_identity_sha256': 'c' * 64,
            'research_contract_status': 'CONSISTENT',
            'history_completeness': 'VERIFIED', 'limitations': ['synthetic'],
        }
        assessment['assessment_sha256'] = digest(canonical(assessment))
        commitment = {
            'schema_version': 1, 'authority_id': 'AUTH-1', 'generation': 3,
            'commitment_id': 'COMMIT-1', 'committed_at': '2026-09-27T23:00:00Z',
            'assessment_sha256': assessment['assessment_sha256'],
            'current_state_sha256': assessment['current_state_sha256'],
            'experiment_identity_sha256': assessment['experiment_identity_sha256'],
            'claim_identity_sha256': claim_identity(assessment),
            'limitations': ['synthetic local binding'],
        }
        commitment['commitment_sha256'] = commitment_digest(commitment)
        return assessment, commitment

    def attestation(self, *, identifier: str, alias: str, role: str,
                    subject_type: str, subject_id: str, subject_sha: str,
                    scope: str) -> dict:
        return seal({
            'schema_version': 1, 'attestation_id': identifier,
            'actor_alias': alias, 'role': role, 'decision': 'APPROVE',
            'subject_type': subject_type, 'subject_id': subject_id,
            'subject_sha256': subject_sha, 'evidence_sha256': SHA,
            'policy_id': 'POLICY-1', 'policy_generation': 7,
            'scope': scope, 'issued_at': '2026-09-27T23:30:00Z',
            'valid_until': '2026-09-28T12:00:00Z', 'disclosures': [],
        }, 'attestation_sha256')

    def test_scientific_commitment_is_consumed_once_and_never_authorizes(self):
        assessment, commitment = self.assessment_commitment()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(
                path, policy_id='POLICY-1', policy_generation=7,
                authority_generations={'AUTH-1': 3})
            result = consume_scientific_commitment(
                ROOT, assessment, commitment, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                replay_store=JsonReplayStore(path), now=NOW)
            self.assertTrue(result['scientific_integrity_consistent'])
            for field in ('lifecycle_eligible', 'paper_eligible', 'live_eligible',
                          'capital_available', 'execution_authorized'):
                self.assertFalse(result[field])
            with self.assertRaisesRegex(ValueError, 'replay|duplicate'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=self.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path), now=NOW)
            altered = copy.deepcopy(commitment)
            altered['commitment_sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'replay|duplicate'):
                JsonReplayStore(path).consume(altered, policy=self.policy(),
                                              consumed_at=NOW)

    def test_authority_forgery_missing_store_stale_generation_and_self_issue_deny(self):
        assessment, commitment = self.assessment_commitment()
        policy = self.policy()
        untrusted = copy.deepcopy(policy)
        untrusted['controller_authentication'] = 'UNVERIFIED'
        with self.assertRaisesRegex(ValueError, 'not externally authenticated'):
            validate_trust_policy(ROOT, untrusted,
                                  expected_source='synthetic-verifier://risk-tests', now=NOW)
        with self.assertRaisesRegex(ValueError, 'replay state'):
            consume_scientific_commitment(
                ROOT, assessment, commitment, policy=policy,
                expected_policy_source='synthetic-verifier://risk-tests',
                replay_store=None, now=NOW)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(path, policy_id='POLICY-1',
                                       policy_generation=7,
                                       authority_generations={'AUTH-1': 2})
            with self.assertRaisesRegex(ValueError, 'generation'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=policy,
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path), now=NOW)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(path, policy_id='POLICY-1',
                                       policy_generation=7,
                                       authority_generations={'AUTH-1': 3})
            with self.assertRaisesRegex(ValueError, 'self-issued'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=policy,
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path),
                    assessment_author_ids={'quant'}, now=NOW)

    def lifecycle(self, *, through: str = 'PAPER_TRADING') -> tuple[list[dict], list[dict]]:
        path = ['IDEA', 'REGISTERED', 'RESEARCHING', 'BACKTESTED',
                'ROBUSTNESS_REVIEW', 'ADVERSARIAL_REVIEW',
                'PAPER_ELIGIBLE', 'PAPER_TRADING']
        path = path[:path.index(through) + 1]
        role_alias = {
            '01_DATA': 'data@example', '03_RESEARCH': 'research@example',
            '04_QUANT': 'quant@example', '05_SKEPTIC': 'skeptic@example',
            '06_RISK': 'risk@example',
        }
        required = {
            ('IDEA', 'REGISTERED'): ['01_DATA'],
            ('REGISTERED', 'RESEARCHING'): ['04_QUANT'],
            ('RESEARCHING', 'BACKTESTED'): ['04_QUANT'],
            ('BACKTESTED', 'ROBUSTNESS_REVIEW'): ['04_QUANT'],
            ('ROBUSTNESS_REVIEW', 'ADVERSARIAL_REVIEW'): ['04_QUANT'],
            ('ADVERSARIAL_REVIEW', 'PAPER_ELIGIBLE'): ['05_SKEPTIC', '06_RISK'],
            ('PAPER_ELIGIBLE', 'PAPER_TRADING'): ['01_DATA', '06_RISK'],
        }
        events, approvals = [], []
        previous = None
        for index, state in enumerate(path, start=1):
            prior = None if index == 1 else path[index - 2]
            event = {
                'schema_version': 1, 'event_id': f'LE-{index}',
                'sequence': index, 'strategy_id': 'STRAT-1', 'strategy_version': 1,
                'occurred_at': f'2026-09-27T{index:02d}:00:00Z',
                'actor_alias': 'research@example', 'actor_role': '03_RESEARCH',
                'from_state': prior, 'to_state': state,
                'evidence_sha256': SHA, 'approval_ids': [], 'trigger_refs': [],
                'previous_event_sha256': previous,
            }
            for role in required.get((prior, state), []):
                approval_id = f'A-{index}-{role}'
                event['approval_ids'].append(approval_id)
                approvals.append((approval_id, role, event))
            seal(event, 'event_sha256')
            previous = event['event_sha256']
            events.append(event)
        records = [self.attestation(
            identifier=identifier, alias=role_alias[role], role=role,
            subject_type='LIFECYCLE_TRANSITION', subject_id=event['event_id'],
            subject_sha=transition_subject(event), scope='LIFECYCLE_APPROVE')
            for identifier, role, event in approvals]
        return events, records

    def test_fully_evidenced_synthetic_paper_path_is_eligible_not_authorized(self):
        events, approvals = self.lifecycle()
        result = replay_lifecycle(
            ROOT, events, approvals, policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence={'scientific_integrity_consistent': True}, now=NOW)
        self.assertEqual(result['state'], 'PAPER_TRADING')
        self.assertTrue(result['paper_eligible'])
        self.assertFalse(result['execution_authorized'])

    def test_lifecycle_skip_terminal_resurrection_self_review_and_stop_deny(self):
        events, approvals = self.lifecycle(through='REGISTERED')
        skipped = copy.deepcopy(events)
        skipped[-1]['to_state'] = 'BACKTESTED'
        seal(skipped[-1], 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'Skipped|illegal'):
            replay_lifecycle(ROOT, skipped, approvals, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'},
                scientific_evidence={'scientific_integrity_consistent': True}, now=NOW)
        events, approvals = self.lifecycle(through='PAPER_ELIGIBLE')
        with self.assertRaisesRegex(ValueError, 'STOP'):
            replay_lifecycle(ROOT, events, approvals, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'DENY'},
                scientific_evidence={'scientific_integrity_consistent': True}, now=NOW)
        events, approvals = self.lifecycle(through='REGISTERED')
        bad = copy.deepcopy(approvals[0])
        bad['actor_alias'] = 'data@example'
        seal(bad, 'attestation_sha256')
        events[-1]['actor_alias'] = 'data@example'
        events[-1]['actor_role'] = '01_DATA'
        events[-1]['approval_ids'] = [bad['attestation_id']]
        seal(events[-1], 'event_sha256')
        bad['subject_sha256'] = transition_subject(events[-1])
        seal(bad, 'attestation_sha256')
        with self.assertRaises(ValueError):
            replay_lifecycle(ROOT, events, [bad], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'}, scientific_evidence=None, now=NOW)
        rejected, registered_approvals = self.lifecycle(through='REGISTERED')
        terminal = copy.deepcopy(rejected[-1])
        terminal.update({'event_id': 'LE-3', 'sequence': 3,
                         'from_state': 'REGISTERED', 'to_state': 'REJECTED',
                         'previous_event_sha256': rejected[-1]['event_sha256'],
                         'approval_ids': []})
        seal(terminal, 'event_sha256')
        resurrect = copy.deepcopy(terminal)
        resurrect.update({'event_id': 'LE-4', 'sequence': 4,
                          'from_state': 'REJECTED', 'to_state': 'REGISTERED',
                          'previous_event_sha256': terminal['event_sha256']})
        seal(resurrect, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'Terminal'):
            replay_lifecycle(ROOT, [*rejected, terminal, resurrect], registered_approvals,
                policy=self.policy(), expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'}, scientific_evidence=None, now=NOW)

    def stop_snapshot(self) -> dict:
        path = ROOT / 'reports/stops/STOP-M0-001.v1.json'
        return {
            'schema_version': 1, 'generation': 1,
            'generated_at': '2026-09-27T23:50:00Z',
            'valid_until': '2026-09-28T00:10:00Z',
            'trusted': True, 'complete': True,
            'stops': [{
                'stop_ref': 'reports/stops/STOP-M0-001.v1.json',
                'stop_sha256': digest(path.read_bytes()),
                'actions': ['PAPER_ELIGIBILITY', 'NEW_EXPOSURE'],
                'scope': {'kind': 'global', 'targets': []},
            }],
        }

    def test_real_open_stop_blocks_and_missing_stale_state_fail_closed(self):
        decision = evaluate_stop_snapshot(
            ROOT, self.stop_snapshot(), action='PAPER_ELIGIBILITY',
            targets={'strategy:1'}, dependency_graph={'strategy:1': set()},
            expected_stop_refs={'reports/stops/STOP-M0-001.v1.json'}, now=NOW)
        self.assertEqual(decision['decision'], 'DENY')
        self.assertEqual(decision['applicable_stop_ids'], ['STOP-M0-001'])
        for mutation in ({'complete': False}, {'valid_until': '2026-09-27T23:59:00Z'},
                         {'stops': []}):
            snapshot = {**self.stop_snapshot(), **mutation}
            with self.assertRaises(ValueError):
                evaluate_stop_snapshot(
                    ROOT, snapshot, action='PAPER_ELIGIBILITY',
                    targets={'strategy:1'}, dependency_graph={'strategy:1': set()},
                    expected_stop_refs={'reports/stops/STOP-M0-001.v1.json'}, now=NOW)

    def test_stop_clearance_requires_typed_independent_authority_and_revalidation(self):
        stop = read(ROOT / 'reports/stops/STOP-M0-001.v1.json')
        resolution = seal({
            'schema_version': 1, 'event_id': 'SR-1', 'stop_id': stop['id'],
            'stop_version': stop['version'], 'stop_sha256': digest(canonical(stop)),
            'occurred_at': '2026-09-27T23:40:00Z', 'acknowledged': True,
            'remediation_evidence': [SHA], 'descendants_revalidated': True,
            'required_roles': ['05_SKEPTIC'], 'capital_implicated': True,
            'remediation_author_actor_ids': ['research'],
        }, 'event_sha256')
        approvals = [self.attestation(
            identifier='SR-A-S', alias='skeptic@example', role='05_SKEPTIC',
            subject_type='STOP_RESOLUTION', subject_id='SR-1',
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR'),
            self.attestation(
            identifier='SR-A-R', alias='risk@example', role='06_RISK',
            subject_type='STOP_RESOLUTION', subject_id='SR-1',
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR')]
        result = validate_stop_clearance(
            ROOT, stop, resolution, approvals, policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests', now=NOW)
        self.assertTrue(result['clearance_eligible'])
        self.assertFalse(result['execution_authorized'])
        with self.assertRaisesRegex(ValueError, 'authority'):
            validate_stop_clearance(
                ROOT, stop, resolution, approvals[:1], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests', now=NOW)
        bad = {**resolution, 'descendants_revalidated': False}
        seal(bad, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'revalidated'):
            validate_stop_clearance(
                ROOT, stop, bad, [], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests', now=NOW)

    def ledger_event(self, sequence: int, kind: str, *, previous=None, amount=0,
                     reservation=None, settlement=None, returned=None,
                     account='PAPER') -> dict:
        return seal({
            'schema_version': 1, 'event_id': f'{account}-{sequence}-{kind}',
            'sequence': sequence, 'account': account, 'event_type': kind,
            'occurred_at': f'2026-09-27T{sequence:02d}:00:00Z',
            'amount_minor': amount, 'reservation_id': reservation,
            'settlement_id': settlement, 'return_minor': returned,
            'evidence_sha256': SHA, 'previous_event_sha256': previous,
        }, 'event_sha256')

    def ledger(self) -> list[dict]:
        opening = self.ledger_event(1, 'OPENING', amount=10000)
        reserve = self.ledger_event(2, 'RESERVE', previous=opening['event_sha256'],
                                    amount=500, reservation='R-1')
        settle = self.ledger_event(3, 'SETTLE', previous=reserve['event_sha256'],
                                   amount=500, reservation='R-1',
                                   settlement='S-1', returned=950)
        return [opening, reserve, settle]

    def test_exact_ledger_reservation_settlement_and_reconciliation(self):
        events = self.ledger()
        state = replay_ledger(ROOT, events, account='PAPER',
                              expected_opening_minor=10000, now=NOW)
        self.assertEqual((state['cash_minor'], state['realized_minor']), (10450, 450))
        snapshot = seal({
            'schema_version': 1, **state, 'as_of': '2026-09-27T23:30:00Z',
            'valid_until': '2026-09-28T00:10:00Z',
        }, 'snapshot_sha256')
        self.assertTrue(reconcile_ledger(
            ROOT, events, snapshot, account='PAPER', expected_opening_minor=10000,
            now=NOW)['reconciled'])

    def test_ledger_rejects_money_creation_negative_duplicate_settlement_and_stale_state(self):
        events = self.ledger()
        duplicate = self.ledger_event(
            4, 'SETTLE', previous=events[-1]['event_sha256'], amount=500,
            reservation='R-1', settlement='S-2', returned=950)
        with self.assertRaises(ValueError):
            replay_ledger(ROOT, [*events, duplicate], account='PAPER',
                          expected_opening_minor=10000, now=NOW)
        altered_opening = {**events[0], 'amount_minor': 10001}
        seal(altered_opening, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'Opening'):
            replay_ledger(ROOT, [altered_opening], account='PAPER',
                          expected_opening_minor=10000, now=NOW)
        opening = self.ledger_event(1, 'OPENING', amount=100)
        reserve = self.ledger_event(2, 'RESERVE', previous=opening['event_sha256'],
                                    amount=101, reservation='R')
        with self.assertRaises(ValueError):
            replay_ledger(ROOT, [opening, reserve], account='PAPER',
                          expected_opening_minor=100, now=NOW)
        state = replay_ledger(ROOT, events, account='PAPER',
                              expected_opening_minor=10000, now=NOW)
        stale = seal({'schema_version': 1, **state,
                      'as_of': '2026-09-27T20:00:00Z',
                      'valid_until': '2026-09-27T21:00:00Z'}, 'snapshot_sha256')
        with self.assertRaisesRegex(ValueError, 'stale'):
            reconcile_ledger(ROOT, events, stale, account='PAPER',
                             expected_opening_minor=10000, now=NOW)
        with self.assertRaises(ValueError):
            replay_ledger(ROOT, events, account='LIVE',
                          expected_opening_minor=10000, now=NOW)

    def position(self, identifier: str, stake: int, *, source='SRC-1',
                 event='EV-1', selection='HOME', environment='PAPER') -> dict:
        return {
            'position_id': identifier, 'environment': environment, 'status': 'OPEN',
            'stake_minor': stake, 'exposure_date': '2026-09-28',
            'strategy_id': 'STRAT-1', 'source_id': source, 'event_id': event,
            'market_id': 'MKT-1', 'selection_id': selection,
            'correlation_keys': [f'event:{event}', 'strategy:STRAT-1',
                                 f'source:{source}', 'market:MKT-1',
                                 f'selection:{event}:{selection}'],
        }

    def limits(self, value=1000) -> dict:
        return {name: value for name in (
            'position_minor', 'daily_exposure_minor', 'strategy_exposure_minor',
            'source_concentration_minor', 'event_exposure_minor',
            'correlated_exposure_minor')}

    def test_correlation_aggregates_duplicate_opinions_and_limits_each_dimension(self):
        existing = self.position('P-1', 600, source='SRC-1')
        request = self.position('P-2', 500, source='SRC-2')
        result = evaluate_exposure(ROOT, [existing], request,
                                   environment='PAPER', limits=self.limits())
        self.assertEqual(result['decision'], 'DENY')
        self.assertIn('correlated_exposure_minor', result['breaches'])
        self.assertFalse(result['duplicate_opinions_diversify'])
        unresolved = self.limits()
        unresolved['position_minor'] = None
        with self.assertRaisesRegex(ValueError, 'Unresolved live'):
            evaluate_exposure(ROOT, [], {**request, 'environment': 'LIVE'},
                              environment='LIVE', limits=unresolved)

    def kill_event(self, sequence: int, kind: str, generation: int, *,
                   previous=None, phase='M0', trigger=None) -> dict:
        return seal({
            'schema_version': 1, 'event_id': f'K-{sequence}', 'sequence': sequence,
            'generation': generation, 'event_type': kind, 'phase': phase,
            'occurred_at': f'2026-09-27T{sequence:02d}:00:00Z',
            'trigger': trigger, 'evidence_sha256': SHA,
            'remediation_refs': [SHA] if kind == 'RESET' else [],
            'reset_attestation_ids': ['RISK-A'] if kind == 'RESET' else [],
            'previous_event_sha256': previous,
        }, 'event_sha256')

    def test_kill_switch_latches_invalidates_pending_and_allows_neutral_settlement(self):
        initial = self.kill_event(1, 'INITIAL_ENGAGE', 1)
        with self.assertRaisesRegex(ValueError, 'M0'):
            reset = self.kill_event(2, 'RESET', 2,
                                    previous=initial['event_sha256'])
            replay_kill_switch(ROOT, [initial, reset], now=NOW)
        post = self.kill_event(2, 'RESET', 2, previous=initial['event_sha256'],
                               phase='M1')
        approval = self.attestation(
            identifier='RISK-A', alias='risk@example', role='06_RISK',
            subject_type='KILL_SWITCH_RESET', subject_id=post['event_id'],
            subject_sha=post['event_sha256'], scope='KILL_RESET')
        with self.assertRaisesRegex(ValueError, 'trust and safety'):
            replay_kill_switch(ROOT, [initial, post], now=NOW)
        state = replay_kill_switch(
            ROOT, [initial, post], policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            attestations=[approval], stop_decision={'decision': 'ALLOW'},
            health_ok=True, now=NOW)
        verify_execution_token({'kill_generation': 2, 'controls_sha256': SHA},
                               kill_state=state, current_controls_sha256=SHA)
        trigger = self.kill_event(3, 'TRIGGER', 3,
                                  previous=post['event_sha256'], phase='M1',
                                  trigger='APPLICABLE_STOP')
        engaged = replay_kill_switch(
            ROOT, [initial, post, trigger], policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            attestations=[approval], stop_decision={'decision': 'ALLOW'},
            health_ok=True, now=NOW)
        with self.assertRaisesRegex(ValueError, 'globally blocks|invalidated'):
            verify_execution_token({'kill_generation': 2, 'controls_sha256': SHA},
                                   kill_state=engaged, current_controls_sha256=SHA)
        self.assertTrue(settlement_allowed_while_engaged(
            adds_exposure=False, reservation_exists=True))
        self.assertFalse(settlement_allowed_while_engaged(
            adds_exposure=True, reservation_exists=True))

    def test_machine_decision_keeps_all_layers_distinct_and_capital_locked(self):
        decision = risk_decision(
            ROOT, decision_id='RD-1', decided_at='2026-09-28T00:00:00Z',
            action='NEW_EXPOSURE', environment='LIVE',
            scientific={'scientific_integrity_consistent': True},
            lifecycle={'lifecycle_eligible': True}, stop={'decision': 'ALLOW'},
            ledger={'reconciled': True}, exposure={'decision': 'ALLOW'},
            kill={'state': 'DISENGAGED'}, capital_deployable_minor=0,
            live_status='LOCKED', individual_authorization_current=True, phase='M0')
        self.assertTrue(decision['scientific_consistent'])
        self.assertTrue(decision['lifecycle_eligible'])
        self.assertFalse(decision['capital_available'])
        self.assertFalse(decision['execution_authorized'])
        self.assertIn('LIVE_UNAVAILABLE_IN_M0', decision['reasons'])
        self.assertIn('LIVE_CAPITAL_LOCKED', decision['reasons'])

    def test_eligibility_and_controls_do_not_replace_individual_authorization(self):
        arguments = dict(
            decision_id='RD-PAPER', decided_at='2026-09-28T00:00:00Z',
            action='NEW_EXPOSURE', environment='PAPER',
            scientific={'scientific_integrity_consistent': True},
            lifecycle={'lifecycle_eligible': True}, stop={'decision': 'ALLOW'},
            ledger={'reconciled': True}, exposure={'decision': 'ALLOW'},
            kill={'state': 'DISENGAGED'}, capital_deployable_minor=1000,
            live_status='LOCKED', phase='M0')
        denied = risk_decision(
            ROOT, **arguments, individual_authorization_current=False)
        self.assertFalse(denied['execution_authorized'])
        self.assertIn('INDIVIDUAL_AUTHORIZATION_MISSING_OR_STALE', denied['reasons'])
        synthetic = risk_decision(
            ROOT, **{**arguments, 'decision_id': 'RD-PAPER-SYNTHETIC'},
            individual_authorization_current=True)
        self.assertTrue(synthetic['execution_authorized'])


if __name__ == '__main__':
    unittest.main()
