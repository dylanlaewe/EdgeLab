"""Owner tests for authoritative, exact-action M0 Risk controls."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.edgelab.data_integrity import canonical, digest
from src.edgelab.quant_protocol import claim_identity, commitment_digest
from src.edgelab.risk_controls import (
    JsonAuthorizationStore, JsonReplayStore, assemble_authoritative_decision,
    consume_scientific_commitment, evaluate_exposure, evaluate_stop_snapshot,
    history_head, reconcile_ledger, replay_kill_switch, replay_ledger,
    replay_lifecycle, risk_decision, settlement_allowed_while_engaged,
    transition_subject, validate_stop_clearance, validate_trust_policy,
    validate_authorization_token, verify_execution_token,
)
from src.edgelab.validate import ROOT, read


NOW = datetime(2026, 9, 28, 0, 0, tzinfo=timezone.utc)
SHA = 'a' * 64


def seal(record: dict, field: str) -> dict:
    record[field] = digest(canonical({k: v for k, v in record.items() if k != field}))
    return record


class StaticRiskAuthority:
    def __init__(self, state: dict, action: dict):
        self.state = state
        self.action = action

    def current_state(self, action_sha256: str) -> dict:
        if action_sha256 != self.action['action_sha256']:
            raise ValueError('Unknown action subject')
        return copy.deepcopy(self.state)

    def commit_if_current(self, expected_state_sha256: str,
                          decision: dict) -> dict:
        if expected_state_sha256 != self.state['state_sha256']:
            raise ValueError('Stale Risk state')
        token = {
            'schema_version': 1,
            'token_id': decision['authorization_id'],
            'issued_at': '2026-09-27T23:59:00Z',
            'expires_at': '2026-09-28T00:05:00Z',
            'action_id': self.action['action_id'],
            'action_sha256': self.action['action_sha256'],
            'action_type': self.action['action_type'],
            'strategy_id': self.action['strategy_id'],
            'strategy_version': self.action['strategy_version'],
            'strategy_identity_sha256': self.action['strategy_identity_sha256'],
            'source_identity_sha256': self.action['source_identity_sha256'],
            'environment': self.action['environment'],
            'event_identity_sha256': self.action['event_identity_sha256'],
            'market_identity_sha256': self.action['market_identity_sha256'],
            'selection_identity_sha256': self.action['selection_identity_sha256'],
            'amount_minor': self.action['amount_minor'],
            'price_constraint_sha256': self.action['price_constraint_sha256'],
            'reservation_id': self.action['reservation_id'],
            'related_action_sha256': self.action['related_action_sha256'],
            'position_id': self.action['position_id'],
            'decision_sha256': decision['decision_sha256'],
            'current_state_sha256': self.state['state_sha256'],
            'authority_id': self.state['authority_id'],
            'authority_generation': self.state['generation'],
            'kill_generation': self.state['kill']['head']['count'],
            'controls_sha256': decision['controls_sha256'],
            'exposure_state_sha256': self.state['exposure']['head']['inventory_sha256'],
            'ledger_head_sha256': self.state['ledger']['head']['inventory_sha256'],
        }
        return seal(token, 'token_sha256')


class RiskControlTests(unittest.TestCase):
    def policy(self) -> dict:
        definitions = [
            ('research', 'research@example', ['03_RESEARCH'], []),
            ('data', 'data@example', ['01_DATA'], []),
            ('quant', 'quant@example', ['04_QUANT'],
             [{'authority_id': 'AUTH-1', 'generation': 3}]),
            ('skeptic', 'skeptic@example', ['05_SKEPTIC'], []),
            ('risk', 'risk@example', ['06_RISK'], []),
        ]
        actors = []
        for actor_id, alias, roles, authorities in definitions:
            scopes = ['LIFECYCLE_PROPOSE', 'LIFECYCLE_APPROVE', 'STOP_CLEAR']
            if actor_id == 'quant': scopes.append('SCIENTIFIC_COMMITMENT')
            if actor_id == 'risk': scopes.append('KILL_RESET')
            actors.append({'actor_id': actor_id, 'aliases': [alias],
                           'roles': roles, 'scopes': scopes,
                           'authorities': authorities, 'conflicts': [],
                           'revoked_at': None})
        return {'schema_version': 1, 'policy_id': 'POLICY-1', 'generation': 7,
                'controller_id': 'external-test-controller',
                'controller_authentication': 'VERIFIED_EXTERNAL',
                'source': 'synthetic-verifier://risk-tests',
                'valid_from': '2026-09-27T00:00:00Z',
                'valid_until': '2026-09-29T00:00:00Z', 'actors': actors}

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
            'history_completeness': 'VERIFIED', 'limitations': ['synthetic']}
        assessment['assessment_sha256'] = digest(canonical(assessment))
        commitment = {
            'schema_version': 1, 'authority_id': 'AUTH-1', 'generation': 3,
            'commitment_id': 'COMMIT-1', 'committed_at': '2026-09-27T23:00:00Z',
            'assessment_sha256': assessment['assessment_sha256'],
            'current_state_sha256': assessment['current_state_sha256'],
            'experiment_identity_sha256': assessment['experiment_identity_sha256'],
            'claim_identity_sha256': claim_identity(assessment),
            'limitations': ['synthetic local binding']}
        commitment['commitment_sha256'] = commitment_digest(commitment)
        return assessment, commitment

    def attestation(self, *, identifier: str, alias: str, role: str,
                    subject_type: str, subject_id: str, subject_sha: str,
                    scope: str) -> dict:
        return seal({'schema_version': 1, 'attestation_id': identifier,
                     'actor_alias': alias, 'role': role, 'decision': 'APPROVE',
                     'subject_type': subject_type, 'subject_id': subject_id,
                     'subject_sha256': subject_sha, 'evidence_sha256': SHA,
                     'policy_id': 'POLICY-1', 'policy_generation': 7,
                     'scope': scope, 'issued_at': '2026-09-27T23:30:00Z',
                     'valid_until': '2026-09-28T12:00:00Z',
                     'disclosures': []}, 'attestation_sha256')

    def scientific_result(self) -> dict:
        return {'status': 'SCIENTIFIC_EVIDENCE_CONSUMED',
                'scientific_integrity_consistent': True,
                'commitment_receipt': {'commitment_id': 'COMMIT-1'},
                'strategy_id': 'STRAT-1', 'strategy_version': 1,
                'execution_authorized': False}

    def lifecycle(self, *, through: str = 'PAPER_TRADING') -> tuple[list[dict], list[dict]]:
        path = ['IDEA', 'REGISTERED', 'RESEARCHING', 'BACKTESTED',
                'ROBUSTNESS_REVIEW', 'ADVERSARIAL_REVIEW',
                'PAPER_ELIGIBLE', 'PAPER_TRADING']
        path = path[:path.index(through) + 1]
        role_alias = {'01_DATA': 'data@example', '03_RESEARCH': 'research@example',
                      '04_QUANT': 'quant@example', '05_SKEPTIC': 'skeptic@example',
                      '06_RISK': 'risk@example'}
        required = {('IDEA', 'REGISTERED'): ['01_DATA'],
                    ('REGISTERED', 'RESEARCHING'): ['04_QUANT'],
                    ('RESEARCHING', 'BACKTESTED'): ['04_QUANT'],
                    ('BACKTESTED', 'ROBUSTNESS_REVIEW'): ['04_QUANT'],
                    ('ROBUSTNESS_REVIEW', 'ADVERSARIAL_REVIEW'): ['04_QUANT'],
                    ('ADVERSARIAL_REVIEW', 'PAPER_ELIGIBLE'): ['05_SKEPTIC', '06_RISK'],
                    ('PAPER_ELIGIBLE', 'PAPER_TRADING'): ['01_DATA', '06_RISK']}
        events, pending = [], []
        previous = None
        for index, state in enumerate(path, start=1):
            prior = None if index == 1 else path[index - 2]
            event = {'schema_version': 1, 'event_id': f'LE-{index}',
                     'sequence': index, 'strategy_id': 'STRAT-1',
                     'strategy_version': 1,
                     'occurred_at': f'2026-09-27T{index:02d}:00:00Z',
                     'actor_alias': 'research@example', 'actor_role': '03_RESEARCH',
                     'from_state': prior, 'to_state': state,
                     'evidence_sha256': SHA, 'approval_ids': [],
                     'trigger_refs': [], 'previous_event_sha256': previous}
            for role in required.get((prior, state), []):
                identifier = f'A-{index}-{role}'
                event['approval_ids'].append(identifier)
                pending.append((identifier, role, event))
            seal(event, 'event_sha256'); previous = event['event_sha256']
            events.append(event)
        approvals = [self.attestation(
            identifier=identifier, alias=role_alias[role], role=role,
            subject_type='LIFECYCLE_TRANSITION', subject_id=event['event_id'],
            subject_sha=transition_subject(event), scope='LIFECYCLE_APPROVE')
            for identifier, role, event in pending]
        return events, approvals

    def action(self, *, action_type='NEW_EXPOSURE', amount=500,
               environment='PAPER', related=None, reservation=None) -> dict:
        identities = self.identities()
        by_namespace = {item['namespace']: item['identity_sha256'] for item in identities}
        return seal({'schema_version': 1, 'action_id': 'ACTION-1',
                     'created_at': '2026-09-27T23:50:00Z',
                     'expires_at': '2026-09-28T00:08:00Z',
                     'action_type': action_type, 'environment': environment,
                     'strategy_id': 'STRAT-1', 'strategy_version': 1,
                     'strategy_identity_sha256': by_namespace['strategy'],
                     'source_identity_sha256': by_namespace['source'],
                     'event_identity_sha256': by_namespace['event'],
                     'market_identity_sha256': by_namespace['market'],
                     'selection_identity_sha256': by_namespace['selection'],
                     'position_id': 'POSITION-1', 'amount_minor': amount,
                     'price_constraint_sha256': 'd' * 64,
                     'reservation_id': reservation,
                     'related_action_sha256': related}, 'action_sha256')

    def action_graph(self, action: dict) -> dict[str, set[str]]:
        return {
            f"strategy:{action['strategy_id']}:v{action['strategy_version']}": set(),
            f"position:{action['position_id']}": set(),
            f"source:{action['source_identity_sha256']}": set(),
            f"event:{action['event_identity_sha256']}": set(),
            f"market:{action['market_identity_sha256']}": set(),
            f"selection:{action['selection_identity_sha256']}": set(),
        }

    def identities(self) -> list[dict]:
        result = []
        for namespace, identifier in [('strategy', 'STRAT-1'), ('source', 'SRC-1'),
                                      ('event', 'EVENT-1'), ('market', 'MARKET-1'),
                                      ('selection', 'HOME')]:
            result.append(seal({'schema_version': 1, 'namespace': namespace,
                                'canonical_id': identifier, 'version': 1,
                                'authority_id': 'DATA-CANONICAL-1',
                                'status': 'VERIFIED', 'aliases': [identifier]},
                               'identity_sha256'))
        return result

    def stop_snapshot(self, root: Path = ROOT) -> dict:
        path = root / 'reports/stops/STOP-M0-001.v1.json'
        return {'schema_version': 1, 'generation': 1,
                'generated_at': '2026-09-27T23:50:00Z',
                'valid_until': '2026-09-28T00:10:00Z',
                'trusted': True, 'complete': True,
                'stops': [{'stop_ref': 'reports/stops/STOP-M0-001.v1.json',
                           'stop_sha256': digest(path.read_bytes()),
                           'actions': ['UNTRUSTED_CANDIDATE_LABEL'],
                           'scope': {'kind': 'records', 'targets': ['untrusted']}}]}

    def stop_head(self, snapshot: dict) -> dict:
        return {'generation': snapshot['generation'],
                'inventory_sha256': digest(canonical(sorted(
                    (item['stop_ref'], item['stop_sha256'])
                    for item in snapshot['stops'])))}

    def stop_policy(self, *, actions=None) -> dict:
        return {'schema_version': 1, 'policy_id': 'STOP-POLICY-1',
                'generation': 1, 'entries': [{
                    'stop_id': 'STOP-M0-001',
                    'action_types': actions or ['*'],
                    'scope': {'kind': 'global', 'targets': []},
                    'clearance_roles': ['05_SKEPTIC', '06_RISK'],
                    'capital_implicated': True}]}

    def economic_binding(self) -> dict:
        action = self.action()
        return {'action_id': action['action_id'],
                'action_sha256': action['action_sha256'],
                'position_id': action['position_id'],
                'strategy_id': action['strategy_id'],
                'strategy_version': action['strategy_version'],
                'strategy_identity_sha256': action['strategy_identity_sha256'],
                'event_identity_sha256': action['event_identity_sha256'],
                'market_identity_sha256': action['market_identity_sha256'],
                'selection_identity_sha256': action['selection_identity_sha256'],
                'authorization_sha256': 'e' * 64}

    def ledger_event(self, sequence: int, kind: str, *, previous=None, amount=0,
                     reservation=None, settlement=None, returned=None,
                     account='PAPER', binding: dict | None = None) -> dict:
        fields = binding or {key: None for key in (
            'action_id', 'action_sha256', 'position_id',
            'strategy_id', 'strategy_version',
            'strategy_identity_sha256', 'event_identity_sha256',
            'market_identity_sha256', 'selection_identity_sha256',
            'authorization_sha256')}
        economic = None
        if binding is not None:
            economic = digest(canonical(fields | {'account': account,
                                                   'amount_minor': amount}))
        return seal({'schema_version': 1, 'event_id': f'{account}-{sequence}-{kind}',
                     'sequence': sequence, 'account': account, 'event_type': kind,
                     'occurred_at': f'2026-09-27T{sequence:02d}:00:00Z',
                     'amount_minor': amount, 'reservation_id': reservation,
                     'settlement_id': settlement, 'return_minor': returned,
                     **fields, 'economic_identity_sha256': economic,
                     'evidence_sha256': SHA, 'previous_event_sha256': previous},
                    'event_sha256')

    def ledger(self) -> list[dict]:
        opening = self.ledger_event(1, 'OPENING', amount=10000)
        binding = self.economic_binding()
        reserve = self.ledger_event(2, 'RESERVE', previous=opening['event_sha256'],
                                    amount=500, reservation='R-1', binding=binding)
        settle = self.ledger_event(3, 'SETTLE', previous=reserve['event_sha256'],
                                   amount=500, reservation='R-1', settlement='S-1',
                                   returned=950, binding=binding)
        # Settlement must carry the exact reservation economic identity.
        settle['economic_identity_sha256'] = reserve['economic_identity_sha256']
        seal(settle, 'event_sha256')
        return [opening, reserve, settle]

    def position(self, identifier: str, stake: int, *, source='SRC-1',
                 event='EVENT-1', selection='HOME', environment='PAPER',
                 status='OPEN') -> dict:
        identities = self.identities()
        values = {item['namespace']: item['identity_sha256'] for item in identities}
        action = self.action()
        record = {'position_id': identifier, 'action_sha256': action['action_sha256'],
                  'environment': environment, 'status': status,
                  'stake_minor': stake, 'exposure_date': '2026-09-28',
                  'strategy_identity_sha256': values['strategy'],
                  'source_identity_sha256': values['source'],
                  'event_identity_sha256': values['event'],
                  'market_identity_sha256': values['market'],
                  'selection_identity_sha256': values['selection']}
        record['correlation_keys'] = [
            'event:' + event, 'strategy:STRAT-1', 'source:' + source,
            'market:MARKET-1', 'selection:' + selection]
        return seal(record, 'position_sha256')

    def limits(self, value=1000) -> dict:
        return {name: value for name in (
            'position_minor', 'daily_exposure_minor', 'strategy_exposure_minor',
            'source_concentration_minor', 'event_exposure_minor',
            'correlated_exposure_minor')}

    def kill_event(self, sequence: int, kind: str, generation: int, *,
                   previous=None, phase='M0', trigger=None) -> dict:
        return seal({'schema_version': 1, 'event_id': f'K-{sequence}',
                     'sequence': sequence, 'generation': generation,
                     'event_type': kind, 'phase': phase,
                     'occurred_at': f'2026-09-27T{sequence:02d}:00:00Z',
                     'trigger': trigger, 'evidence_sha256': SHA,
                     'remediation_refs': [SHA] if kind == 'RESET' else [],
                     'reset_attestation_ids': ['RISK-A'] if kind == 'RESET' else [],
                     'previous_event_sha256': previous}, 'event_sha256')

    def test_scientific_authority_requires_provenance_revocation_and_replay(self):
        assessment, commitment = self.assessment_commitment()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(path, policy_id='POLICY-1',
                                       policy_generation=7,
                                       authority_generations={'AUTH-1': 3})
            result = consume_scientific_commitment(
                ROOT, assessment, commitment, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                replay_store=JsonReplayStore(path),
                assessment_author_ids={'research'}, now=NOW)
            self.assertFalse(result['execution_authorized'])
            with self.assertRaisesRegex(ValueError, 'provenance'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=self.policy(),
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path),
                    assessment_author_ids=None, now=NOW)
        revoked = self.policy(); revoked['actors'][2]['revoked_at'] = '2026-09-27T23:00:00Z'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(path, policy_id='POLICY-1', policy_generation=7,
                                       authority_generations={'AUTH-1': 3})
            with self.assertRaisesRegex(ValueError, 'revoked'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=revoked,
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path),
                    assessment_author_ids={'research'}, now=NOW)
        for authors, pattern in (({'quant'}, 'self-issued'),
                                 ({'unknown'}, 'provenance')):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'replay.json'
                JsonReplayStore.initialize(
                    path, policy_id='POLICY-1', policy_generation=7,
                    authority_generations={'AUTH-1': 3})
                with self.assertRaisesRegex(ValueError, pattern):
                    consume_scientific_commitment(
                        ROOT, assessment, commitment, policy=self.policy(),
                        expected_policy_source='synthetic-verifier://risk-tests',
                        replay_store=JsonReplayStore(path),
                        assessment_author_ids=authors, now=NOW)
        stale = self.policy()
        stale['actors'][2]['authorities'][0]['generation'] = 4
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(
                path, policy_id='POLICY-1', policy_generation=7,
                authority_generations={'AUTH-1': 3})
            with self.assertRaisesRegex(ValueError, 'generation'):
                consume_scientific_commitment(
                    ROOT, assessment, commitment, policy=stale,
                    expected_policy_source='synthetic-verifier://risk-tests',
                    replay_store=JsonReplayStore(path),
                    assessment_author_ids={'research'}, now=NOW)

    def test_lifecycle_current_head_and_conflicted_approvers(self):
        events, approvals = self.lifecycle()
        result = replay_lifecycle(
            ROOT, events, approvals, policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            stop_decision={'decision': 'ALLOW'},
            scientific_evidence=self.scientific_result(),
            current_head=history_head(events, digest_field='event_sha256'), now=NOW)
        self.assertEqual(result['state'], 'PAPER_TRADING')
        terminal = copy.deepcopy(events[-1]); terminal.update({
            'event_id': 'LE-9', 'sequence': 9, 'from_state': 'PAPER_TRADING',
            'to_state': 'REJECTED', 'approval_ids': [], 'trigger_refs': [],
            'occurred_at': '2026-09-27T09:00:00Z',
            'previous_event_sha256': events[-1]['event_sha256']})
        seal(terminal, 'event_sha256'); full = [*events, terminal]
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_lifecycle(
                ROOT, events, approvals, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'},
                scientific_evidence=self.scientific_result(),
                current_head=history_head(full, digest_field='event_sha256'), now=NOW)
        conflicted = self.policy(); conflicted['actors'][3]['conflicts'] = ['risk']; conflicted['actors'][4]['conflicts'] = ['skeptic']
        with self.assertRaisesRegex(ValueError, 'conflict'):
            replay_lifecycle(
                ROOT, events, approvals, policy=conflicted,
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_decision={'decision': 'ALLOW'},
                scientific_evidence=self.scientific_result(),
                current_head=history_head(events, digest_field='event_sha256'), now=NOW)

    def test_authoritative_stop_ignores_candidate_relabel_and_inventory_omission(self):
        action = self.action(); snapshot = self.stop_snapshot()
        graph = self.action_graph(action)
        result = evaluate_stop_snapshot(
            ROOT, snapshot, action=action, dependency_graph=graph,
            stop_policy=self.stop_policy(), current_head=self.stop_head(snapshot), now=NOW)
        self.assertEqual(result['decision'], 'DENY')
        snapshot['stops'] = []
        with self.assertRaisesRegex(ValueError, 'inventory'):
            evaluate_stop_snapshot(
                ROOT, snapshot, action=action, dependency_graph=graph,
                stop_policy=self.stop_policy(), current_head=self.stop_head(snapshot), now=NOW)
        omitted = self.stop_snapshot()
        incomplete_graph = self.action_graph(action)
        del incomplete_graph[f"market:{action['market_identity_sha256']}"]
        with self.assertRaisesRegex(ValueError, 'omitted'):
            evaluate_stop_snapshot(
                ROOT, omitted, action=action, dependency_graph=incomplete_graph,
                stop_policy=self.stop_policy(), current_head=self.stop_head(omitted),
                now=NOW)

    def test_stop_clearance_derives_roles_and_rejects_future(self):
        stop = read(ROOT / 'reports/stops/STOP-M0-001.v1.json')
        evidence_path = ROOT / 'reports/M0.1-risk-remediation.v1.md'
        resolution = seal({'schema_version': 1, 'event_id': 'SR-1',
                           'stop_id': stop['id'], 'stop_version': stop['version'],
                           'stop_sha256': digest(canonical(stop)),
                           'occurred_at': '2999-01-01T00:00:00Z',
                           'acknowledged': True,
                           'remediation_evidence': [{
                               'path': 'reports/M0.1-risk-remediation.v1.md',
                               'sha256': digest(evidence_path.read_bytes())}],
                           'descendants_revalidated': True,
                           'required_roles': ['03_RESEARCH'],
                           'capital_implicated': False,
                           'remediation_author_actor_ids': ['data']}, 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'future'):
            validate_stop_clearance(
                ROOT, stop, resolution, [], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_policy=self.stop_policy(),
                current_stop_head={'stop_id': stop['id'], 'stop_version': 1,
                                   'stop_sha256': digest(canonical(stop)),
                                   'status': 'OPEN'}, now=NOW)

    def test_stop_clearance_rejects_candidate_roles_wrong_head_and_stale_authority(self):
        stop = read(ROOT / 'reports/stops/STOP-M0-001.v1.json')
        evidence_path = ROOT / 'reports/M0.1-risk-remediation.v1.md'
        resolution = seal({
            'schema_version': 1, 'event_id': 'SR-2', 'stop_id': stop['id'],
            'stop_version': stop['version'],
            'stop_sha256': digest(canonical(stop)),
            'occurred_at': '2026-09-27T23:00:00Z', 'acknowledged': True,
            'remediation_evidence': [{
                'path': 'reports/M0.1-risk-remediation.v1.md',
                'sha256': digest(evidence_path.read_bytes())}],
            'descendants_revalidated': True,
            'required_roles': ['03_RESEARCH'], 'capital_implicated': False,
            'remediation_author_actor_ids': ['data']}, 'event_sha256')
        friendly = self.attestation(
            identifier='FRIEND', alias='research@example', role='03_RESEARCH',
            subject_type='STOP_RESOLUTION', subject_id=resolution['event_id'],
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR')
        head = {'stop_id': stop['id'], 'stop_version': stop['version'],
                'stop_sha256': digest(canonical(stop)), 'status': 'OPEN'}
        with self.assertRaisesRegex(ValueError, 'Required STOP'):
            validate_stop_clearance(
                ROOT, stop, resolution, [friendly], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_policy=self.stop_policy(), current_stop_head=head, now=NOW)
        approvals = [self.attestation(
            identifier='CLEAR-SKEPTIC', alias='skeptic@example', role='05_SKEPTIC',
            subject_type='STOP_RESOLUTION', subject_id=resolution['event_id'],
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR'),
            self.attestation(
            identifier='CLEAR-RISK', alias='risk@example', role='06_RISK',
            subject_type='STOP_RESOLUTION', subject_id=resolution['event_id'],
            subject_sha=resolution['event_sha256'], scope='STOP_CLEAR')]
        wrong = {**head, 'stop_version': 2}
        with self.assertRaisesRegex(ValueError, 'current OPEN'):
            validate_stop_clearance(
                ROOT, stop, resolution, approvals, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_policy=self.stop_policy(), current_stop_head=wrong, now=NOW)
        stale = copy.deepcopy(approvals)
        stale[0]['valid_until'] = '2026-09-27T23:59:59Z'
        seal(stale[0], 'attestation_sha256')
        with self.assertRaisesRegex(ValueError, 'stale'):
            validate_stop_clearance(
                ROOT, stop, resolution, stale, policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                stop_policy=self.stop_policy(), current_stop_head=head, now=NOW)

    def test_ledger_exact_binding_conservation_and_current_head(self):
        events = self.ledger(); head = history_head(events, digest_field='event_sha256')
        state = replay_ledger(ROOT, events, account='PAPER',
                              expected_opening_minor=10000, current_head=head, now=NOW)
        self.assertEqual(state['cash_minor'], 10450)
        prefix = events[:2]
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_ledger(ROOT, prefix, account='PAPER', expected_opening_minor=10000,
                          current_head=head, now=NOW)
        changed = copy.deepcopy(events); changed[2]['position_id'] = 'OTHER'; seal(changed[2], 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay_ledger(ROOT, changed, account='PAPER', expected_opening_minor=10000,
                          current_head=history_head(changed, digest_field='event_sha256'), now=NOW)

        for field, value in (
            ('amount_minor', 501), ('action_id', 'ACTION-OTHER'),
            ('event_identity_sha256', 'f' * 64), ('reservation_id', 'R-OTHER'),
            ('strategy_version', 2)):
            attack = copy.deepcopy(events)
            attack[2][field] = value
            seal(attack[2], 'event_sha256')
            with self.assertRaisesRegex(ValueError, 'settlement'):
                replay_ledger(
                    ROOT, attack, account='PAPER', expected_opening_minor=10000,
                    current_head=history_head(attack, digest_field='event_sha256'),
                    now=NOW)

        cross_environment = copy.deepcopy(events[:2])
        cross_environment[1]['account'] = 'LIVE'
        seal(cross_environment[1], 'event_sha256')
        with self.assertRaisesRegex(ValueError, 'account'):
            replay_ledger(
                ROOT, cross_environment, account='PAPER',
                expected_opening_minor=10000,
                current_head=history_head(cross_environment,
                                          digest_field='event_sha256'), now=NOW)

        opening, reserve = copy.deepcopy(events[:2])
        binding = self.economic_binding()
        release = self.ledger_event(
            3, 'RELEASE', previous=reserve['event_sha256'], amount=500,
            reservation='R-1', binding=binding)
        release['economic_identity_sha256'] = reserve['economic_identity_sha256']
        seal(release, 'event_sha256')
        substitute = self.ledger_event(
            4, 'RESERVE', previous=release['event_sha256'], amount=500,
            reservation='R-2', binding=binding)
        released = [opening, reserve, release, substitute]
        with self.assertRaisesRegex(ValueError, 'duplicate reservation'):
            replay_ledger(
                ROOT, released, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(released, digest_field='event_sha256'),
                now=NOW)

        duplicate = copy.deepcopy(events[2])
        duplicate.update({'event_id': 'PAPER-4-SETTLE-WRAPPER', 'sequence': 4,
                          'settlement_id': 'S-OTHER',
                          'previous_event_sha256': events[2]['event_sha256']})
        seal(duplicate, 'event_sha256')
        duplicated = [*events, duplicate]
        with self.assertRaisesRegex(ValueError, 'settlement'):
            replay_ledger(
                ROOT, duplicated, account='PAPER', expected_opening_minor=10000,
                current_head=history_head(duplicated, digest_field='event_sha256'),
                now=NOW)

    def test_pending_and_open_exposure_use_canonical_identity(self):
        pending = self.position('PENDING', 600, status='PENDING')
        request = self.position('REQUEST', 600, status='PENDING')
        limits = self.limits(); limits['daily_exposure_minor'] = 5000
        result = evaluate_exposure(
            ROOT, [pending], request, environment='PAPER', limits=limits,
            current_head=history_head([pending], digest_field='position_sha256'),
            canonical_identities=self.identities())
        self.assertEqual(result['decision'], 'DENY')
        self.assertIn('event_exposure_minor', result['breaches'])
        unknown = self.identities(); unknown[2]['status'] = 'UNKNOWN'; seal(unknown[2], 'identity_sha256')
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            evaluate_exposure(
                ROOT, [], request, environment='PAPER', limits=self.limits(5000),
                current_head=history_head([], digest_field='position_sha256'),
                canonical_identities=unknown)

        open_position = self.position('OPEN', 400, status='OPEN')
        pending = self.position('PENDING-2', 400, status='PENDING')
        request = self.position('REQUEST-2', 300, status='PENDING')
        split_limits = self.limits(1000)
        split_limits['daily_exposure_minor'] = 5000
        split = evaluate_exposure(
            ROOT, [open_position, pending], request, environment='PAPER',
            limits=split_limits,
            current_head=history_head([open_position, pending],
                                      digest_field='position_sha256'),
            canonical_identities=self.identities())
        self.assertEqual(split['decision'], 'DENY')
        self.assertEqual(split['checks_minor']['event_exposure_minor'], 1100)

        identities_v1 = self.identities()
        identities_v2 = []
        for identity in identities_v1:
            changed = copy.deepcopy(identity)
            changed['version'] = 2
            changed['aliases'] = ['cosmetic-' + identity['canonical_id']]
            seal(changed, 'identity_sha256')
            identities_v2.append(changed)
        renamed = self.position('RENAMED', 700, status='PENDING')
        replacements = {
            item['namespace']: item['identity_sha256'] for item in identities_v2}
        for namespace in ('strategy', 'source', 'event', 'market', 'selection'):
            renamed[namespace + '_identity_sha256'] = replacements[namespace]
        seal(renamed, 'position_sha256')
        canonical = evaluate_exposure(
            ROOT, [open_position], renamed, environment='PAPER', limits=limits,
            current_head=history_head([open_position],
                                      digest_field='position_sha256'),
            canonical_identities=[*identities_v1, *identities_v2])
        self.assertEqual(canonical['decision'], 'DENY')
        self.assertEqual(canonical['checks_minor']['event_exposure_minor'], 1100)

    def test_kill_current_head_blocks_valid_prefix_rollback(self):
        initial = self.kill_event(1, 'INITIAL_ENGAGE', 1)
        reset = self.kill_event(2, 'RESET', 2, previous=initial['event_sha256'], phase='M1')
        approval = self.attestation(identifier='RISK-A', alias='risk@example',
            role='06_RISK', subject_type='KILL_SWITCH_RESET', subject_id=reset['event_id'],
            subject_sha=reset['event_sha256'], scope='KILL_RESET')
        trigger = self.kill_event(3, 'TRIGGER', 3, previous=reset['event_sha256'],
                                  phase='M1', trigger='APPLICABLE_STOP')
        full = [initial, reset, trigger]
        with self.assertRaisesRegex(ValueError, 'current history'):
            replay_kill_switch(
                ROOT, [initial, reset], policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                attestations=[approval], stop_decision={'decision': 'ALLOW'},
                health_ok=True, current_head=history_head(full, digest_field='event_sha256'),
                now=NOW)

    def test_legacy_caller_assertions_are_deny_only(self):
        decision = risk_decision(
            ROOT, decision_id='FORGED', decided_at='2026-09-28T00:00:00Z',
            action='NEW_EXPOSURE', environment='LIVE',
            scientific={'scientific_integrity_consistent': True},
            lifecycle={'lifecycle_eligible': True}, stop={'decision': 'ALLOW'},
            ledger={'reconciled': True}, exposure={'decision': 'ALLOW'},
            kill={'state': 'DISENGAGED'}, capital_deployable_minor=100000,
            live_status='UNLOCKED', individual_authorization_current=True, phase='M1')
        self.assertEqual(decision['verdict'], 'DENIED')
        self.assertIn('LEGACY_CALLER_ASSERTED_STATE_UNTRUSTED', decision['reasons'])

    def synthetic_root(self, directory: str) -> Path:
        root = Path(directory) / 'root'
        shutil.copytree(ROOT / 'schemas', root / 'schemas')
        (root / 'docs').mkdir()
        (root / 'portfolio').mkdir()
        (root / 'reports/stops').mkdir(parents=True)
        project = read(ROOT / 'docs/project-state.json')
        project['phase'] = 'M1'
        policy = read(ROOT / 'portfolio/risk-policy.json')
        policy.update({'phase': 'M1', 'kill_switch': 'ENGAGED'})
        policy['limits'].update({key: 1000 for key in policy['limits']})
        bankroll = read(ROOT / 'portfolio/bankroll.json')
        bankroll['paper_capital_minor'] = 10000
        bankroll_schema = read(root / 'schemas/bankroll.schema.json')
        bankroll_schema['properties']['paper_capital_minor'] = {
            'type': ['integer', 'null'], 'minimum': 0}
        risk_schema = read(root / 'schemas/risk-policy.schema.json')
        risk_schema['properties']['phase'] = {'type': 'string', 'minLength': 1}
        risk_schema['properties']['kill_switch'] = {
            'enum': ['ENGAGED', 'DISENGAGED']}
        for value in risk_schema['properties']['limits']['properties'].values():
            value.clear(); value.update({'type': 'integer', 'minimum': 0})
        for path, value in (
            (root / 'docs/project-state.json', project),
            (root / 'portfolio/risk-policy.json', policy),
            (root / 'portfolio/bankroll.json', bankroll),
            (root / 'schemas/bankroll.schema.json', bankroll_schema),
            (root / 'schemas/risk-policy.schema.json', risk_schema),
        ):
            path.write_text(json.dumps(value, indent=2) + '\n')
        shutil.copy2(ROOT / 'reports/stops/STOP-M0-001.v1.json',
                     root / 'reports/stops/STOP-M0-001.v1.json')
        return root

    def settlement_state(self, root: Path) -> tuple[dict, dict]:
        reserve_events = self.ledger()[:2]
        related = reserve_events[1]['action_sha256']
        action = self.action(action_type='SETTLEMENT', amount=500,
                             related=related, reservation='R-1')
        ledger_state = replay_ledger(
            root, reserve_events, account='PAPER', expected_opening_minor=10000,
            current_head=history_head(reserve_events, digest_field='event_sha256'), now=NOW)
        snapshot = seal({'schema_version': 1, **ledger_state,
                         'as_of': '2026-09-27T23:50:00Z',
                         'valid_until': '2026-09-28T00:10:00Z'}, 'snapshot_sha256')
        stop_snapshot = self.stop_snapshot(root)
        kill_events = [self.kill_event(1, 'INITIAL_ENGAGE', 1)]
        graph = {key: [] for key in self.action_graph(action)}
        state = {
            'schema_version': 1, 'authority_id': 'RISK-STATE-1', 'generation': 4,
            'decision_id': 'DECISION-SETTLE-1',
            'generated_at': '2026-09-27T23:59:00Z',
            'valid_until': '2026-09-28T00:06:00Z',
            'action_sha256': action['action_sha256'], 'phase': 'M1',
            'project_state': {'path': 'docs/project-state.json',
                              'sha256': digest((root/'docs/project-state.json').read_bytes())},
            'bankroll': {'path': 'portfolio/bankroll.json',
                         'sha256': digest((root/'portfolio/bankroll.json').read_bytes())},
            'risk_policy': {'path': 'portfolio/risk-policy.json',
                            'sha256': digest((root/'portfolio/risk-policy.json').read_bytes())},
            'scientific': None, 'lifecycle': None,
            'stop': {'snapshot': stop_snapshot,
                     'policy': self.stop_policy(actions=['NEW_EXPOSURE']),
                     'head': self.stop_head(stop_snapshot), 'dependency_graph': graph},
            'ledger': {'events': reserve_events, 'snapshot': snapshot,
                       'head': history_head(reserve_events, digest_field='event_sha256'),
                       'opening_minor': 10000},
            'exposure': {'positions': [],
                         'head': history_head([], digest_field='position_sha256'),
                         'canonical_identities': self.identities(),
                         'limits': self.limits(), 'request': {}},
            'kill': {'events': kill_events, 'attestations': [],
                     'head': history_head(kill_events, digest_field='event_sha256'),
                     'health_ok': True}}
        seal(state, 'state_sha256')
        return action, state

    def m0_live_state(self) -> tuple[dict, dict]:
        action = self.action(action_type='SETTLEMENT', environment='LIVE',
                             amount=1, related='f' * 64, reservation='NONE')
        opening = self.ledger_event(1, 'OPENING', amount=0, account='LIVE')
        events = [opening]
        ledger_state = replay_ledger(
            ROOT, events, account='LIVE', expected_opening_minor=0,
            current_head=history_head(events, digest_field='event_sha256'), now=NOW)
        snapshot = seal({'schema_version': 1, **ledger_state,
                         'as_of': '2026-09-27T23:50:00Z',
                         'valid_until': '2026-09-28T00:10:00Z'},
                        'snapshot_sha256')
        stop_snapshot = self.stop_snapshot()
        kill_events = [self.kill_event(1, 'INITIAL_ENGAGE', 1)]
        state = {
            'schema_version': 1, 'authority_id': 'RISK-STATE-1', 'generation': 4,
            'decision_id': 'DECISION-M0-LIVE',
            'generated_at': '2026-09-27T23:59:00Z',
            'valid_until': '2026-09-28T00:06:00Z',
            'action_sha256': action['action_sha256'], 'phase': 'M0',
            'project_state': {'path': 'docs/project-state.json',
                              'sha256': digest((ROOT/'docs/project-state.json').read_bytes())},
            'bankroll': {'path': 'portfolio/bankroll.json',
                         'sha256': digest((ROOT/'portfolio/bankroll.json').read_bytes())},
            'risk_policy': {'path': 'portfolio/risk-policy.json',
                            'sha256': digest((ROOT/'portfolio/risk-policy.json').read_bytes())},
            'scientific': None, 'lifecycle': None,
            'stop': {'snapshot': stop_snapshot,
                     'policy': self.stop_policy(actions=['NEW_EXPOSURE']),
                     'head': self.stop_head(stop_snapshot),
                     'dependency_graph': {
                         key: [] for key in self.action_graph(action)}},
            'ledger': {'events': events, 'snapshot': snapshot,
                       'head': history_head(events, digest_field='event_sha256'),
                       'opening_minor': 0},
            'exposure': {'positions': [],
                         'head': history_head([], digest_field='position_sha256'),
                         'canonical_identities': self.identities(),
                         'limits': self.limits(0), 'request': {}},
            'kill': {'events': kill_events, 'attestations': [],
                     'head': history_head(kill_events, digest_field='event_sha256'),
                     'health_ok': True}}
        seal(state, 'state_sha256')
        return action, state

    def new_exposure_state(self, root: Path) -> tuple[dict, dict]:
        risk_policy_path = root / 'portfolio/risk-policy.json'
        risk_policy = read(risk_policy_path)
        risk_policy['kill_switch'] = 'DISENGAGED'
        risk_policy_path.write_text(json.dumps(risk_policy, indent=2) + '\n')
        action = self.action()
        opening = self.ledger_event(1, 'OPENING', amount=10000)
        ledger_events = [opening]
        ledger_state = replay_ledger(
            root, ledger_events, account='PAPER', expected_opening_minor=10000,
            current_head=history_head(ledger_events, digest_field='event_sha256'),
            now=NOW)
        snapshot = seal({'schema_version': 1, **ledger_state,
                         'as_of': '2026-09-27T23:50:00Z',
                         'valid_until': '2026-09-28T00:10:00Z'},
                        'snapshot_sha256')
        stop_snapshot = self.stop_snapshot(root)
        initial = self.kill_event(1, 'INITIAL_ENGAGE', 1)
        reset = self.kill_event(2, 'RESET', 2, previous=initial['event_sha256'],
                                phase='M1')
        reset_approval = self.attestation(
            identifier='RISK-A', alias='risk@example', role='06_RISK',
            subject_type='KILL_SWITCH_RESET', subject_id=reset['event_id'],
            subject_sha=reset['event_sha256'], scope='KILL_RESET')
        lifecycle_events, lifecycle_approvals = self.lifecycle()
        assessment, commitment = self.assessment_commitment()
        request = self.position('POSITION-1', 500, status='PENDING')
        state = {
            'schema_version': 1, 'authority_id': 'RISK-STATE-1', 'generation': 4,
            'decision_id': 'DECISION-NEW-1',
            'generated_at': '2026-09-27T23:59:00Z',
            'valid_until': '2026-09-28T00:06:00Z',
            'action_sha256': action['action_sha256'], 'phase': 'M1',
            'project_state': {'path': 'docs/project-state.json',
                              'sha256': digest((root/'docs/project-state.json').read_bytes())},
            'bankroll': {'path': 'portfolio/bankroll.json',
                         'sha256': digest((root/'portfolio/bankroll.json').read_bytes())},
            'risk_policy': {'path': 'portfolio/risk-policy.json',
                            'sha256': digest(risk_policy_path.read_bytes())},
            'scientific': {
                'assessment': assessment, 'commitment': commitment,
                'assessment_author_ids': ['research'], 'strategy_id': 'STRAT-1',
                'strategy_version': 1,
                'experiment_identity_sha256': assessment['experiment_identity_sha256']},
            'lifecycle': {
                'events': lifecycle_events, 'attestations': lifecycle_approvals,
                'head': history_head(lifecycle_events,
                                     digest_field='event_sha256')},
            'stop': {'snapshot': stop_snapshot,
                     'policy': self.stop_policy(actions=['SETTLEMENT']),
                     'head': self.stop_head(stop_snapshot),
                     'dependency_graph': {
                         key: [] for key in self.action_graph(action)}},
            'ledger': {'events': ledger_events, 'snapshot': snapshot,
                       'head': history_head(ledger_events,
                                            digest_field='event_sha256'),
                       'opening_minor': 10000},
            'exposure': {
                'positions': [],
                'head': history_head([], digest_field='position_sha256'),
                'canonical_identities': self.identities(),
                'limits': self.limits(1000), 'request': request},
            'kill': {'events': [initial, reset],
                     'attestations': [reset_approval],
                     'head': history_head([initial, reset],
                                          digest_field='event_sha256'),
                     'health_ok': True}}
        seal(state, 'state_sha256')
        return action, state

    def test_exact_settlement_token_is_single_use_and_action_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.synthetic_root(directory)
            action, state = self.settlement_state(root)
            store_path = Path(directory) / 'auth.json'
            JsonAuthorizationStore.initialize(store_path, authority_id='RISK-STATE-1',
                                              generation=4)
            store = JsonAuthorizationStore(store_path)
            decision, token, returned = assemble_authoritative_decision(
                root, action, authority=StaticRiskAuthority(state, action),
                policy=self.policy(), expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None, authorization_store=store, now=NOW)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertIsNotNone(token)
            verify_execution_token(root, token, action=action, decision=decision,
                                   current_state=returned,
                                   kill_state={'state': 'ENGAGED', 'generation': 1},
                                   authorization_store=store, now=NOW)
            with self.assertRaisesRegex(ValueError, 'already consumed'):
                verify_execution_token(root, token, action=action, decision=decision,
                                       current_state=returned,
                                       kill_state={'state': 'ENGAGED', 'generation': 1},
                                       authorization_store=store, now=NOW)
            changed = copy.deepcopy(action); changed['amount_minor'] = 501; seal(changed, 'action_sha256')
            with self.assertRaises(ValueError):
                verify_execution_token(root, token, action=changed, decision=decision,
                                       current_state=returned,
                                       kill_state={'state': 'ENGAGED', 'generation': 1},
                                       authorization_store=store, now=NOW)

    def test_token_mutation_generation_and_expiry_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.synthetic_root(directory)
            action, state = self.settlement_state(root)
            store_path = Path(directory) / 'auth.json'
            JsonAuthorizationStore.initialize(
                store_path, authority_id='RISK-STATE-1', generation=4)
            decision, token, returned = assemble_authoritative_decision(
                root, action, authority=StaticRiskAuthority(state, action),
                policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None,
                authorization_store=JsonAuthorizationStore(store_path), now=NOW)
            assert token is not None
            for field, value in (
                ('action_id', 'ACTION-B'), ('amount_minor', 5000),
                ('environment', 'LIVE'), ('strategy_version', 2),
                ('event_identity_sha256', '1' * 64),
                ('market_identity_sha256', '2' * 64),
                ('selection_identity_sha256', '3' * 64),
                ('price_constraint_sha256', '4' * 64),
                ('position_id', 'POSITION-B'), ('reservation_id', 'R-B')):
                changed = copy.deepcopy(action)
                changed[field] = value
                seal(changed, 'action_sha256')
                with self.subTest(field=field), self.assertRaisesRegex(
                        ValueError, 'binding'):
                    validate_authorization_token(
                        root, token, action=changed, decision=decision,
                        current_state=returned,
                        kill_state={'state': 'ENGAGED', 'generation': 1}, now=NOW)
            newer = copy.deepcopy(returned)
            newer['generation'] = 5
            seal(newer, 'state_sha256')
            with self.assertRaisesRegex(ValueError, 'binding'):
                validate_authorization_token(
                    root, token, action=action, decision=decision,
                    current_state=newer,
                    kill_state={'state': 'ENGAGED', 'generation': 1}, now=NOW)
            with self.assertRaisesRegex(ValueError, 'kill_generation'):
                validate_authorization_token(
                    root, token, action=action, decision=decision,
                    current_state=returned,
                    kill_state={'state': 'ENGAGED', 'generation': 2}, now=NOW)
            with self.assertRaisesRegex(ValueError, 'expired'):
                validate_authorization_token(
                    root, token, action=action, decision=decision,
                    current_state=returned,
                    kill_state={'state': 'ENGAGED', 'generation': 1},
                    now=datetime(2026, 9, 28, 0, 5, 1, tzinfo=timezone.utc))

    def test_isolated_exact_new_exposure_positive_requires_all_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.synthetic_root(directory)
            action, state = self.new_exposure_state(root)
            replay_path = Path(directory) / 'replay.json'
            JsonReplayStore.initialize(
                replay_path, policy_id='POLICY-1', policy_generation=7,
                authority_generations={'AUTH-1': 3})
            auth_path = Path(directory) / 'auth.json'
            JsonAuthorizationStore.initialize(
                auth_path, authority_id='RISK-STATE-1', generation=4)
            decision, token, _ = assemble_authoritative_decision(
                root, action, authority=StaticRiskAuthority(state, action),
                policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=JsonReplayStore(replay_path),
                authorization_store=JsonAuthorizationStore(auth_path), now=NOW)
            self.assertEqual(decision['verdict'], 'AUTHORIZED')
            self.assertTrue(decision['scientific_consistent'])
            self.assertTrue(decision['lifecycle_eligible'])
            self.assertTrue(decision['paper_eligible'])
            self.assertTrue(decision['capital_available'])
            self.assertTrue(decision['individual_controls_current'])
            self.assertIsNotNone(token)

    def test_actual_m0_and_fixed_state_substitution_cannot_authorize_live(self):
        action, state = self.m0_live_state()
        decision, token, _ = assemble_authoritative_decision(
            ROOT, action, authority=StaticRiskAuthority(state, action),
            policy=self.policy(),
            expected_policy_source='synthetic-verifier://risk-tests',
            scientific_replay_store=None, authorization_store=None, now=NOW)
        self.assertEqual(decision['verdict'], 'DENIED')
        self.assertFalse(decision['live_eligible'])
        self.assertFalse(decision['capital_available'])
        self.assertIsNone(token)
        forged = copy.deepcopy(state)
        forged['ledger']['opening_minor'] = 10000
        seal(forged, 'state_sha256')
        with self.assertRaisesRegex(ValueError, 'authoritative capital'):
            assemble_authoritative_decision(
                ROOT, action, authority=StaticRiskAuthority(forged, action),
                policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None, authorization_store=None, now=NOW)
        phase = copy.deepcopy(state)
        phase['phase'] = 'M1'
        seal(phase, 'state_sha256')
        with self.assertRaisesRegex(ValueError, 'phase'):
            assemble_authoritative_decision(
                ROOT, action, authority=StaticRiskAuthority(phase, action),
                policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None, authorization_store=None, now=NOW)
        alternate = copy.deepcopy(state)
        alternate['bankroll']['path'] = 'portfolio/risk-policy.json'
        alternate['bankroll']['sha256'] = alternate['risk_policy']['sha256']
        seal(alternate, 'state_sha256')
        with self.assertRaisesRegex(ValueError, 'fixed-state'):
            assemble_authoritative_decision(
                ROOT, action, authority=StaticRiskAuthority(alternate, action),
                policy=self.policy(),
                expected_policy_source='synthetic-verifier://risk-tests',
                scientific_replay_store=None, authorization_store=None, now=NOW)

    def test_neutral_settlement_rule_preserved(self):
        self.assertTrue(settlement_allowed_while_engaged(
            adds_exposure=False, reservation_exists=True))
        self.assertFalse(settlement_allowed_while_engaged(
            adds_exposure=True, reservation_exists=True))


if __name__ == '__main__':
    unittest.main()
