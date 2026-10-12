"""Fail-closed M0 Risk controls.

The module deliberately separates scientific consistency, lifecycle eligibility,
capital availability, and per-action authorization.  Local JSON digests bind
content; only a verifier-supplied policy can establish trusted authority.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator

from .data_integrity import canonical, digest, quarantine
from .quant_protocol import verify_authority_commitment
from .validate import CHECKER, instant, read, validate_record


TERMINAL_STATES = frozenset({'REJECTED', 'RETIRED'})
LIVE_STATES = frozenset({'LIVE_CANDIDATE', 'LIVE_APPROVED', 'LIVE'})
LEGAL_FORWARD = {
    'IDEA': 'REGISTERED',
    'REGISTERED': 'RESEARCHING',
    'RESEARCHING': 'BACKTESTED',
    'BACKTESTED': 'ROBUSTNESS_REVIEW',
    'ROBUSTNESS_REVIEW': 'ADVERSARIAL_REVIEW',
    'ADVERSARIAL_REVIEW': 'PAPER_ELIGIBLE',
    'PAPER_ELIGIBLE': 'PAPER_TRADING',
    'PAPER_TRADING': 'LIVE_CANDIDATE',
    'LIVE_CANDIDATE': 'LIVE_APPROVED',
    'LIVE_APPROVED': 'LIVE',
}
TRANSITION_APPROVALS = {
    ('IDEA', 'REGISTERED'): {'01_DATA'},
    ('REGISTERED', 'RESEARCHING'): {'04_QUANT'},
    ('RESEARCHING', 'BACKTESTED'): {'04_QUANT'},
    ('BACKTESTED', 'ROBUSTNESS_REVIEW'): {'04_QUANT'},
    ('ROBUSTNESS_REVIEW', 'ADVERSARIAL_REVIEW'): {'04_QUANT'},
    ('ADVERSARIAL_REVIEW', 'PAPER_ELIGIBLE'): {'05_SKEPTIC', '06_RISK'},
    ('PAPER_ELIGIBLE', 'PAPER_TRADING'): {'01_DATA', '06_RISK'},
}
EXPOSURE_LIMITS = frozenset({
    'position_minor', 'daily_exposure_minor', 'strategy_exposure_minor',
    'source_concentration_minor', 'event_exposure_minor',
    'correlated_exposure_minor',
})
KILL_TRIGGERS = frozenset({
    'STALE_DATA', 'MALFORMED_DATA', 'MISSING_CRITICAL_INPUT',
    'ABNORMAL_EXECUTION', 'PRICE_DISCREPANCY', 'EXPOSURE_LIMIT',
    'DRAWDOWN', 'STRATEGY_DEGRADATION', 'MARKET_UNAVAILABLE',
    'BANKROLL_INCONSISTENT', 'RECONCILIATION_FAILED',
    'SETTLEMENT_ERROR', 'HEALTH_CHECK_FAILED', 'APPLICABLE_STOP',
})
RISK_SCHEMA_KINDS = frozenset({
    'authority-policy', 'approval-attestation', 'lifecycle-event',
    'stop-snapshot', 'stop-resolution-event', 'ledger-event',
    'ledger-snapshot', 'exposure-position', 'kill-switch-event',
    'risk-decision', 'risk-action', 'risk-current-state',
    'action-authorization', 'canonical-risk-identity', 'stop-policy',
})


class RiskStateAuthority(Protocol):
    """Verifier-controlled current-state and atomic authorization boundary."""

    def current_state(self, action_sha256: str) -> dict: ...

    def commit_if_current(self, expected_state_sha256: str,
                          decision: dict) -> dict: ...


def _shape(root: Path, kind: str, record: dict) -> None:
    schema = read(root / 'schemas' / f'{kind}.schema.json')
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=CHECKER).validate(record)


def _unsigned_sha(record: dict, field: str) -> str:
    return digest(canonical({key: value for key, value in record.items() if key != field}))


def _now(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Verifier time must be offset-aware')
    return value


def _bounded_time(start: str, end: str, now: datetime) -> None:
    if instant(start) > now or instant(end) <= now or instant(end) <= instant(start):
        raise ValueError('Authority evidence is not currently valid')


def history_head(records: list[dict], *, digest_field: str) -> dict:
    values = [record[digest_field] for record in records]
    return {
        'count': len(records),
        'last_sha256': values[-1] if values else None,
        'inventory_sha256': digest(canonical(values)),
    }


def verify_current_head(records: list[dict], supplied: dict, *,
                        digest_field: str, label: str) -> None:
    expected = history_head(records, digest_field=digest_field)
    if supplied != expected:
        raise ValueError(f'{label} is not the verifier-selected current history')


def validate_trust_policy(root: Path, policy: dict, *, expected_source: str,
                          now: datetime | None = None) -> dict:
    """Validate verifier-controlled policy; never load it from submitted evidence."""
    _shape(root, 'authority-policy', policy)
    current = _now(now)
    if policy['controller_authentication'] != 'VERIFIED_EXTERNAL':
        raise ValueError('Authority controller is not externally authenticated')
    if policy['source'] != expected_source:
        raise ValueError('Authority policy did not come from the verifier-selected source')
    _bounded_time(policy['valid_from'], policy['valid_until'], current)
    aliases: dict[str, str] = {}
    authorities: dict[str, tuple[str, int]] = {}
    actor_ids = {actor['actor_id'] for actor in policy['actors']}
    if len(actor_ids) != len(policy['actors']):
        raise ValueError('Duplicate canonical authority actor')
    for actor in policy['actors']:
        if actor['revoked_at'] is not None and instant(actor['revoked_at']) <= current:
            continue
        for alias in actor['aliases']:
            if alias in aliases:
                raise ValueError('Alias maps to multiple actors')
            aliases[alias] = actor['actor_id']
        for authority in actor['authorities']:
            key = authority['authority_id']
            if key in authorities:
                raise ValueError('Authority ID maps to multiple actors')
            authorities[key] = (actor['actor_id'], authority['generation'])
        if not set(actor['conflicts']) <= actor_ids:
            raise ValueError('Unknown conflict actor')
    if not aliases or not authorities:
        all_authorities = [
            authority
            for actor in policy['actors']
            for authority in actor['authorities']
        ]
        if all_authorities and not authorities:
            raise ValueError('Authority policy has no usable identities; authority is revoked')
        raise ValueError('Authority policy has no usable identities')
    return policy


def _actor(policy: dict, alias: str, *, role: str, scope: str,
           now: datetime) -> dict:
    matches = [actor for actor in policy['actors'] if alias in actor['aliases']]
    if len(matches) != 1:
        raise ValueError('Unmapped or ambiguous actor alias')
    actor = matches[0]
    if actor['revoked_at'] is not None and instant(actor['revoked_at']) <= now:
        raise ValueError('Actor authority is revoked')
    if role not in actor['roles'] or scope not in actor['scopes']:
        raise ValueError('Actor lacks required role or scope')
    return actor


def verify_attestation(root: Path, attestation: dict, policy: dict, *,
                       expected_subject_type: str, expected_subject_id: str,
                       expected_subject_sha256: str, required_role: str,
                       required_scope: str, author_actor_ids: set[str] | None = None,
                       now: datetime | None = None) -> str:
    _shape(root, 'approval-attestation', attestation)
    current = _now(now)
    if _unsigned_sha(attestation, 'attestation_sha256') != attestation['attestation_sha256']:
        raise ValueError('Attestation digest mismatch')
    if (attestation['policy_id'], attestation['policy_generation']) != (
            policy['policy_id'], policy['generation']):
        raise ValueError('Attestation trust policy is stale or substituted')
    if (attestation['subject_type'], attestation['subject_id'],
            attestation['subject_sha256']) != (
            expected_subject_type, expected_subject_id, expected_subject_sha256):
        raise ValueError('Attestation subject binding mismatch')
    if attestation['role'] != required_role or attestation['scope'] != required_scope:
        raise ValueError('Attestation role or scope mismatch')
    if attestation['decision'] != 'APPROVE':
        raise ValueError('Attestation does not approve')
    if instant(attestation['issued_at']) > current or instant(attestation['valid_until']) <= current:
        raise ValueError('Attestation is future or stale')
    actor = _actor(policy, attestation['actor_alias'], role=required_role,
                   scope=required_scope, now=current)
    authors = author_actor_ids or set()
    if actor['actor_id'] in authors or set(actor['conflicts']) & authors:
        raise ValueError('Self-review or disclosed conflict')
    return actor['actor_id']


def _assert_independent(policy: dict, actor_ids: set[str]) -> None:
    actors = {actor['actor_id']: actor for actor in policy['actors']}
    for actor_id in actor_ids:
        if actor_id not in actors:
            raise ValueError('Approval actor provenance is missing')
        conflicts = set(actors[actor_id]['conflicts'])
        if conflicts & (actor_ids - {actor_id}):
            raise ValueError('Independent approvers have a declared conflict')


def _active_actor_ids(policy: dict, actor_ids: set[str], *, now: datetime) -> None:
    actors = {actor['actor_id']: actor for actor in policy['actors']}
    if not actor_ids or not actor_ids <= actors.keys():
        raise ValueError('Complete canonical actor provenance is required')
    for actor_id in actor_ids:
        revoked = actors[actor_id]['revoked_at']
        if revoked is not None and instant(revoked) <= now:
            raise ValueError('Provenance includes a revoked actor')


class JsonReplayStore:
    """Small durable M0 replay ledger with a separate advisory lock file.

    The path must be verifier-selected and pre-initialized.  This provides
    process-safe local persistence, not remote durability or hostile-host safety.
    """

    def __init__(self, path: Path):
        self.path = path
        self.lock_path = path.with_name(path.name + '.lock')

    @staticmethod
    def initialize(path: Path, *, policy_id: str, policy_generation: int,
                   authority_generations: dict[str, int]) -> None:
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise ValueError('Replay store target must be a new regular path')
        state = {
            'schema_version': 1,
            'policy_id': policy_id,
            'policy_generation': policy_generation,
            'store_generation': 1,
            'authority_generations': authority_generations,
            'consumed': [],
        }
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(state, handle, sort_keys=True, separators=(',', ':'))
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())

    def _read(self) -> dict:
        if not self.path.is_file() or self.path.is_symlink():
            raise ValueError('Durable replay state is unavailable')
        state = read(self.path)
        expected = {'schema_version', 'policy_id', 'policy_generation',
                    'store_generation', 'authority_generations', 'consumed'}
        if set(state) != expected or state['schema_version'] != 1:
            raise ValueError('Corrupt replay state')
        if not isinstance(state['consumed'], list) or not isinstance(
                state['authority_generations'], dict):
            raise ValueError('Corrupt replay state')
        return state

    def consume(self, commitment: dict, *, policy: dict,
                consumed_at: datetime | None = None) -> dict:
        current = _now(consumed_at)
        self.lock_path.parent.mkdir(parents=False, exist_ok=True)
        with self.lock_path.open('a+b') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._read()
            if (state['policy_id'], state['policy_generation']) != (
                    policy['policy_id'], policy['generation']):
                raise ValueError('Replay state trust generation is stale')
            expected_generation = state['authority_generations'].get(
                commitment['authority_id'])
            if expected_generation != commitment['generation']:
                raise ValueError('Authority generation is stale or unknown')
            identifiers = {item['commitment_id'] for item in state['consumed']}
            digests = {item['commitment_sha256'] for item in state['consumed']}
            if (commitment['commitment_id'] in identifiers or
                    commitment['commitment_sha256'] in digests):
                raise ValueError('Authority commitment replay or duplicate consumption')
            receipt = {
                'commitment_id': commitment['commitment_id'],
                'commitment_sha256': commitment['commitment_sha256'],
                'authority_id': commitment['authority_id'],
                'generation': commitment['generation'],
                'consumed_at': current.isoformat().replace('+00:00', 'Z'),
                'store_generation': state['store_generation'] + 1,
            }
            state['consumed'].append(receipt)
            state['store_generation'] += 1
            fd, temporary = tempfile.mkstemp(prefix=self.path.name + '.',
                                             dir=self.path.parent)
            try:
                with os.fdopen(fd, 'w') as handle:
                    json.dump(state, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return receipt


def consume_scientific_commitment(root: Path, assessment: dict,
                                  commitment: dict, *, policy: dict,
                                  expected_policy_source: str,
                                  replay_store: JsonReplayStore | None,
                                  assessment_author_ids: set[str] | None = None,
                                  now: datetime | None = None) -> dict:
    """Consume Quant evidence once without turning it into authorization."""
    current = _now(now)
    validate_trust_policy(root, policy, expected_source=expected_policy_source,
                          now=current)
    required = {
        'status': 'SCIENTIFIC_INTEGRITY_CONSISTENT',
        'scientific_integrity_eligible': True,
        'operational_authorization': False,
        'paper_authorization': False,
        'live_authorization': False,
        'risk_approval': False,
    }
    if any(assessment.get(key) != value for key, value in required.items()):
        raise ValueError('Quant assessment is absent, inconsistent, or over-authorizing')
    verify_authority_commitment(root, assessment, commitment, now=current)
    if not assessment_author_ids:
        raise ValueError('Complete scientific authorship provenance is required')
    matches = []
    for actor in policy['actors']:
        for authority in actor['authorities']:
            if authority['authority_id'] == commitment['authority_id']:
                matches.append((actor, authority))
    if len(matches) != 1:
        raise ValueError('Commitment authority is untrusted or ambiguous')
    actor, authority = matches[0]
    if actor['revoked_at'] is not None and instant(actor['revoked_at']) <= current:
        raise ValueError('Scientific authority is revoked')
    if authority['generation'] != commitment['generation']:
        raise ValueError('Commitment authority generation is stale')
    if 'SCIENTIFIC_COMMITMENT' not in actor['scopes']:
        raise ValueError('Authority lacks scientific commitment scope')
    authors = assessment_author_ids
    _active_actor_ids(policy, authors, now=current)
    if actor['actor_id'] in authors or set(actor['conflicts']) & authors:
        raise ValueError('Scientific authority is self-issued or conflicted')
    _assert_independent(policy, authors | {actor['actor_id']})
    if replay_store is None:
        raise ValueError('Durable commitment replay state is required')
    receipt = replay_store.consume(commitment, policy=policy, consumed_at=current)
    return {
        'status': 'SCIENTIFIC_EVIDENCE_CONSUMED',
        'scientific_integrity_consistent': True,
        'lifecycle_eligible': False,
        'paper_eligible': False,
        'live_eligible': False,
        'capital_available': False,
        'execution_authorized': False,
        'authority_actor_id': actor['actor_id'],
        'commitment_receipt': receipt,
        'limitations': [
            'Local persistence does not authenticate the host or external controller.',
            'Scientific consistency is evidence, not operational authorization.',
        ],
    }


def transition_subject(event: dict) -> str:
    return digest(canonical({
        key: value for key, value in event.items()
        if key not in {'event_sha256', 'approval_ids'}
    }))


def replay_lifecycle(root: Path, events: list[dict], attestations: list[dict], *,
                     policy: dict, expected_policy_source: str,
                     stop_decision: dict, scientific_evidence: dict | None,
                     current_head: dict,
                     now: datetime | None = None) -> dict:
    current = _now(now)
    validate_trust_policy(root, policy, expected_source=expected_policy_source,
                          now=current)
    if not events:
        raise ValueError('Lifecycle event history is missing')
    by_id = {item['attestation_id']: item for item in attestations}
    if len(by_id) != len(attestations):
        raise ValueError('Duplicate attestation identity')
    state = None
    previous = None
    strategy = None
    for index, event in enumerate(events, start=1):
        _shape(root, 'lifecycle-event', event)
        if _unsigned_sha(event, 'event_sha256') != event['event_sha256']:
            raise ValueError('Lifecycle event digest mismatch')
        if event['sequence'] != index or event['previous_event_sha256'] != previous:
            raise ValueError('Lifecycle history is missing, reordered, or forked')
        if instant(event['occurred_at']) > current:
            raise ValueError('Lifecycle event is a future completed fact')
        if strategy is None:
            strategy = (event['strategy_id'], event['strategy_version'])
        if strategy != (event['strategy_id'], event['strategy_version']):
            raise ValueError('Lifecycle history mixes strategy versions')
        if state is None:
            if event['from_state'] is not None or event['to_state'] != 'IDEA':
                raise ValueError('Lifecycle must begin with an IDEA event')
        else:
            if event['from_state'] != state:
                raise ValueError('Lifecycle asserted state conflicts with event history')
            if state in TERMINAL_STATES:
                raise ValueError('Terminal strategy version cannot resurrect')
            destination = event['to_state']
            if destination in LIVE_STATES:
                raise ValueError('Live lifecycle states are unavailable during M0')
            if destination in TERMINAL_STATES:
                pass
            elif destination == 'SUSPENDED':
                if not event['trigger_refs']:
                    raise ValueError('Suspension requires a material trigger')
            elif state == 'SUSPENDED':
                raise ValueError('M0 suspended strategies cannot resume by transition')
            elif LEGAL_FORWARD.get(state) != destination:
                raise ValueError('Skipped or illegal lifecycle transition')
            required = TRANSITION_APPROVALS.get((state, destination), set())
            if destination in {'BACKTESTED', 'ROBUSTNESS_REVIEW',
                               'ADVERSARIAL_REVIEW', 'PAPER_ELIGIBLE',
                               'PAPER_TRADING'}:
                if (not scientific_evidence or
                        scientific_evidence.get('status') != 'SCIENTIFIC_EVIDENCE_CONSUMED' or
                        not scientific_evidence.get('scientific_integrity_consistent') or
                        not scientific_evidence.get('commitment_receipt') or
                        scientific_evidence.get('strategy_id') != event['strategy_id'] or
                        scientific_evidence.get('strategy_version') != event['strategy_version']):
                    raise ValueError('Required scientific evidence is unavailable')
            subject = transition_subject(event)
            author = _actor(policy, event['actor_alias'], role=event['actor_role'],
                            scope='LIFECYCLE_PROPOSE', now=current)
            approved_actors = set()
            supplied_roles = set()
            for approval_id in event['approval_ids']:
                if approval_id not in by_id:
                    raise ValueError('Lifecycle approval record is missing')
                approval = by_id[approval_id]
                role = approval['role']
                actor_id = verify_attestation(
                    root, approval, policy,
                    expected_subject_type='LIFECYCLE_TRANSITION',
                    expected_subject_id=event['event_id'],
                    expected_subject_sha256=subject,
                    required_role=role, required_scope='LIFECYCLE_APPROVE',
                    author_actor_ids={author['actor_id']}, now=current)
                if actor_id in approved_actors:
                    raise ValueError('One actor supplied multiple independent approvals')
                approved_actors.add(actor_id)
                supplied_roles.add(role)
            _assert_independent(policy, approved_actors | {author['actor_id']})
            if not required <= supplied_roles:
                raise ValueError('Required lifecycle approvals are missing')
        state = event['to_state']
        previous = event['event_sha256']
    verify_current_head(events, current_head, digest_field='event_sha256',
                        label='Lifecycle history')
    lifecycle_eligible = state in {'PAPER_ELIGIBLE', 'PAPER_TRADING'}
    return {
        'strategy_id': strategy[0], 'strategy_version': strategy[1],
        'state': state,
        'lifecycle_eligible': lifecycle_eligible,
        'paper_eligible': (lifecycle_eligible and
                           stop_decision.get('decision') == 'ALLOW'),
        'live_eligible': False,
        'execution_authorized': False,
        'last_event_sha256': previous,
    }


def evaluate_stop_snapshot(root: Path, snapshot: dict, *, action: dict,
                           dependency_graph: dict[str, set[str]],
                           stop_policy: dict, current_head: dict,
                           now: datetime | None = None) -> dict:
    current = _now(now)
    _shape(root, 'stop-snapshot', snapshot)
    if not snapshot['trusted'] or not snapshot['complete']:
        raise ValueError('Trusted complete STOP state is unavailable')
    if instant(snapshot['generated_at']) > current or instant(snapshot['valid_until']) <= current:
        raise ValueError('STOP state is future or stale')
    _shape(root, 'risk-action', action)
    if _unsigned_sha(action, 'action_sha256') != action['action_sha256']:
        raise ValueError('Action digest mismatch')
    _shape(root, 'stop-policy', stop_policy)
    refs = {item['stop_ref'] for item in snapshot['stops']}
    repository_refs = {
        path.relative_to(root).as_posix()
        for path in (root / 'reports/stops').glob('*.json')
        if path.is_file() and not path.is_symlink()
    }
    if refs != repository_refs:
        raise ValueError('STOP inventory is missing, substituted, or inconsistent')
    stop_inventory = sorted((item['stop_ref'], item['stop_sha256'])
                            for item in snapshot['stops'])
    expected_head = {
        'generation': snapshot['generation'],
        'inventory_sha256': digest(canonical(stop_inventory)),
    }
    if current_head != expected_head:
        raise ValueError('STOP inventory is not the verifier-selected current state')
    policy_by_id = {entry['stop_id']: entry for entry in stop_policy['entries']}
    if len(policy_by_id) != len(stop_policy['entries']):
        raise ValueError('Duplicate STOP policy identity')
    targets = {
        f"strategy:{action['strategy_id']}:v{action['strategy_version']}",
        f"position:{action['position_id']}",
        f"source:{action['source_identity_sha256']}",
        f"event:{action['event_identity_sha256']}",
        f"market:{action['market_identity_sha256']}",
        f"selection:{action['selection_identity_sha256']}",
    }
    missing_targets = targets - dependency_graph.keys()
    if missing_targets:
        raise ValueError('Action dependency identity is omitted from STOP graph')
    blocked: set[str] = set()
    applicable: list[str] = []
    for item in snapshot['stops']:
        path = (root / item['stop_ref']).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file() or path.is_symlink():
            raise ValueError('STOP record is missing or unreadable')
        record = read(path)
        validate_record('stop', record, root, now=current)
        if digest(path.read_bytes()) != item['stop_sha256']:
            raise ValueError('STOP content binding mismatch')
        rule = policy_by_id.get(record['id'])
        if rule is None:
            raise ValueError('Authoritative STOP policy is missing')
        applies = ('*' in rule['action_types'] or
                   action['action_type'] in rule['action_types'])
        if record['status'] == 'OPEN' and applies:
            scoped = quarantine(dependency_graph, rule['scope'])
            hits = targets & scoped
            if hits or rule['scope']['kind'] == 'global':
                blocked |= hits or targets
                applicable.append(record['id'])
    return {
        'decision': 'DENY' if applicable else 'ALLOW',
        'action_id': action['action_id'],
        'action_sha256': action['action_sha256'],
        'targets': sorted(targets),
        'blocked_targets': sorted(blocked),
        'applicable_stop_ids': applicable,
        'stop_generation': snapshot['generation'],
        'execution_authorized': False,
    }


def validate_stop_clearance(root: Path, stop_record: dict, resolution: dict,
                            attestations: list[dict], *, policy: dict,
                            expected_policy_source: str,
                            stop_policy: dict, current_stop_head: dict,
                            now: datetime | None = None) -> dict:
    """Validate a candidate clearance event; never mutates the OPEN record."""
    current = _now(now)
    validate_trust_policy(root, policy, expected_source=expected_policy_source,
                          now=current)
    validate_record('stop', stop_record, root, now=current)
    _shape(root, 'stop-resolution-event', resolution)
    _shape(root, 'stop-policy', stop_policy)
    if stop_record['status'] != 'OPEN':
        raise ValueError('Clearance must refer to the preserved OPEN STOP')
    if _unsigned_sha(resolution, 'event_sha256') != resolution['event_sha256']:
        raise ValueError('STOP resolution digest mismatch')
    if instant(resolution['occurred_at']) > current:
        raise ValueError('STOP resolution is a future completed fact')
    if (resolution['stop_id'], resolution['stop_version'],
            resolution['stop_sha256']) != (
            stop_record['id'], stop_record['version'],
            digest(canonical(stop_record))):
        raise ValueError('STOP resolution subject mismatch')
    if not resolution['acknowledged'] or not resolution['remediation_evidence']:
        raise ValueError('STOP acknowledgement or remediation evidence missing')
    for evidence in resolution['remediation_evidence']:
        path = (root / evidence['path']).resolve()
        if (not path.is_relative_to(root.resolve()) or not path.is_file() or
                path.is_symlink() or digest(path.read_bytes()) != evidence['sha256']):
            raise ValueError('STOP remediation evidence is missing or altered')
    if not resolution['descendants_revalidated']:
        raise ValueError('Quarantined descendants have not been revalidated')
    rules = [entry for entry in stop_policy['entries']
             if entry['stop_id'] == stop_record['id']]
    if len(rules) != 1:
        raise ValueError('Authoritative STOP clearance policy is missing or ambiguous')
    rule = rules[0]
    required = set(rule['clearance_roles'])
    if rule['capital_implicated']:
        required.add('06_RISK')
    expected_head = {
        'stop_id': stop_record['id'], 'stop_version': stop_record['version'],
        'stop_sha256': digest(canonical(stop_record)), 'status': 'OPEN',
    }
    if current_stop_head != expected_head:
        raise ValueError('STOP clearance is not based on current OPEN state')
    subject = resolution['event_sha256']
    found_roles = set()
    actors = set()
    author_ids = set(resolution['remediation_author_actor_ids'])
    _active_actor_ids(policy, author_ids, now=current)
    for item in attestations:
        role = item['role']
        actor_id = verify_attestation(
            root, item, policy, expected_subject_type='STOP_RESOLUTION',
            expected_subject_id=resolution['event_id'],
            expected_subject_sha256=subject, required_role=role,
            required_scope='STOP_CLEAR', author_actor_ids=author_ids, now=current)
        if actor_id in actors:
            raise ValueError('Duplicate STOP clearing authority')
        actors.add(actor_id)
        found_roles.add(role)
    _assert_independent(policy, actors | author_ids)
    if not required <= found_roles:
        raise ValueError('Required STOP clearing authority is missing')
    return {
        'clearance_eligible': True,
        'stop_id': stop_record['id'],
        'event_sha256': resolution['event_sha256'],
        'execution_authorized': False,
    }


def ledger_event_sha(event: dict) -> str:
    return _unsigned_sha(event, 'event_sha256')


def replay_ledger(root: Path, events: list[dict], *, account: str,
                  expected_opening_minor: int, current_head: dict,
                  now: datetime | None = None) -> dict:
    current = _now(now)
    if account not in {'PAPER', 'LIVE'} or not events:
        raise ValueError('A typed nonempty paper/live ledger is required')
    cash = reserved = liability = realized = 0
    prior = None
    reservations: dict[str, dict] = {}
    settlements: dict[str, dict] = {}
    corrections: set[str] = set()
    action_bindings: dict[str, str] = {}
    position_bindings: dict[str, str] = {}
    liability_bindings: dict[str, str] = {}
    seen_ids = set()
    for sequence, event in enumerate(events, start=1):
        _shape(root, 'ledger-event', event)
        if ledger_event_sha(event) != event['event_sha256']:
            raise ValueError('Ledger event digest mismatch')
        if event['event_id'] in seen_ids:
            raise ValueError('Duplicate ledger event identity')
        seen_ids.add(event['event_id'])
        if (event['sequence'] != sequence or event['account'] != account or
                event['previous_event_sha256'] != prior or
                instant(event['occurred_at']) > current):
            raise ValueError('Ledger ordering, account, hash chain, or time is invalid')
        kind = event['event_type']
        amount = event['amount_minor']
        if kind == 'OPENING':
            if sequence != 1 or amount != expected_opening_minor:
                raise ValueError('Opening balance mismatch')
            if any(event[field] is not None for field in (
                    'action_id', 'action_sha256', 'position_id',
                    'strategy_id', 'strategy_version',
                    'experiment_identity_sha256',
                    'strategy_identity_sha256', 'event_identity_sha256',
                    'market_identity_sha256', 'selection_identity_sha256',
                    'authorization_sha256', 'liability_identity_sha256',
                    'economic_identity_sha256')):
                raise ValueError('Opening event cannot assert an economic action')
            cash = amount
        elif sequence == 1:
            raise ValueError('Ledger must begin with opening balance')
        elif kind == 'RESERVE':
            rid = event['reservation_id']
            binding_fields = (
                'action_id', 'action_sha256', 'position_id',
                'strategy_id', 'strategy_version',
                'experiment_identity_sha256',
                'strategy_identity_sha256', 'event_identity_sha256',
                'market_identity_sha256', 'selection_identity_sha256',
                'authorization_sha256', 'liability_identity_sha256',
                'economic_identity_sha256')
            if any(event[field] is None for field in binding_fields):
                raise ValueError('Reservation lacks exact action/economic binding')
            expected_liability = digest(canonical({
                field: event[field] for field in (
                    'position_id', 'strategy_id', 'strategy_version',
                    'experiment_identity_sha256',
                    'strategy_identity_sha256', 'event_identity_sha256',
                    'market_identity_sha256', 'selection_identity_sha256')
            } | {'account': account, 'amount_minor': amount}))
            if event['liability_identity_sha256'] != expected_liability:
                raise ValueError('Reservation semantic liability identity mismatch')
            expected_economic = digest(canonical({
                field: event[field] for field in binding_fields
                if field != 'economic_identity_sha256'
            } | {'account': account, 'amount_minor': amount}))
            if event['economic_identity_sha256'] != expected_economic:
                raise ValueError('Reservation economic identity mismatch')
            if (not rid or rid in reservations or amount <= 0 or amount > cash or
                    event['action_sha256'] in action_bindings or
                    event['position_id'] in position_bindings or
                    event['liability_identity_sha256'] in liability_bindings):
                raise ValueError('Invalid or duplicate reservation')
            cash -= amount
            reserved += amount
            liability += amount
            reservations[rid] = {
                'stake': amount, 'status': 'OPEN',
                **{field: event[field] for field in binding_fields},
            }
            action_bindings[event['action_sha256']] = rid
            position_bindings[event['position_id']] = rid
            liability_bindings[event['liability_identity_sha256']] = rid
        elif kind == 'RELEASE':
            rid = event['reservation_id']
            reservation = reservations.get(rid)
            if (not reservation or reservation['status'] != 'OPEN' or
                    amount != reservation['stake'] or
                    any(event[field] != reservation[field] for field in (
                        'action_id', 'action_sha256', 'position_id',
                        'strategy_id', 'strategy_version',
                        'experiment_identity_sha256',
                        'strategy_identity_sha256', 'event_identity_sha256',
                        'market_identity_sha256', 'selection_identity_sha256',
                        'authorization_sha256', 'liability_identity_sha256',
                        'economic_identity_sha256'))):
                raise ValueError('Invalid reservation release')
            cash += amount
            reserved -= amount
            liability -= amount
            reservation['status'] = 'RELEASED'
        elif kind == 'SETTLE':
            rid, sid = event['reservation_id'], event['settlement_id']
            reservation = reservations.get(rid)
            returned = event['return_minor']
            if (not reservation or reservation['status'] != 'OPEN' or not sid or
                    sid in settlements or amount != reservation['stake'] or
                    returned is None or any(
                        event[field] != reservation[field] for field in (
                            'action_id', 'action_sha256', 'position_id',
                            'strategy_id', 'strategy_version',
                            'experiment_identity_sha256',
                            'strategy_identity_sha256', 'event_identity_sha256',
                            'market_identity_sha256', 'selection_identity_sha256',
                            'authorization_sha256', 'liability_identity_sha256',
                            'economic_identity_sha256'))):
                raise ValueError('Duplicate or invalid settlement')
            cash += returned
            reserved -= amount
            liability -= amount
            realized += returned - amount
            reservation['status'] = 'SETTLED'
            semantic = digest(canonical({
                'liability_identity_sha256':
                    reservation['liability_identity_sha256'],
            }))
            if semantic in {value['semantic'] for value in settlements.values()}:
                raise ValueError('Duplicate semantic settlement')
            settlements[sid] = {'return': returned, 'stake': amount,
                                'semantic': semantic, **reservation}
        elif kind == 'CORRECT_SETTLEMENT':
            sid = event['settlement_id']
            corrected = event['return_minor']
            if (sid not in settlements or sid in corrections or corrected is None or
                    amount != 0 or any(
                        event[field] != settlements[sid][field] for field in (
                            'action_id', 'action_sha256', 'position_id',
                            'strategy_id', 'strategy_version',
                            'experiment_identity_sha256',
                            'strategy_identity_sha256', 'event_identity_sha256',
                            'market_identity_sha256', 'selection_identity_sha256',
                            'authorization_sha256', 'liability_identity_sha256',
                            'economic_identity_sha256'))):
                raise ValueError('Invalid or duplicate compensating settlement correction')
            delta = corrected - settlements[sid]['return']
            if cash + delta < 0:
                raise ValueError('Settlement correction creates negative cash')
            cash += delta
            realized += delta
            settlements[sid]['return'] = corrected
            corrections.add(sid)
        else:
            raise ValueError('Unsupported ledger event type')
        if min(cash, reserved, liability) < 0 or reserved != liability:
            raise ValueError('Negative or inconsistent ledger balance')
        if cash + reserved != expected_opening_minor + realized:
            raise ValueError('Ledger conservation invariant violated')
        prior = event['event_sha256']
    verify_current_head(events, current_head, digest_field='event_sha256',
                        label='Ledger history')
    return {
        'account': account, 'currency': 'USD', 'opening_minor': expected_opening_minor,
        'cash_minor': cash, 'reserved_minor': reserved,
        'liability_minor': liability, 'realized_minor': realized,
        'sequence': len(events), 'last_event_sha256': prior,
        'open_reservations': sorted(
            key for key, value in reservations.items() if value['status'] == 'OPEN'),
        'open_reservation_bindings': {
            key: {'stake': value['stake']} | {
                field: value[field] for field in (
                    'action_id', 'action_sha256', 'position_id',
                    'strategy_id', 'strategy_version',
                    'experiment_identity_sha256',
                    'strategy_identity_sha256', 'event_identity_sha256',
                    'market_identity_sha256', 'selection_identity_sha256',
                    'liability_identity_sha256', 'economic_identity_sha256')
            }
            for key, value in reservations.items() if value['status'] == 'OPEN'
        },
    }


def reconcile_ledger(root: Path, events: list[dict], snapshot: dict, *,
                     account: str, expected_opening_minor: int,
                     current_head: dict,
                     now: datetime | None = None) -> dict:
    current = _now(now)
    _shape(root, 'ledger-snapshot', snapshot)
    if instant(snapshot['as_of']) > current or instant(snapshot['valid_until']) <= current:
        raise ValueError('Ledger reconciliation is future or stale')
    if _unsigned_sha(snapshot, 'snapshot_sha256') != snapshot['snapshot_sha256']:
        raise ValueError('Ledger snapshot digest mismatch')
    state = replay_ledger(root, events, account=account,
                          expected_opening_minor=expected_opening_minor,
                          current_head=current_head, now=current)
    for field in ('account', 'currency', 'opening_minor', 'cash_minor',
                  'reserved_minor', 'liability_minor', 'realized_minor',
                  'sequence', 'last_event_sha256', 'open_reservations',
                  'open_reservation_bindings'):
        if snapshot[field] != state[field]:
            raise ValueError('Ledger snapshot does not reconcile: ' + field)
    return {**state, 'reconciled': True, 'snapshot_sha256': snapshot['snapshot_sha256']}


def evaluate_exposure(root: Path, positions: list[dict], request: dict, *,
                      environment: str, limits: dict[str, int | None],
                      current_head: dict, canonical_identities: list[dict]) -> dict:
    if set(limits) != EXPOSURE_LIMITS:
        raise ValueError('Complete exposure limits are required')
    if environment == 'LIVE' and any(value is None or value <= 0 for value in limits.values()):
        raise ValueError('Unresolved live exposure limits deny')
    if environment not in {'PAPER', 'LIVE'}:
        raise ValueError('Unknown exposure environment')
    identity_by_sha = {}
    identity_versions = set()
    for identity in canonical_identities:
        _shape(root, 'canonical-risk-identity', identity)
        if _unsigned_sha(identity, 'identity_sha256') != identity['identity_sha256']:
            raise ValueError('Canonical identity digest mismatch')
        if identity['identity_sha256'] in identity_by_sha:
            raise ValueError('Duplicate canonical identity')
        identity_key = (identity['namespace'], identity['canonical_id'],
                        identity['version'])
        if identity_key in identity_versions:
            raise ValueError('Conflicting canonical identity version')
        identity_versions.add(identity_key)
        identity_by_sha[identity['identity_sha256']] = identity
    identity_fields = (
        'strategy_identity_sha256', 'source_identity_sha256',
        'event_identity_sha256', 'market_identity_sha256',
        'selection_identity_sha256')
    namespaces = dict(zip(identity_fields, (
        'strategy', 'source', 'event', 'market', 'selection'), strict=True))
    resolved: dict[str, dict[str, str]] = {}
    for item in [*positions, request]:
        _shape(root, 'exposure-position', item)
        if _unsigned_sha(item, 'position_sha256') != item['position_sha256']:
            raise ValueError('Exposure position digest mismatch')
        if item['environment'] != environment or item['stake_minor'] <= 0:
            raise ValueError('Mixed environment or nonpositive exposure')
        for field in identity_fields:
            identity = identity_by_sha.get(item[field])
            if (identity is None or identity['status'] != 'VERIFIED' or
                    identity['namespace'] != namespaces[field]):
                raise ValueError('Canonical exposure identity is unresolved')
        canonical_ids = {
            namespaces[field]: identity_by_sha[item[field]]['canonical_id']
            for field in identity_fields
        }
        resolved[item['position_sha256']] = canonical_ids
        mandatory = {
            namespace + ':' + canonical_id
            for namespace, canonical_id in canonical_ids.items()
        }
        if not mandatory <= set(item['correlation_keys']):
            raise ValueError('Exposure omits mandatory correlation dependencies')
    verify_current_head(positions, current_head, digest_field='position_sha256',
                        label='Exposure inventory')
    active = [item for item in positions if item['status'] in {'PENDING', 'OPEN'}]
    candidate = [*active, request]
    stake = request['stake_minor']
    checks = {
        'position_minor': stake,
        'daily_exposure_minor': sum(p['stake_minor'] for p in candidate
                                    if p['exposure_date'] == request['exposure_date']),
        'strategy_exposure_minor': sum(
            p['stake_minor'] for p in candidate
            if resolved[p['position_sha256']]['strategy'] ==
            resolved[request['position_sha256']]['strategy']),
        'source_concentration_minor': sum(
            p['stake_minor'] for p in candidate
            if resolved[p['position_sha256']]['source'] ==
            resolved[request['position_sha256']]['source']),
        'event_exposure_minor': sum(
            p['stake_minor'] for p in candidate
            if resolved[p['position_sha256']]['event'] ==
            resolved[request['position_sha256']]['event']),
        'correlated_exposure_minor': max(
            sum(p['stake_minor'] for p in candidate if key in p['correlation_keys'])
            for key in request['correlation_keys']),
    }
    breaches = [name for name, value in checks.items()
                if limits[name] is None or value > limits[name]]
    return {
        'decision': 'DENY' if breaches else 'ALLOW',
        'environment': environment, 'checks_minor': checks,
        'breaches': breaches,
        'duplicate_opinions_diversify': False,
        'execution_authorized': False,
    }


def kill_event_sha(event: dict) -> str:
    return _unsigned_sha(event, 'event_sha256')


def replay_kill_switch(root: Path, events: list[dict], *, policy: dict | None = None,
                       expected_policy_source: str | None = None,
                       attestations: list[dict] | None = None,
                       stop_decision: dict | None = None,
                       health_ok: bool = False,
                       current_head: dict,
                       now: datetime | None = None) -> dict:
    current = _now(now)
    if not events:
        raise ValueError('Kill-switch state is missing')
    state = None
    generation = 0
    previous = None
    for sequence, event in enumerate(events, start=1):
        _shape(root, 'kill-switch-event', event)
        if kill_event_sha(event) != event['event_sha256']:
            raise ValueError('Kill-switch event digest mismatch')
        if (event['sequence'] != sequence or event['previous_event_sha256'] != previous or
                event['generation'] != generation + 1 or
                instant(event['occurred_at']) > current):
            raise ValueError('Kill-switch history is stale, forked, or invalid')
        if sequence == 1 and event['event_type'] != 'INITIAL_ENGAGE':
            raise ValueError('Kill switch must initialize ENGAGED')
        if event['event_type'] in {'INITIAL_ENGAGE', 'TRIGGER'}:
            if event['event_type'] == 'TRIGGER' and event['trigger'] not in KILL_TRIGGERS:
                raise ValueError('Unknown kill-switch trigger')
            state = 'ENGAGED'
        elif event['event_type'] == 'RESET':
            if state != 'ENGAGED' or not event['reset_attestation_ids'] or not event['remediation_refs']:
                raise ValueError('Kill reset lacks current authority or remediation')
            if event['phase'] == 'M0':
                raise ValueError('Kill switch cannot disengage during M0')
            if (policy is None or expected_policy_source is None or
                    attestations is None or stop_decision is None):
                raise ValueError('Kill reset trust and safety state is unavailable')
            validate_trust_policy(root, policy,
                                  expected_source=expected_policy_source,
                                  now=current)
            if stop_decision.get('decision') != 'ALLOW' or not health_ok:
                raise ValueError('Kill reset blocked by STOP or unhealthy controls')
            by_id = {item['attestation_id']: item for item in attestations}
            if len(by_id) != len(attestations):
                raise ValueError('Duplicate kill-reset attestation identity')
            actors = set()
            for identifier in event['reset_attestation_ids']:
                if identifier not in by_id:
                    raise ValueError('Kill reset attestation is missing')
                actor_id = verify_attestation(
                    root, by_id[identifier], policy,
                    expected_subject_type='KILL_SWITCH_RESET',
                    expected_subject_id=event['event_id'],
                    expected_subject_sha256=event['event_sha256'],
                    required_role='06_RISK', required_scope='KILL_RESET',
                    author_actor_ids=set(), now=current)
                if actor_id in actors:
                    raise ValueError('Duplicate kill-reset authority')
                actors.add(actor_id)
            state = 'DISENGAGED'
        else:
            raise ValueError('Unknown kill-switch event')
        generation = event['generation']
        previous = event['event_sha256']
    verify_current_head(events, current_head, digest_field='event_sha256',
                        label='Kill-switch history')
    return {'state': state, 'generation': generation,
            'last_event_sha256': previous, 'execution_authorized': False}


class JsonAuthorizationStore:
    """Trusted-host single-use action authorization registry."""

    def __init__(self, path: Path):
        self.path = path
        self.lock_path = path.with_name(path.name + '.lock')

    @staticmethod
    def initialize(path: Path, *, authority_id: str, generation: int) -> None:
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise ValueError('Authorization store target must be a new regular path')
        state = {'schema_version': 1, 'authority_id': authority_id,
                 'generation': generation, 'issued': [], 'consumed': []}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(state, handle, sort_keys=True, separators=(',', ':'))
            handle.write('\n'); handle.flush(); os.fsync(handle.fileno())

    def _read(self) -> dict:
        if not self.path.is_file() or self.path.is_symlink():
            raise ValueError('Action authorization state is unavailable')
        state = read(self.path)
        if set(state) != {'schema_version', 'authority_id', 'generation',
                          'issued', 'consumed'} or state['schema_version'] != 1:
            raise ValueError('Corrupt action authorization state')
        return state

    def _write(self, state: dict) -> None:
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + '.',
                                         dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                json.dump(state, handle, sort_keys=True, separators=(',', ':'))
                handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def issue(self, token: dict) -> None:
        self.lock_path.parent.mkdir(parents=False, exist_ok=True)
        with self.lock_path.open('a+b') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._read()
            if (token['authority_id'], token['authority_generation']) != (
                    state['authority_id'], state['generation']):
                raise ValueError('Authorization store generation mismatch')
            if any(item['token_id'] == token['token_id'] or
                   item['action_sha256'] == token['action_sha256']
                   for item in state['issued']):
                raise ValueError('Duplicate token or action authorization')
            state['issued'].append({
                'token_id': token['token_id'],
                'token_sha256': token['token_sha256'],
                'action_sha256': token['action_sha256'],
            })
            self._write(state)

    def consume(self, token: dict) -> None:
        self.lock_path.parent.mkdir(parents=False, exist_ok=True)
        with self.lock_path.open('a+b') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = self._read()
            matches = [item for item in state['issued']
                       if item['token_id'] == token['token_id'] and
                       item['token_sha256'] == token['token_sha256'] and
                       item['action_sha256'] == token['action_sha256']]
            if len(matches) != 1:
                raise ValueError('Action authorization was not durably issued')
            if token['token_id'] in state['consumed']:
                raise ValueError('Action authorization already consumed')
            state['consumed'].append(token['token_id'])
            self._write(state)


def validate_authorization_token(root: Path, token: dict, *, action: dict,
                                 decision: dict, current_state: dict,
                                 kill_state: dict,
                                 now: datetime | None = None) -> None:
    current = _now(now)
    _shape(root, 'risk-action', action)
    _shape(root, 'risk-decision', decision)
    _shape(root, 'action-authorization', token)
    if _unsigned_sha(action, 'action_sha256') != action['action_sha256']:
        raise ValueError('Action digest mismatch')
    if _unsigned_sha(token, 'token_sha256') != token['token_sha256']:
        raise ValueError('Authorization token digest mismatch')
    if instant(token['issued_at']) > current or instant(token['expires_at']) <= current:
        raise ValueError('Action authorization is future or expired')
    if (instant(token['expires_at']) > instant(action['expires_at']) or
            instant(token['expires_at']) > instant(current_state['valid_until'])):
        raise ValueError('Action authorization outlives action or current state')
    if token['token_id'] != decision['authorization_id']:
        raise ValueError('Action authorization identity mismatch')
    if (decision['action_sha256'] != action['action_sha256'] or
            decision['experiment_identity_sha256'] !=
            action['experiment_identity_sha256']):
        raise ValueError('Risk decision binding mismatch: action or experiment')
    expected = {
        'action_id': action['action_id'],
        'action_sha256': action['action_sha256'],
        'action_type': action['action_type'],
        'strategy_id': action['strategy_id'],
        'strategy_version': action['strategy_version'],
        'experiment_identity_sha256': action['experiment_identity_sha256'],
        'scientific_assessment_sha256':
            decision['scientific_assessment_sha256'],
        'scientific_commitment_sha256':
            decision['scientific_commitment_sha256'],
        'strategy_identity_sha256': action['strategy_identity_sha256'],
        'source_identity_sha256': action['source_identity_sha256'],
        'environment': action['environment'],
        'event_identity_sha256': action['event_identity_sha256'],
        'market_identity_sha256': action['market_identity_sha256'],
        'selection_identity_sha256': action['selection_identity_sha256'],
        'amount_minor': action['amount_minor'],
        'price_constraint_sha256': action['price_constraint_sha256'],
        'reservation_id': action['reservation_id'],
        'related_action_sha256': action['related_action_sha256'],
        'position_id': action['position_id'],
        'decision_sha256': decision['decision_sha256'],
        'current_state_sha256': current_state['state_sha256'],
        'authority_id': current_state['authority_id'],
        'authority_generation': current_state['generation'],
        'kill_generation': kill_state['generation'],
        'controls_sha256': decision['controls_sha256'],
        'exposure_state_sha256': current_state['exposure']['head']['inventory_sha256'],
        'ledger_head_sha256': current_state['ledger']['head']['inventory_sha256'],
    }
    for field, value in expected.items():
        if token[field] != value:
            raise ValueError('Action authorization binding mismatch: ' + field)
    if decision['verdict'] != 'AUTHORIZED' or not decision['execution_authorized']:
        raise ValueError('Decision does not authorize this action')
    if action['action_type'] == 'NEW_EXPOSURE' and kill_state['state'] != 'DISENGAGED':
        raise ValueError('Kill switch globally blocks new exposure')
    if action['action_type'] == 'SETTLEMENT' and not settlement_allowed_while_engaged(
            adds_exposure=False, reservation_exists=bool(action['reservation_id'])):
        raise ValueError('Settlement is not exposure-neutral')


def verify_execution_token(root: Path, token: dict, *, action: dict,
                           decision: dict, current_state: dict,
                           kill_state: dict, authorization_store: JsonAuthorizationStore,
                           now: datetime | None = None) -> None:
    validate_authorization_token(
        root, token, action=action, decision=decision,
        current_state=current_state, kill_state=kill_state, now=now)
    authorization_store.consume(token)


def risk_decision(root: Path, *, decision_id: str, decided_at: str,
                  action: str, environment: str, scientific: dict | None,
                  lifecycle: dict | None, stop: dict | None,
                  ledger: dict | None, exposure: dict | None,
                  kill: dict | None, capital_deployable_minor: int,
                  live_status: str, individual_authorization_current: bool,
                  phase: str = 'M0') -> dict:
    # Compatibility endpoint: caller-assembled control assertions are never an
    # authorization boundary.  Use assemble_authoritative_decision instead.
    reasons = ['LEGACY_CALLER_ASSERTED_STATE_UNTRUSTED']
    decision = {
        'schema_version': 1, 'decision_id': decision_id,
        'decided_at': decided_at, 'action': action, 'environment': environment,
        'action_sha256': None, 'experiment_identity_sha256': None,
        'scientific_assessment_sha256': None,
        'scientific_commitment_sha256': None,
        'authoritative_state_sha256': None,
        'scientific_consistent': False, 'lifecycle_eligible': False,
        'paper_eligible': False, 'live_eligible': False,
        'capital_available': False, 'individual_controls_current': False,
        'individual_authorization_current': False,
        'execution_authorized': False, 'verdict': 'DENIED',
        'reasons': reasons, 'control_digests': {},
        'controls_sha256': digest(canonical({})),
        'authority_generation': None, 'kill_generation': None,
        'authorization_id': None,
    }
    decision['decision_sha256'] = _unsigned_sha(decision, 'decision_sha256')
    _shape(root, 'risk-decision', decision)
    return decision


def _fixed_state_record(root: Path, binding: dict, *, path: str, kind: str) -> dict:
    if set(binding) != {'path', 'sha256'} or binding['path'] != path:
        raise ValueError('Authoritative fixed-state reference mismatch')
    target = (root / path).resolve()
    if (not target.is_relative_to(root.resolve()) or not target.is_file() or
            target.is_symlink() or digest(target.read_bytes()) != binding['sha256']):
        raise ValueError('Authoritative fixed-state bytes are unavailable')
    record = read(target)
    validate_record(kind, record, root)
    return record


def assemble_authoritative_decision(
        root: Path, action: dict, *, authority: RiskStateAuthority | None,
        policy: dict, expected_policy_source: str,
        scientific_replay_store: JsonReplayStore | None,
        authorization_store: JsonAuthorizationStore | None,
        now: datetime | None = None) -> tuple[dict, dict | None, dict]:
    """Derive one decision from a trusted current-state bundle and exact action."""
    current = _now(now)
    _shape(root, 'risk-action', action)
    if _unsigned_sha(action, 'action_sha256') != action['action_sha256']:
        raise ValueError('Action digest mismatch')
    if instant(action['created_at']) > current or instant(action['expires_at']) <= current:
        raise ValueError('Action is future or expired')
    if authority is None:
        raise ValueError('Verifier-controlled Risk current-state authority is required')
    state = authority.current_state(action['action_sha256'])
    _shape(root, 'risk-current-state', state)
    if _unsigned_sha(state, 'state_sha256') != state['state_sha256']:
        raise ValueError('Risk current-state digest mismatch')
    if state['action_sha256'] != action['action_sha256']:
        raise ValueError('Risk current state is bound to another action')
    if instant(state['generated_at']) > current or instant(state['valid_until']) <= current:
        raise ValueError('Risk current state is future or stale')
    project = _fixed_state_record(
        root, state['project_state'], path='docs/project-state.json',
        kind='project-state')
    bankroll = _fixed_state_record(
        root, state['bankroll'], path='portfolio/bankroll.json', kind='bankroll')
    risk_policy = _fixed_state_record(
        root, state['risk_policy'], path='portfolio/risk-policy.json',
        kind='risk-policy')
    if state['phase'] != project['phase'] or risk_policy['phase'] != project['phase']:
        raise ValueError('Risk phase conflicts with authoritative project state')

    if action['environment'] == 'PAPER':
        authoritative_opening = bankroll['paper_capital_minor']
    else:
        authoritative_opening = (bankroll['live_deployable_minor'] +
                                 bankroll['reserved_minor'])
    capital_configured = authoritative_opening is not None
    expected_opening = authoritative_opening if capital_configured else 0
    if state['ledger']['opening_minor'] != expected_opening:
        raise ValueError('Ledger opening is not derived from authoritative capital')

    graph = {key: set(values) for key, values in state['stop']['dependency_graph'].items()}
    stop_result = evaluate_stop_snapshot(
        root, state['stop']['snapshot'], action=action,
        dependency_graph=graph, stop_policy=state['stop']['policy'],
        current_head=state['stop']['head'], now=current)

    ledger_result = reconcile_ledger(
        root, state['ledger']['events'], state['ledger']['snapshot'],
        account=action['environment'],
        expected_opening_minor=expected_opening,
        current_head=state['ledger']['head'], now=current)
    if (action['environment'] == 'LIVE' and
            ledger_result['reserved_minor'] != bankroll['reserved_minor']):
        raise ValueError('Live ledger reservation conflicts with authoritative bankroll')

    kill_result = replay_kill_switch(
        root, state['kill']['events'], policy=policy,
        expected_policy_source=expected_policy_source,
        attestations=state['kill']['attestations'],
        stop_decision=stop_result, health_ok=state['kill']['health_ok'],
        current_head=state['kill']['head'], now=current)
    if ((risk_policy['kill_switch'] == 'ENGAGED') !=
            (kill_result['state'] == 'ENGAGED')):
        raise ValueError('Kill history conflicts with authoritative Risk policy')

    scientific_result = None
    lifecycle_result = None
    exposure_result = None
    if action['action_type'] == 'NEW_EXPOSURE':
        science = state['scientific']
        if science is None:
            raise ValueError('Exact scientific evidence is required for new exposure')
        if (science['strategy_id'], science['strategy_version'],
                science['experiment_identity_sha256']) != (
                action['strategy_id'], action['strategy_version'],
                action['experiment_identity_sha256']) or (
                science['assessment']['experiment_identity_sha256'] !=
                action['experiment_identity_sha256']) or (
                science['commitment']['experiment_identity_sha256'] !=
                action['experiment_identity_sha256']):
            raise ValueError('Scientific evidence is bound to another strategy or experiment')
        scientific_result = consume_scientific_commitment(
            root, science['assessment'], science['commitment'], policy=policy,
            expected_policy_source=expected_policy_source,
            replay_store=scientific_replay_store,
            assessment_author_ids=set(science['assessment_author_ids']), now=current)
        scientific_result.update({
            'strategy_id': science['strategy_id'],
            'strategy_version': science['strategy_version'],
            'experiment_identity_sha256':
                science['experiment_identity_sha256'],
            'assessment_sha256': science['assessment']['assessment_sha256'],
            'commitment_sha256': science['commitment']['commitment_sha256'],
            'action_sha256': action['action_sha256'],
        })
        lifecycle_result = replay_lifecycle(
            root, state['lifecycle']['events'], state['lifecycle']['attestations'],
            policy=policy, expected_policy_source=expected_policy_source,
            stop_decision=stop_result, scientific_evidence=scientific_result,
            current_head=state['lifecycle']['head'], now=current)
        request = state['exposure']['request']
        request_binding = {
            'action_sha256': action['action_sha256'],
            'position_id': action['position_id'],
            'environment': action['environment'],
            'stake_minor': action['amount_minor'],
            'strategy_identity_sha256': action['strategy_identity_sha256'],
            'source_identity_sha256': action['source_identity_sha256'],
            'event_identity_sha256': action['event_identity_sha256'],
            'market_identity_sha256': action['market_identity_sha256'],
            'selection_identity_sha256': action['selection_identity_sha256'],
        }
        if any(request[field] != value for field, value in request_binding.items()):
            raise ValueError('Exposure request is bound to another action')
        canonical_by_sha = {
            item['identity_sha256']: item
            for item in state['exposure']['canonical_identities']
        }
        strategy_identity = canonical_by_sha.get(action['strategy_identity_sha256'])
        if (not strategy_identity or
                strategy_identity.get('canonical_id') != action['strategy_id'] or
                strategy_identity.get('version') != action['strategy_version']):
            raise ValueError('Action strategy/version canonical identity mismatch')
        policy_limits = risk_policy['limits']
        authoritative_limits = {
            'position_minor': policy_limits['position_minor'],
            'daily_exposure_minor': policy_limits['daily_exposure_minor'],
            'strategy_exposure_minor': policy_limits['strategy_exposure_minor'],
            'source_concentration_minor': policy_limits['source_concentration_minor'],
            'event_exposure_minor': policy_limits['correlated_exposure_minor'],
            'correlated_exposure_minor': policy_limits['correlated_exposure_minor'],
        }
        if state['exposure']['limits'] != authoritative_limits:
            raise ValueError('Exposure limits are not derived from authoritative Risk policy')
        exposure_result = evaluate_exposure(
            root, state['exposure']['positions'], request,
            environment=action['environment'], limits=authoritative_limits,
            current_head=state['exposure']['head'],
            canonical_identities=state['exposure']['canonical_identities'])

    control_results = {
        'scientific': scientific_result,
        'lifecycle': lifecycle_result,
        'stop': stop_result,
        'ledger': ledger_result,
        'exposure': exposure_result,
        'kill': kill_result,
        'project_state_sha256': state['project_state']['sha256'],
        'bankroll_sha256': state['bankroll']['sha256'],
        'risk_policy_sha256': state['risk_policy']['sha256'],
    }
    control_digests = {
        key: digest(canonical(value)) for key, value in control_results.items()
    }
    controls_sha = digest(canonical(control_digests))
    science_ok = bool(scientific_result and
                      scientific_result['scientific_integrity_consistent'])
    lifecycle_ok = bool(lifecycle_result and lifecycle_result['lifecycle_eligible'])
    stop_ok = stop_result['decision'] == 'ALLOW'
    ledger_ok = ledger_result['reconciled']
    exposure_ok = bool(exposure_result and exposure_result['decision'] == 'ALLOW')
    kill_ok = kill_result['state'] == 'DISENGAGED'
    capital_ok = capital_configured and (
        ledger_result['cash_minor'] >= action['amount_minor'] if
        action['environment'] == 'PAPER' else
        risk_policy['live_enabled'] and bankroll['live_status'] == 'UNLOCKED' and
        bankroll['live_deployable_minor'] >= action['amount_minor'])
    reasons = []
    if action['action_type'] == 'NEW_EXPOSURE':
        for ok, reason in (
            (science_ok, 'SCIENTIFIC_EVIDENCE_UNAVAILABLE'),
            (lifecycle_ok, 'LIFECYCLE_INELIGIBLE'),
            (stop_ok, 'STOP_STATE_BLOCKS'), (ledger_ok, 'LEDGER_UNRECONCILED'),
            (exposure_ok, 'EXPOSURE_DENIED'), (kill_ok, 'KILL_SWITCH_ENGAGED'),
            (capital_ok, 'CAPITAL_UNAVAILABLE')):
            if not ok:
                reasons.append(reason)
        if action['environment'] == 'LIVE':
            if project['phase'] == 'M0': reasons.append('LIVE_UNAVAILABLE_IN_M0')
            if bankroll['live_status'] != 'UNLOCKED': reasons.append('LIVE_CAPITAL_LOCKED')
            if bankroll['live_deployable_minor'] <= 0: reasons.append('NO_DEPLOYABLE_CAPITAL')
    else:
        binding = ledger_result['open_reservation_bindings'].get(action['reservation_id'])
        if (not ledger_ok or not binding or
                binding['stake'] != action['amount_minor'] or
                binding['action_sha256'] != action['related_action_sha256'] or
                binding['position_id'] != action['position_id'] or
                binding['strategy_id'] != action['strategy_id'] or
                binding['strategy_version'] != action['strategy_version'] or
                binding['experiment_identity_sha256'] !=
                action['experiment_identity_sha256'] or
                binding['strategy_identity_sha256'] != action['strategy_identity_sha256'] or
                binding['event_identity_sha256'] != action['event_identity_sha256'] or
                binding['market_identity_sha256'] != action['market_identity_sha256'] or
                binding['selection_identity_sha256'] != action['selection_identity_sha256']):
            reasons.append('SETTLEMENT_RESERVATION_BINDING_INVALID')
        if not stop_ok:
            reasons.append('STOP_STATE_BLOCKS_SETTLEMENT')
    authorized = not reasons
    decision = {
        'schema_version': 1,
        'decision_id': state['decision_id'],
        'decided_at': current.isoformat().replace('+00:00', 'Z'),
        'action': action['action_type'], 'environment': action['environment'],
        'action_sha256': action['action_sha256'],
        'experiment_identity_sha256': action['experiment_identity_sha256'],
        'scientific_assessment_sha256': (
            state['scientific']['assessment']['assessment_sha256']
            if scientific_result else None),
        'scientific_commitment_sha256': (
            state['scientific']['commitment']['commitment_sha256']
            if scientific_result else None),
        'authoritative_state_sha256': state['state_sha256'],
        'scientific_consistent': science_ok,
        'lifecycle_eligible': lifecycle_ok,
        'paper_eligible': bool(lifecycle_result and
                               lifecycle_result['paper_eligible'] and
                               action['environment'] == 'PAPER'),
        'live_eligible': False,
        'capital_available': capital_ok,
        'individual_controls_current': stop_ok and ledger_ok and (
            exposure_ok and kill_ok if action['action_type'] == 'NEW_EXPOSURE' else True),
        'individual_authorization_current': authorized,
        'execution_authorized': authorized,
        'verdict': 'AUTHORIZED' if authorized else 'DENIED',
        'reasons': sorted(set(reasons)), 'control_digests': control_digests,
        'controls_sha256': controls_sha,
        'authority_generation': state['generation'],
        'kill_generation': kill_result['generation'],
        'authorization_id': (state['decision_id'] + ':authorization'
                             if authorized else None),
    }
    decision['decision_sha256'] = _unsigned_sha(decision, 'decision_sha256')
    _shape(root, 'risk-decision', decision)
    token = None
    if authorized:
        latest = authority.current_state(action['action_sha256'])
        if latest.get('state_sha256') != state['state_sha256']:
            raise ValueError('Risk current state changed before authorization commit')
        token = authority.commit_if_current(state['state_sha256'], decision)
        validate_authorization_token(
            root, token, action=action, decision=decision,
            current_state=state, kill_state=kill_result, now=current)
        if authorization_store is None:
            raise ValueError('Durable action authorization store is required')
        authorization_store.issue(token)
    return decision, token, state


def settlement_allowed_while_engaged(*, adds_exposure: bool,
                                     reservation_exists: bool) -> bool:
    """An engaged switch permits only exposure-neutral liability reduction."""
    return not adds_exposure and reservation_exists
