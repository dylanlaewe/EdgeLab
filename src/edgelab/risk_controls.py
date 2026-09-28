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
from typing import Iterable

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
    'risk-decision',
})


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
    matches = []
    for actor in policy['actors']:
        for authority in actor['authorities']:
            if authority['authority_id'] == commitment['authority_id']:
                matches.append((actor, authority))
    if len(matches) != 1:
        raise ValueError('Commitment authority is untrusted or ambiguous')
    actor, authority = matches[0]
    if authority['generation'] != commitment['generation']:
        raise ValueError('Commitment authority generation is stale')
    if 'SCIENTIFIC_COMMITMENT' not in actor['scopes']:
        raise ValueError('Authority lacks scientific commitment scope')
    authors = assessment_author_ids or set()
    if actor['actor_id'] in authors or set(actor['conflicts']) & authors:
        raise ValueError('Scientific authority is self-issued or conflicted')
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
                if not scientific_evidence or not scientific_evidence.get(
                        'scientific_integrity_consistent'):
                    raise ValueError('Required scientific evidence is unavailable')
            if destination in {'PAPER_ELIGIBLE', 'PAPER_TRADING'} and (
                    stop_decision.get('decision') != 'ALLOW'):
                raise ValueError('Applicable STOP state blocks paper lifecycle')
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
            if not required <= supplied_roles:
                raise ValueError('Required lifecycle approvals are missing')
        state = event['to_state']
        previous = event['event_sha256']
    return {
        'strategy_id': strategy[0], 'strategy_version': strategy[1],
        'state': state,
        'lifecycle_eligible': state in {'PAPER_ELIGIBLE', 'PAPER_TRADING'},
        'paper_eligible': state in {'PAPER_ELIGIBLE', 'PAPER_TRADING'},
        'live_eligible': False,
        'execution_authorized': False,
        'last_event_sha256': previous,
    }


def evaluate_stop_snapshot(root: Path, snapshot: dict, *, action: str,
                           targets: set[str], dependency_graph: dict[str, set[str]],
                           expected_stop_refs: set[str],
                           now: datetime | None = None) -> dict:
    current = _now(now)
    _shape(root, 'stop-snapshot', snapshot)
    if not snapshot['trusted'] or not snapshot['complete']:
        raise ValueError('Trusted complete STOP state is unavailable')
    if instant(snapshot['generated_at']) > current or instant(snapshot['valid_until']) <= current:
        raise ValueError('STOP state is future or stale')
    refs = {item['stop_ref'] for item in snapshot['stops']}
    if refs != expected_stop_refs:
        raise ValueError('STOP inventory is missing, substituted, or inconsistent')
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
        if record['status'] == 'OPEN' and action in item['actions']:
            scoped = quarantine(dependency_graph, item['scope'])
            hits = targets & scoped
            if hits or item['scope']['kind'] == 'global':
                blocked |= hits or targets
                applicable.append(record['id'])
    return {
        'decision': 'DENY' if applicable else 'ALLOW',
        'action': action,
        'targets': sorted(targets),
        'blocked_targets': sorted(blocked),
        'applicable_stop_ids': applicable,
        'stop_generation': snapshot['generation'],
        'execution_authorized': False,
    }


def validate_stop_clearance(root: Path, stop_record: dict, resolution: dict,
                            attestations: list[dict], *, policy: dict,
                            expected_policy_source: str,
                            now: datetime | None = None) -> dict:
    """Validate a candidate clearance event; never mutates the OPEN record."""
    current = _now(now)
    validate_trust_policy(root, policy, expected_source=expected_policy_source,
                          now=current)
    validate_record('stop', stop_record, root, now=current)
    _shape(root, 'stop-resolution-event', resolution)
    if stop_record['status'] != 'OPEN':
        raise ValueError('Clearance must refer to the preserved OPEN STOP')
    if _unsigned_sha(resolution, 'event_sha256') != resolution['event_sha256']:
        raise ValueError('STOP resolution digest mismatch')
    if (resolution['stop_id'], resolution['stop_version'],
            resolution['stop_sha256']) != (
            stop_record['id'], stop_record['version'],
            digest(canonical(stop_record))):
        raise ValueError('STOP resolution subject mismatch')
    if not resolution['acknowledged'] or not resolution['remediation_evidence']:
        raise ValueError('STOP acknowledgement or remediation evidence missing')
    if not resolution['descendants_revalidated']:
        raise ValueError('Quarantined descendants have not been revalidated')
    required = set(resolution['required_roles'])
    if resolution['capital_implicated']:
        required.add('06_RISK')
    subject = resolution['event_sha256']
    found_roles = set()
    actors = set()
    author_ids = set(resolution['remediation_author_actor_ids'])
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
                  expected_opening_minor: int, now: datetime | None = None) -> dict:
    current = _now(now)
    if account not in {'PAPER', 'LIVE'} or not events:
        raise ValueError('A typed nonempty paper/live ledger is required')
    cash = reserved = liability = realized = 0
    prior = None
    reservations: dict[str, dict] = {}
    settlements: dict[str, dict] = {}
    corrections: set[str] = set()
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
            cash = amount
        elif sequence == 1:
            raise ValueError('Ledger must begin with opening balance')
        elif kind == 'RESERVE':
            rid = event['reservation_id']
            if not rid or rid in reservations or amount <= 0 or amount > cash:
                raise ValueError('Invalid or duplicate reservation')
            cash -= amount
            reserved += amount
            liability += amount
            reservations[rid] = {'stake': amount, 'status': 'OPEN'}
        elif kind == 'RELEASE':
            rid = event['reservation_id']
            reservation = reservations.get(rid)
            if not reservation or reservation['status'] != 'OPEN' or amount != reservation['stake']:
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
                    sid in settlements or amount != reservation['stake'] or returned is None):
                raise ValueError('Duplicate or invalid settlement')
            cash += returned
            reserved -= amount
            liability -= amount
            realized += returned - amount
            reservation['status'] = 'SETTLED'
            settlements[sid] = {'return': returned, 'stake': amount}
        elif kind == 'CORRECT_SETTLEMENT':
            sid = event['settlement_id']
            corrected = event['return_minor']
            if sid not in settlements or sid in corrections or corrected is None or amount != 0:
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
    return {
        'account': account, 'currency': 'USD', 'opening_minor': expected_opening_minor,
        'cash_minor': cash, 'reserved_minor': reserved,
        'liability_minor': liability, 'realized_minor': realized,
        'sequence': len(events), 'last_event_sha256': prior,
        'open_reservations': sorted(
            key for key, value in reservations.items() if value['status'] == 'OPEN'),
    }


def reconcile_ledger(root: Path, events: list[dict], snapshot: dict, *,
                     account: str, expected_opening_minor: int,
                     now: datetime | None = None) -> dict:
    current = _now(now)
    _shape(root, 'ledger-snapshot', snapshot)
    if instant(snapshot['as_of']) > current or instant(snapshot['valid_until']) <= current:
        raise ValueError('Ledger reconciliation is future or stale')
    if _unsigned_sha(snapshot, 'snapshot_sha256') != snapshot['snapshot_sha256']:
        raise ValueError('Ledger snapshot digest mismatch')
    state = replay_ledger(root, events, account=account,
                          expected_opening_minor=expected_opening_minor, now=current)
    for field in ('account', 'currency', 'opening_minor', 'cash_minor',
                  'reserved_minor', 'liability_minor', 'realized_minor',
                  'sequence', 'last_event_sha256', 'open_reservations'):
        if snapshot[field] != state[field]:
            raise ValueError('Ledger snapshot does not reconcile: ' + field)
    return {**state, 'reconciled': True, 'snapshot_sha256': snapshot['snapshot_sha256']}


def evaluate_exposure(root: Path, positions: list[dict], request: dict, *,
                      environment: str, limits: dict[str, int | None]) -> dict:
    if set(limits) != EXPOSURE_LIMITS:
        raise ValueError('Complete exposure limits are required')
    if environment == 'LIVE' and any(value is None or value <= 0 for value in limits.values()):
        raise ValueError('Unresolved live exposure limits deny')
    if environment not in {'PAPER', 'LIVE'}:
        raise ValueError('Unknown exposure environment')
    for item in [*positions, request]:
        _shape(root, 'exposure-position', item)
        if item['environment'] != environment or item['stake_minor'] <= 0:
            raise ValueError('Mixed environment or nonpositive exposure')
        mandatory = {
            'event:' + item['event_id'], 'strategy:' + item['strategy_id'],
            'source:' + item['source_id'], 'market:' + item['market_id'],
            'selection:' + item['event_id'] + ':' + item['selection_id'],
        }
        if not mandatory <= set(item['correlation_keys']):
            raise ValueError('Exposure omits mandatory correlation dependencies')
    active = [item for item in positions if item['status'] == 'OPEN']
    candidate = [*active, request]
    stake = request['stake_minor']
    checks = {
        'position_minor': stake,
        'daily_exposure_minor': sum(p['stake_minor'] for p in candidate
                                    if p['exposure_date'] == request['exposure_date']),
        'strategy_exposure_minor': sum(p['stake_minor'] for p in candidate
                                       if p['strategy_id'] == request['strategy_id']),
        'source_concentration_minor': sum(p['stake_minor'] for p in candidate
                                          if p['source_id'] == request['source_id']),
        'event_exposure_minor': sum(p['stake_minor'] for p in candidate
                                    if p['event_id'] == request['event_id']),
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
    return {'state': state, 'generation': generation,
            'last_event_sha256': previous, 'execution_authorized': False}


def verify_execution_token(token: dict, *, kill_state: dict,
                           current_controls_sha256: str) -> None:
    if kill_state['state'] != 'DISENGAGED':
        raise ValueError('Kill switch globally blocks new exposure')
    if token.get('kill_generation') != kill_state['generation']:
        raise ValueError('Pending authorization invalidated by kill-switch change')
    if token.get('controls_sha256') != current_controls_sha256:
        raise ValueError('Pending authorization is stale')


def risk_decision(root: Path, *, decision_id: str, decided_at: str,
                  action: str, environment: str, scientific: dict | None,
                  lifecycle: dict | None, stop: dict | None,
                  ledger: dict | None, exposure: dict | None,
                  kill: dict | None, capital_deployable_minor: int,
                  live_status: str, individual_authorization_current: bool,
                  phase: str = 'M0') -> dict:
    reasons = []
    scientific_ok = bool(scientific and scientific.get('scientific_integrity_consistent'))
    lifecycle_ok = bool(lifecycle and lifecycle.get('lifecycle_eligible'))
    stop_ok = bool(stop and stop.get('decision') == 'ALLOW')
    ledger_ok = bool(ledger and ledger.get('reconciled'))
    exposure_ok = bool(exposure and exposure.get('decision') == 'ALLOW')
    kill_ok = bool(kill and kill.get('state') == 'DISENGAGED')
    capital_ok = capital_deployable_minor > 0
    for ok, reason in (
        (scientific_ok, 'SCIENTIFIC_EVIDENCE_UNAVAILABLE'),
        (lifecycle_ok, 'LIFECYCLE_INELIGIBLE'),
        (stop_ok, 'STOP_STATE_BLOCKS'),
        (ledger_ok, 'LEDGER_UNRECONCILED'),
        (exposure_ok, 'EXPOSURE_DENIED'),
        (kill_ok, 'KILL_SWITCH_ENGAGED'),
    ):
        if not ok:
            reasons.append(reason)
    if not individual_authorization_current:
        reasons.append('INDIVIDUAL_AUTHORIZATION_MISSING_OR_STALE')
    if environment == 'LIVE':
        if phase == 'M0':
            reasons.append('LIVE_UNAVAILABLE_IN_M0')
        if live_status != 'UNLOCKED':
            reasons.append('LIVE_CAPITAL_LOCKED')
        if not capital_ok:
            reasons.append('NO_DEPLOYABLE_CAPITAL')
    execution = not reasons and action == 'NEW_EXPOSURE'
    decision = {
        'schema_version': 1, 'decision_id': decision_id,
        'decided_at': decided_at, 'action': action, 'environment': environment,
        'scientific_consistent': scientific_ok,
        'lifecycle_eligible': lifecycle_ok,
        'paper_eligible': lifecycle_ok and environment == 'PAPER',
        'live_eligible': lifecycle_ok and environment == 'LIVE' and phase != 'M0',
        'capital_available': capital_ok,
        'individual_controls_current': stop_ok and ledger_ok and exposure_ok and kill_ok,
        'individual_authorization_current': individual_authorization_current,
        'execution_authorized': execution,
        'verdict': 'AUTHORIZED' if execution else 'DENIED',
        'reasons': sorted(set(reasons)),
    }
    decision['decision_sha256'] = _unsigned_sha(decision, 'decision_sha256')
    _shape(root, 'risk-decision', decision)
    return decision


def settlement_allowed_while_engaged(*, adds_exposure: bool,
                                     reservation_exists: bool) -> bool:
    """An engaged switch permits only exposure-neutral liability reduction."""
    return not adds_exposure and reservation_exists
