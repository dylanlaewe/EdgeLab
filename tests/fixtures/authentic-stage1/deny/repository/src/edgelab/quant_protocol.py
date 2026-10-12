"""Quant experiment identity, completeness, currency and reproduction checks.

These checks can establish a bounded scientific-integrity result under a
verifier-supplied current-state authority.  They never grant operational,
paper, live, Risk or capital authorization.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Protocol

from jsonschema import Draft202012Validator

from .data_integrity import (blob, canonical, digest, exact, sample_keys,
                             validate_data, verify_history)
from .research_protocol import check_confirmation_contract, research_record_snapshot
from .validate import CHECKER, instant, read, validate_record


QUANT_LOCATIONS = {
    'quant-protocol': 'research/experiment-protocols/*.json',
    'trial': 'research/trials/*.json',
    'trial-inventory': 'research/trial-inventories/*.json',
    'reproduction': 'research/reproductions/*.json',
}
SPLITS = ('train', 'validation', 'test', 'holdout')
TRIAL_STATUSES = ('ATTEMPTED', 'SUCCEEDED', 'FAILED', 'CANCELLED')


class CurrentStateAuthority(Protocol):
    """Externally trusted compare-and-commit boundary.

    ``commit_if_current`` must atomically compare ``expected_state_sha256`` to
    the authority's current accepted generation and commit the assessment, or
    reject without committing.  Quant cannot prove an adapter implements that
    promise; authority provisioning and custody remain external assumptions.
    """

    def current_state(self) -> dict: ...

    def commit_if_current(self, expected_state_sha256: str,
                          assessment: dict) -> dict: ...


def _shape(root: Path, kind: str, record: dict) -> None:
    schema = read(root / 'schemas' / f'{kind}.schema.json')
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=CHECKER).validate(record)


def checkpoint_digest(checkpoint: dict) -> str:
    return digest(canonical(checkpoint))


def state_digest(state: dict) -> str:
    unsigned = {key: value for key, value in state.items() if key != 'state_sha256'}
    return digest(canonical(unsigned))


def claim_identity(assessment: dict) -> str:
    """Hash the exact evidence references that define a confirmation claim."""
    return digest(canonical({
        field: assessment[field] for field in (
            'protocol_ref', 'preregistration_ref', 'trial_ref',
            'trial_inventory_ref', 'reproduction_ref', 'results_access_ref',
        )
    }))


def commitment_digest(commitment: dict) -> str:
    """Hash a commitment without its self-digest field."""
    unsigned = {
        key: value for key, value in commitment.items()
        if key != 'commitment_sha256'
    }
    return digest(canonical(unsigned))


def verify_authority_commitment(root: Path, assessment: dict,
                                commitment: dict, *, now=None) -> dict:
    """Verify a local binding, not external authority identity or honesty."""
    if not isinstance(commitment, dict):
        raise ValueError('Authority commitment must be a structured record')
    validate_record('authority-commitment', commitment, root, now=now)
    unsigned_assessment = {
        key: value for key, value in assessment.items()
        if key != 'assessment_sha256'
    }
    if digest(canonical(unsigned_assessment)) != assessment.get('assessment_sha256'):
        raise ValueError('Assessment digest mismatch')
    if commitment_digest(commitment) != commitment['commitment_sha256']:
        raise ValueError('Authority commitment digest mismatch')
    expected = {
        'authority_id': assessment['authority_id'],
        'generation': assessment['authority_generation'],
        'assessment_sha256': assessment['assessment_sha256'],
        'current_state_sha256': assessment['current_state_sha256'],
        'experiment_identity_sha256': assessment['experiment_identity_sha256'],
        'claim_identity_sha256': claim_identity(assessment),
    }
    for field, value in expected.items():
        if commitment[field] != value:
            raise ValueError('Authority commitment binding mismatch: ' + field)
    return commitment


def _git_is_ancestor(root: Path, older: str, newer: str) -> bool:
    result = subprocess.run(
        ['git', '-C', str(root), 'merge-base', '--is-ancestor', older, newer],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode not in (0, 1):
        raise ValueError('Unable to verify accepted-state ancestry')
    return result.returncode == 0


def _registry_snapshot(root: Path, locations: dict[str, str], *, now=None) -> dict[str, str]:
    found: dict[str, str] = {}
    for kind, pattern in locations.items():
        directory = root / pattern.split('*')[0]
        if directory.exists() and directory.is_symlink():
            raise ValueError('Aliased Quant registry')
        for path in sorted(root.glob(pattern)):
            if path.is_symlink() or not path.is_file():
                raise ValueError('Aliased Quant evidence')
            record = read(path)
            if record.get('kind') != kind:
                raise ValueError('Misplaced or untyped Quant evidence')
            relative = path.relative_to(root).as_posix()
            validate_record(kind, record, root, now=now)
            found[relative] = digest(path.read_bytes())
        if directory.exists():
            for path in sorted(directory.rglob('*')):
                if path.is_symlink():
                    raise ValueError('Aliased Quant evidence')
                if path.is_file() and path not in root.glob(pattern):
                    raise ValueError('Unrecognized or nested Quant registry evidence')
    return found


def quant_record_snapshot(root: Path, *, now=None) -> dict[str, str]:
    found = _registry_snapshot(root, QUANT_LOCATIONS, now=now)
    research = root / 'research'
    if not research.is_dir() or research.is_symlink():
        raise ValueError('Authoritative Quant evidence unavailable')
    for path in sorted(research.rglob('*')):
        if path.is_symlink():
            raise ValueError('Aliased Quant evidence')
        if not path.is_file() or path.suffix != '.json':
            continue
        relative = path.relative_to(root).as_posix()
        record = read(path)
        kind = record.get('kind') if isinstance(record, dict) else None
        if kind in QUANT_LOCATIONS:
            expected = root / QUANT_LOCATIONS[kind].split('*')[0]
            if path.parent != expected or relative not in found:
                raise ValueError('Misplaced or untyped Quant evidence')
    return found


def _record_ref(root: Path, kind: str, record: dict) -> dict:
    path = f"{QUANT_LOCATIONS[kind].split('*')[0]}{record['id']}.v{record['version']}.json"
    file = root / path
    return {'path': path, 'kind': kind, 'id': record['id'],
            'version': record['version'], 'sha256': digest(file.read_bytes())}


def _inventory_slice(inventory: dict[str, str], locations: dict[str, str]) -> dict[str, str]:
    prefixes = tuple(pattern.split('*')[0] for pattern in locations.values())
    return {path: sha for path, sha in inventory.items() if path.startswith(prefixes)}


def verify_current_state(root: Path, state: dict, *, now=None) -> None:
    """Verify a verifier-selected current accepted generation and its bytes."""
    validate_record('quant-current-state', state, root, now=now)
    if state_digest(state) != state['state_sha256']:
        raise ValueError('Current accepted-state digest mismatch')
    before = state['pre_access_checkpoint']
    current = state['current_checkpoint']
    if checkpoint_digest(before) != state['pre_access_checkpoint_sha256']:
        raise ValueError('Pre-access checkpoint digest mismatch')
    verify_history(root, before['baseline'], before['inventory'])
    verify_history(root, current['baseline'], current['inventory'])
    if not _git_is_ancestor(root, before['baseline'], current['baseline']):
        raise ValueError('Current accepted state rolls back pre-access history')
    accepted_research = _inventory_slice(current['inventory'], {
        'exposure': 'research/exposures/*.json',
        'preregistration': 'research/preregistrations/*.json',
    })
    if accepted_research != research_record_snapshot(root):
        raise ValueError('Current accepted Research registry mismatch')
    accepted_quant = _inventory_slice(current['inventory'], QUANT_LOCATIONS)
    if accepted_quant != quant_record_snapshot(root, now=now):
        raise ValueError('Current accepted Quant registry mismatch')


def _resolve_manifests(root: Path, refs: list[dict], *, now=None) -> tuple[list[dict], frozenset[str]]:
    records, keys = [], set()
    for ref in refs:
        record = exact(root, ref, {'manifest'}, now=now)
        validate_data(root, 'manifest', record, now=now)
        if record['purpose'] != 'decision':
            raise ValueError('Quant split input must be a decision manifest')
        membership = exact(root, record['membership_ref'], {'membership'}, now=now)
        records.append(record)
        keys.update(sample_keys(membership))
    return records, frozenset(keys)


def _validate_protocol_contents(root: Path, protocol: dict, *, now=None) -> tuple[dict, dict[str, frozenset[str]]]:
    registration = exact(root, protocol['preregistration_ref'], {'preregistration'}, now=now)
    if instant(protocol['frozen_at']) < instant(registration['frozen_at']):
        raise ValueError('Quant protocol predates Research freeze')
    for field, media_type in (('code', 'text/x-python'), ('configuration', 'application/json'),
                              ('environment', 'application/json'),
                              ('deterministic_settings', 'application/json')):
        value = protocol[field]
        if value['media_type'] != media_type:
            raise ValueError('Wrong Quant protocol blob type: ' + field)
        blob(root, value)
    randomness = protocol['randomness']
    if randomness['mode'] == 'SEEDED' and randomness['seed'] is None:
        raise ValueError('Seeded protocol requires seed')
    if randomness['mode'] == 'DETERMINISTIC_NO_RANDOMNESS' and randomness['seed'] is not None:
        raise ValueError('No-randomness protocol cannot carry seed')
    split_keys: dict[str, frozenset[str]] = {}
    split_records: dict[str, list[dict]] = {}
    seen_refs = set()
    for split in SPLITS:
        refs = protocol['splits'][split]
        if split in protocol['required_splits'] and not refs:
            raise ValueError('Required split is empty: ' + split)
        identities = [canonical(item) for item in refs]
        if len(identities) != len(set(identities)):
            raise ValueError('Duplicate manifest in split: ' + split)
        if seen_refs & set(identities):
            raise ValueError('Manifest assigned to multiple splits')
        seen_refs.update(identities)
        split_records[split], split_keys[split] = _resolve_manifests(root, refs, now=now)
        for manifest in split_records[split]:
            if (instant(manifest['created_at']) > instant(protocol['frozen_at']) or
                    instant(manifest['decision_at']) > instant(protocol['frozen_at'])):
                raise ValueError('Split manifest was not frozen before protocol')
    for index, left in enumerate(SPLITS):
        for right in SPLITS[index + 1:]:
            if split_keys[left] & split_keys[right]:
                raise ValueError(f'Canonical split overlap: {left}/{right}')
    holdout = exact(root, registration['holdout_ref'], {'exposure'}, now=now)
    holdout_membership = exact(root, holdout['membership_ref'], {'membership'}, now=now)
    if (len(split_records['holdout']) != 1 or
            split_records['holdout'][0]['membership_ref'] != holdout['membership_ref']):
        raise ValueError('Holdout manifest must bind exact preregistered membership reference')
    if split_keys['holdout'] != sample_keys(holdout_membership):
        raise ValueError('Actual holdout split does not equal preregistered membership')
    return registration, split_keys


def validate_protocol(root: Path, ref: dict, state: dict, *,
                      frozen_sha256: str, now=None) -> tuple[dict, dict, dict[str, frozenset[str]]]:
    if ref['sha256'] != frozen_sha256:
        raise ValueError('Verifier-held frozen Quant protocol digest required/mismatch')
    protocol = exact(root, ref, {'quant-protocol'}, now=now)
    validate_record('quant-protocol', protocol, root, now=now)
    if protocol['pre_access_checkpoint_sha256'] != state['pre_access_checkpoint_sha256']:
        raise ValueError('Frozen protocol is bound to a different pre-access checkpoint')
    registration, split_keys = _validate_protocol_contents(root, protocol, now=now)
    return protocol, registration, split_keys


def validate_trial(root: Path, ref: dict, protocol_ref: dict, protocol: dict, *,
                   now=None) -> dict:
    trial = exact(root, ref, {'trial'}, now=now)
    validate_record('trial', trial, root, now=now)
    if trial['protocol_ref'] != protocol_ref:
        raise ValueError('Trial protocol substitution')
    if trial['actual_splits'] != protocol['splits']:
        raise ValueError('Actual split manifests differ from frozen protocol')
    for split in SPLITS:
        _resolve_manifests(root, trial['actual_splits'][split], now=now)
    for field in ('code', 'configuration', 'environment', 'deterministic_settings', 'randomness'):
        if trial[field] != protocol[field]:
            raise ValueError('Trial changed frozen ' + field)
    if instant(trial['started_at']) < instant(protocol['frozen_at']):
        raise ValueError('Trial started before protocol freeze')
    if instant(trial['created_at']) < instant(trial['started_at']):
        raise ValueError('Trial record predates trial start')
    if trial['completed_at'] and instant(trial['completed_at']) < instant(trial['started_at']):
        raise ValueError('Trial completed before start')
    status = trial['status']
    if status == 'ATTEMPTED':
        if trial['completed_at'] is not None or trial['failure_reason'] is not None:
            raise ValueError('Attempted trial has terminal fields')
        if trial['outputs'] or trial['metrics'] is not None or trial['results_access_ref'] is not None:
            raise ValueError('Nonterminal trial cannot assert results')
    elif trial['completed_at'] is None:
        raise ValueError('Terminal trial requires completion time')
    if status == 'SUCCEEDED':
        if not trial['outputs'] or trial['metrics'] is None or trial['results_access_ref'] is None:
            raise ValueError('Successful trial requires outputs, metrics and results access')
        if trial['failure_reason'] is not None:
            raise ValueError('Successful trial cannot assert failure')
    elif status in {'FAILED', 'CANCELLED'} and trial['failure_reason'] is None:
        raise ValueError('Failed/cancelled trial requires reason')
    names = [item['name'] for item in trial['outputs']]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate output name')
    for item in trial['outputs']:
        blob(root, item['artifact'])
    if trial['metrics'] is not None:
        blob(root, trial['metrics'])
    if trial['results_access_ref'] is not None:
        access = exact(root, trial['results_access_ref'], {'exposure'}, now=now)
        if access['status'] != 'EXAMINED' or access['purpose'] != 'CONFIRMATORY_ACCESS':
            raise ValueError('Trial results access is not confirmatory examined evidence')
        accessed_at = instant(access['first_results_access_at'])
        if accessed_at < instant(trial['started_at']) or (
                trial['completed_at'] and accessed_at > instant(trial['completed_at'])):
            raise ValueError('Trial results access falls outside execution interval')
    return trial


def validate_trial_inventory(root: Path, ref: dict, *, now=None,
                             require_complete: bool = True) -> tuple[dict, list[tuple[dict, dict]]]:
    inventory = exact(root, ref, {'trial-inventory'}, now=now)
    validate_record('trial-inventory', inventory, root, now=now)
    current_snapshot = {path: sha for path, sha in quant_record_snapshot(root, now=now).items()
                        if path.startswith('research/trials/')}
    supplied_snapshot = {item['path']: item['sha256'] for item in inventory['trials']}
    if digest(canonical(supplied_snapshot)) != inventory['trial_registry_sha256']:
        raise ValueError('Trial registry snapshot mismatch')
    expected = set(current_snapshot)
    supplied = {item['path'] for item in inventory['trials']}
    if len(supplied) != len(inventory['trials']) or (
            require_complete and (supplied != expected or supplied_snapshot != current_snapshot)):
        raise ValueError('Trial inventory is incomplete')
    trials: list[tuple[dict, dict]] = []
    counts = {status: 0 for status in TRIAL_STATUSES}
    attempts = set()
    for trial_ref in inventory['trials']:
        trial = exact(root, trial_ref, {'trial'}, now=now)
        attempt = (canonical(trial['protocol_ref']), trial['attempt_ordinal'])
        if attempt in attempts:
            raise ValueError('Duplicate trial attempt ordinal')
        attempts.add(attempt)
        if instant(trial['created_at']) > instant(inventory['observed_through']):
            raise ValueError('Trial inventory coverage is stale')
        counts[trial['status']] += 1
        trials.append((trial_ref, trial))
    if counts != inventory['status_counts']:
        raise ValueError('Trial inventory status counts mismatch')
    return inventory, trials


def experiment_identity(protocol_ref: dict, trial_ref: dict, trial: dict,
                        inventory_ref: dict) -> str:
    return digest(canonical({
        'protocol_ref': protocol_ref,
        'preregistration_ref': trial['preregistration_ref'],
        'trial_ref': trial_ref,
        'actual_splits': trial['actual_splits'],
        'code': trial['code'],
        'configuration': trial['configuration'],
        'environment': trial['environment'],
        'randomness': trial['randomness'],
        'deterministic_settings': trial['deterministic_settings'],
        'results_access_ref': trial['results_access_ref'],
        'outputs': trial['outputs'],
        'metrics': trial['metrics'],
        'trial_inventory_ref': inventory_ref,
    }))


def verify_reproduction(root: Path, ref: dict, protocol_ref: dict, trial_ref: dict,
                        trial: dict, inventory_ref: dict,
                        reproducer: Callable[[Path, dict, dict], dict] | None, *,
                        now=None) -> dict:
    if reproducer is None:
        raise ValueError('Independent trusted reproducer required')
    reproduction = exact(root, ref, {'reproduction'}, now=now)
    validate_record('reproduction', reproduction, root, now=now)
    if reproduction['protocol_ref'] != protocol_ref or reproduction['trial_ref'] != trial_ref:
        raise ValueError('Reproduction subject mismatch')
    if (trial['completed_at'] is None or
            instant(reproduction['reproduced_at']) < instant(trial['completed_at']) or
            instant(reproduction['created_at']) < instant(reproduction['reproduced_at'])):
        raise ValueError('Invalid reproduction chronology')
    identity = experiment_identity(protocol_ref, trial_ref, trial, inventory_ref)
    if reproduction['experiment_identity_sha256'] != identity:
        raise ValueError('Reproduction experiment identity mismatch')
    originals = {item['name']: blob(root, item['artifact']) for item in trial['outputs']}
    reproduced = {}
    for item in reproduction['outputs']:
        if item['name'] in reproduced:
            raise ValueError('Duplicate reproduced output name')
        reproduced[item['name']] = blob(root, item['artifact'])
    if reproduced != originals:
        raise ValueError('Reproduced outputs differ from bound trial outputs')
    if trial['metrics'] is None or blob(root, reproduction['metrics']) != blob(root, trial['metrics']):
        raise ValueError('Reproduced metrics differ from bound trial metrics')
    rerun = reproducer(root, protocol_ref, trial_ref)
    if set(rerun) != {'outputs', 'metrics'} or rerun['outputs'] != originals:
        raise ValueError('Trusted deterministic rerun output mismatch')
    if rerun['metrics'] != blob(root, trial['metrics']):
        raise ValueError('Trusted deterministic rerun metrics mismatch')
    return reproduction


def validate_quant_record(root: Path, kind: str, record: dict, *, now=None) -> None:
    """Repository-level semantics; this is not confirmation eligibility."""
    validate_record(kind, record, root, now=now)
    if record['supersedes'] is not None:
        prior = exact(root, record['supersedes'], {kind}, now=now)
        if prior['id'] != record['id'] or prior['version'] != record['version'] - 1:
            raise ValueError('Quant correction requires exact predecessor')
        if instant(prior['created_at']) > instant(record['created_at']):
            raise ValueError('Quant correction precedes original')
    elif record['version'] != 1:
        raise ValueError('Quant correction requires predecessor')
    if kind == 'quant-protocol':
        _validate_protocol_contents(root, record, now=now)
    elif kind == 'trial':
        protocol = exact(root, record['protocol_ref'], {'quant-protocol'}, now=now)
        _validate_protocol_contents(root, protocol, now=now)
        validate_trial(root, _record_ref(root, kind, record),
                       record['protocol_ref'], protocol, now=now)
    elif kind == 'trial-inventory':
        validate_trial_inventory(root, _record_ref(root, kind, record), now=now,
                                 require_complete=False)
    else:
        exact(root, record['protocol_ref'], {'quant-protocol'}, now=now)
        exact(root, record['trial_ref'], {'trial'}, now=now)
        for item in record['outputs']:
            blob(root, item['artifact'])
        blob(root, record['metrics'])


def _deny_prior_holdout_use(root: Path, claimed_ref: dict,
                            all_trials: list[tuple[dict, dict]], holdout: frozenset[str],
                            access_at, *, now=None) -> None:
    """Deny a holdout consumed in any split before its proposed first access.

    Canonical membership keys, rather than manifest names or split labels, define
    consumption.  Missing results-access evidence never proves a failed,
    cancelled, or incomplete trial did not consume its declared inputs.
    """
    for ref, trial in all_trials:
        if ref == claimed_ref:
            continue
        if instant(trial['started_at']) > access_at:
            continue
        for split in SPLITS:
            _, values = _resolve_manifests(root, trial['actual_splits'][split], now=now)
            if values & holdout:
                raise ValueError(
                    'Prior/repeated trial consumed overlapping confirmatory holdout '
                    f'in {split} split; freshness is not established')


def assess_confirmation(root: Path, request: dict, authority: CurrentStateAuthority | None,
                        reproducer: Callable[[Path, dict, dict], dict] | None, *,
                        now=None) -> dict:
    """Assess one exact confirmation claim against current accepted evidence."""
    if authority is None:
        raise ValueError('Current accepted-state authority is required')
    state = authority.current_state()
    verify_current_state(root, state, now=now)
    if request.get('expected_current_state_sha256') != state['state_sha256']:
        raise ValueError('Stale or substituted current accepted state')
    protocol_ref = request['protocol_ref']
    protocol, registration, split_keys = validate_protocol(
        root, protocol_ref, state, frozen_sha256=request['frozen_protocol_sha256'], now=now)
    access_ref = request['results_access_ref']
    research_result = check_confirmation_contract(
        root, protocol['preregistration_ref'],
        frozen_sha256=protocol['preregistration_ref']['sha256'],
        access_ref=access_ref, disclosure_refs=[], now=now,
        history_baseline=state['pre_access_checkpoint']['baseline'],
        history_inventory=state['pre_access_checkpoint']['inventory'],
    )
    trial_ref = request['trial_ref']
    trial = validate_trial(root, trial_ref, protocol_ref, protocol, now=now)
    if trial['status'] != 'SUCCEEDED':
        raise ValueError('Confirmation claim requires a successful trial')
    if trial['preregistration_ref'] != protocol['preregistration_ref']:
        raise ValueError('Trial preregistration substitution')
    if trial['results_access_ref'] != access_ref:
        raise ValueError('Trial/result access substitution')
    inventory_ref = request['trial_inventory_ref']
    _, trials = validate_trial_inventory(root, inventory_ref, now=now)
    if trial_ref not in [ref for ref, _ in trials]:
        raise ValueError('Claimed trial absent from complete inventory')
    access = exact(root, access_ref, {'exposure'}, now=now)
    access_at = instant(access['first_results_access_at'])
    _deny_prior_holdout_use(
        root, trial_ref, trials, split_keys['holdout'], access_at, now=now)
    verify_reproduction(root, request['reproduction_ref'], protocol_ref, trial_ref,
                        trial, inventory_ref, reproducer, now=now)
    # Recheck all accepted bytes after the expensive assessment.  The atomic
    # compare-and-commit below is still required; this recheck alone is not CAS.
    verify_current_state(root, state, now=now)
    assessment = {
        'schema_version': 1,
        'status': 'SCIENTIFIC_INTEGRITY_CONSISTENT',
        'scientific_integrity_eligible': True,
        'operational_authorization': False,
        'paper_authorization': False,
        'live_authorization': False,
        'risk_approval': False,
        'protocol_ref': protocol_ref,
        'preregistration_ref': protocol['preregistration_ref'],
        'trial_ref': trial_ref,
        'trial_inventory_ref': inventory_ref,
        'reproduction_ref': request['reproduction_ref'],
        'results_access_ref': access_ref,
        'authority_id': state['authority_id'],
        'authority_generation': state['generation'],
        'current_state_sha256': state['state_sha256'],
        'experiment_identity_sha256': experiment_identity(protocol_ref, trial_ref, trial, inventory_ref),
        'research_contract_status': research_result['contract_status'],
        'history_completeness': 'VERIFIED_CURRENT_ACCEPTED_RESEARCH_AND_QUANT_REGISTRIES',
        'limitations': [
            'External authority integrity and atomic adapter behavior are assumed, not locally authenticated.',
            'Unrecorded off-system access and dishonest upstream canonical identities are not detectable.',
            'Scientific integrity does not establish profitability or operational eligibility.',
        ],
    }
    assessment['assessment_sha256'] = digest(canonical(assessment))
    return assessment


def commit_confirmation_claim(root: Path, request: dict,
                              authority: CurrentStateAuthority | None,
                              reproducer: Callable[[Path, dict, dict], dict] | None, *,
                              now=None) -> tuple[dict, dict]:
    """Assess, then atomically compare current generation and commit via authority."""
    assessment = assess_confirmation(root, request, authority, reproducer, now=now)
    assert authority is not None
    latest = authority.current_state()
    if latest.get('state_sha256') != assessment['current_state_sha256']:
        raise ValueError('Accepted state changed between assessment and commit')
    commitment = authority.commit_if_current(
        assessment['current_state_sha256'], assessment)
    verify_authority_commitment(root, assessment, commitment, now=now)
    return assessment, commitment
