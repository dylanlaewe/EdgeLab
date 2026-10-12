"""Authoritative Research exposure and frozen protocol checks, never approval.

A verifier selects accepted history; Research also checks all local typed records.
Quant owns complete execution evidence. Digests do not authenticate external truth.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .data_integrity import (blob, digest, exact, sample_keys, safe_path,
                             validate_data, verify_history)
from .validate import instant, read, validate_record, validate_repository

RESEARCH_LOCATIONS = {
    'exposure': 'research/exposures/*.json',
    'preregistration': 'research/preregistrations/*.json',
}


def validate_research(root: Path, kind: str, record: dict, *,
                      now: datetime | None = None, stack: tuple = ()) -> None:
    validate_record(kind, record, root, now=now)
    identity = (kind, record['id'], record['version'])
    if identity in stack:
        raise ValueError('Research dependency cycle')
    stack = (*stack, identity)

    def parent(ref: dict, expected: set[str]) -> dict:
        value = exact(root, ref, expected, now=now)
        if ref['kind'] in RESEARCH_LOCATIONS:
            validate_research(root, ref['kind'], value, now=now, stack=stack)
        elif ref['kind'] == 'membership':
            validate_data(root, 'membership', value, now=now)
        return value

    if record['supersedes'] is not None:
        prior = parent(record['supersedes'], {kind})
        if prior['id'] != record['id'] or prior['version'] != record['version'] - 1:
            raise ValueError('Research correction requires exact predecessor')
        if instant(prior['created_at']) > instant(record['created_at']):
            raise ValueError('Research correction precedes original')
    elif record['version'] != 1:
        raise ValueError('Research correction requires predecessor')

    if kind == 'exposure':
        membership = parent(record['membership_ref'], {'membership'})
        if instant(membership['created_at']) > instant(record['created_at']):
            raise ValueError('Exposure predates membership binding')
        blob(root, record['evidence'])
        if instant(record['coverage_through']) > instant(record['created_at']):
            raise ValueError('Exposure coverage exceeds recorded observation')
        access = record['first_results_access_at']
        if record['status'] == 'EXAMINED':
            if access is None or instant(access) > instant(record['coverage_through']):
                raise ValueError('Examined exposure requires first access within coverage')
        elif access is not None:
            raise ValueError('Unexamined/unknown exposure cannot assert first access')
        if (record['status'] == 'UNKNOWN') != (record['unknown_reason'] is not None):
            raise ValueError('Unknown exposure requires explicit reason')
        if record['status'] == 'UNEXAMINED' and record['purpose'] != 'HOLDOUT_CUSTODY':
            raise ValueError('Unexamined status requires holdout custody')
        for ref in record['ancestors']:
            ancestor = parent(ref, {'exposure'})
            if instant(ancestor['created_at']) > instant(record['created_at']):
                raise ValueError('Exposure ancestor recorded later than descendant')
    else:
        hypothesis = parent(record['hypothesis_ref'], {'hypothesis'})
        blob(root, record['analysis_plan'])
        frozen = instant(record['frozen_at'])
        if frozen > instant(record['created_at']) or instant(hypothesis['registered_at']) > frozen:
            raise ValueError('Retroactive or invalid registration ordering')
        if hypothesis['unresolved_thresholds']:
            raise ValueError('Unresolved thresholds block frozen registration')
        holdout = parent(record['holdout_ref'], {'exposure'})
        if holdout['status'] != 'UNEXAMINED':
            raise ValueError('Holdout must have known unexamined status')
        if instant(holdout['created_at']) > frozen or instant(holdout['coverage_through']) < frozen:
            raise ValueError('Holdout custody must cover freeze without retrospective disclosure')
        refs = registration_exposure_refs(root, record, now=now)
        holdout_keys = sample_keys(parent(holdout['membership_ref'], {'membership'}))
        for exposure in exposure_closure(root, refs, now=now):
            if exposure['status'] == 'UNKNOWN':
                raise ValueError('Unknown exposure blocks freshness')
            if instant(exposure['created_at']) > frozen:
                raise ValueError('Exploratory disclosure after freeze')
            members = parent(exposure['membership_ref'], {'membership'})
            if exposure['status'] == 'EXAMINED' and holdout_keys & sample_keys(members):
                raise ValueError('Examined membership overlaps holdout')


def registration_exposure_refs(root: Path, record: dict, *,
                               now: datetime | None = None) -> list[dict]:
    """Carry every predecessor custody/disclosure forward to the CURRENT holdout."""
    refs, seen = [], set()
    while True:
        identity = (record['id'], record['version'])
        if identity in seen:
            raise ValueError('Research dependency cycle')
        seen.add(identity)
        refs.extend([record['holdout_ref'], *record['exploratory_ancestors']])
        if record['supersedes'] is None:
            return refs
        record = exact(root, record['supersedes'], {'preregistration'}, now=now)


def exposure_closure(root: Path, refs: list[dict], *, now: datetime | None = None) -> list[dict]:
    """Include ancestors AND previous versions: corrections cannot erase exposure."""
    found = {}
    def visit(ref: dict) -> None:
        key = (ref['path'], ref['sha256'])
        if key in found:
            return
        record = exact(root, ref, {'exposure'}, now=now)
        validate_research(root, 'exposure', record, now=now)
        found[key] = record
        for child in record['ancestors'] + ([record['supersedes']] if record['supersedes'] else []):
            visit(child)
    for ref in refs:
        visit(ref)
    return list(found.values())


def check_confirmation_contract(root: Path, registration_ref: dict, *,
                                frozen_sha256: str | None, access_ref: dict,
                                disclosure_refs: list[dict], now: datetime | None = None,
                                history_baseline: str | None = None,
                                history_inventory: dict[str, str] | None = None) -> dict:
    """Research v2: verify a prior checkpoint and inspect all local Research records.

    The verifier supplies the baseline, its full Data inventory and the freeze pin.
    The checkpoint must include this registration but exclude proposed first access.
    No default checkpoint or submitter-selected disclosure subset provides assurance.
    Quant retains execution-time completeness, input binding and enforcement.
    """
    if frozen_sha256 is None or registration_ref['sha256'] != frozen_sha256:
        raise ValueError('Verifier-held frozen registration digest required/mismatch')
    registration = exact(root, registration_ref, {'preregistration'}, now=now)
    validate_research(root, 'preregistration', registration, now=now)
    holdout = exact(root, registration['holdout_ref'], {'exposure'}, now=now)
    access = exact(root, access_ref, {'exposure'}, now=now)
    validate_research(root, 'exposure', access, now=now)
    if access['status'] != 'EXAMINED' or access['purpose'] != 'CONFIRMATORY_ACCESS':
        raise ValueError('Known confirmatory first-access evidence required')
    if access['membership_ref'] != holdout['membership_ref']:
        raise ValueError('Exact holdout membership reference required')
    if instant(access['first_results_access_at']) <= instant(registration['frozen_at']):
        raise ValueError('First results access must strictly follow freeze')
    members = exact(root, holdout['membership_ref'], {'membership'}, now=now)
    holdout_keys = sample_keys(members)
    # The intended first access is excluded only at the top level. Its ancestors
    # remain disclosures, so a prior access cannot be hidden behind that exclusion.
    refs = [*registration_exposure_refs(root, registration, now=now),
            *disclosure_refs, *access['ancestors']]
    if access['supersedes']:
        refs.append(access['supersedes'])
    for exposed in exposure_closure(root, refs, now=now):
        if exposed['status'] == 'UNKNOWN':
            raise ValueError('Unknown exposure blocks freshness')
        keys = sample_keys(exact(root, exposed['membership_ref'], {'membership'}, now=now))
        if exposed['status'] == 'EXAMINED' and keys & holdout_keys:
            raise ValueError('Examined membership overlaps holdout')
    authoritative_refs, snapshot = authoritative_research_history(
        root, registration_ref, access_ref, history_baseline, history_inventory, now=now)
    for exposed in exposure_closure(root, authoritative_refs, now=now):
        if exposed['status'] == 'UNKNOWN':
            raise ValueError('Unknown exposure blocks authoritative freshness')
        keys = sample_keys(exact(root, exposed['membership_ref'], {'membership'}, now=now))
        if exposed['status'] == 'EXAMINED' and keys & holdout_keys:
            raise ValueError('Examined membership overlaps authoritative holdout')
    # Detect changed checked records; this is not an execution-time transaction.
    if research_record_snapshot(root) != snapshot:
        raise ValueError('Research evidence changed during assessment')
    verify_history(root, history_baseline, history_inventory)
    return {'contract_status': 'CONSISTENT_AUTHORITATIVE_RESEARCH_EVIDENCE',
            'membership_sha256': members['membership_sha256'],
            'operational_authorization': False,
            'history_completeness': 'VERIFIED_RESEARCH_REGISTRIES_ONLY',
            'history_baseline': history_baseline,
            'research_record_hashes': snapshot}


def research_record_snapshot(root: Path) -> dict[str, str]:
    """The authoritative local Research universe is both complete typed registries.

    Inspect all JSON under research/ too: a typed exposure/preregistration placed
    outside its registry is an error, not an invitation to silently omit it.
    Tests/reports are archived examples, not active Research registries.
    """
    found = {}
    research = root / 'research'
    if not research.is_dir() or research.is_symlink():
        raise ValueError('Authoritative Research evidence unavailable')
    for path in sorted(research.rglob('*')):
        if path.is_symlink():
            raise ValueError('Aliased Research evidence')
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        in_registry = any(relative.startswith(pattern.split('*')[0])
                          for pattern in RESEARCH_LOCATIONS.values())
        if in_registry and path.suffix != '.json':
            raise ValueError('Unrecognized Research registry evidence')
        if path.suffix != '.json':
            continue
        record = read(safe_path(root, relative))
        kind = record.get('kind') if isinstance(record, dict) else None
        if in_registry or kind in RESEARCH_LOCATIONS:
            if kind not in RESEARCH_LOCATIONS or path not in root.glob(RESEARCH_LOCATIONS[kind]):
                raise ValueError('Misplaced or untyped Research evidence')
            found[relative] = digest(path.read_bytes())
    return found


def authoritative_research_history(root: Path, registration_ref: dict, access_ref: dict,
                                   baseline: str | None, inventory: dict | None, *,
                                   now: datetime | None = None) -> tuple[list[dict], dict]:
    """No candidate-selected list can suppress a known local exposure.

    Data's verifier-supplied full checkpoint prevents deletion/rewrite of accepted
    history. Current additions are also checked, even when omitted from every
    registration. No prior recorded access can be exempted as the proposed access.
    """
    if baseline is None or inventory is None:
        raise ValueError('Authoritative history requires verifier baseline and full inventory')
    verified = verify_history(root, baseline, inventory)
    if verified.get(registration_ref['path']) != registration_ref['sha256']:
        raise ValueError('Frozen registration absent from authoritative checkpoint')
    if access_ref['path'] in verified:
        raise ValueError('Proposed first access already in authoritative history')
    snapshot = research_record_snapshot(root)
    # Data registry checks retain type, version, graph and temporal invariants.
    # This validates records; it does not integrate legacy experiment eligibility.
    validate_repository(root, now=now)
    refs = []
    for path, sha in snapshot.items():
        record = read(safe_path(root, path))
        ref = dict(path=path, kind=record['kind'], id=record['id'],
                   version=record['version'], sha256=sha)
        if record['kind'] == 'exposure':
            # Exactly this new proposed access may be excluded, never its parents.
            if ref != access_ref:
                refs.append(ref)
            else:
                refs.extend(record['ancestors'])
                if record['supersedes']:
                    refs.append(record['supersedes'])
        else:
            refs.extend(registration_exposure_refs(root, record, now=now))
    return refs, snapshot
