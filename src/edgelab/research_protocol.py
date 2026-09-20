"""Declared exposure and frozen protocol checks, never operational approval.

Quant must supply complete trial/access history and a verifier-held freeze digest.
A digest authenticates bytes, not the truth or completeness of disclosures.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .data_integrity import blob, exact, sample_keys, validate_data
from .validate import instant, validate_record

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
        refs = [record['holdout_ref'], *record['exploratory_ancestors']]
        holdout_keys = sample_keys(parent(holdout['membership_ref'], {'membership'}))
        for exposure in exposure_closure(root, refs, now=now):
            if exposure['status'] == 'UNKNOWN':
                raise ValueError('Unknown exposure blocks freshness')
            if instant(exposure['created_at']) > frozen:
                raise ValueError('Exploratory disclosure after freeze')
            members = parent(exposure['membership_ref'], {'membership'})
            if exposure['status'] == 'EXAMINED' and holdout_keys & sample_keys(members):
                raise ValueError('Examined membership overlaps holdout')


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
                                disclosure_refs: list[dict], now: datetime | None = None) -> dict:
    """Check supplied evidence for one fresh first access; no authorization result.

The caller must obtain frozen_sha256 from a verifier-selected prior checkpoint,
not from the submitted candidate. Complete history/experiment binding is Quant's
responsibility. This function neither executes nor authorizes an experiment.
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
    refs = [*registration['exploratory_ancestors'], *disclosure_refs, *access['ancestors']]
    if access['supersedes']:
        refs.append(access['supersedes'])
    for exposed in exposure_closure(root, refs, now=now):
        if exposed['status'] == 'UNKNOWN':
            raise ValueError('Unknown exposure blocks freshness')
        keys = sample_keys(exact(root, exposed['membership_ref'], {'membership'}, now=now))
        if exposed['status'] == 'EXAMINED' and keys & holdout_keys:
            raise ValueError('Examined membership overlaps holdout')
    return {'contract_status': 'CONSISTENT_SUPPLIED_EVIDENCE',
            'membership_sha256': members['membership_sha256'],
            'operational_authorization': False,
            'history_completeness': 'CALLER_MUST_ESTABLISH'}
