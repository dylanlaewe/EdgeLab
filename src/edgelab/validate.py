"""Validate repository records and fail-closed M0 invariants."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
GATES = {
    'reliable_data', 'reproducible_research', 'registered_strategy',
    'historical_evaluation_where_appropriate', 'robustness_analysis',
    'independent_adversarial_review', 'forward_paper_evidence',
    'bankroll_accounting', 'risk_limits', 'kill_switches',
    'validated_execution_logic', 'audit_logging', 'strategy_specific_live_approval',
}
LOCATIONS = {
    'source': 'data/sources/*.json', 'hypothesis': 'research/hypotheses/*.json',
    'experiment': 'research/experiments/*.json', 'strategy': 'strategies/*.json',
    'audit': 'reports/audit/*.json', 'handoff': 'docs/handoffs/*.json',
    'stop': 'reports/stops/*.json', 'bankroll': 'portfolio/bankroll.json',
    'risk-policy': 'portfolio/risk-policy.json',
}
CHECKER = FormatChecker()


@CHECKER.checks('date-time', raises=(ValueError, TypeError))
def timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return True  # Type validation belongs to the schema.
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00')).utcoffset() is not None


def read(path: Path) -> dict:
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'Duplicate JSON key: {key}')
            result[key] = value
        return result
    def invalid_constant(value: str) -> None:
        raise ValueError(f'Nonfinite JSON number: {value}')
    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=invalid_constant)


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.upper().replace('Z', '+00:00'))


def reference(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f'Missing or non-repository reference: {value}')
    return path


def validate_record(kind: str, record: dict, root: Path = ROOT, *, now: datetime | None = None) -> None:
    schema = read(root / 'schemas' / f'{kind}.schema.json')
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=CHECKER).validate(record)
    from .data_integrity import clock_checks, permission_check
    clock_checks(record, now)
    if kind == 'risk-policy' and set(record['live_gate_requirements']) != GATES:
        raise ValueError('All thirteen exact capital gates are required')
    if kind == 'source' and record['access_status'] == 'PERMITTED':
        permission_check(root, record, now)
    if kind == 'stop':
        if (record['status'] == 'RESOLVED') != (record['resolution_event_ref'] is not None):
            raise ValueError('STOP resolution status and event must agree')
        if record['resolution_event_ref']:
            reference(root, record['resolution_event_ref'])
    if kind == 'strategy':
        if record['state'] in {'LIVE_CANDIDATE', 'LIVE_APPROVED', 'LIVE'}:
            raise ValueError('Live lifecycle states unavailable during M0')
        if record['state'] != 'IDEA' and record['hypothesis_ref'] is None:
            raise ValueError('Non-IDEA strategy requires a hypothesis')
    if kind == 'experiment':
        if instant(record['protocol_frozen_at']) > instant(record['started_at']):
            raise ValueError('Protocol must be frozen before execution')
        if record['completed_at'] and instant(record['completed_at']) < instant(record['started_at']):
            raise ValueError('Completion precedes start')
        if record['result'] != 'PENDING':
            if not all(record[k] for k in ('completed_at', 'metrics_ref', 'uncertainty_ref', 'robustness_ref')):
                raise ValueError('Completed outcomes require result artifacts and completion time')
        if record['mode'] == 'CONFIRMATORY':
            if record['hypothesis_ref'] is None:
                raise ValueError('Confirmation requires preregistration')
            hypothesis = read(reference(root, record['hypothesis_ref']))
            validate_record('hypothesis', hypothesis, root, now=now)
            if hypothesis['unresolved_thresholds']:
                raise ValueError('Unresolved thresholds block confirmation')
            if instant(hypothesis['registered_at']) > instant(record['protocol_frozen_at']):
                raise ValueError('Hypothesis registered after protocol freeze')
    if kind == 'handoff':
        for ref in record['evidence_refs']:
            reference(root, ref)


def validate_repository(root: Path = ROOT, *, now: datetime | None = None,
                        baseline: str | None = None) -> int:
    from .data_integrity import DATA_LOCATIONS, validate_data, registry_checks, verify_history
    locations = {**LOCATIONS, **DATA_LOCATIONS}
    for kind in locations:
        path = reference(root, f'schemas/{kind}.schema.json')
        Draft202012Validator.check_schema(read(path))
    for required in ('portfolio/bankroll.json', 'portfolio/risk-policy.json'):
        reference(root, required)
    count = 0
    seen = set()
    records = {}
    for kind, pattern in locations.items():
        for path in sorted(root.glob(pattern)):
            record = read(path)
            try:
                if kind in DATA_LOCATIONS:
                    validate_data(root, kind, record, now=now)
                else:
                    validate_record(kind, record, root, now=now)
                if 'id' in record:
                    key = (kind, record['id'], record['version'])
                    if key in seen:
                        raise ValueError(f'Duplicate record identity: {key}')
                    seen.add(key)
            except Exception as error:
                raise ValueError(f'{path.relative_to(root)}: {error}') from error
            records[path.relative_to(root).as_posix()] = (kind, record)
            count += 1
    registry_checks(root, records, now=now)
    state = root / 'docs/project-state.json'
    if state.exists():
        validate_record('project-state', read(state), root, now=now)
        count += 1
    # Legacy experiment schema remains readable; persisted inputs must be typed.
    for kind, record in records.values():
        if kind == 'experiment':
            for ref in record['dataset_manifests']:
                path = reference(root, ref)
                if path not in root.resolve().glob(DATA_LOCATIONS['manifest']):
                    raise ValueError('Experiment input must be typed manifest')
                manifest = read(path)
                validate_data(root, 'manifest', manifest, now=now)
                if record['mode'] == 'CONFIRMATORY' and (manifest['purpose'] != 'decision' or instant(manifest['decision_at']) > instant(record['started_at'])):
                    raise ValueError('Unsafe confirmation input purpose or decision time')
    if baseline is not None:
        verify_history(root, baseline)
    return count


if __name__ == '__main__':
    import argparse
    from .data_integrity import INITIAL_BASELINE
    parser = argparse.ArgumentParser(description='Data structural checks, never operational approval')
    parser.add_argument('--baseline', default=INITIAL_BASELINE,
                        help='Verifier-selected full published-history commit; not a moving ref')
    args = parser.parse_args()
    print(f'Validated {validate_repository(baseline=args.baseline)} records and published history; M0 capital remains LOCKED. No scientific or operational approval.')
