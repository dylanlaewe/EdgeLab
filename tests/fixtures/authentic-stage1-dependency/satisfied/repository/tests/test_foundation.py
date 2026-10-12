"""Synthetic contract attacks; fixtures are not research evidence."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from jsonschema import ValidationError
from src.edgelab.validate import ROOT, read, validate_record, validate_repository


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.bank = read(ROOT / 'portfolio/bankroll.json')
        self.risk = read(ROOT / 'portfolio/risk-policy.json')

    def denied(self, kind, record):
        with self.assertRaises((ValueError, ValidationError)):
            validate_record(kind, record)

    def test_repository(self):
        self.assertGreaterEqual(validate_repository(), 3)

    def test_capital_mutations_denied(self):
        for field, value in [('total_minor', 5001), ('live_deployable_minor', 1),
                             ('reserved_minor', 1), ('live_status', 'UNLOCKED'),
                             ('paper_capital_minor', 5000), ('currency', 'EUR')]:
            with self.subTest(field=field):
                self.denied('bankroll', {**self.bank, field: value})

    def test_missing_and_unknown_fields(self):
        for field in self.bank:
            record = self.bank.copy()
            del record[field]
            self.denied('bankroll', record)
        self.denied('bankroll', {**self.bank, 'override': True})

    def test_timestamp_requires_real_date_and_offset(self):
        for value in ['2026-09-19T12:00:00', '2026-02-30T00:00:00Z', 'yesterday']:
            self.denied('bankroll', {**self.bank, 'as_of': value})
        validate_record('bankroll', {**self.bank, 'as_of': '2026-09-19T12:00:00-04:00'})

    def test_live_enable_and_kill_reset_denied(self):
        for field, value in [('live_enabled', True), ('kill_switch', 'DISENGAGED')]:
            self.denied('risk-policy', {**self.risk, field: value})

    def test_each_exposure_limit_locked(self):
        for field in self.risk['limits']:
            record = copy.deepcopy(self.risk)
            record['limits'][field] = 1
            self.denied('risk-policy', record)

    def test_gate_removal_replacement_and_duplication_denied(self):
        gates = self.risk['live_gate_requirements']
        for altered in [gates[:-1], gates[:-1] + ['director_override'], gates[:-1] + [gates[0]]]:
            self.denied('risk-policy', {**self.risk, 'live_gate_requirements': altered})

    def test_missing_portfolio_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                validate_repository(Path(directory))

    def test_missing_unused_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'schemas', root / 'schemas')
            shutil.copytree(ROOT / 'portfolio', root / 'portfolio')
            (root / 'schemas/hypothesis.schema.json').unlink()
            with self.assertRaisesRegex(ValueError, 'hypothesis.schema.json'):
                validate_repository(root)

    def test_duplicate_json_keys_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.json'
            path.write_text('{"live_status":"LOCKED","live_status":"UNLOCKED"}')
            with self.assertRaises(ValueError):
                read(path)

    def test_handoff_missing_evidence_denied(self):
        record = read(ROOT / 'docs/handoffs/H-M0-001.v1.json')
        self.denied('handoff', {**record, 'evidence_refs': ['missing.md']})
        self.denied('handoff', {**record, 'evidence_refs': ['../../outside.md']})

    def fixture(self, kind):
        # Populate a syntactically complete synthetic record from its schema.
        props = read(ROOT / 'schemas' / f'{kind}.schema.json')['properties']
        def value(spec):
            if 'const' in spec:
                return spec['const']
            if 'enum' in spec:
                return spec['enum'][0]
            if spec.get('format') == 'date-time':
                return '2026-09-19T12:00:00Z'
            if 'anyOf' in spec:
                return None
            if spec.get('type') == 'array':
                return ['synthetic'] if spec.get('minItems') else []
            if spec.get('type') == 'integer':
                return 1
            if isinstance(spec.get('type'), list):
                return None
            return 'synthetic'
        return {key: value(spec) for key, spec in props.items()}

    def test_live_states_denied_even_with_review_strings(self):
        record = self.fixture('strategy')
        validate_record('strategy', record)
        for state in ['LIVE_CANDIDATE', 'LIVE_APPROVED', 'LIVE']:
            self.denied('strategy', {**record, 'state': state, 'review_refs': ['approved']})
        self.denied('strategy', {**record, 'state': 'REGISTERED'})

    def test_stop_resolution_requires_event(self):
        record = self.fixture('stop')
        validate_record('stop', record)
        self.denied('stop', {**record, 'status': 'RESOLVED'})
        self.denied('stop', {**record, 'resolution_event_ref': 'fake'})

    def test_permission_requires_evidence(self):
        record = self.fixture('source')
        record['url'] = 'https://example.invalid/synthetic'
        validate_record('source', record)
        self.denied('source', {**record, 'access_status': 'PERMITTED'})

    def test_protocol_and_completion_order(self):
        record = self.fixture('experiment')
        validate_record('experiment', record)
        self.denied('experiment', {**record, 'started_at': '2026-09-18T12:00:00Z'})
        self.denied('experiment', {**record, 'completed_at': '2026-09-18T12:00:00Z'})
        self.denied('experiment', {**record, 'result': 'REJECTED'})

    def test_confirmation_requires_registration(self):
        self.denied('experiment', {**self.fixture('experiment'), 'mode': 'CONFIRMATORY'})

    def test_confirmation_thresholds_and_registration_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'schemas', root / 'schemas')
            hypothesis = self.fixture('hypothesis')
            path = root / 'hypothesis.json'
            experiment = {**self.fixture('experiment'), 'mode': 'CONFIRMATORY', 'hypothesis_ref': 'hypothesis.json'}
            for thresholds, registered, valid in [([], '2026-09-18T12:00:00Z', True),
                                                (['unknown'], '2026-09-18T12:00:00Z', False),
                                                ([], '2026-09-20T12:00:00Z', False)]:
                path.write_text(json.dumps({**hypothesis, 'unresolved_thresholds': thresholds, 'registered_at': registered}))
                if valid:
                    validate_record('experiment', experiment, root)
                else:
                    with self.assertRaises(ValueError):
                        validate_record('experiment', experiment, root)

    def test_duplicate_identities_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder in ['schemas', 'portfolio', 'reports/stops']:
                shutil.copytree(ROOT / folder, root / folder)
            record = self.fixture('stop')
            for name in ['one', 'two']:
                (root / 'reports/stops' / f'{name}.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'Duplicate record identity'):
                validate_repository(root)


if __name__ == '__main__':
    unittest.main()
