"""Synthetic M0.1 review probes, never research evidence.

Known-gap tests deliberately assert CURRENT ACCEPTANCE, not safety. They must
be replaced by rejection regressions when the referenced finding is remediated.
All mutations occur in disposable repositories; production policy is unchanged.
"""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from jsonschema import ValidationError
from src.edgelab.validate import ROOT, LOCATIONS, read, validate_record, validate_repository
import test_foundation


class SkepticAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for folder in ('schemas', 'portfolio'):
            shutil.copytree(ROOT / folder, self.root / folder)
        self.write('evidence.txt', {'synthetic': True})

    def write(self, path, record):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(record))
        return path

    def fixture(self, kind):
        if kind in ('bankroll', 'risk-policy'):
            return read(ROOT / 'portfolio' / f'{kind}.json')
        r = test_foundation.FoundationTests().fixture(kind)
        if kind == 'source':
            r['url'] = 'https://example.invalid/synthetic'
        if kind == 'handoff':
            r['evidence_refs'] = ['evidence.txt']
        return r

    def accept(self, kind, record):
        validate_record(kind, record, self.root)

    def reject(self, kind, record):
        with self.assertRaises((ValueError, ValidationError)):
            self.accept(kind, record)

    def test_all_nine_schemas_reject_missing_extra_and_incompatible_version(self):
        for kind in LOCATIONS:
            r = self.fixture(kind)
            self.accept(kind, r)
            for field in r:
                with self.subTest(kind=kind, missing=field):
                    x = copy.deepcopy(r)
                    del x[field]
                    self.reject(kind, x)
            self.reject(kind, {**r, 'unexpected': True})
            self.reject(kind, {**r, 'schema_version': 2})

    def test_all_timestamp_fields_reject_malformed_dates(self):
        for kind in LOCATIONS:
            r = self.fixture(kind)
            for field, spec in read(self.root / f'schemas/{kind}.schema.json')['properties'].items():
                if 'date-time' in json.dumps(spec):
                    for bad in ('yesterday', '2026-02-30T12:00:00Z', '2026-09-19T12:00:00'):
                        with self.subTest(kind=kind, field=field, bad=bad):
                            self.reject(kind, {**r, field: bad})

    def test_capital_negative_creation_overdeployment_and_kill_reset_denied(self):
        for field in ('total_minor', 'live_deployable_minor', 'reserved_minor'):
            for value in (-1, 5001, 10000):
                self.reject('bankroll', {**self.fixture('bankroll'), field: value})
        self.reject('risk-policy', {**self.fixture('risk-policy'), 'kill_switch': 'DISENGAGED'})

    def test_all_requested_live_skips_denied(self):
        for previous in ('IDEA', 'BACKTESTED', 'REJECTED'):
            for state in ('LIVE_CANDIDATE', 'LIVE_APPROVED', 'LIVE'):
                with self.subTest(previous=previous, state=state):
                    self.reject('strategy', {**self.fixture('strategy'), 'state': state,
                                            'hypothesis_ref': 'missing', 'transition_event_refs': [previous]})

    def test_H01_paper_promotion_without_evidence_accepted(self):
        for state in ('REGISTERED', 'BACKTESTED', 'PAPER_ELIGIBLE', 'PAPER_TRADING'):
            with self.subTest(state=state):
                r = {**self.fixture('strategy'), 'state': state, 'hypothesis_ref': 'nonexistent.v999.json'}
                self.write('strategies/S.v1.json', r)
                self.assertEqual(validate_repository(self.root), 3)

    def test_H01_rejected_version_resurrected_and_conflicting_versions_accepted(self):
        r = {**self.fixture('strategy'), 'state': 'REJECTED', 'hypothesis_ref': 'missing'}
        self.write('strategies/S.v1.json', r)
        self.write('strategies/S.v2.json', {**r, 'version': 2, 'state': 'PAPER_TRADING'})
        self.assertEqual(validate_repository(self.root), 4)
        r['state'] = 'PAPER_ELIGIBLE'
        self.write('strategies/S.v1.json', r)
        self.assertEqual(validate_repository(self.root), 4)

    def test_H02_single_actor_can_claim_all_approvals(self):
        for i, role in enumerate(('03 Research', '05 Skeptic', '06 Risk & Execution')):
            r = {**self.fixture('audit'), 'id': f'A-{i}', 'actor': 'same-author',
                 'role': role, 'event_type': 'APPROVED', 'subject_ref': 'missing-strategy'}
            self.write(f'reports/audit/A-{i}.v1.json', r)
        self.assertEqual(validate_repository(self.root), 5)

    def test_H03_open_stop_does_not_block_affected_paper_state(self):
        self.write('reports/stops/STOP.v1.json', {**self.fixture('stop'),
                   'affected_components': ['strategies/S.v1.json']})
        self.write('strategies/S.v1.json', {**self.fixture('strategy'),
                   'state': 'PAPER_TRADING', 'hypothesis_ref': 'missing',
                   'active_stop_refs': ['reports/stops/STOP.v1.json']})
        self.assertEqual(validate_repository(self.root), 4)

    def test_H03_stop_resolved_by_arbitrary_file(self):
        self.accept('stop', {**self.fixture('stop'), 'status': 'RESOLVED',
                            'resolution_event_ref': 'evidence.txt'})

    def confirmatory(self):
        self.write('research/hypotheses/H.v1.json', self.fixture('hypothesis'))
        return {**self.fixture('experiment'), 'mode': 'CONFIRMATORY',
                'hypothesis_ref': 'research/hypotheses/H.v1.json'}

    def test_H04_completed_confirmation_without_reproduction_inputs_accepted(self):
        r = {**self.confirmatory(), 'result': 'PROMISING_REQUIRES_REVIEW',
             'completed_at': '2026-09-19T13:00:00Z', 'metrics_ref': 'missing',
             'uncertainty_ref': 'missing', 'robustness_ref': 'missing'}
        self.write('research/experiments/E.v1.json', r)
        self.assertEqual(validate_repository(self.root), 4)

    def test_H04_late_unknown_and_mutated_lineage_accepted(self):
        r = self.confirmatory()
        r['dataset_manifests'] = ['data/derived/manifest.json']
        for available in (None, '2026-09-20T00:00:00Z'):
            self.write('data/derived/manifest.json', {'available_at': available,
                       'decision_at': '2026-09-18T00:00:00Z', 'sha256': 'incorrect'})
            self.write('research/experiments/E.v1.json', r)
            self.assertEqual(validate_repository(self.root), 4)

    def test_H05_explored_dataset_reused_as_confirmation(self):
        r = self.confirmatory()
        explored = {**self.fixture('experiment'), 'id': 'explored',
                    'protocol_frozen_at': '2026-09-18T00:00:00Z',
                    'started_at': '2026-09-18T00:00:00Z', 'completed_at': '2026-09-18T01:00:00Z',
                    'result': 'PROMISING_REQUIRES_REVIEW', 'metrics_ref': 'evidence.txt',
                    'uncertainty_ref': 'evidence.txt', 'robustness_ref': 'evidence.txt'}
        self.assertEqual(explored['dataset_manifests'], r['dataset_manifests'])
        self.write('research/experiments/explored.v1.json', explored)
        self.write('research/experiments/confirmed.v1.json', r)
        self.assertEqual(validate_repository(self.root), 5)

    def test_H06_history_mutation_deletion_and_circular_supersession_accepted(self):
        path = 'reports/audit/A.v1.json'
        r = {**self.fixture('audit'), 'supersedes': path}
        self.write(path, r)
        self.assertEqual(validate_repository(self.root), 3)
        self.write(path, {**r, 'reason': 'erased earlier reason'})
        self.assertEqual(validate_repository(self.root), 3)
        (self.root / path).unlink()
        self.assertEqual(validate_repository(self.root), 2)

    def test_M01_identifiers_filenames_dependencies_and_project_state_unchecked(self):
        r = {**self.fixture('handoff'), 'id': '../ malformed id ', 'version': 99,
             'depends_on': ['nonexistent', '../ malformed id ']}
        self.write('docs/handoffs/unrelated.v1.json', r)
        self.write('docs/project-state.json', {'live_status': 'UNLOCKED', 'active_strategies': -1})
        self.assertEqual(validate_repository(self.root), 3)

    def test_M02_future_stale_times_and_unverified_permission_evidence_accepted(self):
        for date in ('1900-01-01T00:00:00Z', '2999-01-01T00:00:00Z'):
            self.accept('bankroll', {**self.fixture('bankroll'), 'as_of': date})
        self.accept('source', {**self.fixture('source'), 'access_status': 'PERMITTED',
                    'terms_checked_at': '2999-01-01T00:00:00Z',
                    'allowed_uses': ['ingest'], 'access_evidence': ['nonexistent']})


if __name__ == '__main__':
    unittest.main()
