"""H-M0-008 versioned semantic probes; original probes remain immutable.

Successful unsafe-acceptance probes document OPEN owner gaps, not approval.
Data fixtures are reused only for valid prerequisite construction. Each attack
starts from a repository that validates, then targets one semantic invariant.
"""
import copy
import subprocess
import unittest

import test_data_integrity as data
import test_foundation as foundation
from src.edgelab.validate import validate_repository, read
from src.edgelab.data_integrity import verify_history, quarantine, sample_keys


class SemanticV2Tests(unittest.TestCase):
    def setUp(self):
        self.f = data.DataIntegrityTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.valid()

    def valid(self, baseline=None):
        return validate_repository(self.root, now=data.NOW, baseline=baseline)

    def record(self, kind, ident, **updates):
        r = foundation.FoundationTests().fixture(kind)
        r.update(id=ident, **updates)
        return r

    def put(self, folder, r):
        path = f"{folder}/{r['id']}.v{r['version']}.json"
        self.f.content(path, r)
        return path

    def hypothesis(self):
        return self.put('research/hypotheses', self.record('hypothesis', 'H'))

    def strategy(self, **updates):
        return self.record('strategy', 'S', hypothesis_ref=self.hypothesis(),
                           risk_policy_ref='portfolio/risk-policy.json', **updates)

    def experiment(self, ident='E', **updates):
        r = self.record('experiment', ident, mode='CONFIRMATORY',
                        hypothesis_ref=self.hypothesis(), dataset_manifests=['data/derived/D.v1.json'])
        r.update(updates)
        return r

    def test_v2_H01_unsupported_paper_states_still_accepted(self):
        r = self.strategy(state='IDEA')
        self.put('strategies', r)
        self.valid()
        for state in ('REGISTERED', 'BACKTESTED', 'PAPER_ELIGIBLE', 'PAPER_TRADING'):
            with self.subTest(state=state):
                self.put('strategies', {**r, 'state': state})
                self.valid()  # No experiments, reviews, transition events or paper ledger.

    def test_v2_H01_terminal_resurrection_still_accepted(self):
        r = self.strategy(state='REJECTED')
        prior = self.put('strategies', r)
        self.valid()
        self.put('strategies', {**r, 'version': 2, 'supersedes': prior, 'state': 'PAPER_TRADING'})
        self.valid()  # Valid version edge is not a legal lifecycle transition.

    def test_v2_H03_open_stop_still_allows_paper_state(self):
        r = self.strategy(state='PAPER_TRADING')
        path = self.put('strategies', r)
        self.valid()
        stop = self.record('stop', 'STOP', affected_components=[path], evidence_refs=['data/derived/D.v1.json'])
        ref = self.put('reports/stops', stop)
        self.put('strategies', {**r, 'active_stop_refs': [ref]})
        self.valid()
        graph = {'observation': set(), 'feature': {'observation'}, 'dataset': {'feature'}, path: {'dataset'}}
        self.assertEqual(quarantine(graph, {'kind': 'records', 'targets': ['observation']}), set(graph))
        # The primitive works; repository eligibility does not consume it.

    def test_v2_H04_missing_manifests_rejected_but_missing_reproduction_still_accepted(self):
        r = self.experiment()
        self.put('research/experiments', r)
        self.valid()
        self.put('research/experiments', {**r, 'dataset_manifests': ['data/derived/MISSING.v1.json']})
        with self.assertRaisesRegex(ValueError, 'Missing/wrong-type experiment manifest'):
            self.valid()
        self.put('research/experiments', {**r, 'completed_at': '2026-09-19T13:00:00Z',
                 'result': 'PROMISING_REQUIRES_REVIEW', 'metrics_ref': 'missing-metrics',
                 'uncertainty_ref': 'missing-uncertainty', 'robustness_ref': 'missing-robustness'})
        self.valid()  # Real typed dataset; code/environment/results remain unverified strings.

    def test_v2_H04_unknown_and_late_availability_rejected_semantically(self):
        self.put('research/experiments', self.experiment())
        self.valid()
        for late in (False, True):
            with self.subTest(late=late):
                obs = copy.deepcopy(self.f.observation)
                if late:
                    av = {**self.f.availability, 'available_at': '2026-09-19T12:00:00Z',
                          'observed_at': '2026-09-19T12:00:00Z'}
                    obs.update(available_at=av['available_at'], availability_ref=self.f.put('availability', av))
                else:
                    obs.update(available_at=None, availability_ref=None)
                ref = self.f.put('observation', obs)
                feature = {**self.f.feature, 'parents': [ref], 'available_at': obs['available_at']}
                self.f.put('manifest', {**self.f.manifest, 'inputs': [self.f.put('feature', feature)]})
                with self.assertRaisesRegex(ValueError, 'Unknown or late availability'):
                    self.valid()

    def test_v2_H04_mutated_snapshot_and_raw_rejected_semantically(self):
        self.put('research/experiments', self.experiment())
        self.valid()
        raw = self.root / self.f.raw['path']
        original = raw.read_bytes()
        raw.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Content digest mismatch'):
            self.valid()
        raw.write_bytes(original)
        self.valid()
        m = copy.deepcopy(self.f.manifest)
        m['snapshot'] = self.f.content('data/raw/forged.json', [{'sample': self.f.membership['samples'][0], 'value': 999}])
        self.f.put('manifest', m)
        with self.assertRaisesRegex(ValueError, 'not reconstructible'):
            self.valid()

    def test_v2_H04_correction_and_evaluation_input_rejected(self):
        self.valid()
        obs = {**self.f.observation, 'retrieved_at': '2026-09-19T12:00:00Z',
               'corrected_at': '2026-09-19T12:00:00Z'}
        ref = self.f.put('observation', obs)
        self.f.put('manifest', {**self.f.manifest, 'inputs': [ref]})
        with self.assertRaisesRegex(ValueError, 'masquerading as earlier fact'):
            self.valid()
        self.f.put('observation', self.f.observation)
        self.f.put('manifest', self.f.manifest)
        self.valid()
        obs = {**self.f.observation, 'observation_type': 'settled_outcome', 'role': 'evaluation'}
        ref = self.f.put('observation', obs)
        self.f.put('feature', {**self.f.feature, 'parents': [ref], 'role': 'evaluation'})
        self.f.put('manifest', {**self.f.manifest, 'inputs': [ref]})
        with self.assertRaisesRegex(ValueError, 'Evaluation leakage'):
            self.valid()

    def test_v2_H05_explored_same_and_renamed_membership_still_accepted(self):
        r = self.experiment()
        self.put('research/experiments', r)
        self.valid()
        explored = {**r, 'id': 'EXPLORED', 'mode': 'EXPLORATORY', 'hypothesis_ref': None,
                    'protocol_frozen_at': '2026-09-19T11:00:00Z', 'started_at': '2026-09-19T11:00:00Z',
                    'completed_at': '2026-09-19T11:30:00Z', 'result': 'PROMISING_REQUIRES_REVIEW',
                    'metrics_ref': 'data/raw/quality.json', 'uncertainty_ref': 'data/raw/quality.json',
                    'robustness_ref': 'data/raw/quality.json'}
        self.put('research/experiments', explored)
        self.valid()  # Exploration completed before the noon registration.
        renamed = {**self.f.membership, 'id': 'RENAMED'}
        self.assertEqual(sample_keys(renamed), sample_keys(self.f.membership))
        m = {**self.f.manifest, 'id': 'RENAMED', 'membership_ref': self.f.put('membership', renamed)}
        self.f.put('manifest', m)
        self.put('research/experiments', {**r, 'dataset_manifests': ['data/derived/RENAMED.v1.json']})
        self.valid()  # Renamed population is detectable but not rejected as contaminated.

    def test_v2_H06_self_supersession_rejected_at_correct_surface(self):
        r = self.record('audit', 'A')
        path = self.put('reports/audit', r)
        self.valid()
        self.put('reports/audit', {**r, 'supersedes': path})
        with self.assertRaisesRegex(ValueError, 'Supersession must name previous exact version'):
            self.valid()

    def test_v2_H06_baseline_detects_mutation_deletion_and_accepts_correction(self):
        r = self.record('audit', 'A')
        path = self.put('reports/audit', r)
        self.valid()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()
        git('init'); git('add', '.')
        git('-c', 'user.name=Synthetic', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Synthetic accepted history')
        baseline = git('rev-parse', 'HEAD')
        self.valid(baseline)
        self.put('reports/audit', {**r, 'reason': 'rewritten'})
        self.valid()  # Baseline-free validation explicitly offers no history assurance.
        with self.assertRaisesRegex(ValueError, 'Published history mutated'):
            self.valid(baseline)
        (self.root / path).unlink()
        self.valid()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.valid(baseline)
        self.put('reports/audit', r)
        self.put('reports/audit', {**r, 'version': 2, 'supersedes': path, 'reason': 'preserved correction'})
        self.valid(baseline)
        self.assertEqual(read(self.root / path), r)
        with self.assertRaisesRegex(ValueError, 'trusted baseline required'):
            verify_history(self.root, None)

    def test_v2_M01_independent_dependency_and_summary_denials(self):
        h = self.record('handoff', 'H', evidence_refs=['data/derived/D.v1.json'])
        self.put('docs/handoffs', h)
        self.valid()
        for dependencies in (['MISSING'], ['H']):
            self.put('docs/handoffs', {**h, 'depends_on': dependencies})
            with self.assertRaisesRegex(ValueError, 'Orphan|cycle'):
                self.valid()
        self.put('docs/handoffs', h)
        self.valid()
        state = read(data.ROOT / 'docs/project-state.json')
        self.f.content('docs/project-state.json', state)
        self.valid()
        self.f.content('docs/project-state.json', {**state, 'active_strategies': -1})
        from jsonschema import ValidationError
        with self.assertRaises(ValidationError):
            self.valid()

    def test_v2_M02_permission_probe_reached_without_future_clock_error(self):
        self.valid()
        self.f.put('source', {**self.f.source, 'access_status': 'PERMITTED',
                   'terms_checked_at': data.T, 'allowed_uses': ['synthetic'], 'access_evidence': ['missing']})
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.valid()


if __name__ == '__main__':
    unittest.main()
