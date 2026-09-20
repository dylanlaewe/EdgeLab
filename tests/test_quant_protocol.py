"""Quant H-M0-005 successors: synthetic scientific integrity, never approval."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import ValidationError

import test_research_history_v2 as research_owner
from src.edgelab.data_integrity import DATA_LOCATIONS, canonical, digest, history_inventory
from src.edgelab.quant_protocol import (
    QUANT_LOCATIONS, assess_confirmation, checkpoint_digest, claim_identity,
    commitment_digest, commit_confirmation_claim, experiment_identity,
    quant_record_snapshot, state_digest, validate_protocol, validate_trial,
    validate_trial_inventory, verify_authority_commitment,
    verify_current_state, verify_reproduction,
)
from src.edgelab.research_protocol import check_confirmation_contract
from src.edgelab.validate import LOCATIONS, read, validate_record, validate_repository

NOW = research_owner.NOW
EARLY = research_owner.EARLY
FREEZE = research_owner.FREEZE
ACCESS = research_owner.ACCESS
PROTOCOL_FREEZE = '2026-09-19T12:10:00Z'
START = '2026-09-19T12:20:00Z'
DONE = '2026-09-19T13:10:00Z'


class SyntheticAuthority:
    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.committed = []
        self.race_state = None

    def current_state(self):
        return copy.deepcopy(self.state)

    def commit_if_current(self, expected_state_sha256, assessment):
        if self.race_state is not None:
            self.state = copy.deepcopy(self.race_state)
        if self.state['state_sha256'] != expected_state_sha256:
            raise ValueError('Atomic accepted-state compare failed')
        self.committed.append(copy.deepcopy(assessment))
        commitment = {
            'schema_version': 1,
            'authority_id': self.state['authority_id'],
            'generation': self.state['generation'],
            'commitment_id': f"synthetic-commit-{len(self.committed)}",
            'committed_at': self.state['accepted_at'],
            'assessment_sha256': assessment['assessment_sha256'],
            'current_state_sha256': assessment['current_state_sha256'],
            'experiment_identity_sha256': assessment['experiment_identity_sha256'],
            'claim_identity_sha256': claim_identity(assessment),
            'limitations': [
                'Synthetic local binding; authority identity and honesty are not authenticated.'
            ],
            'commitment_sha256': '0' * 64,
        }
        commitment['commitment_sha256'] = commitment_digest(commitment)
        return commitment


class QuantProtocolTests(unittest.TestCase):
    def setUp(self):
        self.f = research_owner.ResearchHistoryV2Tests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.pre_access = {'baseline': self.f.baseline, 'inventory': self.f.inventory}
        self._make_data()
        self._make_quant_records()
        self._accept_current()

    def write(self, path, value, *, raw=False):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if raw:
            target.write_bytes(value)
        else:
            target.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
        return digest(target.read_bytes())

    def blob(self, path, value, media='application/json'):
        if media == 'application/json':
            sha = self.write(path, value)
        else:
            data = value.encode() if isinstance(value, str) else value
            sha = self.write(path, data, raw=True)
        return {'path': path, 'sha256': sha, 'media_type': media}

    def put(self, kind, record):
        locations = {**LOCATIONS, **DATA_LOCATIONS, **QUANT_LOCATIONS}
        folder = locations[kind].split('/*')[0]
        path = f"{folder}/{record['id']}.v{record['version']}.json"
        sha = self.write(path, record)
        return {'path': path, 'kind': kind, 'id': record['id'],
                'version': record['version'], 'sha256': sha}

    def base(self, kind, ident, created=PROTOCOL_FREEZE, **values):
        return {'schema_version': 1, 'id': ident, 'version': 1,
                'created_at': created, 'supersedes': None, 'kind': kind, **values}

    def _make_data(self):
        source = read(Path(__file__).parent / 'fixtures/data-integrity/data/sources/SRC.v1.json')
        self.source_ref = self.put('source', source)
        self.parser = self.blob('data/raw/quant-parser.py', '# inert synthetic parser\n', 'text/x-python')
        self.normalizer = self.blob('data/raw/quant-normalizer.py', '# inert synthetic normalizer\n', 'text/x-python')
        self.data_config = self.blob('data/raw/quant-data-config.json', {'synthetic': True})
        memberships = {
            'train': self.f.membership('TRAIN', ['train-1']),
            'validation': self.f.membership('VALIDATION', ['validation-1']),
            'test': self.f.membership('TEST', ['test-1']),
            'holdout': self.f.fresh,
        }
        self.splits = {name: [self._manifest(name, ref)] for name, ref in memberships.items()}

    def _manifest(self, split, membership_ref):
        membership = read(self.root / membership_ref['path'])
        inputs = []
        values = []
        for number, sample in enumerate(membership['samples'], 1):
            ident = f"Q{split.upper()}{number}"
            raw = self.blob(f'data/raw/{ident}.json', {'value': number})
            availability = self.base(
                'availability', f'AV{ident}', created=EARLY, observed_at=EARLY,
                available_at=EARLY, basis='contemporaneous_capture', evidence=raw,
                source_ref=self.source_ref,
            )
            availability_ref = self.put('availability', availability)
            observation = self.base(
                'observation', f'OBS{ident}', created=EARLY,
                source_ref=self.source_ref, source_url='https://example.invalid',
                retrieved_at=EARLY, publication_at=EARLY, event_at=None,
                corrected_at=None, unknown_reason='Synthetic event has no scheduled time',
                available_at=EARLY, availability_ref=availability_ref, role='decision',
                observation_type='observed_fact', raw=raw, parser=self.parser,
                parser_version='synthetic-v1', normalizer=self.normalizer,
                normalizer_version='synthetic-v1', config=self.data_config,
                value=number, inference_method=None,
            )
            inputs.append(self.put('observation', observation))
            values.append({'sample': sample, 'value': number})
        manifest = self.base(
            'manifest', f'M{split.upper()}', inputs=inputs,
            membership_ref=membership_ref, decision_at=PROTOCOL_FREEZE,
            purpose='decision', snapshot=self.blob(f'data/raw/{split}-snapshot.json', values),
            row_count=len(values), quality_report=self.blob(
                f'data/raw/{split}-quality.json', {'synthetic': True}),
            parent_manifests=[],
        )
        return self.put('manifest', manifest)

    def _make_quant_records(self):
        self.code = self.blob(
            'research/experiment-artifacts/model.py',
            '# inert evidence; tests use a verifier-authored callable\n', 'text/x-python')
        self.configuration = self.blob(
            'research/experiment-artifacts/config.json',
            {'threshold': '0', 'feature_set': ['synthetic-value'], 'evaluation': 'identity'})
        self.environment = self.blob(
            'research/experiment-artifacts/environment.json',
            {'python': '3.13', 'dependencies': []})
        self.settings = self.blob(
            'research/experiment-artifacts/determinism.json',
            {'hash_seed': 0, 'single_threaded': True})
        self.randomness = {
            'mode': 'SEEDED', 'seed': 1729, 'algorithm': 'synthetic-fixed-v1',
            'explanation': 'Seed is part of the frozen synthetic identity.'}
        protocol = self.base(
            'quant-protocol', 'QP', preregistration_ref=self.f.regref,
            frozen_at=PROTOCOL_FREEZE,
            pre_access_checkpoint_sha256=checkpoint_digest(self.pre_access),
            splits=self.splits, required_splits=list(('train', 'validation', 'test', 'holdout')),
            code=self.code, configuration=self.configuration, environment=self.environment,
            randomness=self.randomness, deterministic_settings=self.settings,
            execution_assumptions=['Synthetic identity check only; no profit or execution claim.'],
        )
        self.protocol_ref = self.put('quant-protocol', protocol)
        self.protocol_pin = self.protocol_ref['sha256']
        self.output_bytes = canonical({'synthetic_score': 3, 'status': 'NO_PROFIT_CLAIM'}) + b'\n'
        self.metrics_bytes = canonical({'identity_error': 0, 'sample_count': 2}) + b'\n'
        output = self.blob('research/experiment-artifacts/output.json', json.loads(self.output_bytes))
        metrics = self.blob('research/experiment-artifacts/metrics.json', json.loads(self.metrics_bytes))
        trial = self.base(
            'trial', 'TRIALPASS', created=DONE, protocol_ref=self.protocol_ref,
            preregistration_ref=self.f.regref, attempt_ordinal=2, started_at=START,
            completed_at=DONE, status='SUCCEEDED', failure_reason=None,
            actual_splits=self.splits, code=self.code, configuration=self.configuration,
            environment=self.environment, randomness=self.randomness,
            deterministic_settings=self.settings, results_access_ref=self.f.accessref,
            outputs=[{'name': 'predictions', 'artifact': output}], metrics=metrics,
        )
        failed = self.base(
            'trial', 'TRIALFAILED', created='2026-09-19T13:04:00Z',
            protocol_ref=self.protocol_ref, preregistration_ref=self.f.regref,
            attempt_ordinal=1, started_at='2026-09-19T13:02:00Z',
            completed_at='2026-09-19T13:04:00Z', status='FAILED',
            failure_reason='Synthetic injected failure retained in complete inventory.',
            actual_splits=self.splits, code=self.code, configuration=self.configuration,
            environment=self.environment, randomness=self.randomness,
            deterministic_settings=self.settings, results_access_ref=None,
            outputs=[], metrics=None,
        )
        cancelled = self.base(
            'trial', 'TRIALCANCELLED', created='2026-09-19T13:07:00Z',
            protocol_ref=self.protocol_ref, preregistration_ref=self.f.regref,
            attempt_ordinal=3, started_at='2026-09-19T13:05:00Z',
            completed_at='2026-09-19T13:07:00Z', status='CANCELLED',
            failure_reason='Synthetic cancellation retained in complete inventory.',
            actual_splits=self.splits, code=self.code, configuration=self.configuration,
            environment=self.environment, randomness=self.randomness,
            deterministic_settings=self.settings, results_access_ref=None,
            outputs=[], metrics=None,
        )
        attempted = self.base(
            'trial', 'TRIALATTEMPTED', created='2026-09-19T13:08:00Z',
            protocol_ref=self.protocol_ref, preregistration_ref=self.f.regref,
            attempt_ordinal=4, started_at='2026-09-19T13:08:00Z',
            completed_at=None, status='ATTEMPTED', failure_reason=None,
            actual_splits=self.splits, code=self.code, configuration=self.configuration,
            environment=self.environment, randomness=self.randomness,
            deterministic_settings=self.settings, results_access_ref=None,
            outputs=[], metrics=None,
        )
        self.failed_ref = self.put('trial', failed)
        self.trial_ref = self.put('trial', trial)
        self.cancelled_ref = self.put('trial', cancelled)
        self.attempted_ref = self.put('trial', attempted)
        trial_snapshot = {
            self.failed_ref['path']: self.failed_ref['sha256'],
            self.trial_ref['path']: self.trial_ref['sha256'],
            self.cancelled_ref['path']: self.cancelled_ref['sha256'],
            self.attempted_ref['path']: self.attempted_ref['sha256'],
        }
        inventory = self.base(
            'trial-inventory', 'INVENTORY', created=DONE, observed_through=DONE,
            trials=[self.failed_ref, self.trial_ref, self.cancelled_ref, self.attempted_ref],
            trial_registry_sha256=digest(canonical(trial_snapshot)),
            status_counts={'ATTEMPTED': 1, 'SUCCEEDED': 1, 'FAILED': 1, 'CANCELLED': 1},
        )
        self.inventory_ref = self.put('trial-inventory', inventory)
        trial_record = read(self.root / self.trial_ref['path'])
        identity = experiment_identity(self.protocol_ref, self.trial_ref, trial_record,
                                       self.inventory_ref)
        reproduced_output = self.blob(
            'research/experiment-artifacts/reproduced-output.json', json.loads(self.output_bytes))
        reproduced_metrics = self.blob(
            'research/experiment-artifacts/reproduced-metrics.json', json.loads(self.metrics_bytes))
        reproduction = self.base(
            'reproduction', 'REPRO', created=DONE, protocol_ref=self.protocol_ref,
            trial_ref=self.trial_ref, reproduced_at=DONE,
            verifier='synthetic-independent-test-verifier',
            trusted_runner_id='test_quant_protocol.synthetic_runner.v1',
            experiment_identity_sha256=identity,
            outputs=[{'name': 'predictions', 'artifact': reproduced_output}],
            metrics=reproduced_metrics,
            limitations=['Test-authored deterministic runner; external dependencies are not proven deterministic.'],
        )
        self.reproduction_ref = self.put('reproduction', reproduction)

    def _accept_current(self, predecessor=None):
        self.f.git('add', '.')
        self.f.git('-c', 'user.name=Synthetic current-state verifier',
                   '-c', 'user.email=test@example.invalid', 'commit', '-q',
                   '--allow-empty', '-m', 'Accept synthetic Quant evidence')
        baseline = self.f.git('rev-parse', 'HEAD')
        current = {'baseline': baseline, 'inventory': history_inventory(self.root, baseline)}
        state = {
            'schema_version': 1, 'authority_id': 'synthetic-test-authority',
            'generation': 1 if predecessor is None else predecessor['generation'] + 1,
            'accepted_at': DONE,
            'predecessor_state_sha256': None if predecessor is None else predecessor['state_sha256'],
            'pre_access_checkpoint': self.pre_access,
            'pre_access_checkpoint_sha256': checkpoint_digest(self.pre_access),
            'current_checkpoint': current, 'state_sha256': '0' * 64,
        }
        state['state_sha256'] = state_digest(state)
        self.state = state
        self.authority = SyntheticAuthority(state)
        self.request = {
            'protocol_ref': self.protocol_ref,
            'frozen_protocol_sha256': self.protocol_pin,
            'trial_ref': self.trial_ref,
            'trial_inventory_ref': self.inventory_ref,
            'reproduction_ref': self.reproduction_ref,
            'results_access_ref': self.f.accessref,
            'expected_current_state_sha256': state['state_sha256'],
        }

    def runner(self, root, protocol_ref, trial_ref):
        # Verifier-authored code, not a command embedded in an artifact.
        protocol = read(root / protocol_ref['path'])
        trial = read(root / trial_ref['path'])
        self.assertEqual(protocol['splits'], trial['actual_splits'])
        return {'outputs': {'predictions': self.output_bytes}, 'metrics': self.metrics_bytes}

    def _replace_inventory_and_reproduction(self, extra_refs):
        prior_inventory = read(self.root / self.inventory_ref['path'])
        refs = [self.failed_ref, self.trial_ref, self.cancelled_ref,
                self.attempted_ref, *extra_refs]
        counts = {status: 0 for status in ('ATTEMPTED', 'SUCCEEDED', 'FAILED', 'CANCELLED')}
        for ref in refs:
            counts[read(self.root / ref['path'])['status']] += 1
        inventory = {
            **prior_inventory, 'version': 2, 'supersedes': self.inventory_ref,
            'trials': refs,
            'trial_registry_sha256': digest(canonical(
                {ref['path']: ref['sha256'] for ref in refs})),
            'status_counts': counts,
        }
        inventory_ref = self.put('trial-inventory', inventory)
        reproduction = read(self.root / self.reproduction_ref['path'])
        reproduction.update(
            version=2, supersedes=self.reproduction_ref,
            experiment_identity_sha256=experiment_identity(
                self.protocol_ref, self.trial_ref,
                read(self.root / self.trial_ref['path']), inventory_ref))
        reproduction_ref = self.put('reproduction', reproduction)
        prior_state = copy.deepcopy(self.state)
        self._accept_current(predecessor=prior_state)
        self.request.update(
            trial_inventory_ref=inventory_ref,
            reproduction_ref=reproduction_ref,
            expected_current_state_sha256=self.state['state_sha256'],
        )

    def _install_prior_consumption(self, role, *, variant='exact', status='SUCCEEDED'):
        if role == 'holdout':
            prior_registration_ref = self.f.regref
            prior_access_ref = self.f.accessref
            prior_splits = copy.deepcopy(self.splits)
        else:
            prior_holdout = self.f.membership(
                f'PRIORHOLDOUT{role.upper()}{variant.upper()}', ['prior-holdout-1'])
            prior_custody = self.f.exposure(
                f'PRIORCUSTODY{role.upper()}{variant.upper()}', prior_holdout,
                'UNEXAMINED', 'HOLDOUT_CUSTODY', FREEZE)
            prior_custody_ref = self.f.put('exposure', prior_custody)
            prior_registration = {
                **self.f.registration,
                'id': f'PRIORREG{role.upper()}{variant.upper()}',
                'holdout_ref': prior_custody_ref,
            }
            prior_registration_ref = self.f.put('preregistration', prior_registration)
            prior_access = self.f.exposure(
                f'PRIORACCESS{role.upper()}{variant.upper()}', prior_holdout,
                'EXAMINED', 'CONFIRMATORY_ACCESS', ACCESS)
            prior_access_ref = self.f.put('exposure', prior_access)
            prior_splits = copy.deepcopy(self.splits)
            prior_splits['holdout'] = [self._manifest(
                f'priorholdout{role}{variant}', prior_holdout)]

        if variant == 'exact':
            consumed = self.splits['holdout']
        elif variant == 'renamed':
            membership = self.f.membership(
                f'RENAMED{role.upper()}', ['fresh-1', 'fresh-2'])
            consumed = [self._manifest(f'renamed{role}', membership)]
        elif variant == 'reordered':
            membership = self.f.membership(
                f'REORDERED{role.upper()}', ['fresh-2', 'fresh-1'])
            consumed = [self._manifest(f'reordered{role}', membership)]
        elif variant == 'partial':
            membership = self.f.membership(
                f'PARTIAL{role.upper()}', ['unrelated-sample', 'fresh-2'])
            consumed = [self._manifest(f'partial{role}', membership)]
        elif variant == 'versioned':
            membership = read(self.root / self.f.fresh['path'])
            membership.update(
                version=2, supersedes=self.f.fresh,
                created_at=PROTOCOL_FREEZE,
                samples=list(reversed(membership['samples'])),
            )
            membership_ref = self.put('membership', membership)
            consumed = [self._manifest(f'versioned{role}', membership_ref)]
        elif variant == 'nonholdout':
            consumed = self.splits['train']
        else:
            raise AssertionError('unsupported variant')
        prior_splits[role] = consumed

        protocol = read(self.root / self.protocol_ref['path'])
        prior_protocol = {
            **protocol,
            'id': f'PRIORQP{role.upper()}{variant.upper()}{status}',
            'preregistration_ref': prior_registration_ref,
            'splits': prior_splits,
        }
        prior_protocol_ref = self.put('quant-protocol', prior_protocol)
        trial = read(self.root / self.trial_ref['path'])
        prior_trial = {
            **trial,
            'id': f'PRIOR{role.upper()}{variant.upper()}{status}',
            'protocol_ref': prior_protocol_ref,
            'preregistration_ref': prior_registration_ref,
            'attempt_ordinal': 1,
            'actual_splits': prior_splits,
            'results_access_ref': prior_access_ref if status == 'SUCCEEDED' else None,
        }
        if status != 'SUCCEEDED':
            prior_trial.update(
                status=status, outputs=[], metrics=None,
                failure_reason=None if status == 'ATTEMPTED' else 'Synthetic prior terminal outcome.',
                completed_at=None if status == 'ATTEMPTED' else '2026-09-19T12:50:00Z',
                created_at='2026-09-19T12:50:00Z',
            )
        prior_trial_ref = self.put('trial', prior_trial)
        self._replace_inventory_and_reproduction([prior_trial_ref])
        return prior_trial_ref

    def test_positive_current_disjoint_deterministic_claim_has_no_authorization(self):
        assessment, commitment = commit_confirmation_claim(
            self.root, self.request, self.authority, self.runner, now=NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')
        self.assertTrue(assessment['scientific_integrity_eligible'])
        for field in ('operational_authorization', 'paper_authorization',
                      'live_authorization', 'risk_approval'):
            self.assertFalse(assessment[field])
        self.assertEqual(commitment['commitment_id'], 'synthetic-commit-1')
        self.assertEqual(commitment['assessment_sha256'], assessment['assessment_sha256'])
        self.assertEqual(commitment['claim_identity_sha256'], claim_identity(assessment))
        self.assertEqual(
            verify_authority_commitment(self.root, assessment, commitment, now=NOW),
            commitment,
        )
        self.assertEqual(assessment['history_completeness'],
                         'VERIFIED_CURRENT_ACCEPTED_RESEARCH_AND_QUANT_REGISTRIES')

    def test_structured_commitment_rejects_malformed_replayed_and_cross_authority_bindings(self):
        assessment, commitment = commit_confirmation_claim(
            self.root, self.request, self.authority, self.runner, now=NOW)
        with self.assertRaisesRegex(ValueError, 'structured record'):
            verify_authority_commitment(self.root, assessment, 'opaque-token', now=NOW)
        for field in commitment:
            with self.subTest(missing=field):
                missing = copy.deepcopy(commitment)
                del missing[field]
                with self.assertRaises(ValidationError):
                    verify_authority_commitment(
                        self.root, assessment, missing, now=NOW)
        with self.assertRaises(ValidationError):
            verify_authority_commitment(
                self.root, assessment, {**commitment, 'unexpected': True}, now=NOW)
        cases = {
            'authority_id': 'another-authority',
            'generation': commitment['generation'] + 1,
            'assessment_sha256': '0' * 64,
            'current_state_sha256': '1' * 64,
            'experiment_identity_sha256': '2' * 64,
            'claim_identity_sha256': '3' * 64,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                altered = {**commitment, field: value}
                altered['commitment_sha256'] = commitment_digest(altered)
                with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                    verify_authority_commitment(
                        self.root, assessment, altered, now=NOW)
        replayed_assessment = copy.deepcopy(assessment)
        replayed_assessment['trial_ref'] = copy.deepcopy(assessment['trial_ref'])
        replayed_assessment['trial_ref']['id'] = 'OTHER-TRIAL'
        replayed_assessment['assessment_sha256'] = digest(canonical({
            key: value for key, value in replayed_assessment.items()
            if key != 'assessment_sha256'
        }))
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            verify_authority_commitment(
                self.root, replayed_assessment, commitment, now=NOW)

    def test_commit_rejects_opaque_or_dishonest_authority_response(self):
        class OpaqueAuthority(SyntheticAuthority):
            def commit_if_current(self, expected_state_sha256, assessment):
                return 'replayed-token'

        with self.assertRaisesRegex(ValueError, 'structured record'):
            commit_confirmation_claim(
                self.root, self.request, OpaqueAuthority(self.state),
                self.runner, now=NOW)

    def test_missing_unknown_and_stale_authority_deny(self):
        with self.assertRaisesRegex(ValueError, 'authority is required'):
            assess_confirmation(self.root, self.request, None, self.runner, now=NOW)
        stale = copy.deepcopy(self.request)
        stale['expected_current_state_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Stale or substituted'):
            assess_confirmation(self.root, stale, self.authority, self.runner, now=NOW)
        broken = copy.deepcopy(self.state)
        broken['state_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            verify_current_state(self.root, broken, now=NOW)

    def test_rollback_current_checkpoint_denied(self):
        rolled = copy.deepcopy(self.state)
        rolled['current_checkpoint'] = self.pre_access
        rolled['state_sha256'] = state_digest(rolled)
        with self.assertRaisesRegex(ValueError, 'registry mismatch'):
            verify_current_state(self.root, rolled, now=NOW)

    def test_later_accepted_exposure_deleted_cannot_hide_behind_old_checkpoint(self):
        old_state = copy.deepcopy(self.state)
        hidden = self.f.exposure('LATEROVERLAP', self.f.fresh, 'EXAMINED',
                                 'EXPLORATORY', ACCESS)
        hidden_ref = self.f.put('exposure', hidden)
        self._accept_current(predecessor=old_state)
        (self.root / hidden_ref['path']).unlink()
        # Research alone, supplied the old pre-access checkpoint, cannot recover
        # evidence deleted after that checkpoint.
        result = check_confirmation_contract(
            self.root, self.f.regref, frozen_sha256=self.f.pin,
            access_ref=self.f.accessref, disclosure_refs=[], now=NOW,
            history_baseline=self.pre_access['baseline'],
            history_inventory=self.pre_access['inventory'])
        self.assertEqual(result['contract_status'],
                         'CONSISTENT_AUTHORITATIVE_RESEARCH_EVIDENCE')
        stale_request = copy.deepcopy(self.request)
        stale_request['expected_current_state_sha256'] = old_state['state_sha256']
        with self.assertRaisesRegex(ValueError, 'Missing|registry mismatch'):
            assess_confirmation(self.root, stale_request, self.authority,
                                self.runner, now=NOW)

    def test_atomic_compare_and_commit_denies_change_after_final_recheck(self):
        raced = copy.deepcopy(self.state)
        raced['generation'] += 1
        raced['predecessor_state_sha256'] = self.state['state_sha256']
        raced['state_sha256'] = state_digest(raced)
        self.authority.race_state = raced
        with self.assertRaisesRegex(ValueError, 'Atomic accepted-state compare failed'):
            commit_confirmation_claim(self.root, self.request, self.authority,
                                      self.runner, now=NOW)
        self.assertEqual(self.authority.committed, [])

    def test_split_swap_reorder_and_overlap_rejected(self):
        protocol = read(self.root / self.protocol_ref['path'])
        swapped = copy.deepcopy(protocol)
        swapped['splits'].update(train=swapped['splits']['validation'],
                                 validation=swapped['splits']['train'])
        ref = self.put('quant-protocol', swapped)
        with self.assertRaisesRegex(ValueError, 'Verifier-held frozen'):
            validate_protocol(self.root, ref, self.state,
                              frozen_sha256=self.protocol_pin, now=NOW)
        overlapped = copy.deepcopy(protocol)
        overlapped['splits']['test'] = overlapped['splits']['holdout']
        ref = self.put('quant-protocol', overlapped)
        with self.assertRaisesRegex(ValueError, 'overlap|multiple splits'):
            validate_protocol(self.root, ref, self.state,
                              frozen_sha256=ref['sha256'], now=NOW)
        renamed = self.f.membership('HOLDOUTRENAMED', ['fresh-2', 'fresh-1'])
        repackaged = copy.deepcopy(protocol)
        repackaged['splits']['holdout'] = [self._manifest('repackaged', renamed)]
        ref = self.put('quant-protocol', repackaged)
        with self.assertRaisesRegex(ValueError, 'exact preregistered membership'):
            validate_protocol(self.root, ref, self.state,
                              frozen_sha256=ref['sha256'], now=NOW)

    def test_trial_config_code_seed_and_actual_input_substitution_rejected(self):
        protocol = read(self.root / self.protocol_ref['path'])
        trial = read(self.root / self.trial_ref['path'])
        cases = [
            ('configuration', self.blob('research/experiment-artifacts/other-config.json', {'threshold': '1'})),
            ('code', self.blob('research/experiment-artifacts/other.py', '# changed\n', 'text/x-python')),
            ('randomness', {**self.randomness, 'seed': 1730}),
            ('actual_splits', {**self.splits, 'test': self.splits['validation']}),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                bad = {**trial, field: value}
                ref = self.put('trial', bad)
                with self.assertRaisesRegex(ValueError, 'changed frozen|split manifests'):
                    validate_trial(self.root, ref, self.protocol_ref, protocol, now=NOW)

    def test_missing_failed_trial_and_status_rewrite_rejected(self):
        inventory = read(self.root / self.inventory_ref['path'])
        omitted = copy.deepcopy(inventory)
        omitted['trials'] = [self.trial_ref, self.cancelled_ref, self.attempted_ref]
        omitted['status_counts']['FAILED'] = 0
        omitted['trial_registry_sha256'] = digest(canonical({
            ref['path']: ref['sha256'] for ref in omitted['trials']}))
        ref = self.put('trial-inventory', omitted)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            validate_trial_inventory(self.root, ref, now=NOW)
        wrong = copy.deepcopy(inventory)
        wrong['status_counts'] = {'ATTEMPTED': 0, 'SUCCEEDED': 2,
                                  'FAILED': 1, 'CANCELLED': 1}
        ref = self.put('trial-inventory', wrong)
        with self.assertRaisesRegex(ValueError, 'status counts'):
            validate_trial_inventory(self.root, ref, now=NOW)

    def test_prior_repeated_or_partial_holdout_trial_denied(self):
        prior_state = copy.deepcopy(self.state)
        previous = read(self.root / self.trial_ref['path'])
        previous.update(id='PRIOR', attempt_ordinal=5, results_access_ref=self.f.accessref)
        prior_ref = self.put('trial', previous)
        refs = [self.failed_ref, self.trial_ref, self.cancelled_ref,
                self.attempted_ref, prior_ref]
        prior_inventory = read(self.root / self.inventory_ref['path'])
        inventory = {**prior_inventory, 'version': 2, 'supersedes': self.inventory_ref,
                     'trials': refs,
                     'trial_registry_sha256': digest(canonical(
                         {ref['path']: ref['sha256'] for ref in refs})),
                     'status_counts': {'ATTEMPTED': 1, 'SUCCEEDED': 2,
                                       'FAILED': 1, 'CANCELLED': 1}}
        inventory_ref = self.put('trial-inventory', inventory)
        reproduction = read(self.root / self.reproduction_ref['path'])
        reproduction.update(
            version=2, supersedes=self.reproduction_ref,
            experiment_identity_sha256=experiment_identity(
                self.protocol_ref, self.trial_ref,
                read(self.root / self.trial_ref['path']), inventory_ref))
        reproduction_ref = self.put('reproduction', reproduction)
        self._accept_current(predecessor=prior_state)
        self.request.update(trial_inventory_ref=inventory_ref,
                            reproduction_ref=reproduction_ref,
                            expected_current_state_sha256=self.state['state_sha256'])
        with self.assertRaisesRegex(ValueError, 'Prior/repeated trial consumed'):
            assess_confirmation(self.root, self.request, self.authority,
                                self.runner, now=NOW)

    def test_prior_train_consumption_of_holdout_denied(self):
        self._install_prior_consumption('train')
        with self.assertRaisesRegex(ValueError, 'train split'):
            assess_confirmation(
                self.root, self.request, self.authority, self.runner, now=NOW)

    def test_prior_validation_consumption_of_holdout_denied(self):
        self._install_prior_consumption('validation')
        with self.assertRaisesRegex(ValueError, 'validation split'):
            assess_confirmation(
                self.root, self.request, self.authority, self.runner, now=NOW)

    def test_prior_test_consumption_of_holdout_denied(self):
        self._install_prior_consumption('test')
        with self.assertRaisesRegex(ValueError, 'test split'):
            assess_confirmation(
                self.root, self.request, self.authority, self.runner, now=NOW)

    def test_prior_failed_holdout_consumption_without_access_fails_closed(self):
        self._install_prior_consumption('holdout', status='FAILED')
        with self.assertRaisesRegex(ValueError, 'holdout split'):
            assess_confirmation(
                self.root, self.request, self.authority, self.runner, now=NOW)

    def test_renamed_reordered_partial_and_versioned_membership_consumption_denied(self):
        # Each subcase needs an isolated accepted history, so exercise a fresh
        # owner fixture instead of accumulating mutually dependent snapshots.
        for variant in ('renamed', 'reordered', 'partial', 'versioned'):
            with self.subTest(variant=variant):
                case = QuantProtocolTests(
                    methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
                case.setUp()
                try:
                    case._install_prior_consumption('train', variant=variant)
                    with self.assertRaisesRegex(ValueError, 'train split'):
                        assess_confirmation(
                            case.root, case.request, case.authority,
                            case.runner, now=NOW)
                finally:
                    case.doCleanups()

    def test_partial_prior_validation_overlap_denied(self):
        self._install_prior_consumption('validation', variant='partial')
        with self.assertRaisesRegex(ValueError, 'validation split'):
            assess_confirmation(
                self.root, self.request, self.authority, self.runner, now=NOW)

    def test_failed_cancelled_and_attempted_prior_consumption_fail_closed(self):
        for status in ('FAILED', 'CANCELLED', 'ATTEMPTED'):
            with self.subTest(status=status):
                case = QuantProtocolTests(
                    methodName='test_positive_current_disjoint_deterministic_claim_has_no_authorization')
                case.setUp()
                try:
                    case._install_prior_consumption('train', status=status)
                    with self.assertRaisesRegex(ValueError, 'train split'):
                        assess_confirmation(
                            case.root, case.request, case.authority,
                            case.runner, now=NOW)
                finally:
                    case.doCleanups()

    def test_prior_reuse_outside_proposed_holdout_remains_eligible(self):
        self._install_prior_consumption('train', variant='nonholdout')
        assessment = assess_confirmation(
            self.root, self.request, self.authority, self.runner, now=NOW)
        self.assertEqual(assessment['status'], 'SCIENTIFIC_INTEGRITY_CONSISTENT')

    def test_output_metrics_reproduction_identity_and_runner_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'reproducer required'):
            verify_reproduction(self.root, self.reproduction_ref, self.protocol_ref,
                                self.trial_ref, read(self.root / self.trial_ref['path']),
                                self.inventory_ref, None, now=NOW)
        bad_runner = lambda *_: {'outputs': {'predictions': b'changed'},
                                 'metrics': self.metrics_bytes}
        with self.assertRaisesRegex(ValueError, 'rerun output mismatch'):
            assess_confirmation(self.root, self.request, self.authority,
                                bad_runner, now=NOW)
        path = self.root / 'research/experiment-artifacts/reproduced-output.json'
        path.write_text('{"changed":true}\n')
        with self.assertRaisesRegex(ValueError, 'digest mismatch|history mutated'):
            assess_confirmation(self.root, self.request, self.authority,
                                self.runner, now=NOW)

    def test_frozen_protocol_pin_and_preaccess_checkpoint_binding_rejected(self):
        bad = copy.deepcopy(self.request)
        bad['frozen_protocol_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Verifier-held frozen'):
            assess_confirmation(self.root, bad, self.authority, self.runner, now=NOW)
        state = copy.deepcopy(self.state)
        state['pre_access_checkpoint_sha256'] = '0' * 64
        state['state_sha256'] = state_digest(state)
        with self.assertRaisesRegex(ValueError, 'checkpoint digest mismatch'):
            verify_current_state(self.root, state, now=NOW)

    def test_quant_schema_required_fields_and_extra_properties(self):
        records = [
            ('quant-protocol', read(self.root / self.protocol_ref['path'])),
            ('trial', read(self.root / self.trial_ref['path'])),
            ('trial-inventory', read(self.root / self.inventory_ref['path'])),
            ('reproduction', read(self.root / self.reproduction_ref['path'])),
        ]
        for kind, record in records:
            validate_record(kind, record, self.root, now=NOW)
            for field in record:
                with self.subTest(kind=kind, field=field):
                    bad = copy.deepcopy(record)
                    del bad[field]
                    with self.assertRaises(ValidationError):
                        validate_record(kind, bad, self.root, now=NOW)
            with self.assertRaises(ValidationError):
                validate_record(kind, {**record, 'unexpected': True}, self.root, now=NOW)

    def test_repository_structural_validation_is_not_confirmation(self):
        self.assertGreater(validate_repository(self.root, now=NOW), 0)
        self.assertEqual(set(quant_record_snapshot(self.root, now=NOW)), {
            self.protocol_ref['path'], self.failed_ref['path'], self.trial_ref['path'],
            self.cancelled_ref['path'], self.attempted_ref['path'],
            self.inventory_ref['path'], self.reproduction_ref['path'],
        })


if __name__ == '__main__':
    unittest.main()
