import json
import base64
import hashlib
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, RefResolver

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / 'schemas/m0-2-decision-evidence-envelope.v12.schema.json'

def validator():
    schema = json.loads(SCHEMA.read_text())
    return Draft202012Validator(schema, resolver=RefResolver(SCHEMA.resolve().as_uri(), schema))

class V12Conformance(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT / 'tests/fixtures' / name).read_text())

    def canonical(self, value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

    def test_golden_dispatch_and_deny_validate(self):
        check = validator()
        for name in ('m0-2-v12-dispatch.json', 'm0-2-v12-deny.json'):
            self.assertFalse(list(check.iter_errors(self.load(name))))

    def test_raw_deny_has_no_operation(self):
        value = self.load('m0-2-v12-deny.json')
        self.assertNotIn('operation', value['raw_evidence'])
        self.assertIsNone(value['normalized_output']['operation'])

    def test_root_graph_and_raw_evidence_are_self_consistent(self):
        for name in ('m0-2-v12-dispatch.json', 'm0-2-v12-deny.json'):
            value = self.load(name)
            artifacts = {item['artifact_id']: item for item in value['artifacts']}
            blobs = {item['blob_id']: item for item in value['blobs']}
            self.assertEqual(len(artifacts), len(value['artifacts']))
            self.assertEqual(len(blobs), len(value['blobs']))
            for artifact in artifacts.values():
                if artifact['kind'] == 'FILE':
                    self.assertIn(artifact['blob_id'], blobs)
            raw = {key: value['raw_evidence'][key] for key in ('decision','decision_id','task_id','reason','execution_adapter')}
            if value['raw_evidence']['decision'] == 'DISPATCH':
                raw['operation'] = value['raw_evidence']['operation']
            data = self.canonical(raw)
            self.assertEqual(base64.b64decode(value['raw_evidence']['bytes_base64'], validate=True), data)
            self.assertEqual(value['raw_evidence']['byte_length'], len(data))
            self.assertEqual(value['raw_evidence']['sha256'], hashlib.sha256(data).hexdigest())

    def test_currentness_only_mutation_does_not_change_historical_input(self):
        value = self.load('m0-2-v12-dispatch.json')
        historical = self.canonical(value['historical_input'])
        value['currentness_binding']['generations']['scheduler'] += 1
        self.assertEqual(historical, self.canonical(value['historical_input']))
