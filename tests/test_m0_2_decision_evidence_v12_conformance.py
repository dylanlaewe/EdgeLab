import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, RefResolver

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / 'schemas/m0-2-decision-evidence-envelope.v12.schema.json'

def validator():
    schema = json.loads(SCHEMA.read_text())
    return Draft202012Validator(schema, resolver=RefResolver(SCHEMA.resolve().as_uri(), schema))

class V12Conformance(unittest.TestCase):
    def test_golden_dispatch_and_deny_validate(self):
        check = validator()
        for name in ('m0-2-v12-dispatch.json', 'm0-2-v12-deny.json'):
            self.assertFalse(list(check.iter_errors(json.loads((ROOT / 'tests/fixtures' / name).read_text()))))

    def test_raw_deny_has_no_operation(self):
        value = json.loads((ROOT / 'tests/fixtures/m0-2-v12-deny.json').read_text())
        self.assertNotIn('operation', value['raw_evidence'])
        self.assertIsNone(value['normalized_output']['operation'])
