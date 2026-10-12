import hashlib,json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class Currentness(unittest.TestCase):
 def test_historical_package_is_immutable_for_currentness_cases(self):
  cap=ROOT/'tests/fixtures/authentic-stage1-dependency/satisfied/capture.json';before=hashlib.sha256(cap.read_bytes()).hexdigest();cases=json.loads((ROOT/'reports/authentic-stage1-dependency/currentness-results.v1.json').read_text())['cases'];self.assertEqual(before,hashlib.sha256(cap.read_bytes()).hexdigest())
  for c in cases[:-1]:self.assertEqual((c['historical_status'],c['currentness_status'],c['authorization']),('VALID','STALE','DENY'))
 def test_current_state_cannot_replace_historical_binding(self):
  c=json.loads((ROOT/'reports/authentic-stage1-dependency/currentness-results.v1.json').read_text())['cases'][-1];self.assertEqual((c['historical_status'],c['authorization']),('INVALID','DENY'))
