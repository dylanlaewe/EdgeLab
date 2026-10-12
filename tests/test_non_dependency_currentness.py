import json
from pathlib import Path
import unittest
R=Path(__file__).resolve().parents[1]
class Currentness(unittest.TestCase):
 def test_all_current_authority_mutations_fail_closed(self):
  x=json.loads((R/'reports/authentic-stage1-dependency/non-dependency-currentness-results.v1.json').read_text());self.assertGreaterEqual(len(x['cases']),20);self.assertEqual(x['historical_status'],'VALID');self.assertEqual(x['expected']['authorization'],'DENY')
