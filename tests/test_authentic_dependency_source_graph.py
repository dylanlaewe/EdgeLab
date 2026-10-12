import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class DependencySourceGraph(unittest.TestCase):
 def test_sources_exist_once_and_cover_frozen_dependency_reads(self):
  g=json.loads((ROOT/'reports/authentic-stage1-dependency/source-graph.v1.json').read_text());self.assertEqual(len(g['historical_sources']),len(set(g['historical_sources'])))
  for package in ('satisfied','content-sha-denied'):
   root=ROOT/'tests/fixtures/authentic-stage1-dependency'/package
   for source in g['historical_sources']: self.assertTrue((root/source).is_file(),source)
  targets={x for e in g['edges'] for x in e};self.assertTrue({'scheduler-state','dependency-task-head','dependency-task-bytes','completion-bytes','parsed-completion-mapping'}<=targets)
 def test_completion_sha_is_derived_from_retained_task_bytes(self):
  import hashlib
  for package in ('satisfied','content-sha-denied'):
   root=ROOT/'tests/fixtures/authentic-stage1-dependency'/package/'repository';task=(root/'orchestration/tasks/T-DEP-001.v1.json').read_bytes();comp=json.loads((root/'orchestration/completions/T-DEP-001.v1.json').read_text())
   if package=='satisfied':self.assertEqual(comp['content_sha256'],hashlib.sha256(task).hexdigest())
