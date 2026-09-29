import copy
import unittest
from src.edgelab.orchestration import ALLOWED, completion, decision
from src.edgelab.validate import ROOT

class OrchestrationTests(unittest.TestCase):
 def task(self, action='SYNTHETIC_TEST'):
  return {'task_id':'T1','milestone':'M0.2','action_classification':action,'assigned_role':'00 Director','status':'QUEUED','dependencies':[],'handoff_ref':'docs/handoffs/H-M0-027.v2.json','attempt':1,'review_required':True,'reviewer_role':'05 Skeptic'}
 def test_allowed_and_review_routing(self):
  t=self.task(); self.assertEqual(decision(ROOT,t,completed=set())['decision'],'DISPATCH'); self.assertEqual(completion(t,claim_task='T1',evidence=['x'],reviewer_decision='REJECT'),'ROUTE_REMEDIATION'); self.assertEqual(completion(t,claim_task='T1',evidence=['x'],reviewer_decision='APPROVE'),'READY_FOR_DIRECTOR_GATE')
 def test_allowlist_and_safety_denials(self):
  for action in ['OTHER','SCOUT_DISCOVERY','EXTERNAL_INGESTION','RESEARCH_CAMPAIGN','QUANT_REAL_EXPERIMENT','PAPER_PORTFOLIO','LIVE_EXECUTION','CAPITAL_MUTATION','PLUGIN_INSTALL']:
   self.assertEqual(decision(ROOT,self.task(action),completed=set())['decision'],'DENY')
 def test_stale_dependency_writer_selfreview_and_capability_deny(self):
  t=self.task(); self.assertEqual(decision(ROOT,{**t,'handoff_ref':'docs/handoffs/H-M0-027.v1.json'},completed=set())['decision'],'DENY'); self.assertEqual(decision(ROOT,{**t,'dependencies':['X']},completed=set())['decision'],'DENY'); self.assertEqual(decision(ROOT,t,completed=set(),writer_task='other')['decision'],'DENY'); self.assertEqual(decision(ROOT,{**t,'reviewer_role':'00 Director'},completed=set())['decision'],'DENY'); self.assertEqual(decision(ROOT,t,completed=set(),capability={'approval_status':'UNAPPROVED','revoked':False,'executable_code':False})['decision'],'DENY')
 def test_all_governed_categories_explicit(self): self.assertIn('SYNTHETIC_TEST',ALLOWED)
