"""Adversarial evidence for task-state taskId minLength."""
from __future__ import annotations
import copy, hashlib, json, unittest
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V52_TASK_STATE_TASK_ID_PROOF,
    ReadinessError, _resource_site_maps,
    _validate_schema_declarative_keyword_proof, build_report,
)

SITE="cf92955f6103875d6751aec4c72558d0e79c752a7bff2bb15cbcdcebf676127b"
OTHER="05539c8dd1cbfd983353c118532290202301b967e2ac7fb48c308003f1c9fb0b"
EXCLUDED="17390c9d39424cc68c740b2b293fffc51389f9a079064a592c3bc1618bd18b4e"

class TaskStateTaskIdMinLengthProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        discovery=build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        cls.source_sites,cls.schema_sites=_resource_site_maps(discovery); cls.schema_inputs=discovery["schema_inputs"]
        cls.proof=json.loads((ROOT/RESOURCE_CLASSIFICATION_V52_TASK_STATE_TASK_ID_PROOF["path"]).read_text())
    def validate(self,value): return _validate_schema_declarative_keyword_proof(ROOT,value,self.source_sites,self.schema_sites,self.schema_inputs)
    def test_exact_site_context_and_local_behavior(self):
        self.assertEqual(self.validate(self.proof)["schema_site_id"],SITE); self.assertEqual(self.proof["addressed_site"],self.schema_sites[SITE])
        self.assertEqual(self.proof["schema_context"]["containing_subschema_digest"],"508f4e9c702082b8fcc8420d76e459159cb9103585311b30b2e0dc6f51416644")
        local=lambda value: None if type(value) is not str else len(value)>=1
        self.assertFalse(local("")); self.assertTrue(local("A")); self.assertTrue(local("\N{GRINNING FACE}")); self.assertTrue(local("e\N{COMBINING ACUTE ACCENT}"))
        for value in (0,True,None,[],{}): self.assertIsNone(local(value))
    def test_cross_site_and_semantic_attacks_deny(self):
        attacks=[]
        for site in (OTHER,EXCLUDED):
            attacked=copy.deepcopy(self.proof); attacked["schema_site_id"]=site; attacked["addressed_site"]=copy.deepcopy(self.schema_sites[site]); attacks.append(attacked)
        for field,value in (("constraint_id","WRONG"),("semantic_subject","RUNTIME_TASK_BEHAVIOR"),("unit","BYTES")):
            attacked=copy.deepcopy(self.proof); attacked[field]=value; attacks.append(attacked)
        for field,value in (("metric","UTF8_BYTE_COUNT"),("operator",">"),("bound",2)):
            attacked=copy.deepcopy(self.proof); attacked["declarative_equation"][field]=value; attacks.append(attacked)
        attacked=copy.deepcopy(self.proof); attacked["schema_context"]["containing_subschema_digest"]="0"*64; attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError): self.validate(attacked)
    def test_evidence_and_nonclaims_are_member_owned(self):
        for item in self.proof["evidence_inputs"]:
            raw=(ROOT/item["path"]).read_bytes(); self.assertEqual(len(raw),item["byte_length"]); self.assertEqual(hashlib.sha256(raw).hexdigest(),item["raw_sha256"])
        text=(ROOT/self.proof["evidence_inputs"][0]["path"]).read_text()
        for phrase in ("task-id grammar","`$ref` reachability","cross-role equivalence","runtime task behavior","STOP clearance","capital authority"): self.assertIn(phrase,text)

if __name__ == "__main__": unittest.main()
