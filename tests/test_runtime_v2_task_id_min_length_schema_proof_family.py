"""Adversarial evidence for the closed four-member taskId minLength family."""
from __future__ import annotations
import ast, copy, hashlib, inspect, json, os, unittest
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY,
    RESOURCE_CLASSIFICATION_V52_TASK_ID_PROOFS,
    TASK_ID_MIN_LENGTH_FAMILY_DOMAIN,
    ReadinessError, _domain_digest, _validate_task_id_min_length_family,
)

MEMBERS=(
    "05539c8dd1cbfd983353c118532290202301b967e2ac7fb48c308003f1c9fb0b",
    "54cb7f4b6dcfc8579c6d43d5ad4b41a1fd2f90aff99b6cb9ae0b3369723e21a5",
    "237e413d823580d4e5e98825887c2296349718843b5b6de092aec94ff20112da",
    "cf92955f6103875d6751aec4c72558d0e79c752a7bff2bb15cbcdcebf676127b",
)
EXCLUDED="17390c9d39424cc68c740b2b293fffc51389f9a079064a592c3bc1618bd18b4e"
MAXLENGTH_SIBLINGS=(
    "cb1d0aebfb1d23af2030ee9ff52e1469b3b93845d7dc620a91938f761314fd24",
    "bd2bf34983ecec15b22e5b8a48c280f4941c732740ae8515137fb64081ff7182",
    "2fa3bdec1ab1d008f775f42a3e869e69316d81b35b37eb3fa9f0c36654ac5b83",
    "5696f74e622d3eb9fd5126728641b1238afc172e0d5738a5ff88704060f3de77",
)
V51="docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v51.json"
V52="docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v52.json"
V52_SCHEMA="schemas/m0-3a-runtime-v2-resource-classification.v52.schema.json"

class TaskIdMinLengthSchemaProofFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.family=json.loads((ROOT/RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY["path"]).read_text())
        cls.proofs=[json.loads((ROOT/item["path"]).read_text()) for item in RESOURCE_CLASSIFICATION_V52_TASK_ID_PROOFS]
    def validate(self,value): return _validate_task_id_min_length_family(ROOT,value)
    def test_family_is_closed_ordered_and_self_bound(self):
        self.assertEqual(self.validate(self.family)["ordered_site_ids"],list(MEMBERS))
        digest=dict(self.family); claimed=digest.pop("family_sha256")
        self.assertEqual(claimed,_domain_digest(TASK_ID_MIN_LENGTH_FAMILY_DOMAIN,digest))
        self.assertEqual([x["schema_site_id"] for x in self.family["ordered_members"]],list(MEMBERS))
        self.assertEqual(self.family["excluded_candidate"]["site"]["site_id"],EXCLUDED)
    def test_v52_is_exact_v51_prefix_plus_four_proofs(self):
        old=json.loads((ROOT/V51).read_text()); new=json.loads((ROOT/V52).read_text()); schema=json.loads((ROOT/V52_SCHEMA).read_text())
        self.assertEqual(new["constraints"][:-4],old["constraints"]); self.assertEqual(new["constraints"][-4:],self.proofs)
        self.assertEqual((len(new["constraints"]),new["classified_site_count"],new["unclassified_site_count"]),(50,83,638))
        self.assertEqual(schema["properties"]["constraints"]["const"],new["constraints"])
        self.assertEqual((new["coverage_status"],new["generation_disposition"]),("INCOMPLETE","DENY"))
    def test_member_and_family_evidence_are_disjoint_and_not_aliased(self):
        paths=[self.family["family_evidence_inputs"][0]["path"],self.family["family_evidence_inputs"][1]["path"]]
        for proof in self.proofs: paths.extend(x["path"] for x in proof["evidence_inputs"])
        self.assertEqual(len(paths),len(set(paths)))
        identities={(os.stat(ROOT/p,follow_symlinks=False).st_dev,os.stat(ROOT/p,follow_symlinks=False).st_ino) for p in paths}
        self.assertEqual(len(identities),len(paths))
    def test_contraction_expansion_reorder_swap_and_predicate_attacks_deny(self):
        attacks=[]
        attacked=copy.deepcopy(self.family); attacked["ordered_members"].pop(); attacked["member_count"]=3; attacks.append(attacked)
        attacked=copy.deepcopy(self.family); attacked["ordered_members"].append(copy.deepcopy(attacked["ordered_members"][0])); attacked["member_count"]=5; attacks.append(attacked)
        attacked=copy.deepcopy(self.family); attacked["ordered_members"][0]["schema_site_id"]=EXCLUDED; attacked["ordered_members"][0]["constraint_id"]="SCHEMA_DECLARATIVE_MINLENGTH_"+EXCLUDED.upper(); attacks.append(attacked)
        for index,site_id in enumerate(MAXLENGTH_SIBLINGS):
            attacked=copy.deepcopy(self.family); attacked["ordered_members"][index]["schema_site_id"]=site_id; attacked["ordered_members"][index]["constraint_id"]="SCHEMA_DECLARATIVE_MAXLENGTH_"+site_id.upper(); attacks.append(attacked)
        attacked=copy.deepcopy(self.family); attacked["ordered_members"].reverse(); attacks.append(attacked)
        attacked=copy.deepcopy(self.family); attacked["ordered_members"][0]["proof"]=copy.deepcopy(attacked["ordered_members"][1]["proof"]); attacks.append(attacked)
        for field,value in (("keyword","maxLength"),("value",2),("json_pointer","/$defs/taskId/maxLength"),("containing_subschema_digest","0"*64)):
            attacked=copy.deepcopy(self.family); attacked["predicate"][field]=value; attacks.append(attacked)
        for attacked in attacks:
            value=dict(attacked); value.pop("family_sha256"); attacked["family_sha256"]=_domain_digest(TASK_ID_MIN_LENGTH_FAMILY_DOMAIN,value)
            with self.assertRaises(ReadinessError): self.validate(attacked)
    def test_excluded_full_record_field_mutations_deny_with_recomputed_digest(self):
        attacked=copy.deepcopy(self.family); attacked["excluded_candidate"]["reason"]="MEMBER"
        digest=dict(attacked); digest.pop("family_sha256"); attacked["family_sha256"]=_domain_digest(TASK_ID_MIN_LENGTH_FAMILY_DOMAIN,digest)
        with self.assertRaises(ReadinessError): self.validate(attacked)
        replacements={"classification":"SCHEMA_DECLARATIVE_BOUND","json_pointer":"/$defs/taskId/minLength","keyword":"maxLength","path":"schemas/m0-3a-task-state.v2.schema.json","schema_id":"urn:wrong","site_id":MEMBERS[0],"value":2}
        for field,value in replacements.items():
            attacked=copy.deepcopy(self.family); attacked["excluded_candidate"]["site"][field]=value
            digest=dict(attacked); digest.pop("family_sha256"); attacked["family_sha256"]=_domain_digest(TASK_ID_MIN_LENGTH_FAMILY_DOMAIN,digest)
            with self.assertRaises(ReadinessError): self.validate(attacked)
    def test_family_artifact_and_evidence_bytes_are_pinned(self):
        for item in self.family["family_evidence_inputs"]:
            raw=(ROOT/item["path"]).read_bytes(); self.assertEqual(len(raw),item["byte_length"]); self.assertEqual(hashlib.sha256(raw).hexdigest(),item["raw_sha256"])
        raw=(ROOT/RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY["path"]).read_bytes()
        self.assertEqual(len(raw),RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY["byte_length"]); self.assertEqual(hashlib.sha256(raw).hexdigest(),RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY["raw_sha256"])
    def test_frozen_family_validator_has_no_live_proof_aggregate_dependency(self):
        source=inspect.getsource(_validate_task_id_min_length_family)
        tree=ast.parse(source)
        self.assertFalse(any(isinstance(node,ast.Name) and node.id=="RESOURCE_CLASSIFICATION_SCHEMA_PROOFS" for node in ast.walk(tree)))

if __name__ == "__main__": unittest.main()
