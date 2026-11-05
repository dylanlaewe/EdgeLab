"""Adversarial evidence for the closed runtime-attachment minLength family."""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import unittest

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY,
    RESOURCE_CLASSIFICATION_V54_MANIFEST,
    RESOURCE_CLASSIFICATION_V55_GIT_COMMON_DIR_MIN_LENGTH_PROOF,
    RESOURCE_CLASSIFICATION_V55_REPOSITORY_ROOT_MIN_LENGTH_PROOF,
    RESOURCE_CLASSIFICATION_V55_RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY,
    RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY_DOMAIN,
    ReadinessError,
    _domain_digest,
    _validate_runtime_attachment_min_length_family,
)


GIT_SITE = "91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38"
REPO_SITE = "b9d97c6663e8bf814f90b1e69ba3a8ea30573b0ef575709552fe9c5e20ca06ca"
GIT_MAX = "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574"
REPO_MAX = "bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848"
V54 = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v54.json"
V55 = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v55.json"
V55_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v55.schema.json"


class RuntimeAttachmentMinLengthSchemaProofFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.family = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V55_RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY["path"])
            .read_text(encoding="ascii")
        )
        cls.git = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V55_GIT_COMMON_DIR_MIN_LENGTH_PROOF["path"])
            .read_text(encoding="ascii")
        )
        cls.repo = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V55_REPOSITORY_ROOT_MIN_LENGTH_PROOF["path"])
            .read_text(encoding="ascii")
        )

    def validate(self, family):
        return _validate_runtime_attachment_min_length_family(ROOT, family)

    def redigest(self, family):
        attacked = copy.deepcopy(family)
        value = dict(attacked); value.pop("family_sha256")
        attacked["family_sha256"] = _domain_digest(
            RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY_DOMAIN, value
        )
        return attacked

    def test_family_is_closed_self_bound_and_executable(self):
        self.assertEqual(
            self.validate(self.family),
            {"family_id": "EDGELAB_RUNTIME_V2_RUNTIME_ATTACHMENT_MIN_LENGTH_SCHEMA_PROOF_FAMILY_V1", "member_count": 2, "ordered_site_ids": [GIT_SITE, REPO_SITE]},
        )
        value = dict(self.family); claimed = value.pop("family_sha256")
        self.assertEqual(claimed, _domain_digest(RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY_DOMAIN, value))

    def test_v55_is_exact_v54_prefix_plus_two_zero_rebase_proofs(self):
        predecessor = json.loads((ROOT / V54).read_text(encoding="ascii"))
        current = json.loads((ROOT / V55).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V55_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-2], predecessor["constraints"])
        self.assertEqual(current["constraints"][-2:], [self.git, self.repo])
        self.assertEqual((len(current["constraints"]), current["classified_site_count"], current["unclassified_site_count"]), (54, 87, 634))
        self.assertEqual(schema["properties"]["constraints"]["const"], current["constraints"])
        self.assertEqual((current["coverage_status"], current["generation_disposition"]), ("INCOMPLETE", "DENY"))

    def test_exact_predicate_member_order_coordinates_and_sibling_exclusions(self):
        predicate = self.family["predicate"]
        self.assertEqual((predicate["keyword"], predicate["value"]), ("minLength", 1))
        self.assertEqual(predicate["containing_subschema"], {"type": "string", "minLength": 1, "maxLength": 4096})
        self.assertEqual(predicate["containing_subschema_digest"], "1cb0f2473cb55b110447de322170e5050e56184fc26d1d544cb298ff202d9ac5")
        self.assertEqual([item["site_id"] for item in predicate["allowed_schema_locations"]], [GIT_SITE, REPO_SITE])
        self.assertEqual([item["site"]["site_id"] for item in self.family["excluded_sibling_sites"]], [GIT_MAX, REPO_MAX])

    def test_family_membership_order_predicate_and_full_exclusion_attacks_deny(self):
        attacks = []
        attacked = copy.deepcopy(self.family); attacked["ordered_members"].reverse(); attacks.append(attacked)
        attacked = copy.deepcopy(self.family); attacked["ordered_members"].pop(); attacked["member_count"] = 1; attacks.append(attacked)
        attacked = copy.deepcopy(self.family); attacked["ordered_members"].append(copy.deepcopy(attacked["ordered_members"][0])); attacked["member_count"] = 3; attacks.append(attacked)
        attacked = copy.deepcopy(self.family); attacked["ordered_members"][0]["proof"] = copy.deepcopy(attacked["ordered_members"][1]["proof"]); attacks.append(attacked)
        for key, value in (("keyword", "maxLength"), ("value", 2), ("containing_subschema_digest", "0" * 64)):
            attacked = copy.deepcopy(self.family); attacked["predicate"][key] = value; attacks.append(attacked)
        for key, value in (("path", "schemas/wrong.json"), ("schema_id", "urn:wrong"), ("site_id", REPO_SITE), ("json_pointer", "/properties/wrong/minLength")):
            attacked = copy.deepcopy(self.family); attacked["predicate"]["allowed_schema_locations"][0][key] = value; attacks.append(attacked)
        attacked = copy.deepcopy(self.family); attacked["predicate"]["allowed_schema_locations"][0]["ordered_ancestor_pointers"] = [""]; attacks.append(attacked)
        for index in range(2):
            for field, value in (("classification", "SCHEMA_DECLARATIVE_BOUND"), ("json_pointer", "/wrong"), ("keyword", "minLength"), ("path", "schemas/wrong.json"), ("schema_id", "urn:wrong"), ("site_id", GIT_SITE), ("value", 1)):
                attacked = copy.deepcopy(self.family); attacked["excluded_sibling_sites"][index]["site"][field] = value; attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError): self.validate(self.redigest(attacked))

    def test_member_evidence_family_evidence_and_file_identities_are_disjoint(self):
        member_evidence = [{item["path"] for item in proof["evidence_inputs"]} for proof in (self.git, self.repo)]
        self.assertTrue(member_evidence[0].isdisjoint(member_evidence[1]))
        paths = {
            RESOURCE_CLASSIFICATION_V55_RUNTIME_ATTACHMENT_MIN_LENGTH_FAMILY["path"],
            RESOURCE_CLASSIFICATION_V55_GIT_COMMON_DIR_MIN_LENGTH_PROOF["path"],
            RESOURCE_CLASSIFICATION_V55_REPOSITORY_ROOT_MIN_LENGTH_PROOF["path"],
            *(item["path"] for item in self.family["family_evidence_inputs"]),
            *member_evidence[0], *member_evidence[1],
        }
        identities = {(os.stat(ROOT / path, follow_symlinks=False).st_dev, os.stat(ROOT / path, follow_symlinks=False).st_ino) for path in paths}
        self.assertEqual(len(paths), len(identities))
        for item in [*self.family["family_evidence_inputs"], *self.git["evidence_inputs"], *self.repo["evidence_inputs"]]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (item["byte_length"], item["raw_sha256"]))

    def test_validator_freezes_prior_lanes_and_rejects_live_aggregate_slicing(self):
        source = inspect.getsource(_validate_runtime_attachment_min_length_family)
        tree = ast.parse(source)
        forbidden = "RESOURCE_CLASSIFICATION_SCHEMA_PROOFS"
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == forbidden for node in ast.walk(tree)))
        self.assertIn("RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF", source)
        self.assertEqual(self.family["predecessor"]["manifest_raw_sha256"], RESOURCE_CLASSIFICATION_V54_MANIFEST[2] if len(RESOURCE_CLASSIFICATION_V54_MANIFEST) > 2 else "3713cda2668776f474dfabcf8bafb8b2f2ae9d7b44199a5f1b43fa33076b179a")

    def test_v50_temporal_nonmembership_and_nonclaims_are_explicit(self):
        v50_family = json.loads((ROOT / RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["path"]).read_text(encoding="ascii"))
        excluded = {item["site"]["site_id"] for item in v50_family["excluded_candidates"]}
        self.assertTrue({GIT_SITE, REPO_SITE} <= excluded)
        text = (ROOT / "docs/M0.3A_RUNTIME_ATTACHMENT_MIN_LENGTH_SCHEMA_PROOF_FAMILY.v1.md").read_text()
        for phrase in ("separate successor evidence", "cannot independently discriminate", "Copied-container similarity is not identity", "filesystem paths", "Git common-directory authenticity", "runtime `_string`", "STOP or release clearance", "capital authority"):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
