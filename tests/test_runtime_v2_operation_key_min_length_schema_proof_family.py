"""Adversarial evidence for the closed operation-key minLength family."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    OPERATION_KEY_MIN_LENGTH_FAMILY_DOMAIN,
    RESOURCE_CLASSIFICATION_V49_COMMAND_REQUEST_PROOF,
    RESOURCE_CLASSIFICATION_V50_COMMAND_REQUEST_PROOF,
    RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY,
    RESOURCE_CLASSIFICATION_V50_RESPONSE_PROJECTION_PROOF,
    ReadinessError,
    _domain_digest,
    _validate_operation_key_min_length_family,
)


COMMAND_SITE = "b2840fbfba98b7107e46eee42f8d818a2e8d60582f9fbd4e394993a686bda437"
RESPONSE_SITE = "5dce821ee45f15010f24959f58819323b0112024635aeb4ede5380e3e47c69d4"
EXCLUDED_SITES = (
    "9b3ca1986a596bd1fadb7cf6559bd1a3e866025dbf8b13c740b7066a144ea6cf",
    "9836fab2fe041176198024df5b8f7dc1f53079e2ae0e7476d64234d419b320a3",
    "11aad2118d8aa3770406f102d8352ab1c53768ca67f00e89a27e805a277a0d44",
    "98b8b606f34e83fc7d09db7812895974a0fc51620342cc4369f3d4f1d152649f",
    "17390c9d39424cc68c740b2b293fffc51389f9a079064a592c3bc1618bd18b4e",
    "91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38",
    "b9d97c6663e8bf814f90b1e69ba3a8ea30573b0ef575709552fe9c5e20ca06ca",
    "5ecdd89c144526d940c1014e6bc6978dba8c91385f5a638f90c08d797957fc9f",
    "283b853e73f8a1a8f37eb152fd5e8d16f4471f69eb3e1949c89bdcdf2c81cf58",
    "abf041254a94aa485d41185f38601e013776a07ea7c18a6d5752cf12ade18568",
    "61d74daa869567fffcb684c270d1a932b1fd394ff00f9c1f42aa7a1db021591e",
    "85e3025e297b6d908712678e0358a97de2d8d04f2ce9af152e2ea3f566185a0a",
    "efe3d459a742b92d49ba6951b37702e45fe4ca0d5647246ffed0d54d6021419f",
    "ccab1adbac540b97ae382559e66a6c612395613e35a558e9d47a845f4db67c8b",
)
V49_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v49.json"
V50_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v50.json"
V50_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v50.schema.json"


class OperationKeyMinLengthSchemaProofFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.family = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["path"])
            .read_text(encoding="ascii")
        )
        cls.command = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_COMMAND_REQUEST_PROOF["path"])
            .read_text(encoding="ascii")
        )
        cls.response = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_RESPONSE_PROJECTION_PROOF["path"])
            .read_text(encoding="ascii")
        )

    def validate(self, family):
        return _validate_operation_key_min_length_family(ROOT, family)

    def test_family_is_closed_self_bound_and_executable(self):
        self.assertEqual(
            self.validate(self.family),
            {
                "family_id": (
                    "EDGELAB_RUNTIME_V2_OPERATION_KEY_MIN_LENGTH_"
                    "SCHEMA_PROOF_FAMILY_V1"
                ),
                "member_count": 2,
                "ordered_site_ids": [COMMAND_SITE, RESPONSE_SITE],
            },
        )
        digest_value = dict(self.family)
        claimed = digest_value.pop("family_sha256")
        self.assertEqual(
            claimed,
            _domain_digest(OPERATION_KEY_MIN_LENGTH_FAMILY_DOMAIN, digest_value),
        )

    def test_v50_is_exact_v49_prefix_plus_two_independent_proofs(self):
        predecessor = json.loads((ROOT / V49_MANIFEST).read_text(encoding="ascii"))
        current = json.loads((ROOT / V50_MANIFEST).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V50_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-2], predecessor["constraints"])
        self.assertEqual(current["constraints"][-2:], [self.command, self.response])
        self.assertEqual(len(current["constraints"]), 45)
        self.assertEqual(current["classified_site_count"], 78)
        self.assertEqual(current["unclassified_site_count"], 643)
        self.assertEqual(schema["properties"]["constraints"]["const"], current["constraints"])
        self.assertEqual(current["coverage_status"], "INCOMPLETE")
        self.assertEqual(current["generation_disposition"], "DENY")

    def test_member_proof_and_evidence_lanes_are_unique_and_disjoint(self):
        members = self.family["ordered_members"]
        self.assertEqual(len({item["proof"]["path"] for item in members}), 2)
        evidence_sets = [
            {item["path"] for item in proof["evidence_inputs"]}
            for proof in (self.command, self.response)
        ]
        self.assertTrue(evidence_sets[0].isdisjoint(evidence_sets[1]))
        all_paths = {
            *(item["proof"]["path"] for item in members),
            *evidence_sets[0],
            *evidence_sets[1],
            *(item["path"] for item in self.family["family_evidence_inputs"]),
        }
        identities = {
            (
                os.stat(ROOT / path, follow_symlinks=False).st_dev,
                os.stat(ROOT / path, follow_symlinks=False).st_ino,
            )
            for path in all_paths
        }
        self.assertEqual(len(identities), len(all_paths))

    def test_exact_family_predicate_and_all_exclusions_are_pinned(self):
        predicate = self.family["predicate"]
        self.assertEqual(predicate["keyword"], "minLength")
        self.assertEqual(predicate["value"], 1)
        self.assertEqual(
            predicate["json_pointer"], "/properties/operation_key/minLength"
        )
        self.assertEqual(
            predicate["ordered_ancestor_pointers"],
            ["", "/properties", "/properties/operation_key"],
        )
        self.assertEqual(
            predicate["containing_subschema_digest"],
            "1018889ae7b09b8e99363ab04e7d8637e3bfda0ae1aabed405c2aae2e9c78a26",
        )
        self.assertEqual(
            [item["site"]["site_id"] for item in self.family["excluded_candidates"]],
            list(EXCLUDED_SITES),
        )
        self.assertEqual(
            [item["reason"] for item in self.family["excluded_candidates"][:2]],
            ["NESTED_OPERATION_KEY_LOOKALIKE"] * 2,
        )
        self.assertEqual(
            [item["reason"] for item in self.family["excluded_candidates"][2:]],
            ["NON_MEMBER_MIN_LENGTH_CANDIDATE"] * 12,
        )

    def test_family_expansion_contraction_reorder_swap_and_exclusion_attacks_deny(self):
        attacks = []
        attacked = copy.deepcopy(self.family)
        attacked["ordered_members"].reverse()
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["ordered_members"].pop()
        attacked["member_count"] = 1
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["ordered_members"].append(copy.deepcopy(attacked["ordered_members"][0]))
        attacked["member_count"] = 3
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["ordered_members"][0]["proof"] = copy.deepcopy(
            attacked["ordered_members"][1]["proof"]
        )
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["ordered_members"][0]["constraint_id"] = (
            "SCHEMA_DECLARATIVE_MAXLENGTH_"
            "9A219D2847AF954061FE8E233E8E316F57A09E9EC256C83ED829724B9930F626"
        )
        attacked["ordered_members"][0]["proof"] = dict(
            RESOURCE_CLASSIFICATION_V49_COMMAND_REQUEST_PROOF
        )
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["predicate"]["value"] = 2
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["excluded_candidates"].pop()
        attacks.append(attacked)
        exclusion_field_attacks = {
            "classification": "SCHEMA_DECLARATIVE_BOUND",
            "json_pointer": "/properties/operation_key/minLength",
            "keyword": "maxLength",
            "path": "schemas/m0-3a-command-request.v2.schema.json",
            "schema_id": "urn:edgelab:m0-3a-command-request:2",
            "value": 2,
        }
        for field, value in exclusion_field_attacks.items():
            attacked = copy.deepcopy(self.family)
            attacked["excluded_candidates"][0]["site"][field] = value
            attacks.append(attacked)
        for excluded in self.family["excluded_candidates"]:
            attacked = copy.deepcopy(self.family)
            attacked["ordered_members"][0]["schema_site_id"] = excluded["site"]["site_id"]
            attacks.append(attacked)
        for attacked in attacks:
            digest_value = dict(attacked)
            digest_value.pop("family_sha256")
            attacked["family_sha256"] = _domain_digest(
                OPERATION_KEY_MIN_LENGTH_FAMILY_DOMAIN, digest_value
            )
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_family_evidence_and_artifact_bytes_are_pinned(self):
        for item in self.family["family_evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
        path = ROOT / RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["path"]
        data = path.read_bytes()
        self.assertEqual(
            len(data),
            RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["byte_length"],
        )
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["raw_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
