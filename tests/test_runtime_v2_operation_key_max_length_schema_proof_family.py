"""Adversarial evidence for the closed operation-key maxLength family."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    OPERATION_KEY_MAX_LENGTH_FAMILY_DOMAIN,
    RESOURCE_CLASSIFICATION_V49_COMMAND_REQUEST_PROOF,
    RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY,
    RESOURCE_CLASSIFICATION_V49_RESPONSE_PROJECTION_PROOF,
    ReadinessError,
    _domain_digest,
    _validate_operation_key_max_length_family,
)


COMMAND_SITE = "9a219d2847af954061fe8e233e8e316f57a09e9ec256c83ed829724b9930f626"
RESPONSE_SITE = "1d6cb316a9edd5dfe397fc767d6e23f7c22e93c1e1292f19cbeff98cfea96514"
EXCLUDED_SITES = (
    "f8244837e97c8e26be37e62a9421ed1fc119d6a963d59be35a8e1e6f6aaee1b4",
    "a35ed77aadc69aa6cb058b3aa72dc3041f416318c992c539b051443710054f23",
)
V48_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v48.json"
V49_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v49.json"
V49_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v49.schema.json"


class OperationKeyMaxLengthSchemaProofFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.family = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY["path"])
            .read_text(encoding="ascii")
        )
        cls.command = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V49_COMMAND_REQUEST_PROOF["path"])
            .read_text(encoding="ascii")
        )
        cls.response = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V49_RESPONSE_PROJECTION_PROOF["path"])
            .read_text(encoding="ascii")
        )

    def validate(self, family):
        return _validate_operation_key_max_length_family(ROOT, family)

    def test_family_is_closed_self_bound_and_executable(self):
        self.assertEqual(
            self.validate(self.family),
            {
                "family_id": (
                    "EDGELAB_RUNTIME_V2_OPERATION_KEY_MAX_LENGTH_"
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
            _domain_digest(OPERATION_KEY_MAX_LENGTH_FAMILY_DOMAIN, digest_value),
        )
        self.assertEqual(self.family["member_count"], 2)
        self.assertEqual(
            [item["schema_site_id"] for item in self.family["ordered_members"]],
            [COMMAND_SITE, RESPONSE_SITE],
        )

    def test_v49_is_exact_v48_prefix_plus_two_independent_proofs(self):
        predecessor = json.loads((ROOT / V48_MANIFEST).read_text(encoding="ascii"))
        current = json.loads((ROOT / V49_MANIFEST).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V49_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-2], predecessor["constraints"])
        self.assertEqual(current["constraints"][-2:], [self.command, self.response])
        self.assertEqual(len(current["constraints"]), 43)
        self.assertEqual(current["classified_site_count"], 76)
        self.assertEqual(current["unclassified_site_count"], 645)
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
        self.assertTrue(
            set(self.family["family_evidence_inputs"][0].keys())
            == {"byte_length", "path", "raw_sha256"}
        )
        all_paths = {
            *(item["proof"]["path"] for item in members),
            *evidence_sets[0],
            *evidence_sets[1],
            *(item["path"] for item in self.family["family_evidence_inputs"]),
        }
        identities = {
            (os.stat(ROOT / path, follow_symlinks=False).st_dev,
             os.stat(ROOT / path, follow_symlinks=False).st_ino)
            for path in all_paths
        }
        self.assertEqual(len(identities), len(all_paths))

    def test_exact_family_predicate_and_excluded_lookalikes_are_pinned(self):
        predicate = self.family["predicate"]
        self.assertEqual(predicate["keyword"], "maxLength")
        self.assertEqual(predicate["value"], 256)
        self.assertEqual(
            predicate["json_pointer"], "/properties/operation_key/maxLength"
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
            [item["site_id"] for item in self.family["excluded_lookalikes"]],
            list(EXCLUDED_SITES),
        )

    def test_family_expansion_contraction_reorder_and_swap_attacks_deny(self):
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
        attacked["predicate"]["value"] = 255
        attacks.append(attacked)
        attacked = copy.deepcopy(self.family)
        attacked["excluded_lookalikes"].pop()
        attacks.append(attacked)
        for attacked in attacks:
            digest_value = dict(attacked)
            digest_value.pop("family_sha256")
            attacked["family_sha256"] = _domain_digest(
                OPERATION_KEY_MAX_LENGTH_FAMILY_DOMAIN, digest_value
            )
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_family_evidence_and_artifact_bytes_are_pinned(self):
        for item in self.family["family_evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
        raw = (ROOT / RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY["path"])
        data = raw.read_bytes()
        self.assertEqual(
            len(data), RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY["byte_length"]
        )
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY["raw_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
