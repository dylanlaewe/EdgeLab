"""Adversarial evidence for response-projection operation-key minLength."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V50_RESPONSE_PROJECTION_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SITE_ID = "5dce821ee45f15010f24959f58819323b0112024635aeb4ede5380e3e47c69d4"
OTHER_MEMBER_ID = (
    "b2840fbfba98b7107e46eee42f8d818a2e8d60582f9fbd4e394993a686bda437"
)
MAX_LENGTH_SITE_ID = (
    "1d6cb316a9edd5dfe397fc767d6e23f7c22e93c1e1292f19cbeff98cfea96514"
)


class ResponseProjectionOperationKeyMinLengthProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        report = build_report(ROOT)
        cls.discovery = report["inventory"]["resource_inventory_discovery"]
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_RESPONSE_PROJECTION_PROOF["path"])
            .read_text(encoding="ascii")
        )

    def validate(self, proof):
        return _validate_schema_declarative_keyword_proof(
            ROOT,
            proof,
            self.source_sites,
            self.schema_sites,
            self.discovery["schema_inputs"],
        )

    def test_proof_is_closed_exact_and_executable(self):
        schema = json.loads(
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"])
            .read_text(encoding="ascii")
        )
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(self.proof)), [])
        result = self.validate(self.proof)
        self.assertEqual(result["schema_site_id"], SITE_ID)
        self.assertEqual(result["validated_evidence_input_count"], 2)
        self.assertEqual(self.proof["addressed_site"], self.schema_sites[SITE_ID])
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "1018889ae7b09b8e99363ab04e7d8637e3bfda0ae1aabed405c2aae2e9c78a26",
        )

    def test_local_string_boundaries_and_non_domain_behavior(self):
        bound = self.proof["declarative_equation"]["bound"]

        def local(value):
            return None if type(value) is not str else len(value) >= bound

        self.assertFalse(local(""))
        self.assertTrue(local("a"))
        self.assertTrue(local("ab"))
        astral = "\N{GRINNING FACE}"
        self.assertEqual(len(astral), 1)
        self.assertGreater(len(astral.encode("utf-8")), 1)
        self.assertTrue(local(astral))
        for value in (0, True, None, [], {}):
            self.assertIsNone(local(value))

    def test_coordinate_context_equation_and_cross_member_attacks_deny(self):
        attacks = []
        for field, value in (
            ("constraint_id", "SCHEMA_DECLARATIVE_MINLENGTH_WRONG"),
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "OPERATION_KEY_GRAMMAR"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "UTF8_BYTE_COUNT"), ("operator", ">"), ("bound", 2)
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("schema_document_raw_sha256", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
            ("containing_subschema_pointer", "/properties"),
            ("containing_subschema_digest", "1" * 64),
            ("instance_domain", "PATH"),
            ("non_domain_behavior", "REJECT"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"]["ordered_pointer_sequence"].reverse()
        attacks.append(attacked)
        for sibling in ("type", "maxLength", "pattern"):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"]["required_sibling_pointers"] = [
                f"/properties/operation_key/{sibling}"
            ]
            attacks.append(attacked)
        for substitution in (OTHER_MEMBER_ID, MAX_LENGTH_SITE_ID):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_site_id"] = substitution
            attacked["addressed_site"] = copy.deepcopy(self.schema_sites[substitution])
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = next(iter(self.source_sites))
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_evidence_is_member_owned_distinct_and_pinned(self):
        evidence = self.proof["evidence_inputs"]
        self.assertEqual(len(evidence), 2)
        self.assertEqual(len({item["path"] for item in evidence}), 2)
        for item in evidence:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
        attacked = copy.deepcopy(self.proof)
        attacked["evidence_inputs"][1] = copy.deepcopy(attacked["evidence_inputs"][0])
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_member_nonclaims_remain_explicit(self):
        evidence = (ROOT / self.proof["evidence_inputs"][0]["path"]).read_text()
        for phrase in (
            "adjacent `type`, `maxLength`, and `pattern`",
            "full nonempty-string validity",
            "`allOf`, `if`, or `then` behavior",
            "projection correspondence",
            "runtime `_OPERATION_KEY`",
            "STOP clearance",
            "capital authority",
        ):
            self.assertIn(phrase, evidence)


if __name__ == "__main__":
    unittest.main()
