"""Adversarial evidence for repository-root realpath maxLength."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848"
)
GIT_COMMON_MAX_SITE = (
    "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574"
)
REPOSITORY_ROOT_MIN_SITE = (
    "b9d97c6663e8bf814f90b1e69ba3a8ea30573b0ef575709552fe9c5e20ca06ca"
)
GIT_COMMON_MIN_SITE = (
    "91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38"
)
SOURCE_HELPER_SITE = (
    "c82b0b9f12d9693bea73cc4ab5e3f77a4a5b83d19c5f8f8e8dee1d1c201cbc6b"
)
V50_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v50.json"
V51_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v51.json"
V51_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v51.schema.json"


class RepositoryRootRealpathMaxLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        report = build_report(ROOT)
        cls.discovery = report["inventory"]["resource_inventory_discovery"]
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF["path"])
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

    def test_selected_proof_is_closed_and_executable(self):
        proof_schema = json.loads(
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"])
            .read_text(encoding="ascii")
        )
        Draft202012Validator.check_schema(proof_schema)
        self.assertEqual(
            list(Draft202012Validator(proof_schema).iter_errors(self.proof)), []
        )
        self.assertEqual(
            self.validate(self.proof),
            {
                "constraint_id": "SCHEMA_DECLARATIVE_MAXLENGTH_" + SELECTED_SITE_ID.upper(),
                "proof_kind": "SCHEMA_DECLARATIVE_KEYWORD_V1",
                "schema_site_id": SELECTED_SITE_ID,
                "validated_evidence_input_count": 2,
            },
        )
        self.assertEqual(self.proof["addressed_site"], self.schema_sites[SELECTED_SITE_ID])
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "1cb0f2473cb55b110447de322170e5050e56184fc26d1d544cb298ff202d9ac5",
        )

    def test_local_boundaries_unicode_units_and_nonstring_no_assertion(self):
        bound = self.proof["declarative_equation"]["bound"]

        def local(instance):
            return None if type(instance) is not str else len(instance) <= bound

        self.assertTrue(local("a" * 4095))
        self.assertTrue(local("a" * 4096))
        self.assertFalse(local("a" * 4097))
        self.assertTrue(local(""))
        astral = "\N{GRINNING FACE}" * 4096
        self.assertEqual(len(astral), 4096)
        self.assertGreater(len(astral.encode("utf-8")), 4096)
        self.assertTrue(local(astral))
        self.assertFalse(local(astral + "\N{GRINNING FACE}"))
        combined = "e\N{COMBINING ACUTE ACCENT}" * 2048
        self.assertEqual(len(combined), 4096)
        self.assertTrue(local(combined))
        self.assertFalse(local(combined + "x"))
        for value in (0, True, None, [], {}):
            self.assertIsNone(local(value))

    def test_v51_is_exact_v50_prefix_plus_one_proof(self):
        predecessor = json.loads((ROOT / V50_MANIFEST).read_text(encoding="ascii"))
        current = json.loads((ROOT / V51_MANIFEST).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V51_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-1], predecessor["constraints"])
        self.assertEqual(current["constraints"][-1], self.proof)
        self.assertEqual(len(current["constraints"]), 46)
        self.assertEqual(current["classified_site_count"], 79)
        self.assertEqual(current["unclassified_site_count"], 642)
        self.assertEqual(schema["properties"]["constraints"]["const"], current["constraints"])
        self.assertEqual(current["coverage_status"], "INCOMPLETE")
        self.assertEqual(current["generation_disposition"], "DENY")

    def test_reverse_schema_and_equal_valued_source_substitutions_deny(self):
        for site_id in (
            GIT_COMMON_MAX_SITE,
            REPOSITORY_ROOT_MIN_SITE,
            GIT_COMMON_MIN_SITE,
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_site_id"] = site_id
            attacked["addressed_site"] = copy.deepcopy(self.schema_sites[site_id])
            with self.assertRaises(ReadinessError):
                self.validate(attacked)
        source_helper = self.source_sites[SOURCE_HELPER_SITE]
        self.assertEqual(source_helper["path"], "src/edgelab/runtime_v2_bootstrap.py")
        self.assertEqual(
            source_helper["expression"],
            "_string(attachment['repository_root_realpath'], "
            "'/repository_root_realpath', minimum=1, maximum=4096)",
        )
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = SOURCE_HELPER_SITE
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_semantic_coordinate_context_and_sibling_attacks_deny(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MAXLENGTH_WRONG"),
            ("classification", "RESOURCE_MAXIMUM"),
            ("semantic_subject", "REALPATH_CHARACTER_MAXIMUM"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (("metric", "UTF8_BYTE_COUNT"), ("operator", "<"), ("bound", 4095)):
            attacked = copy.deepcopy(self.proof)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("dialect", "https://json-schema.org/draft/2019-09/schema"),
            ("schema_document_byte_length", 1526),
            ("schema_document_raw_sha256", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
            ("containing_subschema_pointer", "/properties"),
            ("containing_subschema_digest", "1" * 64),
            ("applicability", "ROOT_SCHEMA"),
            ("instance_domain", "PATH"),
            ("non_domain_behavior", "REJECT"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"]["ordered_pointer_sequence"][-1]["pointer"] = "/properties"
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["required_sibling_pointers"] = [
            "/properties/repository_root_realpath/type"
        ]
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_evidence_and_artifact_bytes_are_pinned(self):
        self.assertEqual(len(self.proof["evidence_inputs"]), 2)
        for item in self.proof["evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
        raw = (ROOT / RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(len(raw), RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF["byte_length"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF["raw_sha256"],
        )

    def test_nonclaims_remain_explicit(self):
        evidence = (ROOT / self.proof["evidence_inputs"][0]["path"]).read_text()
        for phrase in (
            "path canonicalization", "path existence", "symlink resolution",
            "repository containment", "filesystem or repository identity",
            "equality with the Git-common-dir value", "attachment validity",
            "runtime_v2_bootstrap._string", "full-schema validity",
            "STOP clearance", "capital authority",
        ):
            self.assertIn(phrase, evidence)


if __name__ == "__main__":
    unittest.main()
