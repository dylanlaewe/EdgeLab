"""Adversarial evidence for git-common-dir identity maxLength."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574"
)
V47_MANIFEST_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v47.json"
V47_SCHEMA_PATH = "schemas/m0-3a-runtime-v2-resource-classification.v47.schema.json"
V48_MANIFEST_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v48.json"
V48_SCHEMA_PATH = "schemas/m0-3a-runtime-v2-resource-classification.v48.schema.json"


class GitCommonDirIdentityMaxLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF["path"]).read_text(
                encoding="ascii"
            )
        )
        cls.predecessor = json.loads(
            (ROOT / V47_MANIFEST_PATH).read_text(encoding="ascii")
        )
        cls.predecessor_schema = json.loads(
            (ROOT / V47_SCHEMA_PATH).read_text(encoding="ascii")
        )
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)

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
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"]).read_text(
                encoding="ascii"
            )
        )
        Draft202012Validator.check_schema(proof_schema)
        self.assertEqual(
            list(Draft202012Validator(proof_schema).iter_errors(self.proof)), []
        )
        self.assertEqual(
            self.validate(self.proof),
            {
                "constraint_id": (
                    "SCHEMA_DECLARATIVE_MAXLENGTH_"
                    "D35901DD714A95A4A2AA09A3CE17CBCC45DD1634B681CCA5ACA40BE61D479574"
                ),
                "proof_kind": "SCHEMA_DECLARATIVE_KEYWORD_V1",
                "schema_site_id": SELECTED_SITE_ID,
                "validated_evidence_input_count": 2,
            },
        )
        self.assertEqual(
            self.proof["addressed_site"], self.schema_sites[SELECTED_SITE_ID]
        )
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "1cb0f2473cb55b110447de322170e5050e56184fc26d1d544cb298ff202d9ac5",
        )

    def test_local_boundaries_empty_and_astral_code_points(self):
        bound = self.proof["declarative_equation"]["bound"]

        def exact_local_keyword_assertion(instance):
            if type(instance) is not str:
                return None
            return len(instance) <= bound

        self.assertTrue(exact_local_keyword_assertion("a" * 4095))
        self.assertTrue(exact_local_keyword_assertion("a" * 4096))
        self.assertFalse(exact_local_keyword_assertion("a" * 4097))
        self.assertTrue(exact_local_keyword_assertion(""))
        astral = "\N{GRINNING FACE}" * 4096
        self.assertEqual(len(astral), 4096)
        self.assertGreater(len(astral.encode("utf-8")), 4096)
        self.assertTrue(exact_local_keyword_assertion(astral))
        self.assertFalse(
            exact_local_keyword_assertion(astral + "\N{GRINNING FACE}")
        )
        combined = "e\N{COMBINING ACUTE ACCENT}" * 2048
        self.assertEqual(len(combined), 4096)
        self.assertTrue(exact_local_keyword_assertion(combined))
        self.assertFalse(
            exact_local_keyword_assertion(combined + "\N{COMBINING ACUTE ACCENT}")
        )
        for value in (0, True, None, [], {}):
            with self.subTest(value=value):
                self.assertIsNone(exact_local_keyword_assertion(value))
        self.assertEqual(
            self.proof["schema_context"]["non_domain_behavior"],
            "NO_ASSERTION_FROM_THIS_KEYWORD",
        )

    def test_v48_is_exact_v47_prefix_plus_one_ordered_proof(self):
        current = json.loads((ROOT / V48_MANIFEST_PATH).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V48_SCHEMA_PATH).read_text(encoding="ascii"))
        self.assertEqual(
            current["constraints"][:-1], self.predecessor["constraints"]
        )
        self.assertEqual(current["constraints"][-1], self.proof)
        self.assertEqual(len(current["constraints"]), 41)
        self.assertEqual(current["classified_site_count"], 74)
        self.assertEqual(current["unclassified_site_count"], 647)
        self.assertEqual(
            schema["properties"]["constraints"]["const"],
            current["constraints"],
        )
        self.assertEqual(
            self.predecessor_schema["properties"]["constraints"]["const"],
            self.predecessor["constraints"],
        )
        self.assertEqual(
            [
                item["schema_site_id"]
                for item in current["constraints"]
                if item["classification"] == "SCHEMA_DECLARATIVE_BOUND"
            ],
            [
                "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea",
                "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b",
                SELECTED_SITE_ID,
            ],
        )

    def test_exact_evidence_inputs_are_distinct_pinned_and_not_schema(self):
        self.assertEqual(len(self.proof["evidence_inputs"]), 2)
        paths = [item["path"] for item in self.proof["evidence_inputs"]]
        self.assertEqual(len(set(paths)), 2)
        self.assertNotIn(self.proof["addressed_site"]["path"], paths)
        for item in self.proof["evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
        attacked = copy.deepcopy(self.proof)
        attacked["evidence_inputs"][0]["raw_sha256"] = "0" * 64
        with self.assertRaises(ReadinessError):
            self.validate(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["evidence_inputs"][1] = copy.deepcopy(
            attacked["evidence_inputs"][0]
        )
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_site_namespace_and_other_schema_substitution_attacks_deny(self):
        attacks = []
        for field, value in (
            ("json_pointer", "/properties/git_common_dir_identity/minLength"),
            ("keyword", "minLength"),
            ("path", "schemas/m0-3a-runtime-selector.v2.schema.json"),
            ("schema_id", "urn:wrong"),
            ("site_id", "0" * 64),
            ("value", 4095),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["addressed_site"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = "0" * 64
        attacks.append(attacked)
        other = self.schema_sites[
            "bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848"
        ]
        self.assertEqual(other["keyword"], "maxLength")
        self.assertEqual(other["value"], 4096)
        self.assertEqual(
            other["json_pointer"],
            "/properties/repository_root_realpath/maxLength",
        )
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = other["site_id"]
        attacked["addressed_site"] = copy.deepcopy(other)
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = next(iter(self.source_sites))
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_role_equation_coordinate_context_and_sibling_attacks_deny(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MAXLENGTH_WRONG"),
            ("classification", "RESOURCE_MAXIMUM"),
            ("semantic_subject", "FILESYSTEM_PATH_CHARACTER_MAXIMUM"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "UTF8_BYTE_COUNT"),
            ("operator", "<"),
            ("bound", 4095),
        ):
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
        attacked["schema_context"]["ancestor_context"]["binding"] = "POINTERS_ONLY"
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ][-1]["index"] = 9
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ][-1]["pointer"] = "/properties"
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ].pop()
        attacks.append(attacked)
        for sibling in ("type", "minLength"):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"]["required_sibling_pointers"] = [
                f"/properties/git_common_dir_identity/{sibling}"
            ]
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["definition_site_ids"] = []
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_neighboring_meanings_and_authority_remain_unclaimed(self):
        current = json.loads((ROOT / V48_MANIFEST_PATH).read_text(encoding="ascii"))
        schema_ids = {
            item["schema_site_id"]
            for item in current["constraints"]
            if item["classification"] == "SCHEMA_DECLARATIVE_BOUND"
        }
        self.assertEqual(
            schema_ids,
            {
                "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea",
                "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b",
                SELECTED_SITE_ID,
            },
        )
        proof_text = json.dumps(self.proof).lower()
        for forbidden in (
            "filesystem_path",
            "repository_identity",
            "property_presence",
            "public_reachability",
            "stop_clearance",
            "release_authority",
            "execution_authority",
            "wagering_authority",
            "capital_authority",
        ):
            self.assertNotIn(forbidden, proof_text)

    def test_selected_proof_artifact_bytes_are_exactly_pinned(self):
        raw = (ROOT / RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(
            len(raw), RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF["byte_length"]
        )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF["raw_sha256"],
        )
        self.assertEqual(
            Path(RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF["path"]).suffix,
            ".json",
        )


if __name__ == "__main__":
    unittest.main()
