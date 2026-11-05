"""Adversarial evidence for the generator-version minimum schema site."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b"
)
V46_MANIFEST_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v46.json"
V46_SCHEMA_PATH = "schemas/m0-3a-runtime-v2-resource-classification.v46.schema.json"


class GeneratorVersionMinimumSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF["path"]).read_text(
                encoding="ascii"
            )
        )
        cls.predecessor = json.loads(
            (ROOT / V46_MANIFEST_PATH).read_text(encoding="ascii")
        )
        cls.predecessor_schema = json.loads(
            (ROOT / V46_SCHEMA_PATH).read_text(encoding="ascii")
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
                    "SCHEMA_DECLARATIVE_MINIMUM_"
                    "55FED7617DC5FEDBE4F113493AE8096CF62078A2A6DC7803FD4417FB6D60E44B"
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
            "c0b9a5eadd4ba5794d76f6147f0bd5dbcecc2797f72d213ea03fcf803bf3b034",
        )

    def test_isolated_local_number_behavior_does_not_narrow_to_integer(self):
        bound = self.proof["declarative_equation"]["bound"]

        def exact_local_keyword_assertion(instance):
            if type(instance) not in (int, float):
                return None
            return instance >= bound

        self.assertFalse(exact_local_keyword_assertion(-1))
        self.assertFalse(exact_local_keyword_assertion(0))
        self.assertFalse(exact_local_keyword_assertion(0.5))
        self.assertTrue(exact_local_keyword_assertion(1))
        self.assertTrue(exact_local_keyword_assertion(1.0))
        self.assertTrue(exact_local_keyword_assertion(1.5))
        for value in ("1", True, None, [], {}):
            with self.subTest(value=value):
                self.assertIsNone(exact_local_keyword_assertion(value))
        self.assertEqual(
            self.proof["schema_context"]["non_domain_behavior"],
            "NO_ASSERTION_FROM_THIS_KEYWORD",
        )

    def test_v47_is_exact_v46_prefix_plus_one_schema_proof(self):
        current = json.loads(
            (
                ROOT
                / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v47.json"
            ).read_text(encoding="ascii")
        )
        schema = json.loads(
            (
                ROOT
                / "schemas/m0-3a-runtime-v2-resource-classification.v47.schema.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(
            current["constraints"][:-1], self.predecessor["constraints"]
        )
        self.assertEqual(current["constraints"][-1], self.proof)
        self.assertEqual(len(current["constraints"]), 40)
        self.assertEqual(current["classified_site_count"], 73)
        self.assertEqual(current["unclassified_site_count"], 648)
        self.assertEqual(
            schema["properties"]["constraints"]["const"],
            current["constraints"],
        )
        self.assertEqual(
            self.predecessor_schema["properties"]["constraints"]["const"],
            self.predecessor["constraints"],
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
            ("json_pointer", "/properties/generator_identity/minimum"),
            ("keyword", "maximum"),
            ("path", "schemas/m0-3a-active-runtime-selector.v2.schema.json"),
            ("schema_id", "urn:wrong"),
            ("site_id", "0" * 64),
            ("value", 0),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["addressed_site"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = "0" * 64
        attacks.append(attacked)
        other = next(
            item
            for item in self.schema_sites.values()
            if item["keyword"] == "minimum"
            and item["site_id"] != SELECTED_SITE_ID
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

    def test_role_equation_coordinate_and_context_attacks_deny(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MINIMUM_WRONG"),
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "SCHEMA_INTEGER_MINIMUM"),
            ("unit", "INTEGERS"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "INTEGER_VALUE"),
            ("operator", ">"),
            ("bound", 0),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("dialect", "https://json-schema.org/draft/2019-09/schema"),
            ("schema_document_byte_length", 15937),
            ("containing_subschema_pointer", "/properties/generator_identity"),
            ("containing_subschema_digest", "1" * 64),
            ("applicability", "ROOT_SCHEMA"),
            ("instance_domain", "INTEGER"),
            ("non_domain_behavior", "REJECT"),
            ("schema_document_raw_sha256", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
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
        ][-1]["pointer"] = "/properties/generator_identity"
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ].pop()
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ][-2:] = reversed(
            attacked["schema_context"]["ancestor_context"][
                "ordered_pointer_sequence"
            ][-2:]
        )
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["required_sibling_pointers"] = [
            "/properties/generator_identity/properties/generator_version/type"
        ]
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["definition_site_ids"] = []
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_neighboring_meanings_and_authority_remain_unclaimed(self):
        current = json.loads(
            (
                ROOT
                / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v47.json"
            ).read_text(encoding="ascii")
        )
        schema_ids = {
            item["schema_site_id"]
            for item in current["constraints"]
            if item["classification"] == "SCHEMA_DECLARATIVE_BOUND"
        }
        self.assertEqual(
            schema_ids,
            {
                "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea",
                SELECTED_SITE_ID,
            },
        )
        proof_text = json.dumps(self.proof).lower()
        for forbidden in (
            "integer_only",
            "requiredness",
            "operational_generator_version",
            "runtime_v2_closure._integer",
            "public_reachability",
            "stop_clearance",
            "release_authority",
            "execution_authority",
            "wagering_authority",
            "capital_authority",
        ):
            self.assertNotIn(forbidden, proof_text)

    def test_selected_proof_artifact_bytes_are_exactly_pinned(self):
        raw = (ROOT / RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(
            len(raw), RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF["byte_length"]
        )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF["raw_sha256"],
        )
        self.assertEqual(
            Path(RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF["path"]).suffix,
            ".json",
        )


if __name__ == "__main__":
    unittest.main()
