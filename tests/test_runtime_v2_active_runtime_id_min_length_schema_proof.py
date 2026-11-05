"""Adversarial evidence for the first real schema-site classification."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea"
)
V45_MANIFEST_PATH = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v45.json"
V45_SCHEMA_PATH = "schemas/m0-3a-runtime-v2-resource-classification.v45.schema.json"
V45_PROOF_PATH = "docs/M0.3A_ACTIVE_RUNTIME_ID_MIN_LENGTH_SCHEMA_PROOF.v1.json"


class ActiveRuntimeIdMinLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF["path"]).read_text(
                encoding="ascii"
            )
        )
        cls.v45_proof = json.loads(
            (ROOT / V45_PROOF_PATH).read_text(encoding="ascii")
        )
        cls.manifest = json.loads(
            (ROOT / V45_MANIFEST_PATH).read_text(encoding="ascii")
        )
        cls.schema = json.loads(
            (ROOT / V45_SCHEMA_PATH).read_text(encoding="ascii")
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

    def test_selected_proof_is_closed_and_executable_against_real_schema(self):
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
                    "SCHEMA_DECLARATIVE_MINLENGTH_"
                    "685812B87027CEA3E8FC9CE370FD21377B11FC6459C06BF2151261260CD178EA"
                ),
                "proof_kind": "SCHEMA_DECLARATIVE_KEYWORD_V1",
                "schema_site_id": SELECTED_SITE_ID,
                "validated_evidence_input_count": 2,
            },
        )
        self.assertEqual(self.proof["addressed_site"], self.schema_sites[SELECTED_SITE_ID])
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "b7a6b72a800efef8bdffac78cdac9fec371555f5f8dbaf7fbffa022c35b8a2f5",
        )

    def test_exact_local_keyword_behavior_has_no_full_schema_claim(self):
        bound = self.proof["declarative_equation"]["bound"]

        def exact_local_keyword_assertion(instance):
            if type(instance) is not str:
                return None
            return len(instance) >= bound

        self.assertFalse(exact_local_keyword_assertion(""))
        self.assertTrue(exact_local_keyword_assertion("x"))
        self.assertTrue(exact_local_keyword_assertion("\N{GRINNING FACE}"))
        self.assertIsNone(exact_local_keyword_assertion(0))
        self.assertIsNone(exact_local_keyword_assertion([]))
        self.assertEqual(
            self.proof["schema_context"]["non_domain_behavior"],
            "NO_ASSERTION_FROM_THIS_KEYWORD",
        )

    def test_v45_is_v44_semantic_prefix_plus_one_selected_schema_proof(self):
        predecessor = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v44.json")
            .read_text(encoding="ascii")
        )
        for successor, historical in zip(
            self.manifest["constraints"][:-1],
            predecessor["constraints"],
            strict=True,
        ):
            self.assertEqual(
                {key: value for key, value in successor.items() if key != "evidence_inputs"},
                {key: value for key, value in historical.items() if key != "evidence_inputs"},
            )
        self.assertEqual(self.manifest["constraints"][-1], self.v45_proof)
        self.assertEqual(
            {
                key: value for key, value in self.proof.items()
                if key != "evidence_inputs"
            },
            {
                key: value for key, value in self.v45_proof.items()
                if key != "evidence_inputs"
            },
        )
        self.assertEqual(len(self.manifest["constraints"]), 39)
        self.assertEqual(self.manifest["classified_site_count"], 72)
        self.assertEqual(self.manifest["unclassified_site_count"], 649)
        self.assertEqual(self.schema["properties"]["constraints"]["const"], self.manifest["constraints"])
        classified_source_ids = {
            site_id
            for constraint in self.manifest["constraints"][:-1]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in constraint[field]
        }
        self.assertEqual(len(classified_source_ids), 71)
        self.assertTrue(classified_source_ids.isdisjoint({SELECTED_SITE_ID}))

    def test_site_identity_other_schema_site_and_source_cross_kind_attacks_deny(self):
        attacks = []
        attacked = copy.deepcopy(self.proof)
        attacked["addressed_site"]["value"] = 2
        attacks.append(attacked)
        other = next(
            item for item in self.schema_sites.values()
            if item["keyword"] == "minLength" and item["site_id"] != SELECTED_SITE_ID
        )
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = other["site_id"]
        attacked["addressed_site"] = copy.deepcopy(other)
        attacks.append(attacked)
        source_id = next(iter(self.source_sites))
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = source_id
        attacks.append(attacked)
        for attacked in attacks:
            with self.subTest(site_id=attacked["schema_site_id"]):
                with self.assertRaises(ReadinessError):
                    self.validate(attacked)

    def test_equation_context_and_declarative_role_attacks_deny(self):
        attacks = []
        for field, value in (
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "SCHEMA_DECLARATIVE_MINIMUM_AT_EXACT_PINNED_LOCATION"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "ARRAY_ITEM_COUNT"),
            ("operator", ">"),
            ("bound", 2),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("dialect", "https://json-schema.org/draft/2019-09/schema"),
            ("schema_document_raw_sha256", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
            ("containing_subschema_pointer", "/properties"),
            ("containing_subschema_digest", "1" * 64),
            ("instance_domain", "NUMBER"),
            ("non_domain_behavior", "REJECT"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"]["ordered_pointer_sequence"][1][
            "index"
        ] = 9
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["enforcement_site_ids"] = []
        attacks.append(attacked)
        for index, attacked in enumerate(attacks):
            with self.subTest(index=index):
                with self.assertRaises(ReadinessError):
                    self.validate(attacked)

    def test_exact_two_evidence_inputs_are_distinct_pinned_and_not_schema(self):
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
        attacked["evidence_inputs"][1] = copy.deepcopy(attacked["evidence_inputs"][0])
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_other_schema_sites_and_all_authority_claims_remain_denied(self):
        classified_schema_ids = {self.manifest["constraints"][-1]["schema_site_id"]}
        self.assertEqual(classified_schema_ids, {SELECTED_SITE_ID})
        self.assertEqual(len(self.schema_sites) - len(classified_schema_ids), 295)
        proof_text = json.dumps(self.proof).lower()
        for forbidden in (
            "stop_clearance", "release_authority", "execution_authority",
            "capital_authority", "public_reachability", "runtime_validator",
            "uuid_format", "selector_validity", "cutover_acceptance",
        ):
            self.assertNotIn(forbidden, proof_text)

    def test_selected_proof_artifact_bytes_are_exactly_pinned(self):
        raw = (ROOT / RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(
            len(raw), RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF["byte_length"]
        )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF["raw_sha256"],
        )
        self.assertEqual(
            Path(RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF["path"]).suffix,
            ".json",
        )


if __name__ == "__main__":
    unittest.main()
