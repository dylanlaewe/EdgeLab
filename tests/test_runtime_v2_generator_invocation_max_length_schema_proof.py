"""Adversarial evidence for generator invocation maxLength."""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY,
    RESOURCE_CLASSIFICATION_V49_SCHEMA_PROOFS,
    RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY,
    RESOURCE_CLASSIFICATION_V50_SCHEMA_PROOFS,
    RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY,
    RESOURCE_CLASSIFICATION_V52_TASK_ID_PROOFS,
    RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "f193d860a83da82df674ace3da79ca2a26371f43751c4ca1776713d4d4130195"
)
SIBLING_MIN_SITE = (
    "85e3025e297b6d908712678e0358a97de2d8d04f2ce9af152e2ea3f566185a0a"
)
OTHER_MAX_SITES = (
    "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574",
    "bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848",
    "9a219d2847af954061fe8e233e8e316f57a09e9ec256c83ed829724b9930f626",
)
SAME_SCHEMA_MAX_SITES = (
    "c216234daf099293bc50c0ab4a404da2e307493632ce52bcb008634232360cb0",
    "7dc43e25cd14a88cdec15e27911b28d2b7703e708e09cbab63a61c352d3a0127",
    "c9b9da9c642b7e90c6a239030b22cff71dd230e33f1eae0d51118d19fff8d81e",
    "30914766491bd154e748c8047aca8b2d17e63f200bd43e08757be1d906fe6c27",
    "2ef2bee84a6f59b7c95f4ec28fa71362b8f5fdc1040940499d0418387009256c",
)
SOURCE_INVOCATION_MAX_SITE = (
    "b250568edeae7a083c7cb99bde57ae855f914db83267902b1b4622a723afc59e"
)
SOURCE_COORDINATE_MAX_SITE = (
    "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
)
SOURCE_INITIAL_COORDINATE_MAX_SITE = (
    "e82e2fbfb0c25192c551e66d85793a97190f689d55dc359d92d2415b8c0e97dd"
)
V52_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v52.json"
V53_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v53.json"
V53_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v53.schema.json"


class GeneratorInvocationMaxLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        report = build_report(ROOT)
        cls.discovery = report["inventory"]["resource_inventory_discovery"]
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF["path"])
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

    def test_selected_proof_is_closed_exact_and_executable(self):
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
                "constraint_id": (
                    "SCHEMA_DECLARATIVE_MAXLENGTH_" + SELECTED_SITE_ID.upper()
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
            "5789bce9561e2fea80886b8fe5436a7a73d413ac9c49dd3a6628a7a2b575d83c",
        )

    def test_local_boundaries_unicode_units_and_nonstring_no_assertion(self):
        bound = self.proof["declarative_equation"]["bound"]

        def local(instance):
            return None if type(instance) is not str else len(instance) <= bound

        for size in (0, 1, 511, 512):
            self.assertTrue(local("a" * size))
        self.assertFalse(local("a" * 513))
        astral = "\N{GRINNING FACE}" * 512
        self.assertEqual(len(astral), 512)
        self.assertGreater(len(astral.encode("utf-8")), 512)
        self.assertTrue(local(astral))
        self.assertFalse(local(astral + "\N{GRINNING FACE}"))
        combined = "e\N{COMBINING ACUTE ACCENT}" * 256
        self.assertEqual(len(combined), 512)
        self.assertTrue(local(combined))
        self.assertFalse(local(combined + "x"))
        for value in (0, True, None, [], {}):
            self.assertIsNone(local(value))

    def test_v53_is_exact_v52_prefix_plus_one_proof(self):
        predecessor = json.loads((ROOT / V52_MANIFEST).read_text(encoding="ascii"))
        current = json.loads((ROOT / V53_MANIFEST).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V53_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-1], predecessor["constraints"])
        self.assertEqual(current["constraints"][-1], self.proof)
        self.assertEqual(len(current["constraints"]), 51)
        self.assertEqual(current["classified_site_count"], 84)
        self.assertEqual(current["unclassified_site_count"], 637)
        self.assertEqual(
            schema["properties"]["constraints"]["const"], current["constraints"]
        )
        self.assertEqual(current["coverage_status"], "INCOMPLETE")
        self.assertEqual(current["generation_disposition"], "DENY")

    def test_sibling_other_max_and_source_cross_kind_substitutions_deny(self):
        exact_512_sites = sorted(
            site_id
            for site_id, site in self.schema_sites.items()
            if site["keyword"] == "maxLength" and site["value"] == 512
        )
        self.assertEqual(exact_512_sites, [SELECTED_SITE_ID])
        for site_id in (SIBLING_MIN_SITE, *OTHER_MAX_SITES, *SAME_SCHEMA_MAX_SITES):
            with self.subTest(site_id=site_id):
                attacked = copy.deepcopy(self.proof)
                attacked["schema_site_id"] = site_id
                attacked["addressed_site"] = copy.deepcopy(
                    self.schema_sites[site_id]
                )
                with self.assertRaises(ReadinessError):
                    self.validate(attacked)
        source_attacks = {
            SOURCE_INVOCATION_MAX_SITE: (
                "_string(generator['invocation'], '/generator_identity/invocation', 1, 512)"
            ),
            SOURCE_COORDINATE_MAX_SITE: "MAX_FINDING_COORDINATE_CHARS = 512",
            SOURCE_INITIAL_COORDINATE_MAX_SITE: "bounded(coordinate, 512)",
        }
        for site_id, expression in source_attacks.items():
            with self.subTest(source_site_id=site_id):
                self.assertEqual(self.source_sites[site_id]["expression"], expression)
                attacked = copy.deepcopy(self.proof)
                attacked["schema_site_id"] = site_id
                with self.assertRaises(ReadinessError):
                    self.validate(attacked)

    def test_semantic_coordinate_context_and_sibling_attacks_deny(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MAXLENGTH_WRONG"),
            ("classification", "RESOURCE_MAXIMUM"),
            ("semantic_subject", "GENERATOR_INVOCATION_CONTENT"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked[field] = value
            attacks.append(attacked)
        for field, value in (
            ("metric", "UTF8_BYTE_COUNT"), ("operator", "<"), ("bound", 511)
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["declarative_equation"][field] = value
            attacks.append(attacked)
        for field, value in (
            ("dialect", "https://json-schema.org/draft/2019-09/schema"),
            ("schema_document_byte_length", 15937),
            ("schema_document_raw_sha256", "0" * 64),
            ("schema_document_root_id", "urn:wrong"),
            ("containing_subschema_pointer", "/properties/generator_identity"),
            ("containing_subschema_digest", "1" * 64),
            ("applicability", "ROOT_SCHEMA"),
            ("instance_domain", "COMMAND"),
            ("non_domain_behavior", "REJECT"),
        ):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_context"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["ancestor_context"][
            "ordered_pointer_sequence"
        ][-1]["pointer"] = "/properties/generator_identity"
        attacks.append(attacked)
        addressed_mutations = {
            "classification": "SCHEMA_DECLARATIVE_BOUND",
            "json_pointer": "/properties/generator_identity/properties/invocation/minLength",
            "keyword": "minLength",
            "path": "schemas/m0-3a-runtime-attachment.v2.schema.json",
            "schema_id": "urn:wrong",
            "site_id": SIBLING_MIN_SITE,
            "value": 511,
        }
        for field, value in addressed_mutations.items():
            attacked = copy.deepcopy(self.proof)
            attacked["addressed_site"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = SIBLING_MIN_SITE
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["addressed_site"] = copy.deepcopy(
            self.schema_sites[SIBLING_MIN_SITE]
        )
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["required_sibling_pointers"] = [
            "/properties/generator_identity/properties/invocation/type"
        ]
        attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError):
                self.validate(attacked)

    def test_evidence_artifact_and_file_identities_are_pinned(self):
        self.assertEqual(len(self.proof["evidence_inputs"]), 2)
        paths = []
        identities = set()
        for item in self.proof["evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["byte_length"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["raw_sha256"])
            paths.append(item["path"])
            stat = os.stat(ROOT / item["path"], follow_symlinks=False)
            identities.add((stat.st_dev, stat.st_ino))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len(identities), len(paths))
        raw = (ROOT / RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(len(raw), RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF["byte_length"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF["raw_sha256"],
        )

    def test_evidence_is_disjoint_from_frozen_prior_lanes_and_live_aggregate(self):
        prior_proofs = (
            RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF,
            RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF,
            RESOURCE_CLASSIFICATION_V48_SCHEMA_PROOF,
            *RESOURCE_CLASSIFICATION_V49_SCHEMA_PROOFS,
            *RESOURCE_CLASSIFICATION_V50_SCHEMA_PROOFS,
            RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF,
            *RESOURCE_CLASSIFICATION_V52_TASK_ID_PROOFS,
        )
        prior_families = (
            RESOURCE_CLASSIFICATION_V49_OPERATION_KEY_FAMILY,
            RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY,
            RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY,
        )
        prior_paths = set()
        prior_identities = set()
        for record in prior_proofs:
            prior_paths.add(record["path"])
            stat = os.stat(ROOT / record["path"], follow_symlinks=False)
            prior_identities.add((stat.st_dev, stat.st_ino))
            proof = json.loads((ROOT / record["path"]).read_text())
            for evidence in proof["evidence_inputs"]:
                prior_paths.add(evidence["path"])
                stat = os.stat(ROOT / evidence["path"], follow_symlinks=False)
                prior_identities.add((stat.st_dev, stat.st_ino))
        for record in prior_families:
            prior_paths.add(record["path"])
            stat = os.stat(ROOT / record["path"], follow_symlinks=False)
            prior_identities.add((stat.st_dev, stat.st_ino))
            family = json.loads((ROOT / record["path"]).read_text())
            for evidence in family["family_evidence_inputs"]:
                prior_paths.add(evidence["path"])
                stat = os.stat(ROOT / evidence["path"], follow_symlinks=False)
                prior_identities.add((stat.st_dev, stat.st_ino))
        new_records = [
            RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF,
            *self.proof["evidence_inputs"],
        ]
        new_paths = {record["path"] for record in new_records}
        new_identities = {
            (
                os.stat(ROOT / record["path"], follow_symlinks=False).st_dev,
                os.stat(ROOT / record["path"], follow_symlinks=False).st_ino,
            )
            for record in new_records
        }
        self.assertTrue(new_paths.isdisjoint(prior_paths))
        self.assertTrue(new_identities.isdisjoint(prior_identities))
        source = inspect.getsource(self.__class__)
        tree = ast.parse(source)
        self.assertFalse(any(
            isinstance(node, ast.Name)
            and node.id == "RESOURCE_CLASSIFICATION_SCHEMA_PROOFS"
            for node in ast.walk(tree)
        ))

    def test_nonclaims_are_explicit_and_correlations_are_not_independence(self):
        evidence = (ROOT / self.proof["evidence_inputs"][0]["path"]).read_text()
        for phrase in (
            "sibling type or minimum-length meaning",
            "invocation grammar or content",
            "generator identity or authenticity",
            "generator behavior or authority",
            "command, argv, shell, process, reproducibility",
            "property reachability, requiredness, or composition",
            "cross-document schema or evidence independence",
            "deployed-validator conformance",
            "STOP clearance",
            "capital authority",
            "runtime behavior",
        ):
            self.assertIn(phrase, evidence)


if __name__ == "__main__":
    unittest.main()
