"""Adversarial evidence for generator invocation minLength."""
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
    RESOURCE_CLASSIFICATION_V50_MANIFEST,
    RESOURCE_CLASSIFICATION_V50_SCHEMA_PROOFS,
    RESOURCE_CLASSIFICATION_V51_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V52_TASK_ID_FAMILY,
    RESOURCE_CLASSIFICATION_V52_TASK_ID_PROOFS,
    RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF,
    RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SELECTED_SITE_ID = (
    "85e3025e297b6d908712678e0358a97de2d8d04f2ce9af152e2ea3f566185a0a"
)
SIBLING_MAX_SITE = (
    "f193d860a83da82df674ace3da79ca2a26371f43751c4ca1776713d4d4130195"
)
SAME_SCHEMA_MIN_SITES = (
    "0e20496797c975f7d70da9aa0ff13c36346c34eb6b0769aef4387e982740078a",
    "7fa3a13af289ce5140793772d08d65a99570a240fcbe76b846adfaeae223ae53",
    "725721e72dede5d7a0ce972351b5bdf19eb1e069d8e11b1e442eef7bc518b39c",
    "efe3d459a742b92d49ba6951b37702e45fe4ca0d5647246ffed0d54d6021419f",
    "ccab1adbac540b97ae382559e66a6c612395613e35a558e9d47a845f4db67c8b",
)
GIT_COMMON_MIN_SITE = (
    "91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38"
)
SOURCE_INVOCATION_SITE = (
    "b250568edeae7a083c7cb99bde57ae855f914db83267902b1b4622a723afc59e"
)
V53_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v53.json"
V54_MANIFEST = "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v54.json"
V54_SCHEMA = "schemas/m0-3a-runtime-v2-resource-classification.v54.schema.json"


class GeneratorInvocationMinLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        report = build_report(ROOT)
        cls.discovery = report["inventory"]["resource_inventory_discovery"]
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF["path"])
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
                    "SCHEMA_DECLARATIVE_MINLENGTH_" + SELECTED_SITE_ID.upper()
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
            return None if type(instance) is not str else len(instance) >= bound

        self.assertFalse(local(""))
        for value in ("a", "ab", "\N{GRINNING FACE}", "\N{COMBINING ACUTE ACCENT}"):
            self.assertTrue(local(value))
        self.assertGreater(len("\N{GRINNING FACE}".encode("utf-8")), 1)
        self.assertEqual(len("e\N{COMBINING ACUTE ACCENT}"), 2)
        for value in (0, True, None, [], {}):
            self.assertIsNone(local(value))

    def test_v54_is_exact_v53_prefix_plus_one_proof(self):
        predecessor = json.loads((ROOT / V53_MANIFEST).read_text(encoding="ascii"))
        current = json.loads((ROOT / V54_MANIFEST).read_text(encoding="ascii"))
        schema = json.loads((ROOT / V54_SCHEMA).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][:-1], predecessor["constraints"])
        self.assertEqual(current["constraints"][-1], self.proof)
        self.assertEqual(len(current["constraints"]), 52)
        self.assertEqual(current["classified_site_count"], 85)
        self.assertEqual(current["unclassified_site_count"], 636)
        self.assertEqual(
            schema["properties"]["constraints"]["const"], current["constraints"]
        )
        self.assertEqual(current["coverage_status"], "INCOMPLETE")
        self.assertEqual(current["generation_disposition"], "DENY")

    def test_v50_family_exclusion_is_version_scoped_not_successor_authority(self):
        v50 = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        v50_schema_ids = {
            constraint["schema_site_id"]
            for constraint in v50["constraints"]
            if constraint["classification"] == "SCHEMA_DECLARATIVE_BOUND"
        }
        self.assertNotIn(SELECTED_SITE_ID, v50_schema_ids)
        family = json.loads(
            (
                ROOT
                / RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY[
                    "path"
                ]
            ).read_text(encoding="ascii")
        )
        self.assertIn(
            SELECTED_SITE_ID,
            {
                item["site"]["site_id"]
                for item in family["excluded_candidates"]
            },
        )
        self.assertNotIn(
            SELECTED_SITE_ID,
            {item["schema_site_id"] for item in family["ordered_members"]},
        )
        current = json.loads((ROOT / V54_MANIFEST).read_text(encoding="ascii"))
        self.assertEqual(current["constraints"][-1]["schema_site_id"], SELECTED_SITE_ID)

    def test_sibling_lookalike_and_source_cross_kind_substitutions_deny(self):
        selected_container = {
            "type": "string", "minLength": 1, "maxLength": 512,
        }
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "5789bce9561e2fea80886b8fe5436a7a73d413ac9c49dd3a6628a7a2b575d83c",
        )
        self.assertEqual(selected_container["minLength"], 1)
        for site_id in (
            SIBLING_MAX_SITE, *SAME_SCHEMA_MIN_SITES, GIT_COMMON_MIN_SITE,
        ):
            with self.subTest(site_id=site_id):
                attacked = copy.deepcopy(self.proof)
                attacked["schema_site_id"] = site_id
                attacked["addressed_site"] = copy.deepcopy(
                    self.schema_sites[site_id]
                )
                with self.assertRaises(ReadinessError):
                    self.validate(attacked)
        source_site = self.source_sites[SOURCE_INVOCATION_SITE]
        self.assertEqual(
            source_site["expression"],
            "_string(generator['invocation'], '/generator_identity/invocation', 1, 512)",
        )
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = SOURCE_INVOCATION_SITE
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_semantic_coordinate_context_and_sibling_attacks_deny(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MINLENGTH_WRONG"),
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "GENERATOR_INVOCATION_CONTENT"),
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
            "json_pointer": "/properties/generator_identity/properties/invocation/maxLength",
            "keyword": "maxLength",
            "path": "schemas/m0-3a-runtime-attachment.v2.schema.json",
            "schema_id": "urn:wrong",
            "site_id": SIBLING_MAX_SITE,
            "value": 2,
        }
        for field, value in addressed_mutations.items():
            attacked = copy.deepcopy(self.proof)
            attacked["addressed_site"][field] = value
            attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = SIBLING_MAX_SITE
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["addressed_site"] = copy.deepcopy(
            self.schema_sites[SIBLING_MAX_SITE]
        )
        attacks.append(attacked)
        attacked = copy.deepcopy(self.proof)
        attacked["schema_context"]["required_sibling_pointers"] = [
            "/properties/generator_identity/properties/invocation/maxLength"
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
        raw = (ROOT / RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF["path"]).read_bytes()
        self.assertEqual(len(raw), RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF["byte_length"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF["raw_sha256"],
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
            RESOURCE_CLASSIFICATION_V53_SCHEMA_PROOF,
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
            RESOURCE_CLASSIFICATION_V54_SCHEMA_PROOF,
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
            "sibling type or maximum-length meaning",
            "combined\none-to-512-code-point validity",
            "invocation grammar or\ncontent",
            "generator identity or authenticity",
            "generator behavior or authority",
            "runtime `_string` behavior",
            "outcomes do not\nindependently distinguish Unicode code-point count from byte count, grapheme",
            "unit comes from the frozen Draft\n2020-12 declarative proof profile",
            "excluded from and a non-member of the immutable V50",
            "version-scoped\nexclusion is not a perpetual ban",
            "V54 does not rewrite or enlarge the V50 family or its evidence",
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
