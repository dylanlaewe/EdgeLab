"""Adversarial evidence for the exact git-common-dir minLength site."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY,
    RESOURCE_CLASSIFICATION_V50_MANIFEST,
    RESOURCE_CLASSIFICATION_V55_GIT_COMMON_DIR_MIN_LENGTH_PROOF,
    SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA,
    ReadinessError,
    _resource_site_maps,
    _validate_schema_declarative_keyword_proof,
    build_report,
)


SITE = "91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38"
OTHER_MEMBER = "b9d97c6663e8bf814f90b1e69ba3a8ea30573b0ef575709552fe9c5e20ca06ca"
OWN_MAX = "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574"
OTHER_MAX = "bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848"
SOURCE_HELPER = "edba3c9f8efee4f6f8c8fc4602a580fc2a952010b6fab2dcfee05559c5bdf83b"


class GitCommonDirIdentityMinLengthSchemaProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        report = build_report(ROOT)
        cls.discovery = report["inventory"]["resource_inventory_discovery"]
        cls.source_sites, cls.schema_sites = _resource_site_maps(cls.discovery)
        cls.proof = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V55_GIT_COMMON_DIR_MIN_LENGTH_PROOF["path"])
            .read_text(encoding="ascii")
        )

    def validate(self, proof):
        return _validate_schema_declarative_keyword_proof(
            ROOT, proof, self.source_sites, self.schema_sites,
            self.discovery["schema_inputs"],
        )

    def test_proof_is_exact_schema_valid_and_executable(self):
        proof_schema = json.loads(
            (ROOT / SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA["path"])
            .read_text(encoding="ascii")
        )
        Draft202012Validator.check_schema(proof_schema)
        self.assertEqual(list(Draft202012Validator(proof_schema).iter_errors(self.proof)), [])
        self.assertEqual(self.proof["addressed_site"], self.schema_sites[SITE])
        self.assertEqual(
            self.proof["schema_context"]["containing_subschema_digest"],
            "1cb0f2473cb55b110447de322170e5050e56184fc26d1d544cb298ff202d9ac5",
        )
        self.assertEqual(self.validate(self.proof)["schema_site_id"], SITE)

    def test_boundaries_weak_metric_and_nonstring_no_assertion(self):
        bound = self.proof["declarative_equation"]["bound"]
        local = lambda value: None if type(value) is not str else len(value) >= bound
        self.assertFalse(local(""))
        for value in ("a", "ab", "\N{GRINNING FACE}", "\N{COMBINING ACUTE ACCENT}"):
            self.assertTrue(local(value))
        self.assertGreater(len("\N{GRINNING FACE}".encode("utf-8")), 1)
        self.assertEqual(len("e\N{COMBINING ACUTE ACCENT}"), 2)
        for value in (0, True, None, [], {}):
            self.assertIsNone(local(value))
        text = (ROOT / "docs/M0.3A_GIT_COMMON_DIR_IDENTITY_MIN_LENGTH_SCHEMA_PROOF.v1.md").read_text()
        self.assertIn("cannot independently distinguish code-point count from byte count", text)
        self.assertIn("frozen Draft 2020-12 proof profile", text)

    def test_coordinates_siblings_copied_container_and_source_kind_deny(self):
        for site_id in (OTHER_MEMBER, OWN_MAX, OTHER_MAX):
            attacked = copy.deepcopy(self.proof)
            attacked["schema_site_id"] = site_id
            attacked["addressed_site"] = copy.deepcopy(self.schema_sites[site_id])
            with self.subTest(site_id=site_id), self.assertRaises(ReadinessError):
                self.validate(attacked)
        self.assertIn("git_common_dir_identity", self.source_sites[SOURCE_HELPER]["expression"])
        attacked = copy.deepcopy(self.proof)
        attacked["schema_site_id"] = SOURCE_HELPER
        with self.assertRaises(ReadinessError):
            self.validate(attacked)

    def test_every_semantic_and_address_binding_denies_drift(self):
        attacks = []
        for field, value in (
            ("proof_kind", "SOURCE_BOUND_V1"),
            ("constraint_id", "SCHEMA_DECLARATIVE_MINLENGTH_WRONG"),
            ("classification", "RESOURCE_MINIMUM"),
            ("semantic_subject", "FILESYSTEM_PATH"),
            ("unit", "BYTES"),
        ):
            attacked = copy.deepcopy(self.proof); attacked[field] = value; attacks.append(attacked)
        for field, value in (("metric", "UTF8_BYTE_COUNT"), ("operator", ">"), ("bound", 2)):
            attacked = copy.deepcopy(self.proof); attacked["declarative_equation"][field] = value; attacks.append(attacked)
        for field, value in (
            ("classification", "SCHEMA_DECLARATIVE_BOUND"),
            ("json_pointer", "/properties/repository_root_realpath/minLength"),
            ("keyword", "maxLength"),
            ("path", "schemas/m0-3a-runtime-attachment.v1.schema.json"),
            ("schema_id", "urn:edgelab:wrong"),
            ("site_id", OTHER_MEMBER),
            ("value", 2),
        ):
            attacked = copy.deepcopy(self.proof); attacked["addressed_site"][field] = value; attacks.append(attacked)
        attacked = copy.deepcopy(self.proof); attacked["schema_context"]["required_sibling_pointers"] = ["/properties/git_common_dir_identity/maxLength"]; attacks.append(attacked)
        attacked = copy.deepcopy(self.proof); attacked["schema_context"]["ordered_ancestor_pointers"] = []; attacks.append(attacked)
        for attacked in attacks:
            with self.assertRaises(ReadinessError): self.validate(attacked)

    def test_evidence_bytes_nonclaims_and_v50_temporal_boundary(self):
        for item in self.proof["evidence_inputs"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (item["byte_length"], item["raw_sha256"]))
        text = (ROOT / "docs/M0.3A_GIT_COMMON_DIR_IDENTITY_MIN_LENGTH_SCHEMA_PROOF.v1.md").read_text()
        for phrase in ("filesystem path or realpath semantics", "common-directory authenticity", "runtime `_string`", "STOP clearance", "capital authority"):
            self.assertIn(phrase, text)
        v50 = json.loads((ROOT / RESOURCE_CLASSIFICATION_V50_MANIFEST[1]).read_text(encoding="ascii"))
        v50_ids = {item["schema_site_id"] for item in v50["constraints"] if item["classification"] == "SCHEMA_DECLARATIVE_BOUND"}
        family = json.loads((ROOT / RESOURCE_CLASSIFICATION_V50_OPERATION_KEY_MIN_LENGTH_FAMILY["path"]).read_text(encoding="ascii"))
        self.assertNotIn(SITE, v50_ids)
        self.assertIn(SITE, {item["site"]["site_id"] for item in family["excluded_candidates"]})
        self.assertIn("not a perpetual ban", text)


if __name__ == "__main__":
    unittest.main()
