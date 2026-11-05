"""Adversarial evidence for the verifier schema-reference token ceiling."""
from __future__ import annotations

import json
import unittest

from src.edgelab.validate import ROOT
import src.edgelab.runtime_v2_verifier as verifier
from src.edgelab.runtime_v2_verifier import VerificationFinding
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_MANIFEST,
    _source_bound_inventory,
    build_report,
)


TOKEN_SLICE_SITE = "6e95fce4ad2ed77d84d5bfaad79566cb4276adc28054fb8bde30b0bbb5c911c5"
TOKEN_COMPARISON_SITE = "66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474"
DEFINITION_NAME_COMPARISON_SITE = (
    "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd"
)


class SchemaRefTokenCharacterBoundTests(unittest.TestCase):
    schema_id = "urn:edgelab:test:schema-ref-token-bound"

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(encoding="ascii")
        )
        cls.source = (ROOT / "src/edgelab/runtime_v2_verifier.py").read_bytes()

    @classmethod
    def value(cls, token: str, *, target: bool = True) -> dict[str, object]:
        definitions = {token: {"type": "null"}} if target else {
            "Existing": {"type": "null"}
        }
        return {
            "$schema": verifier._DRAFT_2020_12,
            "$id": cls.schema_id,
            "$defs": definitions,
            "properties": {"value": {"$ref": f"#/$defs/{token}"}},
        }

    def constraint(self) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"]
            == "VERIFIER_SCHEMA_REF_TOKEN_CHARACTER_MAXIMUM"
        )

    def test_one_sixty_three_and_sixty_four_accept_sixty_five_rejects(self):
        for length in (1, 63, 64):
            with self.subTest(length=length):
                token = "A" + "a" * (length - 1)
                self.assertEqual(
                    verifier._schema_safety_findings(
                        self.schema_id, self.value(token)
                    ),
                    [],
                )

        token = "A" + "a" * 64
        self.assertEqual(
            verifier._schema_safety_findings(
                self.schema_id, self.value(token, target=False)
            ),
            [
                VerificationFinding(
                    "SCHEMA_REF_OUTSIDE_PROFILE",
                    self.schema_id,
                    "/properties/value/$ref",
                )
            ],
        )

    def test_valid_existing_targets_are_unchanged(self):
        value = {
            "$schema": verifier._DRAFT_2020_12,
            "$id": self.schema_id,
            "$defs": {
                "Alpha": {"type": "null"},
                "Beta_2": {"type": "null"},
            },
            "allOf": [
                {"$ref": "#/$defs/Alpha"},
                {"$ref": "#/$defs/Beta_2"},
            ],
        }
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, value), []
        )

    def test_diagnostic_budget_short_circuits_before_token_inspection(self):
        token = "A" + "a" * 64
        value = {
            "$schema": verifier._DRAFT_2020_12,
            "$id": self.schema_id,
            "$unknown": True,
            "properties": {"value": {"$ref": f"#/$defs/{token}"}},
            "$defs": {"Existing": {"type": "null"}},
        }
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, value, limit=1),
            [
                VerificationFinding(
                    "SCHEMA_UNKNOWN_KEYWORD", self.schema_id, "/$unknown"
                )
            ],
        )

    def test_source_order_prefix_type_startswith_slice_condition_and_diagnostic(self):
        fragments = (
            b"child[8:]",
            b'type(child) is str',
            b'child.startswith("#/$defs/")',
            b"len(token) > 64",
            b'add("SCHEMA_REF_OUTSIDE_PROFILE", child_path)',
        )
        for fragment in fragments:
            self.assertEqual(self.source.count(fragment), 1)
        positions = [self.source.index(fragment) for fragment in fragments]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            b"not token\n                        or len(token) > 64\n",
            self.source,
        )

    def test_slice_and_comparator_attacks_change_bound_site_identity(self):
        path = "src/edgelab/runtime_v2_verifier.py"
        for old, new in (
            (b"child[8:]", b"child[7:]"),
            (b"len(token) > 64", b"len(token) >= 64"),
            (b"len(token) > 64", b"len(token) > 63"),
            (b"len(token) > 64", b"len(token) > 65"),
        ):
            with self.subTest(old=old, new=new):
                mutated = {path: self.source.replace(old, new, 1)}
                site_ids = {
                    item["site_id"] for item in _source_bound_inventory(mutated)
                }
                self.assertFalse(
                    {TOKEN_SLICE_SITE, TOKEN_COMPARISON_SITE}.issubset(site_ids)
                )

    def test_v40_preserves_v39_schema_ref_token_constraint(self):
        predecessor = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v39.json"
            ).read_text(encoding="ascii")
        )
        for successor, historical in zip(
            self.manifest["constraints"][:-1], predecessor["constraints"], strict=True
        ):
            self.assertEqual(
                {key: value for key, value in successor.items() if key != "evidence_inputs"},
                {key: value for key, value in historical.items() if key != "evidence_inputs"},
            )
        constraint = self.constraint()
        self.assertEqual(len(self.manifest["constraints"]), 36)
        self.assertEqual(constraint["maximum"], 64)
        self.assertEqual(constraint["unit"], "CHARACTERS")
        self.assertEqual(constraint["definition_site_ids"], [TOKEN_SLICE_SITE])
        self.assertEqual(
            constraint["enforcement_site_ids"], [TOKEN_COMPARISON_SITE]
        )
        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 36)
        self.assertEqual(classification["classified_site_count"], 69)
        self.assertEqual(classification["unclassified_site_count"], 652)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")
        self.assertEqual(
            [item["code"] for item in self.report["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )

    def test_adjacent_equal_valued_meanings_and_authority_remain_excluded(self):
        constraint = self.constraint()
        classified = {
            site_id
            for item in self.manifest["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in item[field]
        }
        constraint_sites = set(constraint["definition_site_ids"]) | set(
            constraint["enforcement_site_ids"]
        )
        self.assertNotIn(DEFINITION_NAME_COMPARISON_SITE, constraint_sites)
        self.assertIn(DEFINITION_NAME_COMPARISON_SITE, classified)
        discovery = self.report["inventory"]["resource_inventory_discovery"]
        sixty_four_comparisons = {
            item["site_id"] for item in discovery["source_bound_sites"]
            if item.get("expression") in {"len(token) > 64", "len(name) > 64"}
        }
        self.assertEqual(
            sixty_four_comparisons & constraint_sites, {TOKEN_COMPARISON_SITE}
        )
        self.assertEqual(
            constraint["semantic_proof"]["selection_semantics"],
            "LOCAL_DEFS_REFERENCE_TOKEN_CHARACTER_MAXIMUM_ONLY_NOT_"
            "DEFINITION_NAME_TARGET_EXISTENCE_GRAPH_OR_GENERIC_STRING_LIMIT",
        )
        semantic_text = json.dumps(constraint, sort_keys=True).lower().replace(
            "_", " "
        ).replace("-", " ")
        for nonclaim in (
            "public-verifier acceptance",
            "stop clearance",
            "capital authority",
        ):
            self.assertNotIn(nonclaim.replace("-", " "), semantic_text)


if __name__ == "__main__":
    unittest.main()
