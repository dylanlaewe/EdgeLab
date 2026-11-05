"""Adversarial evidence for the verifier schema-definition name ceiling."""
from __future__ import annotations

import json
import unittest

from src.edgelab.validate import ROOT
import src.edgelab.runtime_v2_verifier as verifier
from src.edgelab.runtime_v2_verifier import VerificationFinding
from tools.check_runtime_v2_release_readiness import _source_bound_inventory, build_report


NAME_COMPARISON_SITE = "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd"
REF_TOKEN_COMPARISON_SITE = "66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474"


class SchemaDefinitionNameCharacterBoundTests(unittest.TestCase):
    schema_id = "urn:edgelab:test:schema-definition-name-bound"

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.manifest = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v42.json")
            .read_text(encoding="ascii")
        )
        cls.source = (ROOT / "src/edgelab/runtime_v2_verifier.py").read_bytes()

    @classmethod
    def value(cls, name: str, definition: object | None = None) -> dict[str, object]:
        return {
            "$schema": verifier._DRAFT_2020_12,
            "$id": cls.schema_id,
            "$defs": {name: {"type": "null"} if definition is None else definition},
        }

    def constraint(self) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"]
            == "VERIFIER_SCHEMA_DEFINITION_NAME_CHARACTER_MAXIMUM"
        )

    def test_one_sixty_three_and_sixty_four_accept_sixty_five_rejects(self):
        for length in (1, 63, 64):
            with self.subTest(length=length):
                name = "A" + "a" * (length - 1)
                self.assertEqual(
                    verifier._schema_safety_findings(self.schema_id, self.value(name)),
                    [],
                )

        name = "A" + "a" * 64
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, self.value(name)),
            [VerificationFinding("SCHEMA_DEF_NAME", self.schema_id, "/$defs")],
        )

    def test_rejected_name_creates_no_edge_and_does_not_walk_definition(self):
        name = "A" + "a" * 64
        # The body would emit an unknown-keyword diagnostic if recursively walked.
        value = self.value(name, {"$notAllowed": True, "$ref": f"#/$defs/{name}"})
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, value),
            [VerificationFinding("SCHEMA_DEF_NAME", self.schema_id, "/$defs")],
        )

    def test_diagnostic_budget_short_circuits_before_definition_iteration(self):
        name = "A" + "a" * 64
        value = self.value(name)
        value["$unknown"] = True
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, value, limit=1),
            [VerificationFinding("SCHEMA_UNKNOWN_KEYWORD", self.schema_id, "/$unknown")],
        )

    def test_invalid_short_name_is_an_explicit_nonclaim(self):
        self.assertEqual(
            verifier._schema_safety_findings(self.schema_id, self.value("1")),
            [VerificationFinding("SCHEMA_DEF_NAME", self.schema_id, "/$defs")],
        )

    def test_exact_extraction_guard_loop_profile_effects_and_order_are_pinned(self):
        fragments = (
            b'definitions = value.get("$defs", {})',
            b"if type(definitions) is not dict:",
            b"definitions = {}",
            b"for name, definition in definitions.items():",
            b"type(name) is not str",
            b"or not name",
            b"or len(name) > 64",
            b'add("SCHEMA_DEF_NAME", "/$defs")',
            b'add("SCHEMA_DEF_NAME", "/$defs")\n            continue',
            b"edges.setdefault(name, set())",
            b'walk(definition, f"/$defs/{name}", name)',
        )
        for fragment in fragments:
            self.assertGreaterEqual(self.source.count(fragment), 1)
        positions = [self.source.index(fragment) for fragment in fragments]
        self.assertEqual(positions, sorted(positions))

    def test_source_attack_matrix_changes_site_or_pinned_semantics(self):
        path = "src/edgelab/runtime_v2_verifier.py"
        attacks = (
            (b"len(name) > 64", b"len(name) >= 64"),
            (b"len(name) > 64", b"len(name) > 63"),
            (b"len(name) > 64", b"len(name) > 65"),
            (b'value.get("$defs", {})', b'value.get("definitions", {})'),
            (b"definitions = {}", b"definitions = dict()"),
            (b"definitions.items()", b"sorted(definitions.items())"),
            (b"type(name) is not str", b"not isinstance(name, str)"),
            (b"or not name", b"or name == ''"),
            (b'add("SCHEMA_DEF_NAME", "/$defs")', b'add("SCHEMA_DEF_NAME", "/")'),
            (
                b'add("SCHEMA_DEF_NAME", "/$defs")\n            continue',
                b'add("SCHEMA_DEF_NAME", "/$defs")\n            pass',
            ),
            (b"edges.setdefault(name, set())", b"edges[name] = set()"),
            (b'walk(definition, f"/$defs/{name}", name)', b"walk(definition, name, name)"),
        )
        for old, new in attacks:
            with self.subTest(old=old, new=new):
                self.assertGreaterEqual(self.source.count(old), 1)
                mutated = self.source.replace(old, new, 1)
                if old == b"len(name) > 64":
                    site_ids = {
                        item["site_id"] for item in _source_bound_inventory({path: mutated})
                    }
                    self.assertNotIn(NAME_COMPARISON_SITE, site_ids)
                else:
                    self.assertNotEqual(mutated, self.source)

    def test_v42_preserves_v41_schema_definition_name_constraint(self):
        predecessor = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v41.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(len(self.manifest["constraints"]), 38)
        for successor, historical in zip(
            self.manifest["constraints"][:-1], predecessor["constraints"], strict=True
        ):
            self.assertEqual(
                {key: value for key, value in successor.items() if key != "evidence_inputs"},
                {key: value for key, value in historical.items() if key != "evidence_inputs"},
            )
        constraint = self.constraint()
        self.assertEqual(constraint["maximum"], 64)
        self.assertEqual(constraint["unit"], "CHARACTERS")
        self.assertEqual(constraint["definition_site_ids"], [NAME_COMPARISON_SITE])
        self.assertEqual(constraint["enforcement_site_ids"], [NAME_COMPARISON_SITE])
        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 39)
        self.assertEqual(classification["classified_site_count"], 72)
        self.assertEqual(classification["unclassified_site_count"], 649)
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

    def test_h162_separation_adjacent_exclusions_and_authority_nonclaims(self):
        classified = {
            site_id
            for item in self.manifest["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in item[field]
        }
        self.assertIn(REF_TOKEN_COMPARISON_SITE, classified)
        self.assertIn(NAME_COMPARISON_SITE, classified)
        self.assertNotEqual(REF_TOKEN_COMPARISON_SITE, NAME_COMPARISON_SITE)
        constraint = self.constraint()
        self.assertIn("DEFINITION_NAME", constraint["semantic_subject"])
        self.assertNotIn("REFERENCE_TOKEN", constraint["semantic_subject"])
        semantic_text = json.dumps(constraint, sort_keys=True).lower().replace("_", " ")
        for nonclaim in ("public verifier acceptance", "stop clearance", "capital authority"):
            self.assertNotIn(nonclaim, semantic_text)


if __name__ == "__main__":
    unittest.main()
