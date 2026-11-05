"""Adversarial evidence for the private codec validation-depth ceiling."""
from __future__ import annotations

import json
import unittest

import src.edgelab.runtime_v2_codec as codec
from src.edgelab.runtime_v2_codec import CanonicalJsonError
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_MANIFEST,
    _source_bound_inventory,
    build_report,
)


DEPTH_COMPARISON_SITE = "be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c"
DEFAULT_DEPTH_SITE = "b3ed1a4f14af6fb6e7f9d2a7246adfe2cf28de8ac18cb3b45a473970e9a9009a"


class CodecPrivateValidateDepthBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(encoding="ascii")
        )
        cls.source = (ROOT / "src/edgelab/runtime_v2_codec.py").read_bytes()

    def constraint(self) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"] == "CODEC_PRIVATE_VALIDATE_DEPTH_MAXIMUM"
        )

    def test_direct_private_depth_127_128_pass_and_129_rejects(self):
        for depth in (127, 128):
            with self.subTest(depth=depth):
                self.assertIsNone(codec._validate(None, set(), depth))
        with self.assertRaisesRegex(CanonicalJsonError, "MAX_DEPTH_EXCEEDED"):
            codec._validate(None, set(), 129)

    def test_guard_rejects_before_value_dispatch(self):
        unsupported = object()
        with self.assertRaisesRegex(CanonicalJsonError, "MAX_DEPTH_EXCEEDED"):
            codec._validate(unsupported, set(), 129)
        with self.assertRaisesRegex(CanonicalJsonError, "UNSUPPORTED_TYPE"):
            codec._validate(unsupported, set(), 128)

    def test_negative_depth_is_an_explicit_nonclaim(self):
        self.assertIsNone(codec._validate(None, set(), -1))
        self.assertIn(
            "NEGATIVE_DEPTH_VALIDITY",
            self.constraint()["semantic_proof"]["selection_semantics"],
        )

    def test_nested_list_boundary_is_consistent_with_private_guard(self):
        def nested(levels: int) -> object:
            value: object = None
            for _ in range(levels):
                value = [value]
            return value

        self.assertIsInstance(codec.canonical_json(nested(128)), bytes)
        with self.assertRaisesRegex(CanonicalJsonError, "MAX_DEPTH_EXCEEDED"):
            codec.canonical_json(nested(129))

    def test_exact_guard_error_function_callers_and_recursive_calls_are_pinned(self):
        fragments = (
            b"def _validate(value: Any, active: set[int], depth: int = 0) -> None:",
            b"if depth > 128:",
            b'raise CanonicalJsonError("MAX_DEPTH_EXCEEDED")',
            b"_validate(value, set())",
            b"_validate(item, active, depth + 1)",
            b"_validate(key, active, depth + 1)",
        )
        expected_counts = (1, 1, 1, 2, 2, 1)
        for fragment, count in zip(fragments, expected_counts, strict=True):
            self.assertEqual(self.source.count(fragment), count)
        self.assertLess(
            self.source.index(b"if depth > 128:"),
            self.source.index(b"if value is None"),
        )

    def test_comparator_and_literal_attacks_change_site_identity(self):
        path = "src/edgelab/runtime_v2_codec.py"
        for old, new in (
            (b"depth > 128", b"depth >= 128"),
            (b"depth > 128", b"depth > 127"),
            (b"depth > 128", b"depth > 129"),
            (b"depth > 128", b"128 < depth"),
        ):
            with self.subTest(old=old, new=new):
                mutated = self.source.replace(old, new, 1)
                site_ids = {
                    item["site_id"] for item in _source_bound_inventory({path: mutated})
                }
                self.assertNotIn(DEPTH_COMPARISON_SITE, site_ids)

    def test_v42_preserves_v41_private_depth_constraint(self):
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
        self.assertEqual(constraint["maximum"], 128)
        self.assertEqual(constraint["unit"], "LEVELS")
        self.assertEqual(constraint["definition_site_ids"], [DEPTH_COMPARISON_SITE])
        self.assertEqual(constraint["enforcement_site_ids"], [DEPTH_COMPARISON_SITE])
        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 38)
        self.assertEqual(classification["classified_site_count"], 71)
        self.assertEqual(classification["unclassified_site_count"], 650)
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

    def test_default_depth_and_broader_authority_remain_unclassified(self):
        classified = {
            site_id
            for item in self.manifest["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in item[field]
        }
        self.assertIn(DEPTH_COMPARISON_SITE, classified)
        self.assertNotIn(DEFAULT_DEPTH_SITE, classified)
        semantic_text = json.dumps(self.constraint(), sort_keys=True).lower().replace(
            "_", " "
        )
        for authority_claim in (
            "public acceptance granted",
            "parser rejection guaranteed",
            "stop clearance",
            "execution authority",
            "capital authority",
        ):
            self.assertNotIn(authority_claim, semantic_text)


if __name__ == "__main__":
    unittest.main()
