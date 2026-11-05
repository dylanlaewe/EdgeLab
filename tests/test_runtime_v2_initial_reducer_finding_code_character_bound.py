"""Adversarial evidence for initial-reducer finding-code transformation."""
from __future__ import annotations

from hashlib import sha256
import json
import unittest

from src.edgelab.validate import ROOT
import src.edgelab.runtime_v2_initial as initial
from tools.check_runtime_v2_release_readiness import _source_bound_inventory, build_report


CODE_CALLER_SITE = "299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8"
HELPER_COMPARISON_SITE = "b9d6e7685b9750d0d4f2878693dd8399352026da86bc702a68e0665c52660aa8"
HELPER_SLICE_SITE = "3a002bdb48f59524713c8d1b2196549abd25f5266f695051e4cbc0767b816cd2"
ARTIFACT_CALLER_SITE = "a5067812eaa4a7612788561ee9e7139d356a76f5adce38fcfd1296e37a6c37df"
COORDINATE_CALLER_SITE = "e82e2fbfb0c25192c551e66d85793a97190f689d55dc359d92d2415b8c0e97dd"
MAX_FINDINGS_SITE = "7f1ed86fdd9b0941afaa1d7ca91c80e88ec157b2cfcbc16c184b92e09cd63c95"


class InitialReducerFindingCodeCharacterBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.manifest = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v42.json")
            .read_text(encoding="ascii")
        )
        cls.source = (ROOT / "src/edgelab/runtime_v2_initial.py").read_bytes()

    def constraint(self) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"]
            == "INITIAL_REDUCER_FINDING_CODE_CHARACTER_MAXIMUM"
        )

    @staticmethod
    def stored_code(code: str) -> str:
        sink = initial._Sink()
        sink.add(code, "artifact", "/coordinate")
        return sink.result()[0].code

    def test_127_and_128_are_unchanged_and_129_is_exactly_transformed(self):
        for length in (127, 128):
            with self.subTest(length=length):
                code = "C" * length
                self.assertEqual(self.stored_code(code), code)
        code = "C" * 129
        expected = code[:56] + "#sha256=" + sha256(code.encode("utf-8")).hexdigest()
        self.assertEqual(self.stored_code(code), expected)
        self.assertEqual(len(expected), 128)

    def test_unicode_counts_characters_but_digests_full_utf8(self):
        code = "é" * 129
        expected = code[:56] + "#sha256=" + sha256(code.encode("utf-8")).hexdigest()
        self.assertEqual(self.stored_code(code), expected)
        self.assertEqual(len(expected), 128)
        self.assertGreater(len(code.encode("utf-8")), len(code))

    def test_empty_code_has_no_classified_minimum(self):
        self.assertEqual(self.stored_code(""), "")

    def test_synthetic_findings_truncated_bypasses_classified_caller(self):
        sink = initial._Sink()
        sink._truncated = True
        self.assertEqual(
            sink.result(),
            (initial.InitialViolation("FINDINGS_TRUNCATED", "reducer", "/findings"),),
        )

    def test_exact_helper_subject_constructor_and_siblings_are_pinned(self):
        fragments = (
            b"if len(value) <= maximum:",
            b"return value\n",
            b'suffix = f"#sha256={sha256(value.encode(\'utf-8\')).hexdigest()}"',
            b"return value[:maximum - len(suffix)] + suffix",
            b"bounded(code, 128)",
            b"bounded(artifact, 256)",
            b"bounded(coordinate, 512)",
        )
        for fragment in fragments:
            self.assertEqual(self.source.count(fragment), 1)
        self.assertEqual(
            [self.source.index(fragment) for fragment in fragments],
            sorted(self.source.index(fragment) for fragment in fragments),
        )

    def test_literal_and_argument_attacks_change_subject_caller_site(self):
        path = "src/edgelab/runtime_v2_initial.py"
        for old, new in (
            (b"bounded(code, 128)", b"bounded(code, 127)"),
            (b"bounded(code, 128)", b"bounded(code, 129)"),
            (b"bounded(code, 128)", b"bounded(artifact, 128)"),
        ):
            with self.subTest(old=old, new=new):
                mutated = self.source.replace(old, new, 1)
                site_ids = {
                    item["site_id"] for item in _source_bound_inventory({path: mutated})
                }
                self.assertNotIn(CODE_CALLER_SITE, site_ids)

    def test_v42_is_v41_semantic_prefix_plus_one_deny_only_constraint(self):
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
        self.assertEqual(constraint["unit"], "CHARACTERS")
        self.assertEqual(constraint["definition_site_ids"], [CODE_CALLER_SITE])
        self.assertEqual(constraint["enforcement_site_ids"], [CODE_CALLER_SITE])
        self.assertEqual(self.manifest["classified_site_count"], 71)
        self.assertEqual(self.manifest["unclassified_site_count"], 650)
        self.assertEqual(self.manifest["coverage_status"], "INCOMPLETE")
        self.assertEqual(self.manifest["generation_disposition"], "DENY")

    def test_shared_helper_siblings_count_and_authority_remain_excluded(self):
        classified = {
            site_id
            for item in self.manifest["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in item[field]
        }
        self.assertIn(CODE_CALLER_SITE, classified)
        for site_id in (
            HELPER_COMPARISON_SITE,
            HELPER_SLICE_SITE,
            ARTIFACT_CALLER_SITE,
            COORDINATE_CALLER_SITE,
            MAX_FINDINGS_SITE,
        ):
            self.assertNotIn(site_id, classified)
        semantic_text = json.dumps(self.constraint(), sort_keys=True).lower().replace(
            "_", " "
        )
        for authority_claim in (
            "public acceptance granted",
            "stop clearance",
            "release authority",
            "execution authority",
            "capital authority",
        ):
            self.assertNotIn(authority_claim, semantic_text)


if __name__ == "__main__":
    unittest.main()
