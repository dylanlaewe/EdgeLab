"""Adversarial evidence for the atomic H160 verifier finding-string bounds."""
from __future__ import annotations

import hashlib
import json
import unittest

from src.edgelab.runtime_v2_verifier import _finding
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_MANIFEST,
    ReadinessError,
    _source_bound_finding_coordinate_character_maximum_inventory,
    build_report,
)


ARTIFACT_COMPOSITE = "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e"
ARTIFACT_DEFINITION = "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
ARTIFACT_CALLER = "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98"
COORDINATE_COMPOSITE = "fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8"
COORDINATE_DEFINITION = "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
COORDINATE_CALLER = "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c"
SHARED_COMPARISON = "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
SHARED_SLICE = "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"


class FindingStringBoundsClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.sites = cls.discovery["source_bound_sites"]
        cls.source_bytes = {
            item["path"]: (ROOT / item["path"]).read_bytes()
            for item in cls.report["inventory"]["source_closure"]["local_artifacts"]
        }
        cls.manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(encoding="ascii")
        )

    def constraint(self, constraint_id: str) -> dict[str, object]:
        return next(
            item for item in self.manifest["constraints"]
            if item["constraint_id"] == constraint_id
        )

    def test_discovery_v7_adds_exact_coordinate_composite(self):
        records = [
            item for item in self.sites
            if item["kind"]
            == "BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING"
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["site_id"], COORDINATE_COMPOSITE)
        self.assertEqual(record["classification"], "UNCLASSIFIED")
        self.assertEqual(record["maximum"], 512)
        self.assertEqual(record["unit"], "CHARACTERS")
        self.assertEqual(record["definition_site_id"], COORDINATE_DEFINITION)
        self.assertEqual(record["caller_site_id"], COORDINATE_CALLER)
        self.assertEqual(record["comparison_site_id"], SHARED_COMPARISON)
        self.assertEqual(record["slice_site_id"], SHARED_SLICE)
        self.assertEqual(self.discovery["profile_id"], "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V7")
        self.assertEqual(len(self.sites), 425)

    def test_runtime_boundary_and_full_utf8_digest_matrices(self):
        for field, maximum, prefix in (
            ("artifact", 256, 184),
            ("coordinate", 512, 440),
        ):
            for length in (0, maximum - 1, maximum):
                value = "a" * length
                finding = _finding("X", value if field == "artifact" else "a", value if field == "coordinate" else "/x")
                self.assertEqual(getattr(finding, field), value)

            value = "a" * (maximum + 1)
            suffix = "#sha256=" + hashlib.sha256(value.encode("utf-8")).hexdigest()
            finding = _finding("X", value if field == "artifact" else "a", value if field == "coordinate" else "/x")
            observed = getattr(finding, field)
            self.assertEqual(observed, value[:prefix] + suffix)
            self.assertEqual(len(observed), maximum)
            self.assertEqual(len(suffix), 72)

            unicode_value = "é" * (maximum + 1)
            unicode_suffix = "#sha256=" + hashlib.sha256(
                unicode_value.encode("utf-8")
            ).hexdigest()
            finding = _finding(
                "X",
                unicode_value if field == "artifact" else "a",
                unicode_value if field == "coordinate" else "/x",
            )
            self.assertEqual(
                getattr(finding, field), unicode_value[:prefix] + unicode_suffix
            )
            self.assertNotEqual(
                unicode_suffix,
                "#sha256=" + hashlib.sha256(unicode_value.encode("utf-16")).hexdigest(),
            )

    def test_coordinate_source_and_subject_substitution_fail_closed(self):
        predecessor = [
            item for item in self.sites
            if item["kind"]
            != "BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING"
        ]
        path = "src/edgelab/runtime_v2_verifier.py"
        original = self.source_bytes[path]
        attacks = (
            (b"MAX_FINDING_COORDINATE_CHARS = 512", b"MAX_FINDING_COORDINATE_CHARS = 511"),
            (b"bounded(coordinate, MAX_FINDING_COORDINATE_CHARS)", b"bounded(coordinate, MAX_FINDING_ARTIFACT_CHARS)"),
            (b"bounded(coordinate, MAX_FINDING_COORDINATE_CHARS)", b"bounded(str(coordinate), MAX_FINDING_COORDINATE_CHARS)"),
            (b"len(value) <= maximum", b"len(value) < maximum"),
            (b"value.encode('utf-8')", b"value.encode('utf-16')"),
            (b"sha256(value.encode('utf-8')).hexdigest()", b"sha256(value[:maximum].encode('utf-8')).hexdigest()"),
            (b'f"#sha256={', b'f"#digest={'),
            (b"value[:maximum - len(suffix)] + suffix", b"value[:maximum - len(suffix) - 1] + suffix"),
            (b"return value[:maximum - len(suffix)] + suffix", b"return suffix + value[:maximum - len(suffix)]"),
        )
        for old, new in attacks:
            with self.subTest(old=old, new=new):
                self.assertEqual(original.count(old), 1)
                source = dict(self.source_bytes)
                source[path] = original.replace(old, new)
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_finding_coordinate_character_maximum_inventory(
                        source, predecessor
                    )
                self.assertTrue(
                    caught.exception.code.startswith("RESOURCE_FINDING_COORDINATE_")
                )

    def test_coordinate_predecessor_missing_substituted_and_duplicate_deny(self):
        predecessor = [
            item for item in self.sites
            if item["kind"]
            != "BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING"
        ]
        for site_id in (
            COORDINATE_DEFINITION,
            COORDINATE_CALLER,
            SHARED_COMPARISON,
            SHARED_SLICE,
        ):
            with self.subTest(site_id=site_id):
                missing = [item for item in predecessor if item["site_id"] != site_id]
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_finding_coordinate_character_maximum_inventory(
                        self.source_bytes, missing
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_FINDING_COORDINATE_PREDECESSOR_SITE",
                )
        duplicated = predecessor + [dict(predecessor[0])]
        with self.assertRaises(ReadinessError) as caught:
            _source_bound_finding_coordinate_character_maximum_inventory(
                self.source_bytes, duplicated
            )
        self.assertEqual(
            caught.exception.code,
            "RESOURCE_FINDING_COORDINATE_PREDECESSOR_DUPLICATE",
        )

    def test_v39_preserves_v38_finding_string_constraints(self):
        predecessor = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v38.json"
            ).read_text(encoding="ascii")
        )
        for successor, historical in zip(
            self.manifest["constraints"][:-1], predecessor["constraints"], strict=True
        ):
            self.assertEqual(
                {
                    key: value for key, value in successor.items()
                    if key != "evidence_inputs"
                },
                {
                    key: value for key, value in historical.items()
                    if key != "evidence_inputs"
                },
            )
        self.assertEqual(len(self.manifest["constraints"]), 35)
        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 35)
        self.assertEqual(classification["classified_site_count"], 68)
        self.assertEqual(classification["unclassified_site_count"], 653)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")

        artifact = self.constraint("VERIFIER_FINDING_ARTIFACT_CHARACTER_MAXIMUM")
        coordinate = self.constraint("VERIFIER_FINDING_COORDINATE_CHARACTER_MAXIMUM")
        self.assertEqual(artifact["definition_site_ids"], [ARTIFACT_DEFINITION])
        self.assertEqual(
            artifact["enforcement_site_ids"],
            [ARTIFACT_CALLER, ARTIFACT_COMPOSITE],
        )
        self.assertEqual(artifact["maximum"], 256)
        self.assertEqual(coordinate["definition_site_ids"], [COORDINATE_DEFINITION])
        self.assertEqual(
            coordinate["enforcement_site_ids"],
            [COORDINATE_CALLER, COORDINATE_COMPOSITE],
        )
        self.assertEqual(coordinate["maximum"], 512)

    def test_shared_helper_sibling_and_max_findings_stay_unclassified(self):
        classified = {
            site_id
            for constraint in self.manifest["constraints"]
            for key in ("definition_site_ids", "enforcement_site_ids")
            for site_id in constraint[key]
        }
        self.assertNotIn(SHARED_COMPARISON, classified)
        self.assertNotIn(SHARED_SLICE, classified)
        for site_id in (
            "d67e4928791f1598983e53ec2e2dbc637560ee94550a1583f3e8da9c90943a8f",
            "7135d2129160fe8e9b98da19d36e035472c32c715ab19768eaa31ce35f799ab9",
            "574e0937067c05cc45100bea4d43d654e74a9cdaad45959e81221a6bee3cc62a",
        ):
            self.assertNotIn(site_id, classified)
        artifact = self.constraint("VERIFIER_FINDING_ARTIFACT_CHARACTER_MAXIMUM")
        coordinate = self.constraint("VERIFIER_FINDING_COORDINATE_CHARACTER_MAXIMUM")
        self.assertNotEqual(artifact["semantic_subject"], coordinate["semantic_subject"])
        self.assertTrue(
            set(artifact["definition_site_ids"] + artifact["enforcement_site_ids"]).isdisjoint(
                coordinate["definition_site_ids"] + coordinate["enforcement_site_ids"]
            )
        )


if __name__ == "__main__":
    unittest.main()
