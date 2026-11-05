"""Adversarial evidence for deny-only Discovery V6 artifact truncation."""
from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from src.edgelab.runtime_v2_verifier import _finding
from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    ReadinessError,
    _source_bound_finding_artifact_character_maximum_inventory,
    build_report,
)


SITE_ID = "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e"
DEFINITION_ID = "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
CALLER_ID = "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98"
COMPARISON_ID = "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
SLICE_ID = "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"
COORDINATE_DEFINITION_ID = "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
COORDINATE_CALLER_ID = "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c"


class FindingArtifactCharacterDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        discovery = cls.report["inventory"]["resource_inventory_discovery"]
        cls.sites = discovery["source_bound_sites"]
        cls.predecessor_sites = [
            item for item in cls.sites
            if item["kind"] != "BOUND_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING"
        ]
        cls.source_bytes = {
            item["path"]: (ROOT / item["path"]).read_bytes()
            for item in cls.report["inventory"]["source_closure"]["local_artifacts"]
        }

    def test_v7_preserves_one_exact_artifact_composite(self):
        records = [
            item for item in self.sites
            if item["kind"] == "BOUND_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING"
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["site_id"], SITE_ID)
        self.assertEqual(record["classification"], "UNCLASSIFIED")
        self.assertEqual(record["maximum"], 256)
        self.assertEqual(record["unit"], "CHARACTERS")
        self.assertEqual(
            record["selection_semantics"],
            "VERIFICATION_FINDING_ARTIFACT_CHARACTER_MAXIMUM_ONLY",
        )
        self.assertEqual(record["definition_site_id"], DEFINITION_ID)
        self.assertEqual(record["caller_site_id"], CALLER_ID)
        self.assertEqual(record["comparison_site_id"], COMPARISON_ID)
        self.assertEqual(record["slice_site_id"], SLICE_ID)
        self.assertEqual(len(self.sites), 425)
        classification = self.report["inventory"]["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 37)
        self.assertEqual(classification["classified_site_count"], 70)
        self.assertEqual(classification["unclassified_site_count"], 651)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")

    def test_runtime_boundaries_and_utf8_digest_are_exact(self):
        for length in (0, 255, 256):
            value = "a" * length
            self.assertEqual(_finding("X", value, "/x").artifact, value)

        value = "a" * 257
        suffix = "#sha256=" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        observed = _finding("X", value, "/x").artifact
        self.assertEqual(observed, value[:184] + suffix)
        self.assertEqual(len(observed), 256)
        self.assertEqual(len(suffix), 72)

        unicode_value = "é" * 257
        unicode_suffix = "#sha256=" + hashlib.sha256(
            unicode_value.encode("utf-8")
        ).hexdigest()
        unicode_observed = _finding("X", unicode_value, "/x").artifact
        self.assertEqual(unicode_observed, unicode_value[:184] + unicode_suffix)
        self.assertEqual(len(unicode_observed), 256)
        self.assertNotEqual(
            unicode_suffix,
            "#sha256=" + hashlib.sha256(unicode_value.encode("utf-16")).hexdigest(),
        )

    def test_source_semantic_drift_fails_closed(self):
        attacks = (
            (b"len(value) <= maximum", b"len(value.encode('utf-8')) <= maximum"),
            (b"len(value) <= maximum", b"len(value) < maximum"),
            (b"len(value) <= maximum", b"len(value) >= maximum"),
            (
                b"sha256(value.encode('utf-8')).hexdigest()",
                b"sha256(value[:maximum].encode('utf-8')).hexdigest()",
            ),
            (b"value.encode('utf-8')", b"value.encode('utf-16')"),
            (b'f"#sha256={', b'f"#digest={'),
            (
                b"value[:maximum - len(suffix)] + suffix",
                b"value[:maximum - len(suffix) - 1] + suffix",
            ),
            (
                b"return value[:maximum - len(suffix)] + suffix",
                b"return suffix + value[:maximum - len(suffix)]",
            ),
            (
                b"bounded(artifact, MAX_FINDING_ARTIFACT_CHARS)",
                b"bounded(str(artifact), MAX_FINDING_ARTIFACT_CHARS)",
            ),
        )
        path = "src/edgelab/runtime_v2_verifier.py"
        original = self.source_bytes[path]
        for old, new in attacks:
            with self.subTest(old=old, new=new):
                self.assertEqual(original.count(old), 1)
                source = dict(self.source_bytes)
                source[path] = original.replace(old, new)
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_finding_artifact_character_maximum_inventory(
                        source, self.predecessor_sites
                    )
                self.assertTrue(caught.exception.code.startswith("RESOURCE_FINDING_ARTIFACT_"))

    def test_predecessor_and_subject_substitution_fail_closed(self):
        attacks = (
            (DEFINITION_ID, "0" * 64),
            (CALLER_ID, "1" * 64),
            (COMPARISON_ID, "2" * 64),
            (SLICE_ID, "3" * 64),
        )
        for site_id, replacement in attacks:
            with self.subTest(site_id=site_id):
                sites = [dict(item) for item in self.predecessor_sites]
                target = next(item for item in sites if item["site_id"] == site_id)
                target["site_id"] = replacement
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_finding_artifact_character_maximum_inventory(
                        self.source_bytes, sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_FINDING_ARTIFACT_PREDECESSOR_SITE",
                )

    def test_coordinate_and_shared_sites_remain_separate(self):
        by_id = {item["site_id"]: item for item in self.sites}
        for site_id in (
            DEFINITION_ID,
            CALLER_ID,
            COMPARISON_ID,
            SLICE_ID,
            COORDINATE_DEFINITION_ID,
            COORDINATE_CALLER_ID,
        ):
            self.assertEqual(by_id[site_id]["classification"], "UNCLASSIFIED")
        record = by_id[SITE_ID]
        self.assertNotIn(COORDINATE_DEFINITION_ID, record.values())
        self.assertNotIn(COORDINATE_CALLER_ID, record.values())
        self.assertIn(
            "VERIFICATION_FINDING_COORDINATE_CHARACTER_MAXIMUM",
            record["excluded_semantics"],
        )


if __name__ == "__main__":
    unittest.main()
