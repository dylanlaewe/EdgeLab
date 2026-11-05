"""Current-only integration accounting for runtime-v2 resource classification."""
from __future__ import annotations

import json
import unittest

from src.edgelab.validate import ROOT
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_CURRENT_TEST_PATH,
    RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES,
    RESOURCE_CLASSIFICATION_V46_MANIFEST,
    RESOURCE_CLASSIFICATION_V47_MANIFEST,
    RESOURCE_CLASSIFICATION_V48_MANIFEST,
    RESOURCE_CLASSIFICATION_V49_MANIFEST,
    RESOURCE_CLASSIFICATION_V50_MANIFEST,
    build_report,
)


class RuntimeV2ResourceClassificationCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_report(ROOT)
        cls.classification = cls.report["inventory"][
            "resource_inventory_classification"
        ]
        cls.manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V50_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        cls.predecessor = json.loads(
            (
                ROOT / RESOURCE_CLASSIFICATION_V49_MANIFEST[1]
            ).read_text(encoding="ascii")
        )
        cls.v48 = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V48_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        cls.v47 = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V47_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        cls.v46 = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_V46_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        cls.v45 = json.loads(
            (ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v45.json")
            .read_text(encoding="ascii")
        )

    def test_current_manifest_report_and_partition_are_exact(self):
        self.assertEqual(self.manifest["schema_version"], 50)
        self.assertEqual(len(self.manifest["constraints"]), 45)
        source_ids = {
            site_id
            for constraint in self.manifest["constraints"]
            if constraint["classification"] != "SCHEMA_DECLARATIVE_BOUND"
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in constraint[field]
        }
        schema_ids = {
            constraint["schema_site_id"]
            for constraint in self.manifest["constraints"]
            if constraint["classification"] == "SCHEMA_DECLARATIVE_BOUND"
        }
        self.assertEqual(len(source_ids), 71)
        self.assertEqual(len(schema_ids), 7)
        self.assertTrue(source_ids.isdisjoint(schema_ids))
        self.assertEqual(self.manifest["classified_site_count"], 78)
        self.assertEqual(self.manifest["unclassified_site_count"], 643)
        self.assertEqual(self.classification["classified_constraint_count"], 45)
        self.assertEqual(self.classification["classified_site_count"], 78)
        self.assertEqual(self.classification["unclassified_site_count"], 643)
        self.assertEqual(self.classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(self.classification["generation_disposition"], "DENY")

    def test_v50_is_exact_v49_prefix_plus_ordered_two_member_family(self):
        self.assertEqual(
            self.manifest["constraints"][:-2], self.predecessor["constraints"]
        )
        self.assertEqual(
            [item["schema_site_id"] for item in self.manifest["constraints"][-2:]],
            [
                "b2840fbfba98b7107e46eee42f8d818a2e8d60582f9fbd4e394993a686bda437",
                "5dce821ee45f15010f24959f58819323b0112024635aeb4ede5380e3e47c69d4",
            ],
        )

    def test_v49_is_exact_v48_prefix_plus_ordered_two_member_family(self):
        self.assertEqual(
            self.predecessor["constraints"][:-2], self.v48["constraints"]
        )
        self.assertEqual(
            [item["schema_site_id"] for item in self.predecessor["constraints"][-2:]],
            [
                "9a219d2847af954061fe8e233e8e316f57a09e9ec256c83ed829724b9930f626",
                "1d6cb316a9edd5dfe397fc767d6e23f7c22e93c1e1292f19cbeff98cfea96514",
            ],
        )

    def test_v48_is_exact_v47_prefix_plus_one_schema_proof(self):
        self.assertEqual(
            self.v48["constraints"][:-1], self.v47["constraints"]
        )
        self.assertEqual(
            self.v48["constraints"][-1]["schema_site_id"],
            "d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574",
        )

    def test_v47_is_exact_v46_prefix_plus_one_schema_proof(self):
        self.assertEqual(
            self.v47["constraints"][:-1], self.v46["constraints"]
        )
        self.assertEqual(
            self.v47["constraints"][-1]["schema_site_id"],
            "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b",
        )

    def test_v46_changes_only_the_exact_nine_evidence_coordinates(self):
        observed = set()
        for successor, historical in zip(
            self.v46["constraints"],
            self.v45["constraints"],
            strict=True,
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
            for current, previous in zip(
                successor["evidence_inputs"],
                historical["evidence_inputs"],
                strict=True,
            ):
                if current == previous:
                    continue
                coordinate = (successor["constraint_id"], current["path"])
                observed.add(coordinate)
                allowed = RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES[
                    coordinate
                ]
                self.assertEqual(
                    previous,
                    {"path": current["path"], **allowed["historical"]},
                )
                self.assertEqual(
                    current,
                    {"path": current["path"], **allowed["current"]},
                )
        self.assertEqual(
            observed, set(RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES)
        )
        self.assertEqual(len(observed), 9)
        self.assertEqual(len({path for _, path in observed}), 8)

    def test_historical_evidence_is_decoupled_from_live_accounting(self):
        evidence_paths = {
            evidence["path"]
            for constraint in self.v46["constraints"]
            for evidence in constraint["evidence_inputs"]
        }
        self.assertNotIn(RESOURCE_CLASSIFICATION_CURRENT_TEST_PATH, evidence_paths)
        migrated_paths = {
            path for _, path in RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES
        }
        forbidden = (
            "CURRENT_RESOURCE_CLASSIFICATION_MANIFEST",
            "resource_inventory_classification",
            'self.report["blockers"]',
        )
        for path in migrated_paths:
            with self.subTest(path=path):
                source = (ROOT / path).read_text(encoding="utf-8")
                for token in forbidden:
                    self.assertNotIn(token, source)

    def test_current_disposition_retains_the_four_blockers(self):
        self.assertEqual(self.report["authorizing_use"], "DENY")
        self.assertEqual(
            [item["code"] for item in self.report["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )
        classification = self.report["inventory"][
            "resource_inventory_classification"
        ]
        self.assertEqual(classification["classified_source_site_count"], 71)
        self.assertEqual(classification["classified_schema_site_count"], 7)
        blocker = next(
            item for item in self.report["blockers"]
            if item["code"] == "RESOURCE_INVENTORY_INCOMPLETE"
        )
        self.assertIn("354 unclassified source-bound sites", blocker["evidence"])
        self.assertIn("289 unclassified schema-bound sites", blocker["evidence"])
        self.assertNotIn("296 unclassified schema-bound sites", blocker["evidence"])


if __name__ == "__main__":
    unittest.main()
