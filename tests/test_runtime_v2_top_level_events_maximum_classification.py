"""Adversarial evidence for the V35 host-preflight events maximum slice."""
from __future__ import annotations

import json
import unittest

import src.edgelab.runtime_v2_image as host
from tools.check_runtime_v2_release_readiness import (
    RESOURCE_CLASSIFICATION_MANIFEST,
    ROOT,
    build_report,
)


class _TupleSubclass(tuple):
    pass


class RuntimeV2TopLevelEventsMaximumClassificationTests(unittest.TestCase):
    SITE = "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4"
    MAXIMUM = 100_000
    EXCLUDED_SITES = frozenset({
        "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f",
        "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1",
        "53665796e6a36a9a24b6c67772a4522eff123ec97fa030bbecf28cf23dacec0e",
        "7aa7301fdf0c934b7670458f3dc53d479ed5b9ff55c92193f5464447b6654a62",
        "010da3224306d0cd52262c06f3025d561db102d10f9eceec52d17453c5ad3c2f",
        "1cf087a87f9579fff81c9fdc9ba6e0a449869803db1b7a5521ab359b73a66407",
        "528da7f2da6b5b78d436a7e019d9d2e7fb562f19ce944c88b439e730438e4a01",
        "d2a3c649a05bb706d2c425bed0ad99859ad71e4833fb0a7388d6364d2788c4be",
        "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed",
        "7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a",
        "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534",
    })

    @staticmethod
    def image(events: object, event_rows: tuple[object, ...] = ()) -> host.RuntimeImage:
        snapshots = tuple(
            host.TableSnapshot(name, event_rows if name == "events" else ())
            for name in host.TABLE_NAMES
        )
        return host.RuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=b"{}",
            schema_documents=tuple(
                host.SchemaDocumentRecord(
                    f"schema-{index}", f"digest-{index}", b"{}"
                )
                for index in range(9)
            ),
            blobs=(),
            events=events,
            table_snapshots=snapshots,
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    @classmethod
    def constraint(cls) -> dict[str, object]:
        manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        return next(
            item for item in manifest["constraints"]
            if item["constraint_id"]
            == "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM"
        )

    def test_v36_preserves_v35_semantics_with_successor_evidence_rebase(self):
        current = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        v35 = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v35.json"
            ).read_text(encoding="ascii")
        )
        predecessor = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v34.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(current["constraints"][:-1], v35["constraints"][:-1])
        current_last = dict(current["constraints"][-1])
        v35_last = dict(v35["constraints"][-1])
        current_evidence = current_last.pop("evidence_inputs")
        v35_evidence = v35_last.pop("evidence_inputs")
        self.assertEqual(current_last, v35_last)
        self.assertEqual(current_evidence[:-1], v35_evidence[:-1])
        self.assertEqual(
            v35_evidence[-1],
            {
                "byte_length": 9210,
                "path": "tests/test_runtime_v2_top_level_events_maximum_classification.py",
                "raw_sha256": "15ba11cac2ecab6b3c9ace47fa57bffed25c57ac8ca8105108ebe70a084d7835",
            },
        )
        self.assertEqual(
            current_evidence[-1]["path"],
            "tests/test_runtime_v2_top_level_events_maximum_classification.py",
        )
        self.assertEqual(v35["constraints"][:-1], predecessor["constraints"])
        self.assertEqual(len(current["constraints"]), 31)
        self.assertEqual(current["classified_site_count"], 58)
        self.assertEqual(current["unclassified_site_count"], 662)
        self.assertEqual(v35["unclassified_site_count"], 661)
        constraint = current["constraints"][-1]
        self.assertEqual(constraint, self.constraint())
        self.assertEqual(constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(constraint["unit"], "ITEMS")
        self.assertEqual(constraint["maximum"], self.MAXIMUM)
        self.assertEqual(
            constraint["accepted_equation"],
            "0 <= len(captured['events']) <= 100000",
        )
        self.assertEqual(constraint["definition_site_ids"], [self.SITE])
        self.assertEqual(constraint["enforcement_site_ids"], [self.SITE])
        self.assertEqual(
            set(constraint["definition_site_ids"])
            | set(constraint["enforcement_site_ids"]),
            {self.SITE},
        )
        report = build_report(ROOT)["inventory"]["resource_inventory_classification"]
        self.assertEqual(report["classified_constraint_count"], 31)
        self.assertEqual(report["classified_site_count"], 58)
        self.assertEqual(report["unclassified_site_count"], 662)

    def test_exact_subject_selection_and_every_excluded_site_stays_out(self):
        constraint = self.constraint()
        self.assertEqual(
            constraint["semantic_subject"],
            "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_EVENTS_AT_HOST_PREFLIGHT",
        )
        self.assertEqual(
            constraint["semantic_proof"]["selection_semantics"],
            "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY",
        )
        manifest = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        classified = {
            site_id
            for item in manifest["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in item[field]
        }
        self.assertTrue(self.EXCLUDED_SITES.isdisjoint(
            set(constraint["definition_site_ids"])
            | set(constraint["enforcement_site_ids"])
        ))
        self.assertIn(
            "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed",
            classified,
        )
        self.assertNotIn(
            "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f",
            classified,
        )
        self.assertNotIn(
            "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1",
            classified,
        )

    def test_inclusive_boundaries_and_exact_tuple_guard(self):
        for count, rejected in (
            (0, False),
            (99_999, False),
            (100_000, False),
            (100_001, True),
        ):
            with self.subTest(count=count):
                report = host.inspect_runtime_image_host(
                    self.image((b"",) * count)
                )
                self.assertEqual(
                    any(
                        item.code == "IMAGE_CARDINALITY_LIMIT"
                        and item.artifact == "events"
                        for item in report.violations
                    ),
                    rejected,
                )
                self.assertEqual(report.authorizing_use, "DENY")
                self.assertEqual(report.image is None, rejected)
                with self.assertRaises(TypeError):
                    bool(report)

        for hostile in ([], _TupleSubclass()):
            with self.subTest(hostile_type=type(hostile).__name__):
                report = host.inspect_runtime_image_host(self.image(hostile))
                self.assertIn(
                    host.ImageViolation("IMAGE_FIELD_TYPE", "events", "/"),
                    report.violations,
                )
                self.assertNotIn(
                    host.ImageViolation(
                        "IMAGE_CARDINALITY_LIMIT", "events", "/"
                    ),
                    report.violations,
                )
                self.assertIsNone(report.image)
                self.assertIsNone(report.total_accounted_input_bytes)

    def test_at_limit_malformed_member_is_inspected_plus_one_is_skipped(self):
        at_limit = (b"",) * (self.MAXIMUM - 1) + (object(),)
        report = host.inspect_runtime_image_host(self.image(at_limit))
        self.assertIn(
            host.ImageViolation(
                "IMAGE_RECORD_TYPE", "events", f"/{self.MAXIMUM - 1}"
            ),
            report.violations,
        )
        self.assertNotIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            report.violations,
        )
        self.assertIsNone(report.total_accounted_input_bytes)
        self.assertIsNone(report.image)

        plus_one = host.inspect_runtime_image_host(
            self.image((object(),) * (self.MAXIMUM + 1))
        )
        self.assertIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            plus_one.violations,
        )
        self.assertFalse(any(
            item.code == "IMAGE_RECORD_TYPE" and item.artifact == "events"
            for item in plus_one.violations
        ))
        self.assertIsNone(plus_one.total_accounted_input_bytes)
        self.assertIsNone(plus_one.image)

    def test_events_table_row_cap_is_independent(self):
        event_row_overflow = (object(),) * (self.MAXIMUM + 1)
        report = host.inspect_runtime_image_host(
            self.image((), event_rows=event_row_overflow)
        )
        self.assertNotIn(
            host.ImageViolation("IMAGE_CARDINALITY_LIMIT", "events", "/"),
            report.violations,
        )
        self.assertTrue(any(
            item.code == "TABLE_ROW_LIMIT"
            and item.artifact == "table_snapshots"
            and item.coordinate == "/3/rows"
            for item in report.violations
        ))


if __name__ == "__main__":
    unittest.main()
