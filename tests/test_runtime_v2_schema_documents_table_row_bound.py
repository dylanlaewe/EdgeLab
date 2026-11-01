"""Adversarial evidence for the positional schema-documents table row cap."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-tuple rows value")


class RuntimeV2SchemaDocumentsTableRowBoundTests(unittest.TestCase):
    INDEX = 10

    @staticmethod
    def snapshots() -> list[host.TableSnapshot]:
        return [host.TableSnapshot(name, ()) for name in host.TABLE_NAMES]

    @staticmethod
    def image(
        snapshots: tuple[host.TableSnapshot, ...],
        schema_documents=(),
    ) -> host.RuntimeImage:
        return host.RuntimeImage(
            storage_descriptor=b"{}", verifier_dependency_closure=b"{}",
            manifest=b"{}", attachment=b"{}", schema_registry=b"{}",
            schema_documents=schema_documents, blobs=(), events=(),
            table_snapshots=snapshots, checkpoint_copies=(),
            selector_history=(b"{}", b"{}"), legacy_evidence=None,
        )

    @staticmethod
    def table_findings(report, index: int):
        prefix = f"/{index}"
        return tuple(
            finding for finding in report.violations
            if finding.artifact == "table_snapshots"
            and finding.coordinate.startswith(prefix)
        )

    def test_fixed_position_and_inclusive_maximum_are_exact(self):
        self.assertEqual(host.TABLE_NAMES[self.INDEX], "schema_documents")
        spec = host._TABLE_SPECS[self.INDEX]
        self.assertEqual((spec.name, spec.max_rows), ("schema_documents", 9))

    def test_zero_near_boundary_at_boundary_and_plus_one_are_deny_only(self):
        for count, rejected in ((0, False), (8, False), (9, False), (10, True)):
            with self.subTest(count=count):
                snapshots = self.snapshots()
                snapshots[self.INDEX] = host.TableSnapshot(
                    "schema_documents", (object(),) * count
                )
                candidate = self.image(tuple(snapshots))
                original = candidate.table_snapshots
                first = host.inspect_runtime_image_host(candidate)
                self.assertEqual(first, host.inspect_runtime_image_host(candidate))
                self.assertEqual(first.authorizing_use, "DENY")
                self.assertEqual(candidate.table_snapshots, original)
                self.assertEqual(any(
                    item.code == "TABLE_ROW_LIMIT"
                    for item in self.table_findings(first, self.INDEX)
                ), rejected)
                with self.assertRaises(TypeError):
                    bool(first)

    def test_nine_malformed_rows_reach_content_validation_without_authority(self):
        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", (object(),) * 9
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        findings = self.table_findings(report, self.INDEX)
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))
        self.assertTrue(findings)
        self.assertEqual(report.authorizing_use, "DENY")

    def test_over_limit_rejects_before_row_validation_or_accounting(self):
        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", (object(),) * 10
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_ROW_LIMIT", "table_snapshots", "/10/rows"),
        ))

    def test_top_level_exact_nine_cardinality_is_independent_both_directions(self):
        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", (object(),) * 9
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots), ()))
        self.assertFalse(any(
            item.code == "TABLE_ROW_LIMIT"
            for item in self.table_findings(report, self.INDEX)
        ))
        self.assertIn(
            host.ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "schema_documents", "/"
            ), report.violations,
        )

        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", (object(),) * 10
        )
        report = host.inspect_runtime_image_host(
            self.image(tuple(snapshots), (b"{}",) * 9)
        )
        self.assertIn(
            host.ImageViolation(
                "TABLE_ROW_LIMIT", "table_snapshots", "/10/rows"
            ), report.violations,
        )

    def test_supplied_label_cannot_select_or_bypass_the_positional_cap(self):
        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot("attempts", (object(),) * 10)
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_INVENTORY", "table_snapshots", "/10/table"),
            host.ImageViolation("TABLE_ROW_LIMIT", "table_snapshots", "/10/rows"),
        ))

        snapshots = self.snapshots()
        snapshots[0] = host.TableSnapshot("schema_documents", (object(),) * 10)
        findings = self.table_findings(
            host.inspect_runtime_image_host(self.image(tuple(snapshots))), 0
        )
        self.assertIn(
            host.ImageViolation("TABLE_INVENTORY", "table_snapshots", "/0/table"),
            findings,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))

    def test_missing_and_non_tuple_rows_skip_len(self):
        missing = object.__new__(host.TableSnapshot)
        object.__setattr__(missing, "table", "schema_documents")
        snapshots = self.snapshots()
        snapshots[self.INDEX] = missing
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation(
                "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots", "/10/rows"
            ),
        ))

        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", _ExplosiveLength()
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_ROWS_TYPE", "table_snapshots", "/10/rows"),
        ))

    def test_outer_cardinality_gate_precedes_positional_zip(self):
        snapshots = self.snapshots()[:-1]
        snapshots[self.INDEX] = host.TableSnapshot(
            "schema_documents", (object(),) * 10
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertIn(
            host.ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "table_snapshots", "/"
            ), report.violations,
        )
        self.assertFalse(any(
            item.code == "TABLE_ROW_LIMIT" for item in report.violations
        ))


if __name__ == "__main__":
    unittest.main()
