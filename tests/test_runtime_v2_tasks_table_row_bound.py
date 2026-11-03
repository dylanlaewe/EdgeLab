"""Adversarial evidence for the positional tasks table row cap."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-tuple rows value")


class RuntimeV2TasksTableRowBoundTests(unittest.TestCase):
    INDEX = 14
    MAXIMUM = 100_000

    @staticmethod
    def snapshots() -> list[host.TableSnapshot]:
        return [host.TableSnapshot(name, ()) for name in host.TABLE_NAMES]

    @staticmethod
    def image(snapshots: tuple[host.TableSnapshot, ...]) -> host.RuntimeImage:
        return host.RuntimeImage(
            storage_descriptor=b"{}", verifier_dependency_closure=b"{}",
            manifest=b"{}", attachment=b"{}", schema_registry=b"{}",
            schema_documents=(), blobs=(), events=(),
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

    def inspect(self, rows: tuple[object, ...], label: str = "tasks"):
        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot(label, rows)
        return host.inspect_runtime_image_host(self.image(tuple(snapshots)))

    def test_fixed_position_and_inclusive_maximum_are_exact(self):
        self.assertEqual(host.TABLE_NAMES[self.INDEX], "tasks")
        spec = host._TABLE_SPECS[self.INDEX]
        self.assertEqual((spec.name, spec.max_rows), (
            "tasks", self.MAXIMUM,
        ))

    def test_zero_near_boundary_at_boundary_and_plus_one_are_deny_only(self):
        for count, rejected in (
            (0, False), (99_999, False), (100_000, False), (100_001, True),
        ):
            with self.subTest(count=count):
                rows = ((),) * count
                snapshots = self.snapshots()
                snapshots[self.INDEX] = host.TableSnapshot("tasks", rows)
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

    def test_at_boundary_malformed_rows_reach_content_validation(self):
        report = self.inspect(((),) * self.MAXIMUM)
        findings = self.table_findings(report, self.INDEX)
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))
        self.assertTrue(any(item.code == "TABLE_ROW_WIDTH" for item in findings))
        self.assertEqual(report.authorizing_use, "DENY")

    def test_full_width_semantically_false_task_is_not_authority(self):
        row = (
            "same-task", -1, "impossible-workflow", "impossible-execution",
            "impossible-review", -1, -1, -1, "missing-claim",
            "missing-assignment", -1, -1, "bad-receipt", "same-owner",
            "invalid-role", "same-owner", "same-task", "same-task",
        )
        report = self.inspect((row, row))
        self.assertFalse(any(
            item.code == "TABLE_ROW_LIMIT"
            for item in self.table_findings(report, self.INDEX)
        ))
        self.assertEqual(report.authorizing_use, "DENY")
        with self.assertRaises(TypeError):
            bool(report)

    def test_over_limit_rejects_before_row_validation_or_accounting(self):
        report = self.inspect((object(),) * (self.MAXIMUM + 1))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_ROW_LIMIT", "table_snapshots", "/14/rows"),
        ))

    def test_supplied_label_cannot_select_or_bypass_the_positional_cap(self):
        report = self.inspect((object(),) * (self.MAXIMUM + 1), "blobs")
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_INVENTORY", "table_snapshots", "/14/table"),
            host.ImageViolation("TABLE_ROW_LIMIT", "table_snapshots", "/14/rows"),
        ))

        snapshots = self.snapshots()
        snapshots[1] = host.TableSnapshot(
            "tasks", (object(),) * (self.MAXIMUM + 1)
        )
        findings = self.table_findings(
            host.inspect_runtime_image_host(self.image(tuple(snapshots))), 1
        )
        self.assertIn(
            host.ImageViolation("TABLE_INVENTORY", "table_snapshots", "/1/table"),
            findings,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))

    def test_missing_and_non_tuple_rows_skip_len(self):
        missing = object.__new__(host.TableSnapshot)
        object.__setattr__(missing, "table", "tasks")
        snapshots = self.snapshots()
        snapshots[self.INDEX] = missing
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation(
                "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots", "/14/rows"
            ),
        ))

        snapshots = self.snapshots()
        snapshots[self.INDEX] = host.TableSnapshot("tasks", _ExplosiveLength())
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(self.table_findings(report, self.INDEX), (
            host.ImageViolation("TABLE_ROWS_TYPE", "table_snapshots", "/14/rows"),
        ))

    def test_outer_cardinality_gate_precedes_positional_zip(self):
        baseline = self.snapshots()
        baseline[self.INDEX] = host.TableSnapshot(
            "tasks", (object(),) * (self.MAXIMUM + 1)
        )
        for snapshots in (baseline[:-1], baseline + [
            host.TableSnapshot("extra", ())
        ]):
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
