"""Adversarial runtime evidence for positional table row ceilings."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-tuple rows value")


class RuntimeV2TableRowCapBindingTests(unittest.TestCase):
    @staticmethod
    def image(snapshots: tuple[host.TableSnapshot, ...]) -> host.RuntimeImage:
        return host.RuntimeImage(
            storage_descriptor=b"{}",
            verifier_dependency_closure=b"{}",
            manifest=b"{}",
            attachment=b"{}",
            schema_registry=b"{}",
            schema_documents=(),
            blobs=(),
            events=(),
            table_snapshots=snapshots,
            checkpoint_copies=(),
            selector_history=(b"{}", b"{}"),
            legacy_evidence=None,
        )

    @staticmethod
    def snapshots() -> list[host.TableSnapshot]:
        return [host.TableSnapshot(name, ()) for name in host.TABLE_NAMES]

    @staticmethod
    def relevant(report, index: int) -> tuple[host.ImageViolation, ...]:
        prefix = f"/{index}"
        return tuple(
            finding for finding in report.violations
            if finding.artifact == "table_snapshots"
            and finding.coordinate.startswith(prefix)
            and finding.code in {
                "TABLE_INVENTORY", "TABLE_ROW_LIMIT", "TABLE_ROWS_TYPE",
                "TABLE_SNAPSHOT_FIELD_MISSING",
            }
        )

    def test_all_distinct_cap_classes_are_inclusive_and_deny_only(self):
        cases = (
            ("migrations", 0),
            ("metadata", 1),
            ("schema_documents", 9),
            ("attempts", 100_000),
            ("blobs", 300_000),
        )
        for table, maximum in cases:
            index = host.TABLE_NAMES.index(table)
            for count, rejected in ((maximum, False), (maximum + 1, True)):
                with self.subTest(table=table, count=count):
                    snapshots = self.snapshots()
                    snapshots[index] = host.TableSnapshot(table, ((),) * count)
                    candidate = self.image(tuple(snapshots))
                    first = host.inspect_runtime_image_host(candidate)
                    second = host.inspect_runtime_image_host(candidate)
                    self.assertEqual(first, second)
                    self.assertEqual(first.authorizing_use, "DENY")
                    self.assertEqual(
                        any(
                            item.code == "TABLE_ROW_LIMIT"
                            for item in self.relevant(first, index)
                        ),
                        rejected,
                    )
                    with self.assertRaises(TypeError):
                        bool(first)

    def test_cap_selection_is_positional_not_supplied_table_label(self):
        snapshots = self.snapshots()
        snapshots[1] = host.TableSnapshot("events", ((),) * 100_001)
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        relevant = self.relevant(report, 1)
        self.assertIn(
            host.ImageViolation("TABLE_INVENTORY", "table_snapshots", "/1/table"),
            relevant,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in relevant))

        snapshots = self.snapshots()
        snapshots[3] = host.TableSnapshot("blobs", ((),) * 100_001)
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.relevant(report, 3),
            (
                host.ImageViolation(
                    "TABLE_INVENTORY", "table_snapshots", "/3/table"
                ),
                host.ImageViolation(
                    "TABLE_ROW_LIMIT", "table_snapshots", "/3/rows"
                ),
            ),
        )

    def test_missing_and_non_tuple_rows_fail_before_len(self):
        missing = object.__new__(host.TableSnapshot)
        object.__setattr__(missing, "table", "attempts")
        snapshots = self.snapshots()
        snapshots[0] = missing
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertIn(
            host.ImageViolation(
                "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots", "/0/rows"
            ),
            self.relevant(report, 0),
        )

        snapshots = self.snapshots()
        snapshots[0] = host.TableSnapshot("attempts", _ExplosiveLength())
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.relevant(report, 0),
            (host.ImageViolation("TABLE_ROWS_TYPE", "table_snapshots", "/0/rows"),),
        )


if __name__ == "__main__":
    unittest.main()
