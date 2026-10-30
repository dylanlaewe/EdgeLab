"""Adversarial evidence for the positional migrations-table zero-row cap."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-tuple rows value")


class RuntimeV2MigrationsTableRowBoundTests(unittest.TestCase):
    MIGRATIONS_INDEX = 7

    @staticmethod
    def snapshots() -> list[host.TableSnapshot]:
        return [host.TableSnapshot(name, ()) for name in host.TABLE_NAMES]

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
    def table_findings(report, index: int):
        prefix = f"/{index}"
        return tuple(
            finding for finding in report.violations
            if finding.artifact == "table_snapshots"
            and finding.coordinate.startswith(prefix)
        )

    def test_fixed_position_and_zero_maximum_are_exact(self):
        self.assertEqual(host.TABLE_NAMES[self.MIGRATIONS_INDEX], "migrations")
        spec = host._TABLE_SPECS[self.MIGRATIONS_INDEX]
        self.assertEqual((spec.name, spec.max_rows), ("migrations", 0))
        self.assertEqual(
            tuple(item.max_rows for item in host._TABLE_SPECS).count(0), 1
        )

    def test_zero_boundary_and_boundary_plus_one_are_deterministic_deny_only(self):
        for count, rejected in ((0, False), (1, True)):
            with self.subTest(count=count):
                snapshots = self.snapshots()
                snapshots[self.MIGRATIONS_INDEX] = host.TableSnapshot(
                    "migrations", (object(),) if count else ()
                )
                candidate = self.image(tuple(snapshots))
                original = candidate.table_snapshots
                first = host.inspect_runtime_image_host(candidate)
                second = host.inspect_runtime_image_host(candidate)
                self.assertEqual(first, second)
                self.assertEqual(first.authorizing_use, "DENY")
                self.assertEqual(candidate.table_snapshots, original)
                self.assertEqual(
                    any(
                        finding.code == "TABLE_ROW_LIMIT"
                        for finding in self.table_findings(
                            first, self.MIGRATIONS_INDEX
                        )
                    ),
                    rejected,
                )
                with self.assertRaises(TypeError):
                    bool(first)

    def test_over_limit_rejects_before_row_validation_or_accounting(self):
        snapshots = self.snapshots()
        snapshots[self.MIGRATIONS_INDEX] = host.TableSnapshot(
            "migrations", (object(),)
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.MIGRATIONS_INDEX),
            (host.ImageViolation(
                "TABLE_ROW_LIMIT", "table_snapshots", "/7/rows"
            ),),
        )

    def test_supplied_label_cannot_select_or_bypass_the_positional_cap(self):
        snapshots = self.snapshots()
        snapshots[self.MIGRATIONS_INDEX] = host.TableSnapshot(
            "attempts", (object(),)
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.MIGRATIONS_INDEX),
            (
                host.ImageViolation(
                    "TABLE_INVENTORY", "table_snapshots", "/7/table"
                ),
                host.ImageViolation(
                    "TABLE_ROW_LIMIT", "table_snapshots", "/7/rows"
                ),
            ),
        )
        snapshots = self.snapshots()
        snapshots[0] = host.TableSnapshot("migrations", (object(),))
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        findings = self.table_findings(report, 0)
        self.assertIn(
            host.ImageViolation(
                "TABLE_INVENTORY", "table_snapshots", "/0/table"
            ),
            findings,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))

    def test_missing_and_non_tuple_rows_skip_len(self):
        missing = object.__new__(host.TableSnapshot)
        object.__setattr__(missing, "table", "migrations")
        snapshots = self.snapshots()
        snapshots[self.MIGRATIONS_INDEX] = missing
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.MIGRATIONS_INDEX),
            (host.ImageViolation(
                "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots", "/7/rows"
            ),),
        )
        snapshots = self.snapshots()
        snapshots[self.MIGRATIONS_INDEX] = host.TableSnapshot(
            "migrations", _ExplosiveLength()
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.MIGRATIONS_INDEX),
            (host.ImageViolation(
                "TABLE_ROWS_TYPE", "table_snapshots", "/7/rows"
            ),),
        )

    def test_outer_cardinality_gate_precedes_positional_zip(self):
        snapshots = self.snapshots()[:-1]
        snapshots[self.MIGRATIONS_INDEX] = host.TableSnapshot(
            "migrations", (object(),)
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertIn(
            host.ImageViolation(
                "IMAGE_CARDINALITY_LIMIT", "table_snapshots", "/"
            ),
            report.violations,
        )
        self.assertFalse(any(
            finding.code == "TABLE_ROW_LIMIT" for finding in report.violations
        ))

    def test_sibling_table_rows_do_not_acquire_the_zero_cap(self):
        for table, count in (
            ("legacy_archive", 1),
            ("metadata", 1),
            ("schema_documents", 9),
            ("attempts", 2),
        ):
            with self.subTest(table=table):
                index = host.TABLE_NAMES.index(table)
                snapshots = self.snapshots()
                snapshots[index] = host.TableSnapshot(table, (object(),) * count)
                report = host.inspect_runtime_image_host(
                    self.image(tuple(snapshots))
                )
                self.assertFalse(any(
                    finding.code == "TABLE_ROW_LIMIT"
                    for finding in self.table_findings(report, index)
                ))


if __name__ == "__main__":
    unittest.main()
