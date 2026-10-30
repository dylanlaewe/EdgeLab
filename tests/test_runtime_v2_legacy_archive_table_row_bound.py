"""Adversarial evidence for the positional legacy-archive row cap."""
from __future__ import annotations

import unittest

import src.edgelab.runtime_v2_image as host


class _ExplosiveLength:
    def __len__(self):
        raise AssertionError("len() must not inspect a non-tuple rows value")


class RuntimeV2LegacyArchiveTableRowBoundTests(unittest.TestCase):
    LEGACY_ARCHIVE_INDEX = 5

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

    def test_fixed_position_and_inclusive_maximum_are_exact(self):
        self.assertEqual(
            host.TABLE_NAMES[self.LEGACY_ARCHIVE_INDEX], "legacy_archive"
        )
        spec = host._TABLE_SPECS[self.LEGACY_ARCHIVE_INDEX]
        self.assertEqual((spec.name, spec.max_rows), ("legacy_archive", 1))

    def test_zero_one_and_boundary_plus_one_are_deterministic_deny_only(self):
        for count, rejected in ((0, False), (1, False), (2, True)):
            with self.subTest(count=count):
                snapshots = self.snapshots()
                snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
                    "legacy_archive", (object(),) * count
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
                            first, self.LEGACY_ARCHIVE_INDEX
                        )
                    ),
                    rejected,
                )
                with self.assertRaises(TypeError):
                    bool(first)

    def test_one_row_is_not_reinterpreted_as_a_validity_or_minimum_claim(self):
        snapshots = self.snapshots()
        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "legacy_archive", (object(),)
        )
        findings = self.table_findings(
            host.inspect_runtime_image_host(self.image(tuple(snapshots))),
            self.LEGACY_ARCHIVE_INDEX,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))
        self.assertTrue(findings)

        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "legacy_archive", ()
        )
        findings = self.table_findings(
            host.inspect_runtime_image_host(self.image(tuple(snapshots))),
            self.LEGACY_ARCHIVE_INDEX,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))

    def test_over_limit_rejects_before_row_validation_or_accounting(self):
        snapshots = self.snapshots()
        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "legacy_archive", (object(), object())
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.LEGACY_ARCHIVE_INDEX),
            (host.ImageViolation(
                "TABLE_ROW_LIMIT", "table_snapshots", "/5/rows"
            ),),
        )

    def test_supplied_label_cannot_select_or_bypass_the_positional_cap(self):
        snapshots = self.snapshots()
        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "attempts", (object(), object())
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.LEGACY_ARCHIVE_INDEX),
            (
                host.ImageViolation(
                    "TABLE_INVENTORY", "table_snapshots", "/5/table"
                ),
                host.ImageViolation(
                    "TABLE_ROW_LIMIT", "table_snapshots", "/5/rows"
                ),
            ),
        )

        snapshots = self.snapshots()
        snapshots[0] = host.TableSnapshot(
            "legacy_archive", (object(), object())
        )
        findings = self.table_findings(
            host.inspect_runtime_image_host(self.image(tuple(snapshots))), 0
        )
        self.assertIn(
            host.ImageViolation(
                "TABLE_INVENTORY", "table_snapshots", "/0/table"
            ),
            findings,
        )
        self.assertFalse(any(item.code == "TABLE_ROW_LIMIT" for item in findings))

    def test_missing_and_non_tuple_rows_skip_len(self):
        missing = object.__new__(host.TableSnapshot)
        object.__setattr__(missing, "table", "legacy_archive")
        snapshots = self.snapshots()
        snapshots[self.LEGACY_ARCHIVE_INDEX] = missing
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.LEGACY_ARCHIVE_INDEX),
            (host.ImageViolation(
                "TABLE_SNAPSHOT_FIELD_MISSING", "table_snapshots", "/5/rows"
            ),),
        )

        snapshots = self.snapshots()
        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "legacy_archive", _ExplosiveLength()
        )
        report = host.inspect_runtime_image_host(self.image(tuple(snapshots)))
        self.assertEqual(
            self.table_findings(report, self.LEGACY_ARCHIVE_INDEX),
            (host.ImageViolation(
                "TABLE_ROWS_TYPE", "table_snapshots", "/5/rows"
            ),),
        )

    def test_outer_cardinality_gate_precedes_positional_zip(self):
        snapshots = self.snapshots()[:-1]
        snapshots[self.LEGACY_ARCHIVE_INDEX] = host.TableSnapshot(
            "legacy_archive", (object(), object())
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


if __name__ == "__main__":
    unittest.main()
