"""Focused tests for the pure runtime-v2 bootstrap schema validators."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_bootstrap import (
    ACTIVE_RUNTIME_SELECTOR_SCHEMA_SHA256,
    BOOTSTRAP_VALIDATION_PROFILE,
    BootstrapValidationError,
    RUNTIME_ATTACHMENT_SCHEMA_SHA256,
    RUNTIME_MANIFEST_SCHEMA_SHA256,
    validate_attachment,
    validate_manifest,
    validate_selector,
)
from src.edgelab.runtime_v2_codec import canonical_json, parse_canonical_json


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
UUID = "123e4567-e89b-42d3-a456-426614174000"
UUID2 = "123e4567-e89b-42d3-a456-426614174001"


def parsed(value):
    """Load positive fixtures as JSON only in the test boundary."""
    return json.loads(json.dumps(value))


def attachment_fixture():
    return parsed({
        "attachment_schema_version": 2,
        "runtime_format_version": 2,
        "runtime_id": UUID,
        "chain_id": DIGEST,
        "canonical_project_id": "EdgeLab",
        "repository_root_realpath": "/repo",
        "expected_remote": "https://github.com/dylanlaewe/EdgeLab.git",
        "git_common_dir_identity": "/repo/.git",
        "repository_marker_sha256": DIGEST,
        "checkout_nonce": DIGEST,
        "created_at": "2026-10-16T00:00:00Z",
        "anchor_status": "UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
    })


def bridge_fixture():
    return {
        "source_runtime_format_version": 1,
        "source_assurance": "V16_BOUNDED_REPLAY_ONLY",
        "source_runtime_id": "legacy-runtime",
        "source_attachment_sha256": DIGEST,
        "source_storage_inventory_sha256": DIGEST,
        "source_backup_sha256": DIGEST,
        "source_global_head_id": "legacy-head",
        "source_global_head_sha256": DIGEST,
        "source_row_archive_sha256": DIGEST,
        "source_projection_sha256": DIGEST,
        "migration_plan_sha256": DIGEST,
        "frozen_verifier_commit": "a" * 40,
        "frozen_verifier_closure_sha256": DIGEST,
        "source_repository_bundle_sha256": DIGEST,
    }


def manifest_fixture(*, migrated=False):
    return parsed({
        "schema_version": 1,
        "runtime_format_version": 2,
        "event_format_version": 2,
        "runtime_id": UUID,
        "chain_id": DIGEST,
        "canonicalization": "EDGELAB_CANONICAL_JSON_V1",
        "digest_algorithm": "SHA-256",
        "sqlite_application_id": 1162102578,
        "sqlite_user_version": 2,
        "storage_schema_sha256": DIGEST,
        "schema_registry_sha256": DIGEST,
        "genesis_event_id": UUID2,
        "genesis_event_sha256": DIGEST,
        "attachment_sha256": DIGEST,
        "source_kind": "V1_MIGRATION" if migrated else "NEW",
        "legacy_bridge": bridge_fixture() if migrated else None,
        "authority_binding": None,
        "anchor_status": "UNANCHORED",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "created_at": "2026-10-16T00:00:00Z",
    })


def selector_fixture(generation=0):
    v2 = generation > 0
    return parsed({
        "schema_version": 1,
        "selector_format_version": 1,
        "selector_generation": generation,
        "active_runtime_format_version": 2 if v2 else 1,
        "active_runtime_id": UUID if v2 else "runtime-1",
        "active_database_path": "runtime.v2.sqlite" if v2 else "runtime.sqlite",
        "active_attachment_path": "attachment.v2.json" if v2 else "attachment.json",
        "active_manifest_path": "runtime.v2.manifest.json" if v2 else None,
        "active_manifest_sha256": DIGEST if v2 else None,
        "latest_v2_checkpoint_sha256": DIGEST if generation >= 2 else None,
        "selector_history_path": f"selectors/{generation:020d}.json",
        "prior_selector_path": (
            f"selectors/{generation - 1:020d}.json" if v2 else None
        ),
        "prior_selector_sha256": DIGEST if v2 else None,
        "cutover_state": "V2_ACTIVE" if v2 else "V1_ACTIVE",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "written_at": "2026-10-16T00:00:00Z",
        "selector_sha256": DIGEST,
    })


class RuntimeV2BootstrapTests(unittest.TestCase):
    def assert_invalid(self, validator, value):
        with self.assertRaises(BootstrapValidationError):
            validator(value)

    def test_positive_parsed_fixtures_validate_without_a_result(self):
        cases = (
            (validate_attachment, attachment_fixture()),
            (validate_manifest, manifest_fixture()),
            (validate_manifest, manifest_fixture(migrated=True)),
            (validate_selector, selector_fixture(0)),
            (validate_selector, selector_fixture(1)),
            (validate_selector, selector_fixture(2)),
        )
        for validator, value in cases:
            with self.subTest(validator=validator.__name__, value=value):
                self.assertIsNone(validator(value))

    def test_raw_schema_byte_pins_reproduce_exactly(self):
        expected = {
            "m0-3a-runtime-attachment.v2.schema.json":
                RUNTIME_ATTACHMENT_SCHEMA_SHA256,
            "m0-3a-runtime-manifest.v2.schema.json":
                RUNTIME_MANIFEST_SCHEMA_SHA256,
            "m0-3a-active-runtime-selector.v2.schema.json":
                ACTIVE_RUNTIME_SELECTOR_SCHEMA_SHA256,
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                raw = (ROOT / "schemas" / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_strict_profile_is_explicit_and_composes_after_canonical_parse(self):
        self.assertEqual(
            BOOTSTRAP_VALIDATION_PROFILE,
            "EDGELAB_RUNTIME_V2_BOOTSTRAP_STRICT_V1",
        )
        for validator, value in (
            (validate_attachment, attachment_fixture()),
            (validate_manifest, manifest_fixture()),
            (validate_selector, selector_fixture()),
        ):
            parsed_value = parse_canonical_json(canonical_json(value))
            with self.subTest(validator=validator.__name__):
                self.assertIsNone(validator(parsed_value))

    def test_strict_profile_closes_schema_pattern_and_format_aliases(self):
        schema = json.loads((
            ROOT / "schemas" / "m0-3a-runtime-attachment.v2.schema.json"
        ).read_text(encoding="utf-8"))
        draft_without_format_assertion = Draft202012Validator(schema)

        trailing_newline = attachment_fixture()
        trailing_newline["chain_id"] = DIGEST + "\n"
        self.assertEqual(
            list(draft_without_format_assertion.iter_errors(trailing_newline)),
            [],
            "documents why the closed profile uses whole-string patterns",
        )
        self.assert_invalid(validate_attachment, trailing_newline)

        impossible_calendar = attachment_fixture()
        impossible_calendar["created_at"] = "2026-02-30T00:00:00Z"
        self.assertEqual(
            list(draft_without_format_assertion.iter_errors(impossible_calendar)),
            [],
            "documents why the closed profile asserts Gregorian UTC seconds",
        )
        self.assert_invalid(validate_attachment, impossible_calendar)

    def test_attachment_closed_keys_constants_patterns_and_lengths(self):
        mutations = []
        for operation in (
            lambda value: value.update(extra=True),
            lambda value: value.pop("chain_id"),
            lambda value: value.update(runtime_id="not-a-uuid"),
            lambda value: value.update(repository_marker_sha256="A" * 64),
            lambda value: value.update(canonical_project_id="Other"),
            lambda value: value.update(repository_root_realpath=""),
            lambda value: value.update(git_common_dir_identity="x" * 4097),
            lambda value: value.update(authorizing_use="ALLOW"),
        ):
            value = attachment_fixture()
            operation(value)
            mutations.append(value)
        for value in mutations:
            with self.subTest(value=value):
                self.assert_invalid(validate_attachment, value)

    def test_manifest_bridge_is_exactly_conditional_and_closed(self):
        new_with_bridge = manifest_fixture()
        new_with_bridge["legacy_bridge"] = bridge_fixture()
        migrated_without_bridge = manifest_fixture(migrated=True)
        migrated_without_bridge["legacy_bridge"] = None
        bridge_extra = manifest_fixture(migrated=True)
        bridge_extra["legacy_bridge"]["extra"] = "x"
        bridge_bad_commit = manifest_fixture(migrated=True)
        bridge_bad_commit["legacy_bridge"]["frozen_verifier_commit"] = "a" * 39
        wrong_authority = manifest_fixture()
        wrong_authority["authority_binding"] = {}
        wrong_version = manifest_fixture()
        wrong_version["event_format_version"] = 3
        for value in (
            new_with_bridge, migrated_without_bridge, bridge_extra,
            bridge_bad_commit, wrong_authority, wrong_version,
        ):
            with self.subTest(value=value):
                self.assert_invalid(validate_manifest, value)

    def test_selector_ranges_patterns_and_conditionals_are_closed(self):
        mutations = []
        for generation, operation in (
            (0, lambda value: value.update(selector_generation=-1)),
            (0, lambda value: value.update(selector_generation=2 ** 63)),
            (0, lambda value: value.update(
                selector_history_path="selectors/00000000000000000001.json")),
            (0, lambda value: value.update(active_runtime_format_version=2)),
            (1, lambda value: value.update(active_runtime_format_version=1)),
            (1, lambda value: value.update(active_runtime_id="runtime-1")),
            (1, lambda value: value.update(prior_selector_path=None)),
            (1, lambda value: value.update(latest_v2_checkpoint_sha256=DIGEST)),
            (2, lambda value: value.update(latest_v2_checkpoint_sha256=None)),
            (2, lambda value: value.update(active_database_path="runtime.sqlite")),
            (2, lambda value: value.update(cutover_state="V1_ACTIVE")),
        ):
            value = selector_fixture(generation)
            operation(value)
            mutations.append(value)
        for value in mutations:
            with self.subTest(value=value):
                self.assert_invalid(validate_selector, value)

    def test_real_gregorian_utc_second_validation(self):
        valid = manifest_fixture()
        valid["created_at"] = "2000-02-29T23:59:59Z"
        self.assertIsNone(validate_manifest(valid))
        for timestamp in (
            "0000-01-01T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-02-30T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00.000Z",
        ):
            for validator, fixture, field in (
                (validate_attachment, attachment_fixture, "created_at"),
                (validate_manifest, manifest_fixture, "created_at"),
                (validate_selector, selector_fixture, "written_at"),
            ):
                value = fixture()
                value[field] = timestamp
                with self.subTest(timestamp=timestamp, validator=validator.__name__):
                    self.assert_invalid(validator, value)

    def test_boolean_integer_aliases_and_nonexact_json_types_reject(self):
        cases = []
        attachment = attachment_fixture()
        attachment["attachment_schema_version"] = True
        cases.append((validate_attachment, attachment))
        manifest = manifest_fixture()
        manifest["schema_version"] = True
        cases.append((validate_manifest, manifest))
        selector = selector_fixture()
        selector["selector_generation"] = False
        cases.append((validate_selector, selector))
        selector = selector_fixture(1)
        selector["active_runtime_format_version"] = True
        cases.append((validate_selector, selector))

        class IntegerAlias(int):
            pass

        selector = selector_fixture()
        selector["selector_generation"] = IntegerAlias(0)
        cases.append((validate_selector, selector))
        for validator, value in cases:
            with self.subTest(validator=validator.__name__, value=value):
                self.assert_invalid(validator, value)

    def test_non_objects_and_non_string_keys_reject(self):
        for validator in (validate_attachment, validate_manifest, validate_selector):
            for value in (None, [], {1: "not-json-object-key"}):
                with self.subTest(validator=validator.__name__, value=value):
                    self.assert_invalid(validator, value)

    def test_hostile_objects_are_rejected_without_callbacks(self):
        class Hostile:
            def __len__(self):
                raise AssertionError("callback invoked")

            def __eq__(self, other):
                raise AssertionError("callback invoked")

            def __str__(self):
                raise AssertionError("callback invoked")

        class HostileMapping(dict):
            def keys(self):
                raise AssertionError("callback invoked")

        self.assert_invalid(validate_attachment, HostileMapping())
        value = attachment_fixture()
        value["chain_id"] = Hostile()
        self.assert_invalid(validate_attachment, value)

    def test_module_has_no_direct_io_schema_engine_or_runtime_state_imports(self):
        path = ROOT / "src" / "edgelab" / "runtime_v2_bootstrap.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        self.assertEqual(imported, {"__future__", "re", "typing"})
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(calls.isdisjoint({
            "open", "exec", "eval", "compile", "getenv", "__import__",
        }))
        for forbidden in (
            "jsonschema", "pathlib", "sqlite3", "subprocess", "socket",
            "urllib", "requests", "runtime_v2_verifier", "risk_controls",
            "locked_authority", "transactional_scheduler",
        ):
            self.assertNotIn(forbidden, imported)
        self.assertNotIn("runtime_v2_bootstrap", (
            ROOT / "src" / "edgelab" / "runtime_v2_verifier.py"
        ).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
