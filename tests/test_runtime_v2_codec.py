"""Independent vectors and adversarial checks for the pure format-2 codec."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_codec import (
    attachment_digest,
    CanonicalJsonError,
    blob_digest,
    canonical_json,
    checkpoint_digest,
    event_digest,
    export_digest,
    legacy_digest,
    manifest_digest,
    parse_canonical_json,
    remediation_link_digest,
    schema_document_digest,
    schema_registry_digest,
    selector_digest,
    selector_history_digest,
    sqlite_compile_options_digest,
    sqlite_structure_digest,
    storage_schema_digest,
    table_root,
    task_predecessor,
    verifier_dependency_closure_digest,
)


ROOT = Path(__file__).resolve().parents[1]


def independent(prefix, value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(prefix + encoded).hexdigest()


class RuntimeV2CodecTests(unittest.TestCase):
    def test_golden_canonical_vector(self):
        value = {
            "z": [None, True, False, -7, "é", "𝄞", "e\u0301"],
            "a": {"β": "line\nfeed", "quote": "\""},
        }
        expected = (
            b'{"a":{"quote":"\\\"","\\u03b2":"line\\nfeed"},'
            b'"z":[null,true,false,-7,"\\u00e9",'
            b'"\\ud834\\udd1e","e\\u0301"]}'
        )
        self.assertEqual(canonical_json(value), expected)
        self.assertEqual(parse_canonical_json(expected), value)

    def test_code_point_key_order_is_not_normalized(self):
        value = {"é": 1, "e\u0301": 2, "A": 3}
        self.assertEqual(
            canonical_json(value),
            b'{"A":3,"e\\u0301":2,"\\u00e9":1}',
        )

    def test_duplicate_keys_deny_at_any_depth(self):
        for raw in (
            b'{"a":1,"a":1}',
            b'{"outer":{"x":1,"x":2}}',
            b'[{"x":1,"x":2}]',
        ):
            with self.subTest(raw=raw), self.assertRaisesRegex(
                CanonicalJsonError, "DUPLICATE_KEY"
            ):
                parse_canonical_json(raw)

    def test_floats_nonfinite_negative_zero_and_aliases_deny(self):
        for raw in (
            b"1.0", b"1e0", b"-0.0", b"NaN", b"Infinity", b"-Infinity",
            b"-0", b"true ", b'{"a":1, "b":2}', b"\xef\xbb\xbfnull",
        ):
            with self.subTest(raw=raw), self.assertRaises(CanonicalJsonError):
                parse_canonical_json(raw)

    def test_huge_integer_conversion_failure_is_wrapped(self):
        with self.assertRaisesRegex(CanonicalJsonError, "INVALID_JSON"):
            parse_canonical_json(b"9" * 5000)

    def test_invalid_utf8_trailing_data_and_surrogates_deny(self):
        for raw in (b'"\x80"', b"{}{}", b'"\\ud800"', b'"\x01"'):
            with self.subTest(raw=raw), self.assertRaises(CanonicalJsonError):
                parse_canonical_json(raw)

    def test_non_json_host_types_and_cycles_deny(self):
        cycle = []
        cycle.append(cycle)
        for value in (1.0, (1,), {1: "x"}, b"x", cycle):
            with self.subTest(value=type(value)), self.assertRaises(
                CanonicalJsonError
            ):
                canonical_json(value)

    def test_excessive_nesting_denies_without_recursion_escape(self):
        value = None
        for _ in range(130):
            value = [value]
        with self.assertRaisesRegex(CanonicalJsonError, "MAX_DEPTH_EXCEEDED"):
            canonical_json(value)
        raw = b"[" * 130 + b"null" + b"]" * 130
        with self.assertRaises(CanonicalJsonError):
            parse_canonical_json(raw)

    def test_input_is_not_mutated(self):
        value = {"b": [2, 1], "a": {"x": True}}
        before = copy.deepcopy(value)
        canonical_json(value)
        self.assertEqual(value, before)

    def test_domain_digests_match_independent_vectors(self):
        value = {"a": 1}
        self.assertEqual(
            blob_digest(value), independent(b"EDGELAB\0BLOB\0V2\0", value)
        )
        self.assertEqual(
            manifest_digest(value),
            independent(b"EDGELAB\0MANIFEST\0V2\0", value),
        )
        self.assertEqual(
            schema_registry_digest(value),
            independent(b"EDGELAB\0SCHEMA_REGISTRY\0V2\0", value),
        )
        self.assertEqual(
            schema_document_digest(value),
            independent(b"EDGELAB\0SCHEMA_DOCUMENT\0V2\0", value),
        )
        self.assertEqual(
            selector_history_digest([value]),
            independent(b"EDGELAB\0SELECTOR_HISTORY\0V1\0", [value]),
        )
        self.assertEqual(
            sqlite_structure_digest(value),
            independent(b"EDGELAB\0SQLITE_STRUCTURE\0V2\0", value),
        )
        self.assertEqual(
            sqlite_compile_options_digest(["A", "B"]),
            independent(
                b"EDGELAB\0SQLITE_COMPILE_OPTIONS\0V2\0", ["A", "B"]
            ),
        )

    def test_self_digest_fields_are_excluded_exactly(self):
        event = {"event_id": "e", "event_sha256": "x"}
        checkpoint = {"checkpoint_sequence": 0, "checkpoint_sha256": "x"}
        export = {"export_sequence": 0, "export_sha256": "x"}
        link = {"link_id": "l", "link_sha256": "x"}
        selector = {"selector_generation": 0, "selector_sha256": "x"}
        self.assertEqual(
            event_digest(event),
            independent(b"EDGELAB\0EVENT\0V2\0", {"event_id": "e"}),
        )
        self.assertEqual(
            checkpoint_digest(checkpoint),
            independent(
                b"EDGELAB\0CHECKPOINT\0V2\0", {"checkpoint_sequence": 0}
            ),
        )
        self.assertEqual(
            export_digest(export),
            independent(b"EDGELAB\0EXPORT\0V2\0", {"export_sequence": 0}),
        )
        self.assertEqual(
            remediation_link_digest(link),
            independent(b"EDGELAB\0REMEDIATION_LINK\0V2\0", {"link_id": "l"}),
        )
        self.assertEqual(
            selector_digest(selector),
            independent(
                b"EDGELAB\0SELECTOR\0V1\0", {"selector_generation": 0}
            ),
        )
        for function, value in (
            (event_digest, {}), (checkpoint_digest, {}), (export_digest, {}),
            (remediation_link_digest, {}), (selector_digest, {})
        ):
            with self.assertRaises(CanonicalJsonError):
                function(value)

    def test_attachment_digest_has_its_own_domain(self):
        attachment = {"runtime_id": "r"}
        self.assertEqual(
            attachment_digest(attachment),
            independent(b"EDGELAB\0ATTACHMENT\0V2\0", attachment),
        )

    def test_storage_schema_hashes_canonical_descriptor(self):
        descriptor = {"runtime_format_version": 2}
        self.assertEqual(
            storage_schema_digest(descriptor),
            hashlib.sha256(
                b"EDGELAB\0STORAGE_SCHEMA\0V2\0"
                b'{"runtime_format_version":2}'
            ).hexdigest(),
        )

    def test_verifier_dependency_closure_known_answer(self):
        record = {
            "closure_id": "urn:edgelab:m0-3a-verifier-dependency-closure:1",
            "closure_version": 1,
            "runtime_format_version": 2,
            "verifier_dependency_closure_sha256": "ignored",
        }
        self.assertEqual(
            verifier_dependency_closure_digest(record),
            "af1cea71af08443dbaba131fc709d94414d4e6eca5f0da481de0bf3baf1db300",
        )

    def test_verifier_dependency_closure_digest_mutation_and_self_field(self):
        record = {
            "closure_id": "urn:edgelab:m0-3a-verifier-dependency-closure:1",
            "closure_version": 1,
            "verifier_dependency_closure_sha256": "a" * 64,
        }
        expected = verifier_dependency_closure_digest(record)
        self.assertEqual(
            verifier_dependency_closure_digest({
                **record,
                "verifier_dependency_closure_sha256": "b" * 64,
            }),
            expected,
        )
        self.assertNotEqual(
            verifier_dependency_closure_digest({**record, "closure_version": 2}),
            expected,
        )

    def test_verifier_dependency_closure_digest_field_is_required(self):
        for record in ({"closure_id": "closure"}, [], None):
            with self.subTest(record=record), self.assertRaisesRegex(
                CanonicalJsonError,
                "VERIFIER_DEPENDENCY_CLOSURE_DIGEST_FIELD_REQUIRED",
            ):
                verifier_dependency_closure_digest(record)

    def test_dependency_closure_schema_is_closed_and_enforces_root_roles(self):
        schema = json.loads((
            ROOT / "schemas" /
            "m0-3a-verifier-dependency-closure.v1.schema.json"
        ).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        sha = "a" * 64
        bootstrap_roles = (
            "ATTACHMENT", "RUNTIME_MANIFEST", "ACTIVE_RUNTIME_SELECTOR",
            "SCHEMA_REGISTRY_SCHEMA", "STORAGE_DESCRIPTOR_SCHEMA",
        )
        retained_roles = (
            "EVENT_ENVELOPE", "PAYLOAD", "TASK_STATE", "REQUEST",
            "RESPONSE_PROJECTION", "CHECKPOINT_DOCUMENT", "EXPORT_DOCUMENT",
            "LEGACY_ROW_ARCHIVE", "LEGACY_PROJECTION",
        )
        record = {
            "schema_version": 1,
            "closure_id": "urn:edgelab:m0-3a-verifier-dependency-closure:1",
            "closure_version": 1,
            "runtime_format_version": 2,
            "canonicalization": "EDGELAB_CANONICAL_JSON_V1",
            "digest_algorithm": "SHA-256",
            "digest_domain": "EDGELAB\0VERIFIER_DEPENDENCY_CLOSURE\0V2\0",
            "entrypoint": {
                "artifact_path": "src/edgelab/runtime_v2_verifier.py",
                "module": "edgelab.runtime_v2_verifier",
                "callable": "verify_runtime_image",
            },
            "root_boundary": {
                "repository_relative": True,
                "local_import_roots": ["src/edgelab"],
                "filesystem_reads": "DENY",
                "network_access": "DENY",
                "environment_access": "DENY",
                "dynamic_imports": "DENY",
            },
            "pin_elision_profile": {
                "profile_id": "PIN_BLOCK_ELIDED_V1",
                "artifact_path": "src/edgelab/_runtime_v2_release.py",
                "begin_marker": "# BEGIN GENERATED PIN BLOCK",
                "end_marker": "# END GENERATED PIN BLOCK",
                "replacement_literal": "PIN_BLOCK_ELIDED_V1",
                "required_match_count": 1,
            },
            "local_artifacts": [
                {
                    "path": "src/edgelab/runtime_v2_verifier.py",
                    "role": "ENTRYPOINT",
                    "sha256": sha,
                    "byte_length": 1,
                    "pin_elision_applied": False,
                },
                {
                    "path": "src/edgelab/_runtime_v2_release.py",
                    "role": "PIN_CARRIER",
                    "sha256": sha,
                    "byte_length": 1,
                    "pin_elision_applied": True,
                },
            ],
            "bootstrap_schemas": [
                {
                    "role": role,
                    "schema_id": f"urn:edgelab:bootstrap-{index}:1",
                    "path": f"schemas/bootstrap-{index}.json",
                    "raw_sha256": sha,
                    "schema_document_sha256": sha,
                    "byte_length": index + 1,
                }
                for index, role in enumerate(bootstrap_roles)
            ],
            "retained_schema_documents": [
                {
                    "content_role": role,
                    "schema_id": f"urn:edgelab:retained-{index}:2",
                    "path": f"schemas/retained-{index}.json",
                    "raw_sha256": sha,
                    "document_sha256": sha,
                    "byte_length": index + 1,
                }
                for index, role in enumerate(retained_roles)
            ],
            "content_assets": {
                name: {
                    "path": f"schemas/{name}.json",
                    "raw_sha256": sha,
                    "domain_sha256": sha,
                    "byte_length": 1,
                }
                for name in ("storage_descriptor", "schema_registry")
            },
            "digest_domains": [{
                "name": "blob",
                "domain": "EDGELAB\0BLOB\0V2\0",
            }],
            "resource_limits": [{
                "name": "TOTAL_INPUT_BYTES", "maximum": 1, "unit": "BYTES",
            }],
            "standard_library_modules": [{
                "module": "hashlib", "purpose": "SHA-256",
            }],
            "external_distributions": [],
            "tested_runtime_assumptions": [{
                "name": "PYTHON_VERSION", "expected": "3.13.4",
            }],
            "generator_identity": {
                "artifact_path": "tools/build_runtime_v2_release.py",
                "artifact_sha256": sha,
                "generator_version": 1,
                "invocation": "build_runtime_v2_release.py --check",
            },
            "deny_only_boundary": {
                "positive_status": "LOCALLY_CONSISTENT_DENY_ONLY",
                "anchor_status": "UNANCHORED",
                "currentness_status": "UNKNOWN",
                "authorizing_use": "DENY",
                "live_execution": "PROHIBITED",
            },
            "verifier_dependency_closure_sha256": sha,
        }
        self.assertEqual(list(validator.iter_errors(record)), [])

        mutations = []
        extra = copy.deepcopy(record)
        extra["unexpected"] = True
        mutations.append(extra)
        missing_role = copy.deepcopy(record)
        missing_role["bootstrap_schemas"][0]["role"] = "RUNTIME_MANIFEST"
        mutations.append(missing_role)
        dot_alias = copy.deepcopy(record)
        dot_alias["local_artifacts"].append({
            "path": "src/./alias.py",
            "role": "LOCAL_MODULE",
            "sha256": sha,
            "byte_length": 1,
            "pin_elision_applied": False,
        })
        mutations.append(dot_alias)
        wrong_carrier = copy.deepcopy(record)
        wrong_carrier["local_artifacts"][1]["path"] = "src/edgelab/other.py"
        mutations.append(wrong_carrier)
        wrong_elision = copy.deepcopy(record)
        wrong_elision["pin_elision_profile"]["replacement_literal"] = "wildcard"
        mutations.append(wrong_elision)
        second_elision = copy.deepcopy(record)
        second_elision["local_artifacts"][0]["pin_elision_applied"] = True
        mutations.append(second_elision)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(mutation)))

    def test_table_root_binds_name_and_order(self):
        rows = [[1, "a"], [2, "b"]]
        expected = hashlib.sha256(
            b"EDGELAB\0TABLE\0V2\0events\0" + canonical_json(rows)
        ).hexdigest()
        self.assertEqual(table_root("events", rows), expected)
        self.assertNotEqual(table_root("events", list(reversed(rows))), expected)
        self.assertNotEqual(table_root("tasks", rows), expected)
        for name in ("", "bad\0name", True):
            with self.assertRaises(CanonicalJsonError):
                table_root(name, rows)

    def test_task_predecessor_exact_vector_and_strict_attempt(self):
        event_id, digest = task_predecessor("a" * 64, "T", 1)
        self.assertEqual(
            digest,
            "25ca6ef44038ccbafdd34705ab241d2bdaf13f03e94f21e09c75e4f33b5c1036",
        )
        self.assertEqual(event_id, f"FORMAT2_TASK_PREDECESSOR:{digest}")
        for attempt in (True, 0, 9223372036854775808):
            with self.assertRaises(CanonicalJsonError):
                task_predecessor("a" * 64, "T", attempt)

    def test_legacy_domains_are_distinct_and_closed(self):
        value = [["x"]]
        projection = {"projection_sha256": "ignored", "tables": value}
        values = {
            legacy_digest("archive", value),
            legacy_digest("projection", projection),
            legacy_digest("storage", value),
            legacy_digest("columns", value, "meta"),
            legacy_digest("rows", value, "meta"),
        }
        self.assertEqual(len(values), 5)
        self.assertEqual(
            legacy_digest("projection", projection),
            independent(
                b"EDGELAB\0LEGACY_PROJECTION\0V1\0", {"tables": value}
            ),
        )
        with self.assertRaisesRegex(
            CanonicalJsonError, "PROJECTION_DIGEST_FIELD_REQUIRED"
        ):
            legacy_digest("projection", {"tables": value})
        with self.assertRaises(CanonicalJsonError):
            legacy_digest("unknown", value)


if __name__ == "__main__":
    unittest.main()
