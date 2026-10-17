"""Independent vectors and adversarial checks for the pure format-2 codec."""
import copy
import hashlib
import json
import unittest

from src.edgelab.runtime_v2_codec import (
    CanonicalJsonError,
    blob_digest,
    canonical_json,
    checkpoint_digest,
    event_digest,
    legacy_digest,
    manifest_digest,
    parse_canonical_json,
    schema_document_digest,
    schema_registry_digest,
    selector_digest,
    selector_history_digest,
    sqlite_compile_options_digest,
    sqlite_structure_digest,
    storage_schema_digest,
    table_root,
    task_predecessor,
)


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
            selector_digest(selector),
            independent(
                b"EDGELAB\0SELECTOR\0V1\0", {"selector_generation": 0}
            ),
        )
        for function, value in (
            (event_digest, {}), (checkpoint_digest, {}), (selector_digest, {})
        ):
            with self.assertRaises(CanonicalJsonError):
                function(value)

    def test_storage_schema_hashes_canonical_descriptor(self):
        descriptor = {"runtime_format_version": 2}
        self.assertEqual(
            storage_schema_digest(descriptor),
            hashlib.sha256(
                b"EDGELAB\0STORAGE_SCHEMA\0V2\0"
                b'{"runtime_format_version":2}'
            ).hexdigest(),
        )

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
