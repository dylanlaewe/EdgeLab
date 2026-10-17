"""Adversarial tests for the compiled dependency-closure shape validator."""
import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from src.edgelab.runtime_v2_closure import (
    CLOSURE_SHAPE_VALIDATION_PROFILE,
    MAX_DEPENDENCY_CLOSURE_BYTES,
    ClosureValidationError,
    validate_verifier_dependency_closure,
)
from src.edgelab.runtime_v2_codec import (
    canonical_json,
    verifier_dependency_closure_digest,
)
from tests.runtime_v2_closure_fixture import closure_fixture


ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    value["verifier_dependency_closure_sha256"] = "0" * 64
    value["verifier_dependency_closure_sha256"] = (
        verifier_dependency_closure_digest(value)
    )
    return canonical_json(value)


class RuntimeV2ClosureTests(unittest.TestCase):
    def assert_denied(self, raw, code=None):
        with self.assertRaises(ClosureValidationError) as caught:
            validate_verifier_dependency_closure(raw)
        if code is not None:
            self.assertEqual(caught.exception.code, code)

    def test_shape_valid_self_consistent_candidate_is_parsed_but_not_identity_approved(self):
        value = closure_fixture()
        parsed = validate_verifier_dependency_closure(canonical_json(value))
        self.assertEqual(parsed, value)
        self.assertIsNot(parsed, value)
        self.assertEqual(
            CLOSURE_SHAPE_VALIDATION_PROFILE,
            "EDGELAB_RUNTIME_V2_DEPENDENCY_CLOSURE_SHAPE_STRICT_V1",
        )

    def test_strict_positive_fixture_is_also_valid_under_pinned_json_schema(self):
        import json

        schema = json.loads((
            ROOT / "schemas" / "m0-3a-verifier-dependency-closure.v1.schema.json"
        ).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(closure_fixture())),
            [],
        )

    def test_transport_size_canonical_bytes_and_self_digest_fail_closed(self):
        valid = canonical_json(closure_fixture())
        for raw in (None, bytearray(valid), memoryview(valid), valid.decode("ascii")):
            with self.subTest(raw_type=type(raw)):
                self.assert_denied(raw, "BYTES_REQUIRED")
        self.assert_denied(b"0" * (MAX_DEPENDENCY_CLOSURE_BYTES + 1), "BYTE_LIMIT")
        self.assert_denied(valid + b"\n", "CANONICAL_JSON")
        mismatched = closure_fixture()
        mismatched["verifier_dependency_closure_sha256"] = "f" * 64
        self.assert_denied(
            canonical_json(mismatched), "CLOSURE_SELF_DIGEST_MISMATCH"
        )

        huge_integer = valid.replace(b'"maximum":128', b'"maximum":' + b"9" * 5_000)
        prior_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(0)
            self.assert_denied(huge_integer, "CANONICAL_JSON")
        finally:
            sys.set_int_max_str_digits(prior_limit)

    def test_every_top_level_key_is_required_and_unknown_keys_deny(self):
        baseline = closure_fixture()
        for key in tuple(baseline):
            mutation = copy.deepcopy(baseline)
            del mutation[key]
            with self.subTest(missing=key):
                self.assert_denied(canonical_json(mutation), "OBJECT_KEYS")
        extra = copy.deepcopy(baseline)
        extra["ambient_checkout"] = "forbidden"
        self.assert_denied(canonical_json(extra), "OBJECT_KEYS")

    def test_exact_types_constants_patterns_and_integer_aliases_deny(self):
        mutations = []
        for coordinate, mutate in (
            ("schema_bool", lambda value: value.__setitem__("schema_version", True)),
            ("closure_version", lambda value: value.__setitem__("closure_version", 2)),
            ("byte_bool", lambda value: value["local_artifacts"][0].__setitem__("byte_length", True)),
            ("limit_overflow", lambda value: value["resource_limits"][0].__setitem__("maximum", 2**63)),
            ("bad_sha", lambda value: value["generator_identity"].__setitem__("artifact_sha256", "A" * 64)),
            ("bad_path", lambda value: value["generator_identity"].__setitem__("artifact_path", "../generator.py")),
            ("empty_purpose", lambda value: value["standard_library_modules"][0].__setitem__("purpose", "")),
            ("wrong_boundary", lambda value: value["deny_only_boundary"].__setitem__("authorizing_use", "ALLOW")),
        ):
            mutation = copy.deepcopy(closure_fixture())
            mutate(mutation)
            mutations.append((coordinate, mutation))
        for name, mutation in mutations:
            with self.subTest(name=name):
                self.assert_denied(encoded(mutation))

    def test_local_artifact_order_roles_and_pin_elision_are_closed(self):
        mutations = []
        reordered = copy.deepcopy(closure_fixture())
        reordered["local_artifacts"].reverse()
        mutations.append(reordered)
        duplicate_entrypoint = copy.deepcopy(closure_fixture())
        duplicate_entrypoint["local_artifacts"].insert(1, {
            "path": "src/edgelab/other.py",
            "role": "ENTRYPOINT",
            "sha256": "a" * 64,
            "byte_length": 1,
            "pin_elision_applied": False,
        })
        mutations.append(duplicate_entrypoint)
        second_elision = copy.deepcopy(closure_fixture())
        second_elision["local_artifacts"][1]["pin_elision_applied"] = True
        mutations.append(second_elision)
        same_marker = copy.deepcopy(closure_fixture())
        same_marker["pin_elision_profile"]["end_marker"] = (
            same_marker["pin_elision_profile"]["begin_marker"]
        )
        mutations.append(same_marker)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_denied(encoded(mutation))

    def test_local_roots_and_paths_have_one_portable_owner(self):
        overlapping = copy.deepcopy(closure_fixture())
        overlapping["root_boundary"]["local_import_roots"] = [
            "src", "src/edgelab",
        ]
        self.assert_denied(encoded(overlapping), "LOCAL_IMPORT_ROOT_OVERLAP")

        outside = copy.deepcopy(closure_fixture())
        outside["local_artifacts"].append({
            "path": "zzz/module.py",
            "role": "LOCAL_MODULE",
            "sha256": "a" * 64,
            "byte_length": 1,
            "pin_elision_applied": False,
        })
        self.assert_denied(encoded(outside), "LOCAL_ARTIFACT_ROOT")

        trailing_dot = copy.deepcopy(closure_fixture())
        trailing_dot["generator_identity"]["artifact_path"] = "tools/build.py."
        self.assert_denied(encoded(trailing_dot), "PATH_PORTABILITY")

        windows_device = copy.deepcopy(closure_fixture())
        windows_device["generator_identity"]["artifact_path"] = "tools/CON.py"
        self.assert_denied(encoded(windows_device), "PATH_PORTABILITY")

        root_case_alias = copy.deepcopy(closure_fixture())
        root_case_alias["root_boundary"]["local_import_roots"] = [
            "SRC/EDGELAB", "src/edgelab",
        ]
        self.assert_denied(
            encoded(root_case_alias), "LOCAL_IMPORT_ROOT_CASE_COLLISION"
        )

        descendant_first = copy.deepcopy(closure_fixture())
        descendant_first["root_boundary"]["local_import_roots"] = [
            "SRC/edgelab/sub", "src/edgelab",
        ]
        self.assert_denied(
            encoded(descendant_first), "LOCAL_IMPORT_ROOT_OVERLAP"
        )

        prefix_interposer = copy.deepcopy(closure_fixture())
        prefix_interposer["root_boundary"]["local_import_roots"] = [
            "src/edgelab", "src/edgelab-foo", "src/edgelab/sub",
        ]
        self.assert_denied(
            encoded(prefix_interposer), "LOCAL_IMPORT_ROOT_OVERLAP"
        )

        file_roots = copy.deepcopy(closure_fixture())
        file_roots["root_boundary"]["local_import_roots"] = [
            item["path"] for item in file_roots["local_artifacts"]
        ]
        self.assert_denied(encoded(file_roots), "LOCAL_ARTIFACT_ROOT")

    def test_schema_role_id_path_order_and_global_path_namespaces_are_closed(self):
        mutations = []
        wrong_role = copy.deepcopy(closure_fixture())
        wrong_role["bootstrap_schemas"][0]["role"] = "ATTACHMENT"
        mutations.append(wrong_role)
        swapped_bootstrap_roles = copy.deepcopy(closure_fixture())
        swapped_bootstrap_roles["bootstrap_schemas"][0]["role"], (
            swapped_bootstrap_roles["bootstrap_schemas"][1]["role"]
        ) = (
            swapped_bootstrap_roles["bootstrap_schemas"][1]["role"],
            swapped_bootstrap_roles["bootstrap_schemas"][0]["role"],
        )
        self.assert_denied(
            encoded(swapped_bootstrap_roles), "BOOTSTRAP_ROLE_BINDING"
        )
        swapped_retained_roles = copy.deepcopy(closure_fixture())
        swapped_retained_roles["retained_schema_documents"][0]["content_role"], (
            swapped_retained_roles["retained_schema_documents"][1]["content_role"]
        ) = (
            swapped_retained_roles["retained_schema_documents"][1]["content_role"],
            swapped_retained_roles["retained_schema_documents"][0]["content_role"],
        )
        self.assert_denied(
            encoded(swapped_retained_roles), "RETAINED_ROLE_BINDING"
        )
        reordered = copy.deepcopy(closure_fixture())
        reordered["retained_schema_documents"][0:2] = reversed(
            reordered["retained_schema_documents"][0:2]
        )
        mutations.append(reordered)
        bootstrap_id_order = copy.deepcopy(closure_fixture())
        bootstrap_id_order["bootstrap_schemas"][0]["schema_id"] = (
            "urn:edgelab:zz:1"
        )
        bootstrap_id_order["bootstrap_schemas"][1]["schema_id"] = (
            "urn:edgelab:aa:1"
        )
        self.assert_denied(
            encoded(bootstrap_id_order), "BOOTSTRAP_SCHEMA_ID_INVENTORY"
        )
        retained_id_order = copy.deepcopy(closure_fixture())
        retained_id_order["retained_schema_documents"][0]["schema_id"] = (
            "urn:edgelab:zz:1"
        )
        retained_id_order["retained_schema_documents"][1]["schema_id"] = (
            "urn:edgelab:aa:1"
        )
        self.assert_denied(
            encoded(retained_id_order), "RETAINED_SCHEMA_ID_INVENTORY"
        )
        duplicate_id = copy.deepcopy(closure_fixture())
        duplicate_id["retained_schema_documents"][1]["schema_id"] = (
            duplicate_id["retained_schema_documents"][0]["schema_id"]
        )
        mutations.append(duplicate_id)
        reused_path = copy.deepcopy(closure_fixture())
        reused_path["content_assets"]["schema_registry"]["path"] = (
            reused_path["content_assets"]["storage_descriptor"]["path"]
        )
        mutations.append(reused_path)
        case_collision = copy.deepcopy(closure_fixture())
        case_collision["content_assets"]["schema_registry"]["path"] = (
            "SCHEMAS/M0-3A-RUNTIME-STORAGE.V2.JSON"
        )
        mutations.append(case_collision)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_denied(encoded(mutation))

    def test_named_inventories_are_ordered_unique_and_namespace_separated(self):
        mutations = []
        duplicate_domain = copy.deepcopy(closure_fixture())
        duplicate_domain["digest_domains"][1]["domain"] = (
            duplicate_domain["digest_domains"][0]["domain"]
        )
        mutations.append(duplicate_domain)
        reversed_domains = copy.deepcopy(closure_fixture())
        reversed_domains["digest_domains"].reverse()
        self.assert_denied(encoded(reversed_domains), "INVENTORY_ORDER")
        reversed_limits = copy.deepcopy(closure_fixture())
        reversed_limits["resource_limits"].reverse()
        mutations.append(reversed_limits)
        reversed_assumptions = copy.deepcopy(closure_fixture())
        reversed_assumptions["tested_runtime_assumptions"].reverse()
        mutations.append(reversed_assumptions)
        reversed_stdlib = copy.deepcopy(closure_fixture())
        reversed_stdlib["standard_library_modules"].reverse()
        self.assert_denied(encoded(reversed_stdlib), "INVENTORY_ORDER")
        external_stdlib = copy.deepcopy(closure_fixture())
        external_stdlib["external_distributions"] = [{
            "distribution": "json-shadow",
            "version": "1",
            "import_modules": ["json"],
            "metadata_sha256": "a" * 64,
        }]
        mutations.append(external_stdlib)
        duplicate_external_module = copy.deepcopy(closure_fixture())
        duplicate_external_module["external_distributions"] = [
            {
                "distribution": "alpha",
                "version": "1",
                "import_modules": ["thirdparty"],
                "metadata_sha256": "a" * 64,
            },
            {
                "distribution": "beta",
                "version": "1",
                "import_modules": ["thirdparty"],
                "metadata_sha256": "b" * 64,
            },
        ]
        mutations.append(duplicate_external_module)
        normalized_distribution_alias = copy.deepcopy(closure_fixture())
        normalized_distribution_alias["external_distributions"] = [
            {
                "distribution": "foo-bar",
                "version": "1",
                "import_modules": ["foo_bar"],
                "metadata_sha256": "a" * 64,
            },
            {
                "distribution": "foo_bar",
                "version": "1",
                "import_modules": ["foo_alias"],
                "metadata_sha256": "b" * 64,
            },
        ]
        mutations.append(normalized_distribution_alias)
        external_order = copy.deepcopy(closure_fixture())
        external_order["external_distributions"] = [
            {
                "distribution": "beta",
                "version": "1",
                "import_modules": ["beta"],
                "metadata_sha256": "a" * 64,
            },
            {
                "distribution": "alpha",
                "version": "1",
                "import_modules": ["alpha"],
                "metadata_sha256": "b" * 64,
            },
        ]
        self.assert_denied(encoded(external_order), "INVENTORY_ORDER")
        import_module_order = copy.deepcopy(closure_fixture())
        import_module_order["external_distributions"] = [{
            "distribution": "third-party",
            "version": "1",
            "import_modules": ["zeta", "alpha"],
            "metadata_sha256": "a" * 64,
        }]
        self.assert_denied(
            encoded(import_module_order), "IMPORT_MODULE_INVENTORY"
        )
        stdlib_descendant = copy.deepcopy(closure_fixture())
        stdlib_descendant["external_distributions"] = [{
            "distribution": "json-extension",
            "version": "1",
            "import_modules": ["json.tool"],
            "metadata_sha256": "a" * 64,
        }]
        self.assert_denied(
            encoded(stdlib_descendant), "MODULE_NAMESPACE_REUSE"
        )
        external_prefix_alias = copy.deepcopy(closure_fixture())
        external_prefix_alias["external_distributions"] = [
            {
                "distribution": "alpha",
                "version": "1",
                "import_modules": ["foo"],
                "metadata_sha256": "a" * 64,
            },
            {
                "distribution": "beta",
                "version": "1",
                "import_modules": ["foo.bar"],
                "metadata_sha256": "b" * 64,
            },
        ]
        self.assert_denied(
            encoded(external_prefix_alias), "MODULE_NAMESPACE_REUSE"
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_denied(encoded(mutation))

        generator_path_reuse = copy.deepcopy(closure_fixture())
        generator_path_reuse["generator_identity"]["artifact_path"] = (
            "src/edgelab/runtime_v2_verifier.py"
        )
        self.assert_denied(encoded(generator_path_reuse), "PATH_REUSE")

    def test_nested_objects_are_closed(self):
        object_paths = (
            ("entrypoint",),
            ("root_boundary",),
            ("pin_elision_profile",),
            ("local_artifacts", 0),
            ("bootstrap_schemas", 0),
            ("retained_schema_documents", 0),
            ("content_assets", "storage_descriptor"),
            ("digest_domains", 0),
            ("resource_limits", 0),
            ("standard_library_modules", 0),
            ("tested_runtime_assumptions", 0),
            ("generator_identity",),
            ("deny_only_boundary",),
        )
        for path in object_paths:
            mutation = copy.deepcopy(closure_fixture())
            target = mutation
            for component in path:
                target = target[component]
            target["unexpected"] = True
            with self.subTest(path=path):
                self.assert_denied(canonical_json(mutation), "OBJECT_KEYS")

    def test_validator_is_no_io_no_authority_and_ambient_independent(self):
        source_path = ROOT / "src" / "edgelab" / "runtime_v2_closure.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(imported.isdisjoint({
            "os", "pathlib", "socket", "subprocess", "importlib", "urllib",
            "requests", "risk_controls", "orchestration", "transactional_scheduler",
        }))
        raw = canonical_json(closure_fixture())
        with patch("builtins.open", side_effect=AssertionError("I/O attempted")):
            self.assertEqual(validate_verifier_dependency_closure(raw), closure_fixture())

    def test_input_bytes_and_returned_value_do_not_alias(self):
        raw = canonical_json(closure_fixture())
        first = validate_verifier_dependency_closure(raw)
        first["local_artifacts"][0]["role"] = "LOCAL_MODULE"
        second = validate_verifier_dependency_closure(raw)
        self.assertEqual(second["local_artifacts"][0]["role"], "PIN_CARRIER")


if __name__ == "__main__":
    unittest.main()
