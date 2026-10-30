"""Adversarial tests for the offline release-readiness audit."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import tools.check_runtime_v2_release_readiness as readiness_checker
from tools.check_runtime_v2_release_readiness import (
    BOOTSTRAP_SCHEMAS,
    BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE,
    BLOB_CARDINALITY_RESOURCE_EVIDENCE,
    BLOB_RESOURCE_EVIDENCE,
    CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE,
    CLOSURE_SCHEMA,
    CONTENT_ASSETS,
    EVENT_BYTE_RESOURCE_EVIDENCE,
    LEGACY_ARCHIVE_TABLE_ROW_RESOURCE_EVIDENCE,
    METADATA_TABLE_ROW_RESOURCE_EVIDENCE,
    MIGRATIONS_TABLE_ROW_RESOURCE_EVIDENCE,
    PIN_BEGIN_MARKER,
    PIN_END_MARKER,
    PIN_REPLACEMENT,
    PORTABLE_COMPONENT_RESOURCE_EVIDENCE,
    PORTABLE_PATH_RESOURCE_EVIDENCE,
    RESOURCE_CLASSIFICATION_DOMAIN,
    RESOURCE_CLASSIFICATION_ANCESTORS,
    RESOURCE_CLASSIFICATION_EVIDENCE,
    RESOURCE_CLASSIFICATION_MANIFEST,
    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
    RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA,
    RESOURCE_CLASSIFICATION_SCHEMA,
    RESOURCE_DISCOVERY_DOMAIN,
    RESOURCE_DISCOVERY_MANIFEST,
    RESOURCE_DISCOVERY_SCHEMA,
    RESOURCE_DISCOVERY_V2_ID,
    RESOURCE_DISCOVERY_V3_ID,
    RESOURCE_DISCOVERY_V4_ID,
    RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN,
    RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN,
    RESOURCE_SOURCE_BOUND_SITES_V3_SHA256,
    RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
    RESOURCE_SOURCE_BOUND_SITES_V4_SHA256,
    RESOURCE_SOURCE_INPUT_DOMAIN,
    RETAINED_SCHEMAS,
    SCHEMA_REF_NODE_RESOURCE_EVIDENCE,
    SCHEMA_BUNDLE_RESOURCE_EVIDENCE,
    SCHEMA_REGISTRY_RESOURCE_EVIDENCE,
    TRANSITION_ARGUMENT_RESOURCE_EVIDENCE,
    TRANSITION_SEMANTIC_EVENT_RESOURCE_EVIDENCE,
    TRANSITION_TASK_RESOURCE_EVIDENCE,
    ReadinessError,
    _domain_digest,
    _source_bound_cardinality_binding_inventory,
    _source_bound_table_row_cap_binding_inventory,
    _source_bound_inventory,
    _source_bound_binding_inventory,
    _source_inventory,
    build_report,
    elide_pin_block,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeV2ReleaseReadinessTests(unittest.TestCase):
    def copy_inputs(self) -> Path:
        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary)
        shutil.copytree(ROOT / "src", temporary / "src")
        (temporary / "schemas").mkdir()
        paths = {
            path for _, _, path in BOOTSTRAP_SCHEMAS + RETAINED_SCHEMAS
        } | {path for _, _, path in CONTENT_ASSETS} | {
            CLOSURE_SCHEMA[1], RESOURCE_CLASSIFICATION_SCHEMA[1],
            RESOURCE_CLASSIFICATION_MANIFEST[1],
            RESOURCE_DISCOVERY_SCHEMA[1], RESOURCE_DISCOVERY_MANIFEST[1],
            "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v2.json",
            "schemas/m0-3a-runtime-v2-resource-discovery.v2.schema.json",
            "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v3.json",
            "schemas/m0-3a-runtime-v2-resource-discovery.v3.schema.json",
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST["path"],
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA["path"],
            *(item["path"] for item in RESOURCE_CLASSIFICATION_ANCESTORS),
            *(item["path"] for item in RESOURCE_CLASSIFICATION_EVIDENCE),
        }
        for relative in paths:
            source = ROOT / relative
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return temporary

    def rewrite_manifest(self, root: Path, mutate) -> None:
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        manifest = json.loads(path.read_text(encoding="ascii"))
        mutate(manifest)
        digest_value = dict(manifest)
        digest_value.pop("classification_manifest_sha256")
        manifest["classification_manifest_sha256"] = hashlib.sha256(
            RESOURCE_CLASSIFICATION_DOMAIN.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        path.write_text(json.dumps(manifest), encoding="ascii")

    @staticmethod
    def baseline_row_cap_bindings() -> list[dict[str, object]]:
        _, _, source_bytes = _source_inventory(ROOT)
        ordinary = _source_bound_inventory(source_bytes)
        v2 = _source_bound_binding_inventory(source_bytes, ordinary)
        v3 = _source_bound_cardinality_binding_inventory(
            source_bytes, ordinary + v2
        )
        return _source_bound_table_row_cap_binding_inventory(
            source_bytes,
            sorted(ordinary + v2 + v3, key=lambda x: (x["path"], x["site_id"])),
        )

    def refresh_source_bindings(self, root: Path) -> None:
        source, _, source_bytes = _source_inventory(root)
        predecessor_sites = _source_bound_inventory(source_bytes)
        table_binding_sites = _source_bound_binding_inventory(
            source_bytes, predecessor_sites
        )
        try:
            cardinality_binding_sites = (
                _source_bound_cardinality_binding_inventory(
                    source_bytes, predecessor_sites + table_binding_sites
                )
            )
        except ReadinessError as error:
            if error.code != "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST":
                raise
            _, _, baseline_source_bytes = _source_inventory(ROOT)
            baseline_predecessor_sites = _source_bound_inventory(
                baseline_source_bytes
            )
            baseline_table_binding_sites = _source_bound_binding_inventory(
                baseline_source_bytes, baseline_predecessor_sites
            )
            cardinality_binding_sites = (
                _source_bound_cardinality_binding_inventory(
                    baseline_source_bytes,
                    baseline_predecessor_sites + baseline_table_binding_sites,
                )
            )
        v3_sites = sorted(
            predecessor_sites
            + table_binding_sites
            + cardinality_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        try:
            row_cap_sites = _source_bound_table_row_cap_binding_inventory(
                source_bytes, v3_sites
            )
        except ReadinessError as error:
            if not error.code.startswith("RESOURCE_ROW_CAP_BINDING_"):
                raise
            row_cap_sites = self.baseline_row_cap_bindings()
        source_sites = sorted(
            v3_sites + row_cap_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_identity = [
            {key: value for key, value in item.items() if key != "line"}
            for item in source_sites
        ]
        source_inputs = [
            {
                "byte_length": item["byte_length"],
                "module": item["module"],
                "path": item["path"],
                "raw_sha256": item["raw_sha256"],
            }
            for item in source["local_artifacts"]
        ]

        def refresh(manifest):
            manifest["source_input_count"] = len(source_inputs)
            manifest["source_inputs_sha256"] = _domain_digest(
                RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
            )
            manifest["source_bound_site_count"] = len(source_sites)
            manifest["source_bound_sites_sha256"] = _domain_digest(
                RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
                source_identity,
            )
            manifest["unclassified_site_count"] = (
                len(source_sites) + manifest["schema_bound_site_count"]
                - manifest["classified_site_count"]
            )

        self.rewrite_manifest(root, refresh)

    def build_with_refreshed_ordinary_source_bindings(
        self, root: Path, binding_sites: list[dict[str, object]]
    ) -> dict[str, object]:
        """Model an attacker refreshing the ordinary V3 census after source drift."""
        source, _, source_bytes = _source_inventory(root)
        predecessor_sites = _source_bound_inventory(source_bytes)
        v2_source_sites = sorted(
            predecessor_sites + binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_table_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )
        cardinality_binding_sites = _source_bound_cardinality_binding_inventory(
            baseline_source_bytes,
            baseline_predecessor_sites + baseline_table_binding_sites,
        )
        row_cap_binding_sites = self.baseline_row_cap_bindings()
        v3_source_sites = sorted(
            v2_source_sites + cardinality_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_sites = sorted(
            v3_source_sites + row_cap_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_identity = [
            {key: value for key, value in item.items() if key != "line"}
            for item in source_sites
        ]
        source_inputs = [
            {
                "byte_length": item["byte_length"],
                "module": item["module"],
                "path": item["path"],
                "raw_sha256": item["raw_sha256"],
            }
            for item in source["local_artifacts"]
        ]
        v3_source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in v3_source_sites
            ],
        )
        source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN, source_identity
        )
        v2_source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in v2_source_sites
            ],
        )

        def refresh(manifest):
            manifest["source_input_count"] = len(source_inputs)
            manifest["source_inputs_sha256"] = _domain_digest(
                RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
            )
            manifest["source_bound_site_count"] = len(source_sites)
            manifest["source_bound_sites_sha256"] = source_digest
            manifest["unclassified_site_count"] = (
                len(source_sites) + manifest["schema_bound_site_count"]
                - manifest["classified_site_count"]
            )

        self.rewrite_manifest(root, refresh)
        with (
            mock.patch.object(
                readiness_checker,
                "_source_bound_binding_inventory",
                return_value=binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "_source_bound_cardinality_binding_inventory",
                return_value=cardinality_binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "_source_bound_table_row_cap_binding_inventory",
                return_value=row_cap_binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V2_SHA256",
                v2_source_digest,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V3_SHA256",
                v3_source_digest,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                source_digest,
            ),
        ):
            return build_report(root)

    def build_with_attacker_refreshed_v3_bindings(
        self,
        root: Path,
        cardinality_binding_sites: list[dict[str, object]],
    ) -> dict[str, object]:
        """Model an attacker refreshing both census layers after source drift."""
        source, _, source_bytes = _source_inventory(root)
        predecessor_sites = _source_bound_inventory(source_bytes)
        table_binding_sites = _source_bound_binding_inventory(
            source_bytes, predecessor_sites
        )
        v2_source_sites = sorted(
            predecessor_sites + table_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        source_sites = sorted(
            v2_source_sites + cardinality_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        v2_source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in v2_source_sites
            ],
        )
        source_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in source_sites
            ],
        )
        row_cap_binding_sites = self.baseline_row_cap_bindings()
        v4_sites = sorted(
            source_sites + row_cap_binding_sites,
            key=lambda item: (item["path"], item["site_id"]),
        )
        v4_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in v4_sites
            ],
        )
        source_inputs = [
            {
                "byte_length": item["byte_length"],
                "module": item["module"],
                "path": item["path"],
                "raw_sha256": item["raw_sha256"],
            }
            for item in source["local_artifacts"]
        ]

        def refresh(manifest):
            manifest["source_input_count"] = len(source_inputs)
            manifest["source_inputs_sha256"] = _domain_digest(
                RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
            )
            manifest["source_bound_site_count"] = len(v4_sites)
            manifest["source_bound_sites_sha256"] = v4_digest
            manifest["unclassified_site_count"] = (
                len(v4_sites) + manifest["schema_bound_site_count"]
                - manifest["classified_site_count"]
            )

        self.rewrite_manifest(root, refresh)
        with (
            mock.patch.object(
                readiness_checker,
                "_source_bound_cardinality_binding_inventory",
                return_value=cardinality_binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "_source_bound_table_row_cap_binding_inventory",
                return_value=row_cap_binding_sites,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V2_SHA256",
                v2_source_digest,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V3_SHA256",
                source_digest,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                v4_digest,
            ),
        ):
            return build_report(root)

    def rewrite_versioned_classification_manifest(
        self, root: Path, expected: dict[str, object], version: int, mutate
    ) -> dict[str, object]:
        path = root / str(expected["path"])
        manifest = json.loads(path.read_text(encoding="ascii"))
        mutate(manifest)
        digest_value = dict(manifest)
        digest_value.pop("classification_manifest_sha256")
        domain = f"EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V{version}\0"
        manifest["classification_manifest_sha256"] = hashlib.sha256(
            domain.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        raw = json.dumps(manifest).encode("ascii")
        path.write_bytes(raw)
        return {
            "byte_length": len(raw),
            "classification_manifest_sha256": manifest[
                "classification_manifest_sha256"
            ],
            "path": expected["path"],
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def test_current_inventory_is_deterministic_blocked_and_deny_only(self):
        first = build_report(ROOT)
        second = build_report(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "BLOCKED")
        self.assertEqual(first["authorizing_use"], "DENY")
        self.assertFalse(first["release_artifacts_written"])
        self.assertEqual(
            [item["code"] for item in first["blockers"]],
            [
                "ACCEPTANCE_MATRIX_INCOMPLETE",
                "PUBLIC_ENTRYPOINT_DISCONNECTED",
                "RESOURCE_INVENTORY_INCOMPLETE",
                "V1_BRIDGE_UNSUPPORTED",
            ],
        )
        self.assertEqual(first["public_result_vocabulary"], ["INVALID", "UNSUPPORTED"])
        for prohibited in (
            "verifier_dependency_closure_sha256", "closure_candidate",
            "carrier_candidate", "positive_status",
            "release_generation_permitted",
        ):
            self.assertNotIn(prohibited, first)

    def test_exact_current_source_and_content_inventory_is_derived(self):
        inventory = build_report(ROOT)["inventory"]
        sources = inventory["source_closure"]
        self.assertEqual(
            [item["module"] for item in sources["local_artifacts"]],
            sorted({
                "edgelab",
                "edgelab.runtime_v2_bootstrap",
                "edgelab.runtime_v2_closure",
                "edgelab.runtime_v2_codec",
                "edgelab.runtime_v2_genesis",
                "edgelab.runtime_v2_group",
                "edgelab.runtime_v2_image",
                "edgelab.runtime_v2_initial",
                "edgelab.runtime_v2_transition",
                "edgelab.runtime_v2_verifier",
            }),
        )
        self.assertEqual(
            sources["standard_library_modules"],
            ["dataclasses", "hashlib", "json", "re", "typing"],
        )
        self.assertEqual(sources["external_import_modules"], [])
        self.assertEqual(sources["compiler_directives_excluded"], ["__future__"])
        self.assertEqual(len(inventory["bootstrap_schemas"]), 5)
        self.assertEqual(len(inventory["retained_schema_documents"]), 9)
        self.assertEqual(len(inventory["content_assets"]), 2)
        discovery = inventory["resource_inventory_discovery"]
        self.assertEqual(discovery["classification_status"], "UNCLASSIFIED")
        self.assertEqual(discovery["coverage_status"], "INCOMPLETE")
        self.assertEqual(len(discovery["source_bound_sites"]), 422)
        self.assertEqual(len(discovery["schema_bound_sites"]), 296)
        self.assertEqual(len(discovery["schema_inputs"]), 15)
        self.assertEqual(len(discovery["source_inputs"]), 10)
        classification = inventory["resource_inventory_classification"]
        self.assertEqual(classification["classified_constraint_count"], 18)
        self.assertEqual(classification["classified_site_count"], 45)
        self.assertEqual(classification["unclassified_site_count"], 673)
        self.assertEqual(classification["coverage_status"], "INCOMPLETE")
        self.assertEqual(classification["generation_disposition"], "DENY")
        expected_schema_paths = {
            path for _, _, path in BOOTSTRAP_SCHEMAS + RETAINED_SCHEMAS
        } | {CLOSURE_SCHEMA[1]}
        self.assertEqual(
            {item["path"] for item in discovery["schema_inputs"]},
            expected_schema_paths,
        )
        expected_schema_input_digest = hashlib.sha256(
            b"EDGELAB\0RUNTIME_V2_RESOURCE_SCHEMA_INPUTS\0V1\0"
            + json.dumps(
                discovery["schema_inputs"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assertEqual(
            discovery["schema_inputs_sha256"], expected_schema_input_digest
        )
        self.assertTrue(
            expected_schema_paths.isdisjoint({path for _, _, path in CONTENT_ASSETS})
        )
        defaults = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "FUNCTION_DEFAULT"
        ]
        self.assertTrue(defaults)
        self.assertTrue(all(item["qualname"] != "<module>" for item in defaults))
        self.assertTrue(all(item["binding"].startswith("parameter:") for item in defaults))
        self.assertEqual(
            {item["classification"] for item in discovery["source_bound_sites"]},
            {"UNCLASSIFIED"},
        )
        self.assertEqual(
            {item["classification"] for item in discovery["schema_bound_sites"]},
            {"UNCLASSIFIED"},
        )
        self.assertEqual(
            inventory["tested_runtime_assumptions"],
            [
                {"expected": "CPython", "name": "PYTHON_IMPLEMENTATION"},
                {"expected": "3.13", "name": "PYTHON_VERSION"},
            ],
        )
        domain_names = {item["name"] for item in inventory["digest_domains"]}
        self.assertTrue({
            "blob", "event", "event_task_predecessor", "table",
            "verifier_dependency_closure",
        }.issubset(domain_names))
        limit_names = {item["name"] for item in inventory["resource_limits"]}
        self.assertTrue({
            "CANONICAL_JSON_MAX_DEPTH", "CLOSURE_INTEGER_TOKEN_MAX_DIGITS",
            "MAX_SCHEMA_REF_NODES",
            "MAX_TOTAL_ACCOUNTED_INPUT_BYTES", "MAX_TOTAL_ROOT_WORK_BYTES",
            "TABLE_TASKS_ROWS",
        }.issubset(limit_names))
        for namespace_name in (
            "bootstrap_schemas", "content_assets", "retained_schema_documents",
        ):
            namespace = inventory[namespace_name]
            for item in namespace:
                raw = (ROOT / item["path"]).read_bytes()
                self.assertEqual(item["byte_length"], len(raw))
                self.assertEqual(item["raw_sha256"], hashlib.sha256(raw).hexdigest())

    def test_resource_discovery_v4_preserves_v3_and_adds_exact_bindings(self):
        discovery = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        self.assertEqual(discovery["profile_id"], RESOURCE_DISCOVERY_V4_ID)
        self.assertEqual(len(discovery["source_bound_sites"]), 422)
        self.assertEqual(len(discovery["schema_bound_sites"]), 296)
        self.assertEqual(
            len(discovery["source_bound_sites"])
            + len(discovery["schema_bound_sites"]),
            718,
        )
        self.assertEqual(discovery["legacy_source_bound_site_count"], 407)
        self.assertEqual(discovery["derived_binding_site_count"], 15)
        self.assertEqual(discovery["cumulative_derived_binding_site_count"], 28)
        self.assertEqual(
            discovery["source_bound_sites_sha256"],
            RESOURCE_SOURCE_BOUND_SITES_V4_SHA256,
        )
        self.assertEqual(
            RESOURCE_SOURCE_BOUND_SITES_V4_SHA256,
            "5918304896b54b757e26d94367227c9f36db56e367964133d793c3539f47ab2f",
        )
        self.assertEqual(
            discovery["predecessor_discovery"],
            {
                "profile_id": RESOURCE_DISCOVERY_V3_ID,
                "schema_bound_site_count": 296,
                "schema_bound_sites_sha256": (
                    "00b27a32303836f9d9910663e6bd2f76a7ca6d8c7cd614e5f22346b53cd104de"
                ),
                "schema_input_count": 15,
                "schema_inputs_sha256": (
                    "14ccff50a49f337336f01b5a40b845e5011218063d2cdfa68f0b73b1a3c94239"
                ),
                "source_bound_site_count": 407,
                "source_bound_sites_sha256": (
                    "d38e35a0f2466735c0895b6bfb7f20c83b52834ccbc3995943f8147d8f664071"
                ),
                "source_input_count": 10,
                "source_inputs_sha256": (
                    "b22a453f6b2f5f44281054752bf9bce5e259d6a60ae22fe7b190383292e4ba2a"
                ),
            },
        )
        bindings = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_COMPARISON_BINDING"
        ]
        self.assertEqual(
            {item["site_id"] for item in bindings},
            {
                "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534",
                "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
            },
        )
        self.assertTrue(all(item["classification"] == "UNCLASSIFIED" for item in bindings))
        self.assertTrue(all(set(item) == {
            "ast_sha256", "binding", "branch_key", "classification",
            "comparator_site_id", "expression", "kind", "line",
            "loop_ast_sha256", "maximum_expression", "path", "qualname",
            "row_index", "site_id", "subject_expression",
            "table_assignment_ast_sha256", "table_name",
        } for item in bindings))

        _, _, source_bytes = _source_inventory(ROOT)
        predecessor = _source_bound_inventory(source_bytes)
        self.assertEqual(
            _source_bound_binding_inventory(source_bytes, predecessor),
            bindings,
        )
        cardinality_bindings = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING"
        ]
        self.assertEqual(len(cardinality_bindings), 6)
        self.assertEqual(
            {item["branch_key"]: item["site_id"] for item in cardinality_bindings},
            {
                "schema_documents": (
                    "cc70a073ff6cb3d1a80a48869ff0073a91600b675a290a0318e83eb7b6c7907b"
                ),
                "blobs": (
                    "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3"
                ),
                "events": (
                    "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1"
                ),
                "table_snapshots": (
                    "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
                ),
                "checkpoint_copies": (
                    "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13"
                ),
                "selector_history": (
                    "eeee1fcbd15b357a15780fe79e32e2e5046cbb44d1d02e7025828aaa61940557"
                ),
            },
        )
        self.assertEqual(
            {
                item["branch_key"]: (
                    item["minimum_expression"], item["maximum_expression"]
                )
                for item in cardinality_bindings
            },
            {
                "schema_documents": ("9", "9"),
                "blobs": ("0", "MAX_BLOBS"),
                "events": ("0", "MAX_EVENTS"),
                "table_snapshots": (
                    "len(_TABLE_SPECS)", "len(_TABLE_SPECS)"
                ),
                "checkpoint_copies": ("0", "MAX_CHECKPOINT_COPIES"),
                "selector_history": ("MIN_SELECTORS", "MAX_SELECTORS"),
            },
        )
        self.assertTrue(all(
            item["binding"] == f'cardinalities:{item["branch_key"]}'
            and item["subject_binding"]
            == f'captured[\'{item["branch_key"]}\']'
            and item["subject_expression"] == "captured[name]"
            and item["semantic_function_ast_sha256"]
            == "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            and item["classification"] == "UNCLASSIFIED"
            for item in cardinality_bindings
        ))
        self.assertTrue(all(set(item) == {
            "ast_sha256", "binding", "branch_key", "classification",
            "comparator_site_id", "comparison_assignment_ast_sha256",
            "expression", "invalid_branch_ast_sha256", "kind", "line",
            "loop_ast_sha256", "maximum_expression", "minimum_expression",
            "path", "qualname", "result_assignment_ast_sha256", "row_index",
            "semantic_function_ast_sha256", "site_id", "subject_binding",
            "subject_expression",
            "subject_lookup_ast_sha256", "subject_loop_ast_sha256",
            "subject_row_ast_sha256", "subject_table_assignment_ast_sha256",
            "table_assignment_ast_sha256", "table_name",
            "validity_gate_ast_sha256",
        } for item in cardinality_bindings))
        table_bindings = _source_bound_binding_inventory(source_bytes, predecessor)
        self.assertEqual(
            _source_bound_cardinality_binding_inventory(
                source_bytes, predecessor + table_bindings
            ),
            cardinality_bindings,
        )
        row_cap_bindings = [
            item for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        self.assertEqual(len(row_cap_bindings), 15)
        self.assertEqual(
            {(item["row_index"], item["table_name"], item["maximum"])
             for item in row_cap_bindings},
            {
                (0, "attempts", 100_000), (1, "blobs", 300_000),
                (2, "claims", 100_000), (3, "events", 100_000),
                (4, "idempotency", 100_000), (5, "legacy_archive", 1),
                (6, "metadata", 1), (7, "migrations", 0),
                (8, "remediation_links", 100_000),
                (9, "reviews", 100_000), (10, "schema_documents", 9),
                (11, "schema_registry", 1), (12, "seals", 1),
                (13, "snapshots", 100_000), (14, "tasks", 100_000),
            },
        )
        self.assertTrue(all(
            item["classification"] == "UNCLASSIFIED"
            and item["selection_semantics"]
            == "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL"
            and item["subject_binding"]
            == f"captured['table_snapshots'][{item['row_index']}].rows"
            for item in row_cap_bindings
        ))
        self.assertEqual(
            _source_bound_table_row_cap_binding_inventory(
                source_bytes,
                sorted(
                    predecessor + table_bindings + cardinality_bindings,
                    key=lambda item: (item["path"], item["site_id"]),
                ),
            ),
            row_cap_bindings,
        )
        manifest_bytes = (ROOT / RESOURCE_DISCOVERY_MANIFEST[1]).read_bytes()
        manifest = json.loads(manifest_bytes)
        self.assertEqual(
            manifest["discovery_manifest_sha256"],
            "2f34479e4597041b122a61c4aea29ae051446285ec51518d965bfd0e8b8e09d6",
        )
        self.assertEqual(
            hashlib.sha256(manifest_bytes).hexdigest(),
            "9d4c0630a802ef849e3ccb2cd6993cc58b8b2c8fa694888bff8ef96a52384681",
        )
        self.assertEqual(
            hashlib.sha256((ROOT / RESOURCE_DISCOVERY_SCHEMA[1]).read_bytes()).hexdigest(),
            "558baf8aa2e1da502e4c19a733bfe0a73d42bcd1d0c1d5e1ad3b948fd12d9bd4",
        )

    def test_resource_discovery_v4_evidence_artifacts_fail_closed(self):
        root = self.copy_inputs()
        schema = root / RESOURCE_DISCOVERY_SCHEMA[1]
        schema.write_bytes(schema.read_bytes() + b"\n")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_SCHEMA_IDENTITY")

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["coverage_status"] = "COMPLETE"
        digest_value = dict(manifest)
        digest_value.pop("discovery_manifest_sha256")
        manifest["discovery_manifest_sha256"] = _domain_digest(
            RESOURCE_DISCOVERY_DOMAIN, digest_value
        )
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_MANIFEST_BINDING")
        self.assertEqual(caught.exception.coordinate, "coverage_status")

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["discovery_manifest_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_DISCOVERY_MANIFEST_SELF_DIGEST"
        )

        root = self.copy_inputs()
        manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
        manifest_path.unlink()
        manifest_path.hardlink_to(root / RESOURCE_DISCOVERY_SCHEMA[1])
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

    def test_v4_row_cap_derivation_rejects_full_semantic_attack_matrix(self):
        _, _, baseline_bytes = _source_inventory(ROOT)
        ordinary = _source_bound_inventory(baseline_bytes)
        v2 = _source_bound_binding_inventory(baseline_bytes, ordinary)
        v3 = _source_bound_cardinality_binding_inventory(
            baseline_bytes, sorted(ordinary + v2, key=lambda x: (x["path"], x["site_id"])),
        )
        predecessor = sorted(
            ordinary + v2 + v3, key=lambda x: (x["path"], x["site_id"])
        )
        path = "src/edgelab/runtime_v2_image.py"
        original = baseline_bytes[path]
        attempt_row = next(
            line for line in original.splitlines(keepends=True)
            if b'_TableSpec("attempts"' in line
        )
        row_limit_block = (
            b'            if len(rows) > spec.max_rows:\n'
            b'                findings.add("TABLE_ROW_LIMIT", "table_snapshots", f"{coordinate}/rows")\n'
            b'                accounting_complete = False\n'
            b'                continue\n'
        )
        attacks = {
            "class-positional-meaning": (
                b"    row_order: tuple[int, ...]\n    max_rows: int\n",
                b"    max_rows: int\n    row_order: tuple[int, ...]\n",
            ),
            "aggregate-maximum": (b"(0,), (0,), 300_000),", b"(0,), (0,), 299_999),"),
            "same-valued-cap-expression": (
                attempt_row,
                attempt_row.replace(b"100_000),", b"99_999 + 1),"),
            ),
            "helper-delete": (attempt_row, b""),
            "helper-duplicate": (attempt_row, attempt_row + attempt_row),
            "helper-add": (
                attempt_row,
                attempt_row + attempt_row.replace(b'"attempts"', b'"attempts_extra"', 1),
            ),
            "outer-gate": (
                b'if cardinality_valid.get("table_snapshots", False):',
                b'if cardinality_valid.get("table_snapshots", True):',
            ),
            "loop-target": (
                b"for index, (snapshot, spec) in enumerate(zip(",
                b"for index, (spec, snapshot) in enumerate(zip(",
            ),
            "iterator-source": (
                b'captured["table_snapshots"], _TABLE_SPECS, strict=True',
                b'_TABLE_SPECS, captured["table_snapshots"], strict=True',
            ),
            "strict-zip-false": (
                b'captured["table_snapshots"], _TABLE_SPECS, strict=True',
                b'captured["table_snapshots"], _TABLE_SPECS, strict=False',
            ),
            "snapshot-type-gate": (
                b"type(snapshot) is not TableSnapshot",
                b"not isinstance(snapshot, TableSnapshot)",
            ),
            "table-read": (
                b'table = _read_slot(snapshot, "table")',
                b'table = _read_slot(snapshot, "rows")',
            ),
            "rows-read": (
                b'rows = _read_slot(snapshot, "rows")',
                b'rows = _read_slot(snapshot, "table")',
            ),
            "table-missing": (b"if table is _MISSING:", b"if table is None:"),
            "rows-missing": (b"if rows is _MISSING:", b"if rows is None:"),
            "combined-missing": (
                b"if table is _MISSING or rows is _MISSING:",
                b"if table is _MISSING and rows is _MISSING:",
            ),
            "identity-gate": (
                b"if type(table) is not str or table != spec.name:",
                b"if type(table) is not str and table != spec.name:",
            ),
            "identity-mismatch-continue": (
                b'                findings.add("TABLE_INVENTORY", "table_snapshots", f"{coordinate}/table")\n'
                b"                accounting_complete = False\n",
                b'                findings.add("TABLE_INVENTORY", "table_snapshots", f"{coordinate}/table")\n'
                b"                accounting_complete = False\n"
                b"                continue\n",
            ),
            "rows-type-gate": (
                b"if type(rows) is not tuple:",
                b"if not isinstance(rows, tuple):",
            ),
            "comparator": (
                b"if len(rows) > spec.max_rows:",
                b"if len(rows) >= spec.max_rows:",
            ),
            "diagnostic-code": (
                b'findings.add("TABLE_ROW_LIMIT", "table_snapshots", f"{coordinate}/rows")',
                b'findings.add("TABLE_ROWS_TYPE", "table_snapshots", f"{coordinate}/rows")',
            ),
            "diagnostic-artifact": (
                row_limit_block,
                row_limit_block.replace(b'"table_snapshots"', b'"runtime_image"'),
            ),
            "diagnostic-coordinate": (
                row_limit_block,
                row_limit_block.replace(b'f"{coordinate}/rows"', b'f"{coordinate}"'),
            ),
            "accounting": (
                row_limit_block,
                row_limit_block.replace(
                    b"                accounting_complete = False\n", b""
                ),
            ),
            "continue": (
                row_limit_block,
                row_limit_block.replace(b"                continue\n", b"                pass\n"),
            ),
            "inter-loop-rows-rebind": (
                b"            if len(rows) > spec.max_rows:",
                b"            rows = ()\n            if len(rows) > spec.max_rows:",
            ),
            "inter-loop-spec-rebind": (
                b"            if len(rows) > spec.max_rows:",
                b"            spec = _TABLE_SPECS[0]\n            if len(rows) > spec.max_rows:",
            ),
            "len-shadow": (
                b"_MISSING = object()\n",
                b"_MISSING = object()\nlen = tuple.__len__\n",
            ),
            "zip-shadow": (
                b"_MISSING = object()\n",
                b"_MISSING = object()\nzip = lambda *args, **kwargs: ()\n",
            ),
            "type-shadow": (
                b"_MISSING = object()\n",
                b"_MISSING = object()\ntype = lambda value: value.__class__\n",
            ),
            "enumerate-shadow": (
                b"_MISSING = object()\n",
                b"_MISSING = object()\nenumerate = lambda values: ()\n",
            ),
            "read-slot-shadow": (
                b"def inspect_runtime_image_host(candidate: object)",
                b"_read_slot = lambda value, name: ()\ndef inspect_runtime_image_host(candidate: object)",
            ),
            "missing-shadow": (
                b"def inspect_runtime_image_host(candidate: object)",
                b"_MISSING = object()\ndef inspect_runtime_image_host(candidate: object)",
            ),
            "table-specs-rebind": (
                b"    snapshot_sizes: list[int] = []\n",
                b"    _TABLE_SPECS = ()\n    snapshot_sizes: list[int] = []\n",
            ),
            "snapshot-rebind": (
                b"            if type(snapshot) is not TableSnapshot:",
                b"            snapshot = captured['table_snapshots'][0]\n"
                b"            if type(snapshot) is not TableSnapshot:",
            ),
        }
        for name, (needle, replacement) in attacks.items():
            with self.subTest(attack=name):
                self.assertEqual(original.count(needle), 1)
                hostile = dict(baseline_bytes)
                hostile[path] = original.replace(needle, replacement, 1)
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_table_row_cap_binding_inventory(hostile, predecessor)
                self.assertTrue(caught.exception.code.startswith("RESOURCE_ROW_CAP_BINDING_"))

        lines = original.splitlines(keepends=True)
        first = next(i for i, line in enumerate(lines) if b'_TableSpec("attempts"' in line)
        second = next(i for i, line in enumerate(lines) if b'_TableSpec("claims"' in line)
        lines[first], lines[second] = lines[second], lines[first]
        hostile = dict(baseline_bytes)
        hostile[path] = b"".join(lines)
        with self.assertRaises(ReadinessError):
            _source_bound_table_row_cap_binding_inventory(hostile, predecessor)

    def test_v4_evidence_rejects_attacker_refreshed_row_cap_census(self):
        root = self.copy_inputs()
        _, _, source_bytes = _source_inventory(root)
        ordinary = _source_bound_inventory(source_bytes)
        v2 = _source_bound_binding_inventory(source_bytes, ordinary)
        v3 = _source_bound_cardinality_binding_inventory(
            source_bytes, ordinary + v2
        )
        row_caps = _source_bound_table_row_cap_binding_inventory(
            source_bytes,
            sorted(ordinary + v2 + v3, key=lambda x: (x["path"], x["site_id"])),
        )
        forged = [dict(item) for item in row_caps]
        forged[0]["maximum"] = 99_999
        forged[0]["site_id"] = "0" * 64
        all_sites = sorted(
            ordinary + v2 + v3 + forged,
            key=lambda item: (item["path"], item["site_id"]),
        )
        forged_digest = _domain_digest(
            RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
            [
                {key: value for key, value in item.items() if key != "line"}
                for item in all_sites
            ],
        )

        def refresh(manifest):
            manifest["source_bound_sites_sha256"] = forged_digest

        self.rewrite_manifest(root, refresh)
        with (
            mock.patch.object(
                readiness_checker,
                "_source_bound_table_row_cap_binding_inventory",
                return_value=forged,
            ),
            mock.patch.object(
                readiness_checker,
                "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                forged_digest,
            ),
        ):
            with self.assertRaises(ReadinessError) as caught:
                build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_DISCOVERY_MANIFEST_BINDING"
        )

    def test_resource_discovery_v4_binds_v3_predecessor_evidence(self):
        for relative in (
            "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v3.json",
            "schemas/m0-3a-runtime-v2-resource-discovery.v3.schema.json",
        ):
            with self.subTest(predecessor=relative):
                root = self.copy_inputs()
                predecessor = root / relative
                predecessor.write_bytes(predecessor.read_bytes() + b"\n")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_DISCOVERY_PREDECESSOR_IDENTITY",
                )

        for record, field in (
            ("predecessor_manifest", "raw_sha256"),
            ("predecessor_manifest", "discovery_manifest_sha256"),
            ("predecessor_schema", "raw_sha256"),
        ):
            with self.subTest(record=record, field=field):
                root = self.copy_inputs()
                manifest_path = root / RESOURCE_DISCOVERY_MANIFEST[1]
                manifest = json.loads(manifest_path.read_text(encoding="ascii"))
                manifest[record][field] = "0" * 64
                digest_value = dict(manifest)
                digest_value.pop("discovery_manifest_sha256")
                manifest["discovery_manifest_sha256"] = _domain_digest(
                    RESOURCE_DISCOVERY_DOMAIN, digest_value
                )
                manifest_path.write_text(json.dumps(manifest), encoding="ascii")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_DISCOVERY_MANIFEST_BINDING",
                )

    def test_resource_discovery_v2_table_bindings_fail_closed_on_drift(self):
        manifest_row = (
            b'        ("manifest", captured["manifest"], '
            b'MAX_BOOTSTRAP_DOCUMENT_BYTES),\n'
        )
        attachment_row = (
            b'        ("attachment", captured["attachment"], '
            b'MAX_BOOTSTRAP_DOCUMENT_BYTES),\n'
        )
        attacks = (
            (manifest_row, manifest_row.replace(b'"manifest"', b'"wrong"', 1),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row.replace(b'captured["manifest"]', b'captured["attachment"]'),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row.replace(b"MAX_BOOTSTRAP_DOCUMENT_BYTES", b"MAX_SCHEMA_REGISTRY_BYTES"),
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, manifest_row + manifest_row,
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, b"", "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row + attachment_row, attachment_row + manifest_row,
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (manifest_row, b"        *(" + manifest_row.strip().rstrip(b",") + b",),\n",
             "RESOURCE_BINDING_ASSIGNMENT_AST"),
            (b"for name, value, maximum in byte_fields:",
             b"for name, value, maximum in tuple(byte_fields):",
             "RESOURCE_BINDING_LOOP"),
            (b"for name, value, maximum in byte_fields:",
             b"for branch, value, maximum in byte_fields:",
             "RESOURCE_BINDING_LOOP_AST"),
            (b"if maximum is not None and len(value) > maximum:",
             b"if maximum is not None and len(value) >= maximum:",
             "RESOURCE_BINDING_LOOP_AST"),
            (b"for name, values, maximum in byte_collections:",
             b"for name, values, maximum in tuple(byte_collections):",
             "RESOURCE_BINDING_LOOP"),
            (b"if len(value) > maximum:\n",
             b"if len(value) >= maximum:\n",
             "RESOURCE_BINDING_LOOP_AST"),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:50]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_resource_discovery_v3_cardinality_bindings_reject_inter_loop_drift(
        self,
    ):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        path = "src/edgelab/runtime_v2_image.py"
        insertion_point = b'    if captured["legacy_evidence"] is not None:\n'
        cardinality_point = b"    cardinality_valid: dict[str, bool] = {}\n"
        attacks = (
            (
                insertion_point,
                b'    captured["events"] = captured["blobs"]\n'
                + insertion_point,
            ),
            (
                insertion_point,
                b'    tuple_valid["events"] = True\n' + insertion_point,
            ),
            (
                insertion_point,
                b"    tuple_valid.clear()\n" + insertion_point,
            ),
            (
                cardinality_point,
                b"    len = lambda value: value.__len__()\n"
                + cardinality_point,
            ),
        )
        for old, new in attacks:
            with self.subTest(attack=new[:60]):
                source_bytes = dict(baseline_source_bytes)
                original = source_bytes[path]
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source_bytes[path] = mutated
                predecessor_sites = _source_bound_inventory(source_bytes)
                table_binding_sites = _source_bound_binding_inventory(
                    source_bytes, predecessor_sites
                )
                self.assertEqual(len(predecessor_sites), 394)
                self.assertEqual(len(table_binding_sites), 7)
                with self.assertRaises(ReadinessError) as caught:
                    _source_bound_cardinality_binding_inventory(
                        source_bytes,
                        predecessor_sites + table_binding_sites,
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"    byte_fields = (", b"    byte_fields_alias = (", 1
        ).replace(
            b"for name, value, maximum in byte_fields:",
            b"for name, value, maximum in byte_fields_alias:",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_TABLE_NAME")

    def test_resource_discovery_v3_cardinality_bindings_fail_closed_on_drift(self):
        schema_row = b'        ("schema_documents", 9, 9),\n'
        blobs_row = b'        ("blobs", 0, MAX_BLOBS),\n'
        events_row = b'        ("events", 0, MAX_EVENTS),\n'
        table_snapshots_row = (
            b'        ("table_snapshots", len(_TABLE_SPECS), '
            b'len(_TABLE_SPECS)),\n'
        )
        tuple_events_row = b'        ("events", captured["events"]),\n'
        attacks = (
            (
                schema_row,
                schema_row.replace(b'"schema_documents"', b'"wrong"', 1),
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                schema_row,
                schema_row.replace(b"9, 9", b"9 + 0, 9"),
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                blobs_row,
                blobs_row.replace(b"0,", b"False,", 1),
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                events_row,
                events_row.replace(b"MAX_EVENTS", b"100_000"),
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                table_snapshots_row,
                table_snapshots_row.replace(b"len(_TABLE_SPECS)", b"15", 1),
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                schema_row + blobs_row,
                blobs_row + schema_row,
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                events_row,
                events_row + events_row,
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                events_row,
                b"",
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                events_row,
                b"        *(" + events_row.strip().rstrip(b",") + b",),\n",
                "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            ),
            (
                tuple_events_row,
                tuple_events_row.replace(
                    b'captured["events"]', b'captured["blobs"]'
                ),
                "RESOURCE_CARDINALITY_BINDING_SUBJECT_ASSIGNMENT_AST",
            ),
            (
                b"for name, minimum, maximum in cardinalities:",
                b"for name, minimum, maximum in tuple(cardinalities):",
                "RESOURCE_CARDINALITY_BINDING_LOOP",
            ),
            (
                b"for name, minimum, maximum in cardinalities:",
                b"for branch, minimum, maximum in cardinalities:",
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
            (
                b"if not tuple_valid.get(name, False):",
                b"if not tuple_valid.get(name, True):",
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
            (
                b"        value = captured[name]\n",
                b"        value = captured[str(name)]\n",
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
            (
                b"valid = minimum <= len(value) <= maximum",
                b"valid = minimum < len(value) <= maximum",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b"        cardinality_valid[name] = valid\n",
                b"        cardinality_valid[str(name)] = valid\n",
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
            (
                b'findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")',
                b'findings.add("IMAGE_FIELD_TYPE", name, "/")',
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
            (
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n'
                b"            accounting_complete = False\n",
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n',
                "RESOURCE_CARDINALITY_BINDING_LOOP_AST",
            ),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:60]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        source.write_bytes(original.replace(
            b"    cardinalities = (",
            b'    cardinalities_name = "cardinalities"\n    cardinalities = (',
            1,
        ))
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CARDINALITY_BINDING_DYNAMIC_TABLE"
        )

        for old, new, expected_code in (
            (
                b"MAX_EVENTS = 100_000",
                b"MAX_EVENTS = 99_999",
                "RESOURCE_LIMIT_CONFLICT",
            ),
            (
                b'_TableSpec("attempts",',
                b'_TableSpec("attempts_wrong",',
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
        ):
            with self.subTest(semantic_pin=old):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_cli_emits_one_canonical_json_line_and_refuses_release(self):
        command = [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "tools" / "check_runtime_v2_release_readiness.py"),
        ]
        completed = subprocess.run(
            command, cwd=ROOT, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 1, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout.count(b"\n"), 1)
        value = json.loads(completed.stdout)
        expected = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii") + b"\n"
        self.assertEqual(completed.stdout, expected)
        self.assertEqual(value, build_report(ROOT))

        denied = subprocess.run(
            command + ["--root", "/tmp"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(denied.returncode, 2)
        denied_value = json.loads(denied.stdout)
        self.assertEqual(denied_value["status"], "INVALID")
        self.assertEqual(denied_value["error"]["code"], "CLI_ARGUMENTS_DENIED")

    def test_pin_elision_is_exactly_one_complete_inclusive_block(self):
        raw = b"prefix\n" + PIN_BEGIN_MARKER + b"generated\n" + PIN_END_MARKER + b"suffix\n"
        self.assertEqual(
            elide_pin_block(raw), b"prefix\n" + PIN_REPLACEMENT + b"suffix\n"
        )
        changed = b"changed\n" + raw
        self.assertNotEqual(elide_pin_block(changed), elide_pin_block(raw))
        hostile = (
            b"no markers",
            PIN_BEGIN_MARKER + b"partial",
            PIN_END_MARKER + b"reversed" + PIN_BEGIN_MARKER,
            b"attached" + PIN_BEGIN_MARKER + b"body\n" + PIN_END_MARKER,
            PIN_BEGIN_MARKER + b"body\nattached" + PIN_END_MARKER,
            raw + raw,
            PIN_BEGIN_MARKER + PIN_BEGIN_MARKER + PIN_END_MARKER + PIN_END_MARKER,
        )
        for candidate in hostile:
            with self.subTest(candidate=candidate), self.assertRaises(ReadinessError):
                elide_pin_block(candidate)

    def test_external_or_dynamic_imports_fail_closed(self):
        for injected in (
            b"\nimport requests\n",
            b"\n__import__('json')\n",
            b"\n_dynamic_loader = __import__\n_dynamic_loader('json')\n",
            b"\ngetattr(__builtins__, '__import__')('json')\n",
            b'\ngetattr(__builtins__, "__im" + "port__")("json")\n',
        ):
            with self.subTest(injected=injected):
                root = self.copy_inputs()
                path = root / "src" / "edgelab" / "runtime_v2_initial.py"
                path.write_bytes(path.read_bytes() + injected)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                expected = (
                    "EXTERNAL_IMPORTS_PRESENT"
                    if b"requests" in injected else "DYNAMIC_EXECUTION"
                )
                self.assertEqual(caught.exception.code, expected)

    def test_hardcoded_limits_are_derived_from_exact_comparison_shapes(self):
        root = self.copy_inputs()
        path = root / "src" / "edgelab" / "runtime_v2_initial.py"
        raw = path.read_bytes().replace(b"50_001", b"50_002")
        raw += b"\nif False:\n    _readiness_decoy = 50_001\n"
        path.write_bytes(raw)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

    def test_symlink_hardlink_and_duplicate_json_inputs_deny(self):
        root = self.copy_inputs()
        path = root / "src" / "edgelab" / "runtime_v2_codec.py"
        real = path.with_name("runtime_v2_codec_real.py")
        path.rename(real)
        path.symlink_to(real.name)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "SYMLINK_INPUT")

        root = self.copy_inputs()
        first = root / "docs/M0.3A_DEPENDENCY_CLOSURE_SHAPE.v1.md"
        second = root / "tests/test_runtime_v2_closure.py"
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        source = root / BOOTSTRAP_SCHEMAS[0][2]
        target = root / BOOTSTRAP_SCHEMAS[1][2]
        target.unlink()
        target.hardlink_to(source)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        path = root / CONTENT_ASSETS[0][2]
        path.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "DUPLICATE_JSON_KEY")

    def test_unreachable_or_case_aliased_runtime_module_denies(self):
        for name in ("runtime_v2_extra.py", "RUNTIME_V2_EXTRA.py"):
            with self.subTest(name=name):
                root = self.copy_inputs()
                (root / "src" / "edgelab" / name).write_text(
                    "# unreachable runtime module\n", encoding="utf-8"
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertIn(caught.exception.code, {
                    "RUNTIME_MODULE_INVENTORY", "RUNTIME_MODULE_CASE_ALIAS",
                })

        root = self.copy_inputs()
        extra = root / "src" / "edgelab" / "runtime_v2_extra.py"
        extra.symlink_to("missing-runtime-module.py")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RUNTIME_MODULE_INPUT")

    def test_dangling_or_case_aliased_carrier_denies(self):
        for name in ("_runtime_v2_release.py", "_RUNTIME_V2_RELEASE.PY"):
            with self.subTest(name=name):
                root = self.copy_inputs()
                carrier = root / "src" / "edgelab" / name
                carrier.symlink_to("missing-generated-carrier.py")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, "PREMATURE_PIN_CARRIER")

    def test_source_mutation_changes_inventory_without_creating_authority(self):
        root = self.copy_inputs()
        baseline = build_report(root)
        path = root / "src" / "edgelab" / "runtime_v2_codec.py"
        path.write_bytes(path.read_bytes() + b"\n# post-freeze mutation\n")
        self.assertEqual(baseline["authorizing_use"], "DENY")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertEqual(caught.exception.coordinate, "source_inputs_sha256")

    def test_resource_discovery_detects_source_schema_and_regex_bound_drift(self):
        root = self.copy_inputs()
        baseline = build_report(root)["inventory"]["resource_inventory_discovery"]

        source = root / "src" / "edgelab" / "runtime_v2_codec.py"
        source.write_bytes(
            source.read_bytes() + b"\nif len(()) > 777:\n    pass\n"
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

        root = self.copy_inputs()
        closure_schema = root / CLOSURE_SCHEMA[1]
        closure_schema.write_bytes(
            closure_schema.read_bytes().replace(
                b'"maximum": 9223372036854775807',
                b'"maximum": 9223372036854775806',
                1,
            )
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertIn(caught.exception.coordinate, {
            "schema_bound_sites_sha256", "schema_inputs_sha256",
        })

        root = self.copy_inputs()
        regex_source = root / "src" / "edgelab" / "runtime_v2_group.py"
        regex_source.write_bytes(
            regex_source.read_bytes().replace(b"{0,127}", b"{0,126}", 1)
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V2_IDENTITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites_sha256")

    def test_resource_discovery_ignores_comments_but_source_hash_does_not(self):
        root = self.copy_inputs()
        baseline = build_report(root)
        source = root / "src" / "edgelab" / "runtime_v2_codec.py"
        source.write_bytes(
            b"# nonsemantic 999 bound note\n" + source.read_bytes()
        )
        before_discovery = baseline["inventory"]["resource_inventory_discovery"]
        self.assertEqual(len(before_discovery["source_bound_sites"]), 422)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING")
        self.assertEqual(caught.exception.coordinate, "source_inputs_sha256")

    def test_partial_classification_schema_manifest_and_self_digest_are_exact(self):
        from jsonschema import Draft202012Validator

        schema = json.loads((ROOT / RESOURCE_CLASSIFICATION_SCHEMA[1]).read_text())
        manifest = json.loads((ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(manifest)), [])
        digest_value = dict(manifest)
        claimed = digest_value.pop("classification_manifest_sha256")
        expected = hashlib.sha256(
            RESOURCE_CLASSIFICATION_DOMAIN.encode("ascii")
            + json.dumps(
                digest_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assertEqual(claimed, expected)
        self.assertEqual(
            claimed,
            "44929d4058538e354d09940a671ac78306d2d03a0b101bd2ba55035c5814ff8a",
        )
        self.assertEqual(
            hashlib.sha256((ROOT / RESOURCE_CLASSIFICATION_SCHEMA[1]).read_bytes()).hexdigest(),
            "10ebe1d8aeb72c1cb69f2d6f3da0b7e3716d53a1f75c4c43e4d20b146d22eec9",
        )
        self.assertEqual(
            hashlib.sha256((ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_bytes()).hexdigest(),
            "903ce2b2bc63498bc18adfd43c03518bddd1c4d41e1c5fd94b82e2276416e9b1",
        )
        self.assertEqual(manifest["coverage_status"], "INCOMPLETE")
        self.assertEqual(manifest["generation_disposition"], "DENY")
        self.assertEqual(manifest["schema_version"], 21)
        self.assertEqual(
            manifest["profile_id"],
            "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V21",
        )
        self.assertEqual(manifest["classified_site_count"], 45)
        self.assertEqual(manifest["unclassified_site_count"], 673)
        self.assertEqual(
            [item["constraint_id"] for item in manifest["constraints"]],
            [
                "MAX_BLOB_BYTES",
                "MAX_DEPENDENCY_CLOSURE_BYTES",
                "MAX_EVENT_BYTES",
                "MAX_SCHEMA_DOCUMENT_BYTES",
                "MAX_SCHEMA_REF_NODES",
                "MAX_SCHEMA_REGISTRY_BYTES",
                "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                "MAX_ARGUMENTS",
                "_PORTABLE_PATH_MAX",
                "_PORTABLE_COMPONENT_MAX",
                "MAX_GROUP_EVENTS",
                "MAX_TASKS",
                "MAX_SCHEMA_BUNDLE_BYTES",
                "MAX_CHECKPOINT_COPIES",
                "MAX_BLOBS",
                "TABLE_MIGRATIONS_ROWS",
                "TABLE_LEGACY_ARCHIVE_ROWS",
                "TABLE_METADATA_ROWS",
            ],
        )
        event_constraint = manifest["constraints"][2]
        self.assertEqual(event_constraint["unit"], "BYTES")
        self.assertEqual(event_constraint["maximum"], 1_048_576)
        self.assertEqual(
            event_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_MEMBERS_OF_CAPTURED_RUNTIME_IMAGE_EVENTS",
        )
        self.assertEqual(
            event_constraint["definition_site_ids"],
            ["7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a"],
        )
        self.assertEqual(
            event_constraint["enforcement_site_ids"],
            ["8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534"],
        )
        self.assertEqual(
            event_constraint["semantic_function_ast_sha256"],
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
        )
        self.assertEqual(
            event_constraint["semantic_module_ast_sha256"],
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        )
        self.assertEqual(
            event_constraint["evidence_inputs"],
            [dict(item) for item in EVENT_BYTE_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][2], event_constraint
        )
        ref_constraint = manifest["constraints"][4]
        self.assertEqual(ref_constraint["unit"], "NODES")
        self.assertEqual(ref_constraint["maximum"], 4_096)
        self.assertEqual(
            ref_constraint["semantic_subject"],
            "VALID_ROOT_SCHEMA_DEFINITION_OWNER_KEYS_ADMITTED_TO_CYCLE_TRAVERSAL",
        )
        self.assertEqual(
            ref_constraint["definition_site_ids"],
            [
                "61d3dcc5d5ed733e6d561edeb43ddcc00"
                "ab2aa8fc899b09353733877ea76a721"
            ],
        )
        self.assertEqual(
            ref_constraint["enforcement_site_ids"],
            [
                "4650c76c2ae3e065cd5767e97b8a59d9"
                "17415ba1dfc73f79f0efd8b09f4f3eef"
            ],
        )
        self.assertEqual(
            ref_constraint["semantic_function_ast_sha256"],
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d",
        )
        self.assertEqual(
            ref_constraint["semantic_module_ast_sha256"],
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
        )
        self.assertEqual(
            ref_constraint["evidence_inputs"],
            [dict(item) for item in SCHEMA_REF_NODE_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][4], ref_constraint
        )
        registry_constraint = manifest["constraints"][5]
        self.assertEqual(registry_constraint["unit"], "BYTES")
        self.assertEqual(registry_constraint["maximum"], 262_144)
        self.assertEqual(
            registry_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_SCHEMA_REGISTRY_FIELDS_SUPPLIED_TO_HOST_"
            "PREFLIGHT_OR_VERIFIER_BUNDLE_INSPECTION",
        )
        self.assertEqual(
            registry_constraint["definition_site_ids"],
            [
                "4c9346726487e13663e822fd8b63e995c6066a487dfbe2b6350e051ce2440384",
                "cc9e6904b1fdb98deea9fd35ddc4ae864aa572cbf5d963addbf8cc42beae4522",
            ],
        )
        self.assertEqual(
            registry_constraint["enforcement_site_ids"],
            [
                "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                "d02eb8dbac3f0359f160e1fb6259b5a438ec699a64cca7cd05d94c5ab86b1683",
            ],
        )
        self.assertEqual(
            [item["semantic_function_ast_sha256"]
             for item in registry_constraint["semantic_bindings"]],
            [
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
                "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            ],
        )
        self.assertEqual(
            [item["semantic_module_ast_sha256"]
             for item in registry_constraint["semantic_bindings"]],
            [
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
                "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            ],
        )
        self.assertEqual(
            registry_constraint["evidence_inputs"],
            [dict(item) for item in SCHEMA_REGISTRY_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][5],
            registry_constraint,
        )
        bootstrap_constraint = manifest["constraints"][6]
        self.assertEqual(bootstrap_constraint["unit"], "BYTES")
        self.assertEqual(bootstrap_constraint["maximum"], 1_048_576)
        self.assertEqual(
            bootstrap_constraint["semantic_subject"],
            "EXACT_BUILTIN_BYTES_BOOTSTRAP_FIELDS_OR_COLLECTION_MEMBERS_"
            "ADMITTED_BY_HOST_PREFLIGHT",
        )
        self.assertEqual(
            bootstrap_constraint["definition_site_ids"],
            [
                "8927485f8c04590dc06fa8d3bffde6e82517d898ec72637dbf758e21a56996d8"
            ],
        )
        self.assertEqual(
            bootstrap_constraint["enforcement_site_ids"],
            [
                "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
            ],
        )
        self.assertEqual(
            bootstrap_constraint["semantic_function_ast_sha256"],
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
        )
        self.assertEqual(
            bootstrap_constraint["semantic_module_ast_sha256"],
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        )
        self.assertEqual(
            bootstrap_constraint["evidence_inputs"],
            [dict(item) for item in BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][6],
            bootstrap_constraint,
        )
        argument_constraint = manifest["constraints"][7]
        self.assertEqual(argument_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(argument_constraint["unit"], "ITEMS")
        self.assertEqual(argument_constraint["maximum"], 8)
        self.assertEqual(
            argument_constraint["semantic_subject"],
            "EXACT_BUILTIN_TUPLE_ARGUMENT_ITEMS_SUPPLIED_TO_"
            "TRANSITION_INTENT_CONSTRUCTION",
        )
        self.assertEqual(
            argument_constraint["accepted_equation"],
            "for each TransitionIntent construction input reaching the "
            "argument-cardinality guard: len(exact built-in tuple arguments) "
            "<= maximum",
        )
        self.assertEqual(
            argument_constraint["definition_site_ids"],
            [
                "5e7fc3b44c63b42e94213efd280dd3af90eac0beb4a2b28f600a5284f17fc3b4"
            ],
        )
        self.assertEqual(
            argument_constraint["enforcement_site_ids"],
            [
                "3d85d6c3d9c53b2d68ee976d4b159cc92ae9fd506ad608d00ff0563db5864209"
            ],
        )
        self.assertEqual(
            argument_constraint["semantic_function_ast_sha256"],
            "42b1b9103cffdc52d38f4033e71b4b750b334305b3c952d7ac7b86843bec58f7",
        )
        self.assertEqual(
            argument_constraint["semantic_module_ast_sha256"],
            "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b",
        )
        self.assertEqual(
            argument_constraint["semantic_proof"],
            {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_transition.py:"
                    "TransitionIntent.__post_init__"
                ),
                "input_binding": (
                    "EXACT_BUILTIN_TUPLE_ARGUMENTS_FIELD_AFTER_JOINT_"
                    "CONTAINER_TYPE_GUARD"
                ),
                "enforcement_order": (
                    "JOINT_ARGUMENTS_AND_SEMANTIC_EVENT_IDS_EXACT_TUPLE_"
                    "TYPE_GUARD_BEFORE_ARGUMENT_CARDINALITY_GUARD_BEFORE_"
                    "EVENT_CARDINALITY_ARGUMENT_SHAPE_ORDER_DUPLICATE_AND_"
                    "EVENT_ID_VALIDATION"
                ),
                "rejection_action": (
                    "RAISE_TRANSITION_RESOURCE_ARGUMENTS_AT_ARGUMENTS_COORDINATE"
                ),
            },
        )
        self.assertEqual(
            argument_constraint["evidence_inputs"],
            [dict(item) for item in TRANSITION_ARGUMENT_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][7],
            argument_constraint,
        )
        path_constraint = manifest["constraints"][8]
        self.assertEqual(path_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(path_constraint["unit"], "CHARACTERS")
        self.assertEqual(path_constraint["maximum"], 4_096)
        self.assertEqual(
            path_constraint["semantic_subject"],
            "EXACT_BUILTIN_STR_PORTABLE_RELATIVE_PATH_ARGUMENT_AFTER_"
            "PATH_PATTERN_VALIDATION",
        )
        self.assertEqual(
            path_constraint["definition_site_ids"],
            ["fc3a2cf8ca0ab37c1fedcfb108152b40bd65fec0207eac9cd9b3f7f32b8cfd27"],
        )
        self.assertEqual(
            path_constraint["enforcement_site_ids"],
            ["ab8d61b1084c8ac24f8b434b52065e9fc3c5dce60285fed332f3489d165b03d3"],
        )
        self.assertEqual(
            path_constraint["semantic_function_ast_sha256"],
            "d4bcf6527c507a9e580c563f57cc1d2f79b3caa8a205b0fc6fdf2c7f5cc2d806",
        )
        self.assertEqual(
            path_constraint["semantic_module_ast_sha256"],
            "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7",
        )
        self.assertEqual(
            path_constraint["evidence_inputs"],
            [dict(item) for item in PORTABLE_PATH_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][8],
            path_constraint,
        )
        component_constraint = manifest["constraints"][9]
        self.assertEqual(component_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(component_constraint["unit"], "CHARACTERS")
        self.assertEqual(component_constraint["maximum"], 255)
        self.assertEqual(
            component_constraint["semantic_subject"],
            "EXACT_SLASH_SEPARATED_COMPONENT_STRINGS_OF_EXACT_BUILTIN_"
            "STR_PATH_AFTER_PATH_PATTERN_AND_TOTAL_PATH_ADMISSION",
        )
        self.assertEqual(
            component_constraint["definition_site_ids"],
            ["9313b4636313fad249f6a01b9e4ef96f22ef88b10fa98ca95a736d0ce994c3df"],
        )
        self.assertEqual(
            component_constraint["enforcement_site_ids"],
            ["80d3960b21e42ebc549ca5eabd07e811430b1628150d9eb1e8922d491dc86072"],
        )
        self.assertEqual(
            component_constraint["evidence_inputs"],
            [dict(item) for item in PORTABLE_COMPONENT_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][9],
            component_constraint,
        )
        semantic_event_constraint = manifest["constraints"][10]
        self.assertEqual(semantic_event_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(semantic_event_constraint["unit"], "ITEMS")
        self.assertEqual(semantic_event_constraint["maximum"], 10_002)
        self.assertEqual(
            semantic_event_constraint["semantic_subject"],
            "EXACT_BUILTIN_TUPLE_SEMANTIC_EVENT_ID_ITEMS_SUPPLIED_TO_"
            "TRANSITION_INTENT_CONSTRUCTION",
        )
        self.assertEqual(
            semantic_event_constraint["definition_site_ids"],
            ["13130db6d96d447bd0bec45528c39f4354a2897e282585c7b4976335e25b025c"],
        )
        self.assertEqual(
            semantic_event_constraint["enforcement_site_ids"],
            ["6109c0c4afb317c7bde39b19501f7de6b627528dd36f967c82e2ed311fbfc0ca"],
        )
        self.assertEqual(
            semantic_event_constraint["evidence_inputs"],
            [dict(item) for item in TRANSITION_SEMANTIC_EVENT_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][10],
            semantic_event_constraint,
        )
        task_constraint = manifest["constraints"][11]
        self.assertEqual(task_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(task_constraint["unit"], "ITEMS")
        self.assertEqual(task_constraint["maximum"], 100_000)
        self.assertEqual(
            task_constraint["semantic_subject"],
            "REDUCER_STATE_EXACT_BUILTIN_TUPLE_TASK_ITEMS_OR_TRANSITION_"
            "WORKSPACE_RETAINED_TASK_KEYS_PLUS_VALIDATED_ABSENT_KEY_WRITES",
        )
        self.assertEqual(
            task_constraint["definition_site_ids"],
            ["2663812aee226be4f57a1862523798243d7df5a12a1d9e29f586ec8e7ded5638"],
        )
        self.assertEqual(
            task_constraint["enforcement_site_ids"],
            [
                "3d07b02992a995d0a13d408dda7d2acf04e1c5a9d185f98651814d6dfff2b59d",
                "0f3792a9755d878d6e5a60afd21ef8e1d38c30f3be3d59879b6cfa860754f465",
            ],
        )
        self.assertEqual(
            [item["semantic_function_ast_sha256"]
             for item in task_constraint["semantic_bindings"]],
            [
                "acfc468a2815e245ee3da5230df49c20e8dc1f2601fa24b367507e77d847a337",
                "280ca713360ad0b61cd3810999f6d0cf1ea4e31b854596bbaedb4ad03c8b12b1",
            ],
        )
        self.assertEqual(
            task_constraint["evidence_inputs"],
            [dict(item) for item in TRANSITION_TASK_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][11],
            task_constraint,
        )
        bundle_constraint = manifest["constraints"][12]
        self.assertEqual(bundle_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(bundle_constraint["unit"], "BYTES")
        self.assertEqual(bundle_constraint["maximum"], 2_097_152)
        self.assertEqual(
            bundle_constraint["semantic_subject"],
            "SCHEMA_REGISTRY_AND_ADMITTED_SCHEMA_DOCUMENT_BODY_BYTE_"
            "AGGREGATE_OR_SEPARATE_RAW_STORAGE_DESCRIPTOR_BYTES",
        )
        self.assertEqual(
            bundle_constraint["definition_site_ids"],
            [
                "18d9f6c7a27e97c092460277fc35bbf9151791127dd0da5a161a8866ef04bbcf",
                "2d673fb49e50239b37577ac23e4f6fdbf899523908d338e3618993594ab5f410",
            ],
        )
        self.assertEqual(
            bundle_constraint["enforcement_site_ids"],
            [
                "4a75bf21a088cd48d5c1b38b2b3157fc47542b0132b562be3699e94858a65c9e",
                "344713dc75b24db9402649b88570c54a438e5b3b9f17dac677b8cd4313825df4",
                "4ba11eee3bbe1d3fa772fabebf0edc386903f94c9862c242c7124b8bf0cf6cb6",
            ],
        )
        self.assertEqual(
            [item["semantic_function_ast_sha256"]
             for item in bundle_constraint["semantic_bindings"]],
            [
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
                "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
                "1742c7e8785c03ddfb26fbc3c1eb695c0daa79aa355eb77dae6b8350a373502c",
            ],
        )
        self.assertEqual(
            bundle_constraint["evidence_inputs"],
            [dict(item) for item in SCHEMA_BUNDLE_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][12],
            bundle_constraint,
        )
        checkpoint_constraint = manifest["constraints"][13]
        self.assertEqual(
            checkpoint_constraint["classification"], "RESOURCE_MAXIMUM"
        )
        self.assertEqual(checkpoint_constraint["unit"], "ITEMS")
        self.assertEqual(checkpoint_constraint["maximum"], 49_999)
        self.assertEqual(
            checkpoint_constraint["semantic_subject"],
            "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_RUNTIME_IMAGE_"
            "CHECKPOINT_COPIES",
        )
        self.assertEqual(
            checkpoint_constraint["definition_site_ids"],
            ["4c738024dfcbda75cf4c6a621c2b51624a9278bb5b4e10b912c43f1dbd5be208"],
        )
        self.assertEqual(
            checkpoint_constraint["enforcement_site_ids"],
            ["e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13"],
        )
        self.assertEqual(
            checkpoint_constraint["evidence_inputs"],
            [dict(item) for item in CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][13],
            checkpoint_constraint,
        )
        blob_cardinality_constraint = manifest["constraints"][14]
        self.assertEqual(
            blob_cardinality_constraint["classification"], "RESOURCE_MAXIMUM"
        )
        self.assertEqual(blob_cardinality_constraint["unit"], "ITEMS")
        self.assertEqual(blob_cardinality_constraint["maximum"], 300_000)
        self.assertEqual(
            blob_cardinality_constraint["semantic_subject"],
            "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_RUNTIME_IMAGE_BLOBS",
        )
        self.assertEqual(
            blob_cardinality_constraint["definition_site_ids"],
            ["d59dabf071e0d9cce0c5d6e1478ce6aa55a09362b85136709a4df94bf19966e0"],
        )
        self.assertEqual(
            blob_cardinality_constraint["enforcement_site_ids"],
            ["9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3"],
        )
        self.assertEqual(
            blob_cardinality_constraint["evidence_inputs"],
            [dict(item) for item in BLOB_CARDINALITY_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][14],
            blob_cardinality_constraint,
        )
        migrations_constraint = manifest["constraints"][15]
        migrations_site = (
            "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a"
        )
        self.assertEqual(migrations_constraint["constraint_id"], "TABLE_MIGRATIONS_ROWS")
        self.assertEqual(migrations_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(migrations_constraint["unit"], "ITEMS")
        self.assertEqual(migrations_constraint["maximum"], 0)
        self.assertEqual(migrations_constraint["definition_site_ids"], [migrations_site])
        self.assertEqual(migrations_constraint["enforcement_site_ids"], [migrations_site])
        self.assertEqual(
            len(set(
                migrations_constraint["definition_site_ids"]
                + migrations_constraint["enforcement_site_ids"]
            )),
            1,
        )
        self.assertEqual(
            migrations_constraint["evidence_inputs"],
            [dict(item) for item in MIGRATIONS_TABLE_ROW_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][15],
            migrations_constraint,
        )
        legacy_archive_constraint = manifest["constraints"][16]
        legacy_archive_site = (
            "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18"
        )
        self.assertEqual(
            legacy_archive_constraint["constraint_id"],
            "TABLE_LEGACY_ARCHIVE_ROWS",
        )
        self.assertEqual(
            legacy_archive_constraint["classification"], "RESOURCE_MAXIMUM"
        )
        self.assertEqual(legacy_archive_constraint["unit"], "ITEMS")
        self.assertEqual(legacy_archive_constraint["maximum"], 1)
        self.assertEqual(
            legacy_archive_constraint["definition_site_ids"],
            [legacy_archive_site],
        )
        self.assertEqual(
            legacy_archive_constraint["enforcement_site_ids"],
            [legacy_archive_site],
        )
        self.assertEqual(
            len(set(
                legacy_archive_constraint["definition_site_ids"]
                + legacy_archive_constraint["enforcement_site_ids"]
            )),
            1,
        )
        self.assertEqual(
            legacy_archive_constraint["evidence_inputs"],
            [dict(item) for item in LEGACY_ARCHIVE_TABLE_ROW_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][16],
            legacy_archive_constraint,
        )
        metadata_constraint = manifest["constraints"][17]
        metadata_site = (
            "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"
        )
        self.assertEqual(
            metadata_constraint["constraint_id"], "TABLE_METADATA_ROWS"
        )
        self.assertEqual(metadata_constraint["classification"], "RESOURCE_MAXIMUM")
        self.assertEqual(metadata_constraint["unit"], "ITEMS")
        self.assertEqual(metadata_constraint["maximum"], 1)
        self.assertEqual(metadata_constraint["definition_site_ids"], [metadata_site])
        self.assertEqual(metadata_constraint["enforcement_site_ids"], [metadata_site])
        self.assertEqual(
            len(set(
                metadata_constraint["definition_site_ids"]
                + metadata_constraint["enforcement_site_ids"]
            )),
            1,
        )
        self.assertEqual(
            metadata_constraint["evidence_inputs"],
            [dict(item) for item in METADATA_TABLE_ROW_RESOURCE_EVIDENCE],
        )
        self.assertEqual(
            schema["properties"]["constraints"]["const"][17],
            metadata_constraint,
        )
        self.assertEqual(
            manifest["predecessor_manifest"]["path"],
            "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v20.json",
        )
        self.assertEqual(
            manifest["predecessor_schema"]["path"],
            "schemas/m0-3a-runtime-v2-resource-classification.v20.schema.json",
        )
        self.assertEqual(
            [item["path"] for item in RESOURCE_CLASSIFICATION_ANCESTORS],
            [
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v19.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v19.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v18.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v18.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v17.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v17.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v16.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v16.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v15.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v15.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v14.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v14.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v13.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v13.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v12.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v12.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v11.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v11.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v10.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v10.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v9.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v9.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v8.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v8.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v7.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v7.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v6.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v6.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v5.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v5.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v4.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v4.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v3.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v3.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v2.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v2.schema.json",
                "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v1.json",
                "schemas/m0-3a-runtime-v2-resource-classification.v1.schema.json",
            ],
        )

    def test_partial_classification_rejects_hostile_manifest_mutations(self):
        mutations = (
            ("coverage_status", "COMPLETE"),
            ("generation_disposition", "ALLOW"),
            ("classified_site_count", 690),
            ("unclassified_site_count", 0),
            ("source_inputs_sha256", "0" * 64),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                root = self.copy_inputs()
                path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
                self.rewrite_manifest(
                    root, lambda manifest: manifest.__setitem__(key, value)
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING"
                )

        root = self.copy_inputs()
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        raw = path.read_bytes().replace(
            b'"schema_version": 21', b'"schema_version": 21, "schema_version": 21'
        )
        path.write_bytes(raw)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "DUPLICATE_JSON_KEY")

        root = self.copy_inputs()
        path = root / RESOURCE_CLASSIFICATION_MANIFEST[1]
        manifest = json.loads(path.read_text(encoding="ascii"))
        manifest["classification_manifest_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="ascii")
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_SELF_DIGEST")

        ref_constraint_mutations = (
            ("unit", "BYTES"),
            ("maximum", 4_095),
            ("semantic_function_ast_sha256", "0" * 64),
            ("semantic_module_ast_sha256", "1" * 64),
            (
                "definition_site_ids",
                ["2" * 64],
            ),
            (
                "enforcement_site_ids",
                ["3" * 64],
            ),
        )
        for field, hostile_value in ref_constraint_mutations:
            with self.subTest(ref_constraint=field):
                root = self.copy_inputs()

                def alter_ref_constraint(manifest):
                    manifest["constraints"][4][field] = hostile_value

                self.rewrite_manifest(root, alter_ref_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        bootstrap_constraint_mutations = (
            ("maximum", 1_048_575),
            ("definition_site_ids", ["4" * 64]),
            ("enforcement_site_ids", ["5" * 64]),
            ("semantic_function_ast_sha256", "6" * 64),
            ("semantic_module_ast_sha256", "7" * 64),
            ("semantic_proof", {}),
            ("evidence_inputs", []),
        )
        for field, hostile_value in bootstrap_constraint_mutations:
            with self.subTest(bootstrap_constraint=field):
                root = self.copy_inputs()

                def alter_bootstrap_constraint(manifest):
                    manifest["constraints"][6][field] = hostile_value

                self.rewrite_manifest(root, alter_bootstrap_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        argument_constraint_mutations = (
            ("maximum", 7),
            ("semantic_subject", "WRONG_ARGUMENT_SUBJECT"),
            ("accepted_equation", "len(anything) <= 8"),
            ("definition_site_ids", ["8" * 64]),
            ("enforcement_site_ids", ["9" * 64]),
            ("semantic_function_ast_sha256", "a" * 64),
            ("semantic_module_ast_sha256", "b" * 64),
            ("semantic_proof", {}),
            ("evidence_inputs", []),
        )
        for field, hostile_value in argument_constraint_mutations:
            with self.subTest(argument_constraint=field):
                root = self.copy_inputs()

                def alter_argument_constraint(manifest):
                    manifest["constraints"][7][field] = hostile_value

                self.rewrite_manifest(root, alter_argument_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        checkpoint_constraint_mutations = (
            ("maximum", 49_998),
            ("semantic_subject", "WRONG_CHECKPOINT_COPY_SUBJECT"),
            ("accepted_equation", "len(anything) <= 49999"),
            ("definition_site_ids", ["c" * 64]),
            ("enforcement_site_ids", ["d" * 64]),
            ("semantic_function_ast_sha256", "e" * 64),
            ("semantic_module_ast_sha256", "f" * 64),
            ("semantic_proof", {}),
            ("evidence_inputs", []),
        )
        for field, hostile_value in checkpoint_constraint_mutations:
            with self.subTest(checkpoint_constraint=field):
                root = self.copy_inputs()

                def alter_checkpoint_constraint(manifest):
                    manifest["constraints"][13][field] = hostile_value

                self.rewrite_manifest(root, alter_checkpoint_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        blob_cardinality_constraint_mutations = (
            ("maximum", 299_999),
            ("semantic_subject", "WRONG_TOP_LEVEL_BLOB_SUBJECT"),
            ("accepted_equation", "len(anything) <= 300000"),
            ("definition_site_ids", ["0" * 64]),
            ("enforcement_site_ids", ["1" * 64]),
            ("semantic_function_ast_sha256", "2" * 64),
            ("semantic_module_ast_sha256", "3" * 64),
            ("semantic_proof", {}),
            ("evidence_inputs", []),
        )
        for field, hostile_value in blob_cardinality_constraint_mutations:
            with self.subTest(blob_cardinality_constraint=field):
                root = self.copy_inputs()

                def alter_blob_cardinality_constraint(manifest):
                    manifest["constraints"][14][field] = hostile_value

                self.rewrite_manifest(root, alter_blob_cardinality_constraint)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

        root = self.copy_inputs()
        self.rewrite_manifest(
            root,
            lambda manifest: manifest["constraints"][0].__setitem__(
                "maximum", 16_777_215
            ),
        )
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT")

        for mutation in ("reordered", "duplicated"):
            with self.subTest(constraints=mutation):
                root = self.copy_inputs()

                def alter(manifest):
                    constraints = manifest["constraints"]
                    manifest["constraints"] = (
                        list(reversed(constraints))
                        if mutation == "reordered"
                        else [constraints[0], constraints[0]]
                    )

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    (
                        "RESOURCE_CLASSIFICATION_CONSTRAINT"
                        if mutation == "reordered"
                        else "RESOURCE_CLASSIFICATION_CONSTRAINTS"
                    ),
                )

    def test_partial_classification_binds_schema_and_evidence_bytes(self):
        root = self.copy_inputs()
        schema = root / RESOURCE_CLASSIFICATION_SCHEMA[1]
        schema.write_bytes(schema.read_bytes().replace(
            b'"const": "INCOMPLETE"',
            b'"const": "COMPLETE"',
            1,
        ))
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SCHEMA_IDENTITY"
        )

        for evidence_path in (item["path"] for item in RESOURCE_CLASSIFICATION_EVIDENCE):
            with self.subTest(evidence=evidence_path):
                root = self.copy_inputs()
                evidence = root / evidence_path
                evidence.write_bytes(evidence.read_bytes() + b"\nmutation")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_EVIDENCE_IDENTITY",
                )

        root = self.copy_inputs()
        evidence = root / "docs/M0.3A_DEPENDENCY_CLOSURE_SHAPE.v1.md"
        evidence.unlink()
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "PATH_CASE_ALIAS")

        root = self.copy_inputs()
        evidence = root / "tests/test_runtime_v2_closure.py"
        real = evidence.with_name("test_runtime_v2_closure_real.py")
        evidence.rename(real)
        evidence.symlink_to(real.name)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "SYMLINK_INPUT")

        for predecessor in (
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA,
            *RESOURCE_CLASSIFICATION_ANCESTORS,
        ):
            with self.subTest(predecessor=predecessor["path"]):
                root = self.copy_inputs()
                path = root / predecessor["path"]
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_PREDECESSOR_IDENTITY",
                )

        root = self.copy_inputs()
        first = root / BLOB_RESOURCE_EVIDENCE[0]["path"]
        second = root / BLOB_RESOURCE_EVIDENCE[1]["path"]
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

        root = self.copy_inputs()
        first = root / SCHEMA_REF_NODE_RESOURCE_EVIDENCE[0]["path"]
        second = root / SCHEMA_REF_NODE_RESOURCE_EVIDENCE[1]["path"]
        second.unlink()
        second.hardlink_to(first)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "HARDLINK_INPUT_ALIAS")

    def test_partial_classification_binds_full_enforcement_function_context(self):
        for old, new in (
            (
                b"    if type(raw) is not bytes:\n        _fail(\"BYTES_REQUIRED\", \"/\")\n",
                b"",
            ),
            (
                b"    if len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES:\n"
                b"        _fail(\"BYTE_LIMIT\", \"/\")\n",
                b"    if False:\n"
                b"        if len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES:\n"
                b"            _fail(\"BYTE_LIMIT\", \"/\")\n",
            ),
        ):
            with self.subTest(mutation=old[:30]):
                root = self.copy_inputs()
                baseline = build_report(root)
                source = root / "src/edgelab/runtime_v2_closure.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                source_inputs = [
                    dict(item) for item in baseline["inventory"][
                        "resource_inventory_discovery"
                    ]["source_inputs"]
                ]
                for item in source_inputs:
                    if item["path"] == "src/edgelab/runtime_v2_closure.py":
                        item["byte_length"] = len(mutated)
                        item["raw_sha256"] = hashlib.sha256(mutated).hexdigest()
                refreshed = hashlib.sha256(
                    RESOURCE_SOURCE_INPUT_DOMAIN.encode("ascii")
                    + json.dumps(
                        source_inputs, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                ).hexdigest()
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_inputs_sha256", refreshed
                    ),
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        for old, new in (
            (
                b"def _fail(code: str, coordinate: str) -> None:\n"
                b"    raise ClosureValidationError(code, coordinate)\n",
                b"def _fail(code: str, coordinate: str) -> None:\n"
                b"    return None\n",
            ),
            (b"\n__all__ = (", b"\nlen = lambda value: False\n\n__all__ = ("),
        ):
            with self.subTest(transitive_mutation=old[:30]):
                root = self.copy_inputs()
                baseline = build_report(root)
                source = root / "src/edgelab/runtime_v2_closure.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                source_inputs = [
                    dict(item) for item in baseline["inventory"][
                        "resource_inventory_discovery"
                    ]["source_inputs"]
                ]
                for item in source_inputs:
                    if item["path"] == "src/edgelab/runtime_v2_closure.py":
                        item["byte_length"] = len(mutated)
                        item["raw_sha256"] = hashlib.sha256(mutated).hexdigest()
                refreshed = _domain_digest(
                    RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
                )
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_inputs_sha256", refreshed
                    ),
                )
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                )

    def test_partial_classification_rejects_refreshed_census_cardinality(self):
        root = self.copy_inputs()
        source_path = root / "src/edgelab/runtime_v2_codec.py"
        source_path.write_bytes(
            source_path.read_bytes() + b"\nif len(()) > 777:\n    pass\n"
        )
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_DISCOVERY_V1_CARDINALITY")
        self.assertEqual(caught.exception.coordinate, "source_bound_sites")

    def test_blob_classification_binds_site_function_and_module_semantics(self):
        attacks = (
            (
                b"if len(body) > MAX_BLOB_BYTES:",
                b"if len(body) >= MAX_BLOB_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b'findings.add("IMAGE_ITEM_BYTE_LIMIT", "blobs", ',
                b'findings.add("WRONG_LIMIT", "blobs", ',
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                b"\n__all__ = (",
                b"\nlen = lambda value: False\n\n__all__ = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"if len(body) > MAX_BLOB_BYTES:",
                b"if False and len(body) > MAX_BLOB_BYTES:",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                b"        finding = ImageViolation(code, artifact, coordinate)\n",
                b"        return\n        finding = ImageViolation(code, artifact, coordinate)\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"        items = list(self._items)\n",
                b"        return ()\n        items = list(self._items)\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                b'            body = record_values["canonical_json"]\n'
                b'            if type(body) is not bytes:\n'
                b'                findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs",',
                b'            body = record_values["canonical_json"]\n'
                b'            body = body[:True]\n'
                b'            if type(body) is not bytes:\n'
                b'                findings.add("IMAGE_RECORD_FIELD_TYPE", "blobs",',
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:32]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertIn(
                    caught.exception.code,
                    {expected_code, "RESOURCE_ROW_CAP_BINDING_MODULE_AST"},
                )

    def test_event_byte_classification_binds_definition_binding_and_evidence(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_EVENT_BYTES = 1_048_576",
            b"MAX_EVENT_BYTES = 1_048_575",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_MAXIMUM")

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("events", captured["events"], MAX_EVENT_BYTES)',
            b'("events", captured["events"], MAX_BOOTSTRAP_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(caught.exception.code, "RESOURCE_BINDING_ASSIGNMENT_AST")

        # Even if an attacker refreshes the ordinary V2 census and the V8
        # manifest after semantic source drift, the classification's exact
        # definition and enforcement-site identities remain independently
        # pinned.
        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_EVENT_BYTES = 1_048_576",
            b"MAX_EVENT_BYTES = 1_048_575 + 1",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, baseline_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("events", captured["events"], MAX_EVENT_BYTES)',
            b'("events", captured["events"], MAX_BOOTSTRAP_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        hostile_binding_sites = [dict(item) for item in baseline_binding_sites]
        hostile_event_site = next(
            item for item in hostile_binding_sites
            if item.get("branch_key") == "events"
        )
        hostile_event_site.update({
            "ast_sha256": "f" * 64,
            "expression": (
                "('events', captured['events'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "site_id": "e" * 64,
            "table_assignment_ast_sha256": "d" * 64,
        })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, hostile_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        for suffix in (
            b"\n\ndef _event_limit_extra_read():\n"
            b"    return MAX_EVENT_BYTES\n",
            b"\n\ndef _event_limit_extra_store():\n"
            b"    MAX_EVENT_BYTES = 1\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertIn(
                    caught.exception.code,
                    {
                        "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                        "RESOURCE_ROW_CAP_BINDING_MODULE_AST",
                    },
                )

        semantic_attacks = (
            (
                b'            if len(value) > maximum:\n'
                b'                findings.add("IMAGE_ITEM_BYTE_LIMIT", name, coordinate)\n',
                b'            if len(value) > maximum:\n'
                b'                findings.add("WRONG_EVENT_LIMIT", name, coordinate)\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
                False,
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
        )
        for old, new, expected_code, binding_extractor_drift in semantic_attacks:
            with self.subTest(event_semantics=old[:32]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    if binding_extractor_drift:
                        self.build_with_refreshed_ordinary_source_bindings(
                            root, baseline_binding_sites
                        )
                    else:
                        self.refresh_source_bindings(root)
                        build_report(root)
                self.assertIn(
                    caught.exception.code,
                    {expected_code, "RESOURCE_ROW_CAP_BINDING_MODULE_AST"},
                )

    def test_checkpoint_copy_classification_survives_attacker_census_refresh(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        predecessor_sites = _source_bound_inventory(baseline_source_bytes)
        table_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, predecessor_sites
        )
        baseline_cardinality_sites = (
            _source_bound_cardinality_binding_inventory(
                baseline_source_bytes,
                predecessor_sites + table_binding_sites,
            )
        )

        def hostile_sites(**updates):
            sites = [dict(item) for item in baseline_cardinality_sites]
            checkpoint = next(
                item for item in sites
                if item.get("branch_key") == "checkpoint_copies"
            )
            checkpoint.update(updates)
            return sites

        attacks = (
            (
                b"MAX_CHECKPOINT_COPIES = 49_999",
                b"MAX_CHECKPOINT_COPIES = 49_998 + 1",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b"MAX_CHECKPOINT_COPIES = 49_999",
                b"MAX_CHECKPOINT_COPIES = 49_998",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("checkpoint_copies", 0, MAX_CHECKPOINT_COPIES)',
                b'("checkpoint_copies", 0, MAX_BLOBS)',
                hostile_sites(
                    maximum_expression="MAX_BLOBS",
                    expression="('checkpoint_copies', 0, MAX_BLOBS)",
                    ast_sha256="a" * 64,
                    site_id="b" * 64,
                    table_assignment_ast_sha256="c" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("checkpoint_copies", 0, MAX_CHECKPOINT_COPIES)',
                b'("checkpoint_copies", 0, 49_999)',
                hostile_sites(
                    maximum_expression="49999",
                    expression="('checkpoint_copies', 0, 49999)",
                    ast_sha256="d" * 64,
                    site_id="e" * 64,
                    table_assignment_ast_sha256="f" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("checkpoint_copies", captured["checkpoint_copies"]),',
                b'("checkpoint_copies", captured["selector_history"]),',
                hostile_sites(
                    subject_binding="captured['selector_history']",
                    subject_row_ast_sha256="1" * 64,
                    subject_table_assignment_ast_sha256="2" * 64,
                    site_id="3" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                None,
                b"\n\ndef _checkpoint_extra_load():\n"
                b"    return MAX_CHECKPOINT_COPIES\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
            ),
            (
                None,
                b"\n\ndef _checkpoint_extra_store():\n"
                b"    MAX_CHECKPOINT_COPIES = 1\n"
                b"    return None\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
            ),
            (
                b"        valid = minimum <= len(value) <= maximum",
                b"        valid = minimum <= len(value) <= maximum or True",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")',
                b'            findings.add("WRONG_CARDINALITY_LIMIT", name, "/")',
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                None,
                b"\nlen = sum\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                None,
                b"\ntype = len\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, attacker_sites, expected_code in attacks:
            with self.subTest(attack=new[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = (
                    original + new
                    if old is None else original.replace(old, new, 1)
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_attacker_refreshed_v3_bindings(
                        root, [dict(item) for item in attacker_sites]
                    )
                self.assertEqual(caught.exception.code, expected_code)

        for field, hostile_value in (
            (
                "semantic_proof",
                {
                    "function_coordinate": "wrong",
                    "input_binding": "wrong",
                    "enforcement_order": "wrong",
                    "rejection_action": "wrong",
                },
            ),
            ("evidence_inputs", []),
        ):
            with self.subTest(manifest_field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest["constraints"][-1][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

    def test_blob_cardinality_classification_survives_attacker_census_refresh(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        predecessor_sites = _source_bound_inventory(baseline_source_bytes)
        table_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, predecessor_sites
        )
        baseline_cardinality_sites = (
            _source_bound_cardinality_binding_inventory(
                baseline_source_bytes,
                predecessor_sites + table_binding_sites,
            )
        )

        def hostile_sites(**updates):
            sites = [dict(item) for item in baseline_cardinality_sites]
            blobs = next(
                item for item in sites if item.get("branch_key") == "blobs"
            )
            blobs.update(updates)
            return sites

        invalid_branch = (
            b'        if not valid:\n'
            b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")\n'
            b'            accounting_complete = False\n'
        )
        attacks = (
            (
                b"MAX_BLOBS = 300_000",
                b"MAX_BLOBS = 299_999 + 1",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b"MAX_BLOBS = 300_000",
                b"MAX_BLOBS = 299_999",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("blobs", 0, MAX_BLOBS)',
                b'("blobs", 0, MAX_CHECKPOINT_COPIES)',
                hostile_sites(
                    maximum_expression="MAX_CHECKPOINT_COPIES",
                    expression="('blobs', 0, MAX_CHECKPOINT_COPIES)",
                    ast_sha256="a" * 64,
                    site_id="b" * 64,
                    table_assignment_ast_sha256="c" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("blobs", 0, MAX_BLOBS)',
                b'("blobs", 0, 300_000)',
                hostile_sites(
                    maximum_expression="300000",
                    expression="('blobs', 0, 300000)",
                    ast_sha256="d" * 64,
                    site_id="e" * 64,
                    table_assignment_ast_sha256="f" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                b'("blobs", captured["blobs"]),',
                b'("blobs", captured["events"]),',
                hostile_sites(
                    subject_binding="captured['events']",
                    subject_row_ast_sha256="1" * 64,
                    subject_table_assignment_ast_sha256="2" * 64,
                    site_id="3" * 64,
                ),
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                None,
                b"\n\ndef _blob_count_extra_load():\n    return MAX_BLOBS\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
            ),
            (
                None,
                b"\n\ndef _blob_count_extra_store():\n"
                b"    MAX_BLOBS = 1\n    return None\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
            ),
            (
                b"        valid = minimum <= len(value) <= maximum",
                b"        valid = minimum <= len(value) <= maximum or True",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                invalid_branch,
                invalid_branch.replace(
                    b"            accounting_complete = False\n", b"            pass\n"
                ),
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'    if cardinality_valid.get("blobs", False):',
                b"    if True:",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    if not violations:\n        sanitized_image = RuntimeImage(",
                b"    if True:\n        sanitized_image = RuntimeImage(",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'            findings.add("IMAGE_CARDINALITY_LIMIT", name, "/")',
                b'            findings.add("WRONG_CARDINALITY_LIMIT", name, "/")',
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                None,
                b"\nlen = sum\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                None,
                b"\ntype = len\n",
                baseline_cardinality_sites,
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, attacker_sites, expected_code in attacks:
            with self.subTest(attack=new[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = (
                    original + new
                    if old is None else original.replace(old, new, 1)
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_attacker_refreshed_v3_bindings(
                        root, [dict(item) for item in attacker_sites]
                    )
                self.assertEqual(caught.exception.code, expected_code)

        for field, hostile_value in (
            (
                "semantic_proof",
                {
                    "function_coordinate": "wrong",
                    "input_binding": "wrong",
                    "enforcement_order": "wrong",
                    "rejection_action": "wrong",
                },
            ),
            ("evidence_inputs", []),
        ):
            with self.subTest(manifest_field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest["constraints"][-1][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

    def test_bootstrap_document_classification_binds_all_five_branches(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        image_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_image.py"
        ]
        tree = ast.parse(image_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_BOOTSTRAP_DOCUMENT_BYTES"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_BOOTSTRAP_DOCUMENT_BYTES"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 5)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_BOOTSTRAP_DOCUMENT_BYTES = 1_048_576",
            b"MAX_BOOTSTRAP_DOCUMENT_BYTES = 1_048_575 + 1",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, baseline_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        row_attacks = (
            (
                "verifier_dependency_closure",
                b'("verifier_dependency_closure", '
                b'captured["verifier_dependency_closure"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("verifier_dependency_closure", '
                b'captured["verifier_dependency_closure"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "manifest",
                b'("manifest", captured["manifest"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("manifest", captured["manifest"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "attachment",
                b'("attachment", captured["attachment"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("attachment", captured["attachment"], MAX_EVENT_BYTES)',
                "byte_fields",
            ),
            (
                "checkpoint_copies",
                b'("checkpoint_copies", captured["checkpoint_copies"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("checkpoint_copies", captured["checkpoint_copies"], '
                b'MAX_EVENT_BYTES)',
                "byte_collections",
            ),
            (
                "selector_history",
                b'("selector_history", captured["selector_history"], '
                b'MAX_BOOTSTRAP_DOCUMENT_BYTES)',
                b'("selector_history", captured["selector_history"], '
                b'MAX_EVENT_BYTES)',
                "byte_collections",
            ),
        )
        for branch, old, new, table_name in row_attacks:
            with self.subTest(row=branch):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                hostile_sites = [dict(item) for item in baseline_binding_sites]
                for index, item in enumerate(hostile_sites):
                    if item.get("table_name") != table_name:
                        continue
                    item["site_id"] = hashlib.sha256(
                        f"bootstrap-{branch}-{index}".encode("ascii")
                    ).hexdigest()
                    item["table_assignment_ast_sha256"] = hashlib.sha256(
                        f"bootstrap-table-{branch}".encode("ascii")
                    ).hexdigest()
                hostile = next(
                    item for item in hostile_sites
                    if item.get("branch_key") == branch
                )
                hostile.update({
                    "ast_sha256": hashlib.sha256(
                        f"bootstrap-row-{branch}".encode("ascii")
                    ).hexdigest(),
                    "expression": hostile["expression"].replace(
                        "MAX_BOOTSTRAP_DOCUMENT_BYTES", "MAX_EVENT_BYTES"
                    ),
                    "maximum_expression": "MAX_EVENT_BYTES",
                })
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, hostile_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        structural_attacks = (
            (
                "byte_fields_comparator",
                b"if maximum is not None and len(value) > maximum:",
                b"if maximum is not None and len(value) >= maximum:",
                "byte_fields",
            ),
            (
                "byte_collections_comparator",
                b"if len(value) > maximum:",
                b"if len(value) >= maximum:",
                "byte_collections",
            ),
            (
                "byte_fields_loop",
                b"for name, value, maximum in byte_fields:",
                b"for name, value, maximum in tuple(byte_fields):",
                "byte_fields",
            ),
            (
                "byte_collections_loop",
                b"for name, values, maximum in byte_collections:",
                b"for name, values, maximum in tuple(byte_collections):",
                "byte_collections",
            ),
        )
        for label, old, new, table_name in structural_attacks:
            with self.subTest(structure=label):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                hostile_sites = [dict(item) for item in baseline_binding_sites]
                for index, item in enumerate(hostile_sites):
                    if item.get("table_name") != table_name:
                        continue
                    item.update({
                        "comparator_site_id": hashlib.sha256(
                            f"{label}-comparator".encode("ascii")
                        ).hexdigest(),
                        "loop_ast_sha256": hashlib.sha256(
                            f"{label}-loop".encode("ascii")
                        ).hexdigest(),
                        "site_id": hashlib.sha256(
                            f"{label}-site-{index}".encode("ascii")
                        ).hexdigest(),
                    })
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, hostile_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _bootstrap_limit_extra_read():\n"
            b"    return MAX_BOOTSTRAP_DOCUMENT_BYTES\n",
            b"\n\ndef _bootstrap_limit_extra_store():\n"
            b"    MAX_BOOTSTRAP_DOCUMENT_BYTES = 1\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertIn(
                    caught.exception.code,
                    {
                        "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                        "RESOURCE_ROW_CAP_BINDING_MODULE_AST",
                    },
                )

        semantic_attacks = (
            (
                b'            findings.add("IMAGE_ITEM_BYTE_LIMIT", name, "/")\n',
                b'            findings.add("WRONG_BOOTSTRAP_LIMIT", name, "/")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'                findings.add("IMAGE_ITEM_BYTE_LIMIT", name, coordinate)\n',
                b'                findings.add("WRONG_BOOTSTRAP_LIMIT", name, coordinate)\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in semantic_attacks:
            with self.subTest(semantic_attack=old[:40]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_image.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(caught.exception.code, expected_code)

    def test_schema_registry_classification_binds_both_implementations(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        # Equal-valued rewrites must not acquire semantic authority merely by
        # refreshing the ordinary discovery census and classification digest.
        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(same_value_definition=relative):
                root = self.copy_inputs()
                source = root / relative
                original = source.read_bytes()
                mutated = original.replace(
                    b"MAX_SCHEMA_REGISTRY_BYTES = 262_144",
                    b"MAX_SCHEMA_REGISTRY_BYTES = 131_072 + 131_072",
                    1,
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'("schema_registry", captured["schema_registry"], '
            b'MAX_SCHEMA_REGISTRY_BYTES)',
            b'("schema_registry", captured["schema_registry"], '
            b'MAX_SCHEMA_DOCUMENT_BYTES)',
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        hostile_binding_sites = [dict(item) for item in baseline_binding_sites]
        for index, item in enumerate(hostile_binding_sites):
            if item.get("table_name") != "byte_fields":
                continue
            item["site_id"] = hashlib.sha256(
                f"hostile-registry-row-{index}".encode("ascii")
            ).hexdigest()
            item["table_assignment_ast_sha256"] = "c" * 64
        hostile_registry_site = next(
            item for item in hostile_binding_sites
            if item.get("branch_key") == "schema_registry"
        )
        hostile_registry_site.update({
            "ast_sha256": "a" * 64,
            "expression": (
                "('schema_registry', captured['schema_registry'], "
                "MAX_SCHEMA_DOCUMENT_BYTES)"
            ),
            "maximum_expression": "MAX_SCHEMA_DOCUMENT_BYTES",
            "site_id": "b" * 64,
        })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, hostile_binding_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_image.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"if maximum is not None and len(value) > maximum:",
            b"if maximum is not None and len(value) >= maximum:",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        refreshed_comparator_sites = [
            dict(item) for item in baseline_binding_sites
        ]
        for index, item in enumerate(refreshed_comparator_sites):
            if item.get("table_name") != "byte_fields":
                continue
            item.update({
                "comparator_site_id": f"{index + 1:x}" * 64,
                "loop_ast_sha256": f"{index + 2:x}" * 64,
                "site_id": f"{index + 3:x}" * 64,
            })
        with self.assertRaises(ReadinessError) as caught:
            self.build_with_refreshed_ordinary_source_bindings(
                root, refreshed_comparator_sites
            )
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_SITE_MISSING"
        )

        verifier_site_attacks = (
            (
                b"len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES",
                b"len(image.schema_registry) > MAX_SCHEMA_DOCUMENT_BYTES",
            ),
            (
                b"len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES",
                b"len(image.schema_registry) >= MAX_SCHEMA_REGISTRY_BYTES",
            ),
        )
        for old, new in verifier_site_attacks:
            with self.subTest(verifier_enforcement=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_verifier.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for relative, suffix in (
            (
                "src/edgelab/runtime_v2_image.py",
                b"\n\ndef _registry_limit_extra_read():\n"
                b"    return MAX_SCHEMA_REGISTRY_BYTES\n",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"\n\ndef _registry_limit_extra_store():\n"
                b"    MAX_SCHEMA_REGISTRY_BYTES = 1\n"
                b"    return None\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n\ndef _registry_limit_extra_read():\n"
                b"    return MAX_SCHEMA_REGISTRY_BYTES\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n\ndef _registry_limit_extra_store():\n"
                b"    MAX_SCHEMA_REGISTRY_BYTES = 1\n"
                b"    return None\n",
            ),
        ):
            with self.subTest(name_cardinality=(relative, suffix.splitlines()[2])):
                root = self.copy_inputs()
                source = root / relative
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    (
                        "RESOURCE_ROW_CAP_BINDING_MODULE_AST"
                        if relative == "src/edgelab/runtime_v2_image.py"
                        else "RESOURCE_CLASSIFICATION_NAME_CARDINALITY"
                    ),
                )

        semantic_attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b"if maximum is not None and len(value) > maximum:",
                b"if maximum is not None and len(value) >= maximum:",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"        if maximum is not None and len(value) > maximum:\n"
                b'            findings.add("IMAGE_ITEM_BYTE_LIMIT", name, "/")\n',
                b"        if maximum is not None and len(value) > maximum:\n"
                b'            findings.add("WRONG_REGISTRY_LIMIT", name, "/")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                True,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"    if not violations:\n",
                b"    if True:\n",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
                False,
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'_finding("SCHEMA_REGISTRY_TOO_LARGE", "schema_registry", "/")',
                b'_finding("WRONG_REGISTRY_LIMIT", "schema_registry", "/")',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'        findings.append(_finding("SCHEMA_REGISTRY_TOO_LARGE", '
                b'"schema_registry", "/"))\n'
                b"        return findings, False\n",
                b'        findings.append(_finding("SCHEMA_REGISTRY_TOO_LARGE", '
                b'"schema_registry", "/"))\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                False,
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                False,
            ),
        )
        for relative, old, new, expected_code, binding_extractor_drift in (
            semantic_attacks
        ):
            with self.subTest(registry_semantics=(relative, old[:32])):
                root = self.copy_inputs()
                source = root / relative
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    if binding_extractor_drift:
                        self.build_with_refreshed_ordinary_source_bindings(
                            root, baseline_binding_sites
                        )
                    else:
                        self.refresh_source_bindings(root)
                        build_report(root)
                self.assertIn(
                    caught.exception.code,
                    {
                        expected_code,
                        "RESOURCE_ROW_CAP_BINDING_MODULE_AST",
                    },
                )

        for field, hostile_value in (
            ("semantic_bindings", []),
            ("evidence_inputs", []),
        ):
            with self.subTest(manifest_field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest["constraints"][5][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_CONSTRAINT"
                )

    def test_schema_document_classification_binds_both_implementations(self):
        attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b"if body_size > MAX_SCHEMA_DOCUMENT_BYTES:",
                b"if body_size >= MAX_SCHEMA_DOCUMENT_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"if len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:",
                b"if len(record.canonical_json) >= MAX_SCHEMA_DOCUMENT_BYTES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"if body_size > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                b"if False and body_size > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"if len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                b"if False and len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b'findings.add("IMAGE_ITEM_BYTE_LIMIT", "schema_documents", ',
                b'findings.add("WRONG_LIMIT", "schema_documents", ',
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'_finding("SCHEMA_DOCUMENT_TOO_LARGE", "schema_documents", ',
                b'_finding("WRONG_LIMIT", "schema_documents", ',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"                body_size = len(body)\n",
                b"                body_size = len(body[:True])\n",
                "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    if findings:\n        return findings, False\n",
                b"    if False:\n        return findings, False\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    findings.extend(bundle_findings)\n",
                b"    findings.extend(())\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"\n_REQUIRED_DESCRIPTOR_TABLES = (",
                b"\nlen = lambda value: value.__len__()\n\n_REQUIRED_DESCRIPTOR_TABLES = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for relative, old, new, expected_code in attacks:
            with self.subTest(path=relative, attack=old[:36]):
                root = self.copy_inputs()
                source = root / relative
                mutated = source.read_bytes().replace(old, new, 1)
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(path=relative, attack="constant divergence"):
                root = self.copy_inputs()
                source = root / relative
                mutated = source.read_bytes().replace(
                    b"MAX_SCHEMA_DOCUMENT_BYTES = 262_144",
                    b"MAX_SCHEMA_DOCUMENT_BYTES = 262_143",
                    1,
                )
                self.assertNotEqual(mutated, source.read_bytes())
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_LIMIT_CONFLICT"
                )

        for relative in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            with self.subTest(path=relative, attack="extra constant read"):
                root = self.copy_inputs()
                source = root / relative
                source.write_bytes(
                    source.read_bytes()
                    + b"\ndef _extra_limit_read():\n"
                    + b"    return MAX_SCHEMA_DOCUMENT_BYTES\n"
                )
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    (
                        "RESOURCE_ROW_CAP_BINDING_MODULE_AST"
                        if relative == "src/edgelab/runtime_v2_image.py"
                        else "RESOURCE_CLASSIFICATION_NAME_CARDINALITY"
                    ),
                )

    def test_schema_ref_node_classification_binds_exact_semantics(self):
        attacks = (
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:",
                b"if len(edges) >= MAX_SCHEMA_REF_NODES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                b"if False and len(edges) > MAX_SCHEMA_REF_NODES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"if len(edges) > MAX_SCHEMA_REF_NODES:",
                b"if len(definitions) > MAX_SCHEMA_REF_NODES:",
                "RESOURCE_DISCOVERY_V2_IDENTITY",
            ),
            (
                b"    if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                b"    edges.clear()\n"
                b"    if len(edges) > MAX_SCHEMA_REF_NODES:\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'        add("SCHEMA_REF_GRAPH_TOO_LARGE", "/$defs")\n',
                b'        add("WRONG_GRAPH_LIMIT", "/$defs")\n',
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"        add(\"SCHEMA_REF_GRAPH_TOO_LARGE\", \"/$defs\")\n"
                b"        return findings\n",
                b"        add(\"SCHEMA_REF_GRAPH_TOO_LARGE\", \"/$defs\")\n"
                b"        pass\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    for start in sorted(edges):\n",
                b"    for start in ():\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b"    findings.extend(bundle_findings)\n",
                b"    findings.extend(())\n",
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
            ),
            (
                b'    authorizing_use: str = field(default="DENY", init=False)\n',
                b'    authorizing_use: str = field(default="ALLOW", init=False)\n',
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"\n_REQUIRED_DESCRIPTOR_TABLES = (",
                b"\nlen = lambda value: value.__len__()\n\n_REQUIRED_DESCRIPTOR_TABLES = (",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
        )
        for old, new, expected_code in attacks:
            with self.subTest(attack=old[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_verifier.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_verifier.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"MAX_SCHEMA_REF_NODES = 4_096",
            b"MAX_SCHEMA_REF_NODES = 4_095",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_DISCOVERY_V2_IDENTITY"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_verifier.py"
        source.write_bytes(
            source.read_bytes()
            + b"\ndef _extra_schema_ref_limit_read():\n"
            + b"    return MAX_SCHEMA_REF_NODES\n"
        )
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_NAME_CARDINALITY"
        )

    def test_transition_argument_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        transition_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_transition.py"
        ]
        tree = ast.parse(transition_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_ARGUMENTS"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_ARGUMENTS"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 1)

        site_attacks = (
            (b"MAX_ARGUMENTS = 8", b"MAX_ARGUMENTS = 4 + 4"),
            (b"MAX_ARGUMENTS = 8", b"MAX_ARGUMENTS = 7"),
            (
                b"len(self.arguments) > MAX_ARGUMENTS",
                b"len(self.arguments) >= MAX_ARGUMENTS",
            ),
            (
                b"len(self.arguments) > MAX_ARGUMENTS",
                b"len(self.semantic_event_ids) > MAX_ARGUMENTS",
            ),
            (
                b"len(self.arguments) > MAX_ARGUMENTS",
                b"len(self.arguments) > MAX_GROUP_EVENTS",
            ),
        )
        for old, new in site_attacks:
            with self.subTest(site_attack=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _argument_limit_extra_read():\n"
            b"    return MAX_ARGUMENTS\n",
            b"\n\ndef _argument_limit_extra_store():\n"
            b"    MAX_ARGUMENTS = 8\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        function_attacks = (
            (
                b"if len(self.arguments) > MAX_ARGUMENTS:",
                b"if False and len(self.arguments) > MAX_ARGUMENTS:",
            ),
            (
                b"type(self.arguments) is not tuple",
                b"not isinstance(self.arguments, tuple)",
            ),
            (
                b'_deny("TRANSITION_RESOURCE_ARGUMENTS", "/arguments")',
                b'_deny("WRONG_ARGUMENT_LIMIT", "/arguments")',
            ),
            (
                b'_deny("TRANSITION_RESOURCE_ARGUMENTS", "/arguments")',
                b'_deny("TRANSITION_RESOURCE_ARGUMENTS", "/wrong")',
            ),
            (
                b"        if any(\n"
                b"            type(item) is not tuple or len(item) != 2 ",
                b"        if False and any(\n"
                b"            type(item) is not tuple or len(item) != 2 ",
            ),
        )
        for old, new in function_attacks:
            with self.subTest(function_attack=old[:40]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_transition.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"def _deny(code: str, coordinate: str = \"/\") -> None:\n"
            b"    raise TransitionViolation(code, coordinate)\n",
            b"def _deny(code: str, coordinate: str = \"/\") -> None:\n"
            b"    return None\n",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_transition.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"_REASON = re.compile(r\"^[A-Z][A-Z0-9_]{0,63}$\")\n",
            b"_REASON = re.compile(r\"^[A-Z][A-Z0-9_]{0,63}$\")\n"
            b"len = lambda value: value.__len__()\n",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
        )

    def test_transition_semantic_event_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )
        transition_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_transition.py"
        ]
        tree = ast.parse(transition_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_GROUP_EVENTS"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_GROUP_EVENTS"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 1)

        for old, new in (
            (b"MAX_GROUP_EVENTS = 10_002", b"MAX_GROUP_EVENTS = 5_001 + 5_001"),
            (b"MAX_GROUP_EVENTS = 10_002", b"MAX_GROUP_EVENTS = 10_001"),
            (
                b"len(self.semantic_event_ids) > MAX_GROUP_EVENTS",
                b"len(self.semantic_event_ids) >= MAX_GROUP_EVENTS",
            ),
            (
                b"len(self.semantic_event_ids) > MAX_GROUP_EVENTS",
                b"len(self.arguments) > MAX_GROUP_EVENTS",
            ),
            (
                b"len(self.semantic_event_ids) > MAX_GROUP_EVENTS",
                b"len(self.semantic_event_ids) > MAX_ARGUMENTS",
            ),
        ):
            with self.subTest(site_attack=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _semantic_event_limit_extra_read():\n"
            b"    return MAX_GROUP_EVENTS\n",
            b"\n\ndef _semantic_event_limit_extra_store():\n"
            b"    MAX_GROUP_EVENTS = 10_002\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        for old, new in (
            (
                b"if len(self.semantic_event_ids) > MAX_GROUP_EVENTS:",
                b"if False and len(self.semantic_event_ids) > MAX_GROUP_EVENTS:",
            ),
            (
                b'_deny("TRANSITION_RESOURCE_EVENTS", "/semantic_event_ids")',
                b'_deny("WRONG_EVENT_LIMIT", "/semantic_event_ids")',
            ),
            (
                b"        if len(self.arguments) > MAX_ARGUMENTS:\n"
                b"            _deny(\"TRANSITION_RESOURCE_ARGUMENTS\", \"/arguments\")\n"
                b"        if len(self.semantic_event_ids) > MAX_GROUP_EVENTS:\n"
                b"            _deny(\"TRANSITION_RESOURCE_EVENTS\", \"/semantic_event_ids\")\n",
                b"        if len(self.semantic_event_ids) > MAX_GROUP_EVENTS:\n"
                b"            _deny(\"TRANSITION_RESOURCE_EVENTS\", \"/semantic_event_ids\")\n"
                b"        if len(self.arguments) > MAX_ARGUMENTS:\n"
                b"            _deny(\"TRANSITION_RESOURCE_ARGUMENTS\", \"/arguments\")\n",
            ),
            (
                b"        for event_id in self.semantic_event_ids:\n"
                b"            _uuid(event_id, \"/semantic_event_ids\")\n",
                b"        for event_id in self.semantic_event_ids:\n"
                b"            pass\n",
            ),
        ):
            with self.subTest(function_attack=old[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_transition.py"
        original = source.read_bytes()
        mutated = original.replace(
            b'_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")\n',
            b'_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")\n'
            b"len = lambda value: value.__len__()\n",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
        )

    def test_transition_task_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )
        transition_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_transition.py"
        ]
        tree = ast.parse(transition_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_TASKS"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "MAX_TASKS"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 2)

        for old, new in (
            (b"MAX_TASKS = 100_000", b"MAX_TASKS = 50_000 + 50_000"),
            (b"MAX_TASKS = 100_000", b"MAX_TASKS = 99_999"),
            (
                b"len(self.tasks) > MAX_TASKS",
                b"len(self.tasks) >= MAX_TASKS",
            ),
            (
                b"len(self.tasks) > MAX_TASKS",
                b"len(self.claims) > MAX_TASKS",
            ),
            (
                b"len(self._tasks) + added_tasks > MAX_TASKS",
                b"len(self._tasks) + added_tasks >= MAX_TASKS",
            ),
            (
                b"len(self._tasks) + added_tasks > MAX_TASKS",
                b"len(self._tasks) + added_claims > MAX_TASKS",
            ),
        ):
            with self.subTest(site_attack=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _task_limit_extra_read():\n    return MAX_TASKS\n",
            b"\n\ndef _task_limit_extra_store():\n"
            b"    MAX_TASKS = 100_000\n    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        for old, new in (
            (
                b'if type(getattr(self, name)) is not tuple:',
                b'if not isinstance(getattr(self, name), tuple):',
            ),
            (
                b'if len(self.tasks) > MAX_TASKS:\n'
                b'            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")',
                b'if False and len(self.tasks) > MAX_TASKS:\n'
                b'            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")',
            ),
            (
                b"        added_tasks = 0\n",
                b"        added_tasks = int(False)\n",
            ),
            (
                b"            added_tasks += int(current is None)\n",
                b"            added_tasks += int(current is not None)\n",
            ),
            (
                b'if len(self._tasks) + added_tasks > MAX_TASKS:\n'
                b'            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")',
                b'if False and len(self._tasks) + added_tasks > MAX_TASKS:\n'
                b'            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")',
            ),
            (
                b'_deny("TRANSITION_RESOURCE_TASKS", "/tasks")',
                b'_deny("WRONG_TASK_LIMIT", "/tasks")',
            ),
        ):
            with self.subTest(function_attack=old[:52]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        for shadow, expected_code in (
            (
                b"len = lambda value: value.__len__()\n",
                "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
            ),
            (
                b"int = lambda value: 0\n",
                "RESOURCE_DISCOVERY_V1_CARDINALITY",
            ),
        ):
            with self.subTest(module_shadow=shadow):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_transition.py"
                original = source.read_bytes()
                mutated = original.replace(
                    b'_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")\n',
                    b'_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")\n'
                    + shadow,
                    1,
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    expected_code,
                )

    def test_schema_bundle_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )
        for path, expected_stores, expected_loads in (
            ("src/edgelab/runtime_v2_image.py", 1, 1),
            ("src/edgelab/runtime_v2_verifier.py", 1, 2),
        ):
            tree = ast.parse(baseline_source_bytes[path])
            stores = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Name)
                and node.id == "MAX_SCHEMA_BUNDLE_BYTES"
                and isinstance(node.ctx, ast.Store)
            ]
            loads = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Name)
                and node.id == "MAX_SCHEMA_BUNDLE_BYTES"
                and isinstance(node.ctx, ast.Load)
            ]
            self.assertEqual(len(stores), expected_stores)
            self.assertEqual(len(loads), expected_loads)

        site_attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152",
                b"MAX_SCHEMA_BUNDLE_BYTES = 1_048_576 + 1_048_576",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_151",
                "RESOURCE_LIMIT_CONFLICT",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES",
                b"schema_bundle_bytes >= MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES",
                b"total_accounted > MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152",
                b"MAX_SCHEMA_BUNDLE_BYTES = 1_048_576 + 1_048_576",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_153",
                "RESOURCE_LIMIT_CONFLICT",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"raw_total > MAX_SCHEMA_BUNDLE_BYTES",
                b"raw_total >= MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"raw_total > MAX_SCHEMA_BUNDLE_BYTES",
                b"len(image.schema_registry) > MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES",
                b"len(image.storage_descriptor) >= MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES",
                b"len(image.manifest) > MAX_SCHEMA_BUNDLE_BYTES",
                "RESOURCE_CLASSIFICATION_SITE_MISSING",
            ),
        )
        for path, old, new, expected_code in site_attacks:
            with self.subTest(site_attack=(path, new)):
                root = self.copy_inputs()
                source = root / path
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    expected_code,
                )

        for path in (
            "src/edgelab/runtime_v2_image.py",
            "src/edgelab/runtime_v2_verifier.py",
        ):
            for suffix in (
                b"\n\ndef _schema_bundle_extra_read():\n"
                b"    return MAX_SCHEMA_BUNDLE_BYTES\n",
                b"\n\ndef _schema_bundle_extra_store():\n"
                b"    MAX_SCHEMA_BUNDLE_BYTES = 2_097_152\n"
                b"    return None\n",
            ):
                with self.subTest(name_cardinality=(path, suffix.splitlines()[2])):
                    root = self.copy_inputs()
                    source = root / path
                    source.write_bytes(source.read_bytes() + suffix)
                    self.refresh_source_bindings(root)
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                    self.assertEqual(
                        caught.exception.code,
                        (
                            "RESOURCE_ROW_CAP_BINDING_MODULE_AST"
                            if path == "src/edgelab/runtime_v2_image.py"
                            else "RESOURCE_CLASSIFICATION_NAME_CARDINALITY"
                        ),
                    )

        function_attacks = (
            (
                "src/edgelab/runtime_v2_image.py",
                b'len(captured["schema_registry"])\n'
                b'        if type(captured["schema_registry"]) is bytes else 0',
                b'len(captured["schema_registry"])\n'
                b'        if type(captured["schema_registry"]) is bytes else 1',
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"                schema_bundle_bytes += body_size\n",
                b"                schema_bundle_bytes += 0\n",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"            if type(body) is not bytes:\n",
                b"            if not isinstance(body, bytes):\n",
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b"    if schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES:\n"
                b'        findings.add("SCHEMA_BUNDLE_BYTE_LIMIT", "schema_bundle", "/")',
                b"    if False and schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES:\n"
                b'        findings.add("SCHEMA_BUNDLE_BYTE_LIMIT", "schema_bundle", "/")',
            ),
            (
                "src/edgelab/runtime_v2_image.py",
                b'findings.add("SCHEMA_BUNDLE_BYTE_LIMIT", "schema_bundle", "/")',
                b'findings.add("WRONG_SCHEMA_BUNDLE_LIMIT", "schema_bundle", "/")',
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    raw_total = len(image.schema_registry)\n",
                b"    raw_total = 0\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"        raw_total += len(record.canonical_json)\n",
                b"        raw_total += 0\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"        if type(record.canonical_json) is not bytes:\n",
                b"        if not isinstance(record.canonical_json, bytes):\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    if raw_total > MAX_SCHEMA_BUNDLE_BYTES:\n"
                b'        findings.append(_finding("SCHEMA_BUNDLE_TOO_LARGE", "schema_bundle", "/"))',
                b"    if False and raw_total > MAX_SCHEMA_BUNDLE_BYTES:\n"
                b'        findings.append(_finding("SCHEMA_BUNDLE_TOO_LARGE", "schema_bundle", "/"))',
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'_finding("SCHEMA_BUNDLE_TOO_LARGE", "schema_bundle", "/")',
                b'_finding("WRONG_SCHEMA_BUNDLE_LIMIT", "schema_bundle", "/")',
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    if type(image.storage_descriptor) is not bytes:\n",
                b"    if not isinstance(image.storage_descriptor, bytes):\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"    elif len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES:\n",
                b"    if len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES:\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b'findings.append(_finding("DESCRIPTOR_TOO_LARGE", "storage_descriptor", "/"))',
                b'findings.append(_finding("WRONG_DESCRIPTOR_LIMIT", "storage_descriptor", "/"))',
            ),
        )
        for path, old, new in function_attacks:
            with self.subTest(function_attack=(path, old[:52])):
                root = self.copy_inputs()
                source = root / path
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    (
                        "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST"
                        if path == "src/edgelab/runtime_v2_image.py"
                        else "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE"
                    ),
                )

        for path, anchor in (
            (
                "src/edgelab/runtime_v2_image.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152\n",
            ),
            (
                "src/edgelab/runtime_v2_verifier.py",
                b"MAX_SCHEMA_BUNDLE_BYTES = 2_097_152\n",
            ),
        ):
            for shadow in (
                b"len = lambda value: value.__len__()\n",
                b"bytes = bytearray\n",
            ):
                with self.subTest(module_shadow=(path, shadow)):
                    root = self.copy_inputs()
                    source = root / path
                    original = source.read_bytes()
                    mutated = original.replace(anchor, anchor + shadow, 1)
                    self.assertNotEqual(mutated, original)
                    source.write_bytes(mutated)
                    self.refresh_source_bindings(root)
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                    self.assertEqual(
                        caught.exception.code,
                        (
                            "RESOURCE_ROW_CAP_BINDING_MODULE_AST"
                            if path == "src/edgelab/runtime_v2_image.py"
                            else "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
                        ),
                    )

    def test_portable_path_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        closure_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_closure.py"
        ]
        tree = ast.parse(closure_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "_PORTABLE_PATH_MAX"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "_PORTABLE_PATH_MAX"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 1)

        site_attacks = (
            (b"_PORTABLE_PATH_MAX = 4_096", b"_PORTABLE_PATH_MAX = 2_048 + 2_048"),
            (b"_PORTABLE_PATH_MAX = 4_096", b"_PORTABLE_PATH_MAX = 4_095"),
            (
                b"len(path) > _PORTABLE_PATH_MAX",
                b"len(path) >= _PORTABLE_PATH_MAX",
            ),
            (
                b"len(path) > _PORTABLE_PATH_MAX",
                b"len(components) > _PORTABLE_PATH_MAX",
            ),
            (
                b"len(path) > _PORTABLE_PATH_MAX",
                b"len(path) > _PORTABLE_COMPONENT_MAX",
            ),
        )
        for old, new in site_attacks:
            with self.subTest(site_attack=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _portable_path_limit_extra_read():\n"
            b"    return _PORTABLE_PATH_MAX\n",
            b"\n\ndef _portable_path_limit_extra_store():\n"
            b"    _PORTABLE_PATH_MAX = 4_096\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        function_attacks = (
            (
                b"if len(path) > _PORTABLE_PATH_MAX or any(",
                b"if False and len(path) > _PORTABLE_PATH_MAX or any(",
            ),
            (
                b"path = _pattern(value, _PATH, coordinate)",
                b"path = value",
            ),
            (
                b'        _fail("PATH_LENGTH", coordinate)',
                b'        _fail("WRONG_PATH_LIMIT", coordinate)',
            ),
            (
                b"if len(path) > _PORTABLE_PATH_MAX or any(\n"
                b"        len(component) > _PORTABLE_COMPONENT_MAX for component in components\n"
                b"    ):",
                b"if any(\n"
                b"        len(component) > _PORTABLE_COMPONENT_MAX for component in components\n"
                b"    ) or len(path) > _PORTABLE_PATH_MAX:",
            ),
        )
        for old, new in function_attacks:
            with self.subTest(function_attack=old[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_closure.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"def _fail(code: str, coordinate: str) -> None:\n",
            b"def _fail(code: str, coordinate: str) -> None:\n"
            b"    return None\n",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
        )

        root = self.copy_inputs()
        source = root / "src/edgelab/runtime_v2_closure.py"
        original = source.read_bytes()
        mutated = original.replace(
            b"_PORTABLE_PATH_MAX = 4_096\n",
            b"_PORTABLE_PATH_MAX = 4_096\n"
            b"len = lambda value: value.__len__()\n",
            1,
        )
        self.assertNotEqual(mutated, original)
        source.write_bytes(mutated)
        self.refresh_source_bindings(root)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_MODULE_SHAPE"
        )

    def test_portable_component_classification_binds_exact_semantics(self):
        _, _, baseline_source_bytes = _source_inventory(ROOT)
        baseline_predecessor_sites = _source_bound_inventory(
            baseline_source_bytes
        )
        baseline_binding_sites = _source_bound_binding_inventory(
            baseline_source_bytes, baseline_predecessor_sites
        )

        closure_source = baseline_source_bytes[
            "src/edgelab/runtime_v2_closure.py"
        ]
        tree = ast.parse(closure_source)
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "_PORTABLE_COMPONENT_MAX"
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "_PORTABLE_COMPONENT_MAX"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertEqual(len(stores), 1)
        self.assertEqual(len(loads), 1)

        site_attacks = (
            (
                b"_PORTABLE_COMPONENT_MAX = 255",
                b"_PORTABLE_COMPONENT_MAX = 128 + 127",
            ),
            (b"_PORTABLE_COMPONENT_MAX = 255", b"_PORTABLE_COMPONENT_MAX = 254"),
            (
                b"len(component) > _PORTABLE_COMPONENT_MAX",
                b"len(component) >= _PORTABLE_COMPONENT_MAX",
            ),
            (
                b"len(component) > _PORTABLE_COMPONENT_MAX",
                b"len(path) > _PORTABLE_COMPONENT_MAX",
            ),
            (
                b"len(component) > _PORTABLE_COMPONENT_MAX",
                b"len(component) > _PORTABLE_PATH_MAX",
            ),
        )
        for old, new in site_attacks:
            with self.subTest(site_attack=new):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                with self.assertRaises(ReadinessError) as caught:
                    self.build_with_refreshed_ordinary_source_bindings(
                        root, baseline_binding_sites
                    )
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_SITE_MISSING",
                )

        for suffix in (
            b"\n\ndef _portable_component_limit_extra_read():\n"
            b"    return _PORTABLE_COMPONENT_MAX\n",
            b"\n\ndef _portable_component_limit_extra_store():\n"
            b"    _PORTABLE_COMPONENT_MAX = 255\n"
            b"    return None\n",
        ):
            with self.subTest(name_cardinality=suffix.splitlines()[2]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                source.write_bytes(source.read_bytes() + suffix)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_NAME_CARDINALITY",
                )

        function_attacks = (
            (
                b"if len(path) > _PORTABLE_PATH_MAX or any(",
                b"if len(path) > _PORTABLE_PATH_MAX or all(",
            ),
            (
                b"for component in components\n",
                b"for component in components if component\n",
            ),
            (
                b"components = path.split(\"/\")",
                b"components = tuple(reversed(path.split(\"/\")))",
            ),
            (
                b"if len(path) > _PORTABLE_PATH_MAX or any(",
                b"if len(path) > _PORTABLE_PATH_MAX or False or any(",
            ),
            (
                b"if len(path) > _PORTABLE_PATH_MAX or any(\n"
                b"        len(component) > _PORTABLE_COMPONENT_MAX for component in components\n"
                b"    ):",
                b"if any(\n"
                b"        len(component) > _PORTABLE_COMPONENT_MAX for component in components\n"
                b"    ) or len(path) > _PORTABLE_PATH_MAX:",
            ),
            (
                b'        _fail("PATH_LENGTH", coordinate)',
                b'        _fail("WRONG_COMPONENT_LIMIT", coordinate)',
            ),
        )
        for old, new in function_attacks:
            with self.subTest(function_attack=old[:48]):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                original = source.read_bytes()
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                )

        for shadow in (
            b"len = lambda value: value.__len__()\n",
            b"any = lambda values: False\n",
        ):
            with self.subTest(shadow=shadow):
                root = self.copy_inputs()
                source = root / "src/edgelab/runtime_v2_closure.py"
                original = source.read_bytes()
                mutated = original.replace(
                    b"_PORTABLE_COMPONENT_MAX = 255\n",
                    b"_PORTABLE_COMPONENT_MAX = 255\n" + shadow,
                    1,
                )
                self.assertNotEqual(mutated, original)
                source.write_bytes(mutated)
                self.refresh_source_bindings(root)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_MODULE_SHAPE",
                )

    def test_migrations_row_classification_survives_attacker_census_refresh(self):
        baseline = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        v4_bindings = [
            dict(item) for item in baseline["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        migrations_index = next(
            index for index, item in enumerate(v4_bindings)
            if item["table_name"] == "migrations"
        )
        predecessor_sites = [
            item for item in baseline["source_bound_sites"]
            if item["kind"] != "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        for field, hostile_value, expected_code in (
            ("maximum", 1, "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            ("selection_semantics", "SUPPLIED_LABEL", "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            ("site_id", "0" * 64, "RESOURCE_CLASSIFICATION_SITE_MISSING"),
        ):
            with self.subTest(field=field):
                root = self.copy_inputs()
                hostile = [dict(item) for item in v4_bindings]
                hostile[migrations_index][field] = hostile_value
                source_sites = sorted(
                    predecessor_sites + hostile,
                    key=lambda item: (item["path"], item["site_id"]),
                )
                digest = _domain_digest(
                    RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
                    [
                        {key: value for key, value in item.items() if key != "line"}
                        for item in source_sites
                    ],
                )
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_bound_sites_sha256", digest
                    ),
                )
                with (
                    mock.patch.object(
                        readiness_checker,
                        "_source_bound_table_row_cap_binding_inventory",
                        return_value=hostile,
                    ),
                    mock.patch.object(
                        readiness_checker,
                        "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                        digest,
                    ),
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_legacy_archive_row_classification_survives_attacker_census_refresh(self):
        baseline = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        v4_bindings = [
            dict(item) for item in baseline["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        legacy_index = next(
            index for index, item in enumerate(v4_bindings)
            if item["table_name"] == "legacy_archive"
        )
        metadata_site = next(
            item["site_id"] for item in v4_bindings
            if item["table_name"] == "metadata"
        )
        predecessor_sites = [
            item for item in baseline["source_bound_sites"]
            if item["kind"] != "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        for field, hostile_value, expected_code in (
            ("maximum", 0, "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            ("row_index", 6, "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            (
                "selection_semantics",
                "SUPPLIED_LABEL",
                "RESOURCE_CLASSIFICATION_SITE_SHAPE",
            ),
            ("site_id", metadata_site, "RESOURCE_SITE_ID_DUPLICATE"),
            ("site_id", "0" * 64, "RESOURCE_CLASSIFICATION_SITE_MISSING"),
        ):
            with self.subTest(field=field, hostile_value=hostile_value):
                root = self.copy_inputs()
                hostile = [dict(item) for item in v4_bindings]
                hostile[legacy_index][field] = hostile_value
                source_sites = sorted(
                    predecessor_sites + hostile,
                    key=lambda item: (item["path"], item["site_id"]),
                )
                digest = _domain_digest(
                    RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
                    [
                        {key: value for key, value in item.items() if key != "line"}
                        for item in source_sites
                    ],
                )
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_bound_sites_sha256", digest
                    ),
                )
                with (
                    mock.patch.object(
                        readiness_checker,
                        "_source_bound_table_row_cap_binding_inventory",
                        return_value=hostile,
                    ),
                    mock.patch.object(
                        readiness_checker,
                        "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                        digest,
                    ),
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_metadata_row_classification_survives_attacker_census_refresh(self):
        baseline = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        v4_bindings = [
            dict(item) for item in baseline["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        metadata_index = next(
            index for index, item in enumerate(v4_bindings)
            if item["table_name"] == "metadata"
        )
        schema_registry_site = next(
            item["site_id"] for item in v4_bindings
            if item["table_name"] == "schema_registry"
        )
        predecessor_sites = [
            item for item in baseline["source_bound_sites"]
            if item["kind"] != "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        ]
        for field, hostile_value, expected_code in (
            ("maximum", 0, "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            ("row_index", 5, "RESOURCE_CLASSIFICATION_SITE_SHAPE"),
            (
                "selection_semantics",
                "SUPPLIED_LABEL",
                "RESOURCE_CLASSIFICATION_SITE_SHAPE",
            ),
            ("site_id", schema_registry_site, "RESOURCE_SITE_ID_DUPLICATE"),
            ("site_id", "0" * 64, "RESOURCE_CLASSIFICATION_SITE_MISSING"),
        ):
            with self.subTest(field=field, hostile_value=hostile_value):
                root = self.copy_inputs()
                hostile = [dict(item) for item in v4_bindings]
                hostile[metadata_index][field] = hostile_value
                source_sites = sorted(
                    predecessor_sites + hostile,
                    key=lambda item: (item["path"], item["site_id"]),
                )
                digest = _domain_digest(
                    RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN,
                    [
                        {key: value for key, value in item.items() if key != "line"}
                        for item in source_sites
                    ],
                )
                self.rewrite_manifest(
                    root,
                    lambda manifest: manifest.__setitem__(
                        "source_bound_sites_sha256", digest
                    ),
                )
                with (
                    mock.patch.object(
                        readiness_checker,
                        "_source_bound_table_row_cap_binding_inventory",
                        return_value=hostile,
                    ),
                    mock.patch.object(
                        readiness_checker,
                        "RESOURCE_SOURCE_BOUND_SITES_V4_SHA256",
                        digest,
                    ),
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(caught.exception.code, expected_code)

    def test_metadata_row_classification_rejects_scope_expansion(self):
        discovery = build_report(ROOT)["inventory"]["resource_inventory_discovery"]
        sibling = next(
            item["site_id"] for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
            and item["table_name"] == "schema_registry"
        )
        root = self.copy_inputs()

        def expand(manifest):
            manifest["constraints"][-1]["enforcement_site_ids"].append(sibling)
            manifest["classified_site_count"] = 46
            manifest["unclassified_site_count"] = 672

        self.rewrite_manifest(root, expand)
        with self.assertRaises(ReadinessError) as caught:
            build_report(root)
        self.assertIn(
            caught.exception.code,
            {"RESOURCE_CLASSIFICATION_BINDING", "RESOURCE_CLASSIFICATION_CONSTRAINT"},
        )

    def test_v21_classification_extends_v20_with_only_metadata_row_cap(self):
        current = json.loads(
            (ROOT / RESOURCE_CLASSIFICATION_MANIFEST[1]).read_text(
                encoding="ascii"
            )
        )
        predecessor = json.loads(
            (
                ROOT / "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v20.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(current["constraints"][:-1], predecessor["constraints"])
        self.assertEqual(len(current["constraints"]), 18)
        self.assertEqual(current["classified_site_count"], 45)
        self.assertEqual(current["source_bound_site_count"], 422)
        self.assertEqual(current["schema_bound_site_count"], 296)
        self.assertEqual(current["unclassified_site_count"], 673)
        self.assertEqual(current["coverage_status"], "INCOMPLETE")
        self.assertEqual(current["generation_disposition"], "DENY")
        self.assertEqual(
            current["predecessor_manifest"],
            {
                "byte_length": 41850,
                "classification_manifest_sha256": (
                    "6119e639cbc9604ce8a9014a66f3e63a568747d07e42eaa22f9e5f1bf65323d5"
                ),
                "path": (
                    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v20.json"
                ),
                "raw_sha256": (
                    "4f178d854d7ae2ed43cb10dfbbc08376307318deb73a71d23dbb9a98483e8f6a"
                ),
            },
        )
        report = build_report(ROOT)
        discovery = report["inventory"]["resource_inventory_discovery"]
        self.assertIn(
            "V1_BRIDGE_UNSUPPORTED",
            {item["code"] for item in report["blockers"]},
        )
        cardinality_site_ids = {
            item["site_id"] for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING"
        }
        classified_site_ids = {
            site_id
            for constraint in current["constraints"]
            for field in ("definition_site_ids", "enforcement_site_ids")
            for site_id in constraint[field]
        }
        self.assertEqual(
            cardinality_site_ids & classified_site_ids,
            {
                "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3",
                "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13",
            },
        )
        row_cap_site_ids = {
            item["site_id"] for item in discovery["source_bound_sites"]
            if item["kind"] == "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING"
        }
        self.assertEqual(
            row_cap_site_ids & classified_site_ids,
            {
                "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a",
                "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18",
                "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e",
            },
        )
        self.assertTrue({
            "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b",
            "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793",
            "345667d74d800a8ab46094cfecc00b6e867bab5a5dd87a6ad77caedc5e68d31b",
            "1a89ac6ff9afbe3ef25bba879d53ae71f86bc0f26772cf0676ef4230191e61b9",
            "b54cc7867c718ef5b8f6e9566da8b1efe64bde1d302fc15043aa96dd04df0c3d",
            "fe927651d31bf9d0e12db5c17436fb7c8cd4d6a8ee807672ff254e80ec733b5f",
            "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
        }.isdisjoint(classified_site_ids))
        metadata = current["constraints"][-1]
        self.assertEqual(
            set(metadata["definition_site_ids"])
            | set(metadata["enforcement_site_ids"]),
            {"badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"},
        )
        semantic_text = json.dumps({
            key: value for key, value in metadata.items()
            if key not in {"evidence_inputs", "constraint_id"}
        }).lower()
        for excluded_meaning in (
            "descriptor", "reducer", "public_verifier", "migration_authority",
            "schema_authority", "execution_authority", "capital_authority",
            "authorizing_use", "authority_binding", "minimum", "exactly_one",
            "requires_metadata", "metadata_content", "singleton",
        ):
            self.assertNotIn(excluded_meaning, semantic_text)

    def test_v21_classification_binds_predecessor_link_records(self):
        attacks = (
            ("predecessor_manifest", "raw_sha256", "0" * 64),
            ("predecessor_manifest", "classification_manifest_sha256", "1" * 64),
            (
                "predecessor_schema",
                "path",
                "schemas/m0-3a-runtime-v2-resource-classification.v0.schema.json",
            ),
        )
        for record, field, hostile_value in attacks:
            with self.subTest(record=record, field=field):
                root = self.copy_inputs()

                def alter(manifest):
                    manifest[record][field] = hostile_value

                self.rewrite_manifest(root, alter)
                with self.assertRaises(ReadinessError) as caught:
                    build_report(root)
                self.assertEqual(
                    caught.exception.code, "RESOURCE_CLASSIFICATION_BINDING"
                )

    def test_v21_rejects_rewritten_v20_constraint_history(self):
        root = self.copy_inputs()

        def mutate_v20(manifest):
            manifest["constraints"][0]["maximum"] -= 1

        hostile_v20 = self.rewrite_versioned_classification_manifest(
            root,
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
            20,
            mutate_v20,
        )
        self.rewrite_manifest(
            root,
            lambda manifest: manifest.__setitem__(
                "predecessor_manifest", dict(hostile_v20)
            ),
        )
        with mock.patch.dict(
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
            hostile_v20,
            clear=True,
        ):
            with self.assertRaises(ReadinessError) as caught:
                build_report(root)
        self.assertEqual(
            caught.exception.code, "RESOURCE_CLASSIFICATION_CENSUS_REBASE"
        )

    def test_v21_classification_binds_v20_v19_and_earlier_ancestor_links(self):
        for record, field in (
            ("predecessor_manifest", "raw_sha256"),
            ("predecessor_schema", "raw_sha256"),
        ):
            with self.subTest(manifest="v20", record=record, field=field):
                root = self.copy_inputs()

                def mutate_v20(manifest):
                    manifest[record][field] = "0" * 64

                v20_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    20,
                    mutate_v20,
                )
                with mock.patch.dict(
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    v20_expected,
                    clear=True,
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
                )

        for record, field in (
            ("predecessor_manifest", "raw_sha256"),
            ("predecessor_schema", "raw_sha256"),
        ):
            with self.subTest(manifest="v19", record=record, field=field):
                root = self.copy_inputs()

                def mutate_v19(manifest):
                    manifest[record][field] = "0" * 64

                v19_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_ANCESTORS[0],
                    19,
                    mutate_v19,
                )

                def link_v20_to_mutated_v19(manifest):
                    manifest["predecessor_manifest"] = dict(v19_expected)

                v20_expected = self.rewrite_versioned_classification_manifest(
                    root,
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    20,
                    link_v20_to_mutated_v19,
                )
                with mock.patch.dict(
                    RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST,
                    v20_expected,
                    clear=True,
                ), mock.patch.dict(
                    RESOURCE_CLASSIFICATION_ANCESTORS[0],
                    v19_expected,
                    clear=True,
                ):
                    with self.assertRaises(ReadinessError) as caught:
                        build_report(root)
                self.assertEqual(
                    caught.exception.code,
                    "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
                )

    def test_checker_source_has_no_write_network_git_or_package_metadata_path(self):
        path = ROOT / "tools" / "check_runtime_v2_release_readiness.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(imports.isdisjoint({
            "importlib", "requests", "socket", "subprocess", "urllib",
        }))
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertTrue(attributes.isdisjoint({
            "write_bytes", "write_text", "rename", "replace", "unlink",
        }))
        source = path.read_text(encoding="utf-8")
        for token in ("git ", ".git", "importlib.metadata", "urlopen("):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
