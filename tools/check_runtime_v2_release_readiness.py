#!/usr/bin/env python3
"""Audit runtime-v2 release-generation readiness without producing a release.

This offline tool is deliberately incapable of emitting a dependency-closure
candidate or pin carrier.  It inventories the frozen-input candidates and
reports blockers in deterministic JSON.  Its result is never authorization.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ID = "EDGELAB_RUNTIME_V2_RELEASE_READINESS_V1"
PUBLIC_ENTRYPOINT_MODULE = "edgelab.runtime_v2_verifier"
PRIVATE_REDUCER_MODULE = "edgelab.runtime_v2_initial"
GENERATION_ROOT_MODULES = (
    PUBLIC_ENTRYPOINT_MODULE,
    PRIVATE_REDUCER_MODULE,
)
REQUIRED_PACKAGE_MODULES = ("edgelab",)
LOCAL_IMPORT_ROOTS = ("src/edgelab",)
PIN_CARRIER_PATH = "src/edgelab/_runtime_v2_release.py"
PIN_BEGIN_MARKER = b"# BEGIN GENERATED PIN BLOCK\n"
PIN_END_MARKER = b"# END GENERATED PIN BLOCK\n"
PIN_REPLACEMENT = b"PIN_BLOCK_ELIDED_V1"
STANDARD_LIBRARY_ALLOWLIST = frozenset({
    "dataclasses", "hashlib", "json", "re", "typing",
})
TESTED_RUNTIME_ASSUMPTIONS = (
    {"expected": "CPython", "name": "PYTHON_IMPLEMENTATION"},
    {"expected": "3.13", "name": "PYTHON_VERSION"},
)

# These limits are semantically active but are not named module constants in
# the current source.  The readiness profile therefore fixes explicit
# function coordinates until the semantic sources give them stable names.
HARD_CODED_RESOURCE_LIMITS = (
    {
        "expression": "depth > LIMIT",
        "name": "CANONICAL_JSON_MAX_DEPTH",
        "source_coordinate": "src/edgelab/runtime_v2_codec.py:_validate",
        "unit": "DEPTH",
    },
    {
        "expression": "len(digits) > LIMIT",
        "name": "CLOSURE_INTEGER_TOKEN_MAX_DIGITS",
        "source_coordinate": (
            "src/edgelab/runtime_v2_closure.py:_parse_integer_token"
        ),
        "unit": "CHARACTERS",
    },
    {
        "expression": "MINIMUM <= len(image.selector_history) <= MAXIMUM",
        "name": "INITIAL_SELECTOR_MAXIMUM",
        "source_coordinate": (
            "src/edgelab/runtime_v2_initial.py:reduce_initial_runtime_image"
        ),
        "selector": "maximum",
        "unit": "ITEMS",
    },
    {
        "expression": "MINIMUM <= len(image.selector_history) <= MAXIMUM",
        "name": "INITIAL_SELECTOR_MINIMUM",
        "source_coordinate": (
            "src/edgelab/runtime_v2_initial.py:reduce_initial_runtime_image"
        ),
        "selector": "minimum",
        "unit": "ITEMS",
    },
)

BOOTSTRAP_SCHEMAS = (
    (
        "ACTIVE_RUNTIME_SELECTOR",
        "urn:edgelab:m0-3a-active-runtime-selector:2",
        "schemas/m0-3a-active-runtime-selector.v2.schema.json",
    ),
    (
        "ATTACHMENT",
        "urn:edgelab:m0-3a-runtime-attachment:2",
        "schemas/m0-3a-runtime-attachment.v2.schema.json",
    ),
    (
        "RUNTIME_MANIFEST",
        "urn:edgelab:m0-3a-runtime-manifest:2",
        "schemas/m0-3a-runtime-manifest.v2.schema.json",
    ),
    (
        "SCHEMA_REGISTRY_SCHEMA",
        "urn:edgelab:m0-3a-schema-registry:2",
        "schemas/m0-3a-schema-registry.v2.schema.json",
    ),
    (
        "STORAGE_DESCRIPTOR_SCHEMA",
        "urn:edgelab:m0-3a-runtime-storage-descriptor:2",
        "schemas/m0-3a-runtime-storage-descriptor.v2.schema.json",
    ),
)

RETAINED_SCHEMAS = (
    (
        "REQUEST",
        "urn:edgelab:m0-3a-command-request:2",
        "schemas/m0-3a-command-request.v2.schema.json",
    ),
    (
        "EVENT_ENVELOPE",
        "urn:edgelab:m0-3a-event-envelope:2",
        "schemas/m0-3a-event-envelope.v2.schema.json",
    ),
    (
        "PAYLOAD",
        "urn:edgelab:m0-3a-event-payload:2",
        "schemas/m0-3a-event-payload.v2.schema.json",
    ),
    (
        "LEGACY_PROJECTION",
        "urn:edgelab:m0-3a-legacy-v1-projection:1",
        "schemas/m0-3a-legacy-v1-projection.v1.schema.json",
    ),
    (
        "LEGACY_ROW_ARCHIVE",
        "urn:edgelab:m0-3a-legacy-v1-row-archive:1",
        "schemas/m0-3a-legacy-v1-row-archive.v1.schema.json",
    ),
    (
        "RESPONSE_PROJECTION",
        "urn:edgelab:m0-3a-response-projection:2",
        "schemas/m0-3a-response-projection.v2.schema.json",
    ),
    (
        "CHECKPOINT_DOCUMENT",
        "urn:edgelab:m0-3a-runtime-checkpoint:2",
        "schemas/m0-3a-runtime-checkpoint.v2.schema.json",
    ),
    (
        "EXPORT_DOCUMENT",
        "urn:edgelab:m0-3a-runtime-export:2",
        "schemas/m0-3a-runtime-export.v2.schema.json",
    ),
    (
        "TASK_STATE",
        "urn:edgelab:m0-3a-task-state:2",
        "schemas/m0-3a-task-state.v2.schema.json",
    ),
)

CONTENT_ASSETS = (
    (
        "schema_registry",
        "EDGELAB\0SCHEMA_REGISTRY\0V2\0",
        "schemas/m0-3a-schema-registry.v2.json",
    ),
    (
        "storage_descriptor",
        "EDGELAB\0STORAGE_SCHEMA\0V2\0",
        "schemas/m0-3a-runtime-storage.v2.json",
    ),
)

CLOSURE_SCHEMA = (
    "urn:edgelab:m0-3a-verifier-dependency-closure:1",
    "schemas/m0-3a-verifier-dependency-closure.v1.schema.json",
)
RESOURCE_CLASSIFICATION_V45_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-classification:45",
    "schemas/m0-3a-runtime-v2-resource-classification.v45.schema.json",
)
RESOURCE_CLASSIFICATION_V45_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V45",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v45.json",
)
RESOURCE_CLASSIFICATION_V44_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V44",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v44.json",
)
# Frozen V8 evidence imports this unused historical name. Current code uses only
# the versioned V47 constant; retain this V44 alias solely to preserve its bytes.
RESOURCE_CLASSIFICATION_MANIFEST = RESOURCE_CLASSIFICATION_V44_MANIFEST
RESOURCE_CLASSIFICATION_V47_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-classification:47",
    "schemas/m0-3a-runtime-v2-resource-classification.v47.schema.json",
)
RESOURCE_CLASSIFICATION_V47_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V47",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v47.json",
)
RESOURCE_CLASSIFICATION_V47_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V47\0"
)
RESOURCE_CLASSIFICATION_V46_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-classification:46",
    "schemas/m0-3a-runtime-v2-resource-classification.v46.schema.json",
)
RESOURCE_CLASSIFICATION_V46_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V46",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v46.json",
)
RESOURCE_CLASSIFICATION_V46_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V46\0"
)
RESOURCE_SOURCE_INPUT_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_SOURCE_INPUTS\0V1\0"
)
RESOURCE_DISCOVERY_V1_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V1"
RESOURCE_DISCOVERY_V2_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V2"
RESOURCE_DISCOVERY_V3_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V3"
RESOURCE_DISCOVERY_V4_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V4"
RESOURCE_DISCOVERY_V5_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V5"
RESOURCE_DISCOVERY_V6_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V6"
RESOURCE_DISCOVERY_V7_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V7"
RESOURCE_DISCOVERY_V8_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V8"
RESOURCE_DISCOVERY_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-discovery:8",
    "schemas/m0-3a-runtime-v2-resource-discovery.v8.schema.json",
)
RESOURCE_DISCOVERY_MANIFEST = (
    RESOURCE_DISCOVERY_V8_ID,
    "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v8.json",
)
RESOURCE_DISCOVERY_DOMAIN = "EDGELAB\0RUNTIME_V2_RESOURCE_DISCOVERY\0V8\0"
RESOURCE_DISCOVERY_SCHEMA_RAW_SHA256 = (
    "e10ca59c1bf90a0ebaee0647eb6c49a4e573295ee923411e337dc6e90ced50d1"
)
RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST = {
    "byte_length": 4625,
    "discovery_manifest_sha256": (
        "2169d9099446298aa19251790686ece93cc58faab6c3d2c733933c9e711077a3"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v7.json",
    "raw_sha256": "cdcdf26146deb7f9aa3578f62df71517410b16d74a920aff65b381ea857f2c7c",
}
RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA = {
    "byte_length": 6483,
    "path": "schemas/m0-3a-runtime-v2-resource-discovery.v7.schema.json",
    "raw_sha256": "54f0b91eafffd5db8e6f2ee7c0091ccdb946c12ef039a753eb7f626c9aa4a8d3",
}
RESOURCE_DISCOVERY_ANCESTOR_MANIFEST = {
    "byte_length": 4611,
    "discovery_manifest_sha256": (
        "9df58a944adcb004a4b5eb3add0910f8e356573cff2636d7053d66ff0ab1456b"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v6.json",
    "raw_sha256": "6830ac8083e46bce74f535423aafba2fc82c40732c7544e71d301e3fe63aa6e5",
}
RESOURCE_DISCOVERY_ANCESTOR_SCHEMA = {
    "byte_length": 6469,
    "path": "schemas/m0-3a-runtime-v2-resource-discovery.v6.schema.json",
    "raw_sha256": "fa748f5ed12cde22aa0a23e1c4261a27954abb05fc87169c5385838aebfac9e9",
}
SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SCHEMA_RESOURCE_SITE\0V1\0"
)
RESOURCE_SCHEMA_BOUND_SITES_V2_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SCHEMA_BOUND_SITES\0V2\0"
)
RESOURCE_SCHEMA_BOUND_SITES_V2_SHA256 = (
    "2ca911e85141b79c5ae6be653bf6a8b038ca90873a731764b27ac2bf0cae3fcf"
)
SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA = {
    "byte_length": 6245,
    "path": (
        "schemas/m0-3a-runtime-v2-schema-declarative-keyword-proof.v1.schema.json"
    ),
    "raw_sha256": (
        "f7afccfeee300b294b4e498dd6cf243e4c8167c24def540846d8170b5047eefa"
    ),
    "schema_id": (
        "urn:edgelab:m0-3a-runtime-v2-schema-declarative-keyword-proof:1"
    ),
}
SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE = {
    "byte_length": 5051,
    "path": "docs/M0.3A_RUNTIME_V2_SCHEMA_DECLARATIVE_KEYWORD_PROOF.v1.json",
    "profile_id": "EDGELAB_RUNTIME_V2_SCHEMA_DECLARATIVE_KEYWORD_PROOF_V1",
    "profile_sha256": (
        "bb0a64e1b331bbe4df6ba78411b44fc3af9da3cf542b41371f5a5556ee2b2369"
    ),
    "raw_sha256": (
        "de4f676df1d89ecbfcf3de10ae8015a9c1508e053d7bdc9cf7a62ee2a685f921"
    ),
}
RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF = {
    "byte_length": 2397,
    "path": "docs/M0.3A_ACTIVE_RUNTIME_ID_MIN_LENGTH_SCHEMA_PROOF.v2.json",
    "raw_sha256": (
        "ec6f0074f2799cee7a241d217110b11843edd2e4dfe9d6269a66f9d26201213a"
    ),
    "schema_site_id": (
        "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea"
    ),
}
RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF = {
    "byte_length": 2675,
    "path": "docs/M0.3A_GENERATOR_VERSION_MINIMUM_SCHEMA_PROOF.v1.json",
    "raw_sha256": (
        "af0ef9f2cde60c7a73092132394a7d45412b9a21b8eec3256b93f40f62afaf10"
    ),
    "schema_site_id": (
        "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b"
    ),
}
SCHEMA_CONTAINING_SUBSCHEMA_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SCHEMA_CONTAINING_SUBSCHEMA\0V1\0"
)
SCHEMA_DECLARATIVE_PROOF_PROFILE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SCHEMA_DECLARATIVE_PROOF_PROFILE\0V1\0"
)
SCHEMA_DECLARATIVE_KEYWORD_SEMANTICS = (
    ("exclusiveMaximum", "EXCLUSIVE_MAXIMUM", "NUMBER", "JSON_NUMBER_VALUE", "<", "JSON_NUMBER"),
    ("exclusiveMinimum", "EXCLUSIVE_MINIMUM", "NUMBER", "JSON_NUMBER_VALUE", ">", "JSON_NUMBER"),
    ("maxContains", "MAX_CONTAINS", "ARRAY", "CONTAINS_MATCH_COUNT", "<=", "CONTAINS_MATCHES"),
    ("maxItems", "MAX_ITEMS", "ARRAY", "ARRAY_ITEM_COUNT", "<=", "ARRAY_ITEMS"),
    ("maxLength", "MAX_LENGTH", "STRING", "UNICODE_CODE_POINT_COUNT", "<=", "UNICODE_CODE_POINTS"),
    ("maxProperties", "MAX_PROPERTIES", "OBJECT", "OBJECT_PROPERTY_COUNT", "<=", "OBJECT_PROPERTIES"),
    ("maximum", "MAXIMUM", "NUMBER", "JSON_NUMBER_VALUE", "<=", "JSON_NUMBER"),
    ("minContains", "MIN_CONTAINS", "ARRAY", "CONTAINS_MATCH_COUNT", ">=", "CONTAINS_MATCHES"),
    ("minItems", "MIN_ITEMS", "ARRAY", "ARRAY_ITEM_COUNT", ">=", "ARRAY_ITEMS"),
    ("minLength", "MIN_LENGTH", "STRING", "UNICODE_CODE_POINT_COUNT", ">=", "UNICODE_CODE_POINTS"),
    ("minProperties", "MIN_PROPERTIES", "OBJECT", "OBJECT_PROPERTY_COUNT", ">=", "OBJECT_PROPERTIES"),
    ("minimum", "MINIMUM", "NUMBER", "JSON_NUMBER_VALUE", ">=", "JSON_NUMBER"),
)
SCHEMA_DECLARATIVE_PROOF_NONCLAIMS = (
    "NO_RUNTIME_VALIDATOR_BEHAVIOR",
    "NO_PUBLIC_REACHABILITY",
    "NO_ROOT_APPLICABILITY_BEYOND_EXACT_LOCAL_CONTEXT",
    "NO_FULL_SCHEMA_VALIDITY",
    "NO_DEPLOYED_VALIDATOR_CONFORMANCE",
    "NO_ACCEPTANCE_AUTHORITY",
    "NO_STOP_CLEARANCE",
    "NO_RELEASE_AUTHORITY",
    "NO_EXECUTION_AUTHORITY",
    "NO_CAPITAL_AUTHORITY",
)
RESOURCE_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_BINDING_SITE\0V2\0"
)
RESOURCE_CARDINALITY_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CARDINALITY_BINDING_SITE\0V3\0"
)
RESOURCE_TABLE_ROW_CAP_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_TABLE_ROW_CAP_BINDING_SITE\0V4\0"
)
RESOURCE_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING_SITE\0V5\0"
)
RESOURCE_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING_SITE\0V6\0"
)
RESOURCE_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING_SITE\0V7\0"
)
RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V2\0"
)
RESOURCE_SOURCE_BOUND_SITES_V2_SHA256 = (
    "4a8707fd2ea6b1a398de1207a397f57c7dda9f368259dc58a10dc171352e0864"
)
RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V3\0"
)
RESOURCE_SOURCE_BOUND_SITES_V3_SHA256 = (
    "d38e35a0f2466735c0895b6bfb7f20c83b52834ccbc3995943f8147d8f664071"
)
RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V4\0"
)
RESOURCE_SOURCE_BOUND_SITES_V4_SHA256 = (
    "5918304896b54b757e26d94367227c9f36db56e367964133d793c3539f47ab2f"
)
RESOURCE_SOURCE_BOUND_SITES_V5_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V5\0"
)
RESOURCE_SOURCE_BOUND_SITES_V5_SHA256 = (
    "62217a83c01eb5151c51777181f44c8b87b39a9c51fe68d8fe7ab423587fd7bf"
)
RESOURCE_SOURCE_BOUND_SITES_V6_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V6\0"
)
RESOURCE_SOURCE_BOUND_SITES_V6_SHA256 = (
    "2a9e13767fb8003e3395d712e369719cb53249f8eeaf6b04091eff256e6cf064"
)
RESOURCE_SOURCE_BOUND_SITES_V7_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V7\0"
)
RESOURCE_SOURCE_BOUND_SITES_V7_SHA256 = (
    "5cb9a07b9c564cae30ad3c3043be7ab8adcb7f9c9bece0918ead5bdbf537dcfa"
)
RESOURCE_CLASSIFICATION_V46_SCHEMA_RAW_SHA256 = (
    "5ed13467897f95967fb278674063ee598d3da4f7f15353f997430f2fc79e9968"
)
RESOURCE_CLASSIFICATION_V47_SCHEMA_RAW_SHA256 = (
    "5641296c63b6e8ee6e3ef75d682983776f79eb6e949955edcb0b966b621658e9"
)
RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST = {
    "byte_length": 96434,
    "classification_manifest_sha256": (
        "d84fb6db5c982c69483d968d082fca3c028d326354aced767ba78a70036cb718"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v46.json",
    "raw_sha256": "7a501d128c026e68c6ae3faa857f7d8d1b8e78d1a1a94f08775a90e92560d1b9",
}
RESOURCE_CLASSIFICATION_V47_PREDECESSOR_SCHEMA = {
    "byte_length": 103958,
    "path": "schemas/m0-3a-runtime-v2-resource-classification.v46.schema.json",
    "raw_sha256": "5ed13467897f95967fb278674063ee598d3da4f7f15353f997430f2fc79e9968",
}
RESOURCE_CLASSIFICATION_V46_PREDECESSOR_MANIFEST = {
    "byte_length": 96435,
    "classification_manifest_sha256": (
        "e9983c8d5531ad786b4a97a0792f9662503b2e2f1fe4dc3d4cfe601bf0cf21c5"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v45.json",
    "raw_sha256": "85945a0ffc253ce53f39bd12c2ebb7c5c1029f62ca5dabbd3ebd9d1b3663b57e",
}
RESOURCE_CLASSIFICATION_V46_PREDECESSOR_SCHEMA = {
    "byte_length": 103958,
    "path": "schemas/m0-3a-runtime-v2-resource-classification.v45.schema.json",
    "raw_sha256": "2201776e26829ddd1702d01731a467fc6f5621a45cf7330c9324047bdc9f60b9",
}
RESOURCE_CLASSIFICATION_ANCESTORS = (
    {
        "byte_length": 93785,
        "classification_manifest_sha256": (
            "2277c5da17fd52cbb23281769cbf846862e51b4e15e55bf4a9cb767618cebd81"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v44.json",
        "raw_sha256": "592ba55df15012f90dac5ad883c75bde3647d0c56916ffc74b45241b8c6d9e81",
    },
    {
        "byte_length": 101057,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v44.schema.json",
        "raw_sha256": "fbb495f28cb07a2d50fccc5baa3bf26430ccc48f58bc3eedddf817032eb071c1",
    },
    {
        "byte_length": 93785,
        "classification_manifest_sha256": (
            "3e124430a983d305402980cd966f057bad5f9dcedf97c854acf6374ad610da07"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v43.json",
        "raw_sha256": "4d0c85a2faafc5079989c44a981b4d1356ce3eb4f213abd5729637ee74bbf824",
    },
    {
        "byte_length": 101057,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v43.schema.json",
        "raw_sha256": "92d649b4e32417a6004d3efaf1a253c096aaa798da6aaabf874c9fd3acc97142",
    },
    {
        "byte_length": 93784,
        "classification_manifest_sha256": (
            "dc855a01cd87e9e4eb3c81739d29451c373a1226ecd4347e80b7a97a8544ed51"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v42.json",
        "raw_sha256": "9fda39bf5f1227d99ce2018411b78481a273d56dd18f28cde193d001fe295c3e",
    },
    {
        "byte_length": 101032,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v42.schema.json",
        "raw_sha256": "b2cdb38ef8bfab74dcaf6bfa55d9e70170680a1d214dc15a3044f3a3e176187d",
    },
    {
        "byte_length": 90265,
        "classification_manifest_sha256": (
            "23e21a2c8da989a89e578a5456c61894448f7e631c79ccfcea5bb3c09908ce1b"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v41.json",
        "raw_sha256": "50e586829d57bd7e95cf78a69ea722b2c02198ed1c680c05d7ca0831a630458e",
    },
    {
        "byte_length": 97325,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v41.schema.json",
        "raw_sha256": "ac34532f6f1bb13416319f7417eead72d690fb02b2944728674625a86b4cdb2a",
    },
    {
        "byte_length": 87249,
        "classification_manifest_sha256": (
            "00458554e1598a29969ac0fe3bfe94a4dc32e999bab3542eb6cc26c7f1aedf96"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v40.json",
        "raw_sha256": "84af0451a3d4c5674a0147290e717d25142807fd833baa639444ee42550b2992",
    },
    {
        "byte_length": 94133,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v40.schema.json",
        "raw_sha256": "1f59c2f654ff27a4a4e967b07d47b7611207e4922fb36a72516b3a8eaf63762e",
    },
    {
        "byte_length": 83875,
        "classification_manifest_sha256": (
            "667125ba3f0d85eb7729364699f89a74e3b7b079d31dc5da649a51e9058b3972"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v39.json",
        "raw_sha256": "3486368af963e822b6789888b43cd54403433d062f2c1f433e310178b1d1b6cb",
    },
    {
        "byte_length": 90583,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v39.schema.json",
        "raw_sha256": "c0a7561ce33a645004222cd4a1b3ca8a1b49d9e019ec904726ec894d64cc540b",
    },
    {
        "byte_length": 80831,
        "classification_manifest_sha256": (
            "868b3408ba5b1839535dfdc87f0d6f38586f613fd918f68724f1ae4923cfbe2d"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v38.json",
        "raw_sha256": "29b54d7658ba6fd61607f097c0a344106ff10a249136570566e848f1f3683eda",
    },
    {
        "byte_length": 87379,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v38.schema.json",
        "raw_sha256": "8877f740ffa9d71c3786dec01568d31f3104ab356da4aea6a541806bdc84989d",
    },
    {
        "byte_length": 78621,
        "classification_manifest_sha256": (
            "8ad95589877784102f1bbba069ce1f73f5c59cdfe3f6787df9fb8af48cabc925"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v37.json",
        "raw_sha256": "24c17420c7457ebb795019a262ba05d52b7480bde77ce6c614e40b6cfa63be36",
    },
    {
        "byte_length": 85021,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v37.schema.json",
        "raw_sha256": "50765d73330832ff4dbbfa9dcb6dc18914829570999b060bfbeafdbcf5ea58e6",
    },
    {
        "byte_length": 73637,
        "classification_manifest_sha256": (
            "ba9d0d49cf7c201db9b62ee15ae1d88193553047c6e017e95a401782ee2a24e6"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v36.json",
        "raw_sha256": "e933ffac21b652352819c35e9eb3cf31afb5b49b920f9256006c430587907e1e",
    },
    {
        "byte_length": 79709,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v36.schema.json",
        "raw_sha256": "5ae8b3e1b2f71e5934d6a4d83529db6c0ae212e13fc0288384ad3d5ff3b66283",
    },
    {
        "byte_length": 73632,
        "classification_manifest_sha256": (
            "be9ef46386ea1c170cfe4fbc004ec6495ce8784c464a8a1a12e995cbcfef95cf"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v35.json",
        "raw_sha256": "d3f897173eae7b7deb3ec1aced0f6f722fbf567493791717bae68b6dd8e8dafd",
    },
    {
        "byte_length": 79695,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v35.schema.json",
        "raw_sha256": "169a22f38512f75b3f62a62f63ae841692dd499c15731c009d6c0d1bcc8d507b",
    },
    {
        "byte_length": 71504,
        "classification_manifest_sha256": (
            "7c9b02db527a7ec0b87d932e1fa3957d4d75e7f41b41d23af9ab5d1515f6beaa"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v34.json",
        "raw_sha256": "d4c89f461a1cc0f17f18af331529b6f8becd05b219e499586695f6bdaf0394c2",
    },
    {
        "byte_length": 77415,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v34.schema.json",
        "raw_sha256": "4dc2df18649076c37284200259bae9900018ebe03eae634a753f1c18e7ed5b28",
    },
    {
        "byte_length": 71504,
        "classification_manifest_sha256": (
            "c44eb57db828fb99af908da0945a70952f63ded016b897ee344ea7458ebfe7be"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v33.json",
        "raw_sha256": "64c07727fa802d875d8c189630b5a0538aa423e395e33f5cb8442e4d3648fde7",
    },
    {
        "byte_length": 77412,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v33.schema.json",
        "raw_sha256": "d5ade9fcb04db8028c5ad5eb0e3df3b45136ffe392630b68b7dafe68e0f260bb",
    },
    {
        "byte_length": 69229,
        "classification_manifest_sha256": (
            "ad931b58ba062a97e2b94e68f2c00bce57e4eb26a5bf4e56989eb0e730b5b612"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v32.json",
        "raw_sha256": "b4c1826bf559bcaf9dbf8461ab6fbaabed8cbad44b677de73012092b8133132a",
    },
    {
        "byte_length": 75001,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v32.schema.json",
        "raw_sha256": "4d76b86e196ebe7a83a732e2012049197a24d253424f16067617423645f8d29c",
    },
    {
        "byte_length": 66952,
        "classification_manifest_sha256": (
            "7f966303fe66e1e0ba7f4a73e5c2d249ed7bf6b835ffc1bb9cda0d901180f28d"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v31.json",
        "raw_sha256": "40b94ef888a9f0a0cf3088d8bba72c8c5dbe7868cd7c110dbb4942f64e94ab56",
    },
    {
        "byte_length": 72588,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v31.schema.json",
        "raw_sha256": "2d3cefd9a8143010660dc90fa983ba0fe6580ae5dbb3145d76fce8f6ecff4710",
    },
    {
        "byte_length": 64661,
        "classification_manifest_sha256": (
            "b61a3b8067f8be692a100198febe5dcaf3d38cbe77003e6f10bf854a95d1cd37"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v30.json",
        "raw_sha256": "5c5185aeb00edbc1adcd7153fc920af2183d5d69edba9d717988719cf5435d34",
    },
    {
        "byte_length": 70161,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v30.schema.json",
        "raw_sha256": "4b0e2f6897d0abccf045ce54f91539d5b690c1d6ed1fc3d7c9a5bad6f34b06f3",
    },
    {
        "byte_length": 62344,
        "classification_manifest_sha256": (
            "6437ae3086076bafa2e732244b6cb8c4dddf03529c2a7c7d741d0392da383864"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v29.json",
        "raw_sha256": "af16e6b10fad1bf604f0c43457c5cc2cb2f1b183d67d317a4bd94901d850bb2e",
    },
    {
        "byte_length": 67708,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v29.schema.json",
        "raw_sha256": "6288fcbf2a5a23d710709533ba647b8b6838fe2c4bb365a89663846b8a7488b5",
    },
    {
        "byte_length": 60051,
        "classification_manifest_sha256": (
            "248cf2774c60af1c3bb8d23149e923491f0e6e22da8f09c38718d8fc7e57ede2"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v28.json",
        "raw_sha256": "77b39852f3e0f25ec6ae59838f1e910043ffd03e14eee66d1e56afbdc60a1353",
    },
    {
        "byte_length": 65279,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v28.schema.json",
        "raw_sha256": "812f396cdf5d6a995e0df624c9c313ec72da1c16283e4d2a9a0f79ae42e85332",
    },
    {
        "byte_length": 57778,
        "classification_manifest_sha256": (
            "8c01543438e9a6c61d0b29d4fab44ead41a62558521e28529069badda6c550b3"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v27.json",
        "raw_sha256": "b9ef8ebf2d5698c2b7bb37634aae26f56534ca28caeae8480fc1c1b9948bbda3",
    },
    {
        "byte_length": 62870,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v27.schema.json",
        "raw_sha256": "9e58b2729fc9d24565a426c128c3cf20c2b1e853844105cb627197ee584ebbfa",
    },
    {
        "byte_length": 55507,
        "classification_manifest_sha256": (
            "d2c2b022fc159720c610f63556a444135f4089cb444edc2d23c3e84efef8630d"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v26.json",
        "raw_sha256": "10aa0939a83899c7cade75e7aeeee9e46c6fcbea7743bd7964415e73aef5a62a",
    },
    {
        "byte_length": 60463,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v26.schema.json",
        "raw_sha256": "344ec9d5dd2cc7254d0ab63dae07b6ddc98ea0de3fe4d2bef66eb416f5478743",
    },
    {
        "byte_length": 53234,
        "classification_manifest_sha256": (
            "2284b168a3d25c5c9fdff21424cccce2dbc4252549a7829d4e55aadec7e28d48"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v25.json",
        "raw_sha256": "406384b64c63e5bad8319ab2c0929376b428beec13ea82d879807a7634bb5b27",
    },
    {
        "byte_length": 58054,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v25.schema.json",
        "raw_sha256": "9b9919868e8f8eebc378e355fb8fb63cdd48b8f59e190dc68eb1c9912d900ee8",
    },
    {
        "byte_length": 50953,
        "classification_manifest_sha256": (
            "d4669a2151d044665db2950e58d8b99839185a50a9a8718fba0c033765007d07"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v24.json",
        "raw_sha256": "fa06378132d31d828237354802e69959f6f6af63db1c60de6a7c0c916f6b151d",
    },
    {
        "byte_length": 55637,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v24.schema.json",
        "raw_sha256": "5ebd07a1f05b8f5d8180aa9330a8afddb7aa41ff23911e615d2d34f538f0fc5b",
    },
    {
        "byte_length": 48655,
        "classification_manifest_sha256": (
            "fd21be2d20715f8c96b3396a40a196706600f0e1c3ac1cf9c5f923ce3b00b4eb"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v23.json",
        "raw_sha256": "f56a03624186e0fa6643de0f0ce0044d89df1f307f3e840bbb87a948af698728",
    },
    {
        "byte_length": 53203,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v23.schema.json",
        "raw_sha256": "d4219dbdcf440a2c019ca5df6ee68d209295d058620e9d561040efdb525f0ec5",
    },
    {
        "byte_length": 46402,
        "classification_manifest_sha256": (
            "d801a1368aa36a86d9a77de079f35aa4f082b2063dc54862a34642059ab4053a"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v22.json",
        "raw_sha256": "37a6dd62c2c6486189f56b5b4a56091aa5539591a10b07ff5d08350fddfff962",
    },
    {
        "byte_length": 50814,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v22.schema.json",
        "raw_sha256": "128144d02fcaaf399881a817b6b25b065d160b8af7b9f89feeda87c1129a73bf",
    },
    {
        "byte_length": 44109,
        "classification_manifest_sha256": (
            "44929d4058538e354d09940a671ac78306d2d03a0b101bd2ba55035c5814ff8a"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v21.json",
        "raw_sha256": "903ce2b2bc63498bc18adfd43c03518bddd1c4d41e1c5fd94b82e2276416e9b1",
    },
    {
        "byte_length": 48385,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v21.schema.json",
        "raw_sha256": "10ebe1d8aeb72c1cb69f2d6f3da0b7e3716d53a1f75c4c43e4d20b146d22eec9",
    },
    {
        "byte_length": 41850,
        "classification_manifest_sha256": (
            "6119e639cbc9604ce8a9014a66f3e63a568747d07e42eaa22f9e5f1bf65323d5"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v20.json",
        "raw_sha256": "4f178d854d7ae2ed43cb10dfbbc08376307318deb73a71d23dbb9a98483e8f6a",
    },
    {
        "byte_length": 45990,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v20.schema.json",
        "raw_sha256": "faecaead5bc49e60dea73e51ba2f0e1d41de417b267dc2906208d6bc8a8b57ad",
    },
    {
        "byte_length": 39567,
        "classification_manifest_sha256": (
            "ccf08c2b484131ef04231d44beba0e82f04e27a6f97a67e5cbd32db742faba2c"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v19.json",
        "raw_sha256": "0f74476dbb2e6747542a6a2f52b8c525f1d6cb43ef4a1898b8fca6a974b3938e",
    },
    {
        "byte_length": 43571,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v19.schema.json",
        "raw_sha256": "928e254e59d8dac8d82c6c6dc2fc0dd7598be5c1bd33bb5a543e09fe318f87ac",
    },
    {
        "byte_length": 37309,
        "classification_manifest_sha256": (
            "b7ef974f4bf1ae67a60f671fdf607c79be3b0727663f3adafd5bc4e09094947d"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v18.json",
        "raw_sha256": "77a61978d92b1087321ab51281617516faace8a083db12245d8ae1b37e240333",
    },
    {
        "byte_length": 41177,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v18.schema.json",
        "raw_sha256": "7901e551042b9dd95832c811de44d2ff9bad11c6464ee9b104c158a8f900b739",
    },
    {
        "byte_length": 37309,
        "classification_manifest_sha256": (
            "3a7d8c3f595aa516e96422ccce73b3884bdeb6f58ce41e525f291ffe9976cb55"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v17.json",
        "raw_sha256": "595049a2059cd7bf335a55546727500e97e7660f9b54e164db2388fe1e3a8c5b",
    },
    {
        "byte_length": 41177,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v17.schema.json",
        "raw_sha256": "12fe501633f5d6417449a9edd34a47952cb7d0ffa58fe80459ee690f30885504",
    },
    {
        "byte_length": 35018,
        "classification_manifest_sha256": (
            "52772284683ac1ce1dbbf39e7e2858c35de3feb7c9b10afe7ce3537b75a26dc8"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v16.json",
        "raw_sha256": "95cfa3ba2949277a2572da116aa1267bd7d1b77a039338fb2084fe770a9eb407",
    },
    {
        "byte_length": 38710,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v16.schema.json",
        "raw_sha256": "51e5e3e319eaeee34fdb5f592568868381c2c2752b386be80fdd57741c5c1d00",
    },
    {
        "byte_length": 32650,
        "classification_manifest_sha256": (
            "69f5d49e51e7f186fb90e32606002be684ac83060f379e921a6b0edf7cb5a90f"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v15.json",
        "raw_sha256": "cbadcd550071f29fe22ca002accd399df177dc03dafbf54980feeeb4f800eb22",
    },
    {
        "byte_length": 36166,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v15.schema.json",
        "raw_sha256": "2ca078ece22eaa8887184302110b727bfbf3ade49762a4be089c16628bd8378c",
    },
    {
        "byte_length": 32650,
        "classification_manifest_sha256": (
            "855b694a556f4a6ad86ef43301101bc4c69ece5e36a1e310bed9e359514375e7"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v14.json",
        "raw_sha256": "14f31c3f9d5451b7fe42dc45c3de44f58cc5e992f26a3e70e87c99cbdded24f8",
    },
    {
        "byte_length": 36142,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v14.schema.json",
        "raw_sha256": "43bcb30ab3ae233122acec3cc820559b53dfd3071d9441df0f4a799f12e9c509",
    },
    {
        "byte_length": 28604,
        "classification_manifest_sha256": (
            "1fbd86f9587ccfb424bdeff7feda092004436475b491412837fc5d8d29adf043"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v13.json",
        "raw_sha256": "ce9a29e6d2a5703b6513f47afc123e3632d3bd5685edeb626715af66987f395f",
    },
    {
        "byte_length": 31864,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v13.schema.json",
        "raw_sha256": "037d0874beeae356b07f4e38f2f30a2d0256ba85f7824454e55bc79529e09414",
    },
    {
        "byte_length": 25470,
        "classification_manifest_sha256": (
            "59c4ccf12dde9c0204f87cc76c7cf49d875c6f544d3c5401f17d7084fe628834"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v12.json",
        "raw_sha256": "07b93bfe96bc75b2a2f12fee9ab4076d4d1b6224253810ad912d1cad0e2acfff",
    },
    {
        "byte_length": 28544,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v12.schema.json",
        "raw_sha256": "e55c3f71e45384f34973bb1b290a62a59f1fa49201630955b2c20b2559ba249c",
    },
    {
        "byte_length": 23496,
        "classification_manifest_sha256": (
            "9dd7186a350c36035d831c5ac9df1003e2c9b71a286ebd67873c170282c68d4e"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v11.json",
        "raw_sha256": "f427f01f2626ba148f7eb13439d7923fa430b4aaa97cfe7596b3695d2ecd9a0b",
    },
    {
        "byte_length": 26434,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v11.schema.json",
        "raw_sha256": "a2f3d5cb2a7621b1cec5b92d847f8370aba9226626d8dd133302ac5b6ad96049",
    },
    {
        "byte_length": 21616,
        "classification_manifest_sha256": (
            "c7fda664d8a192e63269094e3f9180e475f67adcbcf19592fb6db3572a7e6642"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v10.json",
        "raw_sha256": "6517b015ebb9b50507feffed682cbb4beecb90ff57935d20ee9792f67c71a4e1",
    },
    {
        "byte_length": 24418,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v10.schema.json",
        "raw_sha256": "268206397a113786c985099c9afc9e134dee4027ebb9f8a0f5d6b190ce125bd5",
    },
    {
        "byte_length": 19913,
        "classification_manifest_sha256": (
            "57320a77af9e8b63aa6f4c295c5b6f3102ab9bd2e7300b59d07cf6ac93b483e4"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v9.json",
        "raw_sha256": "81e9c23c36af0ad0123fbaad56a12e96746a32ccd9b249686499cbb44f6be259",
    },
    {
        "byte_length": 22577,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v9.schema.json",
        "raw_sha256": "5d53e9141dfee5758b4b4e841e43d33c0cc1299ed41ff812a5db9728de6d1d77",
    },
    {
        "byte_length": 18074,
        "classification_manifest_sha256": (
            "a2b112dfec65b15cda67ea6d14a1199305a3614cfe2174966894afb32ca261e7"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v8.json",
        "raw_sha256": "32aa72a70f77e9d0a43969b8471e3374ebd3adfd108283a65a1d9f263f2de1b7",
    },
    {
        "byte_length": 20602,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v8.schema.json",
        "raw_sha256": "decde7f7f5927a4809d21077848bfcb31dde68daf4df2e51c8cfcfb5e34a97cb",
    },
    {
        "byte_length": 15279,
        "classification_manifest_sha256": (
            "9f08a5f8f56907a661c9cc0ba31874bf63bf1e730dc2aa728408c07f76d98c0d"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v7.json",
        "raw_sha256": "773579688c9ab1363d3a9576582c1ea9ec21cf00616e05d4878f370f7fe444c5",
    },
    {
        "byte_length": 17615,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v7.schema.json",
        "raw_sha256": "84447dba722c97f50e60e928e3356e485aa093f06a267019e88e01948dd82cb8",
    },
    {
        "byte_length": 11660,
        "classification_manifest_sha256": (
            "1864d1df8a39ccaf20eba1cec2249576e04101ec2f6694b4dfda43aa82ddb443"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v6.json",
        "raw_sha256": "e5a16822a452129ef450fe8b0d582666b51d9d6ad718a01e956c172b6533921a",
    },
    {
        "byte_length": 13724,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v6.schema.json",
        "raw_sha256": "82b3be852d277568e9fd17b61ba17e7248f90316d40f9b096bb1ebb1aed35064",
    },
    {
        "byte_length": 9522,
        "classification_manifest_sha256": (
            "40d56d4ca27903dc0eab6efc9ea402901dcf5bd4a9dfec28784e17e9ea8606f8"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v5.json",
        "raw_sha256": "4de4c0f8df631713fc9dd1a33840b0a9805f4d63bd1cbfd7898922006728f50a",
    },
    {
        "byte_length": 11424,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v5.schema.json",
        "raw_sha256": "2dc2864616981fd9064194998342ad9b8b3ba91523f50663ba8f0686ed10b7ca",
    },
    {
        "byte_length": 9521,
        "classification_manifest_sha256": (
            "fece5b8fb2f53a92a3f92a32b27606be1354fa978fa5e891329bd13d13cddb4b"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v4.json",
        "raw_sha256": "0a7f06fd528ca5bc66f31740cd226de42d36e36ce7d49590b5ac1f5105c8a6d0",
    },
    {
        "byte_length": 11409,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v4.schema.json",
        "raw_sha256": "bad508a26ec01ab88521fd5d54b9a771da6165b6be84b070145bc715be676f25",
    },
    {
        "byte_length": 7399,
        "classification_manifest_sha256": (
            "9e7e799aaa51153b18ef636ca5c6e089538a05d97bedf16c026a396a1e109fc3"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v3.json",
        "raw_sha256": "a27fba61041961a321b4938431219d461b65427896885ce7bf52a43639488330",
    },
    {
        "byte_length": 8751,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v3.schema.json",
        "raw_sha256": "b80559e7e9eeac6b935f06d835b97bceb829da55d06daa390b8ec725088a03bd",
    },
    {
        "byte_length": 4684,
        "classification_manifest_sha256": (
            "2b129c103dd2a5f7ec8764416a8ef0bd34c5c2e9c3ef87a4a275176498ea384b"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v2.json",
        "raw_sha256": "da735f630490c7c59f7c2318f25c22328f8eab22f619dbaedacccaa5d1535ace",
    },
    {
        "byte_length": 8925,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v2.schema.json",
        "raw_sha256": "719392f98cae9798659dd851f13348ba5615895da86bea49e9286be8e58cbbda",
    },
    {
        "byte_length": 2557,
        "classification_manifest_sha256": (
            "8ab916ec611ce6cb8b72aaaa5afb25fcec372fd28071364803b75ba9e1a4ded0"
        ),
        "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v1.json",
        "raw_sha256": "cb510ff0d8fb329c65ede93dce8751c4826047519a7d7de4b74a8276bc6d3736",
    },
    {
        "byte_length": 4294,
        "path": "schemas/m0-3a-runtime-v2-resource-classification.v1.schema.json",
        "raw_sha256": "e032738e99a1f99f1fe3458867fc80517c7a3c7dd4758837306dd71ef8156992",
    },
)
CLOSURE_RESOURCE_EVIDENCE = (
    {
        "byte_length": 4153,
        "path": "docs/M0.3A_DEPENDENCY_CLOSURE_SHAPE.v1.md",
        "raw_sha256": "cb36c54b5e23d517868817e06a5420c954412942eb4451996f8c5f2281e0522b",
    },
    {
        "byte_length": 18786,
        "path": "tests/test_runtime_v2_closure.py",
        "raw_sha256": "56a8bbcf7afbdcb81a6d398fcbbee4f705a054f5cd2736e7a36fc6f20e922b57",
    },
)
BLOB_RESOURCE_EVIDENCE = (
    {
        "byte_length": 27054,
        "path": "docs/M0.3A_CONTENT_REDUCER_CONTRACT.v1.md",
        "raw_sha256": "3f3c031c11be2c9a96bf973447c6c3f04ed29609fca7230793e5fc4afafc7aac",
    },
    {
        "byte_length": 30521,
        "path": "docs/M0.3A_RUNTIME_IMAGE_CONTRACT.v1.md",
        "raw_sha256": "408c62a9fabd6182098d0fbe1c1f88c4b780f96b0aaf208e20b3fedfaf4ec550",
    },
    {
        "byte_length": 18200,
        "path": "tests/test_runtime_v2_image.py",
        "raw_sha256": "2cd685c78186bce2beb4f0d252acb084d03a4f0cf42d3e12364c4cfb1b75488d",
    },
)
SCHEMA_DOCUMENT_RESOURCE_EVIDENCE = (
    BLOB_RESOURCE_EVIDENCE[0],
    BLOB_RESOURCE_EVIDENCE[1],
    {
        "byte_length": 6452,
        "path": "tests/test_runtime_v2_schema_document_bound.py",
        "raw_sha256": "39e0385619d62dbea2018225c1f25212e45a4c15e3e59552a2b90b661c11e121",
    },
)
SCHEMA_REF_NODE_RESOURCE_EVIDENCE = (
    {
        "byte_length": 5330,
        "path": "docs/M0.3A_SCHEMA_REFERENCE_GRAPH_LIMIT.v1.md",
        "raw_sha256": "a7f6b16df0709b95755e83f1309934dff0e168db94c4c57e831f27b5b41d61f7",
    },
    {
        "byte_length": 7920,
        "path": "tests/test_runtime_v2_schema_ref_node_bound.py",
        "raw_sha256": "b0337687f556bfc35af28918614863d4b5aab0437200d5b286b6b8e66667779c",
    },
)
EVENT_BYTE_RESOURCE_EVIDENCE = (
    {
        "byte_length": 8989,
        "path": "docs/M0.3A_EVENT_BYTE_LIMIT.v1.md",
        "raw_sha256": "0b4113252759c144d8d44238b5a33d55fbd48b88f592daddb73354ff7b81ad2e",
    },
    {
        "byte_length": 30521,
        "path": "docs/M0.3A_RUNTIME_IMAGE_CONTRACT.v1.md",
        "raw_sha256": "408c62a9fabd6182098d0fbe1c1f88c4b780f96b0aaf208e20b3fedfaf4ec550",
    },
    {
        "byte_length": 5878,
        "path": "tests/test_runtime_v2_event_byte_bound.py",
        "raw_sha256": "06482fe7b557514ad0f4fbb55aa69fcd24ec901b0897df45ae98e1efaec9cb7b",
    },
    {
        "byte_length": 18200,
        "path": "tests/test_runtime_v2_image.py",
        "raw_sha256": "2cd685c78186bce2beb4f0d252acb084d03a4f0cf42d3e12364c4cfb1b75488d",
    },
)
CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE = (
    {
        "byte_length": 8341,
        "path": "docs/M0.3A_RUNTIME_CHECKPOINT_COPY_CARDINALITY_LIMIT.v1.md",
        "raw_sha256": "724350e3ea697a076b9d1176f1eb5c81305236d097fc5505a9d7e41ddef986fa",
    },
    BLOB_RESOURCE_EVIDENCE[1],
    {
        "byte_length": 9906,
        "path": "tests/test_runtime_v2_checkpoint_copy_cardinality_bound.py",
        "raw_sha256": "2e287d493f1d11451107a05d30a19ac6d25617629fb7a04f53155de866e576e0",
    },
    BLOB_RESOURCE_EVIDENCE[2],
)
BLOB_CARDINALITY_RESOURCE_EVIDENCE = (
    {
        "byte_length": 9018,
        "path": "docs/M0.3A_RUNTIME_BLOB_CARDINALITY_LIMIT.v1.md",
        "raw_sha256": "c102c63a42703bcbecf4edbcb9ab6ef5aaa5cbebe5e4d886b06a40c0411158bd",
    },
    BLOB_RESOURCE_EVIDENCE[1],
    {
        "byte_length": 11439,
        "path": "tests/test_runtime_v2_blob_cardinality_bound.py",
        "raw_sha256": "284ef2be27905cd18c81b5f2cbf6dad870b14d5a4fa508abef9b5ba322fbb93a",
    },
    BLOB_RESOURCE_EVIDENCE[2],
)
SCHEMA_REGISTRY_RESOURCE_EVIDENCE = (
    {
        "byte_length": 14328,
        "path": "docs/M0.3A_SCHEMA_REGISTRY_BYTE_LIMIT.v1.md",
        "raw_sha256": "0feb49080ee64e29f8d578c99c71140402c380794f31a903c8ea4771e767c25a",
    },
    BLOB_RESOURCE_EVIDENCE[0],
    BLOB_RESOURCE_EVIDENCE[1],
    {
        "byte_length": 9613,
        "path": "tests/test_runtime_v2_schema_registry_byte_bound.py",
        "raw_sha256": "7418100acf989cf22c11ccf0eba8de743ec4e7f9220ee3416f72270760ceb6b6",
    },
    BLOB_RESOURCE_EVIDENCE[2],
    {
        "byte_length": 21052,
        "path": "tests/test_runtime_v2_verifier.py",
        "raw_sha256": "159d601546a7c3076479c853154601a27e407c23950e9e61baa38c2abe0fa5fa",
    },
)
BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE = (
    {
        "byte_length": 12317,
        "path": "docs/M0.3A_BOOTSTRAP_DOCUMENT_BYTE_LIMIT.v1.md",
        "raw_sha256": "9366d24c7c9913d05a6a26218e90153927b39fb22304e55cfc6942b93fa452eb",
    },
    BLOB_RESOURCE_EVIDENCE[1],
    {
        "byte_length": 9317,
        "path": "tests/test_runtime_v2_bootstrap_document_byte_bound.py",
        "raw_sha256": "8a24c95f506e9dc8e9f2ddec3bec47e6be0ad8de6a0450b65251a13c44290951",
    },
    BLOB_RESOURCE_EVIDENCE[2],
)
TRANSITION_ARGUMENT_RESOURCE_EVIDENCE = (
    {
        "byte_length": 9182,
        "path": "docs/M0.3A_TRANSITION_ARGUMENT_LIMIT.v1.md",
        "raw_sha256": "bdd5372ccb67e1414036a6b3c4adafff145652f3c397f8546ec76a09345cf7e0",
    },
    {
        "byte_length": 7924,
        "path": "tests/test_runtime_v2_transition_argument_bound.py",
        "raw_sha256": "b2dab044b678b21b873b8b4de036c93dd85df67a704dea54a3f8d0cff543cc0a",
    },
)
TRANSITION_SEMANTIC_EVENT_RESOURCE_EVIDENCE = (
    {
        "byte_length": 7665,
        "path": "docs/M0.3A_TRANSITION_SEMANTIC_EVENT_CONSTRUCTION_LIMIT.v1.md",
        "raw_sha256": "1d1af397aeb3b4af815aa5ea91af9e415ccdf2059aca008d6f00c84832839c90",
    },
    {
        "byte_length": 7354,
        "path": "tests/test_runtime_v2_transition_semantic_event_bound.py",
        "raw_sha256": "60dca2b55983d3daa008a0c5a5ab1d085043434dde223b76c0d992beb5ba2245",
    },
)
TRANSITION_TASK_RESOURCE_EVIDENCE = (
    {
        "byte_length": 8371,
        "path": "docs/M0.3A_TRANSITION_TASK_RESOURCE_LIMIT.v1.md",
        "raw_sha256": "fcdcd50031ff551473f282e52c4b61976f9d31a3c4561891f5b0d20abfcc5481",
    },
    {
        "byte_length": 7979,
        "path": "tests/test_runtime_v2_transition_task_bound.py",
        "raw_sha256": "97c8436043ef7a297cc697dbfff412d823596ea718b81ce7fef60c0e0be0cdd0",
    },
)
SCHEMA_BUNDLE_RESOURCE_EVIDENCE = (
    {
        "byte_length": 4513,
        "path": "docs/M0.3A_SCHEMA_BUNDLE_BYTE_LIMIT.v1.md",
        "raw_sha256": "5f58822d964eed424b8d2e11b23bea10241d227f0b378f67c20dfd7f49092a4e",
    },
    {
        "byte_length": 10794,
        "path": "tests/test_runtime_v2_schema_bundle_byte_bound.py",
        "raw_sha256": "f1d9c240998065e2aec1118a2c35be61f39647a542350ac9b300ce5846b3faea",
    },
)
PORTABLE_PATH_RESOURCE_EVIDENCE = (
    {
        "byte_length": 10592,
        "path": "docs/M0.3A_PORTABLE_PATH_CHARACTER_LIMIT.v1.md",
        "raw_sha256": "1d9995dd26cc8f11b4527a91b9971547141a55f8fce10ecb3b2b8f45ef63d023",
    },
    {
        "byte_length": 6046,
        "path": "tests/test_runtime_v2_portable_path_bound.py",
        "raw_sha256": "f8683bc5ad8da3d29816b3034a23d4d98225ea62ee365af36e3b6454468db50e",
    },
)
PORTABLE_COMPONENT_RESOURCE_EVIDENCE = (
    {
        "byte_length": 8073,
        "path": "docs/M0.3A_PORTABLE_COMPONENT_CHARACTER_LIMIT.v1.md",
        "raw_sha256": "916185c0ba63a6cf482cd4f89072e3709b3dfbbcfeaba18927be683f951f35b8",
    },
    {
        "byte_length": 6380,
        "path": "tests/test_runtime_v2_portable_component_bound.py",
        "raw_sha256": "51ad4220bcc8f540c4e1aaf7b9274af62cc88ff1c3ef48ab2751ad55d9e74e29",
    },
)
MIGRATIONS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 3535,
        "path": "docs/M0.3A_RUNTIME_MIGRATIONS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "64468af7dbd1a2a83c9540b69773d0e7e413b38b4ad99cef5dbe55d24c63e8f3"
        ),
    },
    {
        "byte_length": 7090,
        "path": "tests/test_runtime_v2_migrations_table_row_bound.py",
        "raw_sha256": (
            "85bc9dd3f9c9f9e2d758a9d7d12b2e3f493e750c586b1869078de722066d76a7"
        ),
    },
)
LEGACY_ARCHIVE_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 3822,
        "path": "docs/M0.3A_RUNTIME_LEGACY_ARCHIVE_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "3cd2e54880feb82c77ed598fec64508933e80e07c210607bc5873caa4ad0880b"
        ),
    },
    {
        "byte_length": 7252,
        "path": "tests/test_runtime_v2_legacy_archive_table_row_bound.py",
        "raw_sha256": (
            "f1fa67307be78d835405a1c42878682fc6530fb2ead74bb9ee48b187e504d11b"
        ),
    },
)
METADATA_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 3966,
        "path": "docs/M0.3A_RUNTIME_METADATA_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "ac0c4b266ed61a75d6f53b9a762984507ca309cc3970be19848d8bb99163dac4"
        ),
    },
    {
        "byte_length": 7063,
        "path": "tests/test_runtime_v2_metadata_table_row_bound.py",
        "raw_sha256": (
            "5b8c81858ff2766190b5a83c6a1e988762361b160c06136d574409bd0d2b2152"
        ),
    },
)
SCHEMA_REGISTRY_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 4006,
        "path": "docs/M0.3A_RUNTIME_SCHEMA_REGISTRY_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "f9eb3c17566906a179d3aaea387615b689f92254a842a610a7304a886dc984cf"
        ),
    },
    {
        "byte_length": 7349,
        "path": "tests/test_runtime_v2_schema_registry_table_row_bound.py",
        "raw_sha256": (
            "628d74115c8cfbaa183f9db87e2bab5f8295b04707712a1b20abf14e50068797"
        ),
    },
)
SEALS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2270,
        "path": "docs/M0.3A_RUNTIME_SEALS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "04f422f1fa573d4a83f174e348637a26b261680e9ba3d1c1b43cb5994c1f9257"
        ),
    },
    {
        "byte_length": 6705,
        "path": "tests/test_runtime_v2_seals_table_row_bound.py",
        "raw_sha256": (
            "6f1f0370f605ecaac7d0b8c5c3f2bd2aa003c020e3b3cf80a5f3fec6b043035e"
        ),
    },
)
SCHEMA_DOCUMENTS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2093,
        "path": "docs/M0.3A_RUNTIME_SCHEMA_DOCUMENTS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "25d32f2831360a8a5926af7f2ac87b940bc633a27308b5df0cf9c85ee3379553"
        ),
    },
    {
        "byte_length": 7234,
        "path": "tests/test_runtime_v2_schema_documents_table_row_bound.py",
        "raw_sha256": (
            "2ac84da72b34d0db7b9263eef7ab1b5f71fb56156c36b73d6dfd3e8e17ec08b5"
        ),
    },
)
ATTEMPTS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2441,
        "path": "docs/M0.3A_RUNTIME_ATTEMPTS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "cbb04d1a6cffd1acccb856a39bb6a53e972e684428da1a69f4a895276d952c9b"
        ),
    },
    {
        "byte_length": 6580,
        "path": "tests/test_runtime_v2_attempts_table_row_bound.py",
        "raw_sha256": (
            "35f42d0ce68a554cea5b889a7ea8ef73f3a90fbcd195988aaa9e94b9c26ad875"
        ),
    },
)
CLAIMS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2476,
        "path": "docs/M0.3A_RUNTIME_CLAIMS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "76824e5ed27c6f0313b64565a43b601b16c6a019d1d55d91244f387ffdb77bae"
        ),
    },
    {
        "byte_length": 6566,
        "path": "tests/test_runtime_v2_claims_table_row_bound.py",
        "raw_sha256": (
            "670b71329b1b2e5be52b0154e7cf6607400fb8a1732811e558561ca2e6d325c7"
        ),
    },
)
BLOBS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2315,
        "path": "docs/M0.3A_RUNTIME_BLOBS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "68a3676a38d53f2a80c1d2d208536f5dd99fb2e080f32a935ca84f7f1a824243"
        ),
    },
    {
        "byte_length": 7588,
        "path": "tests/test_runtime_v2_blobs_table_row_bound.py",
        "raw_sha256": (
            "d835030402bf8f3419698b7b57d64614f960820a9e7551a07b0a175dbc4d2e7d"
        ),
    },
)
EVENTS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2418,
        "path": "docs/M0.3A_RUNTIME_EVENTS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "bc876dfec2ea6e7e6dea15d2bc450855be4801a1196027730e597e43279c8d52"
        ),
    },
    {
        "byte_length": 7575,
        "path": "tests/test_runtime_v2_events_table_row_bound.py",
        "raw_sha256": (
            "2864cee9fd5b8dcce53dddfa2566353aeb63b2ee6901b5e2d34207ed51534079"
        ),
    },
)
IDEMPOTENCY_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2291,
        "path": "docs/M0.3A_RUNTIME_IDEMPOTENCY_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "3eeb191d14a93659d5873224b48b4024edcf0b11c07709b9d2e46ea68bcb8eaf"
        ),
    },
    {
        "byte_length": 6746,
        "path": "tests/test_runtime_v2_idempotency_table_row_bound.py",
        "raw_sha256": (
            "0f7058eb2103f7728ac213239ee58084c3af61872ba56440f82c3ecd9aa4dc23"
        ),
    },
)
REMEDIATION_LINKS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2296,
        "path": "docs/M0.3A_RUNTIME_REMEDIATION_LINKS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "c9eb280b9fe0bf7a45e3190bf963389f0b113d074ae33843ee9c67a68d167c95"
        ),
    },
    {
        "byte_length": 6855,
        "path": "tests/test_runtime_v2_remediation_links_table_row_bound.py",
        "raw_sha256": (
            "3e5c9d09168ce065829ab0dfad294e457f1ef106d5a0b7f133b712e9a8581a49"
        ),
    },
)
SNAPSHOTS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2305,
        "path": "docs/M0.3A_RUNTIME_SNAPSHOTS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "67c0620a6fef24e1bdc0c5c57eb539260f742fd9ce46002351b3ce2f2d3bb607"
        ),
    },
    {
        "byte_length": 6809,
        "path": "tests/test_runtime_v2_snapshots_table_row_bound.py",
        "raw_sha256": (
            "27b9fa455672cbd0292f270f155848f9d3988b8baa861323eaa1d018aab5af78"
        ),
    },
)
REVIEWS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2392,
        "path": "docs/M0.3A_RUNTIME_REVIEWS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "cbbf09aefc4875f23a1aceeab3ebad646b0474c3539d3d89ee06fd67508de668"
        ),
    },
    {
        "byte_length": 6729,
        "path": "tests/test_runtime_v2_reviews_table_row_bound.py",
        "raw_sha256": (
            "04b0c8adfdcdc341dba5986a99e7e39a8807ffef89abad3497924208f9917b79"
        ),
    },
)
TASKS_TABLE_ROW_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2537,
        "path": "docs/M0.3A_RUNTIME_TASKS_TABLE_ROW_LIMIT.v1.md",
        "raw_sha256": (
            "cdea0acdc12d16b663b07768f1f689628e46c17995cde6cd08568b6c908b9504"
        ),
    },
    {
        "byte_length": 6823,
        "path": "tests/test_runtime_v2_tasks_table_row_bound.py",
        "raw_sha256": (
            "8050177545754a8cbf5e8c6a933c98ce0112db7fa7fef052a39c0f4fe56ab123"
        ),
    },
)
TOP_LEVEL_EVENTS_MAXIMUM_RESOURCE_EVIDENCE = (
    {
        "byte_length": 3156,
        "path": "docs/M0.3A_RUNTIME_TOP_LEVEL_EVENTS_MAXIMUM.v1.md",
        "raw_sha256": (
            "10a771a7816588b461bb5ab7495c6b16928323a887520d190896ff3bba4bd27b"
        ),
    },
    {
        "byte_length": 9922,
        "path": "tests/test_runtime_v2_top_level_events_maximum_classification.py",
        "raw_sha256": (
            "06a441f684ca9efb51a9226488594c8f751e79ff38d3f5a062494e33db07fcf8"
        ),
    },
)
FINDING_STRING_BOUNDS_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2763,
        "path": "docs/M0.3A_RUNTIME_V2_FINDING_STRING_BOUNDS.v1.md",
        "raw_sha256": (
            "e2bb3f79c8e7877b1ad3f085c6303058a5e2671b73171c384e451837e7214eef"
        ),
    },
    {
        "byte_length": 10740,
        "path": "tests/test_runtime_v2_finding_string_bounds_classification.py",
        "raw_sha256": (
            "7acf9bc779a283e914ad728511c2ec68671c838c7a13d2a84222d887347e8c8a"
        ),
    },
)
CLOSURE_INTEGER_TOKEN_DIGIT_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2041,
        "path": "docs/M0.3A_CLOSURE_INTEGER_TOKEN_DIGIT_LIMIT.v1.md",
        "raw_sha256": (
            "bc3f08c5d8b3ea8d3366cda46fb02ba7c8920dc183845116b9973dacbc753ac1"
        ),
    },
    {
        "byte_length": 7773,
        "path": "tests/test_runtime_v2_closure_integer_token_digit_bound.py",
        "raw_sha256": (
            "6b27185ba24852c9b297816c6c12fd349fca04597c0a243b65a78d9f81e82fd6"
        ),
    },
)
SCHEMA_REF_TOKEN_CHARACTER_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2104,
        "path": "docs/M0.3A_VERIFIER_SCHEMA_REF_TOKEN_CHARACTER_LIMIT.v1.md",
        "raw_sha256": (
            "88092c4ed12cd10cb09f8ae64116265b6651c5249cbb210f594f97538a7d8047"
        ),
    },
    {
        "byte_length": 8156,
        "path": "tests/test_runtime_v2_schema_ref_token_character_bound.py",
        "raw_sha256": (
            "18d634c4540dd784a666e91ed85ea324f4bc5291267fd17f864807c679d3c8b6"
        ),
    },
)
SCHEMA_DEFINITION_NAME_CHARACTER_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2461,
        "path": "docs/M0.3A_VERIFIER_SCHEMA_DEFINITION_NAME_CHARACTER_LIMIT.v1.md",
        "raw_sha256": (
            "6ed7bc37b2c0e90e45a83cfdd629bc9aa1f094f57da55c53e1ce07aee0f1d48d"
        ),
    },
    {
        "byte_length": 8027,
        "path": "tests/test_runtime_v2_schema_definition_name_character_bound.py",
        "raw_sha256": (
            "88edf1e84dfcb27bf44270513269c023cb094ec4f383685ed4aede6d6bad13b0"
        ),
    },
)
CODEC_PRIVATE_VALIDATE_DEPTH_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2066,
        "path": "docs/M0.3A_CODEC_PRIVATE_VALIDATE_DEPTH_LIMIT.v1.md",
        "raw_sha256": (
            "a592c54cab97385d6b0d9286a52b03d4f9cd597db7e1a056af335cdeac98f6a0"
        ),
    },
    {
        "byte_length": 6135,
        "path": "tests/test_runtime_v2_codec_private_validate_depth_bound.py",
        "raw_sha256": (
            "fef0b68465cfb0f1c7ed144f76b58fb8815ce921fa4db74b9346d797846ddb5e"
        ),
    },
)
INITIAL_REDUCER_FINDING_CODE_RESOURCE_EVIDENCE = (
    {
        "byte_length": 2063,
        "path": "docs/M0.3A_INITIAL_REDUCER_FINDING_CODE_CHARACTER_LIMIT.v1.md",
        "raw_sha256": (
            "d3085ec3f8c49b10adb302f3504eaca06f4a80eaa7320ab14e56e153cfa28d92"
        ),
    },
    {
        "byte_length": 6635,
        "path": "tests/test_runtime_v2_initial_reducer_finding_code_character_bound.py",
        "raw_sha256": (
            "bdd9159fa4c36f6f498f75d66c87d4e42f5023d8549bdf5564036fe644332a5c"
        ),
    },
)
RESOURCE_CLASSIFICATION_V45_EVIDENCE_REBASES = {
    "tests/test_runtime_v2_top_level_events_maximum_classification.py": {
        "historical": {"byte_length": 10354, "raw_sha256": "bcd2e1ad3954202b517e85a7ced54ca09dd347064795a41ce3b6286f6490ce33"},
        "current": {"byte_length": 10218, "raw_sha256": "c5265746eac80f6ebba03635e921d963d388bf9e17492f21cc9eebe0e6f92621"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_finding_string_bounds_classification.py": {
        "historical": {"byte_length": 10911, "raw_sha256": "785f29ea75a0e12e90f2823d1a7c4f01bd79b5d99950460f7bfd34837fb2a8bb"},
        "current": {"byte_length": 10907, "raw_sha256": "9137a13418cc83b5728c60807fb60c3e6dff6148bef9815baa841c21adea3768"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_closure_integer_token_digit_bound.py": {
        "historical": {"byte_length": 8274, "raw_sha256": "f792a235d763b5fc0a184219473a53a3fdeacd470c00f0a1e0175c4c1678ad4f"},
        "current": {"byte_length": 8257, "raw_sha256": "f8bec626f11c91287eb283364e5093695623d09da42b797587b6fcddcbb6e704"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_schema_ref_token_character_bound.py": {
        "historical": {"byte_length": 8657, "raw_sha256": "95ad9881e0f412e615c97f694ab66e4096adda75f2918a3231455e9f4865ea25"},
        "current": {"byte_length": 8640, "raw_sha256": "d06deac9683b237d288caaf8cd4147afbb4c5c388ff5c49ac9f09296d1606e91"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_schema_definition_name_character_bound.py": {
        "historical": {"byte_length": 8528, "raw_sha256": "441588800ce13180c778ba32ec137e1b6945900f4865e00b03109909f1aab75d"},
        "current": {"byte_length": 8511, "raw_sha256": "6c096da9e3207a07df5772154c402ee0c7cb1a9c669089c5be6ffa18ee1dabf0"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_codec_private_validate_depth_bound.py": {
        "historical": {"byte_length": 6636, "raw_sha256": "d1dcb9f155ffeefdde3332e3d4d61593542914019a7e12ae2f588c8d8e355b20"},
        "current": {"byte_length": 6619, "raw_sha256": "845d695ca3818d295c23e021f346cf5aa70ebcd3a643b06b737442432a24ece8"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_initial_reducer_finding_code_character_bound.py": {
        "historical": {"byte_length": 7136, "raw_sha256": "155ed49e56885aa536722a8ec5c46d2c82bc514355f6f1b9e9f887641b1da8da"},
        "current": {"byte_length": 7119, "raw_sha256": "c09fc7fae24ed111c568f86f6b453b2bbf3784d6051e624282b66aa4292a9130"},
        "classification_evidence": True,
    },
    "tests/test_runtime_v2_schema_resource_site_identity_discovery.py": {
        "historical": {"byte_length": 12715, "raw_sha256": "6e2225936de6fc605c460fb1ae8445716c72e936cdbf6ebd0910a3b55e02fb9e"},
        "current": {"byte_length": 12822, "raw_sha256": "d61f32aef38ec52eafc55ba9f22c14b9d70d377d5ae82121ded453eda4af7a00"},
        "classification_evidence": False,
    },
}
RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES = {
    (
        "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM",
        "tests/test_runtime_v2_top_level_events_maximum_classification.py",
    ): {
        "historical": {"byte_length": 10218, "raw_sha256": "c5265746eac80f6ebba03635e921d963d388bf9e17492f21cc9eebe0e6f92621"},
        "current": {"byte_length": 9922, "raw_sha256": "06a441f684ca9efb51a9226488594c8f751e79ff38d3f5a062494e33db07fcf8"},
    },
    (
        "VERIFIER_FINDING_ARTIFACT_CHARACTER_MAXIMUM",
        "tests/test_runtime_v2_finding_string_bounds_classification.py",
    ): {
        "historical": {"byte_length": 10907, "raw_sha256": "9137a13418cc83b5728c60807fb60c3e6dff6148bef9815baa841c21adea3768"},
        "current": {"byte_length": 10740, "raw_sha256": "7acf9bc779a283e914ad728511c2ec68671c838c7a13d2a84222d887347e8c8a"},
    },
    (
        "VERIFIER_FINDING_COORDINATE_CHARACTER_MAXIMUM",
        "tests/test_runtime_v2_finding_string_bounds_classification.py",
    ): {
        "historical": {"byte_length": 10907, "raw_sha256": "9137a13418cc83b5728c60807fb60c3e6dff6148bef9815baa841c21adea3768"},
        "current": {"byte_length": 10740, "raw_sha256": "7acf9bc779a283e914ad728511c2ec68671c838c7a13d2a84222d887347e8c8a"},
    },
    (
        "CLOSURE_INTEGER_TOKEN_MAX_DIGITS",
        "tests/test_runtime_v2_closure_integer_token_digit_bound.py",
    ): {
        "historical": {"byte_length": 8257, "raw_sha256": "f8bec626f11c91287eb283364e5093695623d09da42b797587b6fcddcbb6e704"},
        "current": {"byte_length": 7773, "raw_sha256": "6b27185ba24852c9b297816c6c12fd349fca04597c0a243b65a78d9f81e82fd6"},
    },
    (
        "VERIFIER_SCHEMA_REF_TOKEN_CHARACTER_MAXIMUM",
        "tests/test_runtime_v2_schema_ref_token_character_bound.py",
    ): {
        "historical": {"byte_length": 8640, "raw_sha256": "d06deac9683b237d288caaf8cd4147afbb4c5c388ff5c49ac9f09296d1606e91"},
        "current": {"byte_length": 8156, "raw_sha256": "18d634c4540dd784a666e91ed85ea324f4bc5291267fd17f864807c679d3c8b6"},
    },
    (
        "VERIFIER_SCHEMA_DEFINITION_NAME_CHARACTER_MAXIMUM",
        "tests/test_runtime_v2_schema_definition_name_character_bound.py",
    ): {
        "historical": {"byte_length": 8511, "raw_sha256": "6c096da9e3207a07df5772154c402ee0c7cb1a9c669089c5be6ffa18ee1dabf0"},
        "current": {"byte_length": 8027, "raw_sha256": "88edf1e84dfcb27bf44270513269c023cb094ec4f383685ed4aede6d6bad13b0"},
    },
    (
        "CODEC_PRIVATE_VALIDATE_DEPTH_MAXIMUM",
        "tests/test_runtime_v2_codec_private_validate_depth_bound.py",
    ): {
        "historical": {"byte_length": 6619, "raw_sha256": "845d695ca3818d295c23e021f346cf5aa70ebcd3a643b06b737442432a24ece8"},
        "current": {"byte_length": 6135, "raw_sha256": "fef0b68465cfb0f1c7ed144f76b58fb8815ce921fa4db74b9346d797846ddb5e"},
    },
    (
        "INITIAL_REDUCER_FINDING_CODE_CHARACTER_MAXIMUM",
        "tests/test_runtime_v2_initial_reducer_finding_code_character_bound.py",
    ): {
        "historical": {"byte_length": 7119, "raw_sha256": "c09fc7fae24ed111c568f86f6b453b2bbf3784d6051e624282b66aa4292a9130"},
        "current": {"byte_length": 6635, "raw_sha256": "bdd9159fa4c36f6f498f75d66c87d4e42f5023d8549bdf5564036fe644332a5c"},
    },
    (
        "SCHEMA_DECLARATIVE_MINLENGTH_685812B87027CEA3E8FC9CE370FD21377B11FC6459C06BF2151261260CD178EA",
        "tests/test_runtime_v2_active_runtime_id_min_length_schema_proof.py",
    ): {
        "historical": {"byte_length": 11009, "raw_sha256": "911aceadc6b1cd28b9120c21ec77a173ff0348cc06a71de0bcbfe9a973690708"},
        "current": {"byte_length": 10636, "raw_sha256": "1440ad1243636d0fb4faf066e362eee269d0ebca321ee3cec78c451314e6ceca"},
    },
}
RESOURCE_CLASSIFICATION_CURRENT_TEST_PATH = (
    "tests/test_runtime_v2_resource_classification_current.py"
)
RESOURCE_CLASSIFICATION_V42_REBASED_EVIDENCE = {
    "VERIFIER_FINDING_ARTIFACT_CHARACTER_MAXIMUM": (
        {
            "byte_length": 2763,
            "path": "docs/M0.3A_RUNTIME_V2_FINDING_STRING_BOUNDS.v1.md",
            "raw_sha256": (
                "e2bb3f79c8e7877b1ad3f085c6303058a5e2671b73171c384e451837e7214eef"
            ),
        },
        {
            "byte_length": 10906,
            "path": (
                "tests/test_runtime_v2_finding_string_bounds_classification.py"
            ),
            "raw_sha256": (
                "ead184d83fb02f94829214678231ab820e5914bced48cf91b002409f90f6d16a"
            ),
        },
    ),
    "VERIFIER_FINDING_COORDINATE_CHARACTER_MAXIMUM": (
        {
            "byte_length": 2763,
            "path": "docs/M0.3A_RUNTIME_V2_FINDING_STRING_BOUNDS.v1.md",
            "raw_sha256": (
                "e2bb3f79c8e7877b1ad3f085c6303058a5e2671b73171c384e451837e7214eef"
            ),
        },
        {
            "byte_length": 10906,
            "path": (
                "tests/test_runtime_v2_finding_string_bounds_classification.py"
            ),
            "raw_sha256": (
                "ead184d83fb02f94829214678231ab820e5914bced48cf91b002409f90f6d16a"
            ),
        },
    ),
}
RESOURCE_CLASSIFICATION_EVIDENCE = (
    *BLOB_RESOURCE_EVIDENCE,
    *CLOSURE_RESOURCE_EVIDENCE,
    EVENT_BYTE_RESOURCE_EVIDENCE[0],
    EVENT_BYTE_RESOURCE_EVIDENCE[2],
    CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE[0],
    CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE[2],
    BLOB_CARDINALITY_RESOURCE_EVIDENCE[0],
    BLOB_CARDINALITY_RESOURCE_EVIDENCE[2],
    SCHEMA_DOCUMENT_RESOURCE_EVIDENCE[2],
    *SCHEMA_REF_NODE_RESOURCE_EVIDENCE,
    SCHEMA_REGISTRY_RESOURCE_EVIDENCE[0],
    SCHEMA_REGISTRY_RESOURCE_EVIDENCE[3],
    SCHEMA_REGISTRY_RESOURCE_EVIDENCE[5],
    BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE[0],
    BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE[2],
    *TRANSITION_ARGUMENT_RESOURCE_EVIDENCE,
    *TRANSITION_SEMANTIC_EVENT_RESOURCE_EVIDENCE,
    *TRANSITION_TASK_RESOURCE_EVIDENCE,
    *SCHEMA_BUNDLE_RESOURCE_EVIDENCE,
    *PORTABLE_PATH_RESOURCE_EVIDENCE,
    *PORTABLE_COMPONENT_RESOURCE_EVIDENCE,
    *MIGRATIONS_TABLE_ROW_RESOURCE_EVIDENCE,
    *LEGACY_ARCHIVE_TABLE_ROW_RESOURCE_EVIDENCE,
    *METADATA_TABLE_ROW_RESOURCE_EVIDENCE,
    *SCHEMA_REGISTRY_TABLE_ROW_RESOURCE_EVIDENCE,
    *SEALS_TABLE_ROW_RESOURCE_EVIDENCE,
    *SCHEMA_DOCUMENTS_TABLE_ROW_RESOURCE_EVIDENCE,
    *ATTEMPTS_TABLE_ROW_RESOURCE_EVIDENCE,
    *CLAIMS_TABLE_ROW_RESOURCE_EVIDENCE,
    *BLOBS_TABLE_ROW_RESOURCE_EVIDENCE,
    *EVENTS_TABLE_ROW_RESOURCE_EVIDENCE,
    *IDEMPOTENCY_TABLE_ROW_RESOURCE_EVIDENCE,
    *REMEDIATION_LINKS_TABLE_ROW_RESOURCE_EVIDENCE,
    *SNAPSHOTS_TABLE_ROW_RESOURCE_EVIDENCE,
    *REVIEWS_TABLE_ROW_RESOURCE_EVIDENCE,
    *TASKS_TABLE_ROW_RESOURCE_EVIDENCE,
    *TOP_LEVEL_EVENTS_MAXIMUM_RESOURCE_EVIDENCE,
    *FINDING_STRING_BOUNDS_RESOURCE_EVIDENCE,
    *CLOSURE_INTEGER_TOKEN_DIGIT_RESOURCE_EVIDENCE,
    *SCHEMA_REF_TOKEN_CHARACTER_RESOURCE_EVIDENCE,
    *SCHEMA_DEFINITION_NAME_CHARACTER_RESOURCE_EVIDENCE,
    *CODEC_PRIVATE_VALIDATE_DEPTH_RESOURCE_EVIDENCE,
    *INITIAL_REDUCER_FINDING_CODE_RESOURCE_EVIDENCE,
    {
        "byte_length": 1983,
        "path": "docs/M0.3A_ACTIVE_RUNTIME_ID_MIN_LENGTH_SCHEMA_PROOF.v1.md",
        "raw_sha256": (
            "b5b900ea23e8c54b5667510f21900ea81592f9ea893e169716593937457eb593"
        ),
    },
    {
        "byte_length": 10636,
        "path": (
            "tests/test_runtime_v2_active_runtime_id_min_length_schema_proof.py"
        ),
        "raw_sha256": (
            "1440ad1243636d0fb4faf066e362eee269d0ebca321ee3cec78c451314e6ceca"
        ),
    },
)
CLASSIFIED_RESOURCE_SITE_IDS = frozenset({
    "299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8",
    "be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c",
    "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd",
    "6e95fce4ad2ed77d84d5bfaad79566cb4276adc28054fb8bde30b0bbb5c911c5",
    "66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474",
    "7b99b5408a023f557be70736b52ecf6a8de4d8594b0da6318cacb3c9680cf5fc",
    "90292d8f8df61b2ee109adf7df0d0d4e44c2cdf5a6f70c887e7e5228d4cb8657",
    "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f",
    "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98",
    "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e",
    "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed",
    "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c",
    "fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8",
    "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4",
    "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b",
    "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0",
    "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b",
    "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a",
    "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72",
    "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed",
    "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428",
    "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737",
    "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990",
    "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2",
    "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b",
    "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793",
    "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e",
    "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18",
    "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a",
    "d59dabf071e0d9cce0c5d6e1478ce6aa55a09362b85136709a4df94bf19966e0",
    "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3",
    "4c738024dfcbda75cf4c6a621c2b51624a9278bb5b4e10b912c43f1dbd5be208",
    "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13",
    "1ef42fea7eca273c2040d72810435052d0241a4e9a4d7ba63598548d95d5249c",
    "222b398c640f6311f8597b487de626c2dfb65f4340a6fb1ece58292788c9b8d3",
    "344950b527bcecb073b777c4bbf743de50dd920bd4aa76dbbf58045ff9f00ab5",
    "4650c76c2ae3e065cd5767e97b8a59d917415ba1dfc73f79f0efd8b09f4f3eef",
    "9c9756b7f77e91caf4044c0cb19c52dc2d0335a749fc7690e00ddd6a9a1b6b38",
    "a1c0d45cbce3ceffdaeb036a93474801b525220e1d16ab5505dba14115313caa",
    "e5ebe2c841739dfbb79d7fb7c04879320c9d4b5313534822b1e3696798afc40d",
    "f0929588df702f47d6a2f6fe255d87b6bf4a0e083cbfdbb0cc0f699973edc2ab",
    "fa0e657aa776634a22b750a8fce2c4ed1ff0de61ff58841530de76225f9e8630",
    "61d3dcc5d5ed733e6d561edeb43ddcc00ab2aa8fc899b09353733877ea76a721",
    "7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a",
    "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534",
    "4c9346726487e13663e822fd8b63e995c6066a487dfbe2b6350e051ce2440384",
    "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
    "cc9e6904b1fdb98deea9fd35ddc4ae864aa572cbf5d963addbf8cc42beae4522",
    "d02eb8dbac3f0359f160e1fb6259b5a438ec699a64cca7cd05d94c5ab86b1683",
    "8927485f8c04590dc06fa8d3bffde6e82517d898ec72637dbf758e21a56996d8",
    "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
    "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
    "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
    "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
    "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
    "5e7fc3b44c63b42e94213efd280dd3af90eac0beb4a2b28f600a5284f17fc3b4",
    "3d85d6c3d9c53b2d68ee976d4b159cc92ae9fd506ad608d00ff0563db5864209",
    "fc3a2cf8ca0ab37c1fedcfb108152b40bd65fec0207eac9cd9b3f7f32b8cfd27",
    "ab8d61b1084c8ac24f8b434b52065e9fc3c5dce60285fed332f3489d165b03d3",
    "9313b4636313fad249f6a01b9e4ef96f22ef88b10fa98ca95a736d0ce994c3df",
    "80d3960b21e42ebc549ca5eabd07e811430b1628150d9eb1e8922d491dc86072",
    "13130db6d96d447bd0bec45528c39f4354a2897e282585c7b4976335e25b025c",
    "6109c0c4afb317c7bde39b19501f7de6b627528dd36f967c82e2ed311fbfc0ca",
    "2663812aee226be4f57a1862523798243d7df5a12a1d9e29f586ec8e7ded5638",
    "3d07b02992a995d0a13d408dda7d2acf04e1c5a9d185f98651814d6dfff2b59d",
    "0f3792a9755d878d6e5a60afd21ef8e1d38c30f3be3d59879b6cfa860754f465",
    "18d9f6c7a27e97c092460277fc35bbf9151791127dd0da5a161a8866ef04bbcf",
    "4a75bf21a088cd48d5c1b38b2b3157fc47542b0132b562be3699e94858a65c9e",
    "2d673fb49e50239b37577ac23e4f6fdbf899523908d338e3618993594ab5f410",
    "344713dc75b24db9402649b88570c54a438e5b3b9f17dac677b8cd4313825df4",
    "4ba11eee3bbe1d3fa772fabebf0edc386903f94c9862c242c7124b8bf0cf6cb6",
})
CLASSIFIED_SCHEMA_RESOURCE_SITE_IDS = frozenset({
    "55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b",
    "685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea",
})
SCHEMA_BOUND_KEYWORDS = frozenset({
    "exclusiveMaximum", "exclusiveMinimum", "maximum", "maxContains",
    "maxItems", "maxLength", "maxProperties", "minimum", "minContains",
    "minItems", "minLength", "minProperties",
})
SOURCE_BOUND_CALLS = frozenset({
    "_array", "_integer", "_string", "_strict_int", "_TableSpec",
    "bounded", "range",
})


class ReadinessError(ValueError):
    """The inspected tree cannot be represented by this readiness profile."""

    def __init__(self, code: str, coordinate: str) -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parse_json(raw: bytes, coordinate: str) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReadinessError("DUPLICATE_JSON_KEY", coordinate)
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate,
            parse_float=lambda _: (_ for _ in ()).throw(
                ReadinessError("NONINTEGER_JSON_NUMBER", coordinate)
            ),
            parse_constant=lambda _: (_ for _ in ()).throw(
                ReadinessError("NONINTEGER_JSON_NUMBER", coordinate)
            ),
        )
    except ReadinessError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReadinessError("INVALID_JSON", coordinate) from error


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ReadinessError("CANONICAL_JSON", "/") from error


def _domain_digest(domain: str, value: Any) -> str:
    return _sha256(domain.encode("ascii") + _canonical_json(value))


def _module_path(module: str) -> str:
    if module == "edgelab":
        return "src/edgelab/__init__.py"
    prefix = "edgelab."
    if not module.startswith(prefix):
        raise ReadinessError("LOCAL_MODULE_NAME", module)
    leaf = module[len(prefix):]
    if not leaf or "." in leaf:
        raise ReadinessError("LOCAL_MODULE_NAME", module)
    return f"src/edgelab/{leaf}.py"


def _audit_path(root: Path, relative: str) -> tuple[bytes, tuple[int, int]]:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ReadinessError("PATH_OUTSIDE_ROOT", relative)
    root = root.resolve(strict=True)
    path = root / relative
    current = root
    for part in Path(relative).parts:
        try:
            case_matches = [
                child.name for child in current.iterdir()
                if child.name.casefold() == part.casefold()
            ]
        except OSError as error:
            raise ReadinessError("INPUT_PATH", relative) from error
        if case_matches != [part]:
            raise ReadinessError("PATH_CASE_ALIAS", relative)
        current = current / part
        if current.is_symlink():
            raise ReadinessError("SYMLINK_INPUT", relative)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        lexical_before = path.lstat()
        with path.open("rb") as handle:
            descriptor_before = os.fstat(handle.fileno())
            raw = handle.read()
            descriptor_after = os.fstat(handle.fileno())
        lexical_after = path.lstat()
        path.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, OSError, ValueError) as error:
        raise ReadinessError("INPUT_PATH", relative) from error
    snapshots = (lexical_before, descriptor_before, descriptor_after, lexical_after)
    if any(not stat.S_ISREG(item.st_mode) for item in snapshots):
        raise ReadinessError("INPUT_NOT_FILE", relative)
    identities = {(item.st_dev, item.st_ino) for item in snapshots}
    sizes = {item.st_size for item in snapshots}
    mtimes = {item.st_mtime_ns for item in snapshots}
    if len(identities) != 1 or sizes != {len(raw)} or len(mtimes) != 1:
        raise ReadinessError("INPUT_CHANGED_DURING_AUDIT", relative)
    return raw, identities.pop()


def elide_pin_block(raw: bytes) -> bytes:
    """Apply the eventual carrier cycle-breaker to exactly one full block."""
    if type(raw) is not bytes:
        raise ReadinessError("PIN_CARRIER_BYTES", "/")
    begin_count = raw.count(PIN_BEGIN_MARKER)
    end_count = raw.count(PIN_END_MARKER)
    if begin_count != 1 or end_count != 1:
        raise ReadinessError("PIN_MARKER_CARDINALITY", "/")
    begin = raw.find(PIN_BEGIN_MARKER)
    end = raw.find(PIN_END_MARKER)
    if end < begin:
        raise ReadinessError("PIN_MARKER_ORDER", "/")
    if (begin != 0 and raw[begin - 1:begin] != b"\n") or (
        end != 0 and raw[end - 1:end] != b"\n"
    ):
        raise ReadinessError("PIN_MARKER_NOT_STANDALONE", "/")
    after = end + len(PIN_END_MARKER)
    enclosed = raw[begin + len(PIN_BEGIN_MARKER):end]
    if PIN_BEGIN_MARKER in enclosed or PIN_END_MARKER in enclosed:
        raise ReadinessError("PIN_MARKER_NESTED", "/")
    return raw[:begin] + PIN_REPLACEMENT + raw[after:]


def _imports(
    module: str, raw: bytes
) -> tuple[set[str], set[str], bool, bool]:
    try:
        tree = ast.parse(raw, filename=_module_path(module))
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", _module_path(module)) from error
    local: set[str] = set()
    absolute: set[str] = set()
    future = False
    dynamic = False
    forbidden_dynamic_names = {"__import__", "eval", "exec", "compile"}
    forbidden_introspection_names = {
        "__builtins__", "globals", "locals", "vars", "chr",
    }

    def constant_text(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = constant_text(node.left)
            right = constant_text(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            absolute.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__" and node.level == 0:
                future = True
            elif node.level == 1 and node.module:
                local.add(f"edgelab.{node.module}")
            elif node.level != 0:
                raise ReadinessError("RELATIVE_IMPORT_PROFILE", _module_path(module))
            elif node.module:
                absolute.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Name) and node.id in (
            forbidden_dynamic_names | forbidden_introspection_names
        ):
            dynamic = True
        elif isinstance(node, ast.Attribute) and (
            node.attr == "__import__"
            or isinstance(node.value, ast.Name) and node.value.id == "importlib"
        ):
            dynamic = True
        elif constant_text(node) in forbidden_dynamic_names:
            dynamic = True
        elif isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            ):
                dynamic = True
    return local, absolute, future, dynamic


def _source_inventory(
    root: Path,
) -> tuple[dict[str, Any], set[tuple[int, int]], dict[str, bytes]]:
    pending = list(GENERATION_ROOT_MODULES + REQUIRED_PACKAGE_MODULES)
    observed: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str]] = set()
    standard: set[str] = set()
    external: set[str] = set()
    compiler_directives: set[str] = set()
    identities: set[tuple[int, int]] = set()
    source_bytes: dict[str, bytes] = {}
    while pending:
        module = pending.pop()
        if module in observed:
            continue
        path = _module_path(module)
        raw, identity = _audit_path(root, path)
        if identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", path)
        identities.add(identity)
        source_bytes[path] = raw
        local, absolute, future, dynamic = _imports(module, raw)
        if future:
            compiler_directives.add("__future__")
        if dynamic:
            raise ReadinessError("DYNAMIC_EXECUTION", path)
        for target in local:
            if not target.startswith("edgelab.runtime_v2_"):
                raise ReadinessError("LOCAL_IMPORT_OUTSIDE_PROFILE", target)
            edges.add((module, target))
            pending.append(target)
        for imported in absolute:
            if imported in STANDARD_LIBRARY_ALLOWLIST:
                standard.add(imported)
            else:
                external.add(imported)
        role = "LOCAL_MODULE"
        if module == "edgelab":
            role = "PACKAGE_INITIALIZER"
        elif module == PUBLIC_ENTRYPOINT_MODULE:
            role = "PUBLIC_ENTRYPOINT"
        elif module == PRIVATE_REDUCER_MODULE:
            role = "PRIVATE_REDUCER_ROOT"
        observed[module] = {
            "byte_length": len(raw),
            "module": module,
            "path": path,
            "raw_sha256": _sha256(raw),
            "readiness_role": role,
        }
    runtime_directory = root / "src" / "edgelab"
    profiled_names = {
        Path(item["path"]).name for item in observed.values()
        if item["module"].startswith("edgelab.runtime_v2_")
    }
    runtime_entries = [
        item for item in runtime_directory.iterdir()
        if item.suffix.casefold() == ".py"
        and item.name.casefold().startswith("runtime_v2_")
    ]
    for item in runtime_entries:
        try:
            mode = item.lstat().st_mode
        except OSError as error:
            raise ReadinessError("RUNTIME_MODULE_INPUT", item.name) from error
        if item.is_symlink() or not stat.S_ISREG(mode):
            raise ReadinessError("RUNTIME_MODULE_INPUT", item.name)
    present_names = {item.name for item in runtime_entries}
    if present_names != profiled_names:
        difference = sorted(present_names ^ profiled_names, key=str.casefold)
        raise ReadinessError(
            "RUNTIME_MODULE_INVENTORY", ",".join(difference) or "/"
        )
    if len(present_names) != len({name.casefold() for name in present_names}):
        raise ReadinessError("RUNTIME_MODULE_CASE_ALIAS", "src/edgelab")
    carrier = root / PIN_CARRIER_PATH
    carrier_parent_names = {
        item.name for item in carrier.parent.iterdir()
        if item.name.casefold() == carrier.name.casefold()
    }
    if carrier_parent_names:
        raise ReadinessError("PREMATURE_PIN_CARRIER", PIN_CARRIER_PATH)
    if external:
        raise ReadinessError(
            "EXTERNAL_IMPORTS_PRESENT", ",".join(sorted(external))
        )
    return ({
        "compiler_directives_excluded": sorted(compiler_directives),
        "external_import_modules": sorted(external),
        "generation_root_modules": list(GENERATION_ROOT_MODULES),
        "import_edges": [
            {"source": source, "target": target}
            for source, target in sorted(edges)
        ],
        "local_artifacts": sorted(observed.values(), key=lambda item: item["path"]),
        "local_import_roots": list(LOCAL_IMPORT_ROOTS),
        "standard_library_modules": sorted(standard),
    }, identities, source_bytes)


def _schema_inventory(
    root: Path,
    records: tuple[tuple[str, str, str], ...],
    role_name: str,
    digest_name: str,
    identities: set[tuple[int, int]],
    schema_bytes: dict[str, bytes],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for role, schema_id, path in records:
        raw, identity = _audit_path(root, path)
        if identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", path)
        identities.add(identity)
        schema_bytes[path] = raw
        value = _parse_json(raw, path)
        if type(value) is not dict or value.get("$id") != schema_id:
            raise ReadinessError("SCHEMA_ID", path)
        result.append({
            "byte_length": len(raw),
            "path": path,
            "raw_sha256": _sha256(raw),
            role_name: role,
            digest_name: _domain_digest(
                "EDGELAB\0SCHEMA_DOCUMENT\0V2\0", value
            ),
            "schema_id": schema_id,
        })
    return sorted(result, key=lambda item: item["path"])


def _json_pointer_token(value: str) -> str:
    return "".join(
        "~0" if character == "~" else "~1" if character == "/" else character
        for character in value
    )


def _schema_bound_inventory(
    root: Path,
    identities: set[tuple[int, int]],
    schema_bytes: dict[str, bytes],
) -> list[dict[str, Any]]:
    closure_id, closure_path = CLOSURE_SCHEMA
    closure_raw, identity = _audit_path(root, closure_path)
    if identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", closure_path)
    identities.add(identity)
    schema_bytes[closure_path] = closure_raw
    closure_value = _parse_json(closure_raw, closure_path)
    if type(closure_value) is not dict or closure_value.get("$id") != closure_id:
        raise ReadinessError("SCHEMA_ID", closure_path)

    schema_ids = {
        path: schema_id
        for _, schema_id, path in BOOTSTRAP_SCHEMAS + RETAINED_SCHEMAS
    }
    schema_ids[closure_path] = closure_id
    records: list[dict[str, Any]] = []

    def walk(path: str, value: Any, pointer: str) -> None:
        if type(value) is dict:
            for key in sorted(value):
                child_pointer = f"{pointer}/{_json_pointer_token(key)}"
                child = value[key]
                if key in SCHEMA_BOUND_KEYWORDS and type(child) is int:
                    records.append({
                        "classification": "UNCLASSIFIED",
                        "json_pointer": child_pointer,
                        "keyword": key,
                        "path": path,
                        "schema_id": schema_ids[path],
                        "value": child,
                    })
                walk(path, child, child_pointer)
        elif type(value) is list:
            for index, child in enumerate(value):
                walk(path, child, f"{pointer}/{index}")

    for path in sorted(schema_bytes):
        value = _parse_json(schema_bytes[path], path)
        walk(path, value, "")
    return sorted(
        records,
        key=lambda item: (item["path"], item["json_pointer"]),
    )


def _address_schema_bound_inventory(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return stable identities for an already ordered legacy schema census."""
    expected_keys = {
        "classification", "json_pointer", "keyword", "path", "schema_id", "value",
    }
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str, str, int]] = set()
    site_ids: set[str] = set()
    previous_order: tuple[str, str] | None = None
    for index, record in enumerate(records):
        if type(record) is not dict or set(record) != expected_keys:
            raise ReadinessError("SCHEMA_RESOURCE_SITE_KEYS", f"/{index}")
        if (
            record.get("classification") != "UNCLASSIFIED"
            or type(record.get("json_pointer")) is not str
            or not record["json_pointer"].startswith("/")
            or type(record.get("keyword")) is not str
            or not record["keyword"]
            or type(record.get("path")) is not str
            or not record["path"]
            or type(record.get("schema_id")) is not str
            or not record["schema_id"]
            or type(record.get("value")) is not int
        ):
            raise ReadinessError("SCHEMA_RESOURCE_SITE_TYPE", f"/{index}")
        pointer = record["json_pointer"]
        escape_index = pointer.find("~")
        while escape_index != -1:
            if (
                escape_index + 1 == len(pointer)
                or pointer[escape_index + 1] not in "01"
            ):
                raise ReadinessError("SCHEMA_RESOURCE_SITE_POINTER", f"/{index}")
            escape_index = pointer.find("~", escape_index + 2)
        identity = (
            record["json_pointer"], record["keyword"], record["path"],
            record["schema_id"], record["value"],
        )
        if identity in identities:
            raise ReadinessError("SCHEMA_RESOURCE_SITE_DUPLICATE", f"/{index}")
        identities.add(identity)
        order = (record["path"], record["json_pointer"])
        if previous_order is not None and order <= previous_order:
            raise ReadinessError("SCHEMA_RESOURCE_SITE_ORDER", f"/{index}")
        previous_order = order
        identity_value = {
            "json_pointer": record["json_pointer"],
            "keyword": record["keyword"],
            "path": record["path"],
            "schema_id": record["schema_id"],
            "value": record["value"],
        }
        site_id = _domain_digest(SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN, identity_value)
        if site_id in site_ids:
            raise ReadinessError("SCHEMA_RESOURCE_SITE_COLLISION", f"/{index}")
        site_ids.add(site_id)
        result.append({**record, "site_id": site_id})
    return result


def _schema_declarative_keyword_semantics() -> list[dict[str, str]]:
    return [
        {
            "keyword": keyword,
            "semantic_subject": (
                f"SCHEMA_DECLARATIVE_{subject}_AT_EXACT_PINNED_LOCATION"
            ),
            "instance_domain": instance_domain,
            "metric": metric,
            "operator": operator,
            "unit": unit,
        }
        for keyword, subject, instance_domain, metric, operator, unit
        in SCHEMA_DECLARATIVE_KEYWORD_SEMANTICS
    ]


def _json_pointer_tokens(pointer: str, coordinate: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ReadinessError("SCHEMA_DECLARATIVE_POINTER", coordinate)
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        decoded: list[str] = []
        index = 0
        while index < len(encoded):
            character = encoded[index]
            if character != "~":
                decoded.append(character)
                index += 1
                continue
            if index + 1 == len(encoded) or encoded[index + 1] not in "01":
                raise ReadinessError("SCHEMA_DECLARATIVE_POINTER", coordinate)
            decoded.append("~" if encoded[index + 1] == "0" else "/")
            index += 2
        tokens.append("".join(decoded))
    return tokens


def _encode_json_pointer_token(token: str) -> str:
    encoded: list[str] = []
    for character in token:
        if character == "~":
            encoded.append("~0")
        elif character == "/":
            encoded.append("~1")
        else:
            encoded.append(character)
    return "".join(encoded)


def _resolve_json_pointer(document: Any, pointer: str, coordinate: str) -> Any:
    value = document
    for token in _json_pointer_tokens(pointer, coordinate):
        if type(value) is dict:
            if token not in value:
                raise ReadinessError("SCHEMA_DECLARATIVE_POINTER_MISSING", coordinate)
            value = value[token]
        elif type(value) is list:
            if not token.isascii() or not token.isdigit() or (
                len(token) > 1 and token.startswith("0")
            ):
                raise ReadinessError("SCHEMA_DECLARATIVE_POINTER_INDEX", coordinate)
            index = int(token)
            if index >= len(value):
                raise ReadinessError("SCHEMA_DECLARATIVE_POINTER_MISSING", coordinate)
            value = value[index]
        else:
            raise ReadinessError("SCHEMA_DECLARATIVE_POINTER_MISSING", coordinate)
    return value


def _schema_ancestor_context(
    document: Any,
    containing_pointer: str,
    coordinate: str,
) -> dict[str, Any]:
    encoded_tokens = [] if containing_pointer == "" else containing_pointer[1:].split("/")
    pointers = [""]
    for encoded in encoded_tokens:
        pointers.append(f"{pointers[-1]}/{encoded}")
    sequence = []
    for index, pointer in enumerate(pointers):
        _resolve_json_pointer(document, pointer, coordinate)
        sequence.append({"index": index, "pointer": pointer})
    return {
        "binding": "FULL_SCHEMA_DOCUMENT_RAW_SHA256",
        "ordered_pointer_sequence": sequence,
    }


def _validate_local_schema_semantics(document: dict[str, Any], coordinate: str) -> None:
    def walk(value: Any, pointer: str) -> None:
        if type(value) is dict:
            if pointer and ("$id" in value or "$schema" in value):
                raise ReadinessError("SCHEMA_DECLARATIVE_NESTED_DIALECT", pointer)
            if "$dynamicRef" in value or "$recursiveRef" in value:
                raise ReadinessError(
                    "SCHEMA_DECLARATIVE_UNSUPPORTED_REFERENCE", pointer
                )
            reference = value.get("$ref")
            if reference is not None:
                if type(reference) is not str or not (
                    reference == "#" or reference.startswith("#/")
                ):
                    raise ReadinessError("SCHEMA_DECLARATIVE_REFERENCE", pointer)
                if "%" in reference:
                    raise ReadinessError(
                        "SCHEMA_DECLARATIVE_REFERENCE_ENCODING", pointer
                    )
                _resolve_json_pointer(document, reference[1:], coordinate)
            for key, child in value.items():
                escaped = _encode_json_pointer_token(key)
                walk(child, f"{pointer}/{escaped}")
        elif type(value) is list:
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}")

    walk(document, "")


def _validate_schema_declarative_keyword_proof(
    root: Path,
    proof: dict[str, Any],
    source_sites: dict[str, dict[str, Any]],
    schema_sites: dict[str, dict[str, Any]],
    schema_inputs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate one location-scoped declarative schema-keyword proof."""
    expected_keys = {
        "addressed_site", "classification", "constraint_id",
        "declarative_equation", "evidence_inputs", "proof_kind",
        "schema_context", "schema_site_id", "semantic_subject", "unit",
    }
    if type(proof) is not dict or set(proof) != expected_keys:
        raise ReadinessError("SCHEMA_DECLARATIVE_PROOF_KEYS", "/")
    if (
        proof.get("proof_kind") != "SCHEMA_DECLARATIVE_KEYWORD_V1"
        or proof.get("classification") != "SCHEMA_DECLARATIVE_BOUND"
        or type(proof.get("constraint_id")) is not str
        or not proof["constraint_id"].startswith("SCHEMA_DECLARATIVE_")
        or type(proof.get("semantic_subject")) is not str
        or type(proof.get("schema_site_id")) is not str
    ):
        raise ReadinessError("SCHEMA_DECLARATIVE_PROOF_TYPE", "/")
    schema_site_id = proof["schema_site_id"]
    if schema_site_id in source_sites:
        raise ReadinessError("SCHEMA_DECLARATIVE_SOURCE_SITE", schema_site_id)
    addressed_site = schema_sites.get(schema_site_id)
    if addressed_site is None:
        raise ReadinessError("SCHEMA_DECLARATIVE_SCHEMA_SITE", schema_site_id)
    if proof.get("addressed_site") != addressed_site:
        raise ReadinessError("SCHEMA_DECLARATIVE_ADDRESSED_SITE", schema_site_id)
    identity_value = {
        key: addressed_site[key]
        for key in ("json_pointer", "keyword", "path", "schema_id", "value")
    }
    if _domain_digest(
        SCHEMA_RESOURCE_SITE_IDENTITY_DOMAIN, identity_value
    ) != schema_site_id:
        raise ReadinessError("SCHEMA_DECLARATIVE_SITE_IDENTITY", schema_site_id)

    semantics_by_keyword = {
        item["keyword"]: item for item in _schema_declarative_keyword_semantics()
    }
    semantics = semantics_by_keyword.get(addressed_site["keyword"])
    if semantics is None:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_KEYWORD", addressed_site["json_pointer"]
        )
    expected_constraint_id = (
        "SCHEMA_DECLARATIVE_"
        + addressed_site["keyword"].upper()
        + "_"
        + schema_site_id.upper()
    )
    if proof["constraint_id"] != expected_constraint_id:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_CONSTRAINT_ID", addressed_site["json_pointer"]
        )
    if proof["semantic_subject"] != semantics["semantic_subject"]:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_SUBJECT", addressed_site["json_pointer"]
        )
    expected_equation = {
        "metric": semantics["metric"],
        "operator": semantics["operator"],
        "bound": addressed_site["value"],
    }
    if proof.get("declarative_equation") != expected_equation:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_EQUATION", addressed_site["json_pointer"]
        )
    if proof.get("unit") != semantics["unit"]:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_UNIT", addressed_site["json_pointer"]
        )
    if addressed_site["keyword"] not in {
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    } and addressed_site["value"] < 0:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_NONNEGATIVE_BOUND",
            addressed_site["json_pointer"],
        )

    input_by_path: dict[str, dict[str, Any]] = {}
    for item in schema_inputs:
        if type(item) is not dict or set(item) != {
            "byte_length", "path", "raw_sha256",
        } or type(item.get("path")) is not str or item["path"] in input_by_path:
            raise ReadinessError("SCHEMA_DECLARATIVE_SCHEMA_INPUT", "/")
        input_by_path[item["path"]] = item
    schema_input = input_by_path.get(addressed_site["path"])
    if schema_input is None:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_SCHEMA_INPUT", addressed_site["path"]
        )
    schema_raw, schema_identity = _audit_path(root, addressed_site["path"])
    if len(schema_raw) != schema_input["byte_length"] or _sha256(
        schema_raw
    ) != schema_input["raw_sha256"]:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_SCHEMA_BYTES", addressed_site["path"]
        )
    schema_document = _parse_json(schema_raw, addressed_site["path"])
    if type(schema_document) is not dict or (
        schema_document.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or schema_document.get("$id") != addressed_site["schema_id"]
    ):
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_SCHEMA_ROOT", addressed_site["path"]
        )
    _validate_local_schema_semantics(schema_document, addressed_site["path"])
    pointer = addressed_site["json_pointer"]
    pointer_tokens = _json_pointer_tokens(pointer, addressed_site["path"])
    if not pointer_tokens or pointer_tokens[-1] != addressed_site["keyword"]:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_KEYWORD_POINTER", addressed_site["json_pointer"]
        )
    if _resolve_json_pointer(
        schema_document, pointer, addressed_site["path"]
    ) != addressed_site["value"]:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_BOUND", addressed_site["json_pointer"]
        )
    containing_pointer = pointer.rsplit("/", 1)[0]
    containing_subschema = _resolve_json_pointer(
        schema_document, containing_pointer, addressed_site["path"]
    )
    if type(containing_subschema) is not dict:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_CONTAINER", addressed_site["json_pointer"]
        )
    containing_digest = _domain_digest(
        SCHEMA_CONTAINING_SUBSCHEMA_DOMAIN, containing_subschema
    )
    contains_pointer = f"{containing_pointer}/contains"
    required_siblings = (
        [contains_pointer]
        if addressed_site["keyword"] in {"minContains", "maxContains"}
        else []
    )
    if required_siblings:
        contains_schema = _resolve_json_pointer(
            schema_document, contains_pointer, addressed_site["path"]
        )
        if "contains" not in containing_subschema or type(
            contains_schema
        ) not in {bool, dict}:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_CONTAINS_SIBLING", contains_pointer
            )
    expected_context = {
        "dialect": "https://json-schema.org/draft/2020-12/schema",
        "schema_document_byte_length": len(schema_raw),
        "schema_document_raw_sha256": _sha256(schema_raw),
        "schema_document_root_id": addressed_site["schema_id"],
        "containing_subschema_pointer": containing_pointer,
        "containing_subschema_digest": containing_digest,
        "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
        "instance_domain": semantics["instance_domain"],
        "ancestor_context": _schema_ancestor_context(
            schema_document, containing_pointer, addressed_site["path"]
        ),
        "required_sibling_pointers": required_siblings,
        "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
    }
    if proof.get("schema_context") != expected_context:
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_CONTEXT", addressed_site["json_pointer"]
        )

    evidence_inputs = proof.get("evidence_inputs")
    if type(evidence_inputs) is not list or len(evidence_inputs) < 2:
        raise ReadinessError("SCHEMA_DECLARATIVE_EVIDENCE", "/")
    evidence_paths: set[str] = set()
    evidence_identities = {schema_identity}
    for index, item in enumerate(evidence_inputs):
        if type(item) is not dict or set(item) != {
            "byte_length", "path", "raw_sha256",
        } or (
            type(item.get("byte_length")) is not int
            or type(item.get("path")) is not str
            or not item["path"]
            or type(item.get("raw_sha256")) is not str
        ):
            raise ReadinessError("SCHEMA_DECLARATIVE_EVIDENCE", f"/{index}")
        if item["path"] == addressed_site["path"] or item["path"] in evidence_paths:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_EVIDENCE_DUPLICATE", item["path"]
            )
        evidence_paths.add(item["path"])
        evidence_raw, evidence_identity = _audit_path(root, item["path"])
        if evidence_identity in evidence_identities:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_EVIDENCE_ALIAS", item["path"]
            )
        evidence_identities.add(evidence_identity)
        if len(evidence_raw) != item["byte_length"] or _sha256(
            evidence_raw
        ) != item["raw_sha256"]:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_EVIDENCE_IDENTITY", item["path"]
            )
    return {
        "constraint_id": proof["constraint_id"],
        "proof_kind": proof["proof_kind"],
        "schema_site_id": schema_site_id,
        "validated_evidence_input_count": len(evidence_inputs),
    }


def _schema_declarative_proof_profile_inventory(
    root: Path,
    identities: set[tuple[int, int]],
) -> dict[str, Any]:
    schema_expected = SCHEMA_DECLARATIVE_KEYWORD_PROOF_SCHEMA
    schema_raw, schema_identity = _audit_path(root, schema_expected["path"])
    if schema_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", schema_expected["path"])
    identities.add(schema_identity)
    schema = _parse_json(schema_raw, schema_expected["path"])
    if (
        len(schema_raw) != schema_expected["byte_length"]
        or _sha256(schema_raw) != schema_expected["raw_sha256"]
        or type(schema) is not dict
        or schema.get("$id") != schema_expected["schema_id"]
        or schema.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
    ):
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_PROOF_SCHEMA", schema_expected["path"]
        )
    profile_expected = SCHEMA_DECLARATIVE_KEYWORD_PROOF_PROFILE
    profile_raw, profile_identity = _audit_path(root, profile_expected["path"])
    if profile_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", profile_expected["path"])
    identities.add(profile_identity)
    profile = _parse_json(profile_raw, profile_expected["path"])
    if (
        len(profile_raw) != profile_expected["byte_length"]
        or _sha256(profile_raw) != profile_expected["raw_sha256"]
        or type(profile) is not dict
        or profile.get("profile_id") != profile_expected["profile_id"]
        or profile.get("profile_sha256") != profile_expected["profile_sha256"]
    ):
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_PROOF_PROFILE", profile_expected["path"]
        )
    expected_profile = {
        "schema_version": 1,
        "profile_id": profile_expected["profile_id"],
        "proof_kind": "SCHEMA_DECLARATIVE_KEYWORD_V1",
        "classification": "SCHEMA_DECLARATIVE_BOUND",
        "contract_schema": dict(schema_expected),
        "containing_subschema_digest_domain": SCHEMA_CONTAINING_SUBSCHEMA_DOMAIN,
        "dialect": "https://json-schema.org/draft/2020-12/schema",
        "applicability": "EXACT_PINNED_SCHEMA_LOCATION_ONLY",
        "ancestor_context": "FULL_SCHEMA_DOCUMENT_RAW_SHA256",
        "reference_semantics": (
            "LOCAL_DOCUMENT_RAW_RFC6901_POINTER_ONLY_NO_PERCENT_ENCODING_"
            "ALL_RESOLVE_NO_DYNAMIC_OR_RECURSIVE_REFERENCE"
        ),
        "nested_dialect_or_id": "DENY",
        "non_domain_behavior": "NO_ASSERTION_FROM_THIS_KEYWORD",
        "keyword_semantics": _schema_declarative_keyword_semantics(),
        "declarative_roles": [
            "ADDRESSED_SCHEMA_KEYWORD",
            "BOUND_DEFINITION",
            "CONTAINING_SUBSCHEMA_CONTEXT",
            "FULL_DOCUMENT_ANCESTOR_CONTEXT",
            "KEYWORD_APPLICABILITY",
            "REQUIRED_CONTAINS_SIBLING",
        ],
        "runtime_enforcement_roles": [],
        "evidence_input_minimum": 2,
        "evidence_input_requirements": [
            "EXACT_BYTE_LENGTH_AND_RAW_SHA256",
            "PAIRWISE_DISTINCT_PATH_AND_FILE_IDENTITY",
            "NOT_THE_BOUND_SCHEMA_DOCUMENT",
        ],
        "nonclaims": list(SCHEMA_DECLARATIVE_PROOF_NONCLAIMS),
    }
    digest_value = dict(profile)
    claimed_digest = digest_value.pop("profile_sha256", None)
    if profile != {**expected_profile, "profile_sha256": claimed_digest} or (
        _domain_digest(SCHEMA_DECLARATIVE_PROOF_PROFILE_DOMAIN, digest_value)
        != claimed_digest
    ):
        raise ReadinessError(
            "SCHEMA_DECLARATIVE_PROOF_PROFILE_BINDING", profile_expected["path"]
        )
    return {
        "classification": profile["classification"],
        "keyword_count": len(profile["keyword_semantics"]),
        "profile_id": profile["profile_id"],
        "proof_kind": profile["proof_kind"],
        "runtime_enforcement_roles": [],
    }


def _integer_constant(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) is int
    ):
        return -node.operand.value
    return None


def _contains_integer(node: ast.AST) -> bool:
    return any(
        isinstance(item, ast.Constant) and type(item.value) is int
        for item in ast.walk(node)
    )


def _contains_bound_signal(node: ast.AST) -> bool:
    return _contains_integer(node) or any(
        isinstance(item, ast.Name)
        and (item.id.isupper() or item.id.startswith("_MAX_"))
        for item in ast.walk(node)
    ) or any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "len"
        for item in ast.walk(node)
    )


class _SourceBoundVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.qualnames = ["<module>"]
        self.records: list[dict[str, Any]] = []
        self.occurrences: dict[tuple[str, str, str], int] = {}

    def _record(
        self, node: ast.AST, kind: str, binding: str | None = None
    ) -> None:
        normalized = ast.dump(node, annotate_fields=True, include_attributes=False)
        ast_sha256 = _sha256(normalized.encode("utf-8"))
        qualname = ".".join(self.qualnames)
        binding_key = binding or ""
        key = (qualname, f"{kind}:{binding_key}", ast_sha256)
        occurrence = self.occurrences.get(key, 0) + 1
        self.occurrences[key] = occurrence
        site_seed = "\0".join((
            self.path, qualname, kind, binding_key, ast_sha256, str(occurrence),
        )).encode("utf-8")
        self.records.append({
            "ast_sha256": ast_sha256,
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(node),
            "kind": kind,
            "line": getattr(node, "lineno", 0),
            "occurrence": occurrence,
            "path": self.path,
            "qualname": qualname,
            "site_id": _sha256(
                b"EDGELAB\0RUNTIME_V2_RESOURCE_SITE\0V1\0" + site_seed
            ),
        })
        if binding is not None:
            self.records[-1]["binding"] = binding

    def _scoped(self, node: ast.AST, name: str) -> None:
        self.qualnames.append(name)
        self.generic_visit(node)
        self.qualnames.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.qualnames.append(node.name)
        positional = (*node.args.posonlyargs, *node.args.args)
        positional_defaults = positional[-len(node.args.defaults):] if node.args.defaults else ()
        default_bindings = [
            (default, f"parameter:{argument.arg}")
            for argument, default in zip(positional_defaults, node.args.defaults)
        ] + [
            (default, f"parameter:{argument.arg}")
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
            if default is not None
        ]
        for default, binding in default_bindings:
            if default is not None and _contains_bound_signal(default):
                self._record(default, "FUNCTION_DEFAULT", binding)
        self.generic_visit(node)
        self.qualnames.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.qualnames.append(node.name)
        positional = (*node.args.posonlyargs, *node.args.args)
        positional_defaults = positional[-len(node.args.defaults):] if node.args.defaults else ()
        default_bindings = [
            (default, f"parameter:{argument.arg}")
            for argument, default in zip(positional_defaults, node.args.defaults)
        ] + [
            (default, f"parameter:{argument.arg}")
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
            if default is not None
        ]
        for default, binding in default_bindings:
            if default is not None and _contains_bound_signal(default):
                self._record(default, "FUNCTION_DEFAULT", binding)
        self.generic_visit(node)
        self.qualnames.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node, node.name)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.qualnames == ["<module>"] and _contains_bound_signal(node.value):
            self._record(node, "MODULE_NUMERIC_ASSIGNMENT")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            self.qualnames == ["<module>"]
            and node.value is not None
            and _contains_bound_signal(node.value)
        ):
            self._record(node, "MODULE_NUMERIC_ASSIGNMENT")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if _contains_bound_signal(node):
            self._record(node, "BOUND_COMPARISON")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if name in SOURCE_BOUND_CALLS and _contains_bound_signal(node):
            self._record(node, "BOUND_HELPER_CALL")
        is_regex_compile = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.func.attr == "compile"
        )
        if is_regex_compile and node.args:
            pattern = node.args[0]
            if (
                isinstance(pattern, ast.Constant)
                and type(pattern.value) is str
                and any(character.isdigit() for character in pattern.value)
                and "{" in pattern.value
            ):
                self._record(node, "REGEX_NUMERIC_QUANTIFIER")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.slice, ast.Slice) and _contains_bound_signal(node.slice):
            self._record(node, "NUMERIC_SLICE")
        self.generic_visit(node)


def _source_bound_inventory(
    source_bytes: dict[str, bytes],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(source_bytes):
        try:
            tree = ast.parse(source_bytes[path], filename=path)
        except (SyntaxError, ValueError) as error:
            raise ReadinessError("PYTHON_SOURCE", path) from error
        visitor = _SourceBoundVisitor(path)
        visitor.visit(tree)
        records.extend(visitor.records)
    return sorted(records, key=lambda item: (item["path"], item["site_id"]))


def _ast_sha256(node: ast.AST) -> str:
    normalized = ast.dump(node, annotate_fields=True, include_attributes=False)
    return _sha256(normalized.encode("utf-8"))


def _is_captured_branch(node: ast.AST, branch_key: str) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "captured"
        and isinstance(node.slice, ast.Constant)
        and type(node.slice.value) is str
        and node.slice.value == branch_key
    )


def _is_table_bound_comparison(node: ast.AST, value_name: str) -> bool:
    return (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Gt)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "maximum"
        and isinstance(node.left, ast.Call)
        and isinstance(node.left.func, ast.Name)
        and node.left.func.id == "len"
        and len(node.left.args) == 1
        and not node.left.keywords
        and isinstance(node.left.args[0], ast.Name)
        and node.left.args[0].id == value_name
    )


def _source_bound_binding_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the closed V2 table-binding extension to the V1 census."""
    path = "src/edgelab/runtime_v2_image.py"
    coordinate = f"{path}:inspect_runtime_image_host"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError("RESOURCE_BINDING_SOURCE", path) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "inspect_runtime_image_host"
    ]
    if len(functions) != 1:
        raise ReadinessError("RESOURCE_BINDING_FUNCTION", coordinate)
    function = functions[0]

    constant_values = {
        "MAX_BOOTSTRAP_DOCUMENT_BYTES": 1_048_576,
        "MAX_EVENT_BYTES": 1_048_576,
        "MAX_SCHEMA_REGISTRY_BYTES": 262_144,
    }
    for name, expected_value in constant_values.items():
        definitions = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        if (
            len(definitions) != 1
            or _integer_constant(definitions[0].value) != expected_value
        ):
            raise ReadinessError("RESOURCE_BINDING_MAXIMUM", f"{path}:{name}")

    profiles = (
        {
            "assignment_ast_sha256": (
                "dcc4e9f632d4f0014570e55c64f97b42eea6719a5ed2c35966833b065189aa08"
            ),
            "comparator_site_id": (
                "0d8566afcf1d2933abead1ae497a40b4dc65fef9a3a52ae302dc604bbf8c5507"
            ),
            "loop_ast_sha256": (
                "6e9143ae8f7229364ce3b636e4723a8ea2c44bc01016c341d4d9c2644b201941"
            ),
            "loop_target": ("name", "value", "maximum"),
            "table_name": "byte_fields",
            "value_name": "value",
            "rows": (
                (
                    "storage_descriptor", None,
                    "37af07f3babf32a68dc7cb2d8485660c5060dd8987af53c24cc9f6dc97e75e0d",
                    None,
                ),
                (
                    "verifier_dependency_closure",
                    "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                    "5d665629c14569b1b89a8061ed4c973af383ecfb2a058da39e9bfad3a2acdcd0",
                    "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                ),
                (
                    "manifest", "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                    "41021ef757a60ef8081a9ca1443e3ea70a01f06cefad4a965b458f8e6101fea5",
                    "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                ),
                (
                    "attachment", "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                    "c4e33d4a6fbca0dc45c5d2bc9dab4ca8bd2c2afecbf55ac89a2787a59b3f53fe",
                    "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                ),
                (
                    "schema_registry", "MAX_SCHEMA_REGISTRY_BYTES",
                    "9f48b1731194adc88917d3878f5f78f7b7c12ac2b2967231524adfd18cb2f0b3",
                    "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                ),
            ),
        },
        {
            "assignment_ast_sha256": (
                "4ca5b4b0036969d77d3d8235fd0a8c438e9e1a5cd526f970ffc6ec8bb57d8bbe"
            ),
            "comparator_site_id": (
                "349ec1bed6c7edd66926c28b7f33deede98d6f01af5a5c461476b820dfa91e7d"
            ),
            "loop_ast_sha256": (
                "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
            ),
            "loop_target": ("name", "values", "maximum"),
            "table_name": "byte_collections",
            "value_name": "value",
            "rows": (
                (
                    "events", "MAX_EVENT_BYTES",
                    "2e3b9d0115bcd53ae1e76bdd4f4885007c1af420dcfd2f8efcaa0012863de637",
                    "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534",
                ),
                (
                    "checkpoint_copies", "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                    "f6687768c44df59ed8d8a90f0678c8cb81347f40a925fd56aae1653e9421853c",
                    "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                ),
                (
                    "selector_history", "MAX_BOOTSTRAP_DOCUMENT_BYTES",
                    "4d5afd2bc3a80702c612fb94b96d3561a1bd398c7347978016a58fb7aa75d498",
                    "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
                ),
            ),
        },
    )
    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError("RESOURCE_BINDING_PREDECESSOR_DUPLICATE", path)

    result: list[dict[str, Any]] = []
    for profile in profiles:
        table_name = profile["table_name"]
        name_nodes = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Name) and node.id == table_name
        ]
        stores = [node for node in name_nodes if isinstance(node.ctx, ast.Store)]
        loads = [node for node in name_nodes if isinstance(node.ctx, ast.Load)]
        if len(stores) != 1 or len(loads) != 1:
            raise ReadinessError("RESOURCE_BINDING_TABLE_NAME", f"{coordinate}:{table_name}")
        if any(
            isinstance(node, ast.Constant) and node.value == table_name
            for node in ast.walk(function)
        ):
            raise ReadinessError("RESOURCE_BINDING_DYNAMIC_TABLE", f"{coordinate}:{table_name}")

        assignments = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and node.targets[0] is stores[0]
        ]
        if len(assignments) != 1:
            raise ReadinessError("RESOURCE_BINDING_ASSIGNMENT", f"{coordinate}:{table_name}")
        assignment = assignments[0]
        assignment_hash = _ast_sha256(assignment)
        if assignment_hash != profile["assignment_ast_sha256"]:
            raise ReadinessError("RESOURCE_BINDING_ASSIGNMENT_AST", f"{coordinate}:{table_name}")
        if not isinstance(assignment.value, ast.Tuple) or len(
            assignment.value.elts
        ) != len(profile["rows"]):
            raise ReadinessError("RESOURCE_BINDING_ROWS", f"{coordinate}:{table_name}")

        loops = [
            node for node in ast.walk(function)
            if isinstance(node, ast.For) and node.iter is loads[0]
        ]
        if len(loops) != 1:
            raise ReadinessError("RESOURCE_BINDING_LOOP", f"{coordinate}:{table_name}")
        loop = loops[0]
        loop_hash = _ast_sha256(loop)
        if loop_hash != profile["loop_ast_sha256"]:
            raise ReadinessError("RESOURCE_BINDING_LOOP_AST", f"{coordinate}:{table_name}")
        if (
            not isinstance(loop.target, ast.Tuple)
            or tuple(
                item.id if isinstance(item, ast.Name) else None
                for item in loop.target.elts
            ) != profile["loop_target"]
        ):
            raise ReadinessError("RESOURCE_BINDING_LOOP_TARGET", f"{coordinate}:{table_name}")
        comparisons = [
            node for node in ast.walk(loop)
            if _is_table_bound_comparison(node, profile["value_name"])
        ]
        if len(comparisons) != 1:
            raise ReadinessError("RESOURCE_BINDING_COMPARATOR", f"{coordinate}:{table_name}")
        comparator_site_id = profile["comparator_site_id"]
        predecessor = predecessor_by_id.get(comparator_site_id)
        if predecessor != {
            "ast_sha256": _ast_sha256(comparisons[0]),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(comparisons[0]),
            "kind": "BOUND_COMPARISON",
            "line": comparisons[0].lineno,
            "occurrence": predecessor.get("occurrence") if predecessor else None,
            "path": path,
            "qualname": "<module>.inspect_runtime_image_host",
            "site_id": comparator_site_id,
        }:
            raise ReadinessError("RESOURCE_BINDING_COMPARATOR_SITE", f"{coordinate}:{table_name}")

        for row_index, (row, expected) in enumerate(zip(
            assignment.value.elts, profile["rows"], strict=True,
        )):
            branch_key, maximum_expression, expected_ast, expected_site = expected
            if (
                not isinstance(row, ast.Tuple)
                or len(row.elts) != 3
                or not isinstance(row.elts[0], ast.Constant)
                or type(row.elts[0].value) is not str
                or row.elts[0].value != branch_key
                or not _is_captured_branch(row.elts[1], branch_key)
            ):
                raise ReadinessError("RESOURCE_BINDING_ROW", f"{coordinate}:{table_name}:{row_index}")
            maximum = row.elts[2]
            if maximum_expression is None:
                valid_maximum = (
                    isinstance(maximum, ast.Constant) and maximum.value is None
                )
            else:
                valid_maximum = (
                    isinstance(maximum, ast.Name)
                    and maximum.id == maximum_expression
                )
            if not valid_maximum or _ast_sha256(row) != expected_ast:
                raise ReadinessError("RESOURCE_BINDING_ROW_AST", f"{coordinate}:{table_name}:{row_index}")
            if expected_site is None:
                continue
            record = {
                "ast_sha256": expected_ast,
                "binding": f"{table_name}:{branch_key}",
                "branch_key": branch_key,
                "classification": "UNCLASSIFIED",
                "comparator_site_id": comparator_site_id,
                "expression": ast.unparse(row),
                "kind": "BOUND_TABLE_COMPARISON_BINDING",
                "line": row.lineno,
                "loop_ast_sha256": loop_hash,
                "maximum_expression": maximum_expression,
                "path": path,
                "qualname": "<module>.inspect_runtime_image_host",
                "row_index": row_index,
                "subject_expression": ast.unparse(row.elts[1]),
                "table_assignment_ast_sha256": assignment_hash,
                "table_name": table_name,
            }
            identity = {
                key: value for key, value in record.items()
                if key not in {"classification", "expression", "line"}
            }
            record["site_id"] = _domain_digest(
                RESOURCE_BINDING_SITE_DOMAIN, identity
            )
            if record["site_id"] != expected_site:
                raise ReadinessError("RESOURCE_BINDING_SITE_ID", f"{coordinate}:{table_name}:{row_index}")
            result.append(record)

    if len(result) != 7 or len({item["site_id"] for item in result}) != 7:
        raise ReadinessError("RESOURCE_BINDING_CARDINALITY", path)
    return sorted(result, key=lambda item: (item["path"], item["site_id"]))


def _is_cardinality_bound_comparison(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "minimum"
        and len(node.ops) == 2
        and all(isinstance(operator, ast.LtE) for operator in node.ops)
        and len(node.comparators) == 2
        and isinstance(node.comparators[0], ast.Call)
        and isinstance(node.comparators[0].func, ast.Name)
        and node.comparators[0].func.id == "len"
        and len(node.comparators[0].args) == 1
        and not node.comparators[0].keywords
        and isinstance(node.comparators[0].args[0], ast.Name)
        and node.comparators[0].args[0].id == "value"
        and isinstance(node.comparators[1], ast.Name)
        and node.comparators[1].id == "maximum"
    )


def _source_bound_cardinality_binding_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the closed V3 cardinality-table extension to the V2 census."""
    path = "src/edgelab/runtime_v2_image.py"
    coordinate = f"{path}:inspect_runtime_image_host"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError("RESOURCE_CARDINALITY_BINDING_SOURCE", path) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "inspect_runtime_image_host"
    ]
    if len(functions) != 1:
        raise ReadinessError("RESOURCE_CARDINALITY_BINDING_FUNCTION", coordinate)
    function = functions[0]
    semantic_function_ast_sha256 = _ast_sha256(function)

    constant_values = {
        "MAX_BLOBS": 300_000,
        "MAX_EVENTS": 100_000,
        "MAX_CHECKPOINT_COPIES": 49_999,
        "MAX_SELECTORS": 50_001,
        "MIN_SELECTORS": 2,
    }
    for name, expected_value in constant_values.items():
        definitions = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        if (
            len(definitions) != 1
            or _integer_constant(definitions[0].value) != expected_value
        ):
            raise ReadinessError(
                "RESOURCE_CARDINALITY_BINDING_LIMIT", f"{path}:{name}"
            )

    table_spec_assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_TABLE_SPECS"
    ]
    if (
        len(table_spec_assignments) != 1
        or _ast_sha256(table_spec_assignments[0])
        != "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_TABLE_SPECS", f"{path}:_TABLE_SPECS"
        )

    subject_table_name = "tuple_fields"
    subject_name_nodes = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == subject_table_name
    ]
    subject_stores = [
        node for node in subject_name_nodes if isinstance(node.ctx, ast.Store)
    ]
    subject_loads = [
        node for node in subject_name_nodes if isinstance(node.ctx, ast.Load)
    ]
    if len(subject_stores) != 1 or len(subject_loads) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_TABLE_NAME",
            f"{coordinate}:{subject_table_name}",
        )
    subject_assignments = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and node.targets[0] is subject_stores[0]
    ]
    if len(subject_assignments) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_ASSIGNMENT",
            f"{coordinate}:{subject_table_name}",
        )
    subject_assignment = subject_assignments[0]
    if _ast_sha256(subject_assignment) != (
        "2c8b915ebfb7a82cd65a78509e4ef1077045440266f37fa5e284f73a2e6020f5"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_ASSIGNMENT_AST",
            f"{coordinate}:{subject_table_name}",
        )
    expected_branches = (
        "schema_documents", "blobs", "events", "table_snapshots",
        "checkpoint_copies", "selector_history",
    )
    if (
        not isinstance(subject_assignment.value, ast.Tuple)
        or len(subject_assignment.value.elts) != len(expected_branches)
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_ROWS",
            f"{coordinate}:{subject_table_name}",
        )
    for row_index, (row, branch_key) in enumerate(zip(
        subject_assignment.value.elts, expected_branches, strict=True,
    )):
        if (
            not isinstance(row, ast.Tuple)
            or len(row.elts) != 2
            or not isinstance(row.elts[0], ast.Constant)
            or type(row.elts[0].value) is not str
            or row.elts[0].value != branch_key
            or not _is_captured_branch(row.elts[1], branch_key)
        ):
            raise ReadinessError(
                "RESOURCE_CARDINALITY_BINDING_SUBJECT_ROW",
                f"{coordinate}:{subject_table_name}:{row_index}",
            )
    subject_loops = [
        node for node in ast.walk(function)
        if isinstance(node, ast.For) and node.iter is subject_loads[0]
    ]
    if len(subject_loops) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_LOOP",
            f"{coordinate}:{subject_table_name}",
        )
    subject_loop = subject_loops[0]
    if _ast_sha256(subject_loop) != (
        "9e3c2a4b8b7a01aefe2d991cbd889eb3e438c2849d75e31b89ed89afd9265b41"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_LOOP_AST",
            f"{coordinate}:{subject_table_name}",
        )
    if (
        not isinstance(subject_loop.target, ast.Tuple)
        or tuple(
            item.id if isinstance(item, ast.Name) else None
            for item in subject_loop.target.elts
        ) != ("name", "value")
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_SUBJECT_LOOP_TARGET",
            f"{coordinate}:{subject_table_name}",
        )

    table_name = "cardinalities"
    name_nodes = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == table_name
    ]
    stores = [node for node in name_nodes if isinstance(node.ctx, ast.Store)]
    loads = [node for node in name_nodes if isinstance(node.ctx, ast.Load)]
    if len(stores) != 1 or len(loads) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_TABLE_NAME", f"{coordinate}:{table_name}"
        )
    if any(
        isinstance(node, ast.Constant) and node.value == table_name
        for node in ast.walk(function)
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_DYNAMIC_TABLE",
            f"{coordinate}:{table_name}",
        )

    assignments = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and node.targets[0] is stores[0]
    ]
    if len(assignments) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT",
            f"{coordinate}:{table_name}",
        )
    assignment = assignments[0]
    assignment_hash = _ast_sha256(assignment)
    if assignment_hash != (
        "49d78a29c5302a5f0c2a9d4edaef5072af28db8375c35677cb1e1effd2e25c94"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_ASSIGNMENT_AST",
            f"{coordinate}:{table_name}",
        )

    rows = (
        (
            "schema_documents", "9", "9",
            "9322c9eed913fee8a120b2d2bbe4c665d87230d40446aef1621c35a0e4c630d9",
            "cc70a073ff6cb3d1a80a48869ff0073a91600b675a290a0318e83eb7b6c7907b",
        ),
        (
            "blobs", "0", "MAX_BLOBS",
            "8dc4ce59580dbb69690973f368094a14a3292b63e1c523a65abb87230e60c4ff",
            "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3",
        ),
        (
            "events", "0", "MAX_EVENTS",
            "94944d590dfbc915aa3ab92438f56f116ba8066724cd88c5aa9acbe50a9d4751",
            "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1",
        ),
        (
            "table_snapshots", "len(_TABLE_SPECS)", "len(_TABLE_SPECS)",
            "20ae06e86122a5e082532a0a9fdffc229db47b917a9a3a98249bb146a48eb329",
            "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
        ),
        (
            "checkpoint_copies", "0", "MAX_CHECKPOINT_COPIES",
            "795c31fe76805ff8a2cbf3d0d459bfd4a9156dd3a95b24253eacee21334c96f1",
            "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13",
        ),
        (
            "selector_history", "MIN_SELECTORS", "MAX_SELECTORS",
            "9ab078af59b3b851dbd4deba1ea77e7d1822ad3758af503ee8c494ea47b27484",
            "eeee1fcbd15b357a15780fe79e32e2e5046cbb44d1d02e7025828aaa61940557",
        ),
    )
    if not isinstance(assignment.value, ast.Tuple) or len(
        assignment.value.elts
    ) != len(rows):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_ROWS", f"{coordinate}:{table_name}"
        )

    loops = [
        node for node in ast.walk(function)
        if isinstance(node, ast.For) and node.iter is loads[0]
    ]
    if len(loops) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_LOOP", f"{coordinate}:{table_name}"
        )
    loop = loops[0]
    loop_hash = _ast_sha256(loop)
    if loop_hash != (
        "240c758d427bfefb4cd9ae2f020a6c8d8212178637c304811e1751dea8b98e2f"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_LOOP_AST", f"{coordinate}:{table_name}"
        )
    if (
        not isinstance(loop.target, ast.Tuple)
        or tuple(
            item.id if isinstance(item, ast.Name) else None
            for item in loop.target.elts
        ) != ("name", "minimum", "maximum")
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_LOOP_TARGET",
            f"{coordinate}:{table_name}",
        )
    flow_pins = {
        "validity_gate_ast_sha256": (
            "80f43e2757b87785145812c7bbdd11dd7f2b75ca7983a0e20657f51bf0493557"
        ),
        "subject_lookup_ast_sha256": (
            "c7fee319573f6b06586df87192a91ea53633133dc1970225b005d91733d96f34"
        ),
        "comparison_assignment_ast_sha256": (
            "0ac4a3c116faf2d3b271a709a0b15171fa566779bb8e03797b6271aaaec94018"
        ),
        "result_assignment_ast_sha256": (
            "f7babf5f583439c6651955a1f94cd7ded828a872da0550f437198585bcdfc6e6"
        ),
        "invalid_branch_ast_sha256": (
            "10f692935ade01e94f5748199c52cdc242aa0260a5c88603a03dd3710c13accb"
        ),
    }
    if (
        len(loop.body) != 5
        or tuple(_ast_sha256(node) for node in loop.body)
        != tuple(flow_pins.values())
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_FLOW_AST",
            f"{coordinate}:{table_name}",
        )
    comparisons = [
        node for node in ast.walk(loop)
        if _is_cardinality_bound_comparison(node)
    ]
    if len(comparisons) != 1:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_COMPARATOR",
            f"{coordinate}:{table_name}",
        )
    comparator_site_id = (
        "807681eb5829047729803ad4290cd3239097de959106e756ab8bd52329894e24"
    )
    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError("RESOURCE_CARDINALITY_BINDING_PREDECESSOR_DUPLICATE", path)
    predecessor = predecessor_by_id.get(comparator_site_id)
    if predecessor != {
        "ast_sha256": _ast_sha256(comparisons[0]),
        "classification": "UNCLASSIFIED",
        "expression": ast.unparse(comparisons[0]),
        "kind": "BOUND_COMPARISON",
        "line": comparisons[0].lineno,
        "occurrence": predecessor.get("occurrence") if predecessor else None,
        "path": path,
        "qualname": "<module>.inspect_runtime_image_host",
        "site_id": comparator_site_id,
    }:
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_COMPARATOR_SITE",
            f"{coordinate}:{table_name}",
        )
    if semantic_function_ast_sha256 != (
        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
    ):
        raise ReadinessError(
            "RESOURCE_CARDINALITY_BINDING_FUNCTION_AST", coordinate
        )

    result: list[dict[str, Any]] = []
    for row_index, (row, subject_row, expected) in enumerate(zip(
        assignment.value.elts, subject_assignment.value.elts, rows,
        strict=True,
    )):
        branch_key, minimum_expression, maximum_expression, expected_ast, expected_site = expected
        if (
            not isinstance(row, ast.Tuple)
            or len(row.elts) != 3
            or not isinstance(row.elts[0], ast.Constant)
            or type(row.elts[0].value) is not str
            or row.elts[0].value != branch_key
            or ast.unparse(row.elts[1]) != minimum_expression
            or ast.unparse(row.elts[2]) != maximum_expression
            or _ast_sha256(row) != expected_ast
        ):
            raise ReadinessError(
                "RESOURCE_CARDINALITY_BINDING_ROW_AST",
                f"{coordinate}:{table_name}:{row_index}",
            )
        record = {
            "ast_sha256": expected_ast,
            "binding": f"{table_name}:{branch_key}",
            "branch_key": branch_key,
            "classification": "UNCLASSIFIED",
            "comparator_site_id": comparator_site_id,
            "expression": ast.unparse(row),
            "kind": "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING",
            "line": row.lineno,
            "loop_ast_sha256": loop_hash,
            "maximum_expression": maximum_expression,
            "minimum_expression": minimum_expression,
            "path": path,
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": row_index,
            "semantic_function_ast_sha256": semantic_function_ast_sha256,
            "subject_loop_ast_sha256": _ast_sha256(subject_loop),
            "subject_row_ast_sha256": _ast_sha256(subject_row),
            "subject_table_assignment_ast_sha256": _ast_sha256(
                subject_assignment
            ),
            "subject_binding": f"captured[{branch_key!r}]",
            "subject_expression": "captured[name]",
            "table_assignment_ast_sha256": assignment_hash,
            "table_name": table_name,
            **flow_pins,
        }
        identity = {
            key: value for key, value in record.items()
            if key not in {"classification", "expression", "line"}
        }
        record["site_id"] = _domain_digest(
            RESOURCE_CARDINALITY_BINDING_SITE_DOMAIN, identity
        )
        if record["site_id"] != expected_site:
            raise ReadinessError(
                "RESOURCE_CARDINALITY_BINDING_SITE_ID",
                f"{coordinate}:{table_name}:{row_index}",
            )
        result.append(record)

    if len(result) != 6 or len({item["site_id"] for item in result}) != 6:
        raise ReadinessError("RESOURCE_CARDINALITY_BINDING_CARDINALITY", path)
    return sorted(result, key=lambda item: (item["path"], item["site_id"]))


def _source_bound_table_row_cap_binding_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the closed V4 positional table-row-cap extension."""
    path = "src/edgelab/runtime_v2_image.py"
    coordinate = f"{path}:inspect_runtime_image_host"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_SOURCE", path) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "inspect_runtime_image_host"
    ]
    if len(functions) != 1:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_FUNCTION", coordinate)
    function = functions[0]
    function_hash = _ast_sha256(function)
    module_hash = _ast_sha256(tree)
    if function_hash != (
        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_FUNCTION_AST", coordinate)
    if module_hash != (
        "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_MODULE_AST", path)
    table_spec_classes = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_TableSpec"
    ]
    if (
        len(table_spec_classes) != 1
        or _ast_sha256(table_spec_classes[0])
        != "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_TABLE_SPEC_CLASS", path)

    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_TABLE_SPECS"
    ]
    if len(assignments) != 1:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_TABLE_SPECS", path)
    assignment = assignments[0]
    assignment_hash = _ast_sha256(assignment)
    if assignment_hash != (
        "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_TABLE_SPECS_AST", path)

    profiles = (
        ("attempts", 100_000, "ec260bd0442443c8889247aee1b6017204ef8e638d084f43c64e71cdaa9a3ea8", "962b5e773f9ea0b63d583e91fd0e4881dfbcfc9a6324d682f06a9e251148cf22", "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990"),
        ("blobs", 300_000, "db64ac49a822caa146ccce59c9c43493efea07fa867ab01da4f5847e275d9138", "e98f35a3d0537534bea89a539128f69d20e8418fe411720d381b60af58457e34", "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428"),
        ("claims", 100_000, "8022e8bb8dca11ecac4cda6b7d86675a35a33f6586c9fc763a0c88dc2e25af4c", "aafcafb39e3622065dedb4d7e15be502da73177301d29ca792d611dcd18f263c", "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737"),
        ("events", 100_000, "c457e2aaa43bac1efac6887835fc034b2ae6a6aa793284d1f1e0416443ea6eeb", "41321b95b46ab4240d118e9ad347aaf58c1dc21456ec07eb88f12b1fbb6f3a0a", "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed"),
        ("idempotency", 100_000, "c4ae34b3a69aa97f06d98d75313060be2cf8290c032e63593919813095789b7a", "ced10a66c811c98c5760829800b897bab92e18a6d635d56cbf9c2be7dea30cf1", "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72"),
        ("legacy_archive", 1, "1a89ac6ff9afbe3ef25bba879d53ae71f86bc0f26772cf0676ef4230191e61b9", "ba8868ef601db01139797d863b6a2c9b22da8b492b93b14451610ab10346c65f", "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18"),
        ("metadata", 1, "345667d74d800a8ab46094cfecc00b6e867bab5a5dd87a6ad77caedc5e68d31b", "603a2ffd90c3e09feac265d108beb5a7a48ec62def22a202fd0f45ca1feb5579", "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"),
        ("migrations", 0, "b54cc7867c718ef5b8f6e9566da8b1efe64bde1d302fc15043aa96dd04df0c3d", "5cc3d3beb8e159ca0e64e55d0e4118b865f4b82c4bb8ea4771b7f4339bd8a141", "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a"),
        ("remediation_links", 100_000, "1fe1ad94e3df90de6fc3f042d37d286292914522b4bc22ec9e7f3e253dd02366", "570b5960e7888fe6a94cc9cc9d9c725de8ec963ccfd18e7179d191e2df22743d", "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a"),
        ("reviews", 100_000, "4e45ce6231fd6af84a513f6c401a988bbba7b965c12c95576203c41c3de69e04", "71b9da445e2db2016510d7655fd999f887cc6b13326eb91e7896e12d425b6fbb", "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0"),
        ("schema_documents", 9, "b6227ea04426526d2328d17483f16b30c61ec141d6e904878016ee72cf70b07c", "4e00e9f257a857095aae9b98fc61c9897eb437deaf1f499a46b5bd529cdf3486", "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2"),
        ("schema_registry", 1, "8b93a8c07c34c56e41f154e9c01c69802103c63fbd09b1d6858262c5b70aef2d", "79684afc536b1317fe0d6ba1886d7c84a31feb27a642dd43fca0fe636eef1cf0", "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793"),
        ("seals", 1, "c56d6606428c4655ca874181b5c350454abb51ac4f47c8faf02c3113b6277668", "cd3ea4e9a30f79fb4eac41303e9ff0a25e1f66ba63e4cc1e70039aa3d5c18d7c", "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b"),
        ("snapshots", 100_000, "7bd9884cddd766196a998045684c0f28a920f0a50891a6e168d7d9ac9bbda745", "27d01446627311084853618cf3545af4a767ea9ca939c1011e31118b797b9f36", "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b"),
        ("tasks", 100_000, "aefbf071d2ded5d8cc71b0120cae99b970ab4506f5fd6d5b5eb2437b6a025d2a", "9d14812b77c13b635b9ec0f782c2075420d8158c4a1d52825c72f5938fdba59e", "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b"),
    )
    if not isinstance(assignment.value, ast.Tuple) or len(
        assignment.value.elts
    ) != len(profiles):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_TABLE_SPEC_COUNT", path)

    outer_gates = [
        node for node in ast.walk(function)
        if isinstance(node, ast.If)
        and ast.unparse(node.test)
        == "cardinality_valid.get('table_snapshots', False)"
    ]
    if (
        len(outer_gates) != 1
        or _ast_sha256(outer_gates[0])
        != "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_OUTER_GATE", coordinate)
    outer_gate = outer_gates[0]

    loops = [
        node for node in ast.walk(function)
        if isinstance(node, ast.For)
        and _ast_sha256(node)
        == "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91"
    ]
    if len(loops) != 1:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_LOOP", coordinate)
    loop = loops[0]
    loop_hash = _ast_sha256(loop)
    if ast.unparse(loop.target) != "(index, (snapshot, spec))" or ast.unparse(
        loop.iter
    ) != "enumerate(zip(captured['table_snapshots'], _TABLE_SPECS, strict=True))":
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_LOOP_SHAPE", coordinate)
    if (
        not isinstance(loop.iter, ast.Call)
        or len(loop.iter.args) != 1
        or _ast_sha256(loop.iter.args[0])
        != "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81"
    ):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_STRICT_ZIP", coordinate)
    if len(loop.body) != 19:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_LOOP_BODY", coordinate)
    flow_pins = {
        "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
        "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
        "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
        "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
        "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
        "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
        "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
        "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
        "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
    }
    for index, expected_hash in zip(
        (1, 2, 3, 4, 5, 6, 7, 8, 9), flow_pins.values(), strict=True,
    ):
        if _ast_sha256(loop.body[index]) != expected_hash:
            raise ReadinessError("RESOURCE_ROW_CAP_BINDING_FLOW_AST", coordinate)

    row_cap_branch = loop.body[9]
    comparisons = [
        node for node in ast.walk(row_cap_branch)
        if isinstance(node, ast.Compare)
        and ast.unparse(node) == "len(rows) > spec.max_rows"
    ]
    if len(comparisons) != 1:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_COMPARATOR", coordinate)
    comparator_site_id = (
        "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a"
    )
    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_PREDECESSOR_DUPLICATE", path)
    comparator = comparisons[0]
    predecessor = predecessor_by_id.get(comparator_site_id)
    if predecessor != {
        "ast_sha256": _ast_sha256(comparator),
        "classification": "UNCLASSIFIED",
        "expression": ast.unparse(comparator),
        "kind": "BOUND_COMPARISON",
        "line": comparator.lineno,
        "occurrence": predecessor.get("occurrence") if predecessor else None,
        "path": path,
        "qualname": "<module>.inspect_runtime_image_host",
        "site_id": comparator_site_id,
    }:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_COMPARATOR_SITE", coordinate)
    table_snapshots_cardinality_site_id = (
        "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
    )
    cardinality_predecessor = predecessor_by_id.get(
        table_snapshots_cardinality_site_id
    )
    if (
        cardinality_predecessor is None
        or cardinality_predecessor.get("kind")
        != "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING"
        or cardinality_predecessor.get("branch_key") != "table_snapshots"
        or cardinality_predecessor.get("subject_binding")
        != "captured['table_snapshots']"
        or cardinality_predecessor.get("minimum_expression")
        != "len(_TABLE_SPECS)"
        or cardinality_predecessor.get("maximum_expression")
        != "len(_TABLE_SPECS)"
        or cardinality_predecessor.get("classification") != "UNCLASSIFIED"
    ):
        raise ReadinessError(
            "RESOURCE_ROW_CAP_BINDING_CARDINALITY_PREDECESSOR", coordinate
        )

    result: list[dict[str, Any]] = []
    for row_index, (helper, profile) in enumerate(zip(
        assignment.value.elts, profiles, strict=True,
    )):
        table_name, maximum, helper_site_id, helper_ast, expected_site = profile
        if (
            not isinstance(helper, ast.Call)
            or not isinstance(helper.func, ast.Name)
            or helper.func.id != "_TableSpec"
            or len(helper.args) != 5
            or helper.keywords
            or not isinstance(helper.args[0], ast.Constant)
            or helper.args[0].value != table_name
            or _integer_constant(helper.args[4]) != maximum
            or _ast_sha256(helper) != helper_ast
        ):
            raise ReadinessError(
                "RESOURCE_ROW_CAP_BINDING_HELPER",
                f"{coordinate}:{row_index}:{table_name}",
            )
        helper_predecessor = predecessor_by_id.get(helper_site_id)
        if helper_predecessor != {
            "ast_sha256": helper_ast,
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(helper),
            "kind": "BOUND_HELPER_CALL",
            "line": helper.lineno,
            "occurrence": (
                helper_predecessor.get("occurrence")
                if helper_predecessor else None
            ),
            "path": path,
            "qualname": "<module>",
            "site_id": helper_site_id,
        }:
            raise ReadinessError(
                "RESOURCE_ROW_CAP_BINDING_HELPER_SITE",
                f"{coordinate}:{row_index}:{table_name}",
            )
        record = {
            "ast_sha256": helper_ast,
            "binding": f"table_row_caps:{table_name}",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": comparator_site_id,
            "expression": ast.unparse(helper),
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": helper.lineno,
            "loop_ast_sha256": loop_hash,
            "iterator_ast_sha256": _ast_sha256(loop.iter),
            "strict_zip_ast_sha256": _ast_sha256(loop.iter.args[0]),
            "maximum": maximum,
            "outer_cardinality_gate_ast_sha256": _ast_sha256(outer_gate),
            "path": path,
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": row_index,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": function_hash,
            "semantic_module_ast_sha256": module_hash,
            "subject_binding": f"captured['table_snapshots'][{row_index}].rows",
            "table_name": table_name,
            "table_snapshots_cardinality_site_id": (
                table_snapshots_cardinality_site_id
            ),
            "table_spec_class_ast_sha256": _ast_sha256(table_spec_classes[0]),
            "table_spec_ast_sha256": helper_ast,
            "table_spec_site_id": helper_site_id,
            "table_specs_assignment_ast_sha256": assignment_hash,
            **flow_pins,
        }
        identity = {
            key: value for key, value in record.items()
            if key not in {"classification", "expression", "line"}
        }
        record["site_id"] = _domain_digest(
            RESOURCE_TABLE_ROW_CAP_BINDING_SITE_DOMAIN, identity
        )
        if record["site_id"] != expected_site:
            raise ReadinessError(
                "RESOURCE_ROW_CAP_BINDING_SITE_ID",
                f"{coordinate}:{row_index}:{table_name}",
            )
        result.append(record)

    if len(result) != 15 or len({item["site_id"] for item in result}) != 15:
        raise ReadinessError("RESOURCE_ROW_CAP_BINDING_CARDINALITY", path)
    return sorted(result, key=lambda item: (item["path"], item["site_id"]))


def _source_bound_top_level_cardinality_maximum_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the single V5 top-level events maximum semantic binding.

    This deliberately does not classify either predecessor site.  It only
    separates the host-preflight ``captured['events']`` maximum from other
    equal-valued ``MAX_EVENTS`` constants and enforcement mechanisms.
    """
    path = "src/edgelab/runtime_v2_image.py"
    coordinate = f"{path}:inspect_runtime_image_host"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_SOURCE", path
        ) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "inspect_runtime_image_host"
    ]
    if len(functions) != 1:
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_FUNCTION", coordinate
        )
    function = functions[0]
    function_hash = _ast_sha256(function)
    module_hash = _ast_sha256(tree)
    if function_hash != (
        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
    ):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_FUNCTION_AST", coordinate
        )
    if module_hash != (
        "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
    ):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_MODULE_AST", path
        )

    definitions = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "MAX_EVENTS"
    ]
    if (
        len(definitions) != 1
        or _integer_constant(definitions[0].value) != 100_000
        or _ast_sha256(definitions[0])
        != "36776d47d1ea9414c879865979d7d76c23429d7c4cf858cfbb07704214384104"
    ):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_MAXIMUM_DEFINITION", path
        )
    definition = definitions[0]

    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_PREDECESSOR_DUPLICATE", path
        )
    definition_site_id = (
        "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f"
    )
    definition_predecessor = predecessor_by_id.get(definition_site_id)
    if definition_predecessor != {
        "ast_sha256": _ast_sha256(definition),
        "classification": "UNCLASSIFIED",
        "expression": ast.unparse(definition),
        "kind": "MODULE_NUMERIC_ASSIGNMENT",
        "line": definition.lineno,
        "occurrence": 1,
        "path": path,
        "qualname": "<module>",
        "site_id": definition_site_id,
    }:
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_DEFINITION_SITE", path
        )

    cardinality_site_id = (
        "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1"
    )
    cardinality_predecessor = predecessor_by_id.get(cardinality_site_id)
    if (
        cardinality_predecessor is None
        or cardinality_predecessor.get("kind")
        != "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING"
        or cardinality_predecessor.get("binding") != "cardinalities:events"
        or cardinality_predecessor.get("branch_key") != "events"
        or cardinality_predecessor.get("minimum_expression") != "0"
        or cardinality_predecessor.get("maximum_expression") != "MAX_EVENTS"
        or cardinality_predecessor.get("subject_binding")
        != "captured['events']"
        or cardinality_predecessor.get("classification") != "UNCLASSIFIED"
    ):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_BRANCH_SITE", coordinate
        )

    tuple_loop = next(
        (
            node for node in ast.walk(function)
            if isinstance(node, ast.For)
            and ast.unparse(node.target) == "(name, value)"
            and ast.unparse(node.iter) == "tuple_fields"
        ),
        None,
    )
    cardinality_loop = next(
        (
            node for node in ast.walk(function)
            if isinstance(node, ast.For)
            and ast.unparse(node.target) == "(name, minimum, maximum)"
            and ast.unparse(node.iter) == "cardinalities"
        ),
        None,
    )
    member_loop = next(
        (
            node for node in ast.walk(function)
            if isinstance(node, ast.For)
            and ast.unparse(node.target) == "(name, values, maximum)"
            and ast.unparse(node.iter) == "byte_collections"
        ),
        None,
    )
    sanitized_gate = next(
        (
            node for node in ast.walk(function)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not violations"
        ),
        None,
    )
    if (
        tuple_loop is None
        or _ast_sha256(tuple_loop)
        != "9e3c2a4b8b7a01aefe2d991cbd889eb3e438c2849d75e31b89ed89afd9265b41"
        or cardinality_loop is None
        or _ast_sha256(cardinality_loop)
        != "240c758d427bfefb4cd9ae2f020a6c8d8212178637c304811e1751dea8b98e2f"
        or member_loop is None
        or _ast_sha256(member_loop)
        != "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
        or sanitized_gate is None
        or _ast_sha256(sanitized_gate)
        != "96643ddc4991990f0f04524e6e3f44d13fe7ac8938e9818460dc7054d715a7e2"
    ):
        raise ReadinessError(
            "RESOURCE_TOP_LEVEL_CARDINALITY_FLOW_AST", coordinate
        )

    tuple_guard = tuple_loop.body[0]
    tuple_result = tuple_loop.body[1]
    tuple_invalid = tuple_loop.body[2]
    validity_gate = cardinality_loop.body[0]
    comparison_assignment = cardinality_loop.body[2]
    comparison_result = cardinality_loop.body[3]
    invalid_branch = cardinality_loop.body[4]
    member_gate = member_loop.body[0]
    expected_flow_hashes = {
        "tuple_guard_ast_sha256": (
            tuple_guard,
            "48c990518a6d97c4e3c5d6c976111eb55261d758f76466970d2ee40d2c9d3f98",
        ),
        "tuple_result_ast_sha256": (
            tuple_result,
            "b307f58801ce8e78a43696d5953c22e0b2c93a79418f4a3f941f608644979fbb",
        ),
        "tuple_invalid_ast_sha256": (
            tuple_invalid,
            "ebaece4655128040d4ecf6fafb8970b1f4b75d2d2199836efba5b4611fa71aad",
        ),
        "validity_gate_ast_sha256": (
            validity_gate,
            "80f43e2757b87785145812c7bbdd11dd7f2b75ca7983a0e20657f51bf0493557",
        ),
        "comparison_assignment_ast_sha256": (
            comparison_assignment,
            "0ac4a3c116faf2d3b271a709a0b15171fa566779bb8e03797b6271aaaec94018",
        ),
        "comparison_result_ast_sha256": (
            comparison_result,
            "f7babf5f583439c6651955a1f94cd7ded828a872da0550f437198585bcdfc6e6",
        ),
        "invalid_branch_ast_sha256": (
            invalid_branch,
            "10f692935ade01e94f5748199c52cdc242aa0260a5c88603a03dd3710c13accb",
        ),
        "member_gate_ast_sha256": (
            member_gate,
            "e6cb8d515794956552ebab7d5e2932e76e217cb0944ac82a8bfc7139d1cd36ae",
        ),
    }
    for node, expected in expected_flow_hashes.values():
        if _ast_sha256(node) != expected:
            raise ReadinessError(
                "RESOURCE_TOP_LEVEL_CARDINALITY_FLOW_NODE", coordinate
            )

    record = {
        "binding": "cardinality_maxima:events",
        "branch_cardinality_site_id": cardinality_site_id,
        "classification": "UNCLASSIFIED",
        "definition_ast_sha256": _ast_sha256(definition),
        "definition_site_id": definition_site_id,
        "excluded_semantics": [
            "INITIAL_REDUCER_EVENT_CARDINALITY",
            "TRANSITION_COLLECTION_CARDINALITY",
            "EVENTS_TABLE_ROW_CARDINALITY",
            "EVENT_ITEM_BYTE_CARDINALITY",
            "PUBLIC_VERIFIER_OR_AUTHORITY",
        ],
        "expression": "0 <= len(captured['events']) <= MAX_EVENTS",
        "kind": "BOUND_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING",
        "maximum": 100_000,
        "maximum_expression": "MAX_EVENTS",
        "path": path,
        "qualname": "<module>.inspect_runtime_image_host",
        "selection_semantics": "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY",
        "semantic_function_ast_sha256": function_hash,
        "semantic_module_ast_sha256": module_hash,
        "subject_binding": "captured['events']",
        "unit": "ITEMS",
        "tuple_loop_ast_sha256": _ast_sha256(tuple_loop),
        "cardinality_loop_ast_sha256": _ast_sha256(cardinality_loop),
        "member_loop_ast_sha256": _ast_sha256(member_loop),
        "sanitized_image_gate_ast_sha256": _ast_sha256(sanitized_gate),
        **{
            key: expected
            for key, (_, expected) in expected_flow_hashes.items()
        },
    }
    identity = {
        key: value for key, value in record.items()
        if key not in {"classification", "expression"}
    }
    record["site_id"] = _domain_digest(
        RESOURCE_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING_SITE_DOMAIN,
        identity,
    )
    return [record]


def _source_bound_finding_artifact_character_maximum_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the single V6 verifier finding-artifact truncation binding.

    The nested ``bounded`` helper is shared with finding coordinates.  This
    record binds only its artifact caller to the 256-character definition and
    exact UTF-8 digest-suffix truncation flow; it classifies no predecessor.
    """
    path = "src/edgelab/runtime_v2_verifier.py"
    coordinate = f"{path}:_finding"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_SOURCE", path) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_finding"
    ]
    if len(functions) != 1:
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_FUNCTION", coordinate)
    function = functions[0]
    nested = [
        node for node in function.body
        if isinstance(node, ast.FunctionDef) and node.name == "bounded"
    ]
    if len(nested) != 1:
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_HELPER", coordinate)
    bounded = nested[0]
    function_hash = _ast_sha256(function)
    bounded_hash = _ast_sha256(bounded)
    module_hash = _ast_sha256(tree)
    if function_hash != (
        "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781"
    ):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_FUNCTION_AST", coordinate)
    if bounded_hash != (
        "592e2f700af27699e0fe9eade5fd0f357d5bf7949ae370face4a34efd0ab6f9c"
    ):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_HELPER_AST", coordinate)
    if module_hash != (
        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
    ):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_MODULE_AST", path)

    definitions = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "MAX_FINDING_ARTIFACT_CHARS"
    ]
    if (
        len(definitions) != 1
        or _integer_constant(definitions[0].value) != 256
        or _ast_sha256(definitions[0])
        != "ae70f40d2c066a8450ddf01e6bf0a1c75d6bc2a4dad282ed7b350729e4e1111b"
    ):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_MAXIMUM_DEFINITION", path)
    definition = definitions[0]

    if len(bounded.body) != 3 or not isinstance(bounded.body[0], ast.If):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_HELPER_SHAPE", coordinate)
    comparison = bounded.body[0].test
    suffix_assignment = bounded.body[1]
    truncating_return = bounded.body[2]
    slices = [
        node for node in ast.walk(truncating_return)
        if isinstance(node, ast.Subscript)
    ]
    if len(slices) != 1:
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_SLICE", coordinate)
    truncating_slice = slices[0]
    flow_hashes = {
        "comparison_ast_sha256": (
            comparison,
            "159e23864d588432b924de55a370594d8789e3ddbb8a9768388ec472f0cb6ce4",
        ),
        "suffix_assignment_ast_sha256": (
            suffix_assignment,
            "955195bbb5a430a35b8a25506710d4ae29dd97dfb851080af22ddbd3af035f94",
        ),
        "truncating_return_ast_sha256": (
            truncating_return,
            "6fd09e200f846e9e544f8cbd866d35baf4b58e110aea81a6c2919139f03bdedb",
        ),
        "truncating_slice_ast_sha256": (
            truncating_slice,
            "74117ea7f02d52d57cdd5cfd500f420236efd5451e9c19f9fe00afae164cd152",
        ),
    }
    for node, expected in flow_hashes.values():
        if _ast_sha256(node) != expected:
            raise ReadinessError("RESOURCE_FINDING_ARTIFACT_FLOW_AST", coordinate)

    artifact_calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "bounded"
        and len(node.args) == 2
        and ast.unparse(node.args[0]) == "artifact"
        and ast.unparse(node.args[1]) == "MAX_FINDING_ARTIFACT_CHARS"
    ]
    if (
        len(artifact_calls) != 1
        or _ast_sha256(artifact_calls[0])
        != "c5f892612da3da02259a8933ec26ed94d91e9f834c7f7d115f15d23ff085aa73"
    ):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_CALL", coordinate)
    artifact_call = artifact_calls[0]

    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError("RESOURCE_FINDING_ARTIFACT_PREDECESSOR_DUPLICATE", path)
    predecessor_expectations = {
        "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f": {
            "ast_sha256": _ast_sha256(definition),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(definition),
            "kind": "MODULE_NUMERIC_ASSIGNMENT",
            "line": definition.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>",
        },
        "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98": {
            "ast_sha256": _ast_sha256(artifact_call),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(artifact_call),
            "kind": "BOUND_HELPER_CALL",
            "line": artifact_call.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding",
        },
        "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b": {
            "ast_sha256": _ast_sha256(comparison),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(comparison),
            "kind": "BOUND_COMPARISON",
            "line": comparison.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding.bounded",
        },
        "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac": {
            "ast_sha256": _ast_sha256(truncating_slice),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(truncating_slice),
            "kind": "NUMERIC_SLICE",
            "line": truncating_slice.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding.bounded",
        },
    }
    for site_id, expected in predecessor_expectations.items():
        observed = predecessor_by_id.get(site_id)
        if observed != {**expected, "site_id": site_id}:
            raise ReadinessError("RESOURCE_FINDING_ARTIFACT_PREDECESSOR_SITE", site_id)

    record = {
        "binding": "verification_finding:artifact",
        "caller_site_id": (
            "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98"
        ),
        "classification": "UNCLASSIFIED",
        "comparison_site_id": (
            "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
        ),
        "definition_ast_sha256": _ast_sha256(definition),
        "definition_site_id": (
            "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
        ),
        "excluded_semantics": [
            "VERIFICATION_FINDING_COORDINATE_CHARACTER_MAXIMUM",
            "GENERIC_BOUNDED_HELPER_COMPARISON_OR_SLICE",
            "FINDING_COUNT_MAXIMUM",
            "DIAGNOSTIC_CORRECTNESS",
            "PUBLIC_VERIFIER_ACCEPTANCE_OR_AUTHORITY",
        ],
        "expression": (
            "len(artifact) <= 256 else artifact[:184] + "
            "'#sha256=' + sha256(artifact.encode('utf-8')).hexdigest()"
        ),
        "finding_function_ast_sha256": function_hash,
        "kind": "BOUND_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING",
        "maximum": 256,
        "maximum_expression": "MAX_FINDING_ARTIFACT_CHARS",
        "nested_bounded_ast_sha256": bounded_hash,
        "path": path,
        "qualname": "<module>._finding",
        "selection_semantics": (
            "VERIFICATION_FINDING_ARTIFACT_CHARACTER_MAXIMUM_ONLY"
        ),
        "semantic_module_ast_sha256": module_hash,
        "slice_site_id": (
            "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"
        ),
        "subject_binding": "VerificationFinding.artifact",
        "unit": "CHARACTERS",
        **{key: expected for key, (_, expected) in flow_hashes.items()},
    }
    identity = {
        key: value for key, value in record.items()
        if key not in {"classification", "expression"}
    }
    record["site_id"] = _domain_digest(
        RESOURCE_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING_SITE_DOMAIN,
        identity,
    )
    return [record]


def _source_bound_finding_coordinate_character_maximum_inventory(
    source_bytes: dict[str, bytes],
    predecessor_sites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive the single V7 verifier finding-coordinate truncation binding."""
    path = "src/edgelab/runtime_v2_verifier.py"
    coordinate = f"{path}:_finding"
    try:
        tree = ast.parse(source_bytes[path], filename=path)
    except KeyError as error:
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_SOURCE", path) from error
    except (SyntaxError, ValueError) as error:
        raise ReadinessError("PYTHON_SOURCE", path) from error

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_finding"
    ]
    if len(functions) != 1:
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_FUNCTION", coordinate)
    function = functions[0]
    nested = [
        node for node in function.body
        if isinstance(node, ast.FunctionDef) and node.name == "bounded"
    ]
    if len(nested) != 1:
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_HELPER", coordinate)
    bounded = nested[0]
    function_hash = _ast_sha256(function)
    bounded_hash = _ast_sha256(bounded)
    module_hash = _ast_sha256(tree)
    if function_hash != (
        "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781"
    ):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_FUNCTION_AST", coordinate)
    if bounded_hash != (
        "592e2f700af27699e0fe9eade5fd0f357d5bf7949ae370face4a34efd0ab6f9c"
    ):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_HELPER_AST", coordinate)
    if module_hash != (
        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
    ):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_MODULE_AST", path)

    definitions = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "MAX_FINDING_COORDINATE_CHARS"
    ]
    if (
        len(definitions) != 1
        or _integer_constant(definitions[0].value) != 512
        or _ast_sha256(definitions[0])
        != "3abd7812682ddf40aa0dcdb0e07f0f3ec920e5e58441882567c4254006d1da7b"
    ):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_MAXIMUM_DEFINITION", path)
    definition = definitions[0]

    if len(bounded.body) != 3 or not isinstance(bounded.body[0], ast.If):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_HELPER_SHAPE", coordinate)
    comparison = bounded.body[0].test
    suffix_assignment = bounded.body[1]
    truncating_return = bounded.body[2]
    slices = [
        node for node in ast.walk(truncating_return)
        if isinstance(node, ast.Subscript)
    ]
    if len(slices) != 1:
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_SLICE", coordinate)
    truncating_slice = slices[0]
    flow_hashes = {
        "comparison_ast_sha256": (
            comparison,
            "159e23864d588432b924de55a370594d8789e3ddbb8a9768388ec472f0cb6ce4",
        ),
        "suffix_assignment_ast_sha256": (
            suffix_assignment,
            "955195bbb5a430a35b8a25506710d4ae29dd97dfb851080af22ddbd3af035f94",
        ),
        "truncating_return_ast_sha256": (
            truncating_return,
            "6fd09e200f846e9e544f8cbd866d35baf4b58e110aea81a6c2919139f03bdedb",
        ),
        "truncating_slice_ast_sha256": (
            truncating_slice,
            "74117ea7f02d52d57cdd5cfd500f420236efd5451e9c19f9fe00afae164cd152",
        ),
    }
    for node, expected in flow_hashes.values():
        if _ast_sha256(node) != expected:
            raise ReadinessError("RESOURCE_FINDING_COORDINATE_FLOW_AST", coordinate)

    coordinate_calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "bounded"
        and len(node.args) == 2
        and ast.unparse(node.args[0]) == "coordinate"
        and ast.unparse(node.args[1]) == "MAX_FINDING_COORDINATE_CHARS"
    ]
    if (
        len(coordinate_calls) != 1
        or _ast_sha256(coordinate_calls[0])
        != "1aa4ecb66db3f22cd16f2e0c1f9f56102d36fed3eaed9bf8e3cab90766af5249"
    ):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_CALL", coordinate)
    coordinate_call = coordinate_calls[0]

    predecessor_by_id = {item["site_id"]: item for item in predecessor_sites}
    if len(predecessor_by_id) != len(predecessor_sites):
        raise ReadinessError("RESOURCE_FINDING_COORDINATE_PREDECESSOR_DUPLICATE", path)
    predecessor_expectations = {
        "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed": {
            "ast_sha256": _ast_sha256(definition),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(definition),
            "kind": "MODULE_NUMERIC_ASSIGNMENT",
            "line": definition.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>",
        },
        "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c": {
            "ast_sha256": _ast_sha256(coordinate_call),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(coordinate_call),
            "kind": "BOUND_HELPER_CALL",
            "line": coordinate_call.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding",
        },
        "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b": {
            "ast_sha256": _ast_sha256(comparison),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(comparison),
            "kind": "BOUND_COMPARISON",
            "line": comparison.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding.bounded",
        },
        "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac": {
            "ast_sha256": _ast_sha256(truncating_slice),
            "classification": "UNCLASSIFIED",
            "expression": ast.unparse(truncating_slice),
            "kind": "NUMERIC_SLICE",
            "line": truncating_slice.lineno,
            "occurrence": 1,
            "path": path,
            "qualname": "<module>._finding.bounded",
        },
    }
    for site_id, expected in predecessor_expectations.items():
        observed = predecessor_by_id.get(site_id)
        if observed != {**expected, "site_id": site_id}:
            raise ReadinessError("RESOURCE_FINDING_COORDINATE_PREDECESSOR_SITE", site_id)

    record = {
        "binding": "verification_finding:coordinate",
        "caller_site_id": (
            "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c"
        ),
        "classification": "UNCLASSIFIED",
        "comparison_site_id": (
            "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
        ),
        "definition_ast_sha256": _ast_sha256(definition),
        "definition_site_id": (
            "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
        ),
        "excluded_semantics": [
            "VERIFICATION_FINDING_ARTIFACT_CHARACTER_MAXIMUM",
            "GENERIC_BOUNDED_HELPER_COMPARISON_OR_SLICE",
            "FINDING_COUNT_MAXIMUM",
            "DIAGNOSTIC_CORRECTNESS",
            "PUBLIC_VERIFIER_ACCEPTANCE_OR_AUTHORITY",
        ],
        "expression": (
            "len(coordinate) <= 512 else coordinate[:440] + "
            "'#sha256=' + sha256(coordinate.encode('utf-8')).hexdigest()"
        ),
        "finding_function_ast_sha256": function_hash,
        "kind": "BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING",
        "maximum": 512,
        "maximum_expression": "MAX_FINDING_COORDINATE_CHARS",
        "nested_bounded_ast_sha256": bounded_hash,
        "path": path,
        "qualname": "<module>._finding",
        "selection_semantics": (
            "VERIFICATION_FINDING_COORDINATE_CHARACTER_MAXIMUM_ONLY"
        ),
        "semantic_module_ast_sha256": module_hash,
        "slice_site_id": (
            "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"
        ),
        "subject_binding": "VerificationFinding.coordinate",
        "unit": "CHARACTERS",
        **{key: expected for key, (_, expected) in flow_hashes.items()},
    }
    identity = {
        key: value for key, value in record.items()
        if key not in {"classification", "expression"}
    }
    record["site_id"] = _domain_digest(
        RESOURCE_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING_SITE_DOMAIN,
        identity,
    )
    return [record]


def _resource_unit(name: str) -> str:
    if "BYTE" in name:
        return "BYTES"
    if "CHAR" in name or "PATH" in name or "COMPONENT" in name:
        return "CHARACTERS"
    if "DEPTH" in name:
        return "DEPTH"
    if "NODE" in name:
        return "NODES"
    return "ITEMS"


def _named_function(tree: ast.AST, name: str, coordinate: str) -> ast.AST:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1:
        raise ReadinessError("HARDCODED_LIMIT_FUNCTION", coordinate)
    return matches[0]


def _is_len_of(node: ast.AST, expression: str) -> bool:
    if (
        not isinstance(node, ast.Call)
        or len(node.args) != 1
        or node.keywords
        or not isinstance(node.func, ast.Name)
        or node.func.id != "len"
    ):
        return False
    argument = node.args[0]
    if expression == "digits":
        return isinstance(argument, ast.Name) and argument.id == "digits"
    return (
        expression == "image.selector_history"
        and isinstance(argument, ast.Attribute)
        and argument.attr == "selector_history"
        and isinstance(argument.value, ast.Name)
        and argument.value.id == "image"
    )


def _derived_hardcoded_limits(
    source_bytes: dict[str, bytes],
) -> list[dict[str, Any]]:
    derived: dict[str, int] = {}
    for fixed in HARD_CODED_RESOURCE_LIMITS:
        path, function_name = fixed["source_coordinate"].split(":", 1)
        raw = source_bytes[path]
        tree = ast.parse(raw, filename=path)
        function = _named_function(tree, function_name, fixed["source_coordinate"])
        expression = fixed["expression"]
        if expression == "depth > LIMIT":
            matches = [
                _integer_constant(node.comparators[0])
                for node in ast.walk(function)
                if isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Name)
                and node.left.id == "depth"
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Gt)
                and len(node.comparators) == 1
                and _integer_constant(node.comparators[0]) is not None
            ]
            values = matches
        elif expression == "len(digits) > LIMIT":
            values = [
                _integer_constant(node.comparators[0])
                for node in ast.walk(function)
                if isinstance(node, ast.Compare)
                and _is_len_of(node.left, "digits")
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Gt)
                and len(node.comparators) == 1
                and _integer_constant(node.comparators[0]) is not None
            ]
        else:
            bounds = [
                (
                    _integer_constant(node.left),
                    _integer_constant(node.comparators[1]),
                )
                for node in ast.walk(function)
                if isinstance(node, ast.Compare)
                and len(node.ops) == 2
                and all(isinstance(operator, ast.LtE) for operator in node.ops)
                and len(node.comparators) == 2
                and _integer_constant(node.left) is not None
                and _is_len_of(
                    node.comparators[0], "image.selector_history"
                )
                and _integer_constant(node.comparators[1]) is not None
            ]
            if len(bounds) != 2 or len(set(bounds)) != 1:
                raise ReadinessError(
                    "HARDCODED_LIMIT_EXPRESSION", fixed["source_coordinate"]
                )
            lower, upper = bounds[0]
            values = [upper if fixed["selector"] == "maximum" else lower]
        if len(values) != 1 or values[0] is None:
            raise ReadinessError(
                "HARDCODED_LIMIT_EXPRESSION", fixed["source_coordinate"]
            )
        derived[fixed["name"]] = values[0]
    return [
        {
            "name": fixed["name"],
            "source_coordinate": fixed["source_coordinate"],
            "unit": fixed["unit"],
            "value": derived[fixed["name"]],
        }
        for fixed in HARD_CODED_RESOURCE_LIMITS
    ]


def _resource_limits(
    source: dict[str, Any], source_bytes: dict[str, bytes]
) -> list[dict[str, Any]]:
    values: dict[str, int] = {}
    coordinates: dict[str, list[str]] = {}
    source_by_path = {
        item["path"]: item for item in source["local_artifacts"]
    }
    for path in sorted(source_by_path):
        raw = source_bytes[path]
        tree = ast.parse(raw, filename=path)
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value_node = node.value
            if value_node is None:
                continue
            value = _integer_constant(value_node)
            if value is None:
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                normalized = target.id.lstrip("_")
                if not normalized.startswith(("MAX_", "MIN_", "INT64_", "PORTABLE_")):
                    continue
                if normalized in values and values[normalized] != value:
                    raise ReadinessError("RESOURCE_LIMIT_CONFLICT", normalized)
                values[normalized] = value
                coordinates.setdefault(normalized, []).append(
                    f"{path}:{target.id}"
                )
    records = [
        {
            "name": name,
            "source_coordinates": sorted(coordinates[name]),
            "unit": _resource_unit(name),
            "value": values[name],
        }
        for name in sorted(values)
    ]
    records.extend(_derived_hardcoded_limits(source_bytes))
    table_path = "src/edgelab/runtime_v2_image.py"
    table_raw = source_bytes[table_path]
    table_tree = ast.parse(table_raw, filename=table_path)
    for node in ast.walk(table_tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or node.func.id != "_TableSpec"
            or len(node.args) < 5
            or not isinstance(node.args[0], ast.Constant)
            or type(node.args[0].value) is not str
        ):
            continue
        maximum = _integer_constant(node.args[-1])
        if maximum is None:
            raise ReadinessError("TABLE_ROW_LIMIT", f"{table_path}:{node.lineno}")
        records.append({
            "name": f"TABLE_{node.args[0].value.upper()}_ROWS",
            "source_coordinates": [f"{table_path}:{node.lineno}"],
            "unit": "ITEMS",
            "value": maximum,
        })
    return sorted(records, key=lambda item: item["name"])


def _digest_domains(
    source: dict[str, Any], source_bytes: dict[str, bytes]
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for item in source["local_artifacts"]:
        raw = source_bytes[item["path"]]
        tree = ast.parse(raw, filename=item["path"])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or type(node.value) is not bytes:
                continue
            domain = node.value
            if not domain.startswith(b"EDGELAB\0"):
                continue
            try:
                parts = domain.decode("ascii").split("\0")
            except UnicodeError as error:
                raise ReadinessError("DIGEST_DOMAIN_ASCII", item["path"]) from error
            if len(parts) not in {4, 5} or parts[0] != "EDGELAB" or parts[-1] != "":
                raise ReadinessError("DIGEST_DOMAIN_SHAPE", item["path"])
            name_parts = [parts[1].lower()]
            if len(parts) == 5:
                name_parts.append(parts[3].lower())
            name = "_".join(name_parts)
            text = domain.decode("ascii")
            existing = records.get(name)
            if existing is not None and existing["domain"] != text:
                raise ReadinessError("DIGEST_DOMAIN_NAME_COLLISION", name)
            if existing is None:
                records[name] = {
                    "domain": text,
                    "name": name,
                    "source_coordinates": [f"{item['path']}:{node.lineno}"],
                }
            else:
                existing["source_coordinates"].append(
                    f"{item['path']}:{node.lineno}"
                )
    for record in records.values():
        record["source_coordinates"] = sorted(set(record["source_coordinates"]))
    return [records[name] for name in sorted(records)]


def _content_inventory(
    root: Path, identities: set[tuple[int, int]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for name, domain, path in CONTENT_ASSETS:
        raw, identity = _audit_path(root, path)
        if identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", path)
        identities.add(identity)
        value = _parse_json(raw, path)
        if type(value) is not dict:
            raise ReadinessError("CONTENT_ASSET_OBJECT", path)
        result.append({
            "byte_length": len(raw),
            "domain_sha256": _domain_digest(domain, value),
            "name": name,
            "path": path,
            "raw_sha256": _sha256(raw),
        })
    return sorted(result, key=lambda item: item["path"])


def _resource_discovery_evidence_inventory(
    root: Path,
    identities: set[tuple[int, int]],
    resource_discovery: dict[str, Any],
) -> dict[str, Any]:
    """Validate the closed, deny-only Discovery V8 evidence manifest."""
    predecessor_values: dict[str, dict[str, Any]] = {}
    for expected, has_self_digest in (
        (RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST, True),
        (RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA, False),
        (RESOURCE_DISCOVERY_ANCESTOR_MANIFEST, True),
        (RESOURCE_DISCOVERY_ANCESTOR_SCHEMA, False),
    ):
        raw, identity = _audit_path(root, expected["path"])
        if identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", expected["path"])
        identities.add(identity)
        if len(raw) != expected["byte_length"] or _sha256(raw) != expected[
            "raw_sha256"
        ]:
            raise ReadinessError(
                "RESOURCE_DISCOVERY_PREDECESSOR_IDENTITY", expected["path"]
            )
        value = _parse_json(raw, expected["path"])
        if type(value) is not dict:
            raise ReadinessError(
                "RESOURCE_DISCOVERY_PREDECESSOR_OBJECT", expected["path"]
            )
        predecessor_values[expected["path"]] = value
        if has_self_digest and value.get(
            "discovery_manifest_sha256"
        ) != expected["discovery_manifest_sha256"]:
            raise ReadinessError(
                "RESOURCE_DISCOVERY_PREDECESSOR_DIGEST", expected["path"]
            )

    predecessor_manifest = predecessor_values[
        RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST["path"]
    ]
    if (
        predecessor_manifest.get("profile_id") != RESOURCE_DISCOVERY_V7_ID
        or predecessor_manifest.get("source_bound_site_count") != 425
        or predecessor_manifest.get("source_bound_sites_sha256")
        != RESOURCE_SOURCE_BOUND_SITES_V7_SHA256
        or predecessor_manifest.get("schema_bound_site_count") != 296
        or predecessor_manifest.get("schema_bound_sites_sha256")
        != "00b27a32303836f9d9910663e6bd2f76a7ca6d8c7cd614e5f22346b53cd104de"
    ):
        raise ReadinessError(
            "RESOURCE_DISCOVERY_PREDECESSOR_BINDING",
            RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST["path"],
        )

    if (
        predecessor_manifest.get("predecessor_manifest")
        != RESOURCE_DISCOVERY_ANCESTOR_MANIFEST
        or predecessor_manifest.get("predecessor_schema")
        != RESOURCE_DISCOVERY_ANCESTOR_SCHEMA
    ):
        raise ReadinessError(
            "RESOURCE_DISCOVERY_ANCESTOR_BINDING",
            RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST["path"],
        )

    schema_id, schema_path = RESOURCE_DISCOVERY_SCHEMA
    schema_raw, schema_identity = _audit_path(root, schema_path)
    if schema_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", schema_path)
    identities.add(schema_identity)
    schema = _parse_json(schema_raw, schema_path)
    if type(schema) is not dict or schema.get("$id") != schema_id:
        raise ReadinessError("SCHEMA_ID", schema_path)
    if _sha256(schema_raw) != RESOURCE_DISCOVERY_SCHEMA_RAW_SHA256:
        raise ReadinessError("RESOURCE_DISCOVERY_SCHEMA_IDENTITY", schema_path)

    profile_id, manifest_path = RESOURCE_DISCOVERY_MANIFEST
    manifest_raw, manifest_identity = _audit_path(root, manifest_path)
    if manifest_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", manifest_path)
    identities.add(manifest_identity)
    manifest = _parse_json(manifest_raw, manifest_path)
    expected_keys = {
        "classification_status", "coverage_status",
        "cumulative_derived_binding_site_count", "derived_binding_site_count",
        "derived_binding_site_ids", "derived_binding_sites",
        "discovered_site_count", "discovery_manifest_sha256",
        "discovery_schema_raw_sha256", "generation_disposition",
        "legacy_source_bound_site_count", "manifest_id", "predecessor_discovery",
        "predecessor_manifest", "predecessor_schema",
        "profile_id", "schema_bound_site_count", "schema_bound_sites_sha256",
        "schema_input_count", "schema_inputs_sha256", "schema_version",
        "source_bound_site_count", "source_bound_sites_sha256",
        "source_input_count", "source_inputs_sha256",
    }
    if type(manifest) is not dict or set(manifest) != expected_keys:
        raise ReadinessError("RESOURCE_DISCOVERY_MANIFEST_KEYS", manifest_path)

    binding_sites: list[dict[str, Any]] = []
    schema_bound_sites = resource_discovery.get("schema_bound_sites")
    if type(schema_bound_sites) is not list or len(schema_bound_sites) != 296:
        raise ReadinessError("SCHEMA_RESOURCE_SITE_CARDINALITY", "/")
    legacy_records = []
    for index, item in enumerate(schema_bound_sites):
        if type(item) is not dict or set(item) != {
            "classification", "json_pointer", "keyword", "path", "schema_id",
            "site_id", "value",
        }:
            raise ReadinessError("SCHEMA_RESOURCE_SITE_KEYS", f"/{index}")
        legacy_records.append({
            key: value for key, value in item.items() if key != "site_id"
        })
    if _address_schema_bound_inventory(legacy_records) != schema_bound_sites:
        raise ReadinessError("SCHEMA_RESOURCE_SITE_IDENTITY", "/")
    if _domain_digest(
        RESOURCE_SCHEMA_BOUND_SITES_V2_DOMAIN, schema_bound_sites
    ) != RESOURCE_SCHEMA_BOUND_SITES_V2_SHA256:
        raise ReadinessError("RESOURCE_DISCOVERY_V8_SCHEMA_IDENTITY", "/")
    schema_properties = schema.get("properties")
    if type(schema_properties) is not dict:
        raise ReadinessError("RESOURCE_DISCOVERY_SCHEMA_BINDING", schema_path)
    schema_bound_values = {
        "cumulative_derived_binding_site_count": resource_discovery[
            "cumulative_derived_binding_site_count"
        ],
        "derived_binding_site_count": len(binding_sites),
        "derived_binding_site_ids": sorted(
            item["site_id"] for item in binding_sites
        ),
        "derived_binding_sites": binding_sites,
        "source_bound_site_count": len(resource_discovery["source_bound_sites"]),
        "source_bound_sites_sha256": resource_discovery[
            "source_bound_sites_sha256"
        ],
    }
    for key, actual in schema_bound_values.items():
        property_schema = schema_properties.get(key)
        if (
            type(property_schema) is not dict
            or "const" not in property_schema
            or type(property_schema["const"]) is not type(actual)
            or property_schema["const"] != actual
        ):
            raise ReadinessError("RESOURCE_DISCOVERY_SCHEMA_BINDING", key)
    scalar_expected = {
        "schema_version": 8,
        "manifest_id": schema_id,
        "profile_id": profile_id,
        "coverage_status": "INCOMPLETE",
        "classification_status": "UNCLASSIFIED",
        "generation_disposition": "DENY",
        "discovery_schema_raw_sha256": RESOURCE_DISCOVERY_SCHEMA_RAW_SHA256,
        "predecessor_discovery": resource_discovery["predecessor_discovery"],
        "predecessor_manifest": dict(RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST),
        "predecessor_schema": dict(RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA),
        "source_input_count": len(resource_discovery["source_inputs"]),
        "source_inputs_sha256": resource_discovery["source_inputs_sha256"],
        "legacy_source_bound_site_count": resource_discovery[
            "legacy_source_bound_site_count"
        ],
        "cumulative_derived_binding_site_count": resource_discovery[
            "cumulative_derived_binding_site_count"
        ],
        "derived_binding_site_count": len(binding_sites),
        "source_bound_site_count": len(resource_discovery["source_bound_sites"]),
        "source_bound_sites_sha256": resource_discovery[
            "source_bound_sites_sha256"
        ],
        "schema_input_count": len(resource_discovery["schema_inputs"]),
        "schema_inputs_sha256": resource_discovery["schema_inputs_sha256"],
        "schema_bound_site_count": len(resource_discovery["schema_bound_sites"]),
        "schema_bound_sites_sha256": resource_discovery[
            "schema_bound_sites_sha256"
        ],
        "discovered_site_count": (
            len(resource_discovery["source_bound_sites"])
            + len(resource_discovery["schema_bound_sites"])
        ),
        "derived_binding_site_ids": sorted(
            item["site_id"] for item in binding_sites
        ),
        "derived_binding_sites": binding_sites,
    }
    for key, expected in scalar_expected.items():
        if type(manifest.get(key)) is not type(expected) or manifest.get(key) != expected:
            raise ReadinessError("RESOURCE_DISCOVERY_MANIFEST_BINDING", key)

    digest_value = dict(manifest)
    claimed_digest = digest_value.pop("discovery_manifest_sha256")
    if type(claimed_digest) is not str or claimed_digest != _domain_digest(
        RESOURCE_DISCOVERY_DOMAIN, digest_value
    ):
        raise ReadinessError("RESOURCE_DISCOVERY_MANIFEST_SELF_DIGEST", manifest_path)
    return {
        "manifest": {
            "byte_length": len(manifest_raw),
            "path": manifest_path,
            "raw_sha256": _sha256(manifest_raw),
        },
        "predecessor_manifest": dict(RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST),
        "predecessor_schema": dict(RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA),
        "profile_id": profile_id,
        "schema": {
            "byte_length": len(schema_raw),
            "path": schema_path,
            "raw_sha256": _sha256(schema_raw),
            "schema_id": schema_id,
        },
        "self_digest": claimed_digest,
    }


def _resource_site_maps(
    resource_discovery: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Build fail-closed source/schema identity maps before combining them."""
    source_records = resource_discovery.get("source_bound_sites")
    schema_records = resource_discovery.get("schema_bound_sites")
    if type(source_records) is not list or type(schema_records) is not list:
        raise ReadinessError("RESOURCE_SITE_RECORDS_TYPE", "/")
    if any(
        type(item) is not dict or type(item.get("site_id")) is not str
        for item in source_records
    ):
        raise ReadinessError("RESOURCE_SOURCE_SITE_ID_TYPE", "/")
    if any(
        type(item) is not dict or type(item.get("site_id")) is not str
        for item in schema_records
    ):
        raise ReadinessError("RESOURCE_SCHEMA_SITE_ID_TYPE", "/")
    source_sites = {item["site_id"]: item for item in source_records}
    schema_sites = {item["site_id"]: item for item in schema_records}
    if len(source_sites) != len(source_records):
        raise ReadinessError("RESOURCE_SITE_ID_DUPLICATE", "/")
    if len(schema_sites) != len(schema_records):
        raise ReadinessError("RESOURCE_SCHEMA_SITE_ID_DUPLICATE", "/")
    if set(source_sites) & set(schema_sites):
        raise ReadinessError("RESOURCE_SITE_NAMESPACE_COLLISION", "/")
    return source_sites, schema_sites


def _validate_classified_resource_site_ids(
    classified_source_site_ids: set[str],
    classified_schema_site_ids: set[str],
    expected_source_site_ids: frozenset[str],
    expected_schema_site_ids: frozenset[str],
    source_sites: dict[str, dict[str, Any]],
    schema_sites: dict[str, dict[str, Any]],
    coordinate: str,
) -> None:
    """Require the exact source/schema classification partition."""
    if classified_source_site_ids != expected_source_site_ids:
        raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_SET", coordinate)
    if classified_schema_site_ids != expected_schema_site_ids:
        raise ReadinessError("RESOURCE_SCHEMA_CLASSIFICATION_SITE_SET", coordinate)
    if classified_source_site_ids & set(schema_sites):
        raise ReadinessError("RESOURCE_SOURCE_SCHEMA_CROSS_KIND", coordinate)
    if classified_schema_site_ids & set(source_sites):
        raise ReadinessError("RESOURCE_SCHEMA_SOURCE_CROSS_KIND", coordinate)
    if not classified_source_site_ids <= set(source_sites):
        raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_MISSING", coordinate)
    if not classified_schema_site_ids <= set(schema_sites):
        raise ReadinessError("RESOURCE_SCHEMA_CLASSIFICATION_SITE_MISSING", coordinate)


def _resource_classification_inventory(
    root: Path,
    identities: set[tuple[int, int]],
    source_bytes: dict[str, bytes],
    source_inputs: list[dict[str, Any]],
    resource_discovery: dict[str, Any],
) -> dict[str, Any]:
    """Validate the cumulative deny-only semantic classification slices."""
    predecessor_records = (
        (RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST, True),
        (RESOURCE_CLASSIFICATION_V47_PREDECESSOR_SCHEMA, False),
        (RESOURCE_CLASSIFICATION_V46_PREDECESSOR_MANIFEST, True),
        (RESOURCE_CLASSIFICATION_V46_PREDECESSOR_SCHEMA, False),
        *tuple(
            (record, index % 2 == 0)
            for index, record in enumerate(RESOURCE_CLASSIFICATION_ANCESTORS)
        ),
    )
    manifest_values: dict[str, dict[str, Any]] = {}
    for expected, has_self_digest in predecessor_records:
        raw, identity = _audit_path(root, expected["path"])
        if identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", expected["path"])
        identities.add(identity)
        if len(raw) != expected["byte_length"] or _sha256(raw) != expected[
            "raw_sha256"
        ]:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_PREDECESSOR_IDENTITY", expected["path"]
            )
        if has_self_digest:
            value = _parse_json(raw, expected["path"])
            if type(value) is not dict or value.get(
                "classification_manifest_sha256"
            ) != expected["classification_manifest_sha256"]:
                raise ReadinessError(
                    "RESOURCE_CLASSIFICATION_PREDECESSOR_DIGEST", expected["path"]
                )
            manifest_values[expected["path"]] = value

    chain = tuple(
        (
            RESOURCE_CLASSIFICATION_V46_PREDECESSOR_MANIFEST
            if index == 0 else RESOURCE_CLASSIFICATION_ANCESTORS[index - 2],
            RESOURCE_CLASSIFICATION_ANCESTORS[index],
            RESOURCE_CLASSIFICATION_ANCESTORS[index + 1],
        )
        for index in range(0, len(RESOURCE_CLASSIFICATION_ANCESTORS), 2)
    )
    chain = (
        (
            RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST,
            RESOURCE_CLASSIFICATION_V46_PREDECESSOR_MANIFEST,
            RESOURCE_CLASSIFICATION_V46_PREDECESSOR_SCHEMA,
        ),
        *chain,
    )
    for owner, predecessor_manifest, predecessor_schema in chain:
        value = manifest_values.get(owner["path"])
        if value is None or value.get(
            "predecessor_manifest"
        ) != predecessor_manifest or value.get(
            "predecessor_schema"
        ) != predecessor_schema:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING", owner["path"]
            )

    schema_id, schema_path = RESOURCE_CLASSIFICATION_V47_SCHEMA
    schema_raw, schema_identity = _audit_path(root, schema_path)
    if schema_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", schema_path)
    identities.add(schema_identity)
    schema_value = _parse_json(schema_raw, schema_path)
    if type(schema_value) is not dict or schema_value.get("$id") != schema_id:
        raise ReadinessError("SCHEMA_ID", schema_path)
    if _sha256(schema_raw) != RESOURCE_CLASSIFICATION_V47_SCHEMA_RAW_SHA256:
        raise ReadinessError("RESOURCE_CLASSIFICATION_SCHEMA_IDENTITY", schema_path)

    profile_id, manifest_path = RESOURCE_CLASSIFICATION_V47_MANIFEST
    manifest_raw, manifest_identity = _audit_path(root, manifest_path)
    if manifest_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", manifest_path)
    identities.add(manifest_identity)
    manifest = _parse_json(manifest_raw, manifest_path)
    if type(manifest) is not dict:
        raise ReadinessError("RESOURCE_CLASSIFICATION_OBJECT", manifest_path)
    expected_keys = {
        "classification_schema_raw_sha256", "classified_site_count",
        "classification_manifest_sha256",
        "constraints", "coverage_status", "discovery_profile_id",
        "generation_disposition", "manifest_id", "profile_id",
        "predecessor_manifest", "predecessor_schema",
        "schema_bound_site_count", "schema_bound_sites_sha256",
        "schema_inputs_sha256", "schema_version", "source_bound_site_count",
        "source_bound_sites_sha256", "source_input_count",
        "source_inputs_sha256", "unclassified_site_count",
    }
    if set(manifest) != expected_keys:
        raise ReadinessError("RESOURCE_CLASSIFICATION_KEYS", manifest_path)
    scalar_expected = {
        "schema_version": 47,
        "manifest_id": schema_id,
        "profile_id": profile_id,
        "discovery_profile_id": resource_discovery["profile_id"],
        "coverage_status": "INCOMPLETE",
        "generation_disposition": "DENY",
        "classification_schema_raw_sha256": (
            RESOURCE_CLASSIFICATION_V47_SCHEMA_RAW_SHA256
        ),
        "predecessor_manifest": dict(
            RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST
        ),
        "predecessor_schema": dict(
            RESOURCE_CLASSIFICATION_V47_PREDECESSOR_SCHEMA
        ),
        "source_input_count": 10,
        "source_inputs_sha256": _domain_digest(
            RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
        ),
        "source_bound_site_count": len(resource_discovery["source_bound_sites"]),
        "source_bound_sites_sha256": resource_discovery[
            "source_bound_sites_sha256"
        ],
        "schema_bound_site_count": len(resource_discovery["schema_bound_sites"]),
        "schema_bound_sites_sha256": resource_discovery[
            "schema_bound_sites_sha256"
        ],
        "schema_inputs_sha256": resource_discovery["schema_inputs_sha256"],
        "classified_site_count": 73,
        "unclassified_site_count": (
            len(resource_discovery["source_bound_sites"])
            + len(resource_discovery["schema_bound_sites"])
            - 73
        ),
    }
    for key, expected in scalar_expected.items():
        if type(manifest.get(key)) is not type(expected) or manifest.get(key) != expected:
            raise ReadinessError("RESOURCE_CLASSIFICATION_BINDING", key)

    constraints = manifest.get("constraints")
    if type(constraints) is not list or len(constraints) != 40:
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINTS", manifest_path)
    single_binding_constraint_keys = {
        "accepted_equation", "classification", "constraint_id",
        "definition_site_ids", "enforcement_site_ids", "evidence_inputs",
        "maximum", "semantic_function_ast_sha256", "semantic_module_ast_sha256",
        "semantic_proof", "semantic_subject", "unit",
    }
    multi_binding_constraint_keys = {
        "accepted_equation", "classification", "constraint_id",
        "definition_site_ids", "enforcement_site_ids", "evidence_inputs",
        "maximum", "semantic_bindings", "semantic_subject", "unit",
    }
    schema_constraint_keys = {
        "addressed_site", "classification", "constraint_id",
        "declarative_equation", "evidence_inputs", "proof_kind",
        "schema_context", "schema_site_id", "semantic_subject", "unit",
    }
    if any(type(item) is not dict for item in constraints) or any(
        set(item) != (
            multi_binding_constraint_keys
            if "semantic_bindings" in item else single_binding_constraint_keys
        )
        for item in constraints[:-2]
    ) or any(set(item) != schema_constraint_keys for item in constraints[-2:]):
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINT_KEYS", manifest_path)
    def load_selected_schema_proof(expected: dict[str, Any]) -> dict[str, Any]:
        proof_raw, proof_identity = _audit_path(root, expected["path"])
        if proof_identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", expected["path"])
        identities.add(proof_identity)
        if len(proof_raw) != expected["byte_length"] or _sha256(
            proof_raw
        ) != expected["raw_sha256"]:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_SELECTED_PROOF_IDENTITY", expected["path"]
            )
        proof = _parse_json(proof_raw, expected["path"])
        if type(proof) is not dict:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_SELECTED_PROOF_OBJECT", expected["path"]
            )
        return proof

    predecessor_schema_proof = load_selected_schema_proof(
        RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF
    )
    selected_proof = load_selected_schema_proof(
        RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF
    )
    expected_constraints = [
        {
            "accepted_equation": (
                "for each exact BlobRecord in runtime_image.blobs: "
                "len(captured canonical_json bytes) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_BLOB_BYTES",
            "definition_site_ids": [
                "a1c0d45cbce3ceffdaeb036a93474801b525220e1d16ab5505dba14115313caa"
            ],
            "enforcement_site_ids": [
                "1ef42fea7eca273c2040d72810435052d0241a4e9a4d7ba63598548d95d5249c"
            ],
            "evidence_inputs": [dict(item) for item in BLOB_RESOURCE_EVIDENCE],
            "maximum": 16_777_216,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "VALID_CARDINALITY_EXACT_BLOB_RECORD_CAPTURED_BYTES_FIELD"
                ),
                "enforcement_order": (
                    "CARDINALITY_RECORD_AND_FIELD_TYPE_GUARDS_BEFORE_SIZE_GUARD"
                ),
                "rejection_action": (
                    "ADD_IMAGE_ITEM_BYTE_LIMIT_FINDING_AND_WITHHOLD_IMAGE"
                ),
            },
            "semantic_subject": "SUPPLIED_BLOB_RECORD_CANONICAL_JSON_FIELD_BYTES",
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "len(raw_dependency_closure_bytes) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_DEPENDENCY_CLOSURE_BYTES",
            "definition_site_ids": [
                "f0929588df702f47d6a2f6fe255d87b6bf4a0e083cbfdbb0cc0f699973edc2ab"
            ],
            "enforcement_site_ids": [
                "344950b527bcecb073b777c4bbf743de50dd920bd4aa76dbbf58045ff9f00ab5"
            ],
            "evidence_inputs": [dict(item) for item in CLOSURE_RESOURCE_EVIDENCE],
            "maximum": 1_048_576,
            "semantic_function_ast_sha256": (
                "9c9e9b785430028f44d93df883e0b7edd52b777546b8811b732fdf2b99bc0e30"
            ),
            "semantic_module_ast_sha256": (
                "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_closure.py:"
                    "validate_verifier_dependency_closure"
                ),
                "input_binding": "UNMODIFIED_EXACT_BYTES_FUNCTION_ARGUMENT",
                "enforcement_order": "TYPE_GUARD_BEFORE_SIZE_GUARD_BEFORE_PARSE",
                "rejection_action": "RAISE_BYTE_LIMIT",
            },
            "semantic_subject": "RAW_DEPENDENCY_CLOSURE_BYTES",
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "for each exact built-in bytes member reached after events "
                "tuple and cardinality validation: len(supplied event member "
                "bytes) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_EVENT_BYTES",
            "definition_site_ids": [
                "7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a"
            ],
            "enforcement_site_ids": [
                "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534"
            ],
            "evidence_inputs": [
                dict(item) for item in EVENT_BYTE_RESOURCE_EVIDENCE
            ],
            "maximum": 1_048_576,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_BUILTIN_BYTES_MEMBERS_AFTER_EVENTS_TUPLE_AND_"
                    "CARDINALITY_VALIDATION"
                ),
                "enforcement_order": (
                    "TOP_LEVEL_CAPTURE_THEN_TUPLE_TYPE_THEN_CARDINALITY_"
                    "THEN_MEMBER_TYPE_THEN_ACCOUNTING_THEN_SIZE_GUARD"
                ),
                "rejection_action": (
                    "ADD_IMAGE_ITEM_BYTE_LIMIT_FOR_EVENTS_INDEX_AND_WITHHOLD_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_BYTES_MEMBERS_OF_CAPTURED_RUNTIME_IMAGE_EVENTS"
            ),
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "for each exact supplied schema-document record admitted to "
                "host preflight or verifier bundle inspection: "
                "len(supplied canonical_json field bytes) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_SCHEMA_DOCUMENT_BYTES",
            "definition_site_ids": [
                "fa0e657aa776634a22b750a8fce2c4ed1ff0de61ff58841530de76225f9e8630",
                "e5ebe2c841739dfbb79d7fb7c04879320c9d4b5313534822b1e3696798afc40d",
            ],
            "enforcement_site_ids": [
                "9c9756b7f77e91caf4044c0cb19c52dc2d0335a749fc7690e00ddd6a9a1b6b38",
                "222b398c640f6311f8597b487de626c2dfb65f4340a6fb1ece58292788c9b8d3",
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_DOCUMENT_RESOURCE_EVIDENCE
            ],
            "maximum": 262_144,
            "semantic_bindings": [
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                    ),
                    "semantic_function_ast_sha256": (
                        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
                    ),
                    "module_path": "src/edgelab/runtime_v2_image.py",
                    "semantic_module_ast_sha256": (
                        "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
                    ),
                    "input_binding": (
                        "VALID_CARDINALITY_EXACT_SCHEMA_DOCUMENT_RECORD_"
                        "CAPTURED_BYTES_FIELD"
                    ),
                    "enforcement_order": (
                        "CARDINALITY_RECORD_AND_FIELD_TYPE_GUARDS_BEFORE_SIZE_GUARD"
                    ),
                    "rejection_action": (
                        "ADD_IMAGE_ITEM_BYTE_LIMIT_FINDING_AND_WITHHOLD_IMAGE"
                    ),
                },
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_verifier.py:_schema_bundle_findings"
                    ),
                    "semantic_function_ast_sha256": (
                        "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e"
                    ),
                    "module_path": "src/edgelab/runtime_v2_verifier.py",
                    "semantic_module_ast_sha256": (
                        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
                    ),
                    "input_binding": (
                        "EXACT_SCHEMA_DOCUMENT_RECORD_CANONICAL_JSON_BYTES_FIELD"
                    ),
                    "enforcement_order": (
                        "RECORD_AND_FIELD_TYPE_GUARDS_BEFORE_SIZE_GUARD_BEFORE_PARSE"
                    ),
                    "rejection_action": (
                        "ADD_SCHEMA_DOCUMENT_TOO_LARGE_AND_RETURN_INVALID_DENY"
                    ),
                },
            ],
            "semantic_subject": (
                "SUPPLIED_SCHEMA_DOCUMENT_CANONICAL_JSON_FIELD_BYTES"
            ),
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "when graph-cardinality evaluation is reached before "
                "diagnostic-budget exhaustion: len(valid root $defs owner "
                "keys in edges) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_SCHEMA_REF_NODES",
            "definition_site_ids": [
                "61d3dcc5d5ed733e6d561edeb43ddcc00ab2aa8fc899b09353733877ea76a721"
            ],
            "enforcement_site_ids": [
                "4650c76c2ae3e065cd5767e97b8a59d917415ba1dfc73f79f0efd8b09f4f3eef"
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_REF_NODE_RESOURCE_EVIDENCE
            ],
            "maximum": 4_096,
            "semantic_function_ast_sha256": (
                "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d"
            ),
            "semantic_module_ast_sha256": (
                "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_verifier.py:_schema_safety_findings"
                ),
                "input_binding": "VALID_ROOT_SCHEMA_DEFINITION_OWNER_KEYS_IN_EDGES",
                "enforcement_order": (
                    "SCHEMA_WALK_AND_DEFINITION_NAME_VALIDATION_BEFORE_NODE_"
                    "GUARD_BEFORE_CYCLE_TRAVERSAL"
                ),
                "rejection_action": (
                    "ADD_SCHEMA_REF_GRAPH_TOO_LARGE_AND_RETURN_INVALID_DENY_"
                    "BEFORE_CYCLE_TRAVERSAL"
                ),
            },
            "semantic_subject": (
                "VALID_ROOT_SCHEMA_DEFINITION_OWNER_KEYS_ADMITTED_TO_CYCLE_"
                "TRAVERSAL"
            ),
            "unit": "NODES",
        },
        {
            "accepted_equation": (
                "for each exact supplied built-in bytes RuntimeImage."
                "schema_registry field admitted to host preflight or verifier "
                "bundle inspection: len(supplied schema_registry bytes) <= "
                "maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_SCHEMA_REGISTRY_BYTES",
            "definition_site_ids": [
                "4c9346726487e13663e822fd8b63e995c6066a487dfbe2b6350e051ce2440384",
                "cc9e6904b1fdb98deea9fd35ddc4ae864aa572cbf5d963addbf8cc42beae4522",
            ],
            "enforcement_site_ids": [
                "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4",
                "d02eb8dbac3f0359f160e1fb6259b5a438ec699a64cca7cd05d94c5ab86b1683",
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_REGISTRY_RESOURCE_EVIDENCE
            ],
            "maximum": 262_144,
            "semantic_bindings": [
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                    ),
                    "semantic_function_ast_sha256": (
                        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
                    ),
                    "module_path": "src/edgelab/runtime_v2_image.py",
                    "semantic_module_ast_sha256": (
                        "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
                    ),
                    "input_binding": (
                        "EXACT_CAPTURED_SCHEMA_REGISTRY_BYTES_AFTER_RUNTIME_"
                        "IMAGE_FIELD_CAPTURE"
                    ),
                    "enforcement_order": (
                        "FIELD_CAPTURE_AND_EXACT_BYTES_TYPE_GUARD_BEFORE_"
                        "ACCOUNTING_BEFORE_SIZE_GUARD"
                    ),
                    "rejection_action": (
                        "ADD_IMAGE_ITEM_BYTE_LIMIT_FOR_SCHEMA_REGISTRY_AND_"
                        "WITHHOLD_IMAGE"
                    ),
                },
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_verifier.py:_schema_bundle_findings"
                    ),
                    "semantic_function_ast_sha256": (
                        "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e"
                    ),
                    "module_path": "src/edgelab/runtime_v2_verifier.py",
                    "semantic_module_ast_sha256": (
                        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
                    ),
                    "input_binding": (
                        "NONEMPTY_EXACT_SCHEMA_REGISTRY_BYTES_WITH_PRESENT_"
                        "SCHEMA_DOCUMENTS"
                    ),
                    "enforcement_order": (
                        "REGISTRY_AND_DOCUMENT_PRESENCE_GUARDS_BEFORE_SIZE_"
                        "GUARD_BEFORE_INVENTORY_ACCOUNTING_AND_PARSE"
                    ),
                    "rejection_action": (
                        "ADD_SCHEMA_REGISTRY_TOO_LARGE_AND_RETURN_INVALID_"
                        "DENY_BEFORE_DOCUMENT_TRAVERSAL"
                    ),
                },
            ],
            "semantic_subject": (
                "EXACT_BUILTIN_BYTES_SCHEMA_REGISTRY_FIELDS_SUPPLIED_TO_HOST_"
                "PREFLIGHT_OR_VERIFIER_BUNDLE_INSPECTION"
            ),
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "for each exact built-in bytes RuntimeImage."
                "verifier_dependency_closure, RuntimeImage.manifest, or "
                "RuntimeImage.attachment field, and for each exact built-in "
                "bytes member reached after tuple and cardinality validation "
                "in RuntimeImage.checkpoint_copies or RuntimeImage."
                "selector_history: len(supplied field or member bytes) <= "
                "maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "definition_site_ids": [
                "8927485f8c04590dc06fa8d3bffde6e82517d898ec72637dbf758e21a56996d8"
            ],
            "enforcement_site_ids": [
                "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c",
                "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6",
                "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc",
                "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275",
                "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99",
            ],
            "evidence_inputs": [
                dict(item) for item in BOOTSTRAP_DOCUMENT_RESOURCE_EVIDENCE
            ],
            "maximum": 1_048_576,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_CAPTURED_BOOTSTRAP_FIELD_BYTES_OR_EXACT_"
                    "COLLECTION_MEMBER_BYTES_AFTER_TUPLE_AND_CARDINALITY_"
                    "VALIDATION"
                ),
                "enforcement_order": (
                    "COMPLETE_FIELD_CAPTURE_BEFORE_EXACT_SCALAR_TYPE_AND_"
                    "ACCOUNTING_OR_EXACT_TUPLE_TYPE_CARDINALITY_MEMBER_TYPE_"
                    "AND_ACCOUNTING_BEFORE_SIZE_GUARD"
                ),
                "rejection_action": (
                    "ADD_IMAGE_ITEM_BYTE_LIMIT_FOR_EXACT_ARTIFACT_AND_"
                    "COORDINATE_AND_WITHHOLD_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_BYTES_BOOTSTRAP_FIELDS_OR_COLLECTION_MEMBERS_"
                "ADMITTED_BY_HOST_PREFLIGHT"
            ),
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "for each TransitionIntent construction input reaching the "
                "argument-cardinality guard: len(exact built-in tuple "
                "arguments) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_ARGUMENTS",
            "definition_site_ids": [
                "5e7fc3b44c63b42e94213efd280dd3af90eac0beb4a2b28f600a5284f17fc3b4"
            ],
            "enforcement_site_ids": [
                "3d85d6c3d9c53b2d68ee976d4b159cc92ae9fd506ad608d00ff0563db5864209"
            ],
            "evidence_inputs": [
                dict(item) for item in TRANSITION_ARGUMENT_RESOURCE_EVIDENCE
            ],
            "maximum": 8,
            "semantic_function_ast_sha256": (
                "42b1b9103cffdc52d38f4033e71b4b750b334305b3c952d7ac7b86843bec58f7"
            ),
            "semantic_module_ast_sha256": (
                "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b"
            ),
            "semantic_proof": {
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
                    "RAISE_TRANSITION_RESOURCE_ARGUMENTS_AT_ARGUMENTS_"
                    "COORDINATE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ARGUMENT_ITEMS_SUPPLIED_TO_TRANSITION_"
                "INTENT_CONSTRUCTION"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for each exact built-in str path admitted by _PATH: "
                "len(path) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "_PORTABLE_PATH_MAX",
            "definition_site_ids": [
                "fc3a2cf8ca0ab37c1fedcfb108152b40bd65fec0207eac9cd9b3f7f32b8cfd27"
            ],
            "enforcement_site_ids": [
                "ab8d61b1084c8ac24f8b434b52065e9fc3c5dce60285fed332f3489d165b03d3"
            ],
            "evidence_inputs": [
                dict(item) for item in PORTABLE_PATH_RESOURCE_EVIDENCE
            ],
            "maximum": 4_096,
            "semantic_function_ast_sha256": (
                "d4bcf6527c507a9e580c563f57cc1d2f79b3caa8a205b0fc6fdf2c7f5cc2d806"
            ),
            "semantic_module_ast_sha256": (
                "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7"
            ),
            "semantic_proof": {
                "function_coordinate": "src/edgelab/runtime_v2_closure.py:_path",
                "input_binding": (
                    "EXACT_BUILTIN_STR_RETURNED_BY_PATH_PATTERN_VALIDATION"
                ),
                "enforcement_order": (
                    "EXACT_STR_AND_PATH_PATTERN_VALIDATION_BEFORE_SPLIT_BEFORE_"
                    "TOTAL_PATH_COMPARISON_AS_FIRST_SHORT_CIRCUIT_ARM_BEFORE_"
                    "COMPONENT_AND_PORTABILITY_CHECKS"
                ),
                "rejection_action": "RAISE_PATH_LENGTH_AT_CALLER_COORDINATE",
            },
            "semantic_subject": (
                "EXACT_BUILTIN_STR_PORTABLE_RELATIVE_PATH_ARGUMENT_AFTER_"
                "PATH_PATTERN_VALIDATION"
            ),
            "unit": "CHARACTERS",
        },
        {
            "accepted_equation": (
                "for each exact built-in str path admitted by _PATH and the "
                "total-path maximum: all(len(component) <= maximum for "
                "component in path.split(\"/\"))"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "_PORTABLE_COMPONENT_MAX",
            "definition_site_ids": [
                "9313b4636313fad249f6a01b9e4ef96f22ef88b10fa98ca95a736d0ce994c3df"
            ],
            "enforcement_site_ids": [
                "80d3960b21e42ebc549ca5eabd07e811430b1628150d9eb1e8922d491dc86072"
            ],
            "evidence_inputs": [
                dict(item) for item in PORTABLE_COMPONENT_RESOURCE_EVIDENCE
            ],
            "maximum": 255,
            "semantic_function_ast_sha256": (
                "d4bcf6527c507a9e580c563f57cc1d2f79b3caa8a205b0fc6fdf2c7f5cc2d806"
            ),
            "semantic_module_ast_sha256": (
                "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7"
            ),
            "semantic_proof": {
                "function_coordinate": "src/edgelab/runtime_v2_closure.py:_path",
                "input_binding": (
                    "EXACT_BUILTIN_STR_COMPONENTS_PRODUCED_BY_SLASH_SPLIT_"
                    "AND_INSPECTED_AFTER_TOTAL_PATH_ADMISSION"
                ),
                "enforcement_order": (
                    "EXACT_STR_AND_PATH_PATTERN_VALIDATION_BEFORE_SLASH_SPLIT_"
                    "BEFORE_TOTAL_PATH_COMPARISON_AS_FIRST_SHORT_CIRCUIT_ARM_"
                    "BEFORE_COMPONENT_ANY_GENERATOR_BEFORE_PORTABILITY_CHECKS"
                ),
                "rejection_action": "RAISE_PATH_LENGTH_AT_CALLER_COORDINATE",
            },
            "semantic_subject": (
                "EXACT_SLASH_SEPARATED_COMPONENT_STRINGS_OF_EXACT_BUILTIN_"
                "STR_PATH_AFTER_PATH_PATTERN_AND_TOTAL_PATH_ADMISSION"
            ),
            "unit": "CHARACTERS",
        },
        {
            "accepted_equation": (
                "for each TransitionIntent construction input reaching the "
                "semantic-event-cardinality guard: len(exact built-in tuple "
                "semantic_event_ids) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_GROUP_EVENTS",
            "definition_site_ids": [
                "13130db6d96d447bd0bec45528c39f4354a2897e282585c7b4976335e25b025c"
            ],
            "enforcement_site_ids": [
                "6109c0c4afb317c7bde39b19501f7de6b627528dd36f967c82e2ed311fbfc0ca"
            ],
            "evidence_inputs": [
                dict(item) for item in TRANSITION_SEMANTIC_EVENT_RESOURCE_EVIDENCE
            ],
            "maximum": 10_002,
            "semantic_function_ast_sha256": (
                "42b1b9103cffdc52d38f4033e71b4b750b334305b3c952d7ac7b86843bec58f7"
            ),
            "semantic_module_ast_sha256": (
                "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_transition.py:"
                    "TransitionIntent.__post_init__"
                ),
                "input_binding": (
                    "EXACT_BUILTIN_TUPLE_SEMANTIC_EVENT_IDS_FIELD_AFTER_"
                    "JOINT_CONTAINER_AND_ARGUMENT_CARDINALITY_GUARDS"
                ),
                "enforcement_order": (
                    "OPERATION_EXACT_STR_GUARD_BEFORE_JOINT_ARGUMENTS_AND_"
                    "SEMANTIC_EVENT_IDS_EXACT_TUPLE_GUARD_BEFORE_ARGUMENT_"
                    "CARDINALITY_GUARD_BEFORE_SEMANTIC_EVENT_CARDINALITY_"
                    "GUARD_BEFORE_ARGUMENT_SHAPE_ORDER_AND_UUID_MEMBER_"
                    "VALIDATION"
                ),
                "rejection_action": (
                    "RAISE_TRANSITION_RESOURCE_EVENTS_AT_SEMANTIC_EVENT_IDS_"
                    "COORDINATE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_SEMANTIC_EVENT_ID_ITEMS_SUPPLIED_TO_"
                "TRANSITION_INTENT_CONSTRUCTION"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for each ReducerState construction reaching the task-"
                "cardinality guard and each transition-workspace precheck "
                "reaching the prospective task-cardinality guard: len(exact "
                "built-in tuple tasks) <= maximum and len(current workspace "
                "task keys) + count(validated task writes whose current key "
                "is absent) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_TASKS",
            "definition_site_ids": [
                "2663812aee226be4f57a1862523798243d7df5a12a1d9e29f586ec8e7ded5638"
            ],
            "enforcement_site_ids": [
                "3d07b02992a995d0a13d408dda7d2acf04e1c5a9d185f98651814d6dfff2b59d",
                "0f3792a9755d878d6e5a60afd21ef8e1d38c30f3be3d59879b6cfa860754f465",
            ],
            "evidence_inputs": [
                dict(item) for item in TRANSITION_TASK_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_bindings": [
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_transition.py:"
                        "ReducerState.__post_init__"
                    ),
                    "semantic_function_ast_sha256": (
                        "acfc468a2815e245ee3da5230df49c20e8dc1f2601fa24b367507e77d847a337"
                    ),
                    "module_path": "src/edgelab/runtime_v2_transition.py",
                    "semantic_module_ast_sha256": (
                        "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b"
                    ),
                    "input_binding": (
                        "EXACT_BUILTIN_TUPLE_TASKS_FIELD_AFTER_ALL_REDUCER_"
                        "STATE_COLLECTION_CONTAINER_GUARDS"
                    ),
                    "enforcement_order": (
                        "REPOSITORY_SCALAR_GUARDS_BEFORE_ALL_COLLECTION_EXACT_"
                        "TUPLE_GUARDS_BEFORE_TASK_CARDINALITY_GUARD_BEFORE_"
                        "OTHER_RECORD_CARDINALITY_MEMBER_ORDER_UNIQUENESS_"
                        "AND_CROSS_RECORD_VALIDATION"
                    ),
                    "rejection_action": (
                        "RAISE_TRANSITION_RESOURCE_TASKS_AT_TASKS_COORDINATE"
                    ),
                },
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_transition.py:"
                        "_TransitionWorkspace._precheck"
                    ),
                    "semantic_function_ast_sha256": (
                        "280ca713360ad0b61cd3810999f6d0cf1ea4e31b854596bbaedb4ad03c8b12b1"
                    ),
                    "module_path": "src/edgelab/runtime_v2_transition.py",
                    "semantic_module_ast_sha256": (
                        "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b"
                    ),
                    "input_binding": (
                        "CURRENT_WORKSPACE_TASK_KEY_MAPPING_PLUS_VALIDATED_"
                        "ABSENT_KEY_TASK_WRITES"
                    ),
                    "enforcement_order": (
                        "EXACT_DELTA_AND_SORTED_UNIQUE_KEY_SET_GUARDS_BEFORE_"
                        "EXACT_TASK_WRITE_SHAPE_AND_CAS_VALIDATION_BEFORE_"
                        "ABSENT_KEY_COUNT_DERIVATION_BEFORE_PROSPECTIVE_TASK_"
                        "CARDINALITY_GUARD_BEFORE_AUXILIARY_RESOURCE_EVENT_"
                        "REUSE_AND_AFTER_TASK_CHECKS"
                    ),
                    "rejection_action": (
                        "RAISE_TRANSITION_RESOURCE_TASKS_AT_TASKS_COORDINATE_"
                        "WITHOUT_WORKSPACE_MUTATION"
                    ),
                },
            ],
            "semantic_subject": (
                "REDUCER_STATE_EXACT_BUILTIN_TUPLE_TASK_ITEMS_OR_TRANSITION_"
                "WORKSPACE_RETAINED_TASK_KEYS_PLUS_VALIDATED_ABSENT_KEY_WRITES"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for host preflight and verifier schema-bundle inspection: "
                "len(exact built-in bytes schema_registry when admitted) + "
                "sum(len(exact built-in bytes canonical_json body) for each "
                "admitted exact SchemaDocumentRecord) <= maximum; separately "
                "at the public verifier descriptor branch: len(exact built-in "
                "bytes storage_descriptor) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_SCHEMA_BUNDLE_BYTES",
            "definition_site_ids": [
                "18d9f6c7a27e97c092460277fc35bbf9151791127dd0da5a161a8866ef04bbcf",
                "2d673fb49e50239b37577ac23e4f6fdbf899523908d338e3618993594ab5f410",
            ],
            "enforcement_site_ids": [
                "4a75bf21a088cd48d5c1b38b2b3157fc47542b0132b562be3699e94858a65c9e",
                "344713dc75b24db9402649b88570c54a438e5b3b9f17dac677b8cd4313825df4",
                "4ba11eee3bbe1d3fa772fabebf0edc386903f94c9862c242c7124b8bf0cf6cb6",
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_BUNDLE_RESOURCE_EVIDENCE
            ],
            "maximum": 2_097_152,
            "semantic_bindings": [
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                    ),
                    "semantic_function_ast_sha256": (
                        "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
                    ),
                    "module_path": "src/edgelab/runtime_v2_image.py",
                    "semantic_module_ast_sha256": (
                        "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
                    ),
                    "input_binding": (
                        "EXACT_CAPTURED_SCHEMA_REGISTRY_BYTES_OR_ZERO_PLUS_"
                        "EXACT_BYTES_BODIES_OF_ADMITTED_EXACT_SCHEMA_DOCUMENT_"
                        "RECORDS"
                    ),
                    "enforcement_order": (
                        "FIELD_CAPTURE_AND_SCHEMA_DOCUMENT_TUPLE_CARDINALITY_"
                        "BEFORE_REGISTRY_EXACT_TYPE_INITIALIZATION_BEFORE_"
                        "RECORD_AND_BODY_EXACT_TYPE_GUARDS_BEFORE_PER_BODY_"
                        "ADDITION_BEFORE_AGGREGATE_COMPARISON"
                    ),
                    "rejection_action": (
                        "ADD_SCHEMA_BUNDLE_BYTE_LIMIT_AND_WITHHOLD_IMAGE"
                    ),
                },
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_verifier.py:_schema_bundle_findings"
                    ),
                    "semantic_function_ast_sha256": (
                        "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e"
                    ),
                    "module_path": "src/edgelab/runtime_v2_verifier.py",
                    "semantic_module_ast_sha256": (
                        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
                    ),
                    "input_binding": (
                        "NONEMPTY_EXACT_SCHEMA_REGISTRY_BYTES_PLUS_EXACT_"
                        "BYTES_BODIES_OF_EXACT_SCHEMA_DOCUMENT_RECORDS_AFTER_"
                        "PRESENCE_REGISTRY_SIZE_AND_EXACT_INVENTORY_GUARDS"
                    ),
                    "enforcement_order": (
                        "BUNDLE_PRESENCE_REGISTRY_SIZE_AND_EXACT_DOCUMENT_"
                        "COUNT_GUARDS_BEFORE_REGISTRY_INITIALIZATION_BEFORE_"
                        "RECORD_AND_BODY_EXACT_TYPE_GUARDS_BEFORE_BODY_"
                        "ADDITION_BEFORE_AGGREGATE_COMPARISON_BEFORE_PARSE"
                    ),
                    "rejection_action": (
                        "ADD_SCHEMA_BUNDLE_TOO_LARGE_AND_RETURN_INVALID_DENY"
                    ),
                },
                {
                    "function_coordinate": (
                        "src/edgelab/runtime_v2_verifier.py:verify_runtime_image"
                    ),
                    "semantic_function_ast_sha256": (
                        "1742c7e8785c03ddfb26fbc3c1eb695c0daa79aa355eb77dae6b8350a373502c"
                    ),
                    "module_path": "src/edgelab/runtime_v2_verifier.py",
                    "semantic_module_ast_sha256": (
                        "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
                    ),
                    "input_binding": (
                        "EXACT_BUILTIN_BYTES_STORAGE_DESCRIPTOR_FIELD"
                    ),
                    "enforcement_order": (
                        "RUNTIME_IMAGE_AND_DESCRIPTOR_EXACT_TYPE_GUARDS_BEFORE_"
                        "DESCRIPTOR_SIZE_COMPARISON_BEFORE_CANONICAL_PARSE"
                    ),
                    "rejection_action": (
                        "ADD_DESCRIPTOR_TOO_LARGE_AND_RETURN_INVALID_DENY_"
                        "WITHOUT_DESCRIPTOR_PARSE"
                    ),
                },
            ],
            "semantic_subject": (
                "SCHEMA_REGISTRY_AND_ADMITTED_SCHEMA_DOCUMENT_BODY_BYTE_"
                "AGGREGATE_OR_SEPARATE_RAW_STORAGE_DESCRIPTOR_BYTES"
            ),
            "unit": "BYTES",
        },
        {
            "accepted_equation": (
                "for each exact RuntimeImage input reaching the checkpoint-copy "
                "cardinality guard: 0 <= len(exact built-in tuple "
                "checkpoint_copies) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_CHECKPOINT_COPIES",
            "definition_site_ids": [
                "4c738024dfcbda75cf4c6a621c2b51624a9278bb5b4e10b912c43f1dbd5be208"
            ],
            "enforcement_site_ids": [
                "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13"
            ],
            "evidence_inputs": [
                dict(item) for item in CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE
            ],
            "maximum": 49_999,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "COMPLETE_TOP_LEVEL_CAPTURED_CHECKPOINT_COPIES_VALUE_AFTER_"
                    "EXACT_RUNTIME_IMAGE_AND_EXACT_BUILTIN_TUPLE_GUARDS"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_TYPE_THEN_COMPLETE_SLOT_CAPTURE_THEN_"
                    "ALL_TUPLE_FIELD_TYPE_GUARDS_THEN_CHECKPOINT_COPIES_BRANCH_"
                    "CARDINALITY_BEFORE_MEMBER_TYPE_BYTE_ACCOUNTING_AND_SIZE_CHECKS"
                ),
                "rejection_action": (
                    "ADD_IMAGE_CARDINALITY_LIMIT_FOR_CHECKPOINT_COPIES_AT_ROOT_"
                    "SET_ACCOUNTING_INCOMPLETE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_RUNTIME_IMAGE_"
                "CHECKPOINT_COPIES"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for each exact RuntimeImage input reaching the top-level blob "
                "cardinality guard: 0 <= len(exact built-in tuple blobs) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "MAX_BLOBS",
            "definition_site_ids": [
                "d59dabf071e0d9cce0c5d6e1478ce6aa55a09362b85136709a4df94bf19966e0"
            ],
            "enforcement_site_ids": [
                "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3"
            ],
            "evidence_inputs": [
                dict(item) for item in BLOB_CARDINALITY_RESOURCE_EVIDENCE
            ],
            "maximum": 300_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "COMPLETE_TOP_LEVEL_CAPTURED_BLOBS_VALUE_AFTER_EXACT_"
                    "RUNTIME_IMAGE_AND_EXACT_BUILTIN_TUPLE_GUARDS"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_TYPE_THEN_COMPLETE_SLOT_CAPTURE_THEN_"
                    "ALL_TUPLE_FIELD_TYPE_GUARDS_THEN_BLOBS_BRANCH_CARDINALITY_"
                    "BEFORE_RECORD_FIELD_BYTE_ACCOUNTING_SIZE_AND_RECONSTRUCTION_CHECKS"
                ),
                "rejection_action": (
                    "ADD_IMAGE_CARDINALITY_LIMIT_FOR_BLOBS_AT_ROOT_SET_"
                    "ACCOUNTING_INCOMPLETE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_RUNTIME_IMAGE_BLOBS"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[7] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][7].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_MIGRATIONS_ROWS",
            "definition_site_ids": [
                "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a"
            ],
            "enforcement_site_ids": [
                "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a"
            ],
            "evidence_inputs": [
                dict(item) for item in MIGRATIONS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 0,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_7_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_7_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_ZERO_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_7_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_7_MIGRATIONS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[5] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][5].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_LEGACY_ARCHIVE_ROWS",
            "definition_site_ids": [
                "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18"
            ],
            "enforcement_site_ids": [
                "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18"
            ],
            "evidence_inputs": [
                dict(item) for item in LEGACY_ARCHIVE_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 1,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_5_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_5_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_5_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_5_LEGACY_ARCHIVE_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[6] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][6].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_METADATA_ROWS",
            "definition_site_ids": [
                "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"
            ],
            "enforcement_site_ids": [
                "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"
            ],
            "evidence_inputs": [
                dict(item) for item in METADATA_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 1,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_6_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_6_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_6_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_6_METADATA_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[11] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][11].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_SCHEMA_REGISTRY_ROWS",
            "definition_site_ids": [
                "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793"
            ],
            "enforcement_site_ids": [
                "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793"
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_REGISTRY_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 1,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_11_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_11_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_11_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_11_SCHEMA_REGISTRY_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[12] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][12].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_SEALS_ROWS",
            "definition_site_ids": [
                "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b"
            ],
            "enforcement_site_ids": [
                "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b"
            ],
            "evidence_inputs": [
                dict(item) for item in SEALS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 1,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_12_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_12_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_12_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_12_SEALS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[10] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][10].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_SCHEMA_DOCUMENTS_ROWS",
            "definition_site_ids": [
                "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2"
            ],
            "enforcement_site_ids": [
                "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2"
            ],
            "evidence_inputs": [
                dict(item) for item in SCHEMA_DOCUMENTS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 9,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_10_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_10_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_NINE_ROW_"
                    "COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_10_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_10_SCHEMA_DOCUMENTS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[0] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][0].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_ATTEMPTS_ROWS",
            "definition_site_ids": [
                "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990"
            ],
            "enforcement_site_ids": [
                "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990"
            ],
            "evidence_inputs": [
                dict(item) for item in ATTEMPTS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_0_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_0_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_0_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_0_ATTEMPTS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[2] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][2].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_CLAIMS_ROWS",
            "definition_site_ids": [
                "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737"
            ],
            "enforcement_site_ids": [
                "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737"
            ],
            "evidence_inputs": [
                dict(item) for item in CLAIMS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_2_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_2_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_2_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_2_CLAIMS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[1] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][1].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_BLOBS_ROWS",
            "definition_site_ids": [
                "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428"
            ],
            "enforcement_site_ids": [
                "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428"
            ],
            "evidence_inputs": [
                dict(item) for item in BLOBS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 300_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_1_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_1_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_THREE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_1_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_1_BLOBS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[3] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][3].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_EVENTS_ROWS",
            "definition_site_ids": [
                "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed"
            ],
            "enforcement_site_ids": [
                "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed"
            ],
            "evidence_inputs": [
                dict(item) for item in EVENTS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_3_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_3_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_3_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_3_EVENTS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[4] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][4].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_IDEMPOTENCY_ROWS",
            "definition_site_ids": [
                "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72"
            ],
            "enforcement_site_ids": [
                "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72"
            ],
            "evidence_inputs": [
                dict(item) for item in IDEMPOTENCY_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_4_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_4_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_4_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_4_IDEMPOTENCY_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[8] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][8].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_REMEDIATION_LINKS_ROWS",
            "definition_site_ids": [
                "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a"
            ],
            "enforcement_site_ids": [
                "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a"
            ],
            "evidence_inputs": [
                dict(item) for item in REMEDIATION_LINKS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_POSITION_8_"
                    "NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_8_THEN_"
                    "EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_NON_"
                    "BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_MATCH_"
                    "THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_THOUSAND_"
                    "ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_VALIDATION_OR_"
                    "ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_8_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_8_REMEDIATION_LINKS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[13] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][13].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_SNAPSHOTS_ROWS",
            "definition_site_ids": [
                "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b"
            ],
            "enforcement_site_ids": [
                "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b"
            ],
            "evidence_inputs": [
                dict(item) for item in SNAPSHOTS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_"
                    "POSITION_13_NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_13_"
                    "THEN_EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_"
                    "NON_BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_"
                    "MATCH_THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_"
                    "THOUSAND_ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_"
                    "VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_13_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_13_SNAPSHOTS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[9] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][9].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_REVIEWS_ROWS",
            "definition_site_ids": [
                "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0"
            ],
            "enforcement_site_ids": [
                "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0"
            ],
            "evidence_inputs": [
                dict(item) for item in REVIEWS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_"
                    "POSITION_9_NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_9_"
                    "THEN_EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_"
                    "NON_BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_"
                    "MATCH_THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_"
                    "THOUSAND_ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_"
                    "VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_9_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_9_REVIEWS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "for the exact table snapshot paired by strict positional zip "
                "with _TABLE_SPECS[14] after exact table-snapshot cardinality, "
                "snapshot and field-presence guards, the non-blocking table-"
                "identity diagnostic regardless of label match, and the rows-"
                "tuple guard: "
                "len(captured['table_snapshots'][14].rows) <= maximum"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "TABLE_TASKS_ROWS",
            "definition_site_ids": [
                "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b"
            ],
            "enforcement_site_ids": [
                "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b"
            ],
            "evidence_inputs": [
                dict(item) for item in TASKS_TABLE_ROW_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_ROWS_TUPLE_OF_TABLE_SNAPSHOT_AT_STRICT_ZIP_"
                    "POSITION_14_NOT_SELECTED_BY_SUPPLIED_TABLE_LABEL"
                ),
                "enforcement_order": (
                    "EXACT_RUNTIME_IMAGE_AND_TABLE_SNAPSHOTS_TUPLE_THEN_EXACT_"
                    "TABLE_SNAPSHOT_CARDINALITY_THEN_STRICT_ZIP_POSITION_14_"
                    "THEN_EXACT_SNAPSHOT_TYPE_FIELD_READS_AND_PRESENCE_THEN_"
                    "NON_BLOCKING_TABLE_IDENTITY_DIAGNOSTIC_REGARDLESS_OF_"
                    "MATCH_THEN_EXACT_ROWS_TUPLE_THEN_INCLUSIVE_ONE_HUNDRED_"
                    "THOUSAND_ROW_COMPARISON_BEFORE_ROW_CANONICALIZATION_"
                    "VALIDATION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_TABLE_ROW_LIMIT_AT_POSITION_14_ROWS_SET_ACCOUNTING_"
                    "INCOMPLETE_CONTINUE_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ROWS_FIELD_OF_CAPTURED_TABLE_SNAPSHOT_"
                "AT_STRICT_POSITION_14_TASKS_SPEC"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": "0 <= len(captured['events']) <= 100000",
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM",
            "definition_site_ids": [
                "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4"
            ],
            "enforcement_site_ids": [
                "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4"
            ],
            "evidence_inputs": [
                dict(item) for item in TOP_LEVEL_EVENTS_MAXIMUM_RESOURCE_EVIDENCE
            ],
            "maximum": 100_000,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_image.py:inspect_runtime_image_host"
                ),
                "input_binding": (
                    "EXACT_BUILTIN_TUPLE_CAPTURED_EVENTS_AFTER_RUNTIME_"
                    "IMAGE_FIELD_CAPTURE"
                ),
                "enforcement_order": (
                    "RUNTIME_IMAGE_FIELD_CAPTURE_THEN_EXACT_BUILTIN_TUPLE_"
                    "GUARD_THEN_INCLUSIVE_ZERO_TO_ONE_HUNDRED_THOUSAND_"
                    "COMPARISON_BEFORE_MEMBER_INSPECTION_OR_ACCOUNTING"
                ),
                "rejection_action": (
                    "ADD_IMAGE_CARDINALITY_LIMIT_FOR_EVENTS_SET_ACCOUNTING_"
                    "INCOMPLETE_SKIP_EVENT_MEMBERS_AND_WITHHOLD_SANITIZED_IMAGE"
                ),
                "selection_semantics": (
                    "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY"
                ),
                "raw_definition_site_id": (
                    "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f"
                ),
                "branch_cardinality_site_id": (
                    "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1"
                ),
                "definition_occurrence": 1,
            },
            "semantic_subject": (
                "EXACT_BUILTIN_TUPLE_ITEM_COUNT_OF_CAPTURED_EVENTS_AT_"
                "HOST_PREFLIGHT"
            ),
            "unit": "ITEMS",
        },
        {
            "accepted_equation": (
                "if len(artifact) <= 256: artifact; otherwise artifact[:184] "
                "+ '#sha256=' + sha256(artifact.encode('utf-8')).hexdigest()"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "VERIFIER_FINDING_ARTIFACT_CHARACTER_MAXIMUM",
            "definition_site_ids": [
                "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
            ],
            "enforcement_site_ids": [
                "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98",
                "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e",
            ],
            "evidence_inputs": [
                dict(item) for item in FINDING_STRING_BOUNDS_RESOURCE_EVIDENCE
            ],
            "maximum": 256,
            "semantic_function_ast_sha256": (
                "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781"
            ),
            "semantic_module_ast_sha256": (
                "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_verifier.py:_finding"
                ),
                "input_binding": (
                    "EXACT_ARTIFACT_ARGUMENT_TO_NESTED_BOUNDED_HELPER_WITH_"
                    "MAX_FINDING_ARTIFACT_CHARS"
                ),
                "enforcement_order": (
                    "EXACT_CHARACTER_LENGTH_GUARD_THEN_FULL_ORIGINAL_UTF8_"
                    "SHA256_SUFFIX_THEN_PREFIX_SLICE_TO_256_TOTAL_CHARACTERS"
                ),
                "rejection_action": (
                    "NOT_APPLICABLE_DETERMINISTIC_TRUNCATION_WITH_FULL_"
                    "ORIGINAL_DIGEST"
                ),
                "selection_semantics": (
                    "VERIFICATION_FINDING_ARTIFACT_CHARACTER_MAXIMUM_ONLY"
                ),
                "raw_definition_site_id": (
                    "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
                ),
                "subject_caller_site_id": (
                    "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98"
                ),
                "derived_composite_site_id": (
                    "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e"
                ),
                "shared_comparison_site_id": (
                    "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
                ),
                "shared_slice_site_id": (
                    "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"
                ),
            },
            "semantic_subject": (
                "VERIFICATION_FINDING_ARTIFACT_PYTHON_STRING_CHARACTER_"
                "COUNT_AND_TRUNCATION"
            ),
            "unit": "CHARACTERS",
        },
        {
            "accepted_equation": (
                "if len(coordinate) <= 512: coordinate; otherwise "
                "coordinate[:440] + '#sha256=' + "
                "sha256(coordinate.encode('utf-8')).hexdigest()"
            ),
            "classification": "RESOURCE_MAXIMUM",
            "constraint_id": "VERIFIER_FINDING_COORDINATE_CHARACTER_MAXIMUM",
            "definition_site_ids": [
                "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
            ],
            "enforcement_site_ids": [
                "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c",
                "fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8",
            ],
            "evidence_inputs": [
                dict(item) for item in FINDING_STRING_BOUNDS_RESOURCE_EVIDENCE
            ],
            "maximum": 512,
            "semantic_function_ast_sha256": (
                "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781"
            ),
            "semantic_module_ast_sha256": (
                "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
            ),
            "semantic_proof": {
                "function_coordinate": (
                    "src/edgelab/runtime_v2_verifier.py:_finding"
                ),
                "input_binding": (
                    "EXACT_COORDINATE_ARGUMENT_TO_NESTED_BOUNDED_HELPER_WITH_"
                    "MAX_FINDING_COORDINATE_CHARS"
                ),
                "enforcement_order": (
                    "EXACT_CHARACTER_LENGTH_GUARD_THEN_FULL_ORIGINAL_UTF8_"
                    "SHA256_SUFFIX_THEN_PREFIX_SLICE_TO_512_TOTAL_CHARACTERS"
                ),
                "rejection_action": (
                    "NOT_APPLICABLE_DETERMINISTIC_TRUNCATION_WITH_FULL_"
                    "ORIGINAL_DIGEST"
                ),
                "selection_semantics": (
                    "VERIFICATION_FINDING_COORDINATE_CHARACTER_MAXIMUM_ONLY"
                ),
                "raw_definition_site_id": (
                    "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
                ),
                "subject_caller_site_id": (
                    "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c"
                ),
                "derived_composite_site_id": (
                    "fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8"
                ),
                "shared_comparison_site_id": (
                    "00a9f454f52ac495ec96178fb37d0d0c0f588c674afe2556d093d3e64ad7fb3b"
                ),
                "shared_slice_site_id": (
                    "642f873b6a2bf9d504396cdf89289a30df71deba2bd4bfc095f19bf7e70983ac"
                ),
            },
            "semantic_subject": (
                "VERIFICATION_FINDING_COORDINATE_PYTHON_STRING_CHARACTER_"
                "COUNT_AND_TRUNCATION"
            ),
            "unit": "CHARACTERS",
        },
    ]
    expected_constraints.append({
        "accepted_equation": (
            "digits = token[1:] if token starts with one leading minus sign "
            "else token; len(digits) <= 19 proceeds to int(token), while "
            "len(digits) > 19 raises INTEGER_TOKEN_TOO_LONG before integer "
            "conversion"
        ),
        "classification": "RESOURCE_MAXIMUM",
        "constraint_id": "CLOSURE_INTEGER_TOKEN_MAX_DIGITS",
        "definition_site_ids": [
            "7b99b5408a023f557be70736b52ecf6a8de4d8594b0da6318cacb3c9680cf5fc"
        ],
        "enforcement_site_ids": [
            "90292d8f8df61b2ee109adf7df0d0d4e44c2cdf5a6f70c887e7e5228d4cb8657"
        ],
        "evidence_inputs": [
            dict(item) for item in CLOSURE_INTEGER_TOKEN_DIGIT_RESOURCE_EVIDENCE
        ],
        "maximum": 19,
        "semantic_function_ast_sha256": (
            "93f3332d484055779849d85784ce4bc5b9d2d406838513e75e80c42edb2492fd"
        ),
        "semantic_module_ast_sha256": (
            "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7"
        ),
        "semantic_proof": {
            "caller_coordinate": (
                "src/edgelab/runtime_v2_closure.py:_parse_closure_json"
            ),
            "caller_function_ast_sha256": (
                "379d4890883b5519fa33ebf5d305ae803c8627b1dd0599db854ec191bce50f09"
            ),
            "enforcement_order": (
                "OPTIONAL_LEADING_MINUS_SLICE_THEN_STRICT_GREATER_THAN_"
                "NINETEEN_CHARACTER_GUARD_THEN_INTEGER_CONVERSION"
            ),
            "function_coordinate": (
                "src/edgelab/runtime_v2_closure.py:_parse_integer_token"
            ),
            "input_binding": (
                "EXACT_JSON_PARSE_INT_TOKEN_STRING_WITH_OPTIONAL_ONE_LEADING_"
                "ASCII_MINUS_SIGN_EXCLUDED_FROM_DIGIT_COUNT"
            ),
            "rejection_action": (
                "RAISE_CANONICAL_JSON_ERROR_INTEGER_TOKEN_TOO_LONG_BEFORE_"
                "INTEGER_CONVERSION"
            ),
            "selection_semantics": (
                "LEXICAL_DECIMAL_DIGIT_COUNT_ONLY_NOT_INT64_OR_FIELD_RANGE_"
                "VALIDATION"
            ),
        },
        "semantic_subject": (
            "DEPENDENCY_CLOSURE_JSON_INTEGER_TOKEN_DECIMAL_DIGITS_EXCLUDING_"
            "ONE_LEADING_MINUS_SIGN"
        ),
        "unit": "CHARACTERS",
    })
    expected_constraints.append({
        "accepted_equation": (
            "if type(child) is str and child starts with '#/$defs/', token = "
            "child[8:]; within the existing compound schema-reference profile "
            "condition len(token) <= 64 is accepted and len(token) > 64 adds "
            "SCHEMA_REF_OUTSIDE_PROFILE at child_path"
        ),
        "classification": "RESOURCE_MAXIMUM",
        "constraint_id": "VERIFIER_SCHEMA_REF_TOKEN_CHARACTER_MAXIMUM",
        "definition_site_ids": [
            "6e95fce4ad2ed77d84d5bfaad79566cb4276adc28054fb8bde30b0bbb5c911c5"
        ],
        "enforcement_site_ids": [
            "66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474"
        ],
        "evidence_inputs": [
            dict(item) for item in SCHEMA_REF_TOKEN_CHARACTER_RESOURCE_EVIDENCE
        ],
        "maximum": 64,
        "semantic_function_ast_sha256": (
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d"
        ),
        "semantic_module_ast_sha256": (
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
        ),
        "semantic_proof": {
            "compound_condition_ast_sha256": (
                "7608b9ceacbfcfdf61a12da0139e30d3fffff6edee52c4fbce53755987dcc033"
            ),
            "diagnostic_call_ast_sha256": (
                "0df06f8d4f4d223d4da9df2c422b8e017ce1b3b2ca5bf2208ec318ad81c71a92"
            ),
            "enforcement_order": (
                "EXACT_STRING_TYPE_AND_LOCAL_DEFS_PREFIX_GATES_THEN_EIGHT_"
                "CHARACTER_SLICE_THEN_COMPOUND_PROFILE_CONDITION_WITH_STRICT_"
                "GREATER_THAN_SIXTY_FOUR_CHECK_BEFORE_DIAGNOSTIC_OR_TARGET_LOOKUP"
            ),
            "function_coordinate": (
                "src/edgelab/runtime_v2_verifier.py:_schema_safety_findings"
            ),
            "input_binding": (
                "EXACT_CHILD_VALUE_OF_A_JSON_SCHEMA_REF_KEY_DURING_BUDGET_"
                "GUARDED_RECURSIVE_WALK"
            ),
            "nested_walk_coordinate": (
                "src/edgelab/runtime_v2_verifier.py:"
                "_schema_safety_findings.walk"
            ),
            "prefix_constant_ast_sha256": (
                "cc5d3196889a6a14f40a5802b25e1bccad4db0726ef81f864b356114bb63a56c"
            ),
            "rejection_action": (
                "ADD_SCHEMA_REF_OUTSIDE_PROFILE_AT_EXACT_CHILD_PATH_SUBJECT_"
                "TO_EXISTING_DIAGNOSTIC_BUDGET"
            ),
            "selection_semantics": (
                "LOCAL_DEFS_REFERENCE_TOKEN_CHARACTER_MAXIMUM_ONLY_NOT_"
                "DEFINITION_NAME_TARGET_EXISTENCE_GRAPH_OR_GENERIC_STRING_LIMIT"
            ),
            "startswith_call_ast_sha256": (
                "f217f12d2c49fca730036d93eb9cdc63e985b98b021a62306207355c38d465b8"
            ),
            "token_assignment_ast_sha256": (
                "dadccb0d8acde30915a33a88f67fcef3f04b7fc9139746aa2d0b5147d0a6f62d"
            ),
            "type_gate_ast_sha256": (
                "252b73ee6debf88306997d684c5b22f599bdd9ce812f571f1e26171d950d9c9a"
            ),
            "walk_function_ast_sha256": (
                "d4e1299dcda1803cce4265a600cb5f9e1fd102d7dfa6c826c0b4701a7255548d"
            ),
        },
        "semantic_subject": (
            "LOCAL_JSON_SCHEMA_DEFS_REFERENCE_TOKEN_PYTHON_STRING_CHARACTER_"
            "COUNT_AFTER_EXACT_PREFIX_REMOVAL"
        ),
        "unit": "CHARACTERS",
    })
    expected_constraints.append({
        "accepted_equation": (
            "definitions = value.get('$defs', {}) with non-dict values diagnosed "
            "and replaced by {}; for each name, definition in definitions.items(), "
            "within the existing compound definition-name profile condition "
            "len(name) <= 64 is accepted and len(name) > 64 adds SCHEMA_DEF_NAME "
            "at '/$defs' then continues before graph insertion or recursive walk"
        ),
        "classification": "RESOURCE_MAXIMUM",
        "constraint_id": "VERIFIER_SCHEMA_DEFINITION_NAME_CHARACTER_MAXIMUM",
        "definition_site_ids": [
            "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd"
        ],
        "enforcement_site_ids": [
            "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd"
        ],
        "evidence_inputs": [
            dict(item)
            for item in SCHEMA_DEFINITION_NAME_CHARACTER_RESOURCE_EVIDENCE
        ],
        "maximum": 64,
        "semantic_function_ast_sha256": (
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d"
        ),
        "semantic_module_ast_sha256": (
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc"
        ),
        "semantic_proof": {
            "compound_profile_ast_sha256": (
                "4b06800b12b71cbc41ad53077e9b3f9026341c2499d0639c96a32128fe8b4141"
            ),
            "continue_ast_sha256": (
                "3d1e0aaa463df3eefc9bd5be83f453adcd9621b2dc7f387c3eaff3ab42e91059"
            ),
            "definitions_assignment_ast_sha256": (
                "ccaf8d0686b3f24ae4ca531ac8026a1f0c4a9e76bf5a30466db00e47a1f4f94f"
            ),
            "definitions_guard_ast_sha256": (
                "221b0b40155ea6a859985efe8e0eb563be0da0831092542df4fbfc82c9d9a948"
            ),
            "diagnostic_call_ast_sha256": (
                "5b6c969f9feb84773e74a77632bd2f25ac4e029cc2d0957e72906858ec60781b"
            ),
            "edges_insertion_call_ast_sha256": (
                "40aba6d8841818b88ad9cedc77959fd4462e56390176920a2f847cb3c87893e7"
            ),
            "enforcement_order": (
                "ROOT_DEFS_EXTRACTION_THEN_EFFECTIVE_DICT_GUARD_THEN_ROOT_WALK_"
                "AND_BUDGET_GUARD_THEN_EXACT_ITEMS_LOOP_THEN_COMPOUND_PROFILE_"
                "WITH_STRICT_GREATER_THAN_SIXTY_FOUR_THEN_DIAGNOSTIC_AND_"
                "CONTINUE_BEFORE_EDGE_INSERTION_OR_DEFINITION_WALK"
            ),
            "fallback_assignment_ast_sha256": (
                "34418ddea378177305947fdcf67c106a531f1844bbe833024f641e37a82158e9"
            ),
            "function_coordinate": (
                "src/edgelab/runtime_v2_verifier.py:_schema_safety_findings"
            ),
            "input_binding": (
                "EXACT_ROOT_JSON_SCHEMA_DEFS_MEMBER_NAME_AFTER_EFFECTIVE_DICT_"
                "FALLBACK_DURING_BUDGET_GUARDED_DEFINITION_ITERATION"
            ),
            "items_loop_ast_sha256": (
                "d9b67cdccc3e8c40c7256c5d776a3c2b2c579d96cbe7bed2521d642f5d81fb2d"
            ),
            "rejection_action": (
                "ADD_SCHEMA_DEF_NAME_AT_EXACT_ROOT_DEFS_COORDINATE_SUBJECT_TO_"
                "EXISTING_DIAGNOSTIC_BUDGET_THEN_CONTINUE_WITHOUT_EDGE_OR_WALK"
            ),
            "selection_semantics": (
                "ROOT_DEFS_DEFINITION_NAME_CHARACTER_MAXIMUM_ONLY_NOT_OTHER_"
                "NAME_PROFILE_TERMS_REFERENCE_TOKEN_TARGET_GRAPH_OR_BODY_VALIDITY"
            ),
            "walk_call_ast_sha256": (
                "6b451e50276f1db40135e88ab28644895ab981654d2d153e6b2ede6d29f2a47a"
            ),
        },
        "semantic_subject": (
            "ROOT_JSON_SCHEMA_DEFS_DEFINITION_NAME_PYTHON_STRING_CHARACTER_COUNT"
        ),
        "unit": "CHARACTERS",
    })
    expected_constraints.append({
        "accepted_equation": (
            "for the private _validate internal depth argument, depth <= 128 "
            "passes the entry guard and depth > 128 raises "
            "MAX_DEPTH_EXCEEDED before value dispatch or traversal"
        ),
        "classification": "RESOURCE_MAXIMUM",
        "constraint_id": "CODEC_PRIVATE_VALIDATE_DEPTH_MAXIMUM",
        "definition_site_ids": [
            "be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c"
        ],
        "enforcement_site_ids": [
            "be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c"
        ],
        "evidence_inputs": [
            dict(item) for item in CODEC_PRIVATE_VALIDATE_DEPTH_RESOURCE_EVIDENCE
        ],
        "maximum": 128,
        "semantic_function_ast_sha256": (
            "aa685f536f498f68e19e5658d163306608357e6ef66461b18d6cee56d42229f1"
        ),
        "semantic_module_ast_sha256": (
            "9be9408e5415167120cca04deaeb669243467a609dcd25193fb9280294a25eb7"
        ),
        "semantic_proof": {
            "canonical_json_function_ast_sha256": (
                "66ffdc85016ebfac15fac6de24e50542bd2dd8dd9317f8dd0d66e1d370be3473"
            ),
            "comparison_ast_sha256": (
                "8119b6e4c3865b1881f9e783f4f3029f856b1677b79b9f89a708f5c48ba68159"
            ),
            "default_depth_site_id_context_only": (
                "b3ed1a4f14af6fb6e7f9d2a7246adfe2cf28de8ac18cb3b45a473970e9a9009a"
            ),
            "dict_key_recursive_call_ast_sha256": (
                "b392b37fba626c1761cc56c5156249bda6fad656f89af399d3f883ac322869a4"
            ),
            "enforcement_order": (
                "STRICT_GREATER_THAN_ONE_HUNDRED_TWENTY_EIGHT_ENTRY_GUARD_"
                "THEN_MAX_DEPTH_ERROR_BEFORE_SCALAR_OR_CONTAINER_DISPATCH_"
                "AND_RECURSIVE_TRAVERSAL"
            ),
            "error_call_ast_sha256": (
                "4f66b6fc9199097a2fc2d4df0d0ffb0cdf1dcb77cfbfc775a44f981bb6b4e64e"
            ),
            "function_coordinate": "src/edgelab/runtime_v2_codec.py:_validate",
            "guard_if_ast_sha256": (
                "12e3a43a51149fa82cf0d27b247ca1471a110f3718d3f73b7ee027ea25f3b96a"
            ),
            "input_binding": (
                "EXACT_PRIVATE_VALIDATE_INTERNAL_DEPTH_ARGUMENT_IN_LEVELS"
            ),
            "list_and_dict_value_recursive_call_ast_sha256": (
                "9f4943a2da4c497e0faed67aff8715a40453eafd6e3eb177ade28046e591e9e9"
            ),
            "parse_canonical_json_function_ast_sha256": (
                "52886dcd3e9db3c47e7d6b3b7e60f440d48172ef723a0cd95f5d04bed4633bda"
            ),
            "rejection_action": (
                "RAISE_CANONICAL_JSON_ERROR_MAX_DEPTH_EXCEEDED_BEFORE_"
                "DISPATCH_OR_TRAVERSAL"
            ),
            "root_caller_ast_sha256": (
                "3f2b68548ffb99f0523c9b97d604a13e3d541d22e6725557dcb50a00f16ce198"
            ),
            "selection_semantics": (
                "PRIVATE_VALIDATE_INTERNAL_DEPTH_ARGUMENT_ONLY_NOT_DEFAULT_"
                "DEPTH_PUBLIC_CANONICAL_JSON_STRUCTURAL_DEPTH_PARSER_REJECTION_"
                "TRAVERSAL_COMPLETENESS_OR_NEGATIVE_DEPTH_VALIDITY"
            ),
        },
        "semantic_subject": "PRIVATE_CODEC_VALIDATE_INTERNAL_DEPTH_ARGUMENT",
        "unit": "LEVELS",
    })
    expected_constraints.append({
        "accepted_equation": (
            "for the first InitialViolation.code constructed by _Sink.add, "
            "if len(code) <= 128 the code is unchanged; otherwise the stored "
            "code is code[:56] + '#sha256=' + "
            "sha256(code.encode('utf-8')).hexdigest()"
        ),
        "classification": "RESOURCE_MAXIMUM",
        "constraint_id": "INITIAL_REDUCER_FINDING_CODE_CHARACTER_MAXIMUM",
        "definition_site_ids": [
            "299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8"
        ],
        "enforcement_site_ids": [
            "299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8"
        ],
        "evidence_inputs": [
            dict(item) for item in INITIAL_REDUCER_FINDING_CODE_RESOURCE_EVIDENCE
        ],
        "maximum": 128,
        "semantic_function_ast_sha256": (
            "34c20470283590c5ef422d87bb487928a10e43de86e274a6fe510cc77801be0c"
        ),
        "semantic_module_ast_sha256": (
            "15ecffa7a1df62b834bac7be5837f53ce0f7d3211d0942967dbb4c75612b658b"
        ),
        "semantic_proof": {
            "bounded_function_ast_sha256": (
                "592e2f700af27699e0fe9eade5fd0f357d5bf7949ae370face4a34efd0ab6f9c"
            ),
            "comparison_ast_sha256": (
                "159e23864d588432b924de55a370594d8789e3ddbb8a9768388ec472f0cb6ce4"
            ),
            "constructor_call_ast_sha256": (
                "5ee34e310813959bc18ff8a80a3fd8ccdb708ab402dc9f17baf5baadb0377c3e"
            ),
            "digest_call_ast_sha256": (
                "8b66ba6ea0117121e435a44de478594500b850f3662a5da44009ed47db0ccb87"
            ),
            "enforcement_order": (
                "NESTED_BOUNDED_HELPER_CHARACTER_GUARD_THEN_PASSTHROUGH_OR_"
                "FULL_ORIGINAL_UTF8_SHA256_SUFFIX_AND_PREFIX_SLICE_THEN_FIRST_"
                "INITIAL_VIOLATION_CODE_CONSTRUCTION"
            ),
            "finding_assignment_ast_sha256": (
                "e0084beebde261ce1ed7febac19f9676ae77ae37f317f81a6a190b82df050ba8"
            ),
            "function_coordinate": "src/edgelab/runtime_v2_initial.py:_Sink.add",
            "guard_if_ast_sha256": (
                "1ed6be5ba1c5627d79849529e2175a2a2dc67e49b9c4498733dbf47b592218d5"
            ),
            "initial_violation_class_ast_sha256": (
                "be763e1502bbd4b299402dfa10467bacc4c880269fa8692a98977dcf1f619f7d"
            ),
            "input_binding": (
                "EXACT_CODE_ARGUMENT_TO_BOUNDED_WITH_LITERAL_ONE_HUNDRED_"
                "TWENTY_EIGHT_FOR_FIRST_INITIAL_VIOLATION_FIELD"
            ),
            "passthrough_return_ast_sha256": (
                "88b203970aef225f077e527420a8aa37d7bea48c022a704b48a144448b80ec78"
            ),
            "rejection_action": (
                "NOT_APPLICABLE_DETERMINISTIC_PREFIX_TRUNCATION_WITH_FULL_"
                "ORIGINAL_UTF8_SHA256_SUFFIX"
            ),
            "selection_semantics": (
                "INITIAL_REDUCER_FIRST_INITIAL_VIOLATION_CODE_CHARACTER_"
                "TRANSFORMATION_ONLY_NOT_SHARED_HELPER_ARTIFACT_COORDINATE_"
                "FINDINGS_COUNT_BYTES_COLLISION_DEDUPLICATION_REPORT_"
                "COMPLETENESS_OR_SYNTHETIC_FINDINGS_TRUNCATED"
            ),
            "sink_class_ast_sha256": (
                "b61e2b4fbb562a2458c43eadf5b2e548ea520f1b652a06039c4bfd6e7128227e"
            ),
            "slice_ast_sha256": (
                "74117ea7f02d52d57cdd5cfd500f420236efd5451e9c19f9fe00afae164cd152"
            ),
            "suffix_assignment_ast_sha256": (
                "955195bbb5a430a35b8a25506710d4ae29dd97dfb851080af22ddbd3af035f94"
            ),
            "truncating_return_ast_sha256": (
                "6fd09e200f846e9e544f8cbd866d35baf4b58e110aea81a6c2919139f03bdedb"
            ),
        },
        "semantic_subject": (
            "INITIAL_REDUCER_FIRST_INITIAL_VIOLATION_CODE_PYTHON_STRING_"
            "CHARACTER_COUNT_AND_TRANSFORMATION"
        ),
        "unit": "CHARACTERS",
    })
    expected_constraints.append(predecessor_schema_proof)
    expected_constraints.append(selected_proof)
    if constraints != expected_constraints:
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINT", manifest_path)
    current_predecessor_value = manifest_values.get(
        RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST["path"]
    )
    current_predecessor_constraints = (
        current_predecessor_value.get("constraints")
        if type(current_predecessor_value) is dict
        else None
    )
    if not (
        current_predecessor_value is not None
        and type(current_predecessor_constraints) is list
        and len(current_predecessor_constraints) == 39
        and current_predecessor_value.get("classified_site_count") == 72
        and constraints[:-1] == current_predecessor_constraints
    ):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_PREDECESSOR_PREFIX", manifest_path
        )
    historical_value = manifest_values.get(
        RESOURCE_CLASSIFICATION_V46_PREDECESSOR_MANIFEST["path"]
    )
    historical_constraints = (
        historical_value.get("constraints")
        if type(historical_value) is dict
        else None
    )
    if not (
        historical_value is not None
        and type(historical_constraints) is list
        and len(historical_constraints) == len(current_predecessor_constraints)
        and historical_value.get("classified_site_count") == 72
    ):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_V46_PREDECESSOR_PREFIX", manifest_path
        )
    observed_rebases: dict[
        tuple[str, str], tuple[dict[str, Any], dict[str, Any]]
    ] = {}
    for successor, historical in zip(
        current_predecessor_constraints, historical_constraints, strict=True
    ):
        if {
            key: value for key, value in successor.items()
            if key != "evidence_inputs"
        } != {
            key: value for key, value in historical.items()
            if key != "evidence_inputs"
        }:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_PREDECESSOR_SEMANTICS", manifest_path
            )
        successor_evidence = successor["evidence_inputs"]
        historical_evidence = historical["evidence_inputs"]
        if len(successor_evidence) != len(historical_evidence):
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_PREDECESSOR_EVIDENCE", manifest_path
            )
        for current_record, historical_record in zip(
            successor_evidence, historical_evidence, strict=True
        ):
            if current_record == historical_record:
                continue
            path = current_record.get("path")
            if type(path) is not str or historical_record.get("path") != path:
                raise ReadinessError(
                    "RESOURCE_CLASSIFICATION_PREDECESSOR_EVIDENCE", manifest_path
                )
            coordinate = (successor["constraint_id"], path)
            allowed = RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES.get(
                coordinate
            )
            expected_historical = (
                {"path": path, **allowed["historical"]}
                if allowed is not None else None
            )
            expected_current = (
                {"path": path, **allowed["current"]}
                if allowed is not None else None
            )
            if historical_record != expected_historical or current_record != expected_current:
                raise ReadinessError(
                    "RESOURCE_CLASSIFICATION_PREDECESSOR_EVIDENCE", path
                )
            observed_rebases[coordinate] = (historical_record, current_record)
    if set(observed_rebases) != set(RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_PREDECESSOR_REBASE_SET", manifest_path
        )

    evidence_by_path = {item["path"]: item for item in RESOURCE_CLASSIFICATION_EVIDENCE}
    if len(evidence_by_path) != len(RESOURCE_CLASSIFICATION_EVIDENCE):
        raise ReadinessError("RESOURCE_CLASSIFICATION_EVIDENCE_DUPLICATE", "/")
    for evidence in evidence_by_path.values():
        evidence_raw, evidence_identity = _audit_path(root, evidence["path"])
        if evidence_identity in identities:
            raise ReadinessError("HARDLINK_INPUT_ALIAS", evidence["path"])
        identities.add(evidence_identity)
        if len(evidence_raw) != evidence["byte_length"] or _sha256(
            evidence_raw
        ) != evidence["raw_sha256"]:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_EVIDENCE_IDENTITY", evidence["path"]
            )
    for (_, path), rebase in RESOURCE_CLASSIFICATION_V46_EVIDENCE_REBASES.items():
        current_record = {"path": path, **rebase["current"]}
        if evidence_by_path.get(path) != current_record:
            raise ReadinessError("RESOURCE_CLASSIFICATION_REBASE_EVIDENCE", path)
    if any(
        evidence["path"] == RESOURCE_CLASSIFICATION_CURRENT_TEST_PATH
        for constraint in constraints
        for evidence in constraint["evidence_inputs"]
    ):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_CURRENT_TEST_AS_EVIDENCE",
            RESOURCE_CLASSIFICATION_CURRENT_TEST_PATH,
        )

    source_sites, schema_sites = _resource_site_maps(resource_discovery)
    sites = {**source_sites, **schema_sites}
    classified_source_site_ids = {
        site_id
        for constraint in expected_constraints[:-2]
        for field in ("definition_site_ids", "enforcement_site_ids")
        for site_id in constraint[field]
    }
    classified_schema_site_ids = {
        predecessor_schema_proof["schema_site_id"],
        selected_proof["schema_site_id"],
    }
    _validate_classified_resource_site_ids(
        classified_source_site_ids,
        classified_schema_site_ids,
        CLASSIFIED_RESOURCE_SITE_IDS,
        CLASSIFIED_SCHEMA_RESOURCE_SITE_IDS,
        source_sites,
        schema_sites,
        manifest_path,
    )
    for proof, expected in (
        (predecessor_schema_proof, RESOURCE_CLASSIFICATION_V46_SCHEMA_PROOF),
        (selected_proof, RESOURCE_CLASSIFICATION_V47_SCHEMA_PROOF),
    ):
        if proof["schema_site_id"] != expected["schema_site_id"]:
            raise ReadinessError(
                "SCHEMA_DECLARATIVE_SELECTED_PROOF_SITE", expected["path"]
            )
        _validate_schema_declarative_keyword_proof(
            root,
            proof,
            source_sites,
            schema_sites,
            resource_discovery["schema_inputs"],
        )
    site_shapes = {
        "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f": {
            "ast_sha256": (
                "ae70f40d2c066a8450ddf01e6bf0a1c75d6bc2a4dad282ed7b350729e4e1111b"
            ),
            "expression": "MAX_FINDING_ARTIFACT_CHARS = 256",
            "kind": "MODULE_NUMERIC_ASSIGNMENT",
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>",
        },
        "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98": {
            "ast_sha256": (
                "c5f892612da3da02259a8933ec26ed94d91e9f834c7f7d115f15d23ff085aa73"
            ),
            "expression": "bounded(artifact, MAX_FINDING_ARTIFACT_CHARS)",
            "kind": "BOUND_HELPER_CALL",
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._finding",
        },
        "a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e": {
            "binding": "verification_finding:artifact",
            "caller_site_id": (
                "836376ba8aabd7bfca299784acf6abe992e0e7f3ec71bf92b4ae53f9445dda98"
            ),
            "definition_site_id": (
                "faf8073483e0d412600c34a0a24d10145d8c6e42875abd04d14b95e943fd3d7f"
            ),
            "kind": "BOUND_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING",
            "maximum": 256,
            "maximum_expression": "MAX_FINDING_ARTIFACT_CHARS",
            "selection_semantics": (
                "VERIFICATION_FINDING_ARTIFACT_CHARACTER_MAXIMUM_ONLY"
            ),
            "subject_binding": "VerificationFinding.artifact",
            "unit": "CHARACTERS",
        },
        "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed": {
            "ast_sha256": (
                "3abd7812682ddf40aa0dcdb0e07f0f3ec920e5e58441882567c4254006d1da7b"
            ),
            "expression": "MAX_FINDING_COORDINATE_CHARS = 512",
            "kind": "MODULE_NUMERIC_ASSIGNMENT",
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>",
        },
        "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c": {
            "ast_sha256": (
                "1aa4ecb66db3f22cd16f2e0c1f9f56102d36fed3eaed9bf8e3cab90766af5249"
            ),
            "expression": "bounded(coordinate, MAX_FINDING_COORDINATE_CHARS)",
            "kind": "BOUND_HELPER_CALL",
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._finding",
        },
        "fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8": {
            "binding": "verification_finding:coordinate",
            "caller_site_id": (
                "c175d69d2d2d8aeb1553da097a3eb63cf94c9cfa44a2ddcfe65805541824544c"
            ),
            "definition_site_id": (
                "e72a56bc586b85f62a090240bd85f1eeb78ca6b06413c0abb766ed1e96de82ed"
            ),
            "kind": "BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING",
            "maximum": 512,
            "maximum_expression": "MAX_FINDING_COORDINATE_CHARS",
            "selection_semantics": (
                "VERIFICATION_FINDING_COORDINATE_CHARACTER_MAXIMUM_ONLY"
            ),
            "subject_binding": "VerificationFinding.coordinate",
            "unit": "CHARACTERS",
        },
        "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4": {
            "binding": "cardinality_maxima:events",
            "branch_cardinality_site_id": (
                "fd2933fa143fb9fb2d6a9d6f375f1f6b1e0aae26e447e9fea4ad3b9d7c2b92a1"
            ),
            "classification": "UNCLASSIFIED",
            "definition_ast_sha256": (
                "36776d47d1ea9414c879865979d7d76c23429d7c4cf858cfbb07704214384104"
            ),
            "definition_site_id": (
                "2dcbb43b767e41adb2cb59c64d6b3bfab8e9dbb8e583eebc5801d93668b7b43f"
            ),
            "excluded_semantics": [
                "INITIAL_REDUCER_EVENT_CARDINALITY",
                "TRANSITION_COLLECTION_CARDINALITY",
                "EVENTS_TABLE_ROW_CARDINALITY",
                "EVENT_ITEM_BYTE_CARDINALITY",
                "PUBLIC_VERIFIER_OR_AUTHORITY",
            ],
            "expression": "0 <= len(captured['events']) <= MAX_EVENTS",
            "kind": "BOUND_TOP_LEVEL_CARDINALITY_MAXIMUM_BINDING",
            "maximum": 100000,
            "maximum_expression": "MAX_EVENTS",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "selection_semantics": (
                "HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM_ONLY"
            ),
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "subject_binding": "captured['events']",
            "unit": "ITEMS",
            "tuple_loop_ast_sha256": (
                "9e3c2a4b8b7a01aefe2d991cbd889eb3e438c2849d75e31b89ed89afd9265b41"
            ),
            "cardinality_loop_ast_sha256": (
                "240c758d427bfefb4cd9ae2f020a6c8d8212178637c304811e1751dea8b98e2f"
            ),
            "member_loop_ast_sha256": (
                "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
            ),
            "sanitized_image_gate_ast_sha256": (
                "96643ddc4991990f0f04524e6e3f44d13fe7ac8938e9818460dc7054d715a7e2"
            ),
            "tuple_guard_ast_sha256": (
                "48c990518a6d97c4e3c5d6c976111eb55261d758f76466970d2ee40d2c9d3f98"
            ),
            "tuple_result_ast_sha256": (
                "b307f58801ce8e78a43696d5953c22e0b2c93a79418f4a3f941f608644979fbb"
            ),
            "tuple_invalid_ast_sha256": (
                "ebaece4655128040d4ecf6fafb8970b1f4b75d2d2199836efba5b4611fa71aad"
            ),
            "validity_gate_ast_sha256": (
                "80f43e2757b87785145812c7bbdd11dd7f2b75ca7983a0e20657f51bf0493557"
            ),
            "comparison_assignment_ast_sha256": (
                "0ac4a3c116faf2d3b271a709a0b15171fa566779bb8e03797b6271aaaec94018"
            ),
            "comparison_result_ast_sha256": (
                "f7babf5f583439c6651955a1f94cd7ded828a872da0550f437198585bcdfc6e6"
            ),
            "invalid_branch_ast_sha256": (
                "10f692935ade01e94f5748199c52cdc242aa0260a5c88603a03dd3710c13accb"
            ),
            "member_gate_ast_sha256": (
                "e6cb8d515794956552ebab7d5e2932e76e217cb0944ac82a8bfc7139d1cd36ae"
            ),
            "site_id": (
                "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4"
            ),
        },
        "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b": {
            "ast_sha256": "9d14812b77c13b635b9ec0f782c2075420d8158c4a1d52825c72f5938fdba59e",
            "binding": "table_row_caps:tasks",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('tasks', (_c('task_id', 'TEXT'), _c('attempt', 'INTEGER'), _c('workflow', 'TEXT'), _c('execution', 'TEXT'), _c('review', 'TEXT'), _c('scheduler_generation', 'INTEGER'), _c('dispatch_generation', 'INTEGER'), _c('task_fence', 'INTEGER'), _c('active_claim_id', 'TEXT', True), _c('reviewer_assignment_id', 'TEXT', True), _c('continuation_count', 'INTEGER'), _c('repository_generation', 'INTEGER'), _c('decision_receipt_digest', 'TEXT'), _c('owner', 'TEXT'), _c('owner_role', 'TEXT'), _c('reviewer', 'TEXT', True), _c('predecessor_task', 'TEXT', True), _c('successor_task', 'TEXT', True)), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 129,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 14,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][14].rows",
            "table_name": "tasks",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "9d14812b77c13b635b9ec0f782c2075420d8158c4a1d52825c72f5938fdba59e",
            "table_spec_site_id": "aefbf071d2ded5d8cc71b0120cae99b970ab4506f5fd6d5b5eb2437b6a025d2a",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b",
        },
        "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0": {
            "ast_sha256": "71b9da445e2db2016510d7655fd999f887cc6b13326eb91e7896e12d425b6fbb",
            "binding": "table_row_caps:reviews",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('reviews', (_c('assignment_id', 'TEXT'), _c('task_id', 'TEXT'), _c('attempt', 'INTEGER'), _c('actor', 'TEXT'), _c('role', 'TEXT'), _c('status', 'TEXT'), _c('opened_event_id', 'TEXT'), _c('closed_event_id', 'TEXT', True)), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 124,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 9,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][9].rows",
            "table_name": "reviews",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "71b9da445e2db2016510d7655fd999f887cc6b13326eb91e7896e12d425b6fbb",
            "table_spec_site_id": "4e45ce6231fd6af84a513f6c401a988bbba7b965c12c95576203c41c3de69e04",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0",
        },
        "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b": {
            "ast_sha256": "27d01446627311084853618cf3545af4a767ea9ca939c1011e31118b797b9f36",
            "binding": "table_row_caps:snapshots",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('snapshots', (_c('snapshot_id', 'TEXT'), _c('snapshot_kind', 'TEXT'), _c('snapshot_sequence', 'INTEGER'), _c('event_id', 'TEXT'), _c('document_sha256', 'TEXT'), _c('document_blob_sha256', 'TEXT'), _c('through_global_sequence', 'INTEGER'), _c('head_event_id', 'TEXT'), _c('head_event_sha256', 'TEXT'), _c('prior_document_sha256', 'TEXT', True), _c('created_at', 'TEXT')), (0,), (1, 2, 0), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 128,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 13,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][13].rows",
            "table_name": "snapshots",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "27d01446627311084853618cf3545af4a767ea9ca939c1011e31118b797b9f36",
            "table_spec_site_id": "7bd9884cddd766196a998045684c0f28a920f0a50891a6e168d7d9ac9bbda745",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b",
        },
        "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a": {
            "ast_sha256": "570b5960e7888fe6a94cc9cc9d9c725de8ec963ccfd18e7179d191e2df22743d",
            "binding": "table_row_caps:remediation_links",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('remediation_links', (_c('link_id', 'TEXT'), _c('source_task_id', 'TEXT'), _c('source_attempt', 'INTEGER'), _c('child_task_id', 'TEXT'), _c('child_attempt', 'INTEGER'), _c('source_event_id', 'TEXT'), _c('child_event_id', 'TEXT'), _c('decision_sha256', 'TEXT'), _c('link_sha256', 'TEXT')), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 123,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 8,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][8].rows",
            "table_name": "remediation_links",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "570b5960e7888fe6a94cc9cc9d9c725de8ec963ccfd18e7179d191e2df22743d",
            "table_spec_site_id": "1fe1ad94e3df90de6fc3f042d37d286292914522b4bc22ec9e7f3e253dd02366",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a",
        },
        "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72": {
            "ast_sha256": "ced10a66c811c98c5760829800b897bab92e18a6d635d56cbf9c2be7dea30cf1",
            "binding": "table_row_caps:idempotency",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('idempotency', (_c('operation_key', 'TEXT'), _c('transaction_id', 'TEXT'), _c('request_sha256', 'TEXT'), _c('response_sha256', 'TEXT'), _c('commit_event_id', 'TEXT'), _c('commit_global_sequence', 'INTEGER'), _c('committed_at', 'TEXT')), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 119,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 4,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][4].rows",
            "table_name": "idempotency",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "ced10a66c811c98c5760829800b897bab92e18a6d635d56cbf9c2be7dea30cf1",
            "table_spec_site_id": "c4ae34b3a69aa97f06d98d75313060be2cf8290c032e63593919813095789b7a",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72",
        },
        "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed": {
            "ast_sha256": "41321b95b46ab4240d118e9ad347aaf58c1dc21456ec07eb88f12b1fbb6f3a0a",
            "binding": "table_row_caps:events",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('events', (_c('global_sequence', 'INTEGER'), _c('event_id', 'TEXT'), _c('event_sha256', 'TEXT'), _c('canonical_json', 'TEXT')), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 118,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 3,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][3].rows",
            "table_name": "events",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "41321b95b46ab4240d118e9ad347aaf58c1dc21456ec07eb88f12b1fbb6f3a0a",
            "table_spec_site_id": "c457e2aaa43bac1efac6887835fc034b2ae6a6aa793284d1f1e0416443ea6eeb",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed",
        },
        "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428": {
            "ast_sha256": "e98f35a3d0537534bea89a539128f69d20e8418fe411720d381b60af58457e34",
            "binding": "table_row_caps:blobs",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('blobs', (_c('sha256', 'TEXT'), _c('schema_id', 'TEXT'), _c('canonical_json', 'TEXT')), (0,), (0,), 300000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 116,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 300000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 1,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][1].rows",
            "table_name": "blobs",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "e98f35a3d0537534bea89a539128f69d20e8418fe411720d381b60af58457e34",
            "table_spec_site_id": "db64ac49a822caa146ccce59c9c43493efea07fa867ab01da4f5847e275d9138",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428",
        },
        "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737": {
            "ast_sha256": "aafcafb39e3622065dedb4d7e15be502da73177301d29ca792d611dcd18f263c",
            "binding": "table_row_caps:claims",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('claims', (_c('claim_id', 'TEXT'), _c('task_id', 'TEXT'), _c('attempt', 'INTEGER'), _c('fence', 'INTEGER'), _c('status', 'TEXT'), _c('actor', 'TEXT'), _c('opened_event_id', 'TEXT'), _c('closed_event_id', 'TEXT', True)), (0,), (0,), 100000)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 117,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 100000,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 2,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][2].rows",
            "table_name": "claims",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "aafcafb39e3622065dedb4d7e15be502da73177301d29ca792d611dcd18f263c",
            "table_spec_site_id": "8022e8bb8dca11ecac4cda6b7d86675a35a33f6586c9fc763a0c88dc2e25af4c",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737",
        },
        "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990": {
            "ast_sha256": "962b5e773f9ea0b63d583e91fd0e4881dfbcfc9a6324d682f06a9e251148cf22",
            "binding": "table_row_caps:attempts",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('attempts', (_c('task_id', 'TEXT'), _c('attempt', 'INTEGER'), _c('predecessor_attempt', 'INTEGER', True), _c('origin_event_id', 'TEXT'), _c('head_task_sequence', 'INTEGER'), _c('head_event_id', 'TEXT'), _c('head_event_sha256', 'TEXT')), (0, 1), (0, 1), 100000)",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 115,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "maximum": 100000,
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "row_index": 0,
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "site_id": "a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "subject_binding": "captured['table_snapshots'][0].rows",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "table_name": "attempts",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_ast_sha256": "962b5e773f9ea0b63d583e91fd0e4881dfbcfc9a6324d682f06a9e251148cf22",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_site_id": "ec260bd0442443c8889247aee1b6017204ef8e638d084f43c64e71cdaa9a3ea8",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
        },
        "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2": {
            "ast_sha256": "4e00e9f257a857095aae9b98fc61c9897eb437deaf1f499a46b5bd529cdf3486",
            "binding": "table_row_caps:schema_documents",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('schema_documents', (_c('schema_id', 'TEXT'), _c('document_sha256', 'TEXT'), _c('canonical_json', 'TEXT')), (0,), (0,), 9)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 125,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 9,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 10,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][10].rows",
            "table_name": "schema_documents",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "4e00e9f257a857095aae9b98fc61c9897eb437deaf1f499a46b5bd529cdf3486",
            "table_spec_site_id": "b6227ea04426526d2328d17483f16b30c61ec141d6e904878016ee72cf70b07c",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2",
        },
        "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b": {
            "ast_sha256": "cd3ea4e9a30f79fb4eac41303e9ff0a25e1f66ba63e4cc1e70039aa3d5c18d7c",
            "binding": "table_row_caps:seals",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a",
            "expression": "_TableSpec('seals', (_c('seal_id', 'TEXT'), _c('runtime_id', 'TEXT'), _c('chain_id', 'TEXT'), _c('seal_type', 'TEXT'), _c('attachment_sha256', 'TEXT'), _c('genesis_event_id', 'TEXT'), _c('genesis_event_sha256', 'TEXT'), _c('manifest_sha256', 'TEXT'), _c('source_event_id', 'TEXT'), _c('created_at', 'TEXT')), (0,), (0,), 1)",
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 127,
            "loop_ast_sha256": "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91",
            "iterator_ast_sha256": "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc",
            "strict_zip_ast_sha256": "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81",
            "maximum": 1,
            "outer_cardinality_gate_ast_sha256": "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 12,
            "selection_semantics": "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL",
            "semantic_function_ast_sha256": "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "semantic_module_ast_sha256": "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            "subject_binding": "captured['table_snapshots'][12].rows",
            "table_name": "seals",
            "table_snapshots_cardinality_site_id": "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a",
            "table_spec_class_ast_sha256": "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d",
            "table_spec_ast_sha256": "cd3ea4e9a30f79fb4eac41303e9ff0a25e1f66ba63e4cc1e70039aa3d5c18d7c",
            "table_spec_site_id": "c56d6606428c4655ca874181b5c350454abb51ac4f47c8faf02c3113b6277668",
            "table_specs_assignment_ast_sha256": "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae",
            "snapshot_type_gate_ast_sha256": "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf",
            "table_read_ast_sha256": "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5",
            "rows_read_ast_sha256": "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937",
            "table_missing_gate_ast_sha256": "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6",
            "rows_missing_gate_ast_sha256": "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1",
            "missing_gate_ast_sha256": "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86",
            "table_identity_gate_ast_sha256": "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5",
            "rows_type_gate_ast_sha256": "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149",
            "row_cap_branch_ast_sha256": "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306",
            "site_id": "048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b",
        },
        "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793": {
            "ast_sha256": (
                "79684afc536b1317fe0d6ba1886d7c84a31feb27a642dd43fca0fe636eef1cf0"
            ),
            "binding": "table_row_caps:schema_registry",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a"
            ),
            "expression": (
                "_TableSpec('schema_registry', (_c('singleton', 'TEXT'), "
                "_c('schema_registry_sha256', 'TEXT'), "
                "_c('canonical_json', 'TEXT')), (0,), (0,), 1)"
            ),
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 126,
            "loop_ast_sha256": (
                "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91"
            ),
            "iterator_ast_sha256": (
                "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc"
            ),
            "strict_zip_ast_sha256": (
                "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81"
            ),
            "maximum": 1,
            "outer_cardinality_gate_ast_sha256": (
                "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a"
            ),
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 11,
            "selection_semantics": (
                "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL"
            ),
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "subject_binding": "captured['table_snapshots'][11].rows",
            "table_name": "schema_registry",
            "table_snapshots_cardinality_site_id": (
                "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
            ),
            "table_spec_class_ast_sha256": (
                "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d"
            ),
            "table_spec_ast_sha256": (
                "79684afc536b1317fe0d6ba1886d7c84a31feb27a642dd43fca0fe636eef1cf0"
            ),
            "table_spec_site_id": (
                "8b93a8c07c34c56e41f154e9c01c69802103c63fbd09b1d6858262c5b70aef2d"
            ),
            "table_specs_assignment_ast_sha256": (
                "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
            ),
            "snapshot_type_gate_ast_sha256": (
                "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf"
            ),
            "table_read_ast_sha256": (
                "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5"
            ),
            "rows_read_ast_sha256": (
                "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937"
            ),
            "table_missing_gate_ast_sha256": (
                "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6"
            ),
            "rows_missing_gate_ast_sha256": (
                "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1"
            ),
            "missing_gate_ast_sha256": (
                "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86"
            ),
            "table_identity_gate_ast_sha256": (
                "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5"
            ),
            "rows_type_gate_ast_sha256": (
                "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149"
            ),
            "row_cap_branch_ast_sha256": (
                "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306"
            ),
            "site_id": (
                "fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793"
            ),
        },
        "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e": {
            "ast_sha256": (
                "603a2ffd90c3e09feac265d108beb5a7a48ec62def22a202fd0f45ca1feb5579"
            ),
            "binding": "table_row_caps:metadata",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a"
            ),
            "expression": (
                "_TableSpec('metadata', (_c('singleton', 'TEXT'), "
                "_c('runtime_id', 'TEXT'), _c('chain_id', 'TEXT'), "
                "_c('runtime_format_version', 'INTEGER'), "
                "_c('event_format_version', 'INTEGER'), "
                "_c('source_kind', 'TEXT'), _c('created_at', 'TEXT'), "
                "_c('manifest_sha256', 'TEXT'), "
                "_c('attachment_sha256', 'TEXT'), "
                "_c('storage_schema_sha256', 'TEXT'), "
                "_c('schema_registry_sha256', 'TEXT'), "
                "_c('genesis_event_id', 'TEXT'), "
                "_c('genesis_event_sha256', 'TEXT'), "
                "_c('repository_generation', 'INTEGER'), "
                "_c('repository_bundle_sha256', 'TEXT'), "
                "_c('global_head_sequence', 'INTEGER'), "
                "_c('global_head_event_id', 'TEXT'), "
                "_c('global_head_event_sha256', 'TEXT'), "
                "_c('latest_checkpoint_sha256', 'TEXT', True), "
                "_c('active_selector_generation', 'INTEGER'), "
                "_c('active_selector_sha256', 'TEXT'), "
                "_c('selector_history_sha256', 'TEXT'), "
                "_c('authority_binding_sha256', 'TEXT', True), "
                "_c('anchor_status', 'TEXT'), "
                "_c('currentness_status', 'TEXT'), "
                "_c('authorizing_use', 'TEXT')), (0,), (0,), 1)"
            ),
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 121,
            "loop_ast_sha256": (
                "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91"
            ),
            "iterator_ast_sha256": (
                "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc"
            ),
            "strict_zip_ast_sha256": (
                "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81"
            ),
            "maximum": 1,
            "outer_cardinality_gate_ast_sha256": (
                "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a"
            ),
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 6,
            "selection_semantics": (
                "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL"
            ),
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "subject_binding": "captured['table_snapshots'][6].rows",
            "table_name": "metadata",
            "table_snapshots_cardinality_site_id": (
                "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
            ),
            "table_spec_class_ast_sha256": (
                "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d"
            ),
            "table_spec_ast_sha256": (
                "603a2ffd90c3e09feac265d108beb5a7a48ec62def22a202fd0f45ca1feb5579"
            ),
            "table_spec_site_id": (
                "345667d74d800a8ab46094cfecc00b6e867bab5a5dd87a6ad77caedc5e68d31b"
            ),
            "table_specs_assignment_ast_sha256": (
                "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
            ),
            "snapshot_type_gate_ast_sha256": (
                "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf"
            ),
            "table_read_ast_sha256": (
                "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5"
            ),
            "rows_read_ast_sha256": (
                "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937"
            ),
            "table_missing_gate_ast_sha256": (
                "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6"
            ),
            "rows_missing_gate_ast_sha256": (
                "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1"
            ),
            "missing_gate_ast_sha256": (
                "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86"
            ),
            "table_identity_gate_ast_sha256": (
                "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5"
            ),
            "rows_type_gate_ast_sha256": (
                "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149"
            ),
            "row_cap_branch_ast_sha256": (
                "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306"
            ),
            "site_id": (
                "badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e"
            ),
        },
        "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18": {
            "ast_sha256": (
                "ba8868ef601db01139797d863b6a2c9b22da8b492b93b14451610ab10346c65f"
            ),
            "binding": "table_row_caps:legacy_archive",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a"
            ),
            "expression": (
                "_TableSpec('legacy_archive', (_c('singleton', 'TEXT'), "
                "_c('source_runtime_id', 'TEXT'), _c('source_assurance', "
                "'TEXT'), _c('source_attachment_sha256', 'TEXT'), "
                "_c('source_storage_inventory_sha256', 'TEXT'), "
                "_c('source_backup_sha256', 'TEXT'), "
                "_c('source_global_head_id', 'TEXT'), "
                "_c('source_global_head_sha256', 'TEXT'), "
                "_c('source_row_archive_sha256', 'TEXT'), "
                "_c('source_projection_sha256', 'TEXT'), "
                "_c('migration_plan_sha256', 'TEXT'), "
                "_c('frozen_verifier_commit', 'TEXT'), "
                "_c('frozen_verifier_closure_sha256', 'TEXT'), "
                "_c('source_repository_bundle_sha256', 'TEXT'), "
                "_c('archive_blob_sha256', 'TEXT'), "
                "_c('projection_blob_sha256', 'TEXT')), (0,), (0,), 1)"
            ),
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "line": 120,
            "loop_ast_sha256": (
                "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91"
            ),
            "iterator_ast_sha256": (
                "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc"
            ),
            "strict_zip_ast_sha256": (
                "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81"
            ),
            "maximum": 1,
            "outer_cardinality_gate_ast_sha256": (
                "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a"
            ),
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 5,
            "selection_semantics": (
                "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL"
            ),
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "subject_binding": "captured['table_snapshots'][5].rows",
            "table_name": "legacy_archive",
            "table_snapshots_cardinality_site_id": (
                "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
            ),
            "table_spec_class_ast_sha256": (
                "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d"
            ),
            "table_spec_ast_sha256": (
                "ba8868ef601db01139797d863b6a2c9b22da8b492b93b14451610ab10346c65f"
            ),
            "table_spec_site_id": (
                "1a89ac6ff9afbe3ef25bba879d53ae71f86bc0f26772cf0676ef4230191e61b9"
            ),
            "table_specs_assignment_ast_sha256": (
                "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
            ),
            "snapshot_type_gate_ast_sha256": (
                "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf"
            ),
            "table_read_ast_sha256": (
                "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5"
            ),
            "rows_read_ast_sha256": (
                "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937"
            ),
            "table_missing_gate_ast_sha256": (
                "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6"
            ),
            "rows_missing_gate_ast_sha256": (
                "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1"
            ),
            "missing_gate_ast_sha256": (
                "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86"
            ),
            "table_identity_gate_ast_sha256": (
                "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5"
            ),
            "rows_type_gate_ast_sha256": (
                "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149"
            ),
            "row_cap_branch_ast_sha256": (
                "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306"
            ),
            "site_id": (
                "da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18"
            ),
        },
        "8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a": {
            "ast_sha256": (
                "5cc3d3beb8e159ca0e64e55d0e4118b865f4b82c4bb8ea4771b7f4339bd8a141"
            ),
            "binding": "table_row_caps:migrations",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "41ab1d3712b89ce44af6a77c3a694346032502dcad0bca11a5cd6077d06be79a"
            ),
            "expression": (
                "_TableSpec('migrations', (_c('migration_id', 'TEXT'), "
                "_c('migration_sequence', 'INTEGER'), _c('event_id', 'TEXT'), "
                "_c('payload_sha256', 'TEXT'), _c('created_at', 'TEXT')), "
                "(0,), (1, 0), 0)"
            ),
            "kind": "BOUND_TABLE_ROW_CAP_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "e40732e96491df8527c69672882d11dbfd2c1cb319f334cbe62ab7efd4812b91"
            ),
            "iterator_ast_sha256": (
                "a403a440387a29fa43204ecbcf0d89a81197079ca4ecd0d36f442c833e9f13cc"
            ),
            "strict_zip_ast_sha256": (
                "c2b2db9f47e7091791368bf16ce15e2cac2868d2f0a75d5315bd30559e12ab81"
            ),
            "maximum": 0,
            "outer_cardinality_gate_ast_sha256": (
                "c6b3f092d05483b71b492155a293155bbdd8b38dcbb5a445423afc9c45409d3a"
            ),
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 7,
            "selection_semantics": (
                "POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL"
            ),
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "semantic_module_ast_sha256": (
                "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857"
            ),
            "subject_binding": "captured['table_snapshots'][7].rows",
            "table_name": "migrations",
            "table_snapshots_cardinality_site_id": (
                "56e98674b7d3cea2c63839f264be9afd63b55b3d9acb1dfc321cf1c4dc60744a"
            ),
            "table_spec_class_ast_sha256": (
                "97b4789d083370dabe775cbc0a17a023f9786da4a9f1b69ee89aa7a83b11b47d"
            ),
            "table_spec_ast_sha256": (
                "5cc3d3beb8e159ca0e64e55d0e4118b865f4b82c4bb8ea4771b7f4339bd8a141"
            ),
            "table_spec_site_id": (
                "b54cc7867c718ef5b8f6e9566da8b1efe64bde1d302fc15043aa96dd04df0c3d"
            ),
            "table_specs_assignment_ast_sha256": (
                "60d9b16f6030dce58a70f4493dc201afaabb6bd0d1a797508232dd88a6015cae"
            ),
            "snapshot_type_gate_ast_sha256": (
                "155e0217b4406bfc3bfa72b85679d542a1f71cb814e7f957bdb92e8e489fc3bf"
            ),
            "table_read_ast_sha256": (
                "ad5224162b5f5ef63f5d7698b1b8758b3db070e1e33250bab7635f809aac76b5"
            ),
            "rows_read_ast_sha256": (
                "677411f1fdeb57709c313f0579f62a2d5ffe919e92cebfffec0aa69297c7d937"
            ),
            "table_missing_gate_ast_sha256": (
                "110275f6f01f61acc9d39c012d46be5926ae7fd873f99eb1048406f68d99eda6"
            ),
            "rows_missing_gate_ast_sha256": (
                "017cdb5e6ac07bde32192e3257f0f6cfe4feb52e2b23b4857d278b5bebac83b1"
            ),
            "missing_gate_ast_sha256": (
                "5b0670163dbd36c4ff23e8118fe5cd5d823ec1823f9edf4377ef28d7b3cf0d86"
            ),
            "table_identity_gate_ast_sha256": (
                "7bcc4099d0adabfb3853cd6769bd07df9acd85b4206f0dd984655e12783d14d5"
            ),
            "rows_type_gate_ast_sha256": (
                "4006c58377860796372c6a7ba0ade5432be7826ac1c221d92debfbb3e1b49149"
            ),
            "row_cap_branch_ast_sha256": (
                "f08103d3d93095d12467bcaa94798c7cf80a06591850d2c470a182ce920a2306"
            ),
        },
        "d59dabf071e0d9cce0c5d6e1478ce6aa55a09362b85136709a4df94bf19966e0": {
            "ast_sha256": (
                "17227f1bc17a07851a3fe42051e2461d4d430bf79f8ce789972835865d82b350"
            ),
            "expression": "MAX_BLOBS = 300000",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "9cd4a36115b048b5729c12787474b202859dd786e34b645ab8b647a5b68b76c3": {
            "ast_sha256": (
                "8dc4ce59580dbb69690973f368094a14a3292b63e1c523a65abb87230e60c4ff"
            ),
            "binding": "cardinalities:blobs",
            "branch_key": "blobs",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "807681eb5829047729803ad4290cd3239097de959106e756ab8bd52329894e24"
            ),
            "comparison_assignment_ast_sha256": (
                "0ac4a3c116faf2d3b271a709a0b15171fa566779bb8e03797b6271aaaec94018"
            ),
            "expression": "('blobs', 0, MAX_BLOBS)",
            "invalid_branch_ast_sha256": (
                "10f692935ade01e94f5748199c52cdc242aa0260a5c88603a03dd3710c13accb"
            ),
            "kind": "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "240c758d427bfefb4cd9ae2f020a6c8d8212178637c304811e1751dea8b98e2f"
            ),
            "maximum_expression": "MAX_BLOBS",
            "minimum_expression": "0",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "result_assignment_ast_sha256": (
                "f7babf5f583439c6651955a1f94cd7ded828a872da0550f437198585bcdfc6e6"
            ),
            "row_index": 1,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "subject_binding": "captured['blobs']",
            "subject_expression": "captured[name]",
            "subject_lookup_ast_sha256": (
                "c7fee319573f6b06586df87192a91ea53633133dc1970225b005d91733d96f34"
            ),
            "subject_loop_ast_sha256": (
                "9e3c2a4b8b7a01aefe2d991cbd889eb3e438c2849d75e31b89ed89afd9265b41"
            ),
            "subject_row_ast_sha256": (
                "63eb8b4b003aa9cb12dd66a8a78da47559ae90e9992d5cafa645ef0f85bf8cc0"
            ),
            "subject_table_assignment_ast_sha256": (
                "2c8b915ebfb7a82cd65a78509e4ef1077045440266f37fa5e284f73a2e6020f5"
            ),
            "table_assignment_ast_sha256": (
                "49d78a29c5302a5f0c2a9d4edaef5072af28db8375c35677cb1e1effd2e25c94"
            ),
            "table_name": "cardinalities",
            "validity_gate_ast_sha256": (
                "80f43e2757b87785145812c7bbdd11dd7f2b75ca7983a0e20657f51bf0493557"
            ),
        },
        "4c738024dfcbda75cf4c6a621c2b51624a9278bb5b4e10b912c43f1dbd5be208": {
            "ast_sha256": (
                "80532fc78db8b03d02cffb2670a190e982bf2fd25f47d985dbea2ed35ac44067"
            ),
            "expression": "MAX_CHECKPOINT_COPIES = 49999",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "e97220f7bc97ef6a73c731794238c6f6e2ffe2c1b744e945c35cde22afaa2f13": {
            "ast_sha256": (
                "795c31fe76805ff8a2cbf3d0d459bfd4a9156dd3a95b24253eacee21334c96f1"
            ),
            "binding": "cardinalities:checkpoint_copies",
            "branch_key": "checkpoint_copies",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "807681eb5829047729803ad4290cd3239097de959106e756ab8bd52329894e24"
            ),
            "comparison_assignment_ast_sha256": (
                "0ac4a3c116faf2d3b271a709a0b15171fa566779bb8e03797b6271aaaec94018"
            ),
            "expression": "('checkpoint_copies', 0, MAX_CHECKPOINT_COPIES)",
            "invalid_branch_ast_sha256": (
                "10f692935ade01e94f5748199c52cdc242aa0260a5c88603a03dd3710c13accb"
            ),
            "kind": "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "240c758d427bfefb4cd9ae2f020a6c8d8212178637c304811e1751dea8b98e2f"
            ),
            "maximum_expression": "MAX_CHECKPOINT_COPIES",
            "minimum_expression": "0",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "result_assignment_ast_sha256": (
                "f7babf5f583439c6651955a1f94cd7ded828a872da0550f437198585bcdfc6e6"
            ),
            "row_index": 4,
            "semantic_function_ast_sha256": (
                "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f"
            ),
            "subject_binding": "captured['checkpoint_copies']",
            "subject_expression": "captured[name]",
            "subject_lookup_ast_sha256": (
                "c7fee319573f6b06586df87192a91ea53633133dc1970225b005d91733d96f34"
            ),
            "subject_loop_ast_sha256": (
                "9e3c2a4b8b7a01aefe2d991cbd889eb3e438c2849d75e31b89ed89afd9265b41"
            ),
            "subject_row_ast_sha256": (
                "c11892f9255d14fdda980db1e9cbfe7d938ad6b97e1fac74cc2362b1fecd2773"
            ),
            "subject_table_assignment_ast_sha256": (
                "2c8b915ebfb7a82cd65a78509e4ef1077045440266f37fa5e284f73a2e6020f5"
            ),
            "table_assignment_ast_sha256": (
                "49d78a29c5302a5f0c2a9d4edaef5072af28db8375c35677cb1e1effd2e25c94"
            ),
            "table_name": "cardinalities",
            "validity_gate_ast_sha256": (
                "80f43e2757b87785145812c7bbdd11dd7f2b75ca7983a0e20657f51bf0493557"
            ),
        },
        "a1c0d45cbce3ceffdaeb036a93474801b525220e1d16ab5505dba14115313caa": {
            "ast_sha256": "62849f3abfb53a58b818ddb723fe42e71b29a0c828a6131fa3a9e59ecded2665",
            "expression": "MAX_BLOB_BYTES = 16777216",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "1ef42fea7eca273c2040d72810435052d0241a4e9a4d7ba63598548d95d5249c": {
            "ast_sha256": "077ef96d0da69583a93af4ba54fa4d12823c51a69df9d03334b98a80420adab6",
            "expression": "len(body) > MAX_BLOB_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
        },
        "f0929588df702f47d6a2f6fe255d87b6bf4a0e083cbfdbb0cc0f699973edc2ab": {
            "ast_sha256": "acc40cd702b61b819d926d1541c5e0b7cf45ac859e6b3aab7c78f4a8a8b82ec3",
            "expression": "MAX_DEPENDENCY_CLOSURE_BYTES = 1048576",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py", "qualname": "<module>",
        },
        "344950b527bcecb073b777c4bbf743de50dd920bd4aa76dbbf58045ff9f00ab5": {
            "ast_sha256": "c9eac5f8c0d8b650b2862eedc45da5591c5f8c5923591c302ce4d2d89c6f2c3a",
            "expression": "len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>.validate_verifier_dependency_closure",
        },
        "7db6dd7c8847d19d5b451a58dc88346ff1d16db0d6c1b2dc62eec0b0780f662a": {
            "ast_sha256": "ba0cc04137f6af99aa5753c34f3115be0e76d4f606c7d78dcdd063ae6ac833e8",
            "expression": "MAX_EVENT_BYTES = 1048576",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "8a65115a6e18d3b2a23dc717ac5500638641dc0fe90a227554e9b4b500464534": {
            "ast_sha256": "2e3b9d0115bcd53ae1e76bdd4f4885007c1af420dcfd2f8efcaa0012863de637",
            "binding": "byte_collections:events",
            "branch_key": "events",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "349ec1bed6c7edd66926c28b7f33deede98d6f01af5a5c461476b820dfa91e7d"
            ),
            "expression": "('events', captured['events'], MAX_EVENT_BYTES)",
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
            ),
            "maximum_expression": "MAX_EVENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 0,
            "subject_expression": "captured['events']",
            "table_assignment_ast_sha256": (
                "4ca5b4b0036969d77d3d8235fd0a8c438e9e1a5cd526f970ffc6ec8bb57d8bbe"
            ),
            "table_name": "byte_collections",
        },
        "fa0e657aa776634a22b750a8fce2c4ed1ff0de61ff58841530de76225f9e8630": {
            "ast_sha256": "f5638cd91628957d8b4a135acdb33b4511db7b92bc8c0257c98fce381785f054",
            "expression": "MAX_SCHEMA_DOCUMENT_BYTES = 262144",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "9c9756b7f77e91caf4044c0cb19c52dc2d0335a749fc7690e00ddd6a9a1b6b38": {
            "ast_sha256": "fdfee50efca938e2d5ba486b5d60f5546a4b41d48abe26424ea260ecc0eba848",
            "expression": "body_size > MAX_SCHEMA_DOCUMENT_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
        },
        "e5ebe2c841739dfbb79d7fb7c04879320c9d4b5313534822b1e3696798afc40d": {
            "ast_sha256": "f5638cd91628957d8b4a135acdb33b4511db7b92bc8c0257c98fce381785f054",
            "expression": "MAX_SCHEMA_DOCUMENT_BYTES = 262144",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py", "qualname": "<module>",
        },
        "222b398c640f6311f8597b487de626c2dfb65f4340a6fb1ece58292788c9b8d3": {
            "ast_sha256": "e25ec07a4825c87577cfe2a456f480299253f5df7b39ba688d308865ac80b647",
            "expression": (
                "len(record.canonical_json) > MAX_SCHEMA_DOCUMENT_BYTES"
            ),
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_bundle_findings",
        },
        "61d3dcc5d5ed733e6d561edeb43ddcc00ab2aa8fc899b09353733877ea76a721": {
            "ast_sha256": "e52194ceb94539ec59882759e12f46f0251a72a46dd23b0b6c864145183a0cc7",
            "expression": "MAX_SCHEMA_REF_NODES = 4096",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py", "qualname": "<module>",
        },
        "4650c76c2ae3e065cd5767e97b8a59d917415ba1dfc73f79f0efd8b09f4f3eef": {
            "ast_sha256": "2fb2b56ab91ddce7b42b0f3219bffaeca1d02866bb96b9b501729f3a0dea364d",
            "expression": "len(edges) > MAX_SCHEMA_REF_NODES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_safety_findings",
        },
        "4c9346726487e13663e822fd8b63e995c6066a487dfbe2b6350e051ce2440384": {
            "ast_sha256": "6fafd6df3a7e6d64e740da00af9075c4311977b2b9a16158f6f8d8cc5ce1e11d",
            "expression": "MAX_SCHEMA_REGISTRY_BYTES = 262144",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "a5edf2e2129f2918e47e765f74655da1e97a725f42015d1e38dbb7e6a92b50e4": {
            "ast_sha256": "9f48b1731194adc88917d3878f5f78f7b7c12ac2b2967231524adfd18cb2f0b3",
            "binding": "byte_fields:schema_registry",
            "branch_key": "schema_registry",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "0d8566afcf1d2933abead1ae497a40b4dc65fef9a3a52ae302dc604bbf8c5507"
            ),
            "expression": (
                "('schema_registry', captured['schema_registry'], "
                "MAX_SCHEMA_REGISTRY_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "6e9143ae8f7229364ce3b636e4723a8ea2c44bc01016c341d4d9c2644b201941"
            ),
            "maximum_expression": "MAX_SCHEMA_REGISTRY_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 4,
            "subject_expression": "captured['schema_registry']",
            "table_assignment_ast_sha256": (
                "dcc4e9f632d4f0014570e55c64f97b42eea6719a5ed2c35966833b065189aa08"
            ),
            "table_name": "byte_fields",
        },
        "cc9e6904b1fdb98deea9fd35ddc4ae864aa572cbf5d963addbf8cc42beae4522": {
            "ast_sha256": "6fafd6df3a7e6d64e740da00af9075c4311977b2b9a16158f6f8d8cc5ce1e11d",
            "expression": "MAX_SCHEMA_REGISTRY_BYTES = 262144",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py", "qualname": "<module>",
        },
        "d02eb8dbac3f0359f160e1fb6259b5a438ec699a64cca7cd05d94c5ab86b1683": {
            "ast_sha256": "3d570f7252edeeb7daf2e8676ab4c322cd68d51da26f1a9fe8e5eca5b89baace",
            "expression": "len(image.schema_registry) > MAX_SCHEMA_REGISTRY_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_bundle_findings",
        },
        "8927485f8c04590dc06fa8d3bffde6e82517d898ec72637dbf758e21a56996d8": {
            "ast_sha256": "ca97a8e0d1ddfa8d957f0c575d0a047cfd65d3374836a9f8804e03dee7f7d57b",
            "expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES = 1048576",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "55746a75fc2eb842245ba7bcdad51086efbc304200a958f592b064757c9b9f1c": {
            "ast_sha256": "5d665629c14569b1b89a8061ed4c973af383ecfb2a058da39e9bfad3a2acdcd0",
            "binding": "byte_fields:verifier_dependency_closure",
            "branch_key": "verifier_dependency_closure",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "0d8566afcf1d2933abead1ae497a40b4dc65fef9a3a52ae302dc604bbf8c5507"
            ),
            "expression": (
                "('verifier_dependency_closure', "
                "captured['verifier_dependency_closure'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "6e9143ae8f7229364ce3b636e4723a8ea2c44bc01016c341d4d9c2644b201941"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
            "row_index": 1,
            "subject_expression": "captured['verifier_dependency_closure']",
            "table_assignment_ast_sha256": (
                "dcc4e9f632d4f0014570e55c64f97b42eea6719a5ed2c35966833b065189aa08"
            ),
            "table_name": "byte_fields",
        },
        "82ac9bd0ba24bed59304ea8a2aad0cbaa7bdf92db3e332e58b661285512990b6": {
            "ast_sha256": "41021ef757a60ef8081a9ca1443e3ea70a01f06cefad4a965b458f8e6101fea5",
            "binding": "byte_fields:manifest", "branch_key": "manifest",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "0d8566afcf1d2933abead1ae497a40b4dc65fef9a3a52ae302dc604bbf8c5507"
            ),
            "expression": (
                "('manifest', captured['manifest'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "6e9143ae8f7229364ce3b636e4723a8ea2c44bc01016c341d4d9c2644b201941"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host", "row_index": 2,
            "subject_expression": "captured['manifest']",
            "table_assignment_ast_sha256": (
                "dcc4e9f632d4f0014570e55c64f97b42eea6719a5ed2c35966833b065189aa08"
            ),
            "table_name": "byte_fields",
        },
        "7ea348002f2b6caf5e341cc7739453f80b8e576f18a354da8cccd1432ad3a6cc": {
            "ast_sha256": "c4e33d4a6fbca0dc45c5d2bc9dab4ca8bd2c2afecbf55ac89a2787a59b3f53fe",
            "binding": "byte_fields:attachment", "branch_key": "attachment",
            "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "0d8566afcf1d2933abead1ae497a40b4dc65fef9a3a52ae302dc604bbf8c5507"
            ),
            "expression": (
                "('attachment', captured['attachment'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "6e9143ae8f7229364ce3b636e4723a8ea2c44bc01016c341d4d9c2644b201941"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host", "row_index": 3,
            "subject_expression": "captured['attachment']",
            "table_assignment_ast_sha256": (
                "dcc4e9f632d4f0014570e55c64f97b42eea6719a5ed2c35966833b065189aa08"
            ),
            "table_name": "byte_fields",
        },
        "9a911b0807e818c67215b24ca2aef14d904826e042c65cfb5d74f51f989ef275": {
            "ast_sha256": "f6687768c44df59ed8d8a90f0678c8cb81347f40a925fd56aae1653e9421853c",
            "binding": "byte_collections:checkpoint_copies",
            "branch_key": "checkpoint_copies", "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "349ec1bed6c7edd66926c28b7f33deede98d6f01af5a5c461476b820dfa91e7d"
            ),
            "expression": (
                "('checkpoint_copies', captured['checkpoint_copies'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host", "row_index": 1,
            "subject_expression": "captured['checkpoint_copies']",
            "table_assignment_ast_sha256": (
                "4ca5b4b0036969d77d3d8235fd0a8c438e9e1a5cd526f970ffc6ec8bb57d8bbe"
            ),
            "table_name": "byte_collections",
        },
        "4da76883b64b45ef3e46ca843d83de74162b42fc5649008a595c806277a47a99": {
            "ast_sha256": "4d5afd2bc3a80702c612fb94b96d3561a1bd398c7347978016a58fb7aa75d498",
            "binding": "byte_collections:selector_history",
            "branch_key": "selector_history", "classification": "UNCLASSIFIED",
            "comparator_site_id": (
                "349ec1bed6c7edd66926c28b7f33deede98d6f01af5a5c461476b820dfa91e7d"
            ),
            "expression": (
                "('selector_history', captured['selector_history'], "
                "MAX_BOOTSTRAP_DOCUMENT_BYTES)"
            ),
            "kind": "BOUND_TABLE_COMPARISON_BINDING",
            "loop_ast_sha256": (
                "9562db8f41443d06b883ea52b0d1be726a772b412740d6e1732e9031486e5be6"
            ),
            "maximum_expression": "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host", "row_index": 2,
            "subject_expression": "captured['selector_history']",
            "table_assignment_ast_sha256": (
                "4ca5b4b0036969d77d3d8235fd0a8c438e9e1a5cd526f970ffc6ec8bb57d8bbe"
            ),
            "table_name": "byte_collections",
        },
        "5e7fc3b44c63b42e94213efd280dd3af90eac0beb4a2b28f600a5284f17fc3b4": {
            "ast_sha256": "d1a354657b6c476434bc4f4fc14c9dfb03fbf71903f2006d7691a0aa173b9e28",
            "expression": "MAX_ARGUMENTS = 8",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>",
        },
        "3d85d6c3d9c53b2d68ee976d4b159cc92ae9fd506ad608d00ff0563db5864209": {
            "ast_sha256": "c6be7015b670b520b96e47b34766d5482080c89b475479e69eb9d2559b347b56",
            "expression": "len(self.arguments) > MAX_ARGUMENTS",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>.TransitionIntent.__post_init__",
        },
        "13130db6d96d447bd0bec45528c39f4354a2897e282585c7b4976335e25b025c": {
            "ast_sha256": "a1e1eb351f324ed9a3c863d95337148000d6217b3c64640791c7ff92dff0c678",
            "expression": "MAX_GROUP_EVENTS = 10002",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>",
        },
        "6109c0c4afb317c7bde39b19501f7de6b627528dd36f967c82e2ed311fbfc0ca": {
            "ast_sha256": "8d647e8afdc84a49b2522900c6d1a78bba63e3186aa356319adc778ceee232b4",
            "expression": "len(self.semantic_event_ids) > MAX_GROUP_EVENTS",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>.TransitionIntent.__post_init__",
        },
        "2663812aee226be4f57a1862523798243d7df5a12a1d9e29f586ec8e7ded5638": {
            "ast_sha256": "a93eecb8c94bf5a15cfc97ed14385a9a530cdc3d19bf4ef7710b324343f2938f",
            "expression": "MAX_TASKS = 100000",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>",
        },
        "3d07b02992a995d0a13d408dda7d2acf04e1c5a9d185f98651814d6dfff2b59d": {
            "ast_sha256": "0ebc231f6a236beb3fd71102ba6df475322af9d9b7d0e8f7365d50a3b06c9850",
            "expression": "len(self.tasks) > MAX_TASKS",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>.ReducerState.__post_init__",
        },
        "0f3792a9755d878d6e5a60afd21ef8e1d38c30f3be3d59879b6cfa860754f465": {
            "ast_sha256": "e23379a03d5aaa2152cba45ef0f923a4fa13a5783dc5aa960ec8d80141bd9b5d",
            "expression": "len(self._tasks) + added_tasks > MAX_TASKS",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_transition.py",
            "qualname": "<module>._TransitionWorkspace._precheck",
        },
        "18d9f6c7a27e97c092460277fc35bbf9151791127dd0da5a161a8866ef04bbcf": {
            "ast_sha256": "d62d04ec8b3667377679790b50cb1338a10b1f165362421da6480b4b8b0cf298",
            "expression": "MAX_SCHEMA_BUNDLE_BYTES = 2097152",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py", "qualname": "<module>",
        },
        "4a75bf21a088cd48d5c1b38b2b3157fc47542b0132b562be3699e94858a65c9e": {
            "ast_sha256": "9c3e07769ef579a9d7fdb256d86ee59cb3029cc0b7628de7356bbdae6a666f3f",
            "expression": "schema_bundle_bytes > MAX_SCHEMA_BUNDLE_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_image.py",
            "qualname": "<module>.inspect_runtime_image_host",
        },
        "2d673fb49e50239b37577ac23e4f6fdbf899523908d338e3618993594ab5f410": {
            "ast_sha256": "d62d04ec8b3667377679790b50cb1338a10b1f165362421da6480b4b8b0cf298",
            "expression": "MAX_SCHEMA_BUNDLE_BYTES = 2097152",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py", "qualname": "<module>",
        },
        "344713dc75b24db9402649b88570c54a438e5b3b9f17dac677b8cd4313825df4": {
            "ast_sha256": "35a0272498d0eebe546fafa708a8f20b54b2e09edd2b86f0b0ee39af405ded6e",
            "expression": "raw_total > MAX_SCHEMA_BUNDLE_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_bundle_findings",
        },
        "4ba11eee3bbe1d3fa772fabebf0edc386903f94c9862c242c7124b8bf0cf6cb6": {
            "ast_sha256": "cae1123c39910904bae21ca4916212d1125cd36a8cba70fd4ef7c0a6dc11b1e2",
            "expression": "len(image.storage_descriptor) > MAX_SCHEMA_BUNDLE_BYTES",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>.verify_runtime_image",
        },
        "fc3a2cf8ca0ab37c1fedcfb108152b40bd65fec0207eac9cd9b3f7f32b8cfd27": {
            "ast_sha256": "4fe28d2328f0988be50eeb9a03c2fdcc3203a4f5f7cd1e98186c9912e1b6d7f0",
            "expression": "_PORTABLE_PATH_MAX = 4096",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>",
        },
        "ab8d61b1084c8ac24f8b434b52065e9fc3c5dce60285fed332f3489d165b03d3": {
            "ast_sha256": "8ed89dcab2f8359c3fc5f4fc5e3ba66dc6e581fb7c7a074fb746651176bb02f1",
            "expression": "len(path) > _PORTABLE_PATH_MAX",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>._path",
        },
        "9313b4636313fad249f6a01b9e4ef96f22ef88b10fa98ca95a736d0ce994c3df": {
            "ast_sha256": "3a78f1117ccf4cb35e9d2da443f7d4a1e41a26af90ac4974a5f8e706f2034e15",
            "expression": "_PORTABLE_COMPONENT_MAX = 255",
            "kind": "MODULE_NUMERIC_ASSIGNMENT", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>",
        },
        "80d3960b21e42ebc549ca5eabd07e811430b1628150d9eb1e8922d491dc86072": {
            "ast_sha256": "c9b3aa94c2aa41fb4b8c0262e233431f6b59c9426c1d3dd16a9b807693b5a57c",
            "expression": "len(component) > _PORTABLE_COMPONENT_MAX",
            "kind": "BOUND_COMPARISON", "occurrence": 1,
            "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>._path",
        },
        "7b99b5408a023f557be70736b52ecf6a8de4d8594b0da6318cacb3c9680cf5fc": {
            "ast_sha256": "5cd8d83fdc8fcb85f3868c44ee4242883616d1207ce2b67430dc953430968850",
            "expression": "token[1:]", "kind": "NUMERIC_SLICE",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>._parse_integer_token",
        },
        "90292d8f8df61b2ee109adf7df0d0d4e44c2cdf5a6f70c887e7e5228d4cb8657": {
            "ast_sha256": "bc45ff1128f5c9321bcc3ae1ab23ea371e7da3bccc0093bc3adb6058b4d9ccec",
            "expression": "len(digits) > 19", "kind": "BOUND_COMPARISON",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_closure.py",
            "qualname": "<module>._parse_integer_token",
        },
        "6e95fce4ad2ed77d84d5bfaad79566cb4276adc28054fb8bde30b0bbb5c911c5": {
            "ast_sha256": "9ab1899fa2101a4b7074105f5ac87af558a78e1760ef2872d1dcc375052e7164",
            "expression": "child[8:]", "kind": "NUMERIC_SLICE",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_safety_findings.walk",
        },
        "66956e9e92ceed3f5128e1dc746a920e18ce5b51eafd243c43d0500fb9917474": {
            "ast_sha256": "41bdf044e5490f0b5d7a2e86320284ecb87b687dfdbeaf1751f15b408115ea99",
            "expression": "len(token) > 64", "kind": "BOUND_COMPARISON",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_safety_findings.walk",
        },
        "7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd": {
            "ast_sha256": "b678b7f3688c2ab10b1173390a215e5a600d71d5eea5ed9e6e6578b6a567416e",
            "expression": "len(name) > 64", "kind": "BOUND_COMPARISON",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_verifier.py",
            "qualname": "<module>._schema_safety_findings",
        },
        "be6c857e6fce329131b4461868fe22a9f6a710daacc677a63e55a78298dc342c": {
            "ast_sha256": "8119b6e4c3865b1881f9e783f4f3029f856b1677b79b9f89a708f5c48ba68159",
            "expression": "depth > 128", "kind": "BOUND_COMPARISON",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_codec.py",
            "qualname": "<module>._validate",
        },
        "299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8": {
            "ast_sha256": "0d4011ec1ea3c0d77575c2f611d8b025d056326703fa6cd40498c6fe820d977e",
            "expression": "bounded(code, 128)", "kind": "BOUND_HELPER_CALL",
            "occurrence": 1, "path": "src/edgelab/runtime_v2_initial.py",
            "qualname": "<module>._Sink.add",
        },
    }
    for site_id, expected in site_shapes.items():
        record = sites.get(site_id)
        if record is None:
            raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_MISSING", site_id)
        if (
            site_id
            == "0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4"
            and record != expected
        ) or any(record.get(key) != value for key, value in expected.items()):
            raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_SHAPE", site_id)

    closure_tree = ast.parse(
        source_bytes["src/edgelab/runtime_v2_closure.py"],
        filename="src/edgelab/runtime_v2_closure.py",
    )
    closure_functions = {
        node.name: node
        for node in closure_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_parse_integer_token", "_parse_closure_json"}
    }
    if set(closure_functions) != {"_parse_integer_token", "_parse_closure_json"}:
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_FUNCTION",
            "src/edgelab/runtime_v2_closure.py",
        )
    for function_name, expected_digest in (
        (
            "_parse_integer_token",
            "93f3332d484055779849d85784ce4bc5b9d2d406838513e75e80c42edb2492fd",
        ),
        (
            "_parse_closure_json",
            "379d4890883b5519fa33ebf5d305ae803c8627b1dd0599db854ec191bce50f09",
        ),
    ):
        function_dump = ast.dump(
            closure_functions[function_name],
            annotate_fields=True,
            include_attributes=False,
        ).encode("utf-8")
        if _sha256(function_dump) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE",
                "src/edgelab/runtime_v2_closure.py",
            )

    codec_path = "src/edgelab/runtime_v2_codec.py"
    codec_tree = ast.parse(source_bytes[codec_path], filename=codec_path)
    codec_functions = {
        node.name: node
        for node in codec_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_validate", "canonical_json", "parse_canonical_json"}
    }
    if set(codec_functions) != {
        "_validate", "canonical_json", "parse_canonical_json"
    }:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", codec_path)
    codec_function_profiles = (
        ("_validate", "aa685f536f498f68e19e5658d163306608357e6ef66461b18d6cee56d42229f1"),
        ("canonical_json", "66ffdc85016ebfac15fac6de24e50542bd2dd8dd9317f8dd0d66e1d370be3473"),
        ("parse_canonical_json", "52886dcd3e9db3c47e7d6b3b7e60f440d48172ef723a0cd95f5d04bed4633bda"),
    )
    for function_name, expected_digest in codec_function_profiles:
        if _sha256(ast.dump(
            codec_functions[function_name],
            annotate_fields=True,
            include_attributes=False,
        ).encode("utf-8")) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", codec_path
            )
    validate_function = codec_functions["_validate"]
    codec_node_profiles = (
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.Compare)
                  and getattr(node, "lineno", None) == 35), None),
            "8119b6e4c3865b1881f9e783f4f3029f856b1677b79b9f89a708f5c48ba68159",
        ),
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.If)
                  and getattr(node, "lineno", None) == 35), None),
            "12e3a43a51149fa82cf0d27b247ca1471a110f3718d3f73b7ee027ea25f3b96a",
        ),
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 36), None),
            "4f66b6fc9199097a2fc2d4df0d0ffb0cdf1dcb77cfbfc775a44f981bb6b4e64e",
        ),
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 50), None),
            "9f4943a2da4c497e0faed67aff8715a40453eafd6e3eb177ade28046e591e9e9",
        ),
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 63), None),
            "b392b37fba626c1761cc56c5156249bda6fad656f89af399d3f883ac322869a4",
        ),
        (
            next((node for node in ast.walk(validate_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 64), None),
            "9f4943a2da4c497e0faed67aff8715a40453eafd6e3eb177ade28046e591e9e9",
        ),
    )
    for node, expected_digest in codec_node_profiles:
        if node is None or _sha256(ast.dump(
            node, annotate_fields=True, include_attributes=False
        ).encode("utf-8")) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", codec_path
            )
    root_calls = [
        node
        for function_name in ("canonical_json", "parse_canonical_json")
        for node in ast.walk(codec_functions[function_name])
        if isinstance(node, ast.Call)
        and ast.get_source_segment(
            source_bytes[codec_path].decode("utf-8"), node
        ) == "_validate(value, set())"
    ]
    if len(root_calls) != 2 or any(
        _sha256(ast.dump(
            node, annotate_fields=True, include_attributes=False
        ).encode("utf-8"))
        != "3f2b68548ffb99f0523c9b97d604a13e3d541d22e6725557dcb50a00f16ce198"
        for node in root_calls
    ):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", codec_path
        )
    if _sha256(ast.dump(
        codec_tree, annotate_fields=True, include_attributes=False
    ).encode("utf-8")) != (
        "9be9408e5415167120cca04deaeb669243467a609dcd25193fb9280294a25eb7"
    ):
        raise ReadinessError("RESOURCE_CLASSIFICATION_MODULE_SHAPE", codec_path)

    initial_path = "src/edgelab/runtime_v2_initial.py"
    initial_source = source_bytes[initial_path].decode("utf-8")
    initial_tree = ast.parse(initial_source, filename=initial_path)
    initial_classes = {
        node.name: node
        for node in initial_tree.body
        if isinstance(node, ast.ClassDef)
        and node.name in {"InitialViolation", "_Sink"}
    }
    if set(initial_classes) != {"InitialViolation", "_Sink"}:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", initial_path)
    sink_methods = {
        node.name: node
        for node in initial_classes["_Sink"].body
        if isinstance(node, ast.FunctionDef)
    }
    add_function = sink_methods.get("add")
    if add_function is None:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", initial_path)
    bounded_functions = [
        node for node in ast.walk(add_function)
        if isinstance(node, ast.FunctionDef) and node.name == "bounded"
    ]
    if len(bounded_functions) != 1:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", initial_path)
    bounded_function = bounded_functions[0]
    initial_structural_profiles = (
        (
            initial_classes["InitialViolation"],
            "be763e1502bbd4b299402dfa10467bacc4c880269fa8692a98977dcf1f619f7d",
        ),
        (
            initial_classes["_Sink"],
            "b61e2b4fbb562a2458c43eadf5b2e548ea520f1b652a06039c4bfd6e7128227e",
        ),
        (
            add_function,
            "34c20470283590c5ef422d87bb487928a10e43de86e274a6fe510cc77801be0c",
        ),
        (
            bounded_function,
            "592e2f700af27699e0fe9eade5fd0f357d5bf7949ae370face4a34efd0ab6f9c",
        ),
    )
    for node, expected_digest in initial_structural_profiles:
        if _sha256(ast.dump(
            node, annotate_fields=True, include_attributes=False
        ).encode("utf-8")) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", initial_path
            )
    initial_node_profiles = (
        (ast.If, 161, 12, "1ed6be5ba1c5627d79849529e2175a2a2dc67e49b9c4498733dbf47b592218d5"),
        (ast.Return, 162, 16, "88b203970aef225f077e527420a8aa37d7bea48c022a704b48a144448b80ec78"),
        (ast.Assign, 163, 12, "955195bbb5a430a35b8a25506710d4ae29dd97dfb851080af22ddbd3af035f94"),
        (ast.Call, 163, 32, "8b66ba6ea0117121e435a44de478594500b850f3662a5da44009ed47db0ccb87"),
        (ast.Return, 164, 12, "6fd09e200f846e9e544f8cbd866d35baf4b58e110aea81a6c2919139f03bdedb"),
        (ast.Subscript, 164, 19, "74117ea7f02d52d57cdd5cfd500f420236efd5451e9c19f9fe00afae164cd152"),
        (ast.Assign, 166, 8, "e0084beebde261ce1ed7febac19f9676ae77ae37f317f81a6a190b82df050ba8"),
        (ast.Call, 166, 18, "5ee34e310813959bc18ff8a80a3fd8ccdb708ab402dc9f17baf5baadb0377c3e"),
        (ast.Call, 167, 12, "0d4011ec1ea3c0d77575c2f611d8b025d056326703fa6cd40498c6fe820d977e"),
        (ast.Call, 168, 12, "1c744d68a72a6de4f26aa106192a8a2446fda57c6a0b9d5fd9de47e724928cd0"),
        (ast.Call, 169, 12, "3eefa5a385f2b99eec5d1f1b499dce81f7a5d9c7640a85fe31f9248904f85e42"),
    )
    for node_type, line, column, expected_digest in initial_node_profiles:
        node = next(
            (candidate for candidate in ast.walk(add_function)
             if isinstance(candidate, node_type)
             and getattr(candidate, "lineno", None) == line
             and getattr(candidate, "col_offset", None) == column),
            None,
        )
        if node is None or _sha256(ast.dump(
            node, annotate_fields=True, include_attributes=False
        ).encode("utf-8")) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", initial_path
            )
    if _sha256(ast.dump(
        initial_tree, annotate_fields=True, include_attributes=False
    ).encode("utf-8")) != (
        "15ecffa7a1df62b834bac7be5837f53ce0f7d3211d0942967dbb4c75612b658b"
    ):
        raise ReadinessError("RESOURCE_CLASSIFICATION_MODULE_SHAPE", initial_path)

    verifier_path = "src/edgelab/runtime_v2_verifier.py"
    verifier_tree = ast.parse(source_bytes[verifier_path], filename=verifier_path)
    verifier_functions = [
        node for node in verifier_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_schema_safety_findings"
    ]
    if len(verifier_functions) != 1:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", verifier_path)
    schema_safety_function = verifier_functions[0]
    walk_functions = [
        node for node in ast.walk(schema_safety_function)
        if isinstance(node, ast.FunctionDef) and node.name == "walk"
    ]
    if len(walk_functions) != 1:
        raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", verifier_path)
    verifier_node_profiles = (
        (walk_functions[0], "d4e1299dcda1803cce4265a600cb5f9e1fd102d7dfa6c826c0b4701a7255548d"),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.Assign)
                 and getattr(node, "lineno", None) == 214),
                None,
            ),
            "dadccb0d8acde30915a33a88f67fcef3f04b7fc9139746aa2d0b5147d0a6f62d",
        ),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.Compare)
                 and getattr(node, "lineno", None) == 214),
                None,
            ),
            "252b73ee6debf88306997d684c5b22f599bdd9ce812f571f1e26171d950d9c9a",
        ),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.Call)
                 and getattr(node, "lineno", None) == 214
                 and getattr(node, "col_offset", None) == 64),
                None,
            ),
            "f217f12d2c49fca730036d93eb9cdc63e985b98b021a62306207355c38d465b8",
        ),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.Constant)
                 and node.value == "#/$defs/"),
                None,
            ),
            "cc5d3196889a6a14f40a5802b25e1bccad4db0726ef81f864b356114bb63a56c",
        ),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.BoolOp)
                 and getattr(node, "lineno", None) == 216),
                None,
            ),
            "7608b9ceacbfcfdf61a12da0139e30d3fffff6edee52c4fbce53755987dcc033",
        ),
        (
            next(
                (node for node in ast.walk(walk_functions[0])
                 if isinstance(node, ast.Call)
                 and getattr(node, "lineno", None) == 221),
                None,
            ),
            "0df06f8d4f4d223d4da9df2c422b8e017ce1b3b2ca5bf2208ec318ad81c71a92",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Assign)
                  and getattr(node, "lineno", None) == 188), None),
            "ccaf8d0686b3f24ae4ca531ac8026a1f0c4a9e76bf5a30466db00e47a1f4f94f",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.If)
                  and getattr(node, "lineno", None) == 189), None),
            "221b0b40155ea6a859985efe8e0eb563be0da0831092542df4fbfc82c9d9a948",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Assign)
                  and getattr(node, "lineno", None) == 191), None),
            "34418ddea378177305947fdcf67c106a531f1844bbe833024f641e37a82158e9",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.For)
                  and getattr(node, "lineno", None) == 238), None),
            "d9b67cdccc3e8c40c7256c5d776a3c2b2c579d96cbe7bed2521d642f5d81fb2d",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.BoolOp)
                  and getattr(node, "lineno", None) == 242), None),
            "4b06800b12b71cbc41ad53077e9b3f9026341c2499d0639c96a32128fe8b4141",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 248), None),
            "5b6c969f9feb84773e74a77632bd2f25ac4e029cc2d0957e72906858ec60781b",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Continue)
                  and getattr(node, "lineno", None) == 249), None),
            "3d1e0aaa463df3eefc9bd5be83f453adcd9621b2dc7f387c3eaff3ab42e91059",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 250), None),
            "40aba6d8841818b88ad9cedc77959fd4462e56390176920a2f847cb3c87893e7",
        ),
        (
            next((node for node in ast.walk(schema_safety_function)
                  if isinstance(node, ast.Call)
                  and getattr(node, "lineno", None) == 251), None),
            "6b451e50276f1db40135e88ab28644895ab981654d2d153e6b2ede6d29f2a47a",
        ),
    )
    for node, expected_digest in verifier_node_profiles:
        if node is None or _sha256(ast.dump(
            node, annotate_fields=True, include_attributes=False
        ).encode("utf-8")) != expected_digest:
            raise ReadinessError(
                "RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", verifier_path
            )

    ast_profiles = (
        (
            "src/edgelab/runtime_v2_closure.py",
            "MAX_DEPENDENCY_CLOSURE_BYTES",
            "validate_verifier_dependency_closure",
            "9c9e9b785430028f44d93df883e0b7edd52b777546b8811b732fdf2b99bc0e30",
            "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_CHECKPOINT_COPIES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_BLOBS",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_EVENT_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_SCHEMA_DOCUMENT_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_SCHEMA_REGISTRY_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_BOOTSTRAP_DOCUMENT_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            5,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_BLOB_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_SCHEMA_BUNDLE_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_FINDING_ARTIFACT_CHARS",
            "_finding",
            "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_FINDING_COORDINATE_CHARS",
            "_finding",
            "663fd397aaff36b7871917a15c97890377e797b42141cb533e1e3b7f6bb9e781",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_REF_NODES",
            "_schema_safety_findings",
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_DOCUMENT_BYTES",
            "_schema_bundle_findings",
            "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_REGISTRY_BYTES",
            "_schema_bundle_findings",
            "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            1,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_BUNDLE_BYTES",
            "_schema_bundle_findings",
            "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            2,
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_BUNDLE_BYTES",
            "verify_runtime_image",
            "1742c7e8785c03ddfb26fbc3c1eb695c0daa79aa355eb77dae6b8350a373502c",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
            2,
        ),
        (
            "src/edgelab/runtime_v2_transition.py",
            "MAX_ARGUMENTS",
            "TransitionIntent.__post_init__",
            "42b1b9103cffdc52d38f4033e71b4b750b334305b3c952d7ac7b86843bec58f7",
            "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b",
            1,
        ),
        (
            "src/edgelab/runtime_v2_transition.py",
            "MAX_GROUP_EVENTS",
            "TransitionIntent.__post_init__",
            "42b1b9103cffdc52d38f4033e71b4b750b334305b3c952d7ac7b86843bec58f7",
            "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b",
            1,
        ),
        (
            "src/edgelab/runtime_v2_transition.py",
            "MAX_TASKS",
            "ReducerState.__post_init__",
            "acfc468a2815e245ee3da5230df49c20e8dc1f2601fa24b367507e77d847a337",
            "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b",
            2,
        ),
        (
            "src/edgelab/runtime_v2_transition.py",
            "MAX_TASKS",
            "_TransitionWorkspace._precheck",
            "280ca713360ad0b61cd3810999f6d0cf1ea4e31b854596bbaedb4ad03c8b12b1",
            "2bb8a77ac83dc22d9df027384d5c29d1aa6f180fe3de33d4119b3433722b603b",
            2,
        ),
        (
            "src/edgelab/runtime_v2_closure.py",
            "_PORTABLE_PATH_MAX",
            "_path",
            "d4bcf6527c507a9e580c563f57cc1d2f79b3caa8a205b0fc6fdf2c7f5cc2d806",
            "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7",
            1,
        ),
        (
            "src/edgelab/runtime_v2_closure.py",
            "_PORTABLE_COMPONENT_MAX",
            "_path",
            "d4bcf6527c507a9e580c563f57cc1d2f79b3caa8a205b0fc6fdf2c7f5cc2d806",
            "30502d160af1538889e36f2411835749381362cec5935936fcf4e4db90bf48c7",
            1,
        ),
    )
    parsed_profiles: list[tuple[str, str, str, str, str, int, ast.AST]] = []
    parsed_trees: dict[str, ast.AST] = {}
    for (
        path, constant_name, function_name, function_sha256, module_sha256,
        expected_load_count,
    ) in ast_profiles:
        try:
            tree = parsed_trees.setdefault(
                path, ast.parse(source_bytes[path], filename=path)
            )
        except (KeyError, SyntaxError, ValueError) as error:
            raise ReadinessError("RESOURCE_CLASSIFICATION_SOURCE", path) from error
        parsed_profiles.append((
            path, constant_name, function_name, function_sha256,
            module_sha256, expected_load_count, tree,
        ))

    for (
        path, constant_name, _, _, _, expected_load_count, tree,
    ) in parsed_profiles:
        stores = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == constant_name
            and isinstance(node.ctx, ast.Store)
        ]
        loads = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == constant_name
            and isinstance(node.ctx, ast.Load)
        ]
        if len(stores) != 1 or len(loads) != expected_load_count:
            raise ReadinessError("RESOURCE_CLASSIFICATION_NAME_CARDINALITY", path)

    for path, _, function_name, function_sha256, _, _, tree in parsed_profiles:
        coordinate_parts = function_name.split(".")
        if len(coordinate_parts) == 1:
            functions = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
                and node.name == function_name
            ]
        elif len(coordinate_parts) == 2:
            class_name, method_name = coordinate_parts
            owners = [
                node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == class_name
            ]
            functions = [
                node for owner in owners for node in owner.body
                if isinstance(node, ast.FunctionDef) and node.name == method_name
            ]
        else:
            functions = []
        if len(functions) != 1:
            raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", path)
        function_dump = ast.dump(
            functions[0], annotate_fields=True, include_attributes=False
        ).encode("utf-8")
        if _sha256(function_dump) != function_sha256:
            raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", path)

    checked_modules: set[str] = set()
    for path, _, _, _, module_sha256, _, tree in parsed_profiles:
        if path in checked_modules:
            continue
        checked_modules.add(path)
        module_dump = ast.dump(
            tree, annotate_fields=True, include_attributes=False
        ).encode("utf-8")
        if _sha256(module_dump) != module_sha256:
            raise ReadinessError("RESOURCE_CLASSIFICATION_MODULE_SHAPE", path)

    digest_value = dict(manifest)
    claimed_digest = digest_value.pop("classification_manifest_sha256")
    if type(claimed_digest) is not str or claimed_digest != _domain_digest(
        RESOURCE_CLASSIFICATION_V47_DOMAIN, digest_value
    ):
        raise ReadinessError("RESOURCE_CLASSIFICATION_SELF_DIGEST", manifest_path)

    return {
        "classified_constraint_count": 40,
        "classified_site_count": 73,
        "classification_manifest_sha256": claimed_digest,
        "coverage_status": "INCOMPLETE",
        "evidence_inputs": [
            dict(item) for item in evidence_by_path.values()
        ],
        "generation_disposition": "DENY",
        "manifest": {
            "byte_length": len(manifest_raw),
            "path": manifest_path,
            "raw_sha256": _sha256(manifest_raw),
        },
        "profile_id": profile_id,
        "predecessor_manifest": dict(
            RESOURCE_CLASSIFICATION_V47_PREDECESSOR_MANIFEST
        ),
        "predecessor_schema": dict(
            RESOURCE_CLASSIFICATION_V47_PREDECESSOR_SCHEMA
        ),
        "schema": {
            "byte_length": len(schema_raw),
            "path": schema_path,
            "raw_sha256": _sha256(schema_raw),
            "schema_id": schema_id,
        },
        "unclassified_site_count": scalar_expected["unclassified_site_count"],
    }


def _public_import_closure(source_inventory: dict[str, Any]) -> set[str]:
    edges: dict[str, set[str]] = {}
    for item in source_inventory["import_edges"]:
        edges.setdefault(item["source"], set()).add(item["target"])
    seen: set[str] = set()
    pending = [PUBLIC_ENTRYPOINT_MODULE]
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        seen.add(module)
        pending.extend(edges.get(module, ()))
    return seen


def build_report(root: Path = ROOT) -> dict[str, Any]:
    """Return the deterministic, non-authorizing readiness report."""
    source, identities, source_bytes = _source_inventory(root)
    schema_bytes: dict[str, bytes] = {}
    bootstrap = _schema_inventory(
        root, BOOTSTRAP_SCHEMAS, "role", "schema_document_sha256", identities,
        schema_bytes,
    )
    retained = _schema_inventory(
        root, RETAINED_SCHEMAS, "content_role", "document_sha256", identities,
        schema_bytes,
    )
    legacy_schema_bound_sites = _schema_bound_inventory(
        root, identities, schema_bytes
    )
    schema_bound_sites = _address_schema_bound_inventory(
        legacy_schema_bound_sites
    )
    schema_declarative_proof_profile = (
        _schema_declarative_proof_profile_inventory(root, identities)
    )
    content = _content_inventory(root, identities)
    digest_domains = _digest_domains(source, source_bytes)
    resource_limits = _resource_limits(source, source_bytes)
    v1_source_bound_sites = _source_bound_inventory(source_bytes)
    if len(v1_source_bound_sites) != 394:
        raise ReadinessError("RESOURCE_DISCOVERY_V1_CARDINALITY", "source_bound_sites")
    v2_binding_sites = _source_bound_binding_inventory(
        source_bytes, v1_source_bound_sites
    )
    v2_source_bound_sites = sorted(
        v1_source_bound_sites + v2_binding_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(v2_source_bound_sites) != 401:
        raise ReadinessError("RESOURCE_DISCOVERY_V2_CARDINALITY", "source_bound_sites")
    v2_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v2_source_bound_sites
    ]
    v2_source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V2_DOMAIN, v2_source_bound_identity
    )
    if v2_source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V2_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V2_IDENTITY", "source_bound_sites_sha256"
        )
    cardinality_binding_sites = _source_bound_cardinality_binding_inventory(
        source_bytes, v2_source_bound_sites
    )
    v3_source_bound_sites = sorted(
        v2_source_bound_sites + cardinality_binding_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(v3_source_bound_sites) != 407:
        raise ReadinessError("RESOURCE_DISCOVERY_V3_CARDINALITY", "source_bound_sites")
    v3_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v3_source_bound_sites
    ]
    row_cap_binding_sites = _source_bound_table_row_cap_binding_inventory(
        source_bytes, v3_source_bound_sites
    )
    v4_source_bound_sites = sorted(
        v3_source_bound_sites + row_cap_binding_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(v4_source_bound_sites) != 422:
        raise ReadinessError("RESOURCE_DISCOVERY_V4_CARDINALITY", "source_bound_sites")
    v4_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v4_source_bound_sites
    ]
    v1_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v1_source_bound_sites
    ]
    schema_inputs = [
        {
            "byte_length": len(schema_bytes[path]),
            "path": path,
            "raw_sha256": _sha256(schema_bytes[path]),
        }
        for path in sorted(schema_bytes)
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
    resource_discovery_v1 = {
        "classification_status": "UNCLASSIFIED",
        "coverage_status": "INCOMPLETE",
        "profile_id": RESOURCE_DISCOVERY_V1_ID,
        "schema_bound_sites": legacy_schema_bound_sites,
        "schema_bound_sites_sha256": _domain_digest(
            "EDGELAB\0RUNTIME_V2_SCHEMA_BOUND_SITES\0V1\0",
            legacy_schema_bound_sites,
        ),
        "schema_inputs": schema_inputs,
        "schema_inputs_sha256": _domain_digest(
            "EDGELAB\0RUNTIME_V2_RESOURCE_SCHEMA_INPUTS\0V1\0",
            schema_inputs,
        ),
        "source_bound_sites": v1_source_bound_sites,
        "source_bound_sites_sha256": _domain_digest(
            "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V1\0",
            v1_source_bound_identity,
        ),
        "source_inputs": source_inputs,
        "source_inputs_sha256": _domain_digest(
            RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs,
        ),
    }
    resource_discovery_v2 = {
        **resource_discovery_v1,
        "derived_binding_site_count": len(v2_binding_sites),
        "legacy_source_bound_site_count": len(v1_source_bound_sites),
        "profile_id": RESOURCE_DISCOVERY_V2_ID,
        "source_bound_sites": v2_source_bound_sites,
        "source_bound_sites_sha256": v2_source_bound_sites_sha256,
    }
    predecessor_discovery = {
        "profile_id": resource_discovery_v2["profile_id"],
        "schema_bound_site_count": len(schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v2[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v2["schema_inputs_sha256"],
        "source_bound_site_count": len(v2_source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v2[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v2["source_inputs_sha256"],
    }
    source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN, v3_source_bound_identity
    )
    if source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V3_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V3_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery_v3 = {
        **resource_discovery_v2,
        "cumulative_derived_binding_site_count": (
            len(v2_binding_sites) + len(cardinality_binding_sites)
        ),
        "derived_binding_site_count": len(cardinality_binding_sites),
        "legacy_source_bound_site_count": len(v2_source_bound_sites),
        "predecessor_discovery": predecessor_discovery,
        "profile_id": RESOURCE_DISCOVERY_V3_ID,
        "source_bound_sites": v3_source_bound_sites,
        "source_bound_sites_sha256": source_bound_sites_sha256,
    }
    predecessor_discovery_v3 = {
        "profile_id": resource_discovery_v3["profile_id"],
        "schema_bound_site_count": len(schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v3[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v3["schema_inputs_sha256"],
        "source_bound_site_count": len(v3_source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v3[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v3["source_inputs_sha256"],
    }
    v4_source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V4_DOMAIN, v4_source_bound_identity
    )
    if v4_source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V4_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V4_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery_v4 = {
        **resource_discovery_v3,
        "cumulative_derived_binding_site_count": (
            len(v2_binding_sites)
            + len(cardinality_binding_sites)
            + len(row_cap_binding_sites)
        ),
        "derived_binding_site_count": len(row_cap_binding_sites),
        "legacy_source_bound_site_count": len(v3_source_bound_sites),
        "predecessor_discovery": predecessor_discovery_v3,
        "profile_id": RESOURCE_DISCOVERY_V4_ID,
        "source_bound_sites": v4_source_bound_sites,
        "source_bound_sites_sha256": v4_source_bound_sites_sha256,
    }
    predecessor_discovery_v4 = {
        "profile_id": resource_discovery_v4["profile_id"],
        "schema_bound_site_count": len(schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v4[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v4["schema_inputs_sha256"],
        "source_bound_site_count": len(v4_source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v4[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v4["source_inputs_sha256"],
    }
    top_level_cardinality_maximum_sites = (
        _source_bound_top_level_cardinality_maximum_inventory(
            source_bytes, v4_source_bound_sites
        )
    )
    v5_source_bound_sites = sorted(
        v4_source_bound_sites + top_level_cardinality_maximum_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(v5_source_bound_sites) != 423:
        raise ReadinessError("RESOURCE_DISCOVERY_V5_CARDINALITY", "source_bound_sites")
    v5_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v5_source_bound_sites
    ]
    v5_source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V5_DOMAIN, v5_source_bound_identity
    )
    if v5_source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V5_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V5_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery_v5 = {
        **resource_discovery_v4,
        "cumulative_derived_binding_site_count": (
            len(v2_binding_sites)
            + len(cardinality_binding_sites)
            + len(row_cap_binding_sites)
            + len(top_level_cardinality_maximum_sites)
        ),
        "derived_binding_site_count": len(top_level_cardinality_maximum_sites),
        "legacy_source_bound_site_count": len(v4_source_bound_sites),
        "predecessor_discovery": predecessor_discovery_v4,
        "profile_id": RESOURCE_DISCOVERY_V5_ID,
        "source_bound_sites": v5_source_bound_sites,
        "source_bound_sites_sha256": v5_source_bound_sites_sha256,
    }
    predecessor_discovery_v5 = {
        "profile_id": resource_discovery_v5["profile_id"],
        "schema_bound_site_count": len(schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v5[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v5["schema_inputs_sha256"],
        "source_bound_site_count": len(v5_source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v5[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v5["source_inputs_sha256"],
    }
    finding_artifact_maximum_sites = (
        _source_bound_finding_artifact_character_maximum_inventory(
            source_bytes, v5_source_bound_sites
        )
    )
    v6_source_bound_sites = sorted(
        v5_source_bound_sites + finding_artifact_maximum_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(v6_source_bound_sites) != 424:
        raise ReadinessError("RESOURCE_DISCOVERY_V6_CARDINALITY", "source_bound_sites")
    v6_source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in v6_source_bound_sites
    ]
    v6_source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V6_DOMAIN, v6_source_bound_identity
    )
    if v6_source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V6_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V6_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery_v6 = {
        **resource_discovery_v5,
        "cumulative_derived_binding_site_count": (
            len(v2_binding_sites)
            + len(cardinality_binding_sites)
            + len(row_cap_binding_sites)
            + len(top_level_cardinality_maximum_sites)
            + len(finding_artifact_maximum_sites)
        ),
        "derived_binding_site_count": len(finding_artifact_maximum_sites),
        "legacy_source_bound_site_count": len(v5_source_bound_sites),
        "predecessor_discovery": predecessor_discovery_v5,
        "profile_id": RESOURCE_DISCOVERY_V6_ID,
        "source_bound_sites": v6_source_bound_sites,
        "source_bound_sites_sha256": v6_source_bound_sites_sha256,
    }
    predecessor_discovery_v6 = {
        "profile_id": resource_discovery_v6["profile_id"],
        "schema_bound_site_count": len(schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v6[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v6["schema_inputs_sha256"],
        "source_bound_site_count": len(v6_source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v6[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v6["source_inputs_sha256"],
    }
    finding_coordinate_maximum_sites = (
        _source_bound_finding_coordinate_character_maximum_inventory(
            source_bytes, v6_source_bound_sites
        )
    )
    source_bound_sites = sorted(
        v6_source_bound_sites + finding_coordinate_maximum_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(source_bound_sites) != 425:
        raise ReadinessError("RESOURCE_DISCOVERY_V7_CARDINALITY", "source_bound_sites")
    source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in source_bound_sites
    ]
    v7_source_bound_sites_sha256 = _domain_digest(
        RESOURCE_SOURCE_BOUND_SITES_V7_DOMAIN, source_bound_identity
    )
    if v7_source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V7_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V7_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery_v7 = {
        **resource_discovery_v6,
        "cumulative_derived_binding_site_count": (
            resource_discovery_v6["cumulative_derived_binding_site_count"]
            + len(finding_coordinate_maximum_sites)
        ),
        "derived_binding_site_count": len(finding_coordinate_maximum_sites),
        "legacy_source_bound_site_count": len(v6_source_bound_sites),
        "predecessor_discovery": predecessor_discovery_v6,
        "profile_id": RESOURCE_DISCOVERY_V7_ID,
        "source_bound_sites": source_bound_sites,
        "source_bound_sites_sha256": v7_source_bound_sites_sha256,
    }
    predecessor_discovery_v7 = {
        "profile_id": resource_discovery_v7["profile_id"],
        "schema_bound_site_count": len(legacy_schema_bound_sites),
        "schema_bound_sites_sha256": resource_discovery_v7[
            "schema_bound_sites_sha256"
        ],
        "schema_input_count": len(schema_inputs),
        "schema_inputs_sha256": resource_discovery_v7["schema_inputs_sha256"],
        "source_bound_site_count": len(source_bound_sites),
        "source_bound_sites_sha256": resource_discovery_v7[
            "source_bound_sites_sha256"
        ],
        "source_input_count": len(source_inputs),
        "source_inputs_sha256": resource_discovery_v7["source_inputs_sha256"],
    }
    schema_bound_sites_sha256 = _domain_digest(
        RESOURCE_SCHEMA_BOUND_SITES_V2_DOMAIN, schema_bound_sites
    )
    if schema_bound_sites_sha256 != RESOURCE_SCHEMA_BOUND_SITES_V2_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V8_SCHEMA_IDENTITY", "schema_bound_sites_sha256"
        )
    resource_discovery = {
        **resource_discovery_v7,
        "derived_binding_site_count": 0,
        "derived_binding_site_ids": [],
        "derived_binding_sites": [],
        "legacy_source_bound_site_count": len(source_bound_sites),
        "predecessor_discovery": predecessor_discovery_v7,
        "profile_id": RESOURCE_DISCOVERY_V8_ID,
        "schema_bound_sites": schema_bound_sites,
        "schema_bound_sites_sha256": schema_bound_sites_sha256,
    }
    resource_classification = _resource_classification_inventory(
        root, identities, source_bytes, source_inputs, resource_discovery
    )
    resource_discovery_evidence = _resource_discovery_evidence_inventory(
        root, identities, resource_discovery
    )

    blockers: list[dict[str, Any]] = [{
        "code": "ACCEPTANCE_MATRIX_INCOMPLETE",
        "evidence": (
            "This readiness profile has no exact independently accepted A-J "
            "evidence manifest and therefore can never permit generation."
        ),
    }, {
        "code": "RESOURCE_INVENTORY_INCOMPLETE",
        "evidence": (
            "The discovery census contains "
            f"{resource_classification['unclassified_site_count']} "
            "unclassified sites after "
            f"{resource_classification['classified_site_count']} classified "
            "resource sites; "
            f"{len(source_bound_sites)} source-bound sites and "
            f"{len(schema_bound_sites)} unclassified schema-bound sites; no "
            "reviewed bidirectional manifest yet classifies every constraint."
        ),
    }]
    public_closure = _public_import_closure(source)
    if PRIVATE_REDUCER_MODULE not in public_closure:
        blockers.append({
            "code": "PUBLIC_ENTRYPOINT_DISCONNECTED",
            "evidence": (
                "The public entrypoint import closure does not contain "
                "edgelab.runtime_v2_initial."
            ),
        })
    initial_raw = source_bytes[_module_path(PRIVATE_REDUCER_MODULE)]
    if b"V1_MIGRATION_NOT_SUPPORTED" in initial_raw:
        blockers.append({
            "code": "V1_BRIDGE_UNSUPPORTED",
            "evidence": (
                "The private reducer retains the explicit "
                "V1_MIGRATION_NOT_SUPPORTED boundary."
            ),
        })
    return {
        "authorizing_use": "DENY",
        "blockers": sorted(blockers, key=lambda item: item["code"]),
        "eventual_generation_semantics": {
            "external_distributions": (
                "EMPTY_REQUIRED; any external import requires a new profile"
            ),
            "import_closure": (
                "STATIC_AST_TRANSITIVE_UNION_OF_FIXED_GENERATION_ROOTS"
            ),
            "pin_carrier_byte_length_basis": "PIN_BLOCK_ELIDED_SEMANTIC_BYTES",
            "pin_carrier_path": PIN_CARRIER_PATH,
            "pin_elision_begin_marker": PIN_BEGIN_MARKER.decode("ascii").rstrip("\n"),
            "pin_elision_end_marker": PIN_END_MARKER.decode("ascii").rstrip("\n"),
            "pin_elision_required_match_count": 1,
            "pin_elision_sha256_basis": "PIN_BLOCK_ELIDED_SEMANTIC_BYTES",
            "pin_replacement_literal": PIN_REPLACEMENT.decode("ascii"),
            "standard_library_classification": (
                "FIXED_ALLOWLIST; __future__ is an excluded compiler directive"
            ),
        },
        "inventory": {
            "bootstrap_schemas": bootstrap,
            "content_assets": content,
            "digest_domains": digest_domains,
            "resource_limits": resource_limits,
            "resource_inventory_classification": resource_classification,
            "resource_inventory_discovery": resource_discovery,
            "resource_inventory_discovery_evidence": resource_discovery_evidence,
            "retained_schema_documents": retained,
            "schema_declarative_keyword_proof_profile": (
                schema_declarative_proof_profile
            ),
            "source_closure": source,
            "tested_runtime_assumptions": [
                dict(item) for item in TESTED_RUNTIME_ASSUMPTIONS
            ],
        },
        "profile_id": PROFILE_ID,
        "public_result_vocabulary": ["INVALID", "UNSUPPORTED"],
        "schema_version": 1,
        "status": "BLOCKED",
        "release_artifacts_written": False,
    }


def _invalid_report(error: ReadinessError) -> dict[str, Any]:
    return {
        "authorizing_use": "DENY",
        "error": {"code": error.code, "coordinate": error.coordinate},
        "profile_id": PROFILE_ID,
        "schema_version": 1,
        "status": "INVALID",
        "release_artifacts_written": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        report = _invalid_report(ReadinessError("CLI_ARGUMENTS_DENIED", "/"))
        sys.stdout.buffer.write(_canonical_json(report) + b"\n")
        return 2
    try:
        report = build_report(ROOT)
    except ReadinessError as error:
        report = _invalid_report(error)
        exit_code = 2
    else:
        exit_code = 1
    sys.stdout.buffer.write(_canonical_json(report) + b"\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
