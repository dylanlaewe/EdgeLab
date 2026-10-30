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
RESOURCE_CLASSIFICATION_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-classification:16",
    "schemas/m0-3a-runtime-v2-resource-classification.v16.schema.json",
)
RESOURCE_CLASSIFICATION_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V16",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v16.json",
)
RESOURCE_CLASSIFICATION_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V16\0"
)
RESOURCE_SOURCE_INPUT_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_SOURCE_INPUTS\0V1\0"
)
RESOURCE_DISCOVERY_V1_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V1"
RESOURCE_DISCOVERY_V2_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V2"
RESOURCE_DISCOVERY_V3_ID = "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V3"
RESOURCE_DISCOVERY_SCHEMA = (
    "urn:edgelab:m0-3a-runtime-v2-resource-discovery:3",
    "schemas/m0-3a-runtime-v2-resource-discovery.v3.schema.json",
)
RESOURCE_DISCOVERY_MANIFEST = (
    RESOURCE_DISCOVERY_V3_ID,
    "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v3.json",
)
RESOURCE_DISCOVERY_DOMAIN = "EDGELAB\0RUNTIME_V2_RESOURCE_DISCOVERY\0V3\0"
RESOURCE_DISCOVERY_SCHEMA_RAW_SHA256 = (
    "60d8cb918f985308bdb5c7d477398066abc25d230642a266ff6836fa4f85f766"
)
RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST = {
    "byte_length": 9649,
    "discovery_manifest_sha256": (
        "c865ac494361d7ad310464efd19a0bf3d9c79ddfaa7d58e50a4ff9ef449c7725"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_DISCOVERY.v2.json",
    "raw_sha256": "12e0b1e722f9b49e14e530bb2721ee1ded1865fa4168f02d13c741f8e59adefe",
}
RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA = {
    "byte_length": 11712,
    "path": "schemas/m0-3a-runtime-v2-resource-discovery.v2.schema.json",
    "raw_sha256": "05cc1d76c95833e8b2d9bd3eaa2dbc4abc4cbed87088cca7ba1323a04a849243",
}
RESOURCE_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_BINDING_SITE\0V2\0"
)
RESOURCE_CARDINALITY_BINDING_SITE_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CARDINALITY_BINDING_SITE\0V3\0"
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
RESOURCE_CLASSIFICATION_SCHEMA_RAW_SHA256 = (
    "51e5e3e319eaeee34fdb5f592568868381c2c2752b386be80fdd57741c5c1d00"
)
RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST = {
    "byte_length": 32650,
    "classification_manifest_sha256": (
        "69f5d49e51e7f186fb90e32606002be684ac83060f379e921a6b0edf7cb5a90f"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v15.json",
    "raw_sha256": "cbadcd550071f29fe22ca002accd399df177dc03dafbf54980feeeb4f800eb22",
}
RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA = {
    "byte_length": 36166,
    "path": "schemas/m0-3a-runtime-v2-resource-classification.v15.schema.json",
    "raw_sha256": "2ca078ece22eaa8887184302110b727bfbf3ade49762a4be089c16628bd8378c",
}
RESOURCE_CLASSIFICATION_ANCESTORS = (
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
RESOURCE_CLASSIFICATION_EVIDENCE = (
    *BLOB_RESOURCE_EVIDENCE,
    *CLOSURE_RESOURCE_EVIDENCE,
    EVENT_BYTE_RESOURCE_EVIDENCE[0],
    EVENT_BYTE_RESOURCE_EVIDENCE[2],
    CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE[0],
    CHECKPOINT_COPY_CARDINALITY_RESOURCE_EVIDENCE[2],
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
)
CLASSIFIED_RESOURCE_SITE_IDS = frozenset({
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
    """Validate the closed, deny-only Discovery V3 evidence manifest."""
    predecessor_values: dict[str, dict[str, Any]] = {}
    for expected, has_self_digest in (
        (RESOURCE_DISCOVERY_PREDECESSOR_MANIFEST, True),
        (RESOURCE_DISCOVERY_PREDECESSOR_SCHEMA, False),
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
        predecessor_manifest.get("profile_id") != RESOURCE_DISCOVERY_V2_ID
        or predecessor_manifest.get("source_bound_site_count") != 401
        or predecessor_manifest.get("source_bound_sites_sha256")
        != RESOURCE_SOURCE_BOUND_SITES_V2_SHA256
    ):
        raise ReadinessError(
            "RESOURCE_DISCOVERY_PREDECESSOR_BINDING",
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

    binding_sites = [
        item for item in resource_discovery["source_bound_sites"]
        if item.get("kind") == "BOUND_CARDINALITY_TABLE_COMPARISON_BINDING"
    ]
    scalar_expected = {
        "schema_version": 3,
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


def _resource_classification_inventory(
    root: Path,
    identities: set[tuple[int, int]],
    source_bytes: dict[str, bytes],
    source_inputs: list[dict[str, Any]],
    resource_discovery: dict[str, Any],
) -> dict[str, Any]:
    """Validate the cumulative deny-only semantic classification slices."""
    predecessor_records = (
        (RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST, True),
        (RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA, False),
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
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST
            if index == 0 else RESOURCE_CLASSIFICATION_ANCESTORS[index - 2],
            RESOURCE_CLASSIFICATION_ANCESTORS[index],
            RESOURCE_CLASSIFICATION_ANCESTORS[index + 1],
        )
        for index in range(0, len(RESOURCE_CLASSIFICATION_ANCESTORS), 2)
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

    schema_id, schema_path = RESOURCE_CLASSIFICATION_SCHEMA
    schema_raw, schema_identity = _audit_path(root, schema_path)
    if schema_identity in identities:
        raise ReadinessError("HARDLINK_INPUT_ALIAS", schema_path)
    identities.add(schema_identity)
    schema_value = _parse_json(schema_raw, schema_path)
    if type(schema_value) is not dict or schema_value.get("$id") != schema_id:
        raise ReadinessError("SCHEMA_ID", schema_path)
    if _sha256(schema_raw) != RESOURCE_CLASSIFICATION_SCHEMA_RAW_SHA256:
        raise ReadinessError("RESOURCE_CLASSIFICATION_SCHEMA_IDENTITY", schema_path)

    profile_id, manifest_path = RESOURCE_CLASSIFICATION_MANIFEST
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
        "schema_version": 16,
        "manifest_id": schema_id,
        "profile_id": profile_id,
        "discovery_profile_id": resource_discovery["profile_id"],
        "coverage_status": "INCOMPLETE",
        "generation_disposition": "DENY",
        "classification_schema_raw_sha256": (
            RESOURCE_CLASSIFICATION_SCHEMA_RAW_SHA256
        ),
        "predecessor_manifest": dict(
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST
        ),
        "predecessor_schema": dict(
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA
        ),
        "source_input_count": 10,
        "source_inputs_sha256": _domain_digest(
            RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs
        ),
        "source_bound_site_count": 407,
        "source_bound_sites_sha256": resource_discovery[
            "source_bound_sites_sha256"
        ],
        "schema_bound_site_count": 296,
        "schema_bound_sites_sha256": resource_discovery[
            "schema_bound_sites_sha256"
        ],
        "schema_inputs_sha256": resource_discovery["schema_inputs_sha256"],
        "classified_site_count": 40,
        "unclassified_site_count": 663,
    }
    for key, expected in scalar_expected.items():
        if type(manifest.get(key)) is not type(expected) or manifest.get(key) != expected:
            raise ReadinessError("RESOURCE_CLASSIFICATION_BINDING", key)

    constraints = manifest.get("constraints")
    if type(constraints) is not list or len(constraints) != 14:
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
    if any(type(item) is not dict for item in constraints) or any(
        set(item) != (
            multi_binding_constraint_keys
            if "semantic_bindings" in item else single_binding_constraint_keys
        )
        for item in constraints
    ):
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINT_KEYS", manifest_path)
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
    ]
    if constraints != expected_constraints:
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINT", manifest_path)
    predecessor_value = manifest_values.get(
        RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST["path"]
    )
    if (
        predecessor_value is None
        or predecessor_value.get("constraints") != constraints[:-1]
        or predecessor_value.get("classified_site_count") != 38
    ):
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_CENSUS_REBASE", manifest_path
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

    sites = {
        item["site_id"]: item
        for item in resource_discovery["source_bound_sites"]
    }
    if len(sites) != len(resource_discovery["source_bound_sites"]):
        raise ReadinessError("RESOURCE_SITE_ID_DUPLICATE", "/")
    classified_site_ids = {
        site_id
        for constraint in expected_constraints
        for field in ("definition_site_ids", "enforcement_site_ids")
        for site_id in constraint[field]
    }
    if classified_site_ids != CLASSIFIED_RESOURCE_SITE_IDS:
        raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_SET", manifest_path)
    site_shapes = {
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
    }
    for site_id, expected in site_shapes.items():
        record = sites.get(site_id)
        if record is None:
            raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_MISSING", site_id)
        if any(record.get(key) != value for key, value in expected.items()):
            raise ReadinessError("RESOURCE_CLASSIFICATION_SITE_SHAPE", site_id)

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
        RESOURCE_CLASSIFICATION_DOMAIN, digest_value
    ):
        raise ReadinessError("RESOURCE_CLASSIFICATION_SELF_DIGEST", manifest_path)

    return {
        "classified_constraint_count": 14,
        "classified_site_count": 40,
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
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST
        ),
        "predecessor_schema": dict(
            RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA
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
    schema_bound_sites = _schema_bound_inventory(root, identities, schema_bytes)
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
    source_bound_sites = sorted(
        v2_source_bound_sites + cardinality_binding_sites,
        key=lambda item: (item["path"], item["site_id"]),
    )
    if len(source_bound_sites) != 407:
        raise ReadinessError("RESOURCE_DISCOVERY_V3_CARDINALITY", "source_bound_sites")
    source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in source_bound_sites
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
        "schema_bound_sites": schema_bound_sites,
        "schema_bound_sites_sha256": _domain_digest(
            "EDGELAB\0RUNTIME_V2_SCHEMA_BOUND_SITES\0V1\0",
            schema_bound_sites,
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
        RESOURCE_SOURCE_BOUND_SITES_V3_DOMAIN, source_bound_identity
    )
    if source_bound_sites_sha256 != RESOURCE_SOURCE_BOUND_SITES_V3_SHA256:
        raise ReadinessError(
            "RESOURCE_DISCOVERY_V3_IDENTITY", "source_bound_sites_sha256"
        )
    resource_discovery = {
        **resource_discovery_v2,
        "cumulative_derived_binding_site_count": (
            len(v2_binding_sites) + len(cardinality_binding_sites)
        ),
        "derived_binding_site_count": len(cardinality_binding_sites),
        "legacy_source_bound_site_count": len(v2_source_bound_sites),
        "predecessor_discovery": predecessor_discovery,
        "profile_id": RESOURCE_DISCOVERY_V3_ID,
        "source_bound_sites": source_bound_sites,
        "source_bound_sites_sha256": source_bound_sites_sha256,
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
