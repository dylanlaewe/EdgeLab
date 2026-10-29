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
    "urn:edgelab:m0-3a-runtime-v2-resource-classification:4",
    "schemas/m0-3a-runtime-v2-resource-classification.v4.schema.json",
)
RESOURCE_CLASSIFICATION_MANIFEST = (
    "EDGELAB_RUNTIME_V2_RESOURCE_CLASSIFICATION_V4",
    "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v4.json",
)
RESOURCE_CLASSIFICATION_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_CLASSIFICATION\0V4\0"
)
RESOURCE_SOURCE_INPUT_DOMAIN = (
    "EDGELAB\0RUNTIME_V2_RESOURCE_SOURCE_INPUTS\0V1\0"
)
RESOURCE_CLASSIFICATION_SCHEMA_RAW_SHA256 = (
    "bad508a26ec01ab88521fd5d54b9a771da6165b6be84b070145bc715be676f25"
)
RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST = {
    "byte_length": 7399,
    "classification_manifest_sha256": (
        "9e7e799aaa51153b18ef636ca5c6e089538a05d97bedf16c026a396a1e109fc3"
    ),
    "path": "docs/M0.3A_RUNTIME_V2_RESOURCE_CLASSIFICATION.v3.json",
    "raw_sha256": "a27fba61041961a321b4938431219d461b65427896885ce7bf52a43639488330",
}
RESOURCE_CLASSIFICATION_PREDECESSOR_SCHEMA = {
    "byte_length": 8751,
    "path": "schemas/m0-3a-runtime-v2-resource-classification.v3.schema.json",
    "raw_sha256": "b80559e7e9eeac6b935f06d835b97bceb829da55d06daa390b8ec725088a03bd",
}
RESOURCE_CLASSIFICATION_ANCESTORS = (
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
RESOURCE_CLASSIFICATION_EVIDENCE = (
    *BLOB_RESOURCE_EVIDENCE,
    *CLOSURE_RESOURCE_EVIDENCE,
    SCHEMA_DOCUMENT_RESOURCE_EVIDENCE[2],
    *SCHEMA_REF_NODE_RESOURCE_EVIDENCE,
)
CLASSIFIED_RESOURCE_SITE_IDS = frozenset({
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
        (RESOURCE_CLASSIFICATION_ANCESTORS[0], True),
        (RESOURCE_CLASSIFICATION_ANCESTORS[1], False),
        (RESOURCE_CLASSIFICATION_ANCESTORS[2], True),
        (RESOURCE_CLASSIFICATION_ANCESTORS[3], False),
    )
    predecessor_manifest_value: dict[str, Any] | None = None
    ancestor_manifest_value: dict[str, Any] | None = None
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
            if expected is RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST:
                predecessor_manifest_value = value
            elif expected is RESOURCE_CLASSIFICATION_ANCESTORS[0]:
                ancestor_manifest_value = value

    if predecessor_manifest_value is None or predecessor_manifest_value.get(
        "predecessor_manifest"
    ) != RESOURCE_CLASSIFICATION_ANCESTORS[0] or predecessor_manifest_value.get(
        "predecessor_schema"
    ) != RESOURCE_CLASSIFICATION_ANCESTORS[1]:
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
            RESOURCE_CLASSIFICATION_PREDECESSOR_MANIFEST["path"],
        )
    if ancestor_manifest_value is None or ancestor_manifest_value.get(
        "predecessor_manifest"
    ) != RESOURCE_CLASSIFICATION_ANCESTORS[2] or ancestor_manifest_value.get(
        "predecessor_schema"
    ) != RESOURCE_CLASSIFICATION_ANCESTORS[3]:
        raise ReadinessError(
            "RESOURCE_CLASSIFICATION_ANCESTOR_BINDING",
            RESOURCE_CLASSIFICATION_ANCESTORS[0]["path"],
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
        "schema_version": 4,
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
        "source_bound_site_count": 394,
        "source_bound_sites_sha256": resource_discovery[
            "source_bound_sites_sha256"
        ],
        "schema_bound_site_count": 296,
        "schema_bound_sites_sha256": resource_discovery[
            "schema_bound_sites_sha256"
        ],
        "schema_inputs_sha256": resource_discovery["schema_inputs_sha256"],
        "classified_site_count": 10,
        "unclassified_site_count": 680,
    }
    for key, expected in scalar_expected.items():
        if type(manifest.get(key)) is not type(expected) or manifest.get(key) != expected:
            raise ReadinessError("RESOURCE_CLASSIFICATION_BINDING", key)

    constraints = manifest.get("constraints")
    if type(constraints) is not list or len(constraints) != 4:
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
    if (
        any(type(item) is not dict for item in constraints)
        or any(set(item) != single_binding_constraint_keys for item in constraints[:2])
        or set(constraints[2]) != multi_binding_constraint_keys
        or set(constraints[3]) != single_binding_constraint_keys
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
    ]
    if constraints != expected_constraints:
        raise ReadinessError("RESOURCE_CLASSIFICATION_CONSTRAINT", manifest_path)

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
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_SCHEMA_DOCUMENT_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        ),
        (
            "src/edgelab/runtime_v2_image.py",
            "MAX_BLOB_BYTES",
            "inspect_runtime_image_host",
            "b2950edc3a943812969a400bfa5b811dfeac9e03413f559ff89f5bfced29f56f",
            "89d50071bdb9b49f32c631fb6f9ffece243d8a7b97280c3065ca85eea4df9857",
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_REF_NODES",
            "_schema_safety_findings",
            "e445bd1a06dfbee91a6ed8146a6524874a84dbcc0439b06e3667d31a8e49f60d",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
        ),
        (
            "src/edgelab/runtime_v2_verifier.py",
            "MAX_SCHEMA_DOCUMENT_BYTES",
            "_schema_bundle_findings",
            "054e65a5e37bf65c79c2390dcdc6b0ed4b20683496159ad5d2cae04502f2c14e",
            "4cf60eb1416f7cfe080bd68653d748431084e04a17790a4244317834158acdfc",
        ),
    )
    parsed_profiles: list[tuple[str, str, str, str, str, ast.AST]] = []
    parsed_trees: dict[str, ast.AST] = {}
    for path, constant_name, function_name, function_sha256, module_sha256 in ast_profiles:
        try:
            tree = parsed_trees.setdefault(
                path, ast.parse(source_bytes[path], filename=path)
            )
        except (KeyError, SyntaxError, ValueError) as error:
            raise ReadinessError("RESOURCE_CLASSIFICATION_SOURCE", path) from error
        parsed_profiles.append((
            path, constant_name, function_name, function_sha256,
            module_sha256, tree,
        ))

    for path, constant_name, _, _, _, tree in parsed_profiles:
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
        if len(stores) != 1 or len(loads) != 1:
            raise ReadinessError("RESOURCE_CLASSIFICATION_NAME_CARDINALITY", path)

    for path, _, function_name, function_sha256, _, tree in parsed_profiles:
        functions = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        ]
        if len(functions) != 1:
            raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION", path)
        function_dump = ast.dump(
            functions[0], annotate_fields=True, include_attributes=False
        ).encode("utf-8")
        if _sha256(function_dump) != function_sha256:
            raise ReadinessError("RESOURCE_CLASSIFICATION_FUNCTION_SHAPE", path)

    checked_modules: set[str] = set()
    for path, _, _, _, module_sha256, tree in parsed_profiles:
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
        "classified_constraint_count": 4,
        "classified_site_count": 10,
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
    source_bound_sites = _source_bound_inventory(source_bytes)
    source_bound_identity = [
        {key: value for key, value in item.items() if key != "line"}
        for item in source_bound_sites
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
    resource_discovery = {
        "classification_status": "UNCLASSIFIED",
        "coverage_status": "INCOMPLETE",
        "profile_id": "EDGELAB_RUNTIME_V2_RESOURCE_DISCOVERY_V1",
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
        "source_bound_sites": source_bound_sites,
        "source_bound_sites_sha256": _domain_digest(
            "EDGELAB\0RUNTIME_V2_SOURCE_BOUND_SITES\0V1\0",
            source_bound_identity,
        ),
        "source_inputs": source_inputs,
        "source_inputs_sha256": _domain_digest(
            RESOURCE_SOURCE_INPUT_DOMAIN, source_inputs,
        ),
    }
    resource_classification = _resource_classification_inventory(
        root, identities, source_bytes, source_inputs, resource_discovery
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
            f"{len(source_bound_sites) + len(schema_bound_sites) - 10} "
            "unclassified sites after four classified resource maxima bound "
            "ten source sites; "
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
