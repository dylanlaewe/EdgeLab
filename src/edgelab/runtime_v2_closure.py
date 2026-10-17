"""Compiled, pure shape validator for the runtime-v2 dependency closure.

This module validates only the closed version-1 record language and canonical
inventory ordering.  It performs no I/O, never derives candidate identities
from the ambient checkout, and does not establish the exact generated release
identity.  Exact compiled byte equality remains a later source-freeze step.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from .runtime_v2_codec import (
    CanonicalJsonError,
    canonical_json,
    verifier_dependency_closure_digest,
)


CLOSURE_SHAPE_VALIDATION_PROFILE = (
    "EDGELAB_RUNTIME_V2_DEPENDENCY_CLOSURE_SHAPE_STRICT_V1"
)
MAX_DEPENDENCY_CLOSURE_BYTES = 1_048_576


class ClosureValidationError(ValueError):
    """A parsed value is outside the compiled closure-shape profile."""

    def __init__(self, code: str, coordinate: str) -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PATH = re.compile(
    r"^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))"
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$"
)
_MODULE = re.compile(
    r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$"
)
_SCHEMA_ID = re.compile(r"^urn:edgelab:[a-z0-9-]+:[0-9]+$")
_LOWER_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_UPPER_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DISTRIBUTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_DIGEST_DOMAIN = re.compile(
    r"^EDGELAB\0[A-Z0-9_]+\0V[0-9]+\0(?:[A-Z0-9_]+\0)?$"
)
_INT64_MAX = 9_223_372_036_854_775_807
_PORTABLE_PATH_MAX = 4_096
_PORTABLE_COMPONENT_MAX = 255
_WINDOWS_DEVICE_STEMS = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
})

_TOP_KEYS = frozenset({
    "schema_version", "closure_id", "closure_version",
    "runtime_format_version", "canonicalization", "digest_algorithm",
    "digest_domain", "entrypoint", "root_boundary",
    "pin_elision_profile", "local_artifacts", "bootstrap_schemas",
    "retained_schema_documents", "content_assets", "digest_domains",
    "resource_limits", "standard_library_modules", "external_distributions",
    "tested_runtime_assumptions", "generator_identity",
    "deny_only_boundary", "verifier_dependency_closure_sha256",
})
_ENTRYPOINT_KEYS = frozenset({"artifact_path", "module", "callable"})
_ROOT_BOUNDARY_KEYS = frozenset({
    "repository_relative", "local_import_roots", "filesystem_reads",
    "network_access", "environment_access", "dynamic_imports",
})
_PIN_ELISION_KEYS = frozenset({
    "profile_id", "artifact_path", "begin_marker", "end_marker",
    "replacement_literal", "required_match_count",
})
_LOCAL_ARTIFACT_KEYS = frozenset({
    "path", "role", "sha256", "byte_length", "pin_elision_applied",
})
_BOOTSTRAP_SCHEMA_KEYS = frozenset({
    "role", "schema_id", "path", "raw_sha256",
    "schema_document_sha256", "byte_length",
})
_RETAINED_SCHEMA_KEYS = frozenset({
    "content_role", "schema_id", "path", "raw_sha256",
    "document_sha256", "byte_length",
})
_CONTENT_ASSET_KEYS = frozenset({
    "path", "raw_sha256", "domain_sha256", "byte_length",
})
_CONTENT_ASSETS_KEYS = frozenset({"storage_descriptor", "schema_registry"})
_DIGEST_DOMAIN_KEYS = frozenset({"name", "domain"})
_RESOURCE_LIMIT_KEYS = frozenset({"name", "maximum", "unit"})
_STANDARD_LIBRARY_KEYS = frozenset({"module", "purpose"})
_EXTERNAL_DISTRIBUTION_KEYS = frozenset({
    "distribution", "version", "import_modules", "metadata_sha256",
})
_RUNTIME_ASSUMPTION_KEYS = frozenset({"name", "expected"})
_GENERATOR_KEYS = frozenset({
    "artifact_path", "artifact_sha256", "generator_version", "invocation",
})
_DENY_BOUNDARY_KEYS = frozenset({
    "positive_status", "anchor_status", "currentness_status",
    "authorizing_use", "live_execution",
})

_BOOTSTRAP_ROLES = frozenset({
    "ATTACHMENT", "RUNTIME_MANIFEST", "ACTIVE_RUNTIME_SELECTOR",
    "SCHEMA_REGISTRY_SCHEMA", "STORAGE_DESCRIPTOR_SCHEMA",
})
_RETAINED_ROLES = frozenset({
    "EVENT_ENVELOPE", "PAYLOAD", "TASK_STATE", "REQUEST",
    "RESPONSE_PROJECTION", "CHECKPOINT_DOCUMENT", "EXPORT_DOCUMENT",
    "LEGACY_ROW_ARCHIVE", "LEGACY_PROJECTION",
})
_BOOTSTRAP_ROLE_BINDINGS = frozenset({
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
})
_RETAINED_ROLE_BINDINGS = frozenset({
    (
        "CHECKPOINT_DOCUMENT",
        "urn:edgelab:m0-3a-runtime-checkpoint:2",
        "schemas/m0-3a-runtime-checkpoint.v2.schema.json",
    ),
    (
        "EVENT_ENVELOPE",
        "urn:edgelab:m0-3a-event-envelope:2",
        "schemas/m0-3a-event-envelope.v2.schema.json",
    ),
    (
        "EXPORT_DOCUMENT",
        "urn:edgelab:m0-3a-runtime-export:2",
        "schemas/m0-3a-runtime-export.v2.schema.json",
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
        "PAYLOAD",
        "urn:edgelab:m0-3a-event-payload:2",
        "schemas/m0-3a-event-payload.v2.schema.json",
    ),
    (
        "REQUEST",
        "urn:edgelab:m0-3a-command-request:2",
        "schemas/m0-3a-command-request.v2.schema.json",
    ),
    (
        "RESPONSE_PROJECTION",
        "urn:edgelab:m0-3a-response-projection:2",
        "schemas/m0-3a-response-projection.v2.schema.json",
    ),
    (
        "TASK_STATE",
        "urn:edgelab:m0-3a-task-state:2",
        "schemas/m0-3a-task-state.v2.schema.json",
    ),
})


def _fail(code: str, coordinate: str) -> None:
    raise ClosureValidationError(code, coordinate)


def _object(value: Any, keys: frozenset[str], coordinate: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("OBJECT_REQUIRED", coordinate)
    if any(type(key) is not str for key in value):
        _fail("STRING_KEY_REQUIRED", coordinate)
    if value.keys() != keys:
        _fail("OBJECT_KEYS", coordinate)
    return value


def _array(
    value: Any,
    coordinate: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> list[Any]:
    if type(value) is not list:
        _fail("ARRAY_REQUIRED", coordinate)
    if len(value) < minimum or (maximum is not None and len(value) > maximum):
        _fail("ARRAY_LENGTH", coordinate)
    return value


def _const(value: Any, expected: Any, coordinate: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _fail("CONST", coordinate)


def _pattern(value: Any, pattern: re.Pattern[str], coordinate: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("PATTERN", coordinate)
    return value


def _path(value: Any, coordinate: str) -> str:
    path = _pattern(value, _PATH, coordinate)
    components = path.split("/")
    if len(path) > _PORTABLE_PATH_MAX or any(
        len(component) > _PORTABLE_COMPONENT_MAX for component in components
    ):
        _fail("PATH_LENGTH", coordinate)
    for component in components:
        if component.endswith("."):
            _fail("PATH_PORTABILITY", coordinate)
        if component.split(".", 1)[0].upper() in _WINDOWS_DEVICE_STEMS:
            _fail("PATH_PORTABILITY", coordinate)
    return path


def _parse_integer_token(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 19:
        raise CanonicalJsonError("INTEGER_TOKEN_TOO_LONG")
    return int(token)


def _parse_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CanonicalJsonError("DUPLICATE_KEY")
        value[key] = item
    return value


def _reject_noninteger_number(_: str) -> None:
    raise CanonicalJsonError("NONINTEGER_NUMBER")


def _parse_closure_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_parse_object,
            parse_int=_parse_integer_token,
            parse_float=_reject_noninteger_number,
            parse_constant=_reject_noninteger_number,
        )
        if canonical_json(value) != raw:
            raise CanonicalJsonError("NONCANONICAL_JSON")
        return value
    except CanonicalJsonError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise CanonicalJsonError("INVALID_JSON") from error


def _distribution_identity(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _has_component_prefix_collision(values: list[str], separator: str) -> bool:
    ordered = sorted(values)
    return any(
        current == previous or current.startswith(previous + separator)
        for previous, current in zip(ordered, ordered[1:])
    )


def _string(value: Any, coordinate: str, minimum: int, maximum: int) -> str:
    if (
        type(value) is not str
        or not minimum <= len(value) <= maximum
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        _fail("STRING", coordinate)
    return value


def _integer(
    value: Any,
    coordinate: str,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        _fail("INTEGER", coordinate)
    return value


def _enum(value: Any, allowed: frozenset[str], coordinate: str) -> str:
    if type(value) is not str or value not in allowed:
        _fail("ENUM", coordinate)
    return value


def _keyed_inventory(
    values: list[Any],
    coordinate: str,
    key_name: str,
    validator: Callable[[Any, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    keys: list[str] = []
    for index, value in enumerate(values):
        item_coordinate = f"{coordinate}/{index}"
        record = validator(value, item_coordinate)
        key = record[key_name]
        if type(key) is not str:
            _fail("INVENTORY_KEY_TYPE", item_coordinate)
        records.append(record)
        keys.append(key)
    for index in range(1, len(keys)):
        if keys[index - 1] == keys[index]:
            _fail("INVENTORY_KEY_DUPLICATE", coordinate)
        if keys[index - 1] > keys[index]:
            _fail("INVENTORY_ORDER", coordinate)
    if len(keys) != len({key.casefold() for key in keys}):
        _fail("INVENTORY_CASE_COLLISION", coordinate)
    return records


def _validate_local_artifact(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _LOCAL_ARTIFACT_KEYS, coordinate)
    _path(record["path"], f"{coordinate}/path")
    _enum(
        record["role"],
        frozenset({"ENTRYPOINT", "PIN_CARRIER", "LOCAL_MODULE"}),
        f"{coordinate}/role",
    )
    _pattern(record["sha256"], _SHA256, f"{coordinate}/sha256")
    _integer(record["byte_length"], f"{coordinate}/byte_length", 1)
    if type(record["pin_elision_applied"]) is not bool:
        _fail("BOOLEAN", f"{coordinate}/pin_elision_applied")
    return record


def _validate_bootstrap_schema(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _BOOTSTRAP_SCHEMA_KEYS, coordinate)
    _enum(record["role"], _BOOTSTRAP_ROLES, f"{coordinate}/role")
    _pattern(record["schema_id"], _SCHEMA_ID, f"{coordinate}/schema_id")
    _path(record["path"], f"{coordinate}/path")
    _pattern(record["raw_sha256"], _SHA256, f"{coordinate}/raw_sha256")
    _pattern(
        record["schema_document_sha256"],
        _SHA256,
        f"{coordinate}/schema_document_sha256",
    )
    _integer(record["byte_length"], f"{coordinate}/byte_length", 1)
    return record


def _validate_retained_schema(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _RETAINED_SCHEMA_KEYS, coordinate)
    _enum(record["content_role"], _RETAINED_ROLES, f"{coordinate}/content_role")
    _pattern(record["schema_id"], _SCHEMA_ID, f"{coordinate}/schema_id")
    _path(record["path"], f"{coordinate}/path")
    _pattern(record["raw_sha256"], _SHA256, f"{coordinate}/raw_sha256")
    _pattern(record["document_sha256"], _SHA256, f"{coordinate}/document_sha256")
    _integer(record["byte_length"], f"{coordinate}/byte_length", 1)
    return record


def _validate_content_asset(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _CONTENT_ASSET_KEYS, coordinate)
    _path(record["path"], f"{coordinate}/path")
    _pattern(record["raw_sha256"], _SHA256, f"{coordinate}/raw_sha256")
    _pattern(record["domain_sha256"], _SHA256, f"{coordinate}/domain_sha256")
    _integer(record["byte_length"], f"{coordinate}/byte_length", 1)
    return record


def _validate_digest_domain(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _DIGEST_DOMAIN_KEYS, coordinate)
    _pattern(record["name"], _LOWER_NAME, f"{coordinate}/name")
    _pattern(record["domain"], _DIGEST_DOMAIN, f"{coordinate}/domain")
    return record


def _validate_resource_limit(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _RESOURCE_LIMIT_KEYS, coordinate)
    _pattern(record["name"], _UPPER_NAME, f"{coordinate}/name")
    _integer(record["maximum"], f"{coordinate}/maximum", 0, _INT64_MAX)
    _enum(
        record["unit"],
        frozenset({"BYTES", "ITEMS", "CHARACTERS", "NODES", "DEPTH"}),
        f"{coordinate}/unit",
    )
    return record


def _validate_standard_library(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _STANDARD_LIBRARY_KEYS, coordinate)
    _pattern(record["module"], _MODULE, f"{coordinate}/module")
    _string(record["purpose"], f"{coordinate}/purpose", 1, 256)
    return record


def _validate_external_distribution(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _EXTERNAL_DISTRIBUTION_KEYS, coordinate)
    distribution = _pattern(
        record["distribution"], _DISTRIBUTION, f"{coordinate}/distribution"
    )
    if distribution != _distribution_identity(distribution):
        _fail("DISTRIBUTION_CANONICAL_NAME", f"{coordinate}/distribution")
    _string(record["version"], f"{coordinate}/version", 1, 128)
    modules = _array(record["import_modules"], f"{coordinate}/import_modules", minimum=1)
    names = [
        _pattern(module, _MODULE, f"{coordinate}/import_modules/{index}")
        for index, module in enumerate(modules)
    ]
    for index in range(1, len(names)):
        if names[index - 1] >= names[index]:
            _fail("IMPORT_MODULE_INVENTORY", f"{coordinate}/import_modules")
    _pattern(record["metadata_sha256"], _SHA256, f"{coordinate}/metadata_sha256")
    return record


def _validate_runtime_assumption(value: Any, coordinate: str) -> dict[str, Any]:
    record = _object(value, _RUNTIME_ASSUMPTION_KEYS, coordinate)
    _pattern(record["name"], _UPPER_NAME, f"{coordinate}/name")
    _string(record["expected"], f"{coordinate}/expected", 1, 256)
    return record


def _unique_paths(namespaces: tuple[list[str], ...]) -> None:
    paths = [path for namespace in namespaces for path in namespace]
    if len(paths) != len(set(paths)):
        _fail("PATH_REUSE", "/")
    if len(paths) != len({path.casefold() for path in paths}):
        _fail("PATH_CASE_COLLISION", "/")


def _validate_verifier_dependency_closure_shape(value: Any) -> None:
    record = _object(value, _TOP_KEYS, "/")
    for name, expected in (
        ("schema_version", 1),
        ("closure_id", "urn:edgelab:m0-3a-verifier-dependency-closure:1"),
        ("closure_version", 1),
        ("runtime_format_version", 2),
        ("canonicalization", "EDGELAB_CANONICAL_JSON_V1"),
        ("digest_algorithm", "SHA-256"),
        ("digest_domain", "EDGELAB\0VERIFIER_DEPENDENCY_CLOSURE\0V2\0"),
    ):
        _const(record[name], expected, f"/{name}")

    entrypoint = _object(record["entrypoint"], _ENTRYPOINT_KEYS, "/entrypoint")
    for name, expected in (
        ("artifact_path", "src/edgelab/runtime_v2_verifier.py"),
        ("module", "edgelab.runtime_v2_verifier"),
        ("callable", "verify_runtime_image"),
    ):
        _const(entrypoint[name], expected, f"/entrypoint/{name}")

    boundary = _object(
        record["root_boundary"], _ROOT_BOUNDARY_KEYS, "/root_boundary"
    )
    _const(boundary["repository_relative"], True, "/root_boundary/repository_relative")
    roots = _array(
        boundary["local_import_roots"],
        "/root_boundary/local_import_roots",
        minimum=1,
    )
    root_names = [
        _path(root, f"/root_boundary/local_import_roots/{index}")
        for index, root in enumerate(roots)
    ]
    for index in range(1, len(root_names)):
        if root_names[index - 1] >= root_names[index]:
            _fail("LOCAL_IMPORT_ROOT_INVENTORY", "/root_boundary/local_import_roots")
    if len(root_names) != len({name.casefold() for name in root_names}):
        _fail("LOCAL_IMPORT_ROOT_CASE_COLLISION", "/root_boundary/local_import_roots")
    root_components = {
        tuple(component.casefold() for component in root.split("/"))
        for root in root_names
    }
    if any(
        parts[:length] in root_components
        for parts in root_components
        for length in range(1, len(parts))
    ):
        _fail("LOCAL_IMPORT_ROOT_OVERLAP", "/root_boundary/local_import_roots")
    root_set = set(root_names)
    for name in ("filesystem_reads", "network_access", "environment_access", "dynamic_imports"):
        _const(boundary[name], "DENY", f"/root_boundary/{name}")

    elision = _object(
        record["pin_elision_profile"], _PIN_ELISION_KEYS, "/pin_elision_profile"
    )
    for name, expected in (
        ("profile_id", "PIN_BLOCK_ELIDED_V1"),
        ("artifact_path", "src/edgelab/_runtime_v2_release.py"),
        ("replacement_literal", "PIN_BLOCK_ELIDED_V1"),
        ("required_match_count", 1),
    ):
        _const(elision[name], expected, f"/pin_elision_profile/{name}")
    begin_marker = _string(
        elision["begin_marker"], "/pin_elision_profile/begin_marker", 1, 256
    )
    end_marker = _string(
        elision["end_marker"], "/pin_elision_profile/end_marker", 1, 256
    )
    if begin_marker == end_marker:
        _fail("PIN_MARKERS_DISTINCT", "/pin_elision_profile")

    local_values = _array(record["local_artifacts"], "/local_artifacts", minimum=1)
    local = _keyed_inventory(
        local_values, "/local_artifacts", "path", _validate_local_artifact
    )
    for index, item in enumerate(local):
        parts = item["path"].split("/")
        root_owners = sum(
            "/".join(parts[:length]) in root_set
            for length in range(1, len(parts))
        )
        if root_owners != 1:
            _fail("LOCAL_ARTIFACT_ROOT", f"/local_artifacts/{index}/path")
    entrypoints = [item for item in local if item["role"] == "ENTRYPOINT"]
    carriers = [item for item in local if item["role"] == "PIN_CARRIER"]
    elided = [item for item in local if item["pin_elision_applied"] is True]
    if len(entrypoints) != 1 or entrypoints[0]["path"] != entrypoint["artifact_path"]:
        _fail("ENTRYPOINT_ARTIFACT", "/local_artifacts")
    if len(carriers) != 1 or carriers[0]["path"] != elision["artifact_path"]:
        _fail("PIN_CARRIER_ARTIFACT", "/local_artifacts")
    if entrypoints[0]["pin_elision_applied"] is not False:
        _fail("ENTRYPOINT_ELISION", "/local_artifacts")
    if len(elided) != 1 or elided[0] is not carriers[0]:
        _fail("PIN_ELISION_CARDINALITY", "/local_artifacts")

    bootstrap_values = _array(
        record["bootstrap_schemas"], "/bootstrap_schemas", minimum=5, maximum=5
    )
    bootstrap = _keyed_inventory(
        bootstrap_values, "/bootstrap_schemas", "path", _validate_bootstrap_schema
    )
    bootstrap_ids = [item["schema_id"] for item in bootstrap]
    bootstrap_roles = [item["role"] for item in bootstrap]
    for index in range(1, len(bootstrap_ids)):
        if bootstrap_ids[index - 1] >= bootstrap_ids[index]:
            _fail("BOOTSTRAP_SCHEMA_ID_INVENTORY", "/bootstrap_schemas")
    if frozenset(bootstrap_roles) != _BOOTSTRAP_ROLES or len(set(bootstrap_roles)) != 5:
        _fail("BOOTSTRAP_ROLE_INVENTORY", "/bootstrap_schemas")
    if frozenset(
        (item["role"], item["schema_id"], item["path"]) for item in bootstrap
    ) != _BOOTSTRAP_ROLE_BINDINGS:
        _fail("BOOTSTRAP_ROLE_BINDING", "/bootstrap_schemas")

    retained_values = _array(
        record["retained_schema_documents"],
        "/retained_schema_documents",
        minimum=9,
        maximum=9,
    )
    retained = _keyed_inventory(
        retained_values,
        "/retained_schema_documents",
        "path",
        _validate_retained_schema,
    )
    retained_ids = [item["schema_id"] for item in retained]
    retained_roles = [item["content_role"] for item in retained]
    for index in range(1, len(retained_ids)):
        if retained_ids[index - 1] >= retained_ids[index]:
            _fail("RETAINED_SCHEMA_ID_INVENTORY", "/retained_schema_documents")
    if frozenset(retained_roles) != _RETAINED_ROLES or len(set(retained_roles)) != 9:
        _fail("RETAINED_ROLE_INVENTORY", "/retained_schema_documents")
    if frozenset(
        (item["content_role"], item["schema_id"], item["path"])
        for item in retained
    ) != _RETAINED_ROLE_BINDINGS:
        _fail("RETAINED_ROLE_BINDING", "/retained_schema_documents")
    all_schema_ids = bootstrap_ids + retained_ids
    if len(all_schema_ids) != len(set(all_schema_ids)):
        _fail("SCHEMA_ID_REUSE", "/")
    if len(all_schema_ids) != len({item.casefold() for item in all_schema_ids}):
        _fail("SCHEMA_ID_CASE_COLLISION", "/")

    content_assets = _object(
        record["content_assets"], _CONTENT_ASSETS_KEYS, "/content_assets"
    )
    assets = [
        _validate_content_asset(content_assets[name], f"/content_assets/{name}")
        for name in sorted(_CONTENT_ASSETS_KEYS)
    ]

    digest_domains = _keyed_inventory(
        _array(record["digest_domains"], "/digest_domains", minimum=1),
        "/digest_domains",
        "name",
        _validate_digest_domain,
    )
    _keyed_inventory(
        _array(record["resource_limits"], "/resource_limits", minimum=1),
        "/resource_limits",
        "name",
        _validate_resource_limit,
    )
    standard_library = _keyed_inventory(
        _array(
            record["standard_library_modules"],
            "/standard_library_modules",
            minimum=1,
        ),
        "/standard_library_modules",
        "module",
        _validate_standard_library,
    )
    external_distributions = _keyed_inventory(
        _array(record["external_distributions"], "/external_distributions"),
        "/external_distributions",
        "distribution",
        _validate_external_distribution,
    )
    _keyed_inventory(
        _array(
            record["tested_runtime_assumptions"],
            "/tested_runtime_assumptions",
            minimum=1,
        ),
        "/tested_runtime_assumptions",
        "name",
        _validate_runtime_assumption,
    )
    if len({item["domain"] for item in digest_domains}) != len(digest_domains):
        _fail("DIGEST_DOMAIN_ALIAS", "/digest_domains")
    external_identities = [
        _distribution_identity(item["distribution"])
        for item in external_distributions
    ]
    if len(external_identities) != len(set(external_identities)):
        _fail("DISTRIBUTION_IDENTITY_REUSE", "/external_distributions")
    module_names = [item["module"] for item in standard_library]
    module_names.extend(
        module
        for distribution in external_distributions
        for module in distribution["import_modules"]
    )
    if _has_component_prefix_collision(module_names, "."):
        _fail("MODULE_NAMESPACE_REUSE", "/external_distributions")

    generator = _object(
        record["generator_identity"], _GENERATOR_KEYS, "/generator_identity"
    )
    _path(generator["artifact_path"], "/generator_identity/artifact_path")
    _pattern(generator["artifact_sha256"], _SHA256, "/generator_identity/artifact_sha256")
    _integer(generator["generator_version"], "/generator_identity/generator_version", 1)
    _string(generator["invocation"], "/generator_identity/invocation", 1, 512)

    deny = _object(
        record["deny_only_boundary"], _DENY_BOUNDARY_KEYS, "/deny_only_boundary"
    )
    for name, expected in (
        ("positive_status", "LOCALLY_CONSISTENT_DENY_ONLY"),
        ("anchor_status", "UNANCHORED"),
        ("currentness_status", "UNKNOWN"),
        ("authorizing_use", "DENY"),
        ("live_execution", "PROHIBITED"),
    ):
        _const(deny[name], expected, f"/deny_only_boundary/{name}")
    _pattern(
        record["verifier_dependency_closure_sha256"],
        _SHA256,
        "/verifier_dependency_closure_sha256",
    )

    _unique_paths((
        [item["path"] for item in local],
        [item["path"] for item in bootstrap],
        [item["path"] for item in retained],
        [item["path"] for item in assets],
        [generator["artifact_path"]],
    ))


def validate_verifier_dependency_closure(raw: bytes) -> dict[str, Any]:
    """Parse and validate canonical closure bytes without establishing identity."""
    if type(raw) is not bytes:
        _fail("BYTES_REQUIRED", "/")
    if len(raw) > MAX_DEPENDENCY_CLOSURE_BYTES:
        _fail("BYTE_LIMIT", "/")
    try:
        value = _parse_closure_json(raw)
    except CanonicalJsonError as error:
        raise ClosureValidationError("CANONICAL_JSON", "/") from error
    _validate_verifier_dependency_closure_shape(value)
    if type(value) is not dict:
        _fail("OBJECT_REQUIRED", "/")
    try:
        derived = verifier_dependency_closure_digest(value)
    except CanonicalJsonError as error:
        raise ClosureValidationError("CLOSURE_VALUE", "/") from error
    if value["verifier_dependency_closure_sha256"] != derived:
        _fail(
            "CLOSURE_SELF_DIGEST_MISMATCH",
            "/verifier_dependency_closure_sha256",
        )
    return value


__all__ = (
    "CLOSURE_SHAPE_VALIDATION_PROFILE",
    "ClosureValidationError",
    "MAX_DEPENDENCY_CLOSURE_BYTES",
    "validate_verifier_dependency_closure",
)
