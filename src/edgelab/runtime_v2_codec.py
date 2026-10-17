"""Pure canonical encoding and domain-separated digests for runtime format 2.

This module performs no I/O and grants no authority.  It intentionally does
not import the active scheduler or any execution, risk, or currentness code.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalJsonError(ValueError):
    """Raised when a value or byte string is outside canonical JSON v1."""


def _reject_float(_: str) -> None:
    raise CanonicalJsonError("FLOAT_NOT_ALLOWED")


def _reject_constant(_: str) -> None:
    raise CanonicalJsonError("NONFINITE_NOT_ALLOWED")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("DUPLICATE_KEY")
        result[key] = value
    return result


def _validate(value: Any, active: set[int], depth: int = 0) -> None:
    if depth > 128:
        raise CanonicalJsonError("MAX_DEPTH_EXCEEDED")
    if value is None or type(value) is bool or type(value) is int:
        return
    if type(value) is str:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalJsonError("UNPAIRED_SURROGATE")
        return
    if type(value) is list:
        identity = id(value)
        if identity in active:
            raise CanonicalJsonError("CYCLIC_VALUE")
        active.add(identity)
        try:
            for item in value:
                _validate(item, active, depth + 1)
        finally:
            active.remove(identity)
        return
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise CanonicalJsonError("CYCLIC_VALUE")
        active.add(identity)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise CanonicalJsonError("NON_STRING_KEY")
                _validate(key, active, depth + 1)
                _validate(item, active, depth + 1)
        finally:
            active.remove(identity)
        return
    raise CanonicalJsonError("UNSUPPORTED_TYPE")


def canonical_json(value: Any) -> bytes:
    """Return EDGELAB_CANONICAL_JSON_V1 bytes for a strict JSON value."""
    _validate(value, set())
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CanonicalJsonError("ENCODING_FAILED") from error


def parse_canonical_json(raw: bytes) -> Any:
    """Parse exact canonical bytes, rejecting aliases and duplicate keys."""
    if type(raw) is not bytes:
        raise CanonicalJsonError("BYTES_REQUIRED")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJsonError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise CanonicalJsonError("INVALID_JSON") from error
    _validate(value, set())
    if canonical_json(value) != raw:
        raise CanonicalJsonError("NONCANONICAL_JSON")
    return value


def _sha(prefix: bytes, payload: bytes) -> str:
    return hashlib.sha256(prefix + payload).hexdigest()


def _canonical_digest(prefix: bytes, value: Any) -> str:
    return _sha(prefix, canonical_json(value))


def blob_digest(value: Any) -> str:
    return _canonical_digest(b"EDGELAB\0BLOB\0V2\0", value)


def event_digest(event: dict[str, Any]) -> str:
    if type(event) is not dict or "event_sha256" not in event:
        raise CanonicalJsonError("EVENT_DIGEST_FIELD_REQUIRED")
    body = dict(event)
    del body["event_sha256"]
    return _canonical_digest(b"EDGELAB\0EVENT\0V2\0", body)


def checkpoint_digest(checkpoint: dict[str, Any]) -> str:
    if type(checkpoint) is not dict or "checkpoint_sha256" not in checkpoint:
        raise CanonicalJsonError("CHECKPOINT_DIGEST_FIELD_REQUIRED")
    body = dict(checkpoint)
    del body["checkpoint_sha256"]
    return _canonical_digest(b"EDGELAB\0CHECKPOINT\0V2\0", body)


def manifest_digest(manifest: dict[str, Any]) -> str:
    return _canonical_digest(b"EDGELAB\0MANIFEST\0V2\0", manifest)


def selector_digest(selector: dict[str, Any]) -> str:
    if type(selector) is not dict or "selector_sha256" not in selector:
        raise CanonicalJsonError("SELECTOR_DIGEST_FIELD_REQUIRED")
    body = dict(selector)
    del body["selector_sha256"]
    return _canonical_digest(b"EDGELAB\0SELECTOR\0V1\0", body)


def schema_registry_digest(registry: dict[str, Any]) -> str:
    return _canonical_digest(b"EDGELAB\0SCHEMA_REGISTRY\0V2\0", registry)


def schema_document_digest(document: dict[str, Any]) -> str:
    return _canonical_digest(b"EDGELAB\0SCHEMA_DOCUMENT\0V2\0", document)


def storage_schema_digest(descriptor: dict[str, Any]) -> str:
    return _canonical_digest(b"EDGELAB\0STORAGE_SCHEMA\0V2\0", descriptor)


def selector_history_digest(selectors: list[dict[str, Any]]) -> str:
    return _canonical_digest(b"EDGELAB\0SELECTOR_HISTORY\0V1\0", selectors)


def sqlite_structure_digest(observation: dict[str, Any]) -> str:
    return _canonical_digest(b"EDGELAB\0SQLITE_STRUCTURE\0V2\0", observation)


def sqlite_compile_options_digest(options: list[str]) -> str:
    return _canonical_digest(b"EDGELAB\0SQLITE_COMPILE_OPTIONS\0V2\0", options)


def table_root(table_name: str, ordered_rows: list[Any]) -> str:
    if type(table_name) is not str or not table_name or "\0" in table_name:
        raise CanonicalJsonError("INVALID_TABLE_NAME")
    return _sha(
        b"EDGELAB\0TABLE\0V2\0" + table_name.encode("utf-8") + b"\0",
        canonical_json(ordered_rows),
    )


def task_predecessor(chain_id: str, task_id: str, attempt: int) -> tuple[str, str]:
    if type(chain_id) is not str or type(task_id) is not str or not task_id:
        raise CanonicalJsonError("INVALID_TASK_COORDINATE")
    if type(attempt) is not int or attempt < 1 or attempt > 9223372036854775807:
        raise CanonicalJsonError("INVALID_TASK_ATTEMPT")
    coordinates = {"attempt": attempt, "chain_id": chain_id, "task_id": task_id}
    digest = _canonical_digest(
        b"EDGELAB\0EVENT\0V2\0TASK_PREDECESSOR\0", coordinates
    )
    return f"FORMAT2_TASK_PREDECESSOR:{digest}", digest


def legacy_digest(kind: str, value: Any, table_name: str | None = None) -> str:
    """Compute one of the closed format-1 archival digest domains."""
    domains: dict[str, bytes] = {
        "archive": b"EDGELAB\0LEGACY_ROWS\0V1\0",
        "projection": b"EDGELAB\0LEGACY_PROJECTION\0V1\0",
        "storage": b"EDGELAB\0LEGACY_STORAGE\0V1\0",
    }
    if kind == "projection" and table_name is None:
        if type(value) is not dict or "projection_sha256" not in value:
            raise CanonicalJsonError("PROJECTION_DIGEST_FIELD_REQUIRED")
        body = dict(value)
        del body["projection_sha256"]
        return _canonical_digest(domains[kind], body)
    if kind in domains and table_name is None:
        return _canonical_digest(domains[kind], value)
    table_domains: dict[str, bytes] = {
        "columns": b"EDGELAB\0LEGACY_COLUMNS\0V1\0",
        "rows": b"EDGELAB\0LEGACY_TABLE_ROWS\0V1\0",
    }
    if kind not in table_domains or type(table_name) is not str or not table_name:
        raise CanonicalJsonError("INVALID_LEGACY_DIGEST_DOMAIN")
    return _sha(
        table_domains[kind] + table_name.encode("utf-8") + b"\0",
        canonical_json(value),
    )
