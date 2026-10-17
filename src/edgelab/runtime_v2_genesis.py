"""Compiled strict validators for the runtime-format-2 NEW genesis group.

The retained JSON Schema documents establish bundle identity, but candidate
schemas never execute inside reduction.  These functions implement only the
closed SYSTEM_GENESIS/RUNTIME_GENESIS alternatives needed by the initial NEW
runtime reducer.  They perform no I/O and grant no authority.
"""
from __future__ import annotations

import re
from typing import Any


NEW_GENESIS_VALIDATION_PROFILE = "EDGELAB_RUNTIME_V2_NEW_GENESIS_STRICT_V1"
REQUEST_SCHEMA_ID = "urn:edgelab:m0-3a-command-request:2"
RESPONSE_SCHEMA_ID = "urn:edgelab:m0-3a-response-projection:2"
PAYLOAD_SCHEMA_ID = "urn:edgelab:m0-3a-event-payload:2"


class GenesisValidationError(ValueError):
    """A parsed value is outside the compiled NEW-genesis profile."""

    def __init__(self, code: str, coordinate: str) -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECOND = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)

_REQUEST_KEYS = frozenset({
    "schema_version", "request_format_version", "runtime_id", "chain_id",
    "operation", "operation_key", "repository_generation",
    "repository_bundle_sha256", "subject", "expected_state_ref", "arguments",
})
_GENESIS_ARGUMENT_KEYS = frozenset({
    "attachment_sha256", "schema_registry_sha256", "storage_schema_sha256",
})
_RESPONSE_KEYS = frozenset({
    "schema_version", "response_format_version", "runtime_id", "chain_id",
    "operation", "operation_key", "status", "affected_states", "generated_refs",
})
_PAYLOAD_KEYS = frozenset({
    "schema_version", "payload_format_version", "event_type", "data",
})
_GENESIS_DATA_KEYS = frozenset({
    "runtime_id", "chain_id", "runtime_format_version", "event_format_version",
    "attachment_sha256", "storage_schema_sha256", "schema_registry_sha256",
    "verifier_dependency_closure_sha256", "repository_generation",
    "repository_bundle_sha256",
})
_EVENT_KEYS = frozenset({
    "schema_version", "event_format_version", "runtime_id", "chain_id",
    "event_id", "event_type", "occurred_at", "global_sequence",
    "global_predecessor", "stream", "task_context", "transaction",
    "payload_ref", "state_before_ref", "state_after_ref",
    "repository_generation", "repository_bundle_sha256",
    "authority_binding_sha256", "authorizing_use", "event_sha256",
})
_PREDECESSOR_KEYS = frozenset({"event_id", "event_sha256"})
_TRANSACTION_KEYS = frozenset({
    "transaction_id", "position", "event_count", "operation_key",
    "request_sha256", "response_sha256",
})
_BLOB_REF_KEYS = frozenset({"schema_id", "sha256"})


def _fail(code: str, coordinate: str) -> None:
    raise GenesisValidationError(code, coordinate)


def _object(value: Any, keys: frozenset[str], coordinate: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("OBJECT_REQUIRED", coordinate)
    if any(type(key) is not str for key in value):
        _fail("STRING_KEY_REQUIRED", coordinate)
    if value.keys() != keys:
        _fail("OBJECT_KEYS", coordinate)
    return value


def _const(value: Any, expected: Any, coordinate: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _fail("CONST", coordinate)


def _pattern(value: Any, pattern: re.Pattern[str], coordinate: str) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("PATTERN", coordinate)


def _empty_list(value: Any, coordinate: str) -> None:
    if type(value) is not list or value:
        _fail("EMPTY_ARRAY_REQUIRED", coordinate)


def _utc_second(value: Any, coordinate: str) -> None:
    if type(value) is not str:
        _fail("UTC_SECOND", coordinate)
    match = _UTC_SECOND.fullmatch(value)
    if match is None:
        _fail("UTC_SECOND", coordinate)
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    if year == 0 or not 1 <= month <= 12 or hour > 23 or minute > 59 or second > 59:
        _fail("UTC_SECOND", coordinate)
    month_lengths = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    maximum_day = month_lengths[month - 1]
    if month == 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        maximum_day = 29
    if not 1 <= day <= maximum_day:
        _fail("UTC_SECOND", coordinate)


def validate_new_genesis_request(value: Any) -> None:
    request = _object(value, _REQUEST_KEYS, "/")
    _const(request["schema_version"], 1, "/schema_version")
    _const(request["request_format_version"], 2, "/request_format_version")
    _pattern(request["runtime_id"], _UUID4, "/runtime_id")
    _pattern(request["chain_id"], _SHA256, "/chain_id")
    _const(request["operation"], "SYSTEM_GENESIS", "/operation")
    _const(request["operation_key"], "system:v2:genesis", "/operation_key")
    _const(request["repository_generation"], 0, "/repository_generation")
    _pattern(request["repository_bundle_sha256"], _SHA256, "/repository_bundle_sha256")
    _const(request["subject"], None, "/subject")
    _const(request["expected_state_ref"], None, "/expected_state_ref")
    arguments = _object(request["arguments"], _GENESIS_ARGUMENT_KEYS, "/arguments")
    for name in sorted(_GENESIS_ARGUMENT_KEYS):
        _pattern(arguments[name], _SHA256, f"/arguments/{name}")


def validate_new_genesis_response(value: Any) -> None:
    response = _object(value, _RESPONSE_KEYS, "/")
    _const(response["schema_version"], 1, "/schema_version")
    _const(response["response_format_version"], 2, "/response_format_version")
    _pattern(response["runtime_id"], _UUID4, "/runtime_id")
    _pattern(response["chain_id"], _SHA256, "/chain_id")
    _const(response["operation"], "SYSTEM_GENESIS", "/operation")
    _const(response["operation_key"], "system:v2:genesis", "/operation_key")
    _const(response["status"], "COMMITTED", "/status")
    _empty_list(response["affected_states"], "/affected_states")
    _empty_list(response["generated_refs"], "/generated_refs")


def validate_runtime_genesis_payload(value: Any) -> None:
    payload = _object(value, _PAYLOAD_KEYS, "/")
    _const(payload["schema_version"], 1, "/schema_version")
    _const(payload["payload_format_version"], 2, "/payload_format_version")
    _const(payload["event_type"], "RUNTIME_GENESIS", "/event_type")
    data = _object(payload["data"], _GENESIS_DATA_KEYS, "/data")
    _pattern(data["runtime_id"], _UUID4, "/data/runtime_id")
    _pattern(data["chain_id"], _SHA256, "/data/chain_id")
    _const(data["runtime_format_version"], 2, "/data/runtime_format_version")
    _const(data["event_format_version"], 2, "/data/event_format_version")
    for name in (
        "attachment_sha256", "storage_schema_sha256", "schema_registry_sha256",
        "verifier_dependency_closure_sha256", "repository_bundle_sha256",
    ):
        _pattern(data[name], _SHA256, f"/data/{name}")
    _const(data["repository_generation"], 0, "/data/repository_generation")


def validate_runtime_genesis_envelope(value: Any) -> None:
    event = _object(value, _EVENT_KEYS, "/")
    _const(event["schema_version"], 1, "/schema_version")
    _const(event["event_format_version"], 2, "/event_format_version")
    _pattern(event["runtime_id"], _UUID4, "/runtime_id")
    _pattern(event["chain_id"], _SHA256, "/chain_id")
    _pattern(event["event_id"], _UUID4, "/event_id")
    _const(event["event_type"], "RUNTIME_GENESIS", "/event_type")
    _utc_second(event["occurred_at"], "/occurred_at")
    _const(event["global_sequence"], 0, "/global_sequence")
    predecessor = _object(event["global_predecessor"], _PREDECESSOR_KEYS, "/global_predecessor")
    _const(predecessor["event_id"], "FORMAT2_GENESIS_PREDECESSOR", "/global_predecessor/event_id")
    _const(
        predecessor["event_sha256"],
        "228a5eca65d6da5649229c520a9c922c7de239b821e362beddadacdf278f5a99",
        "/global_predecessor/event_sha256",
    )
    _const(event["stream"], "RUNTIME", "/stream")
    _const(event["task_context"], None, "/task_context")
    transaction = _object(event["transaction"], _TRANSACTION_KEYS, "/transaction")
    _pattern(transaction["transaction_id"], _UUID4, "/transaction/transaction_id")
    _const(transaction["position"], 0, "/transaction/position")
    _const(transaction["event_count"], 1, "/transaction/event_count")
    _const(transaction["operation_key"], "system:v2:genesis", "/transaction/operation_key")
    _pattern(transaction["request_sha256"], _SHA256, "/transaction/request_sha256")
    _pattern(transaction["response_sha256"], _SHA256, "/transaction/response_sha256")
    payload_ref = _object(event["payload_ref"], _BLOB_REF_KEYS, "/payload_ref")
    _const(payload_ref["schema_id"], PAYLOAD_SCHEMA_ID, "/payload_ref/schema_id")
    _pattern(payload_ref["sha256"], _SHA256, "/payload_ref/sha256")
    _const(event["state_before_ref"], None, "/state_before_ref")
    _const(event["state_after_ref"], None, "/state_after_ref")
    _const(event["repository_generation"], 0, "/repository_generation")
    _pattern(event["repository_bundle_sha256"], _SHA256, "/repository_bundle_sha256")
    _const(event["authority_binding_sha256"], None, "/authority_binding_sha256")
    _const(event["authorizing_use"], "DENY", "/authorizing_use")
    _pattern(event["event_sha256"], _SHA256, "/event_sha256")


__all__ = (
    "GenesisValidationError",
    "NEW_GENESIS_VALIDATION_PROFILE",
    "PAYLOAD_SCHEMA_ID",
    "REQUEST_SCHEMA_ID",
    "RESPONSE_SCHEMA_ID",
    "validate_new_genesis_request",
    "validate_new_genesis_response",
    "validate_runtime_genesis_envelope",
    "validate_runtime_genesis_payload",
)
