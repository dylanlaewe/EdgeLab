"""Private atomic transaction-group planning for runtime format 2.

This first compiled slice supports only ``INITIALIZE`` after a validated NEW
genesis.  It is deliberately narrow: supplied blobs and events are treated as
untrusted comparison inputs, the task state is recomputed with the immutable
transition kernel, and no result can authorize use.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

from .runtime_v2_codec import event_digest, task_predecessor
from .runtime_v2_genesis import PAYLOAD_SCHEMA_ID, REQUEST_SCHEMA_ID, RESPONSE_SCHEMA_ID
from .runtime_v2_transition import (
    ReducerState,
    TransitionIntent,
    TransitionViolation,
    reduce_transition,
)


TASK_STATE_SCHEMA_ID = "urn:edgelab:m0-3a-task-state:2"
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TASK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OPERATION_KEY = re.compile(r"^v2:([0-9a-f]{64}):[\x21-\x7e]{1,180}$")
_UTC_SECOND = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)
_EVENT_KEYS = frozenset({
    "schema_version", "event_format_version", "runtime_id", "chain_id",
    "event_id", "event_type", "occurred_at", "global_sequence",
    "global_predecessor", "stream", "task_context", "transaction",
    "payload_ref", "state_before_ref", "state_after_ref",
    "repository_generation", "repository_bundle_sha256",
    "authority_binding_sha256", "authorizing_use", "event_sha256",
})
_REQUEST_KEYS = frozenset({
    "schema_version", "request_format_version", "runtime_id", "chain_id",
    "operation", "operation_key", "repository_generation",
    "repository_bundle_sha256", "subject", "expected_state_ref", "arguments",
})
_RESPONSE_KEYS = frozenset({
    "schema_version", "response_format_version", "runtime_id", "chain_id",
    "operation", "operation_key", "status", "affected_states", "generated_refs",
})
_PAYLOAD_KEYS = frozenset({"schema_version", "payload_format_version", "event_type", "data"})


class GroupValidationError(ValueError):
    """Stable rejection from the private transaction-group planner."""

    def __init__(self, code: str, coordinate: str = "/") -> None:
        self.code = code
        self.coordinate = coordinate
        super().__init__(f"{code}:{coordinate}")


@dataclass(frozen=True, slots=True)
class BlobValue:
    schema_id: str
    value: Any
    canonical_text: str


@dataclass(frozen=True, slots=True)
class InitializeGroupPatch:
    state: ReducerState
    reachable_blob_digests: tuple[str, ...]
    attempt_row: tuple[Any, ...]
    idempotency_row: tuple[Any, ...]


def _deny(code: str, coordinate: str = "/") -> None:
    raise GroupValidationError(code, coordinate)


def _object(value: Any, keys: frozenset[str], coordinate: str) -> dict[str, Any]:
    if type(value) is not dict or value.keys() != keys:
        _deny("GROUP_OBJECT", coordinate)
    return value


def _const(value: Any, expected: Any, coordinate: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _deny("GROUP_CONST", coordinate)


def _pattern(value: Any, pattern: re.Pattern[str], coordinate: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _deny("GROUP_PATTERN", coordinate)
    return value


def _integer(value: Any, minimum: int, maximum: int, coordinate: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _deny("GROUP_INTEGER", coordinate)
    return value


def _utc_second(value: Any, coordinate: str) -> str:
    text = _pattern(value, _UTC_SECOND, coordinate)
    match = _UTC_SECOND.fullmatch(text)
    assert match is not None
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    month_lengths = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    leap = month == 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    maximum_day = 29 if leap else month_lengths[month - 1] if 1 <= month <= 12 else 0
    if year == 0 or not 1 <= day <= maximum_day or hour > 23 or minute > 59 or second > 59:
        _deny("GROUP_UTC_SECOND", coordinate)
    return text


def _ref(value: Any, schema_id: str, coordinate: str) -> str:
    ref = _object(value, frozenset({"schema_id", "sha256"}), coordinate)
    _const(ref["schema_id"], schema_id, f"{coordinate}/schema_id")
    return _pattern(ref["sha256"], _DIGEST, f"{coordinate}/sha256")


def _resolve(
    catalog: Mapping[str, BlobValue], digest: str, schema_id: str, coordinate: str,
) -> BlobValue:
    item = catalog.get(digest)
    if item is None:
        _deny("GROUP_BLOB_MISSING", coordinate)
    if item.schema_id != schema_id:
        _deny("GROUP_BLOB_ROLE", coordinate)
    return item


def _validate_event_shape(event: Any, coordinate: str) -> dict[str, Any]:
    value = _object(event, _EVENT_KEYS, coordinate)
    _const(value["schema_version"], 1, f"{coordinate}/schema_version")
    _const(value["event_format_version"], 2, f"{coordinate}/event_format_version")
    _pattern(value["runtime_id"], _UUID4, f"{coordinate}/runtime_id")
    _pattern(value["chain_id"], _DIGEST, f"{coordinate}/chain_id")
    _pattern(value["event_id"], _UUID4, f"{coordinate}/event_id")
    _utc_second(value["occurred_at"], f"{coordinate}/occurred_at")
    _integer(value["global_sequence"], 0, 9_223_372_036_854_775_807, f"{coordinate}/global_sequence")
    predecessor = _object(
        value["global_predecessor"], frozenset({"event_id", "event_sha256"}),
        f"{coordinate}/global_predecessor",
    )
    _pattern(predecessor["event_id"], _UUID4, f"{coordinate}/global_predecessor/event_id")
    _pattern(predecessor["event_sha256"], _DIGEST, f"{coordinate}/global_predecessor/event_sha256")
    transaction = _object(
        value["transaction"],
        frozenset({"transaction_id", "position", "event_count", "operation_key", "request_sha256", "response_sha256"}),
        f"{coordinate}/transaction",
    )
    _pattern(transaction["transaction_id"], _UUID4, f"{coordinate}/transaction/transaction_id")
    _integer(transaction["position"], 0, 10_001, f"{coordinate}/transaction/position")
    _integer(transaction["event_count"], 1, 10_002, f"{coordinate}/transaction/event_count")
    _pattern(transaction["operation_key"], _OPERATION_KEY, f"{coordinate}/transaction/operation_key")
    _pattern(transaction["request_sha256"], _DIGEST, f"{coordinate}/transaction/request_sha256")
    _pattern(transaction["response_sha256"], _DIGEST, f"{coordinate}/transaction/response_sha256")
    _ref(value["payload_ref"], PAYLOAD_SCHEMA_ID, f"{coordinate}/payload_ref")
    _integer(value["repository_generation"], 0, 9_223_372_036_854_775_807, f"{coordinate}/repository_generation")
    _pattern(value["repository_bundle_sha256"], _DIGEST, f"{coordinate}/repository_bundle_sha256")
    _const(value["authority_binding_sha256"], None, f"{coordinate}/authority_binding_sha256")
    _const(value["authorizing_use"], "DENY", f"{coordinate}/authorizing_use")
    _pattern(value["event_sha256"], _DIGEST, f"{coordinate}/event_sha256")
    if event_digest(value) != value["event_sha256"]:
        _deny("GROUP_EVENT_DIGEST", f"{coordinate}/event_sha256")
    return value


def _task_state_document(state: Any) -> dict[str, Any]:
    return asdict(state)


def reduce_initialize_group(
    *,
    genesis_event: dict[str, Any],
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> InitializeGroupPatch:
    """Validate and plan one complete INITIALIZE group atomically."""
    semantic = _validate_event_shape(semantic_event, "/events/1")
    commit = _validate_event_shape(commit_event, "/events/2")
    runtime_id = genesis_event["runtime_id"]
    chain_id = genesis_event["chain_id"]
    repository_generation = genesis_event["repository_generation"]
    repository_bundle = genesis_event["repository_bundle_sha256"]
    transaction = semantic["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(match.group(1), chain_id, "/events/1/transaction/operation_key")
    if len({
        genesis_event["event_id"], semantic["event_id"], commit["event_id"],
    }) != 3:
        _deny("GROUP_EVENT_ID_DUPLICATE", "/events")
    if len({
        genesis_event["event_sha256"], semantic["event_sha256"], commit["event_sha256"],
    }) != 3:
        _deny("GROUP_EVENT_DIGEST_DUPLICATE", "/events")
    if transaction["transaction_id"] == genesis_event["transaction"]["transaction_id"]:
        _deny("GROUP_TRANSACTION_DUPLICATE", "/events/1/transaction/transaction_id")

    shared = (
        "runtime_id", "chain_id", "occurred_at", "repository_generation",
        "repository_bundle_sha256",
    )
    for name in shared:
        _const(commit[name], semantic[name], f"/events/2/{name}")
    for name in (
        "transaction_id", "event_count", "operation_key", "request_sha256",
        "response_sha256",
    ):
        _const(commit["transaction"][name], transaction[name], f"/events/2/transaction/{name}")
    for event, position in ((semantic, 0), (commit, 1)):
        _const(event["runtime_id"], runtime_id, f"/events/{position + 1}/runtime_id")
        _const(event["chain_id"], chain_id, f"/events/{position + 1}/chain_id")
        _const(event["repository_generation"], repository_generation, f"/events/{position + 1}/repository_generation")
        _const(event["repository_bundle_sha256"], repository_bundle, f"/events/{position + 1}/repository_bundle_sha256")
        _const(event["global_sequence"], position + 1, f"/events/{position + 1}/global_sequence")
        _const(event["transaction"]["position"], position, f"/events/{position + 1}/transaction/position")
        _const(event["transaction"]["event_count"], 2, f"/events/{position + 1}/transaction/event_count")
    _const(semantic["global_predecessor"], {
        "event_id": genesis_event["event_id"], "event_sha256": genesis_event["event_sha256"],
    }, "/events/1/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": semantic["event_id"], "event_sha256": semantic["event_sha256"],
    }, "/events/2/global_predecessor")
    _const(semantic["event_type"], "TASK_INITIALIZED", "/events/1/event_type")
    _const(semantic["stream"], "TASK", "/events/1/stream")
    _const(commit["event_type"], "COMMAND_COMMITTED", "/events/2/event_type")
    _const(commit["stream"], "RUNTIME", "/events/2/stream")
    _const(commit["task_context"], None, "/events/2/task_context")
    _const(commit["state_before_ref"], None, "/events/2/state_before_ref")
    _const(commit["state_after_ref"], None, "/events/2/state_after_ref")

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(_resolve(catalog, request_sha, REQUEST_SCHEMA_ID, "/request").value, _REQUEST_KEYS, "/request")
    response = _object(_resolve(catalog, response_sha, RESPONSE_SCHEMA_ID, "/response").value, _RESPONSE_KEYS, "/response")
    for artifact, value, version_key in (
        ("request", request, "request_format_version"),
        ("response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], "INITIALIZE", f"/{artifact}/operation")
        _const(value["operation_key"], operation_key, f"/{artifact}/operation_key")
    _const(request["repository_generation"], repository_generation, "/request/repository_generation")
    _const(request["repository_bundle_sha256"], repository_bundle, "/request/repository_bundle_sha256")
    subject = _object(request["subject"], frozenset({"task_id", "attempt"}), "/request/subject")
    task_id = _pattern(subject["task_id"], _TASK, "/request/subject/task_id")
    _const(subject["attempt"], 1, "/request/subject/attempt")
    _const(request["expected_state_ref"], None, "/request/expected_state_ref")
    arguments = _object(
        request["arguments"],
        frozenset({"decision_receipt_digest", "owner", "owner_role"}),
        "/request/arguments",
    )
    _pattern(arguments["decision_receipt_digest"], _DIGEST, "/request/arguments/decision_receipt_digest")
    for name in ("owner", "owner_role"):
        if type(arguments[name]) is not str or not 1 <= len(arguments[name]) <= 256 or any(
            ord(character) < 0x20 or ord(character) > 0x7E for character in arguments[name]
        ):
            _deny("GROUP_IDENTITY", f"/request/arguments/{name}")
    _const(response["status"], "COMMITTED", "/response/status")
    _const(response["generated_refs"], [], "/response/generated_refs")

    context = _object(
        semantic["task_context"],
        frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
        "/events/1/task_context",
    )
    _const(context["task_id"], task_id, "/events/1/task_context/task_id")
    _const(context["attempt"], 1, "/events/1/task_context/attempt")
    _const(context["task_sequence"], 1, "/events/1/task_context/task_sequence")
    predecessor_id, predecessor_sha = task_predecessor(chain_id, task_id, 1)
    _const(context["task_predecessor"], {
        "event_id": predecessor_id, "event_sha256": predecessor_sha,
    }, "/events/1/task_context/task_predecessor")
    _const(semantic["state_before_ref"], None, "/events/1/state_before_ref")
    after_sha = _ref(semantic["state_after_ref"], TASK_STATE_SCHEMA_ID, "/events/1/state_after_ref")

    semantic_payload_sha = semantic["payload_ref"]["sha256"]
    semantic_payload = _object(
        _resolve(catalog, semantic_payload_sha, PAYLOAD_SCHEMA_ID, "/events/1/payload_ref").value,
        _PAYLOAD_KEYS, "/semantic_payload",
    )
    _const(semantic_payload, {
        "schema_version": 1, "payload_format_version": 2,
        "event_type": "TASK_INITIALIZED", "data": {},
    }, "/semantic_payload")

    try:
        next_state = reduce_transition(
            ReducerState(repository_generation, repository_bundle),
            TransitionIntent(
                operation="INITIALIZE", task_id=task_id, attempt=1,
                arguments=tuple(sorted(arguments.items())),
                semantic_event_ids=(semantic["event_id"],),
            ),
        )
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    derived_state = _task_state_document(next_state.tasks[0])
    supplied_state = _resolve(catalog, after_sha, TASK_STATE_SCHEMA_ID, "/events/1/state_after_ref").value
    if supplied_state != derived_state:
        _deny("GROUP_STATE_DERIVATION", "/events/1/state_after_ref")
    expected_affected = [{
        "task_id": task_id, "attempt": 1,
        "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
    }]
    _const(response["affected_states"], expected_affected, "/response/affected_states")

    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID, "/events/2/payload_ref").value,
        _PAYLOAD_KEYS, "/commit_payload",
    )
    expected_commit_payload = {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic["event_id"]],
            "pre_command_head": {
                "global_sequence": 0,
                "event_id": genesis_event["event_id"],
                "event_sha256": genesis_event["event_sha256"],
            },
            "post_semantic_head": {
                "global_sequence": 1,
                "event_id": semantic["event_id"],
                "event_sha256": semantic["event_sha256"],
            },
            "operation": "INITIALIZE",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }
    _const(commit_payload, expected_commit_payload, "/commit_payload")
    reachable = tuple(sorted({
        request_sha, response_sha, semantic_payload_sha, commit_payload_sha, after_sha,
    }))
    return InitializeGroupPatch(
        state=next_state,
        reachable_blob_digests=reachable,
        attempt_row=(task_id, 1, None, semantic["event_id"], 1, semantic["event_id"], semantic["event_sha256"]),
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha, response_sha,
            commit["event_id"], 2, semantic["occurred_at"],
        ),
    )


__all__ = (
    "BlobValue", "GroupValidationError", "InitializeGroupPatch",
    "TASK_STATE_SCHEMA_ID", "reduce_initialize_group",
)
