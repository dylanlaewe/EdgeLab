"""Private atomic transaction-group planning for runtime format 2.

The compiled slices support ``INITIALIZE`` after a validated NEW genesis,
followed by repeatable ``CLAIM``, worker operations ``START``, ``CONTINUE``,
``YIELD``, ``FAIL``, and ``COMPLETE``, synthetic ``RECOVER``, and exact
attempt-boundary ``RETRY``, plus ``GOVERNANCE_BLOCK`` and ``REVALIDATE``.
They are deliberately
narrow: supplied blobs and events are treated as untrusted comparison inputs,
task state is recomputed with the immutable transition kernel, and no result
can authorize use.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

from .runtime_v2_codec import event_digest, task_predecessor
from .runtime_v2_genesis import PAYLOAD_SCHEMA_ID, REQUEST_SCHEMA_ID, RESPONSE_SCHEMA_ID
from .runtime_v2_transition import (
    TransitionIntent,
    TransitionViolation,
    _StagedTransition,
    _TransitionWorkspace,
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
_FOLLOWUP_PROFILES = {
    "TASK_STARTED": ("START", frozenset({"claim_id", "fence"})),
    "TASK_CONTINUED": (
        "CONTINUE",
        frozenset({"claim_id", "fence", "progress_evidence_sha256"}),
    ),
    "TASK_FAILED": (
        "FAIL",
        frozenset({
            "claim_id", "fence", "failure_code",
            "failure_evidence_sha256",
        }),
    ),
    "TASK_COMPLETED": (
        "COMPLETE",
        frozenset({
            "claim_id", "fence", "close", "completion_evidence_sha256",
        }),
    ),
    "CLAIM_RECOVERED": (
        "RECOVER",
        frozenset({"claim_id", "liveness_evidence_sha256"}),
    ),
    "TASK_YIELDED": (
        "YIELD",
        frozenset({"claim_id", "fence", "yield_evidence_sha256"}),
    ),
    "TASK_RETRIED": (
        "RETRY",
        frozenset({"retry_evidence_sha256", "retryable"}),
    ),
    "GOVERNANCE_BLOCKED": (
        "GOVERNANCE_BLOCK",
        frozenset({"evidence_sha256", "reason_code"}),
    ),
    "GOVERNANCE_REVALIDATED": (
        "REVALIDATE",
        frozenset({"evidence_sha256"}),
    ),
    "REVIEW_ASSIGNED": (
        "ASSIGN_REVIEW",
        frozenset({"actor", "role"}),
    ),
}


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
class _TaskReplayHead:
    predecessor_attempt: int | None
    origin_event_id: str
    sequence: int
    head_event_id: str
    head_event_sha256: str


class _ReplayCursor:
    """Private mutable indexes derived only from fully accepted event groups.

    The cursor is an in-memory replay optimization, never a candidate artifact
    or authority carrier. A group may inspect it while validating, but the
    top-level reducer advances it only after the complete group succeeds.
    """

    __slots__ = (
        "runtime_id", "chain_id", "repository_generation",
        "repository_bundle_sha256", "global_sequence", "head_event_id",
        "head_event_sha256", "_event_ids", "_event_digests",
        "_transaction_ids", "_operation_keys", "_task_heads",
    )

    def __init__(self, genesis_event: dict[str, Any]) -> None:
        if type(genesis_event) is not dict:
            _deny("GROUP_CURSOR_GENESIS", "/events/0")
        transaction = genesis_event.get("transaction")
        if type(transaction) is not dict:
            _deny("GROUP_CURSOR_GENESIS", "/events/0/transaction")
        self.runtime_id = genesis_event["runtime_id"]
        self.chain_id = genesis_event["chain_id"]
        self.repository_generation = genesis_event["repository_generation"]
        self.repository_bundle_sha256 = genesis_event[
            "repository_bundle_sha256"
        ]
        self.global_sequence = genesis_event["global_sequence"]
        self.head_event_id = genesis_event["event_id"]
        self.head_event_sha256 = genesis_event["event_sha256"]
        self._event_ids = {genesis_event["event_id"]}
        self._event_digests = {genesis_event["event_sha256"]}
        self._transaction_ids = {transaction["transaction_id"]}
        self._operation_keys = {transaction["operation_key"]}
        self._task_heads: dict[tuple[str, int], _TaskReplayHead] = {}

    def check_pair(
        self, semantic: dict[str, Any], commit: dict[str, Any]
    ) -> tuple[int, int]:
        semantic_index = self.global_sequence + 1
        commit_index = semantic_index + 1
        if (
            semantic["event_id"] in self._event_ids
            or commit["event_id"] in self._event_ids
            or semantic["event_id"] == commit["event_id"]
        ):
            _deny("GROUP_EVENT_ID_DUPLICATE", f"/events/{semantic_index}")
        if (
            semantic["event_sha256"] in self._event_digests
            or commit["event_sha256"] in self._event_digests
            or semantic["event_sha256"] == commit["event_sha256"]
        ):
            _deny("GROUP_EVENT_DIGEST_DUPLICATE", f"/events/{semantic_index}")
        transaction = semantic["transaction"]
        if transaction["transaction_id"] in self._transaction_ids:
            _deny(
                "GROUP_TRANSACTION_DUPLICATE",
                f"/events/{semantic_index}/transaction/transaction_id",
            )
        if transaction["operation_key"] in self._operation_keys:
            _deny(
                "GROUP_OPERATION_KEY_DUPLICATE",
                f"/events/{semantic_index}/transaction/operation_key",
            )
        return semantic_index, commit_index

    def task_head(self, task_id: str, attempt: int) -> _TaskReplayHead | None:
        return self._task_heads.get((task_id, attempt))

    def attempt_rows(self) -> tuple[tuple[Any, ...], ...]:
        """Project every accepted attempt from the cursor-owned task heads."""
        return tuple(
            (
                task_id,
                attempt,
                head.predecessor_attempt,
                head.origin_event_id,
                head.sequence,
                head.head_event_id,
                head.head_event_sha256,
            )
            for (task_id, attempt), head in sorted(self._task_heads.items())
        )

    def check_attempt_advance(
        self,
        semantic: dict[str, Any],
        *,
        opens_attempt: bool,
        predecessor_attempt: int | None,
    ) -> None:
        """Validate the exact attempt-head mutation before any state commits."""
        context = semantic["task_context"]
        if semantic["stream"] != "TASK" or type(context) is not dict:
            _deny("GROUP_ATTEMPT_EVENT", "/events")
        key = (context["task_id"], context["attempt"])
        prior = self._task_heads.get(key)
        if opens_attempt:
            if prior is not None or context["task_sequence"] != 1:
                _deny("GROUP_ATTEMPT_OPEN", "/events")
            attempt = context["attempt"]
            predecessor_id, predecessor_sha = task_predecessor(
                self.chain_id, context["task_id"], attempt
            )
            if context["task_predecessor"] != {
                "event_id": predecessor_id,
                "event_sha256": predecessor_sha,
            }:
                _deny("GROUP_ATTEMPT_ROOT", "/events")
            if attempt == 1:
                if predecessor_attempt is not None:
                    _deny("GROUP_ATTEMPT_PREDECESSOR", "/events")
            elif (
                predecessor_attempt != attempt - 1
                or (context["task_id"], predecessor_attempt) not in self._task_heads
            ):
                _deny("GROUP_ATTEMPT_PREDECESSOR", "/events")
            return
        if predecessor_attempt is not None or prior is None:
            _deny("GROUP_ATTEMPT_HISTORY", "/events")
        if context["task_sequence"] != prior.sequence + 1:
            _deny("GROUP_ATTEMPT_SEQUENCE", "/events")
        if context["task_predecessor"] != {
            "event_id": prior.head_event_id,
            "event_sha256": prior.head_event_sha256,
        }:
            _deny("GROUP_ATTEMPT_PREDECESSOR", "/events")

    def advance_pair(
        self,
        semantic: dict[str, Any],
        commit: dict[str, Any],
        *,
        opens_attempt: bool,
        predecessor_attempt: int | None,
    ) -> None:
        """Commit indexes after a complete group has validated atomically."""
        self._event_ids.update((semantic["event_id"], commit["event_id"]))
        self._event_digests.update((
            semantic["event_sha256"], commit["event_sha256"],
        ))
        transaction = semantic["transaction"]
        self._transaction_ids.add(transaction["transaction_id"])
        self._operation_keys.add(transaction["operation_key"])
        context = semantic["task_context"]
        if semantic["stream"] == "TASK" and type(context) is dict:
            key = (context["task_id"], context["attempt"])
            prior = self._task_heads.get(key)
            self._task_heads[key] = _TaskReplayHead(
                predecessor_attempt=(
                    predecessor_attempt if prior is None
                    else prior.predecessor_attempt
                ),
                origin_event_id=(
                    semantic["event_id"]
                    if prior is None else prior.origin_event_id
                ),
                sequence=context["task_sequence"],
                head_event_id=semantic["event_id"],
                head_event_sha256=semantic["event_sha256"],
            )
        self.global_sequence = commit["global_sequence"]
        self.head_event_id = commit["event_id"]
        self.head_event_sha256 = commit["event_sha256"]


@dataclass(frozen=True, slots=True)
class InitializeGroupPatch:
    transition: _StagedTransition
    event_pair: tuple[str, str, str, str]
    reachable_blob_digests: tuple[str, ...]
    opens_attempt: bool
    predecessor_attempt: int | None
    idempotency_row: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class ClaimGroupPatch:
    transition: _StagedTransition
    event_pair: tuple[str, str, str, str]
    reachable_blob_digests: tuple[str, ...]
    opens_attempt: bool
    predecessor_attempt: int | None
    idempotency_row: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class WorkerGroupPatch:
    transition: _StagedTransition
    event_pair: tuple[str, str, str, str]
    reachable_blob_digests: tuple[str, ...]
    opens_attempt: bool
    predecessor_attempt: int | None
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


def _identity(value: Any, coordinate: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 256 or any(
        ord(character) < 0x20 or ord(character) > 0x7E for character in value
    ):
        _deny("GROUP_IDENTITY", coordinate)
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
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> InitializeGroupPatch:
    """Validate and plan one complete INITIALIZE group atomically."""
    if type(cursor) is not _ReplayCursor or cursor.global_sequence != 0:
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace or workspace.only_task() is not None:
        _deny("GROUP_PRIOR_STATE", "/state")
    semantic = _validate_event_shape(semantic_event, "/events/1")
    commit = _validate_event_shape(commit_event, "/events/2")
    semantic_index, commit_index = cursor.check_pair(semantic, commit)
    _const(semantic_index, 1, "/events/1/global_sequence")
    _const(commit_index, 2, "/events/2/global_sequence")
    runtime_id = genesis_event["runtime_id"]
    chain_id = genesis_event["chain_id"]
    repository_generation = genesis_event["repository_generation"]
    repository_bundle = genesis_event["repository_bundle_sha256"]
    _const(workspace.repository_generation, repository_generation, "/state/repository_generation")
    _const(
        workspace.repository_bundle_sha256,
        repository_bundle,
        "/state/repository_bundle_sha256",
    )
    for actual, expected, coordinate in (
        (cursor.runtime_id, runtime_id, "/events/0/runtime_id"),
        (cursor.chain_id, chain_id, "/events/0/chain_id"),
        (
            cursor.repository_generation, repository_generation,
            "/events/0/repository_generation",
        ),
        (
            cursor.repository_bundle_sha256, repository_bundle,
            "/events/0/repository_bundle_sha256",
        ),
        (cursor.head_event_id, genesis_event["event_id"], "/events/0/event_id"),
        (
            cursor.head_event_sha256, genesis_event["event_sha256"],
            "/events/0/event_sha256",
        ),
    ):
        _const(actual, expected, coordinate)
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
        _identity(arguments[name], f"/request/arguments/{name}")
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
        staged = workspace.stage(
            TransitionIntent(
                operation="INITIALIZE", task_id=task_id, attempt=1,
                arguments=tuple(sorted(arguments.items())),
                semantic_event_ids=(semantic["event_id"],),
            ),
        )
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    derived_state = _task_state_document(staged.after_task)
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
        transition=staged,
        event_pair=(
            semantic["event_id"], semantic["event_sha256"],
            commit["event_id"], commit["event_sha256"],
        ),
        reachable_blob_digests=reachable,
        opens_attempt=True,
        predecessor_attempt=None,
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha, response_sha,
            commit["event_id"], 2, semantic["occurred_at"],
        ),
    )


def reduce_claim_group(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> ClaimGroupPatch:
    """Validate and plan one complete CLAIM group from a current N0 state."""
    if (
        type(cursor) is not _ReplayCursor
        or cursor.global_sequence < 2
        or cursor.global_sequence % 2 != 0
    ):
        _deny("GROUP_CURSOR", "/events")
    semantic_index = cursor.global_sequence + 1
    commit_index = semantic_index + 1
    semantic = _validate_event_shape(semantic_event, f"/events/{semantic_index}")
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_pair(semantic, commit)
    if type(workspace) is not _TransitionWorkspace:
        _deny("GROUP_PRIOR_STATE", "/state")
    task = workspace.only_task()
    if task is None:
        _deny("GROUP_PRIOR_STATE", "/state")
    _const(
        workspace.repository_generation, cursor.repository_generation,
        "/state/repository_generation",
    )
    _const(
        workspace.repository_bundle_sha256,
        cursor.repository_bundle_sha256,
        "/state/repository_bundle_sha256",
    )
    runtime_id = cursor.runtime_id
    chain_id = cursor.chain_id
    repository_generation = workspace.repository_generation
    repository_bundle = workspace.repository_bundle_sha256
    transaction = semantic["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(match.group(1), chain_id, f"/events/{semantic_index}/transaction/operation_key")

    for name in (
        "runtime_id", "chain_id", "occurred_at", "repository_generation",
        "repository_bundle_sha256",
    ):
        _const(commit[name], semantic[name], f"/events/{commit_index}/{name}")
    for name in (
        "transaction_id", "event_count", "operation_key", "request_sha256",
        "response_sha256",
    ):
        _const(
            commit["transaction"][name], transaction[name],
            f"/events/{commit_index}/transaction/{name}",
        )
    for event, index, position in (
        (semantic, semantic_index, 0), (commit, commit_index, 1),
    ):
        _const(event["runtime_id"], runtime_id, f"/events/{index}/runtime_id")
        _const(event["chain_id"], chain_id, f"/events/{index}/chain_id")
        _const(event["repository_generation"], repository_generation, f"/events/{index}/repository_generation")
        _const(event["repository_bundle_sha256"], repository_bundle, f"/events/{index}/repository_bundle_sha256")
        _const(event["global_sequence"], index, f"/events/{index}/global_sequence")
        _const(event["transaction"]["position"], position, f"/events/{index}/transaction/position")
        _const(event["transaction"]["event_count"], 2, f"/events/{index}/transaction/event_count")
    _const(semantic["global_predecessor"], {
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }, f"/events/{semantic_index}/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": semantic["event_id"], "event_sha256": semantic["event_sha256"],
    }, f"/events/{commit_index}/global_predecessor")
    _const(semantic["event_type"], "CLAIM_ISSUED", f"/events/{semantic_index}/event_type")
    _const(semantic["stream"], "TASK", f"/events/{semantic_index}/stream")
    _const(commit["event_type"], "COMMAND_COMMITTED", f"/events/{commit_index}/event_type")
    _const(commit["stream"], "RUNTIME", f"/events/{commit_index}/stream")
    _const(commit["task_context"], None, f"/events/{commit_index}/task_context")
    _const(commit["state_before_ref"], None, f"/events/{commit_index}/state_before_ref")
    _const(commit["state_after_ref"], None, f"/events/{commit_index}/state_after_ref")

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(
        _resolve(catalog, request_sha, REQUEST_SCHEMA_ID, "/claim_request").value,
        _REQUEST_KEYS, "/claim_request",
    )
    response = _object(
        _resolve(catalog, response_sha, RESPONSE_SCHEMA_ID, "/claim_response").value,
        _RESPONSE_KEYS, "/claim_response",
    )
    for artifact, value, version_key in (
        ("claim_request", request, "request_format_version"),
        ("claim_response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], "CLAIM", f"/{artifact}/operation")
        _const(value["operation_key"], operation_key, f"/{artifact}/operation_key")
    _const(request["repository_generation"], repository_generation, "/claim_request/repository_generation")
    _const(request["repository_bundle_sha256"], repository_bundle, "/claim_request/repository_bundle_sha256")
    subject = _object(request["subject"], frozenset({"task_id", "attempt"}), "/claim_request/subject")
    _const(subject["task_id"], task.task_id, "/claim_request/subject/task_id")
    _const(subject["attempt"], task.attempt, "/claim_request/subject/attempt")
    before_sha = _ref(request["expected_state_ref"], TASK_STATE_SCHEMA_ID, "/claim_request/expected_state_ref")
    arguments = _object(request["arguments"], frozenset({"actor"}), "/claim_request/arguments")
    actor = _identity(arguments["actor"], "/claim_request/arguments/actor")
    _const(response["status"], "COMMITTED", "/claim_response/status")

    context = _object(
        semantic["task_context"],
        frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
        f"/events/{semantic_index}/task_context",
    )
    _const(context["task_id"], task.task_id, f"/events/{semantic_index}/task_context/task_id")
    _const(context["attempt"], task.attempt, f"/events/{semantic_index}/task_context/attempt")
    prior_task = cursor.task_head(task.task_id, task.attempt)
    if prior_task is None:
        _deny("GROUP_TASK_HISTORY", f"/events/{semantic_index}/task_context")
    task_sequence = prior_task.sequence + 1
    _const(
        context["task_sequence"], task_sequence,
        f"/events/{semantic_index}/task_context/task_sequence",
    )
    _const(context["task_predecessor"], {
        "event_id": prior_task.head_event_id,
        "event_sha256": prior_task.head_event_sha256,
    }, f"/events/{semantic_index}/task_context/task_predecessor")
    semantic_before_sha = _ref(
        semantic["state_before_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_before_ref",
    )
    _const(semantic_before_sha, before_sha, f"/events/{semantic_index}/state_before_ref/sha256")
    supplied_before = _resolve(
        catalog, before_sha, TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_before_ref",
    ).value
    if supplied_before != _task_state_document(task):
        _deny("GROUP_STATE_BEFORE", f"/events/{semantic_index}/state_before_ref")
    after_sha = _ref(
        semantic["state_after_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_after_ref",
    )

    semantic_payload_sha = semantic["payload_ref"]["sha256"]
    semantic_payload = _object(
        _resolve(
            catalog, semantic_payload_sha, PAYLOAD_SCHEMA_ID,
            f"/events/{semantic_index}/payload_ref",
        ).value,
        _PAYLOAD_KEYS, "/claim_semantic_payload",
    )
    _const(semantic_payload["schema_version"], 1, "/claim_semantic_payload/schema_version")
    _const(semantic_payload["payload_format_version"], 2, "/claim_semantic_payload/payload_format_version")
    _const(semantic_payload["event_type"], "CLAIM_ISSUED", "/claim_semantic_payload/event_type")
    payload_data = _object(semantic_payload["data"], frozenset({"claim_id"}), "/claim_semantic_payload/data")
    claim_id = _pattern(payload_data["claim_id"], _UUID4, "/claim_semantic_payload/data/claim_id")

    try:
        staged = workspace.stage(
            TransitionIntent(
                operation="CLAIM", task_id=task.task_id, attempt=task.attempt,
                arguments=(("actor", actor),), generated_id=claim_id,
                semantic_event_ids=(semantic["event_id"],),
            ),
        )
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    derived_state = _task_state_document(staged.after_task)
    supplied_after = _resolve(
        catalog, after_sha, TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_after_ref",
    ).value
    if supplied_after != derived_state:
        _deny("GROUP_STATE_DERIVATION", f"/events/{semantic_index}/state_after_ref")
    _const(response["affected_states"], [{
        "task_id": task.task_id,
        "attempt": task.attempt,
        "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
    }], "/claim_response/affected_states")
    _const(response["generated_refs"], [{
        "kind": "CLAIM", "identifier": claim_id, "sha256": None,
    }], "/claim_response/generated_refs")

    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(
            catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID,
            f"/events/{commit_index}/payload_ref",
        ).value,
        _PAYLOAD_KEYS, "/claim_commit_payload",
    )
    _const(commit_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic["event_id"]],
            "pre_command_head": {
                "global_sequence": cursor.global_sequence,
                "event_id": cursor.head_event_id,
                "event_sha256": cursor.head_event_sha256,
            },
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic["event_id"],
                "event_sha256": semantic["event_sha256"],
            },
            "operation": "CLAIM",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }, "/claim_commit_payload")
    reachable = tuple(sorted({
        request_sha, response_sha, semantic_payload_sha, commit_payload_sha, after_sha,
    }))
    return ClaimGroupPatch(
        transition=staged,
        event_pair=(
            semantic["event_id"], semantic["event_sha256"],
            commit["event_id"], commit["event_sha256"],
        ),
        reachable_blob_digests=reachable,
        opens_attempt=False,
        predecessor_attempt=None,
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha, response_sha,
            commit["event_id"], commit_index, semantic["occurred_at"],
        ),
    )


def reduce_worker_group(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> WorkerGroupPatch:
    """Validate one compiled single-task follow-up transaction group."""
    if (
        type(cursor) is not _ReplayCursor
        or cursor.global_sequence < 2
        or cursor.global_sequence % 2 != 0
    ):
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace:
        _deny("GROUP_PRIOR_STATE", "/state")
    task = workspace.only_task()
    if task is None:
        _deny("GROUP_PRIOR_STATE", "/state")
    _const(
        workspace.repository_generation, cursor.repository_generation,
        "/state/repository_generation",
    )
    _const(
        workspace.repository_bundle_sha256,
        cursor.repository_bundle_sha256,
        "/state/repository_bundle_sha256",
    )

    semantic_index = cursor.global_sequence + 1
    commit_index = semantic_index + 1
    semantic = _validate_event_shape(
        semantic_event, f"/events/{semantic_index}"
    )
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_pair(semantic, commit)
    profile = _FOLLOWUP_PROFILES.get(semantic["event_type"])
    if profile is None:
        _deny("GROUP_WORKER_OPERATION", f"/events/{semantic_index}/event_type")
    operation, argument_keys = profile
    opens_attempt = operation == "RETRY"
    creates_review = operation == "ASSIGN_REVIEW"
    runtime_id = cursor.runtime_id
    chain_id = cursor.chain_id
    repository_generation = workspace.repository_generation
    repository_bundle = workspace.repository_bundle_sha256
    transaction = semantic["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(
        match.group(1), chain_id,
        f"/events/{semantic_index}/transaction/operation_key",
    )

    for name in (
        "runtime_id", "chain_id", "occurred_at", "repository_generation",
        "repository_bundle_sha256",
    ):
        _const(commit[name], semantic[name], f"/events/{commit_index}/{name}")
    for name in (
        "transaction_id", "event_count", "operation_key", "request_sha256",
        "response_sha256",
    ):
        _const(
            commit["transaction"][name], transaction[name],
            f"/events/{commit_index}/transaction/{name}",
        )
    for event, index, position in (
        (semantic, semantic_index, 0), (commit, commit_index, 1),
    ):
        _const(event["runtime_id"], runtime_id, f"/events/{index}/runtime_id")
        _const(event["chain_id"], chain_id, f"/events/{index}/chain_id")
        _const(
            event["repository_generation"], repository_generation,
            f"/events/{index}/repository_generation",
        )
        _const(
            event["repository_bundle_sha256"], repository_bundle,
            f"/events/{index}/repository_bundle_sha256",
        )
        _const(
            event["global_sequence"], index,
            f"/events/{index}/global_sequence",
        )
        _const(
            event["transaction"]["position"], position,
            f"/events/{index}/transaction/position",
        )
        _const(
            event["transaction"]["event_count"], 2,
            f"/events/{index}/transaction/event_count",
        )
    _const(semantic["global_predecessor"], {
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }, f"/events/{semantic_index}/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": semantic["event_id"],
        "event_sha256": semantic["event_sha256"],
    }, f"/events/{commit_index}/global_predecessor")
    _const(semantic["stream"], "TASK", f"/events/{semantic_index}/stream")
    _const(
        commit["event_type"], "COMMAND_COMMITTED",
        f"/events/{commit_index}/event_type",
    )
    _const(commit["stream"], "RUNTIME", f"/events/{commit_index}/stream")
    _const(
        commit["task_context"], None,
        f"/events/{commit_index}/task_context",
    )
    _const(
        commit["state_before_ref"], None,
        f"/events/{commit_index}/state_before_ref",
    )
    _const(
        commit["state_after_ref"], None,
        f"/events/{commit_index}/state_after_ref",
    )

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(
        _resolve(
            catalog, request_sha, REQUEST_SCHEMA_ID, "/worker_request"
        ).value,
        _REQUEST_KEYS, "/worker_request",
    )
    response = _object(
        _resolve(
            catalog, response_sha, RESPONSE_SCHEMA_ID, "/worker_response"
        ).value,
        _RESPONSE_KEYS, "/worker_response",
    )
    for artifact, value, version_key in (
        ("worker_request", request, "request_format_version"),
        ("worker_response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], operation, f"/{artifact}/operation")
        _const(
            value["operation_key"], operation_key,
            f"/{artifact}/operation_key",
        )
    _const(
        request["repository_generation"], repository_generation,
        "/worker_request/repository_generation",
    )
    _const(
        request["repository_bundle_sha256"], repository_bundle,
        "/worker_request/repository_bundle_sha256",
    )
    subject = _object(
        request["subject"], frozenset({"task_id", "attempt"}),
        "/worker_request/subject",
    )
    _const(subject["task_id"], task.task_id, "/worker_request/subject/task_id")
    _const(subject["attempt"], task.attempt, "/worker_request/subject/attempt")
    before_sha = _ref(
        request["expected_state_ref"], TASK_STATE_SCHEMA_ID,
        "/worker_request/expected_state_ref",
    )
    arguments = _object(
        request["arguments"], argument_keys, "/worker_request/arguments"
    )
    _const(response["status"], "COMMITTED", "/worker_response/status")

    context = _object(
        semantic["task_context"],
        frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
        f"/events/{semantic_index}/task_context",
    )
    _const(
        context["task_id"], task.task_id,
        f"/events/{semantic_index}/task_context/task_id",
    )
    if not opens_attempt:
        _const(
            context["attempt"], task.attempt,
            f"/events/{semantic_index}/task_context/attempt",
        )
        prior_task = cursor.task_head(task.task_id, task.attempt)
        if prior_task is None:
            _deny("GROUP_TASK_HISTORY", f"/events/{semantic_index}/task_context")
        task_sequence = prior_task.sequence + 1
        _const(
            context["task_sequence"], task_sequence,
            f"/events/{semantic_index}/task_context/task_sequence",
        )
        _const(context["task_predecessor"], {
            "event_id": prior_task.head_event_id,
            "event_sha256": prior_task.head_event_sha256,
        }, f"/events/{semantic_index}/task_context/task_predecessor")

    semantic_before_sha = _ref(
        semantic["state_before_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_before_ref",
    )
    _const(
        semantic_before_sha, before_sha,
        f"/events/{semantic_index}/state_before_ref/sha256",
    )
    supplied_before = _resolve(
        catalog, before_sha, TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_before_ref",
    ).value
    if supplied_before != _task_state_document(task):
        _deny("GROUP_STATE_BEFORE", f"/events/{semantic_index}/state_before_ref")
    after_sha = _ref(
        semantic["state_after_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_after_ref",
    )

    semantic_payload_sha = semantic["payload_ref"]["sha256"]
    semantic_payload = _object(
        _resolve(
            catalog, semantic_payload_sha, PAYLOAD_SCHEMA_ID,
            f"/events/{semantic_index}/payload_ref",
        ).value,
        _PAYLOAD_KEYS, "/worker_semantic_payload",
    )
    expected_payload_data = semantic_payload["data"] if creates_review else {}
    if creates_review:
        expected_payload_data = _object(
            expected_payload_data,
            frozenset({"assignment_id"}),
            "/worker_semantic_payload/data",
        )
        assignment_id = _pattern(
            expected_payload_data["assignment_id"],
            _UUID4,
            "/worker_semantic_payload/data/assignment_id",
        )
        _const(response["generated_refs"], [{
            "kind": "REVIEW_ASSIGNMENT",
            "identifier": assignment_id,
            "sha256": None,
        }], "/worker_response/generated_refs")
    else:
        assignment_id = None
        _const(response["generated_refs"], [], "/worker_response/generated_refs")
    _const(semantic_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": semantic["event_type"],
        "data": expected_payload_data,
    }, "/worker_semantic_payload")

    try:
        staged = workspace.stage(
            TransitionIntent(
                operation=operation,
                task_id=task.task_id,
                attempt=task.attempt,
                arguments=tuple(sorted(arguments.items())),
                generated_id=assignment_id,
                semantic_event_ids=(semantic["event_id"],),
            ),
        )
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    if opens_attempt:
        _const(
            context["attempt"], staged.after_task.attempt,
            f"/events/{semantic_index}/task_context/attempt",
        )
        _const(
            context["task_sequence"], 1,
            f"/events/{semantic_index}/task_context/task_sequence",
        )
        predecessor_id, predecessor_sha = task_predecessor(
            chain_id, task.task_id, staged.after_task.attempt
        )
        _const(context["task_predecessor"], {
            "event_id": predecessor_id,
            "event_sha256": predecessor_sha,
        }, f"/events/{semantic_index}/task_context/task_predecessor")
        if cursor.task_head(task.task_id, staged.after_task.attempt) is not None:
            _deny(
                "GROUP_TASK_HISTORY",
                f"/events/{semantic_index}/task_context",
            )
    supplied_after = _resolve(
        catalog, after_sha, TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_after_ref",
    ).value
    if supplied_after != _task_state_document(staged.after_task):
        _deny("GROUP_STATE_DERIVATION", f"/events/{semantic_index}/state_after_ref")
    _const(response["affected_states"], [{
        "task_id": task.task_id,
        "attempt": staged.after_task.attempt,
        "state_ref": {
            "schema_id": TASK_STATE_SCHEMA_ID,
            "sha256": after_sha,
        },
    }], "/worker_response/affected_states")

    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(
            catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID,
            f"/events/{commit_index}/payload_ref",
        ).value,
        _PAYLOAD_KEYS, "/worker_commit_payload",
    )
    _const(commit_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic["event_id"]],
            "pre_command_head": {
                "global_sequence": cursor.global_sequence,
                "event_id": cursor.head_event_id,
                "event_sha256": cursor.head_event_sha256,
            },
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic["event_id"],
                "event_sha256": semantic["event_sha256"],
            },
            "operation": operation,
            "operation_key": operation_key,
            "request_ref": {
                "schema_id": REQUEST_SCHEMA_ID,
                "sha256": request_sha,
            },
            "response_ref": {
                "schema_id": RESPONSE_SCHEMA_ID,
                "sha256": response_sha,
            },
            "result": "COMMITTED",
        },
    }, "/worker_commit_payload")

    reachable = tuple(sorted({
        request_sha, response_sha, semantic_payload_sha, commit_payload_sha,
        after_sha,
    }))
    return WorkerGroupPatch(
        transition=staged,
        event_pair=(
            semantic["event_id"], semantic["event_sha256"],
            commit["event_id"], commit["event_sha256"],
        ),
        reachable_blob_digests=reachable,
        opens_attempt=opens_attempt,
        predecessor_attempt=(task.attempt if opens_attempt else None),
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha,
            response_sha, commit["event_id"], commit_index,
            semantic["occurred_at"],
        ),
    )


__all__ = (
    "BlobValue", "ClaimGroupPatch", "GroupValidationError",
    "InitializeGroupPatch", "TASK_STATE_SCHEMA_ID",
    "WorkerGroupPatch",
    "reduce_claim_group", "reduce_initialize_group", "reduce_worker_group",
)
