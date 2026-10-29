"""Private atomic transaction-group planning for runtime format 2.

The compiled slices support ``INITIALIZE`` after a validated NEW genesis,
followed by repeatable ``CLAIM``, worker operations ``START``, ``CONTINUE``,
``YIELD``, ``FAIL``, and ``COMPLETE``, synthetic ``RECOVER``, and exact
attempt-boundary ``RETRY``, plus governance, review-decision, and routing
follow-ups, remediation, repository import, and exact checkpoint and
export registration cuts. They are
deliberately narrow: supplied blobs and events are treated as untrusted
comparison inputs, task state is recomputed with the immutable transition
kernel, and no result can authorize use.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

from .runtime_v2_codec import (
    blob_digest,
    checkpoint_digest,
    event_digest,
    export_digest,
    selector_digest,
    selector_history_digest,
    task_predecessor,
)
from .runtime_v2_genesis import PAYLOAD_SCHEMA_ID, REQUEST_SCHEMA_ID, RESPONSE_SCHEMA_ID
from .runtime_v2_transition import (
    TransitionIntent,
    TransitionViolation,
    _StagedTransition,
    _StagedStateReplacement,
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
    "REVIEW_APPROVED": (
        "APPROVE",
        frozenset({"assignment_id", "decision_sha256"}),
    ),
    "REVIEW_REJECTED": (
        "REJECT",
        frozenset({"assignment_id", "decision_sha256"}),
    ),
    "REVIEW_REMEDIATED": (
        "REMEDIATE",
        frozenset({"assignment_id", "decision_sha256"}),
    ),
    "DIRECTOR_ROUTED": (
        "ROUTE",
        frozenset({"routing_evidence_sha256"}),
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

    def check_remediation(
        self,
        source: dict[str, Any],
        child: dict[str, Any],
        commit: dict[str, Any],
    ) -> tuple[int, int, int]:
        """Reject duplicates for a three-event remediation transaction."""
        source_index = self.global_sequence + 1
        child_index = source_index + 1
        commit_index = child_index + 1
        events = (source, child, commit)
        ids = tuple(item["event_id"] for item in events)
        digests = tuple(item["event_sha256"] for item in events)
        if len(set(ids)) != 3 or any(item in self._event_ids for item in ids):
            _deny("GROUP_EVENT_ID_DUPLICATE", f"/events/{source_index}")
        if len(set(digests)) != 3 or any(
            item in self._event_digests for item in digests
        ):
            _deny("GROUP_EVENT_DIGEST_DUPLICATE", f"/events/{source_index}")
        transaction = source["transaction"]
        if transaction["transaction_id"] in self._transaction_ids:
            _deny(
                "GROUP_TRANSACTION_DUPLICATE",
                f"/events/{source_index}/transaction/transaction_id",
            )
        if transaction["operation_key"] in self._operation_keys:
            _deny(
                "GROUP_OPERATION_KEY_DUPLICATE",
                f"/events/{source_index}/transaction/operation_key",
            )
        return source_index, child_index, commit_index

    def check_import(
        self,
        semantic_events: tuple[dict[str, Any], ...],
        commit: dict[str, Any],
    ) -> tuple[int, ...]:
        """Reject duplicate identities across one variable-width import."""
        start = self.global_sequence + 1
        events = semantic_events + (commit,)
        ids = tuple(item["event_id"] for item in events)
        digests = tuple(item["event_sha256"] for item in events)
        if len(set(ids)) != len(ids) or any(item in self._event_ids for item in ids):
            _deny("GROUP_EVENT_ID_DUPLICATE", f"/events/{start}")
        if len(set(digests)) != len(digests) or any(
            item in self._event_digests for item in digests
        ):
            _deny("GROUP_EVENT_DIGEST_DUPLICATE", f"/events/{start}")
        transaction = commit["transaction"]
        if transaction["transaction_id"] in self._transaction_ids:
            _deny(
                "GROUP_TRANSACTION_DUPLICATE",
                f"/events/{start}/transaction/transaction_id",
            )
        if transaction["operation_key"] in self._operation_keys:
            _deny(
                "GROUP_OPERATION_KEY_DUPLICATE",
                f"/events/{start}/transaction/operation_key",
            )
        return tuple(range(start, start + len(events)))

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

    def advance_remediation(
        self,
        source: dict[str, Any],
        child: dict[str, Any],
        commit: dict[str, Any],
    ) -> None:
        """Advance both task heads and the global head as one accepted group."""
        self._event_ids.update(
            (source["event_id"], child["event_id"], commit["event_id"])
        )
        self._event_digests.update((
            source["event_sha256"], child["event_sha256"],
            commit["event_sha256"],
        ))
        transaction = source["transaction"]
        self._transaction_ids.add(transaction["transaction_id"])
        self._operation_keys.add(transaction["operation_key"])
        source_context = source["task_context"]
        source_key = (source_context["task_id"], source_context["attempt"])
        prior = self._task_heads[source_key]
        self._task_heads[source_key] = _TaskReplayHead(
            predecessor_attempt=prior.predecessor_attempt,
            origin_event_id=prior.origin_event_id,
            sequence=source_context["task_sequence"],
            head_event_id=source["event_id"],
            head_event_sha256=source["event_sha256"],
        )
        child_context = child["task_context"]
        child_key = (child_context["task_id"], child_context["attempt"])
        self._task_heads[child_key] = _TaskReplayHead(
            predecessor_attempt=None,
            origin_event_id=child["event_id"],
            sequence=1,
            head_event_id=child["event_id"],
            head_event_sha256=child["event_sha256"],
        )
        self.global_sequence = commit["global_sequence"]
        self.head_event_id = commit["event_id"]
        self.head_event_sha256 = commit["event_sha256"]

    def advance_import(
        self,
        semantic_events: tuple[dict[str, Any], ...],
        commit: dict[str, Any],
        *,
        repository_generation: int,
        repository_bundle_sha256: str,
    ) -> None:
        """Advance all affected task heads and repository coordinates atomically."""
        if not semantic_events:
            _deny("GROUP_IMPORT_EVENTS", "/events")
        runtime_event = semantic_events[-1]
        task_events = semantic_events[:-1]
        if (
            runtime_event["event_type"] != "REPOSITORY_GENERATION_ADVANCED"
            or runtime_event["stream"] != "RUNTIME"
            or runtime_event["task_context"] is not None
        ):
            _deny("GROUP_IMPORT_EVENTS", "/events")
        prepared: list[tuple[tuple[str, int], _TaskReplayHead]] = []
        for event in task_events:
            context = event["task_context"]
            if event["stream"] != "TASK" or type(context) is not dict:
                _deny("GROUP_IMPORT_EVENTS", "/events")
            key = (context["task_id"], context["attempt"])
            prior = self._task_heads.get(key)
            if prior is None:
                _deny("GROUP_TASK_HISTORY", "/events")
            prepared.append((key, _TaskReplayHead(
                predecessor_attempt=prior.predecessor_attempt,
                origin_event_id=prior.origin_event_id,
                sequence=context["task_sequence"],
                head_event_id=event["event_id"],
                head_event_sha256=event["event_sha256"],
            )))
        events = semantic_events + (commit,)
        self._event_ids.update(item["event_id"] for item in events)
        self._event_digests.update(item["event_sha256"] for item in events)
        transaction = commit["transaction"]
        self._transaction_ids.add(transaction["transaction_id"])
        self._operation_keys.add(transaction["operation_key"])
        for key, head in prepared:
            self._task_heads[key] = head
        self.repository_generation = repository_generation
        self.repository_bundle_sha256 = repository_bundle_sha256
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


@dataclass(frozen=True, slots=True)
class RemediationGroupPatch:
    transition: _StagedStateReplacement
    event_triplet: tuple[str, str, str, str, str, str]
    reachable_blob_digests: tuple[str, ...]
    idempotency_row: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class ImportGroupPatch:
    transition: _StagedStateReplacement
    event_sequence: tuple[tuple[str, str], ...]
    reachable_blob_digests: tuple[str, ...]
    idempotency_row: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class SnapshotGroupPatch:
    """Validated non-task checkpoint/export registration plan."""

    event_pair: tuple[str, str, str, str]
    reachable_blob_digests: tuple[str, ...]
    idempotency_row: tuple[Any, ...]
    snapshot_row: tuple[Any, ...]
    next_selector: dict[str, Any] | None


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


def _selected_task(
    workspace: _TransitionWorkspace,
    request: Mapping[str, Any],
    coordinate: str,
) -> Any:
    """Select one retained task only from the request's exact subject.

    Event context is checked independently after selection.  This distinction
    matters for RETRY: the request names attempt n while the semantic event
    opens attempt n+1.
    """
    subject = _object(
        request.get("subject"), frozenset({"task_id", "attempt"}),
        coordinate,
    )
    task_id = _pattern(subject["task_id"], _TASK, f"{coordinate}/task_id")
    attempt = _integer(
        subject["attempt"], 1, 9_223_372_036_854_775_807,
        f"{coordinate}/attempt",
    )
    task = workspace.task(task_id)
    if task is None:
        _deny("GROUP_TASK_SELECTION", f"{coordinate}/task_id")
    _const(attempt, task.attempt, f"{coordinate}/attempt")
    return task


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
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> InitializeGroupPatch:
    """Validate and plan one complete INITIALIZE group atomically."""
    if type(cursor) is not _ReplayCursor:
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace:
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
    semantic_index, commit_index = cursor.check_pair(semantic, commit)
    runtime_id = cursor.runtime_id
    chain_id = cursor.chain_id
    repository_generation = cursor.repository_generation
    repository_bundle = cursor.repository_bundle_sha256
    transaction = semantic["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(
        match.group(1), chain_id,
        f"/events/{semantic_index}/transaction/operation_key",
    )

    shared = (
        "runtime_id", "chain_id", "occurred_at", "repository_generation",
        "repository_bundle_sha256",
    )
    for name in shared:
        _const(commit[name], semantic[name], f"/events/{commit_index}/{name}")
    for name in (
        "transaction_id", "event_count", "operation_key", "request_sha256",
        "response_sha256",
    ):
        _const(
            commit["transaction"][name], transaction[name],
            f"/events/{commit_index}/transaction/{name}",
        )
    for candidate, index, position in (
        (semantic, semantic_index, 0), (commit, commit_index, 1),
    ):
        _const(candidate["runtime_id"], runtime_id, f"/events/{index}/runtime_id")
        _const(candidate["chain_id"], chain_id, f"/events/{index}/chain_id")
        _const(
            candidate["repository_generation"], repository_generation,
            f"/events/{index}/repository_generation",
        )
        _const(
            candidate["repository_bundle_sha256"], repository_bundle,
            f"/events/{index}/repository_bundle_sha256",
        )
        _const(candidate["global_sequence"], index, f"/events/{index}/global_sequence")
        _const(
            candidate["transaction"]["position"], position,
            f"/events/{index}/transaction/position",
        )
        _const(
            candidate["transaction"]["event_count"], 2,
            f"/events/{index}/transaction/event_count",
        )
    _const(semantic["global_predecessor"], {
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }, f"/events/{semantic_index}/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": semantic["event_id"], "event_sha256": semantic["event_sha256"],
    }, f"/events/{commit_index}/global_predecessor")
    _const(
        semantic["event_type"], "TASK_INITIALIZED",
        f"/events/{semantic_index}/event_type",
    )
    _const(semantic["stream"], "TASK", f"/events/{semantic_index}/stream")
    _const(
        commit["event_type"], "COMMAND_COMMITTED",
        f"/events/{commit_index}/event_type",
    )
    _const(commit["stream"], "RUNTIME", f"/events/{commit_index}/stream")
    _const(commit["task_context"], None, f"/events/{commit_index}/task_context")
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
    if workspace.task(task_id) is not None:
        _deny("GROUP_TASK_SELECTION", "/request/subject/task_id")
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
        f"/events/{semantic_index}/task_context",
    )
    _const(
        context["task_id"], task_id,
        f"/events/{semantic_index}/task_context/task_id",
    )
    _const(
        context["attempt"], 1,
        f"/events/{semantic_index}/task_context/attempt",
    )
    _const(
        context["task_sequence"], 1,
        f"/events/{semantic_index}/task_context/task_sequence",
    )
    predecessor_id, predecessor_sha = task_predecessor(chain_id, task_id, 1)
    _const(context["task_predecessor"], {
        "event_id": predecessor_id, "event_sha256": predecessor_sha,
    }, f"/events/{semantic_index}/task_context/task_predecessor")
    _const(
        semantic["state_before_ref"], None,
        f"/events/{semantic_index}/state_before_ref",
    )
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
    supplied_state = _resolve(
        catalog, after_sha, TASK_STATE_SCHEMA_ID,
        f"/events/{semantic_index}/state_after_ref",
    ).value
    if supplied_state != derived_state:
        _deny(
            "GROUP_STATE_DERIVATION",
            f"/events/{semantic_index}/state_after_ref",
        )
    expected_affected = [{
        "task_id": task_id, "attempt": 1,
        "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
    }]
    _const(response["affected_states"], expected_affected, "/response/affected_states")

    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(
            catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID,
            f"/events/{commit_index}/payload_ref",
        ).value,
        _PAYLOAD_KEYS, "/commit_payload",
    )
    expected_commit_payload = {
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
            commit["event_id"], commit_index, semantic["occurred_at"],
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
    if type(cursor) is not _ReplayCursor or cursor.global_sequence < 2:
        _deny("GROUP_CURSOR", "/events")
    semantic_index = cursor.global_sequence + 1
    commit_index = semantic_index + 1
    semantic = _validate_event_shape(semantic_event, f"/events/{semantic_index}")
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_pair(semantic, commit)
    if type(workspace) is not _TransitionWorkspace:
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
    task = _selected_task(workspace, request, "/claim_request/subject")
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
    if type(cursor) is not _ReplayCursor or cursor.global_sequence < 2:
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace:
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
    task = _selected_task(workspace, request, "/worker_request/subject")
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


def reduce_remediation_group(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    source_event: Any,
    child_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> RemediationGroupPatch:
    """Validate the atomic two-task CREATE_REMEDIATION_TASK group."""
    if type(cursor) is not _ReplayCursor or cursor.global_sequence < 2:
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace:
        _deny("GROUP_PRIOR_STATE", "/state")
    source_index = cursor.global_sequence + 1
    child_index = source_index + 1
    commit_index = child_index + 1
    source = _validate_event_shape(source_event, f"/events/{source_index}")
    child = _validate_event_shape(child_event, f"/events/{child_index}")
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_remediation(source, child, commit)
    _const(source["event_type"], "REMEDIATION_CREATED", f"/events/{source_index}/event_type")
    _const(
        child["event_type"], "TASK_CREATED_FROM_REMEDIATION",
        f"/events/{child_index}/event_type",
    )
    _const(commit["event_type"], "COMMAND_COMMITTED", f"/events/{commit_index}/event_type")
    for event, index, position, stream in (
        (source, source_index, 0, "TASK"),
        (child, child_index, 1, "TASK"),
        (commit, commit_index, 2, "RUNTIME"),
    ):
        _const(event["runtime_id"], cursor.runtime_id, f"/events/{index}/runtime_id")
        _const(event["chain_id"], cursor.chain_id, f"/events/{index}/chain_id")
        _const(event["global_sequence"], index, f"/events/{index}/global_sequence")
        _const(event["stream"], stream, f"/events/{index}/stream")
        _const(event["transaction"]["position"], position, f"/events/{index}/transaction/position")
        _const(event["transaction"]["event_count"], 3, f"/events/{index}/transaction/event_count")
        _const(
            event["repository_generation"], workspace.repository_generation,
            f"/events/{index}/repository_generation",
        )
        _const(
            event["repository_bundle_sha256"],
            workspace.repository_bundle_sha256,
            f"/events/{index}/repository_bundle_sha256",
        )
    transaction = source["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(match.group(1), cursor.chain_id, f"/events/{source_index}/transaction/operation_key")
    for event, index in ((child, child_index), (commit, commit_index)):
        for name in (
            "runtime_id", "chain_id", "occurred_at", "repository_generation",
            "repository_bundle_sha256",
        ):
            _const(event[name], source[name], f"/events/{index}/{name}")
        for name in (
            "transaction_id", "event_count", "operation_key",
            "request_sha256", "response_sha256",
        ):
            _const(
                event["transaction"][name], transaction[name],
                f"/events/{index}/transaction/{name}",
            )
    _const(source["global_predecessor"], {
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }, f"/events/{source_index}/global_predecessor")
    _const(child["global_predecessor"], {
        "event_id": source["event_id"],
        "event_sha256": source["event_sha256"],
    }, f"/events/{child_index}/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": child["event_id"],
        "event_sha256": child["event_sha256"],
    }, f"/events/{commit_index}/global_predecessor")
    _const(commit["task_context"], None, f"/events/{commit_index}/task_context")
    _const(commit["state_before_ref"], None, f"/events/{commit_index}/state_before_ref")
    _const(commit["state_after_ref"], None, f"/events/{commit_index}/state_after_ref")

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(
        _resolve(catalog, request_sha, REQUEST_SCHEMA_ID, "/remediation_request").value,
        _REQUEST_KEYS, "/remediation_request",
    )
    response = _object(
        _resolve(catalog, response_sha, RESPONSE_SCHEMA_ID, "/remediation_response").value,
        _RESPONSE_KEYS, "/remediation_response",
    )
    for artifact, value, version_key in (
        ("remediation_request", request, "request_format_version"),
        ("remediation_response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], cursor.runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], cursor.chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], "CREATE_REMEDIATION_TASK", f"/{artifact}/operation")
        _const(value["operation_key"], operation_key, f"/{artifact}/operation_key")
    _const(
        request["repository_generation"], workspace.repository_generation,
        "/remediation_request/repository_generation",
    )
    _const(
        request["repository_bundle_sha256"], workspace.repository_bundle_sha256,
        "/remediation_request/repository_bundle_sha256",
    )
    subject = _object(
        request["subject"],
        frozenset({
            "source_task_id", "source_attempt", "child_task_id",
            "child_attempt",
        }),
        "/remediation_request/subject",
    )
    source_task_id = _pattern(
        subject["source_task_id"], _TASK,
        "/remediation_request/subject/source_task_id",
    )
    source_task = workspace.task(source_task_id)
    if source_task is None:
        _deny(
            "GROUP_PRIOR_STATE",
            "/remediation_request/subject/source_task_id",
        )
    _const(
        subject["source_attempt"], source_task.attempt,
        "/remediation_request/subject/source_attempt",
    )
    child_task_id = _pattern(
        subject["child_task_id"], _TASK,
        "/remediation_request/subject/child_task_id",
    )
    _const(
        subject["child_attempt"], 1,
        "/remediation_request/subject/child_attempt",
    )
    before_sha = _ref(
        request["expected_state_ref"], TASK_STATE_SCHEMA_ID,
        "/remediation_request/expected_state_ref",
    )
    supplied_before = _resolve(
        catalog, before_sha, TASK_STATE_SCHEMA_ID,
        "/remediation_request/expected_state_ref",
    ).value
    if supplied_before != _task_state_document(source_task):
        _deny("GROUP_STATE_BEFORE", "/remediation_request/expected_state_ref")
    arguments = _object(
        request["arguments"],
        frozenset({
            "child_decision_receipt_digest", "child_owner", "child_owner_role",
            "decision_sha256", "relationship_id",
        }),
        "/remediation_request/arguments",
    )
    relationship_id = _pattern(
        arguments["relationship_id"], _UUID4,
        "/remediation_request/arguments/relationship_id",
    )
    try:
        staged = workspace.stage_remediation(TransitionIntent(
            operation="CREATE_REMEDIATION_TASK",
            task_id=source_task.task_id,
            attempt=source_task.attempt,
            child_task_id=child_task_id,
            child_attempt=1,
            arguments=tuple(sorted(arguments.items())),
            semantic_event_ids=(source["event_id"], child["event_id"]),
        ))
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    after_by_id = {item.task_id: item for item in staged.after.tasks}
    source_after = after_by_id[source_task.task_id]
    child_after = after_by_id[child_task_id]
    link = next(
        item for item in staged.after.remediation_links
        if item.link_id == relationship_id
    )

    source_context = _object(
        source["task_context"],
        frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
        f"/events/{source_index}/task_context",
    )
    prior_source = cursor.task_head(source_task.task_id, source_task.attempt)
    if prior_source is None:
        _deny("GROUP_TASK_HISTORY", f"/events/{source_index}/task_context")
    _const(source_context["task_id"], source_task.task_id, f"/events/{source_index}/task_context/task_id")
    _const(source_context["attempt"], source_task.attempt, f"/events/{source_index}/task_context/attempt")
    _const(source_context["task_sequence"], prior_source.sequence + 1, f"/events/{source_index}/task_context/task_sequence")
    _const(source_context["task_predecessor"], {
        "event_id": prior_source.head_event_id,
        "event_sha256": prior_source.head_event_sha256,
    }, f"/events/{source_index}/task_context/task_predecessor")
    child_context = _object(
        child["task_context"],
        frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
        f"/events/{child_index}/task_context",
    )
    child_root_id, child_root_sha = task_predecessor(cursor.chain_id, child_task_id, 1)
    _const(child_context["task_id"], child_task_id, f"/events/{child_index}/task_context/task_id")
    _const(child_context["attempt"], 1, f"/events/{child_index}/task_context/attempt")
    _const(child_context["task_sequence"], 1, f"/events/{child_index}/task_context/task_sequence")
    _const(child_context["task_predecessor"], {
        "event_id": child_root_id, "event_sha256": child_root_sha,
    }, f"/events/{child_index}/task_context/task_predecessor")

    source_before_sha = _ref(
        source["state_before_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{source_index}/state_before_ref",
    )
    _const(source_before_sha, before_sha, f"/events/{source_index}/state_before_ref/sha256")
    source_after_sha = _ref(
        source["state_after_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{source_index}/state_after_ref",
    )
    _const(child["state_before_ref"], None, f"/events/{child_index}/state_before_ref")
    child_after_sha = _ref(
        child["state_after_ref"], TASK_STATE_SCHEMA_ID,
        f"/events/{child_index}/state_after_ref",
    )
    if _resolve(catalog, source_after_sha, TASK_STATE_SCHEMA_ID, f"/events/{source_index}/state_after_ref").value != _task_state_document(source_after):
        _deny("GROUP_STATE_DERIVATION", f"/events/{source_index}/state_after_ref")
    if _resolve(catalog, child_after_sha, TASK_STATE_SCHEMA_ID, f"/events/{child_index}/state_after_ref").value != _task_state_document(child_after):
        _deny("GROUP_STATE_DERIVATION", f"/events/{child_index}/state_after_ref")

    payload_digests: list[str] = []
    for event, index in ((source, source_index), (child, child_index)):
        payload_sha = event["payload_ref"]["sha256"]
        payload_digests.append(payload_sha)
        payload = _object(
            _resolve(catalog, payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{index}/payload_ref").value,
            _PAYLOAD_KEYS, f"/events/{index}/payload_ref",
        )
        _const(payload, {
            "schema_version": 1,
            "payload_format_version": 2,
            "event_type": event["event_type"],
            "data": {"relationship_id": relationship_id},
        }, f"/events/{index}/payload_ref")
    _const(response["status"], "COMMITTED", "/remediation_response/status")
    _const(response["affected_states"], [
        {
            "task_id": source_task.task_id,
            "attempt": source_after.attempt,
            "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": source_after_sha},
        },
        {
            "task_id": child_task_id,
            "attempt": 1,
            "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": child_after_sha},
        },
    ], "/remediation_response/affected_states")
    _const(response["generated_refs"], [{
        "kind": "REMEDIATION_LINK",
        "identifier": relationship_id,
        "sha256": link.link_sha256,
    }], "/remediation_response/generated_refs")

    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{commit_index}/payload_ref").value,
        _PAYLOAD_KEYS, "/remediation_commit_payload",
    )
    _const(commit_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [source["event_id"], child["event_id"]],
            "pre_command_head": {
                "global_sequence": cursor.global_sequence,
                "event_id": cursor.head_event_id,
                "event_sha256": cursor.head_event_sha256,
            },
            "post_semantic_head": {
                "global_sequence": child_index,
                "event_id": child["event_id"],
                "event_sha256": child["event_sha256"],
            },
            "operation": "CREATE_REMEDIATION_TASK",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }, "/remediation_commit_payload")
    reachable = tuple(sorted({
        request_sha, response_sha, *payload_digests, commit_payload_sha,
        source_after_sha, child_after_sha,
    }))
    return RemediationGroupPatch(
        transition=staged,
        event_triplet=(
            source["event_id"], source["event_sha256"],
            child["event_id"], child["event_sha256"],
            commit["event_id"], commit["event_sha256"],
        ),
        reachable_blob_digests=reachable,
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha,
            response_sha, commit["event_id"], commit_index,
            source["occurred_at"],
        ),
    )


def reduce_import_group(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    semantic_events: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
) -> ImportGroupPatch:
    """Validate one atomic IMPORT_REPOSITORY group and every affected task."""
    if type(cursor) is not _ReplayCursor:
        _deny("GROUP_CURSOR", "/events")
    if type(workspace) is not _TransitionWorkspace:
        _deny("GROUP_PRIOR_STATE", "/state")
    _const(cursor.repository_generation, workspace.repository_generation, "/state/repository_generation")
    _const(
        cursor.repository_bundle_sha256,
        workspace.repository_bundle_sha256,
        "/state/repository_bundle_sha256",
    )
    if type(semantic_events) is not tuple or not 1 <= len(semantic_events) <= 10_001:
        _deny("GROUP_HOST_TYPE", "/events")
    start = cursor.global_sequence + 1
    parsed = tuple(
        _validate_event_shape(event, f"/events/{start + offset}")
        for offset, event in enumerate(semantic_events)
    )
    commit_index = start + len(parsed)
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_import(parsed, commit)
    event_count = len(parsed) + 1
    if event_count > 10_002:
        _deny("GROUP_EVENT_COUNT", "/events")
    transaction = commit["transaction"]
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(match.group(1), cursor.chain_id, f"/events/{start}/transaction/operation_key")
    for position, event in enumerate(parsed + (commit,)):
        index = start + position
        _const(event["runtime_id"], cursor.runtime_id, f"/events/{index}/runtime_id")
        _const(event["chain_id"], cursor.chain_id, f"/events/{index}/chain_id")
        _const(event["global_sequence"], index, f"/events/{index}/global_sequence")
        _const(event["occurred_at"], parsed[0]["occurred_at"], f"/events/{index}/occurred_at")
        _const(event["transaction"]["position"], position, f"/events/{index}/transaction/position")
        _const(event["transaction"]["event_count"], event_count, f"/events/{index}/transaction/event_count")
        for name in (
            "transaction_id", "event_count", "operation_key",
            "request_sha256", "response_sha256",
        ):
            _const(
                event["transaction"][name], transaction[name],
                f"/events/{index}/transaction/{name}",
            )
        predecessor = (
            {"event_id": cursor.head_event_id, "event_sha256": cursor.head_event_sha256}
            if position == 0 else {
                "event_id": parsed[position - 1]["event_id"],
                "event_sha256": parsed[position - 1]["event_sha256"],
            }
        )
        _const(event["global_predecessor"], predecessor, f"/events/{index}/global_predecessor")

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(
        _resolve(catalog, request_sha, REQUEST_SCHEMA_ID, "/import_request").value,
        _REQUEST_KEYS, "/import_request",
    )
    response = _object(
        _resolve(catalog, response_sha, RESPONSE_SCHEMA_ID, "/import_response").value,
        _RESPONSE_KEYS, "/import_response",
    )
    for artifact, value, version_key in (
        ("import_request", request, "request_format_version"),
        ("import_response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], cursor.runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], cursor.chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], "IMPORT_REPOSITORY", f"/{artifact}/operation")
        _const(value["operation_key"], operation_key, f"/{artifact}/operation_key")
    _const(request["subject"], None, "/import_request/subject")
    _const(request["expected_state_ref"], None, "/import_request/expected_state_ref")
    arguments = _object(
        request["arguments"],
        frozenset({
            "affected_task_ids", "reason_code", "source_commit",
            "project_state_sha256", "stop_set_sha256",
            "policy_capability_sha256", "task_inventory_sha256",
        }),
        "/import_request/arguments",
    )
    affected_value = arguments["affected_task_ids"]
    if type(affected_value) is not list:
        _deny("GROUP_HOST_TYPE", "/import_request/arguments/affected_task_ids")
    affected = tuple(affected_value)
    _const(len(parsed), len(affected) + 1, "/events")
    next_generation = workspace.repository_generation + 1
    if next_generation > 9_223_372_036_854_775_807:
        _deny("TRANSITION_COUNTER_OVERFLOW", "/repository_generation")
    _const(request["repository_generation"], next_generation, "/import_request/repository_generation")
    next_bundle = _pattern(
        request["repository_bundle_sha256"], _DIGEST,
        "/import_request/repository_bundle_sha256",
    )
    for position, event in enumerate(parsed + (commit,)):
        index = start + position
        _const(event["repository_generation"], next_generation, f"/events/{index}/repository_generation")
        _const(event["repository_bundle_sha256"], next_bundle, f"/events/{index}/repository_bundle_sha256")

    semantic_ids = tuple(event["event_id"] for event in parsed)
    try:
        staged = workspace.stage_import(TransitionIntent(
            operation="IMPORT_REPOSITORY",
            candidate_repository_generation=next_generation,
            candidate_repository_bundle_sha256=next_bundle,
            arguments=tuple(sorted(
                (key, tuple(value) if key == "affected_task_ids" else value)
                for key, value in arguments.items()
            )),
            semantic_event_ids=semantic_ids,
        ))
    except TransitionViolation as error:
        raise GroupValidationError(error.code, error.coordinate) from error
    after_tasks = {task.task_id: task for task in staged.after.tasks}
    affected_states: list[dict[str, Any]] = []
    reachable = {request_sha, response_sha}
    for offset, task_id in enumerate(affected):
        index = start + offset
        event = parsed[offset]
        _const(event["event_type"], "REPOSITORY_GENERATION_APPLIED", f"/events/{index}/event_type")
        _const(event["stream"], "TASK", f"/events/{index}/stream")
        before = workspace.task(task_id)
        if before is None:
            _deny("GROUP_PRIOR_STATE", f"/events/{index}/task_context/task_id")
        context = _object(
            event["task_context"],
            frozenset({"task_id", "attempt", "task_sequence", "task_predecessor"}),
            f"/events/{index}/task_context",
        )
        _const(context["task_id"], task_id, f"/events/{index}/task_context/task_id")
        _const(context["attempt"], before.attempt, f"/events/{index}/task_context/attempt")
        cursor.check_attempt_advance(event, opens_attempt=False, predecessor_attempt=None)
        before_sha = _ref(event["state_before_ref"], TASK_STATE_SCHEMA_ID, f"/events/{index}/state_before_ref")
        if _resolve(catalog, before_sha, TASK_STATE_SCHEMA_ID, f"/events/{index}/state_before_ref").value != _task_state_document(before):
            _deny("GROUP_STATE_BEFORE", f"/events/{index}/state_before_ref")
        after_sha = _ref(event["state_after_ref"], TASK_STATE_SCHEMA_ID, f"/events/{index}/state_after_ref")
        after = after_tasks[task_id]
        if _resolve(catalog, after_sha, TASK_STATE_SCHEMA_ID, f"/events/{index}/state_after_ref").value != _task_state_document(after):
            _deny("GROUP_STATE_DERIVATION", f"/events/{index}/state_after_ref")
        payload_sha = event["payload_ref"]["sha256"]
        payload = _object(
            _resolve(catalog, payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{index}/payload_ref").value,
            _PAYLOAD_KEYS, f"/events/{index}/payload_ref",
        )
        _const(payload, {
            "schema_version": 1, "payload_format_version": 2,
            "event_type": "REPOSITORY_GENERATION_APPLIED", "data": {},
        }, f"/events/{index}/payload_ref")
        reachable.update((before_sha, after_sha, payload_sha))
        affected_states.append({
            "task_id": task_id,
            "attempt": after.attempt,
            "state_ref": {"schema_id": TASK_STATE_SCHEMA_ID, "sha256": after_sha},
        })

    runtime_event = parsed[-1]
    runtime_index = start + len(parsed) - 1
    _const(runtime_event["event_type"], "REPOSITORY_GENERATION_ADVANCED", f"/events/{runtime_index}/event_type")
    _const(runtime_event["stream"], "RUNTIME", f"/events/{runtime_index}/stream")
    _const(runtime_event["task_context"], None, f"/events/{runtime_index}/task_context")
    _const(runtime_event["state_before_ref"], None, f"/events/{runtime_index}/state_before_ref")
    _const(runtime_event["state_after_ref"], None, f"/events/{runtime_index}/state_after_ref")
    runtime_payload_sha = runtime_event["payload_ref"]["sha256"]
    runtime_payload = _object(
        _resolve(catalog, runtime_payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{runtime_index}/payload_ref").value,
        _PAYLOAD_KEYS, "/import_runtime_payload",
    )
    _const(runtime_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "REPOSITORY_GENERATION_ADVANCED",
        "data": {
            "old_generation": workspace.repository_generation,
            "new_generation": next_generation,
            "source_commit": arguments["source_commit"],
            "repository_bundle_sha256": next_bundle,
            "project_state_sha256": arguments["project_state_sha256"],
            "stop_set_sha256": arguments["stop_set_sha256"],
            "policy_capability_sha256": arguments["policy_capability_sha256"],
            "task_inventory_sha256": arguments["task_inventory_sha256"],
            "reason_code": arguments["reason_code"],
            "affected_task_ids": list(affected),
        },
    }, "/import_runtime_payload")
    reachable.add(runtime_payload_sha)
    _const(commit["event_type"], "COMMAND_COMMITTED", f"/events/{commit_index}/event_type")
    _const(commit["stream"], "RUNTIME", f"/events/{commit_index}/stream")
    _const(commit["task_context"], None, f"/events/{commit_index}/task_context")
    _const(commit["state_before_ref"], None, f"/events/{commit_index}/state_before_ref")
    _const(commit["state_after_ref"], None, f"/events/{commit_index}/state_after_ref")
    _const(response["status"], "COMMITTED", "/import_response/status")
    _const(response["affected_states"], affected_states, "/import_response/affected_states")
    _const(response["generated_refs"], [], "/import_response/generated_refs")
    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{commit_index}/payload_ref").value,
        _PAYLOAD_KEYS, "/import_commit_payload",
    )
    _const(commit_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": list(semantic_ids),
            "pre_command_head": {
                "global_sequence": cursor.global_sequence,
                "event_id": cursor.head_event_id,
                "event_sha256": cursor.head_event_sha256,
            },
            "post_semantic_head": {
                "global_sequence": runtime_index,
                "event_id": runtime_event["event_id"],
                "event_sha256": runtime_event["event_sha256"],
            },
            "operation": "IMPORT_REPOSITORY",
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }, "/import_commit_payload")
    reachable.add(commit_payload_sha)
    return ImportGroupPatch(
        transition=staged,
        event_sequence=tuple(
            (event["event_id"], event["event_sha256"])
            for event in parsed + (commit,)
        ),
        reachable_blob_digests=tuple(sorted(reachable)),
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha,
            response_sha, commit["event_id"], commit_index,
            parsed[0]["occurred_at"],
        ),
    )


_ROOT_KEYS = frozenset({
    "attempts", "blobs", "claims", "events", "idempotency",
    "legacy_archive", "metadata", "migrations", "remediation_links",
    "reviews", "schema_documents", "schema_registry", "seals",
    "snapshots", "tasks",
})
_CHECKPOINT_SCHEMA_ID = "urn:edgelab:m0-3a-runtime-checkpoint:2"
_EXPORT_SCHEMA_ID = "urn:edgelab:m0-3a-runtime-export:2"


def reduce_snapshot_group(
    *,
    cursor: _ReplayCursor,
    semantic_event: Any,
    commit_event: Any,
    catalog: Mapping[str, BlobValue],
    cut_roots: Mapping[str, str],
    manifest_sha256: str,
    selectors: tuple[dict[str, Any], ...],
    snapshot_kind: str,
    snapshot_sequence: int,
    prior_document_sha256: str | None,
    source_checkpoint_sha256: str | None,
) -> SnapshotGroupPatch:
    """Validate one exact checkpoint or export registration without I/O."""
    if type(cursor) is not _ReplayCursor:
        _deny("GROUP_CURSOR", "/events")
    if type(snapshot_kind) is not str or snapshot_kind not in {
        "CHECKPOINT", "EXPORT",
    }:
        _deny("GROUP_SNAPSHOT_KIND", "/snapshot_kind")
    if type(cut_roots) is not dict or cut_roots.keys() != _ROOT_KEYS:
        _deny("GROUP_SNAPSHOT_ROOTS", "/roots")
    for name, digest in cut_roots.items():
        _pattern(digest, _DIGEST, f"/roots/{name}")
    if type(selectors) is not tuple or len(selectors) < 2:
        _deny("GROUP_SELECTOR_HISTORY", "/selector_history")
    if type(snapshot_sequence) is not int or snapshot_sequence < 0:
        _deny("GROUP_SNAPSHOT_SEQUENCE", "/snapshot_sequence")
    if snapshot_sequence == 0:
        _const(prior_document_sha256, None, "/prior_document_sha256")
    else:
        _pattern(prior_document_sha256, _DIGEST, "/prior_document_sha256")

    semantic_index = cursor.global_sequence + 1
    commit_index = semantic_index + 1
    semantic = _validate_event_shape(semantic_event, f"/events/{semantic_index}")
    commit = _validate_event_shape(commit_event, f"/events/{commit_index}")
    cursor.check_pair(semantic, commit)
    transaction = semantic["transaction"]
    operation = "CHECKPOINT" if snapshot_kind == "CHECKPOINT" else "EXPORT_SNAPSHOT"
    semantic_type = (
        "RUNTIME_CHECKPOINTED"
        if snapshot_kind == "CHECKPOINT"
        else "RUNTIME_SNAPSHOT_EXPORTED"
    )
    operation_key = transaction["operation_key"]
    match = _OPERATION_KEY.fullmatch(operation_key)
    assert match is not None
    _const(match.group(1), cursor.chain_id, f"/events/{semantic_index}/transaction/operation_key")
    for event, index, position in (
        (semantic, semantic_index, 0), (commit, commit_index, 1),
    ):
        _const(event["runtime_id"], cursor.runtime_id, f"/events/{index}/runtime_id")
        _const(event["chain_id"], cursor.chain_id, f"/events/{index}/chain_id")
        _const(event["repository_generation"], cursor.repository_generation, f"/events/{index}/repository_generation")
        _const(event["repository_bundle_sha256"], cursor.repository_bundle_sha256, f"/events/{index}/repository_bundle_sha256")
        _const(event["global_sequence"], index, f"/events/{index}/global_sequence")
        _const(event["stream"], "RUNTIME", f"/events/{index}/stream")
        _const(event["task_context"], None, f"/events/{index}/task_context")
        _const(event["state_before_ref"], None, f"/events/{index}/state_before_ref")
        _const(event["state_after_ref"], None, f"/events/{index}/state_after_ref")
        _const(event["transaction"]["position"], position, f"/events/{index}/transaction/position")
        _const(event["transaction"]["event_count"], 2, f"/events/{index}/transaction/event_count")
    _const(semantic["event_type"], semantic_type, f"/events/{semantic_index}/event_type")
    _const(commit["event_type"], "COMMAND_COMMITTED", f"/events/{commit_index}/event_type")
    _const(semantic["global_predecessor"], {
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }, f"/events/{semantic_index}/global_predecessor")
    _const(commit["global_predecessor"], {
        "event_id": semantic["event_id"],
        "event_sha256": semantic["event_sha256"],
    }, f"/events/{commit_index}/global_predecessor")
    for name in (
        "runtime_id", "chain_id", "occurred_at", "repository_generation",
        "repository_bundle_sha256",
    ):
        _const(commit[name], semantic[name], f"/events/{commit_index}/{name}")
    for name in (
        "transaction_id", "event_count", "operation_key", "request_sha256",
        "response_sha256",
    ):
        _const(commit["transaction"][name], transaction[name], f"/events/{commit_index}/transaction/{name}")

    request_sha = transaction["request_sha256"]
    response_sha = transaction["response_sha256"]
    request = _object(
        _resolve(catalog, request_sha, REQUEST_SCHEMA_ID, "/snapshot_request").value,
        _REQUEST_KEYS, "/snapshot_request",
    )
    response = _object(
        _resolve(catalog, response_sha, RESPONSE_SCHEMA_ID, "/snapshot_response").value,
        _RESPONSE_KEYS, "/snapshot_response",
    )
    for artifact, value, version_key in (
        ("snapshot_request", request, "request_format_version"),
        ("snapshot_response", response, "response_format_version"),
    ):
        _const(value["schema_version"], 1, f"/{artifact}/schema_version")
        _const(value[version_key], 2, f"/{artifact}/{version_key}")
        _const(value["runtime_id"], cursor.runtime_id, f"/{artifact}/runtime_id")
        _const(value["chain_id"], cursor.chain_id, f"/{artifact}/chain_id")
        _const(value["operation"], operation, f"/{artifact}/operation")
        _const(value["operation_key"], operation_key, f"/{artifact}/operation_key")
    _const(request["repository_generation"], cursor.repository_generation, "/snapshot_request/repository_generation")
    _const(request["repository_bundle_sha256"], cursor.repository_bundle_sha256, "/snapshot_request/repository_bundle_sha256")
    _const(request["subject"], None, "/snapshot_request/subject")
    _const(request["expected_state_ref"], None, "/snapshot_request/expected_state_ref")
    _const(response["status"], "COMMITTED", "/snapshot_response/status")
    _const(response["affected_states"], [], "/snapshot_response/affected_states")

    checkpoint = snapshot_kind == "CHECKPOINT"
    argument_keys = frozenset({
        "snapshot_id",
        "checkpoint_sequence" if checkpoint else "export_sequence",
        "checkpoint_sha256" if checkpoint else "export_sha256",
        "checkpoint_blob_sha256" if checkpoint else "export_blob_sha256",
        "prior_checkpoint_sha256" if checkpoint else "prior_export_sha256",
        *( {
            "next_selector_generation", "next_selector_sha256",
            "next_selector_history_sha256",
        } if checkpoint else set()),
    })
    arguments = _object(request["arguments"], argument_keys, "/snapshot_request/arguments")
    snapshot_id = _pattern(arguments["snapshot_id"], _UUID4, "/snapshot_request/arguments/snapshot_id")
    sequence_name = "checkpoint_sequence" if checkpoint else "export_sequence"
    digest_name = "checkpoint_sha256" if checkpoint else "export_sha256"
    blob_name = "checkpoint_blob_sha256" if checkpoint else "export_blob_sha256"
    prior_name = "prior_checkpoint_sha256" if checkpoint else "prior_export_sha256"
    _const(arguments[sequence_name], snapshot_sequence, f"/snapshot_request/arguments/{sequence_name}")
    document_sha = _pattern(arguments[digest_name], _DIGEST, f"/snapshot_request/arguments/{digest_name}")
    document_blob_sha = _pattern(arguments[blob_name], _DIGEST, f"/snapshot_request/arguments/{blob_name}")
    _const(arguments[prior_name], prior_document_sha256, f"/snapshot_request/arguments/{prior_name}")
    document_schema = _CHECKPOINT_SCHEMA_ID if checkpoint else _EXPORT_SCHEMA_ID
    document = _resolve(catalog, document_blob_sha, document_schema, f"/snapshot_request/arguments/{blob_name}").value
    document_keys = frozenset({
        "schema_version", "runtime_format_version", "runtime_id", "chain_id",
        sequence_name, "through_global_sequence", "head_event_id",
        "head_event_sha256", "manifest_sha256",
        *( {"prior_checkpoint_sha256"} if checkpoint else {
            "source_checkpoint_sha256", "prior_export_sha256",
        }),
        "roots", digest_name, "anchor_status", "currentness_status",
        "authorizing_use", "created_at",
    })
    document = _object(document, document_keys, "/snapshot_document")
    _const(document["schema_version"], 1, "/snapshot_document/schema_version")
    _const(document["runtime_format_version"], 2, "/snapshot_document/runtime_format_version")
    _const(document["runtime_id"], cursor.runtime_id, "/snapshot_document/runtime_id")
    _const(document["chain_id"], cursor.chain_id, "/snapshot_document/chain_id")
    _const(document[sequence_name], snapshot_sequence, f"/snapshot_document/{sequence_name}")
    _const(document["through_global_sequence"], cursor.global_sequence, "/snapshot_document/through_global_sequence")
    _const(document["head_event_id"], cursor.head_event_id, "/snapshot_document/head_event_id")
    _const(document["head_event_sha256"], cursor.head_event_sha256, "/snapshot_document/head_event_sha256")
    _const(document["manifest_sha256"], manifest_sha256, "/snapshot_document/manifest_sha256")
    _const(document["roots"], dict(cut_roots), "/snapshot_document/roots")
    _const(document[prior_name], prior_document_sha256, f"/snapshot_document/{prior_name}")
    if not checkpoint:
        _const(document["source_checkpoint_sha256"], source_checkpoint_sha256, "/snapshot_document/source_checkpoint_sha256")
    _const(document["anchor_status"], "LOCAL_UNANCHORED", "/snapshot_document/anchor_status")
    _const(document["currentness_status"], "UNKNOWN", "/snapshot_document/currentness_status")
    _const(document["authorizing_use"], "DENY", "/snapshot_document/authorizing_use")
    _const(document["created_at"], semantic["occurred_at"], "/snapshot_document/created_at")
    derived_document_sha = checkpoint_digest(document) if checkpoint else export_digest(document)
    _const(document[digest_name], derived_document_sha, f"/snapshot_document/{digest_name}")
    _const(document_sha, derived_document_sha, f"/snapshot_request/arguments/{digest_name}")
    _const(document_blob_sha, blob_digest(document), f"/snapshot_request/arguments/{blob_name}")

    semantic_payload_sha = semantic["payload_ref"]["sha256"]
    semantic_payload = _object(
        _resolve(catalog, semantic_payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{semantic_index}/payload_ref").value,
        _PAYLOAD_KEYS, "/snapshot_payload",
    )
    cut_head = {
        "global_sequence": cursor.global_sequence,
        "event_id": cursor.head_event_id,
        "event_sha256": cursor.head_event_sha256,
    }
    expected_data = dict(arguments)
    expected_data["cut_head"] = cut_head
    _const(semantic_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": semantic_type,
        "data": expected_data,
    }, "/snapshot_payload")

    next_selector: dict[str, Any] | None = None
    if checkpoint:
        current = selectors[-1]
        generation = len(selectors)
        next_selector = {
            "schema_version": 1,
            "selector_format_version": 1,
            "selector_generation": generation,
            "active_runtime_format_version": 2,
            "active_runtime_id": cursor.runtime_id,
            "active_database_path": "runtime.v2.sqlite",
            "active_attachment_path": "attachment.v2.json",
            "active_manifest_path": "runtime.v2.manifest.json",
            "active_manifest_sha256": manifest_sha256,
            "latest_v2_checkpoint_sha256": document_sha,
            "selector_history_path": f"selectors/{generation:020d}.json",
            "prior_selector_path": f"selectors/{generation - 1:020d}.json",
            "prior_selector_sha256": current["selector_sha256"],
            "cutover_state": "V2_ACTIVE",
            "currentness_status": "UNKNOWN",
            "authorizing_use": "DENY",
            "written_at": semantic["occurred_at"],
            "selector_sha256": "0" * 64,
        }
        next_selector["selector_sha256"] = selector_digest(next_selector)
        next_history_sha = selector_history_digest([*selectors, next_selector])
        _const(arguments["next_selector_generation"], generation, "/snapshot_request/arguments/next_selector_generation")
        _const(arguments["next_selector_sha256"], next_selector["selector_sha256"], "/snapshot_request/arguments/next_selector_sha256")
        _const(arguments["next_selector_history_sha256"], next_history_sha, "/snapshot_request/arguments/next_selector_history_sha256")

    _const(response["generated_refs"], [{
        "kind": snapshot_kind,
        "identifier": snapshot_id,
        "sha256": document_sha,
    }], "/snapshot_response/generated_refs")
    commit_payload_sha = commit["payload_ref"]["sha256"]
    commit_payload = _object(
        _resolve(catalog, commit_payload_sha, PAYLOAD_SCHEMA_ID, f"/events/{commit_index}/payload_ref").value,
        _PAYLOAD_KEYS, "/snapshot_commit_payload",
    )
    _const(commit_payload, {
        "schema_version": 1,
        "payload_format_version": 2,
        "event_type": "COMMAND_COMMITTED",
        "data": {
            "semantic_event_ids": [semantic["event_id"]],
            "pre_command_head": cut_head,
            "post_semantic_head": {
                "global_sequence": semantic_index,
                "event_id": semantic["event_id"],
                "event_sha256": semantic["event_sha256"],
            },
            "operation": operation,
            "operation_key": operation_key,
            "request_ref": {"schema_id": REQUEST_SCHEMA_ID, "sha256": request_sha},
            "response_ref": {"schema_id": RESPONSE_SCHEMA_ID, "sha256": response_sha},
            "result": "COMMITTED",
        },
    }, "/snapshot_commit_payload")
    return SnapshotGroupPatch(
        event_pair=(
            semantic["event_id"], semantic["event_sha256"],
            commit["event_id"], commit["event_sha256"],
        ),
        reachable_blob_digests=tuple(sorted({
            request_sha, response_sha, semantic_payload_sha,
            commit_payload_sha, document_blob_sha,
        })),
        idempotency_row=(
            operation_key, transaction["transaction_id"], request_sha,
            response_sha, commit["event_id"], commit_index,
            semantic["occurred_at"],
        ),
        snapshot_row=(
            snapshot_id, snapshot_kind, snapshot_sequence,
            semantic["event_id"], document_sha, document_blob_sha,
            cursor.global_sequence, cursor.head_event_id,
            cursor.head_event_sha256, prior_document_sha256,
            semantic["occurred_at"],
        ),
        next_selector=next_selector,
    )


__all__ = (
    "BlobValue", "ClaimGroupPatch", "GroupValidationError",
    "ImportGroupPatch", "InitializeGroupPatch", "TASK_STATE_SCHEMA_ID",
    "RemediationGroupPatch", "SnapshotGroupPatch", "WorkerGroupPatch",
    "reduce_claim_group", "reduce_initialize_group",
    "reduce_import_group", "reduce_remediation_group", "reduce_snapshot_group",
    "reduce_worker_group",
)
