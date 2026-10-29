"""Pure immutable task-transition kernel for the runtime-v2 reducer.

This module is deliberately private to the future whole-image reducer.  It
does not parse retained events, validate a runtime image, perform I/O, or grant
authority.  Callers must supply already decoded transaction intent and exact
semantic event identifiers.  Every result remains local, unanchored evidence.

The public runtime-v2 verifier does not import this module and continues to
return only INVALID or UNSUPPORTED.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any, Mapping

from .runtime_v2_codec import remediation_link_digest


INT64_MAX = 9_223_372_036_854_775_807
MAX_EVENTS = 100_000
MAX_TASKS = 100_000
MAX_GROUP_EVENTS = 10_002
MAX_ARGUMENTS = 8

_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

_TRIPLES = {
    "N0": ("ACTIVE", "CLAIMABLE", "NOT_REQUIRED"),
    "N1": ("ACTIVE", "CLAIMED", "NOT_REQUIRED"),
    "N2": ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED"),
    "F0": ("ACTIVE", "FAILED", "NOT_REQUIRED"),
    "N3": ("ACTIVE", "EXECUTION_COMPLETED", "REVIEW_PENDING"),
    "N4": ("ACTIVE", "EXECUTION_COMPLETED", "REVIEWING"),
    "N5": ("ACTIVE", "EXECUTION_COMPLETED", "REJECTED"),
    "N6": ("ACTIVE", "EXECUTION_COMPLETED", "REMEDIATION_REQUIRED"),
    "N7": ("ACTIVE", "EXECUTION_COMPLETED", "APPROVED"),
    "N8": ("DIRECTOR_GATE_READY", "EXECUTION_COMPLETED", "APPROVED"),
    "B0": ("GOVERNANCE_BLOCKED", "EXECUTION_BLOCKED", "NOT_REQUIRED"),
    "B1": ("GOVERNANCE_BLOCKED", "EXECUTION_BLOCKED", "REVIEW_PENDING"),
    "C0": ("CLOSED", "EXECUTION_COMPLETED", "NOT_REQUIRED"),
}
_CODE_BY_TRIPLE = {value: key for key, value in _TRIPLES.items()}


class TransitionViolation(ValueError):
    """Stable fail-closed rejection from the private transition kernel."""

    def __init__(self, code: str, coordinate: str = "/") -> None:
        super().__init__(f"{code}:{coordinate}")
        self.code = code
        self.coordinate = coordinate


def _deny(code: str, coordinate: str = "/") -> None:
    raise TransitionViolation(code, coordinate)


def _strict_int(value: Any, minimum: int, coordinate: str) -> int:
    if type(value) is not int or value < minimum or value > INT64_MAX:
        _deny("TRANSITION_INTEGER", coordinate)
    return value


def _increment(value: int, coordinate: str) -> int:
    if value == INT64_MAX:
        _deny("TRANSITION_COUNTER_OVERFLOW", coordinate)
    return value + 1


def _text(value: Any, pattern: re.Pattern[str], coordinate: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _deny("TRANSITION_TEXT", coordinate)
    return value


def _identity(value: Any, coordinate: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 256
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        _deny("TRANSITION_IDENTITY", coordinate)
    return value


def _task_id(value: Any, coordinate: str) -> str:
    return _text(value, _TASK_ID, coordinate)


def _uuid(value: Any, coordinate: str) -> str:
    return _text(value, _UUID4, coordinate)


def _digest(value: Any, coordinate: str) -> str:
    return _text(value, _DIGEST, coordinate)


@dataclass(frozen=True, slots=True)
class TaskState:
    task_id: str
    attempt: int
    workflow: str
    execution: str
    review: str
    scheduler_generation: int
    dispatch_generation: int
    task_fence: int
    active_claim_id: str | None
    reviewer_assignment_id: str | None
    continuation_count: int
    repository_generation: int
    decision_receipt_digest: str
    owner: str
    owner_role: str
    reviewer: None = None
    predecessor_task: str | None = None
    successor_task: str | None = None

    def __post_init__(self) -> None:
        _task_id(self.task_id, "/task_id")
        _strict_int(self.attempt, 1, "/attempt")
        for name in (
            "scheduler_generation",
            "dispatch_generation",
            "task_fence",
            "continuation_count",
            "repository_generation",
        ):
            _strict_int(getattr(self, name), 0, f"/{name}")
        _digest(self.decision_receipt_digest, "/decision_receipt_digest")
        _identity(self.owner, "/owner")
        _identity(self.owner_role, "/owner_role")
        if self.reviewer is not None:
            _deny("TRANSITION_REVIEWER_NOT_NULL", "/reviewer")
        if self.predecessor_task is not None:
            _task_id(self.predecessor_task, "/predecessor_task")
        if self.successor_task is not None:
            _task_id(self.successor_task, "/successor_task")
        if self.task_id in {self.predecessor_task, self.successor_task}:
            _deny("TRANSITION_SELF_LINK", "/task_id")
        if any(type(value) is not str for value in (self.workflow, self.execution, self.review)):
            _deny("TRANSITION_UNREACHABLE_TRIPLE", "/workflow")
        code = _CODE_BY_TRIPLE.get((self.workflow, self.execution, self.review))
        if code is None:
            _deny("TRANSITION_UNREACHABLE_TRIPLE", "/workflow")
        expects_claim = code in {"N1", "N2"}
        expects_review = code == "N4"
        if expects_claim != (self.active_claim_id is not None):
            _deny("TRANSITION_CLAIM_SHAPE", "/active_claim_id")
        if expects_review != (self.reviewer_assignment_id is not None):
            _deny("TRANSITION_REVIEW_SHAPE", "/reviewer_assignment_id")
        if self.active_claim_id is not None:
            _uuid(self.active_claim_id, "/active_claim_id")
        if self.reviewer_assignment_id is not None:
            _uuid(self.reviewer_assignment_id, "/reviewer_assignment_id")

    @property
    def code(self) -> str:
        return _CODE_BY_TRIPLE[(self.workflow, self.execution, self.review)]


@dataclass(frozen=True, slots=True)
class ClaimRecord:
    claim_id: str
    task_id: str
    attempt: int
    fence: int
    status: str
    actor: str
    opened_event_id: str
    closed_event_id: str | None = None

    def __post_init__(self) -> None:
        _uuid(self.claim_id, "/claim_id")
        _task_id(self.task_id, "/task_id")
        _strict_int(self.attempt, 1, "/attempt")
        _strict_int(self.fence, 0, "/fence")
        if type(self.status) is not str or self.status not in {
            "OPEN", "YIELDED", "FAILED", "COMPLETED", "RECOVERED",
            "GOVERNANCE_INVALIDATED",
        }:
            _deny("TRANSITION_CLAIM_STATUS", "/status")
        _identity(self.actor, "/actor")
        _uuid(self.opened_event_id, "/opened_event_id")
        if (self.status == "OPEN") != (self.closed_event_id is None):
            _deny("TRANSITION_CLAIM_CLOSE_SHAPE", "/closed_event_id")
        if self.closed_event_id is not None:
            _uuid(self.closed_event_id, "/closed_event_id")


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    assignment_id: str
    task_id: str
    attempt: int
    actor: str
    role: str
    status: str
    opened_event_id: str
    closed_event_id: str | None = None

    def __post_init__(self) -> None:
        _uuid(self.assignment_id, "/assignment_id")
        _task_id(self.task_id, "/task_id")
        _strict_int(self.attempt, 1, "/attempt")
        _identity(self.actor, "/actor")
        _identity(self.role, "/role")
        if type(self.status) is not str or self.status not in {
            "OPEN", "APPROVED", "REJECTED", "REMEDIATION_REQUIRED",
            "GOVERNANCE_REVOKED",
        }:
            _deny("TRANSITION_REVIEW_STATUS", "/status")
        _uuid(self.opened_event_id, "/opened_event_id")
        if (self.status == "OPEN") != (self.closed_event_id is None):
            _deny("TRANSITION_REVIEW_CLOSE_SHAPE", "/closed_event_id")
        if self.closed_event_id is not None:
            _uuid(self.closed_event_id, "/closed_event_id")


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    task_id: str
    attempt: int
    operation: str
    decision_sha256: str
    event_id: str

    def __post_init__(self) -> None:
        _task_id(self.task_id, "/task_id")
        _strict_int(self.attempt, 1, "/attempt")
        if type(self.operation) is not str or self.operation not in {"APPROVE", "REJECT", "REMEDIATE"}:
            _deny("TRANSITION_DECISION_OPERATION", "/operation")
        _digest(self.decision_sha256, "/decision_sha256")
        _uuid(self.event_id, "/event_id")


@dataclass(frozen=True, slots=True)
class RemediationLinkRecord:
    link_id: str
    source_task_id: str
    source_attempt: int
    child_task_id: str
    child_attempt: int
    source_event_id: str
    child_event_id: str
    decision_sha256: str
    link_sha256: str

    def __post_init__(self) -> None:
        _uuid(self.link_id, "/link_id")
        _task_id(self.source_task_id, "/source_task_id")
        _strict_int(self.source_attempt, 1, "/source_attempt")
        _task_id(self.child_task_id, "/child_task_id")
        _strict_int(self.child_attempt, 1, "/child_attempt")
        if self.source_task_id == self.child_task_id:
            _deny("TRANSITION_LINK_SELF", "/child_task_id")
        _uuid(self.source_event_id, "/source_event_id")
        _uuid(self.child_event_id, "/child_event_id")
        if self.source_event_id == self.child_event_id:
            _deny("TRANSITION_EVENT_DUPLICATE", "/child_event_id")
        _digest(self.decision_sha256, "/decision_sha256")
        _digest(self.link_sha256, "/link_sha256")
        preimage = {
            "link_id": self.link_id,
            "source_task_id": self.source_task_id,
            "source_attempt": self.source_attempt,
            "child_task_id": self.child_task_id,
            "child_attempt": self.child_attempt,
            "source_event_id": self.source_event_id,
            "child_event_id": self.child_event_id,
            "decision_sha256": self.decision_sha256,
            "link_sha256": self.link_sha256,
        }
        if remediation_link_digest(preimage) != self.link_sha256:
            _deny("TRANSITION_LINK_DIGEST", "/link_sha256")


@dataclass(frozen=True, slots=True)
class ReducerState:
    repository_generation: int
    repository_bundle_sha256: str
    tasks: tuple[TaskState, ...] = ()
    claims: tuple[ClaimRecord, ...] = ()
    reviews: tuple[ReviewRecord, ...] = ()
    decisions: tuple[ReviewDecision, ...] = ()
    remediation_links: tuple[RemediationLinkRecord, ...] = ()

    def __post_init__(self) -> None:
        _strict_int(self.repository_generation, 0, "/repository_generation")
        _digest(self.repository_bundle_sha256, "/repository_bundle_sha256")
        for name in ("tasks", "claims", "reviews", "decisions", "remediation_links"):
            if type(getattr(self, name)) is not tuple:
                _deny("TRANSITION_CONTAINER_TYPE", f"/{name}")
        if len(self.tasks) > MAX_TASKS:
            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")
        for name in ("claims", "reviews", "decisions", "remediation_links"):
            if len(getattr(self, name)) > MAX_EVENTS:
                _deny("TRANSITION_RESOURCE_RECORDS", f"/{name}")
        _require_members(self.tasks, TaskState, "/tasks")
        _require_members(self.claims, ClaimRecord, "/claims")
        _require_members(self.reviews, ReviewRecord, "/reviews")
        _require_members(self.decisions, ReviewDecision, "/decisions")
        _require_members(self.remediation_links, RemediationLinkRecord, "/remediation_links")
        _require_sorted_unique(self.tasks, lambda item: item.task_id, "/tasks")
        _require_sorted_unique(self.claims, lambda item: item.claim_id, "/claims")
        _require_sorted_unique(self.reviews, lambda item: item.assignment_id, "/reviews")
        _require_sorted_unique(
            self.decisions, lambda item: (item.task_id, item.attempt), "/decisions"
        )
        _require_sorted_unique(
            self.remediation_links, lambda item: item.link_id, "/remediation_links"
        )
        tasks = {task.task_id: task for task in self.tasks}
        claims = {claim.claim_id: claim for claim in self.claims}
        reviews = {review.assignment_id: review for review in self.reviews}
        decisions = {(item.task_id, item.attempt): item for item in self.decisions}
        active_claims: set[str] = set()
        active_reviews: set[str] = set()
        for task in self.tasks:
            if task.active_claim_id is not None:
                claim = claims.get(task.active_claim_id)
                if (
                    claim is None
                    or claim.status != "OPEN"
                    or (claim.task_id, claim.attempt) != (task.task_id, task.attempt)
                    or claim.fence != task.task_fence
                ):
                    _deny("TRANSITION_STATE_CLAIM_CLOSURE", f"/tasks/{task.task_id}")
                if claim.claim_id in active_claims:
                    _deny("TRANSITION_STATE_CLAIM_REUSED", f"/tasks/{task.task_id}")
                active_claims.add(claim.claim_id)
            if task.reviewer_assignment_id is not None:
                review = reviews.get(task.reviewer_assignment_id)
                if (
                    review is None
                    or review.status != "OPEN"
                    or (review.task_id, review.attempt) != (task.task_id, task.attempt)
                ):
                    _deny("TRANSITION_STATE_REVIEW_CLOSURE", f"/tasks/{task.task_id}")
                if review.assignment_id in active_reviews:
                    _deny("TRANSITION_STATE_REVIEW_REUSED", f"/tasks/{task.task_id}")
                active_reviews.add(review.assignment_id)
        if {item.claim_id for item in self.claims if item.status == "OPEN"} != active_claims:
            _deny("TRANSITION_STATE_ORPHAN_OPEN_CLAIM", "/claims")
        for claim in self.claims:
            task = tasks.get(claim.task_id)
            if (
                task is None
                or claim.attempt > task.attempt
                or claim.fence < 1
                or claim.fence > task.task_fence
            ):
                _deny("TRANSITION_STATE_CLAIM_TASK", f"/claims/{claim.claim_id}")
        if {item.assignment_id for item in self.reviews if item.status == "OPEN"} != active_reviews:
            _deny("TRANSITION_STATE_ORPHAN_OPEN_REVIEW", "/reviews")
        for review in self.reviews:
            task = tasks.get(review.task_id)
            if task is None or task.attempt != review.attempt:
                _deny("TRANSITION_STATE_REVIEW_TASK", f"/reviews/{review.assignment_id}")
            if review.actor == task.owner:
                _deny("TRANSITION_REVIEW_ACTOR_NOT_INDEPENDENT", f"/reviews/{review.assignment_id}/actor")
            if review.role == task.owner_role:
                _deny("TRANSITION_REVIEW_ROLE_NOT_INDEPENDENT", f"/reviews/{review.assignment_id}/role")
        review_closures = {
            (review.task_id, review.attempt, review.status, review.closed_event_id)
            for review in self.reviews
            if review.closed_event_id is not None
        }
        for decision in self.decisions:
            task = tasks.get(decision.task_id)
            expected_status = {
                "APPROVE": "APPROVED",
                "REJECT": "REJECTED",
                "REMEDIATE": "REMEDIATION_REQUIRED",
            }[decision.operation]
            if task is None or (
                decision.task_id, decision.attempt, expected_status, decision.event_id
            ) not in review_closures:
                _deny("TRANSITION_STATE_DECISION_CLOSURE", f"/decisions/{decision.task_id}")
            allowed_codes = {
                "APPROVE": {"N7", "N8"},
                "REJECT": {"N5"},
                "REMEDIATE": {"N6"},
            }[decision.operation]
            if task.attempt != decision.attempt or task.code not in allowed_codes:
                _deny("TRANSITION_STATE_DECISION_TARGET", f"/decisions/{decision.task_id}")
        decision_closures = {
            (
                decision.task_id,
                decision.attempt,
                {
                    "APPROVE": "APPROVED",
                    "REJECT": "REJECTED",
                    "REMEDIATE": "REMEDIATION_REQUIRED",
                }[decision.operation],
                decision.event_id,
            )
            for decision in self.decisions
        }
        for review in self.reviews:
            if review.status in {"APPROVED", "REJECTED", "REMEDIATION_REQUIRED"} and (
                review.task_id, review.attempt, review.status, review.closed_event_id
            ) not in decision_closures:
                _deny("TRANSITION_STATE_REVIEW_DECISION", f"/reviews/{review.assignment_id}")
        for task in self.tasks:
            expected_operation = {
                "N5": "REJECT", "N6": "REMEDIATE", "N7": "APPROVE", "N8": "APPROVE"
            }.get(task.code)
            if expected_operation is not None:
                decision = decisions.get((task.task_id, task.attempt))
                if decision is None or decision.operation != expected_operation:
                    _deny("TRANSITION_STATE_DECISION_REQUIRED", f"/tasks/{task.task_id}")
        for link in self.remediation_links:
            source = tasks.get(link.source_task_id)
            child = tasks.get(link.child_task_id)
            decision = decisions.get((link.source_task_id, link.source_attempt))
            if (
                source is None
                or child is None
                or source.attempt != link.source_attempt
                or link.child_attempt != 1
                or child.attempt < link.child_attempt
                or source.successor_task != child.task_id
                or child.predecessor_task != source.task_id
                or decision is None
                or decision.operation not in {"REJECT", "REMEDIATE"}
                or decision.decision_sha256 != link.decision_sha256
            ):
                _deny("TRANSITION_STATE_LINK_CLOSURE", f"/remediation_links/{link.link_id}")
        source_ids = tuple(link.source_task_id for link in self.remediation_links)
        child_ids = tuple(link.child_task_id for link in self.remediation_links)
        pairs = tuple(
            (link.source_task_id, link.child_task_id) for link in self.remediation_links
        )
        if (
            len(source_ids) != len(set(source_ids))
            or len(child_ids) != len(set(child_ids))
            or len(pairs) != len(set(pairs))
        ):
            _deny("TRANSITION_STATE_LINK_REUSED", "/remediation_links")
        retained_event_ids: list[str] = []
        for claim in self.claims:
            retained_event_ids.append(claim.opened_event_id)
            if claim.closed_event_id is not None:
                retained_event_ids.append(claim.closed_event_id)
        for review in self.reviews:
            retained_event_ids.append(review.opened_event_id)
            if review.closed_event_id is not None:
                retained_event_ids.append(review.closed_event_id)
        for link in self.remediation_links:
            retained_event_ids.extend((link.source_event_id, link.child_event_id))
        if len(retained_event_ids) != len(set(retained_event_ids)):
            _deny("TRANSITION_STATE_EVENT_REUSED", "/")
        link_pairs = {
            (link.source_task_id, link.child_task_id) for link in self.remediation_links
        }
        for task in self.tasks:
            if task.successor_task is not None and (task.task_id, task.successor_task) not in link_pairs:
                _deny("TRANSITION_STATE_SUCCESSOR_LINK", f"/tasks/{task.task_id}")
            if task.predecessor_task is not None and (task.predecessor_task, task.task_id) not in link_pairs:
                _deny("TRANSITION_STATE_PREDECESSOR_LINK", f"/tasks/{task.task_id}")
        lineage_done: set[str] = set()
        for task in self.tasks:
            if task.task_id in lineage_done:
                continue
            path: list[str] = []
            path_set: set[str] = set()
            cursor: TaskState | None = task
            while cursor is not None and cursor.task_id not in lineage_done:
                if cursor.task_id in path_set:
                    _deny("TRANSITION_STATE_LINEAGE_CYCLE", f"/tasks/{task.task_id}")
                path.append(cursor.task_id)
                path_set.add(cursor.task_id)
                if cursor.successor_task is None:
                    break
                cursor = tasks.get(cursor.successor_task)
                if cursor is None:
                    _deny("TRANSITION_STATE_SUCCESSOR_MISSING", f"/tasks/{task.task_id}")
            lineage_done.update(path)


def _require_sorted_unique(items: tuple[Any, ...], key: Any, coordinate: str) -> None:
    keys = tuple(key(item) for item in items)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        _deny("TRANSITION_ORDER_OR_DUPLICATE", coordinate)


def _require_members(items: tuple[Any, ...], expected: type[Any], coordinate: str) -> None:
    for index, item in enumerate(items):
        if type(item) is not expected:
            _deny("TRANSITION_MEMBER_TYPE", f"{coordinate}/{index}")


@dataclass(frozen=True, slots=True)
class TransitionIntent:
    operation: str
    task_id: str | None = None
    attempt: int | None = None
    child_task_id: str | None = None
    child_attempt: int | None = None
    arguments: tuple[tuple[str, Any], ...] = ()
    generated_id: str | None = None
    semantic_event_ids: tuple[str, ...] = ()
    candidate_repository_generation: int | None = None
    candidate_repository_bundle_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.operation) is not str:
            _deny("TRANSITION_OPERATION_TYPE", "/operation")
        if type(self.arguments) is not tuple or type(self.semantic_event_ids) is not tuple:
            _deny("TRANSITION_CONTAINER_TYPE", "/")
        if len(self.arguments) > MAX_ARGUMENTS:
            _deny("TRANSITION_RESOURCE_ARGUMENTS", "/arguments")
        if len(self.semantic_event_ids) > MAX_GROUP_EVENTS:
            _deny("TRANSITION_RESOURCE_EVENTS", "/semantic_event_ids")
        if any(
            type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
            for item in self.arguments
        ):
            _deny("TRANSITION_ARGUMENT_SHAPE", "/arguments")
        keys = tuple(item[0] for item in self.arguments)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            _deny("TRANSITION_ARGUMENT_SHAPE", "/arguments")
        for event_id in self.semantic_event_ids:
            _uuid(event_id, "/semantic_event_ids")

    def args(self, expected: tuple[str, ...]) -> dict[str, Any]:
        expected_sorted = tuple(sorted(expected))
        keys = tuple(key for key, _ in self.arguments)
        if keys != expected_sorted:
            _deny("TRANSITION_ARGUMENT_KEYS", "/arguments")
        return dict(self.arguments)


def _task_map(state: ReducerState) -> dict[str, TaskState]:
    return {task.task_id: task for task in state.tasks}


def _replace_sorted(mapping: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(mapping[key] for key in sorted(mapping))


def _subject(intent: TransitionIntent, tasks: dict[str, TaskState]) -> TaskState:
    task_id = _task_id(intent.task_id, "/task_id")
    attempt = _strict_int(intent.attempt, 1, "/attempt")
    task = tasks.get(task_id)
    if task is None:
        _deny("TRANSITION_TASK_ABSENT", "/task_id")
    if task.attempt != attempt:
        _deny("TRANSITION_ATTEMPT_MISMATCH", "/attempt")
    return task


def _expect_events(intent: TransitionIntent, count: int) -> tuple[str, ...]:
    if len(intent.semantic_event_ids) != count:
        _deny("TRANSITION_EVENT_COUNT", "/semantic_event_ids")
    if len(intent.semantic_event_ids) != len(set(intent.semantic_event_ids)):
        _deny("TRANSITION_EVENT_DUPLICATE", "/semantic_event_ids")
    return intent.semantic_event_ids


def _require_current(task: TaskState, state: ReducerState) -> None:
    if task.repository_generation != state.repository_generation:
        _deny("TRANSITION_STALE_TASK", "/repository_generation")


def _with_code(task: TaskState, code: str, **changes: Any) -> TaskState:
    workflow, execution, review = _TRIPLES[code]
    return replace(
        task, workflow=workflow, execution=execution, review=review, reviewer=None, **changes
    )


def _close_claim(
    claims: dict[str, ClaimRecord], task: TaskState, status: str, event_id: str
) -> None:
    claim_id = task.active_claim_id
    if claim_id is None or claim_id not in claims:
        _deny("TRANSITION_ACTIVE_CLAIM_MISSING", "/active_claim_id")
    claim = claims[claim_id]
    if claim.status != "OPEN" or (claim.task_id, claim.attempt) != (task.task_id, task.attempt):
        _deny("TRANSITION_ACTIVE_CLAIM_MISMATCH", "/active_claim_id")
    claims[claim_id] = replace(claim, status=status, closed_event_id=event_id)


def _close_review(
    reviews: dict[str, ReviewRecord], task: TaskState, status: str, event_id: str
) -> None:
    assignment_id = task.reviewer_assignment_id
    if assignment_id is None or assignment_id not in reviews:
        _deny("TRANSITION_ACTIVE_REVIEW_MISSING", "/reviewer_assignment_id")
    review = reviews[assignment_id]
    if review.status != "OPEN" or (review.task_id, review.attempt) != (task.task_id, task.attempt):
        _deny("TRANSITION_ACTIVE_REVIEW_MISMATCH", "/reviewer_assignment_id")
    reviews[assignment_id] = replace(review, status=status, closed_event_id=event_id)


def _worker_args(intent: TransitionIntent, evidence_key: str | None = None) -> dict[str, Any]:
    keys = ["claim_id", "fence"]
    if evidence_key is not None:
        keys.append(evidence_key)
    args = intent.args(tuple(keys))
    _uuid(args["claim_id"], "/arguments/claim_id")
    _strict_int(args["fence"], 0, "/arguments/fence")
    if evidence_key is not None:
        _digest(args[evidence_key], f"/arguments/{evidence_key}")
    return args


def _check_worker(task: TaskState, args: dict[str, Any]) -> None:
    if args["claim_id"] != task.active_claim_id:
        _deny("TRANSITION_CLAIM_CAS", "/arguments/claim_id")
    if args["fence"] != task.task_fence:
        _deny("TRANSITION_FENCE_CAS", "/arguments/fence")


_WORKSPACE_OPERATIONS = frozenset({
    "INITIALIZE", "CLAIM", "START", "CONTINUE", "YIELD", "FAIL",
    "COMPLETE", "RECOVER", "RETRY", "GOVERNANCE_BLOCK", "REVALIDATE",
})


@dataclass(frozen=True, slots=True)
class _TaskWrite:
    key: str
    before: TaskState | None
    after: TaskState


@dataclass(frozen=True, slots=True)
class _ClaimWrite:
    key: str
    before: ClaimRecord | None
    after: ClaimRecord


@dataclass(frozen=True, slots=True)
class _ReviewWrite:
    key: str
    before: ReviewRecord | None
    after: ReviewRecord


@dataclass(frozen=True, slots=True)
class _TransitionDelta:
    task_writes: tuple[_TaskWrite, ...]
    claim_writes: tuple[_ClaimWrite, ...]
    review_writes: tuple[_ReviewWrite, ...]
    after_task: TaskState


@dataclass(frozen=True, slots=True)
class _StagedTransition:
    _workspace_token: object
    base_revision: int
    delta: _TransitionDelta

    @property
    def after_task(self) -> TaskState:
        return self.delta.after_task


def _closed_claim(
    claims: Mapping[str, ClaimRecord], task: TaskState, status: str, event_id: str
) -> _ClaimWrite:
    claim_id = task.active_claim_id
    if claim_id is None or claim_id not in claims:
        _deny("TRANSITION_ACTIVE_CLAIM_MISSING", "/active_claim_id")
    claim = claims[claim_id]
    if claim.status != "OPEN" or (claim.task_id, claim.attempt) != (task.task_id, task.attempt):
        _deny("TRANSITION_ACTIVE_CLAIM_MISMATCH", "/active_claim_id")
    return _ClaimWrite(
        claim_id,
        claim,
        replace(claim, status=status, closed_event_id=event_id),
    )


def _closed_review_write(
    reviews: Mapping[str, ReviewRecord], task: TaskState, status: str, event_id: str
) -> _ReviewWrite:
    assignment_id = task.reviewer_assignment_id
    if assignment_id is None or assignment_id not in reviews:
        _deny("TRANSITION_ACTIVE_REVIEW_MISSING", "/reviewer_assignment_id")
    review = reviews[assignment_id]
    if review.status != "OPEN" or (review.task_id, review.attempt) != (
        task.task_id,
        task.attempt,
    ):
        _deny("TRANSITION_ACTIVE_REVIEW_MISMATCH", "/reviewer_assignment_id")
    return _ReviewWrite(
        assignment_id,
        review,
        replace(review, status=status, closed_event_id=event_id),
    )


def _plan_workspace_transition(
    repository_generation: int,
    tasks: Mapping[str, TaskState],
    claims: Mapping[str, ClaimRecord],
    reviews: Mapping[str, ReviewRecord],
    intent: TransitionIntent,
) -> _TransitionDelta:
    """Plan one currently compiled task/claim transition without mutation."""
    operation = intent.operation
    if operation not in _WORKSPACE_OPERATIONS:
        _deny("TRANSITION_OPERATION_OUTSIDE_WORKSPACE", "/operation")
    if operation == "INITIALIZE":
        _expect_events(intent, 1)
        task_id = _task_id(intent.task_id, "/task_id")
        if _strict_int(intent.attempt, 1, "/attempt") != 1:
            _deny("TRANSITION_INITIAL_ATTEMPT", "/attempt")
        if task_id in tasks:
            _deny("TRANSITION_TASK_EXISTS", "/task_id")
        args = intent.args(("decision_receipt_digest", "owner", "owner_role"))
        task = TaskState(
            task_id=task_id,
            attempt=1,
            workflow=_TRIPLES["N0"][0],
            execution=_TRIPLES["N0"][1],
            review=_TRIPLES["N0"][2],
            scheduler_generation=0,
            dispatch_generation=0,
            task_fence=0,
            active_claim_id=None,
            reviewer_assignment_id=None,
            continuation_count=0,
            repository_generation=repository_generation,
            decision_receipt_digest=_digest(
                args["decision_receipt_digest"], "/arguments/decision_receipt_digest"
            ),
            owner=_identity(args["owner"], "/arguments/owner"),
            owner_role=_identity(args["owner_role"], "/arguments/owner_role"),
        )
        return _TransitionDelta((_TaskWrite(task_id, None, task),), (), (), task)

    event_id = _expect_events(intent, 1)[0]
    task = _subject(intent, tasks)
    if (
        operation != "GOVERNANCE_BLOCK"
        and task.repository_generation != repository_generation
    ):
        _deny("TRANSITION_STALE_TASK", "/repository_generation")
    claim_writes: tuple[_ClaimWrite, ...] = ()
    review_writes: tuple[_ReviewWrite, ...] = ()

    if operation == "CLAIM":
        if task.code != "N0":
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = intent.args(("actor",))
        claim_id = _uuid(intent.generated_id, "/generated_id")
        if claim_id in claims:
            _deny("TRANSITION_CLAIM_EXISTS", "/generated_id")
        fence = _increment(task.task_fence, "/task_fence")
        after = _with_code(
            task,
            "N1",
            scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
            task_fence=fence,
            active_claim_id=claim_id,
        )
        claim = ClaimRecord(
            claim_id,
            task.task_id,
            task.attempt,
            fence,
            "OPEN",
            _identity(args["actor"], "/arguments/actor"),
            event_id,
        )
        claim_writes = (_ClaimWrite(claim_id, None, claim),)
    elif operation == "START":
        if task.code != "N1":
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = _worker_args(intent)
        _check_worker(task, args)
        after = _with_code(
            task,
            "N2",
            scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
        )
    elif operation == "CONTINUE":
        if task.code != "N2":
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = _worker_args(intent, "progress_evidence_sha256")
        _check_worker(task, args)
        after = _with_code(
            task,
            "N2",
            scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            continuation_count=_increment(task.continuation_count, "/continuation_count"),
        )
    elif operation in {"YIELD", "FAIL", "COMPLETE"}:
        allowed = {"YIELD": {"N1", "N2"}, "FAIL": {"N1", "N2"}, "COMPLETE": {"N2"}}
        if task.code not in allowed[operation]:
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        if operation == "YIELD":
            args = _worker_args(intent, "yield_evidence_sha256")
            target, claim_status = "N0", "YIELDED"
        elif operation == "FAIL":
            args = intent.args(("claim_id", "failure_code", "failure_evidence_sha256", "fence"))
            _uuid(args["claim_id"], "/arguments/claim_id")
            _strict_int(args["fence"], 0, "/arguments/fence")
            _text(args["failure_code"], _REASON, "/arguments/failure_code")
            _digest(args["failure_evidence_sha256"], "/arguments/failure_evidence_sha256")
            target, claim_status = "F0", "FAILED"
        else:
            args = intent.args(("claim_id", "close", "completion_evidence_sha256", "fence"))
            _uuid(args["claim_id"], "/arguments/claim_id")
            _strict_int(args["fence"], 0, "/arguments/fence")
            if type(args["close"]) is not bool:
                _deny("TRANSITION_CLOSE_TYPE", "/arguments/close")
            _digest(args["completion_evidence_sha256"], "/arguments/completion_evidence_sha256")
            target, claim_status = ("C0" if args["close"] else "N3"), "COMPLETED"
        _check_worker(task, args)
        claim_writes = (_closed_claim(claims, task, claim_status, event_id),)
        after = _with_code(
            task,
            target,
            scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
            task_fence=_increment(task.task_fence, "/task_fence"),
            active_claim_id=None,
        )
    elif operation == "RECOVER":
        if task.code != "N1":
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = intent.args(("claim_id", "liveness_evidence_sha256"))
        _uuid(args["claim_id"], "/arguments/claim_id")
        _digest(args["liveness_evidence_sha256"], "/arguments/liveness_evidence_sha256")
        if args["claim_id"] != task.active_claim_id:
            _deny("TRANSITION_CLAIM_CAS", "/arguments/claim_id")
        claim_writes = (_closed_claim(claims, task, "RECOVERED", event_id),)
        after = _with_code(
            task,
            "N0",
            scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
            task_fence=_increment(task.task_fence, "/task_fence"),
            active_claim_id=None,
        )
    elif operation == "RETRY":
        if task.code != "F0":
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = intent.args(("retry_evidence_sha256", "retryable"))
        if args["retryable"] is not True:
            _deny("TRANSITION_RETRYABLE", "/arguments/retryable")
        _digest(args["retry_evidence_sha256"], "/arguments/retry_evidence_sha256")
        after = _with_code(
            task,
            "N0",
            attempt=_increment(task.attempt, "/attempt"),
            scheduler_generation=_increment(
                task.scheduler_generation, "/scheduler_generation"
            ),
            dispatch_generation=_increment(
                task.dispatch_generation, "/dispatch_generation"
            ),
            task_fence=_increment(task.task_fence, "/task_fence"),
            continuation_count=0,
            active_claim_id=None,
            reviewer_assignment_id=None,
        )
    elif operation == "GOVERNANCE_BLOCK":
        if task.code not in {"N0", "N1", "N2", "N3", "N4"}:
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = intent.args(("evidence_sha256", "reason_code"))
        _digest(args["evidence_sha256"], "/arguments/evidence_sha256")
        _text(args["reason_code"], _REASON, "/arguments/reason_code")
        target = "B0" if task.code in {"N0", "N1", "N2"} else "B1"
        if task.code in {"N1", "N2"}:
            claim_writes = (
                _closed_claim(
                    claims, task, "GOVERNANCE_INVALIDATED", event_id
                ),
            )
        if task.code == "N4":
            review_writes = (
                _closed_review_write(
                    reviews, task, "GOVERNANCE_REVOKED", event_id
                ),
            )
        after = _with_code(
            task,
            target,
            scheduler_generation=_increment(
                task.scheduler_generation, "/scheduler_generation"
            ),
            dispatch_generation=_increment(
                task.dispatch_generation, "/dispatch_generation"
            ),
            task_fence=_increment(task.task_fence, "/task_fence"),
            active_claim_id=None,
            reviewer_assignment_id=None,
            repository_generation=repository_generation,
        )
    else:
        if task.code not in {"B0", "B1"}:
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        args = intent.args(("evidence_sha256",))
        evidence = _digest(
            args["evidence_sha256"], "/arguments/evidence_sha256"
        )
        after = _with_code(
            task,
            "N0" if task.code == "B0" else "N3",
            scheduler_generation=_increment(
                task.scheduler_generation, "/scheduler_generation"
            ),
            repository_generation=repository_generation,
            decision_receipt_digest=evidence,
            active_claim_id=None,
            reviewer_assignment_id=None,
        )
    return _TransitionDelta(
        (_TaskWrite(task.task_id, task, after),),
        claim_writes,
        review_writes,
        after,
    )


def _retained_claim_event_ids(claim: ClaimRecord) -> tuple[str, ...]:
    if claim.closed_event_id is None:
        return (claim.opened_event_id,)
    return (claim.opened_event_id, claim.closed_event_id)


def _new_claim_event_ids(
    before: ClaimRecord | None, after: ClaimRecord
) -> tuple[str, ...]:
    if before is None:
        return _retained_claim_event_ids(after)
    if before.opened_event_id != after.opened_event_id:
        _deny("TRANSITION_WORKSPACE_PLAN", "/claims/opened_event_id")
    if before.closed_event_id is None and after.closed_event_id is not None:
        return (after.closed_event_id,)
    if before.closed_event_id != after.closed_event_id:
        _deny("TRANSITION_WORKSPACE_PLAN", "/claims/closed_event_id")
    return ()


def _new_review_event_ids(
    before: ReviewRecord | None, after: ReviewRecord
) -> tuple[str, ...]:
    if before is None:
        if after.closed_event_id is None:
            return (after.opened_event_id,)
        return (after.opened_event_id, after.closed_event_id)
    if before.opened_event_id != after.opened_event_id:
        _deny("TRANSITION_WORKSPACE_PLAN", "/reviews/opened_event_id")
    if before.closed_event_id is None and after.closed_event_id is not None:
        return (after.closed_event_id,)
    if before.closed_event_id != after.closed_event_id:
        _deny("TRANSITION_WORKSPACE_PLAN", "/reviews/closed_event_id")
    return ()


class _TransitionWorkspace:
    """Private two-phase task/claim/review workspace; freeze revalidates all."""

    __slots__ = (
        "_claims", "_decisions", "_links", "_repository_bundle_sha256",
        "_repository_generation", "_retained_event_ids", "_reviews", "_revision",
        "_tasks", "_token", "_issued",
    )

    def __init__(self, state: ReducerState) -> None:
        if type(state) is not ReducerState:
            _deny("TRANSITION_HOST_TYPE", "/")
        self._repository_generation = state.repository_generation
        self._repository_bundle_sha256 = state.repository_bundle_sha256
        self._tasks = {task.task_id: task for task in state.tasks}
        self._claims = {claim.claim_id: claim for claim in state.claims}
        self._reviews = {review.assignment_id: review for review in state.reviews}
        self._decisions = {(item.task_id, item.attempt): item for item in state.decisions}
        self._links = {link.link_id: link for link in state.remediation_links}
        retained: set[str] = set()
        for claim in state.claims:
            retained.update(_retained_claim_event_ids(claim))
        for review in state.reviews:
            retained.add(review.opened_event_id)
            if review.closed_event_id is not None:
                retained.add(review.closed_event_id)
        for link in state.remediation_links:
            retained.update((link.source_event_id, link.child_event_id))
        self._retained_event_ids = retained
        self._revision = 0
        self._token = object()
        self._issued: dict[int, _StagedTransition] = {}

    def __copy__(self) -> None:
        _deny("TRANSITION_WORKSPACE_COPY", "/")

    def __deepcopy__(self, memo: Any) -> None:
        _deny("TRANSITION_WORKSPACE_COPY", "/")

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def repository_generation(self) -> int:
        return self._repository_generation

    @property
    def repository_bundle_sha256(self) -> str:
        return self._repository_bundle_sha256

    def only_task(self) -> TaskState | None:
        if len(self._tasks) != 1:
            return None
        return next(iter(self._tasks.values()))

    def task(self, task_id: str) -> TaskState | None:
        return self._tasks.get(task_id)

    def stage(self, intent: TransitionIntent) -> _StagedTransition:
        if type(intent) is not TransitionIntent:
            _deny("TRANSITION_HOST_TYPE", "/")
        _validate_intent_shape(intent)
        delta = _plan_workspace_transition(
            self._repository_generation,
            self._tasks,
            self._claims,
            self._reviews,
            intent,
        )
        self._precheck(delta)
        staged = _StagedTransition(self._token, self._revision, delta)
        self._issued[id(staged)] = staged
        return staged

    def _precheck(self, delta: _TransitionDelta) -> None:
        if type(delta) is not _TransitionDelta:
            _deny("TRANSITION_WORKSPACE_PLAN", "/")
        task_keys = tuple(write.key for write in delta.task_writes)
        claim_keys = tuple(write.key for write in delta.claim_writes)
        review_keys = tuple(write.key for write in delta.review_writes)
        if (
            not task_keys
            or task_keys != tuple(sorted(task_keys))
            or len(task_keys) != len(set(task_keys))
            or claim_keys != tuple(sorted(claim_keys))
            or len(claim_keys) != len(set(claim_keys))
            or review_keys != tuple(sorted(review_keys))
            or len(review_keys) != len(set(review_keys))
        ):
            _deny("TRANSITION_WORKSPACE_PLAN", "/")
        added_tasks = 0
        for write in delta.task_writes:
            if type(write) is not _TaskWrite or write.key != write.after.task_id:
                _deny("TRANSITION_WORKSPACE_PLAN", "/tasks")
            current = self._tasks.get(write.key)
            if current != write.before:
                _deny("TRANSITION_WORKSPACE_CAS", f"/tasks/{write.key}")
            added_tasks += int(current is None)
        added_claims = 0
        added_events: list[str] = []
        for write in delta.claim_writes:
            if type(write) is not _ClaimWrite or write.key != write.after.claim_id:
                _deny("TRANSITION_WORKSPACE_PLAN", "/claims")
            current = self._claims.get(write.key)
            if current != write.before:
                _deny("TRANSITION_WORKSPACE_CAS", f"/claims/{write.key}")
            added_claims += int(current is None)
            added_events.extend(_new_claim_event_ids(current, write.after))
        added_reviews = 0
        for write in delta.review_writes:
            if type(write) is not _ReviewWrite or write.key != write.after.assignment_id:
                _deny("TRANSITION_WORKSPACE_PLAN", "/reviews")
            current = self._reviews.get(write.key)
            if current != write.before:
                _deny("TRANSITION_WORKSPACE_CAS", f"/reviews/{write.key}")
            added_reviews += int(current is None)
            added_events.extend(_new_review_event_ids(current, write.after))
        if len(self._tasks) + added_tasks > MAX_TASKS:
            _deny("TRANSITION_RESOURCE_TASKS", "/tasks")
        if len(self._claims) + added_claims > MAX_EVENTS:
            _deny("TRANSITION_RESOURCE_RECORDS", "/claims")
        if len(self._reviews) + added_reviews > MAX_EVENTS:
            _deny("TRANSITION_RESOURCE_RECORDS", "/reviews")
        if len(added_events) != len(set(added_events)) or any(
            event_id in self._retained_event_ids for event_id in added_events
        ):
            _deny("TRANSITION_STATE_EVENT_REUSED", "/")
        if delta.after_task not in tuple(write.after for write in delta.task_writes):
            _deny("TRANSITION_WORKSPACE_PLAN", "/after_task")

    def commit(self, staged: _StagedTransition) -> None:
        if type(staged) is not _StagedTransition:
            _deny("TRANSITION_WORKSPACE_PLAN", "/")
        if staged._workspace_token is not self._token:
            _deny("TRANSITION_WORKSPACE_FOREIGN", "/")
        if staged.base_revision != self._revision:
            _deny("TRANSITION_WORKSPACE_STALE", "/")
        if self._issued.get(id(staged)) is not staged:
            _deny("TRANSITION_WORKSPACE_FORGED", "/")
        self._precheck(staged.delta)
        added_events: list[str] = []
        for write in staged.delta.claim_writes:
            added_events.extend(_new_claim_event_ids(write.before, write.after))
        for write in staged.delta.review_writes:
            added_events.extend(_new_review_event_ids(write.before, write.after))
        for write in staged.delta.task_writes:
            self._tasks[write.key] = write.after
        for write in staged.delta.claim_writes:
            self._claims[write.key] = write.after
        for write in staged.delta.review_writes:
            self._reviews[write.key] = write.after
        self._retained_event_ids.update(added_events)
        self._revision += 1
        self._issued.clear()

    def freeze(self) -> ReducerState:
        return ReducerState(
            repository_generation=self._repository_generation,
            repository_bundle_sha256=self._repository_bundle_sha256,
            tasks=_replace_sorted(self._tasks),
            claims=_replace_sorted(self._claims),
            reviews=_replace_sorted(self._reviews),
            decisions=tuple(self._decisions[key] for key in sorted(self._decisions)),
            remediation_links=_replace_sorted(self._links),
        )


def _validate_intent_shape(intent: TransitionIntent) -> None:
    ordinary = {
        "INITIALIZE", "CLAIM", "START", "CONTINUE", "YIELD", "FAIL",
        "COMPLETE", "RECOVER", "RETRY", "GOVERNANCE_BLOCK", "REVALIDATE",
        "ASSIGN_REVIEW", "APPROVE", "REJECT", "REMEDIATE", "ROUTE",
    }
    if intent.operation in ordinary:
        if intent.task_id is None or intent.attempt is None:
            _deny("TRANSITION_INTENT_SUBJECT", "/task_id")
        if intent.child_task_id is not None or intent.child_attempt is not None:
            _deny("TRANSITION_INTENT_EXTRA", "/child_task_id")
        if (
            intent.candidate_repository_generation is not None
            or intent.candidate_repository_bundle_sha256 is not None
        ):
            _deny("TRANSITION_INTENT_EXTRA", "/candidate_repository_generation")
        requires_generated = intent.operation in {"CLAIM", "ASSIGN_REVIEW"}
        if requires_generated != (intent.generated_id is not None):
            _deny("TRANSITION_INTENT_GENERATED", "/generated_id")
    elif intent.operation == "CREATE_REMEDIATION_TASK":
        if (
            intent.task_id is None
            or intent.attempt is None
            or intent.child_task_id is None
            or intent.child_attempt is None
        ):
            _deny("TRANSITION_INTENT_SUBJECT", "/")
        if (
            intent.generated_id is not None
            or intent.candidate_repository_generation is not None
            or intent.candidate_repository_bundle_sha256 is not None
        ):
            _deny("TRANSITION_INTENT_EXTRA", "/")
    elif intent.operation == "IMPORT_REPOSITORY":
        if any(
            value is not None
            for value in (
                intent.task_id, intent.attempt, intent.child_task_id,
                intent.child_attempt, intent.generated_id,
            )
        ):
            _deny("TRANSITION_INTENT_EXTRA", "/task_id")
        if (
            intent.candidate_repository_generation is None
            or intent.candidate_repository_bundle_sha256 is None
        ):
            _deny("TRANSITION_INTENT_REPOSITORY", "/candidate_repository_generation")


def reduce_transition(state: ReducerState, intent: TransitionIntent) -> ReducerState:
    """Apply one already-decoded task transaction atomically.

    This function is not a runtime-image verifier.  It raises a stable
    ``TransitionViolation`` and leaves ``state`` untouched on any rejection.
    """
    if type(state) is not ReducerState or type(intent) is not TransitionIntent:
        _deny("TRANSITION_HOST_TYPE", "/")
    _validate_intent_shape(intent)
    tasks = _task_map(state)
    claims = {claim.claim_id: claim for claim in state.claims}
    reviews = {review.assignment_id: review for review in state.reviews}
    decisions = {(item.task_id, item.attempt): item for item in state.decisions}
    links = {link.link_id: link for link in state.remediation_links}
    operation = intent.operation

    if operation in _WORKSPACE_OPERATIONS:
        delta = _plan_workspace_transition(
            state.repository_generation, tasks, claims, reviews, intent
        )
        for write in delta.task_writes:
            tasks[write.key] = write.after
        for write in delta.claim_writes:
            claims[write.key] = write.after
        for write in delta.review_writes:
            reviews[write.key] = write.after
    elif operation == "CREATE_REMEDIATION_TASK":
        event_ids = _expect_events(intent, 2)
        source = _subject(intent, tasks)
        _require_current(source, state)
        if source.code not in {"N5", "N6"}:
            _deny("TRANSITION_SOURCE_STATE", "/task_id")
        child_id = _task_id(intent.child_task_id, "/child_task_id")
        if _strict_int(intent.child_attempt, 1, "/child_attempt") != 1:
            _deny("TRANSITION_CHILD_ATTEMPT", "/child_attempt")
        if child_id == source.task_id or child_id in tasks:
            _deny("TRANSITION_CHILD_ID", "/child_task_id")
        if source.successor_task is not None:
            _deny("TRANSITION_SUCCESSOR_EXISTS", "/task_id")
        args = intent.args((
            "child_decision_receipt_digest", "child_owner", "child_owner_role",
            "decision_sha256", "relationship_id",
        ))
        link_id = _uuid(args["relationship_id"], "/arguments/relationship_id")
        if link_id in links:
            _deny("TRANSITION_LINK_EXISTS", "/arguments/relationship_id")
        decision_sha256 = _digest(args["decision_sha256"], "/arguments/decision_sha256")
        decision = decisions.get((source.task_id, source.attempt))
        if decision is None or decision.operation not in {"REJECT", "REMEDIATE"}:
            _deny("TRANSITION_DECISION_MISSING", "/arguments/decision_sha256")
        if decision.decision_sha256 != decision_sha256:
            _deny("TRANSITION_DECISION_MISMATCH", "/arguments/decision_sha256")
        tasks[source.task_id] = _with_code(
            source, source.code,
            scheduler_generation=_increment(source.scheduler_generation, "/scheduler_generation"),
            successor_task=child_id,
        )
        child = TaskState(
            task_id=child_id, attempt=1,
            workflow=_TRIPLES["N0"][0], execution=_TRIPLES["N0"][1], review=_TRIPLES["N0"][2],
            scheduler_generation=0, dispatch_generation=0, task_fence=0,
            active_claim_id=None, reviewer_assignment_id=None, continuation_count=0,
            repository_generation=state.repository_generation,
            decision_receipt_digest=_digest(
                args["child_decision_receipt_digest"],
                "/arguments/child_decision_receipt_digest",
            ),
            owner=_identity(args["child_owner"], "/arguments/child_owner"),
            owner_role=_identity(args["child_owner_role"], "/arguments/child_owner_role"),
            predecessor_task=source.task_id,
        )
        tasks[child_id] = child
        preimage = {
            "link_id": link_id,
            "source_task_id": source.task_id,
            "source_attempt": source.attempt,
            "child_task_id": child_id,
            "child_attempt": 1,
            "source_event_id": event_ids[0],
            "child_event_id": event_ids[1],
            "decision_sha256": decision_sha256,
            "link_sha256": "0" * 64,
        }
        digest = remediation_link_digest(preimage)
        links[link_id] = RemediationLinkRecord(
            link_id, source.task_id, source.attempt, child_id, 1,
            event_ids[0], event_ids[1], decision_sha256, digest,
        )
    elif operation == "IMPORT_REPOSITORY":
        args = intent.args((
            "affected_task_ids", "policy_capability_sha256", "project_state_sha256",
            "reason_code", "source_commit", "stop_set_sha256", "task_inventory_sha256",
        ))
        affected = args["affected_task_ids"]
        if type(affected) is not tuple or len(affected) > 10_000:
            _deny("TRANSITION_IMPORT_AFFECTED_TYPE", "/arguments/affected_task_ids")
        for index, task_id in enumerate(affected):
            _task_id(task_id, f"/arguments/affected_task_ids/{index}")
        if affected != tuple(sorted(affected)) or len(affected) != len(set(affected)):
            _deny("TRANSITION_IMPORT_AFFECTED_ORDER", "/arguments/affected_task_ids")
        _expect_events(intent, len(affected) + 1)
        next_generation = _increment(state.repository_generation, "/repository_generation")
        candidate_generation = _strict_int(
            intent.candidate_repository_generation, 1, "/candidate_repository_generation"
        )
        if candidate_generation != next_generation:
            _deny("TRANSITION_IMPORT_GENERATION", "/candidate_repository_generation")
        next_bundle = _digest(
            intent.candidate_repository_bundle_sha256,
            "/candidate_repository_bundle_sha256",
        )
        _text(args["reason_code"], _REASON, "/arguments/reason_code")
        if type(args["source_commit"]) is not str or re.fullmatch(r"[0-9a-f]{40}", args["source_commit"]) is None:
            _deny("TRANSITION_SOURCE_COMMIT", "/arguments/source_commit")
        for key in (
            "policy_capability_sha256", "project_state_sha256", "stop_set_sha256",
            "task_inventory_sha256",
        ):
            _digest(args[key], f"/arguments/{key}")
        mandatory = {
            task.task_id for task in tasks.values()
            if task.code in {"F0", "N5", "N6", "N7", "N8", "B0", "B1"}
        }
        if not mandatory.issubset(set(affected)):
            _deny("TRANSITION_IMPORT_MANDATORY_MISSING", "/arguments/affected_task_ids")
        for index, task_id in enumerate(affected):
            task = tasks.get(task_id)
            if task is None:
                _deny("TRANSITION_IMPORT_TASK_ABSENT", f"/arguments/affected_task_ids/{index}")
            if task.code == "C0":
                _deny("TRANSITION_IMPORT_CLOSED_TASK", f"/arguments/affected_task_ids/{index}")
            event_id = intent.semantic_event_ids[index]
            changes: dict[str, Any] = {
                "scheduler_generation": _increment(task.scheduler_generation, "/scheduler_generation"),
                "repository_generation": next_generation,
            }
            target = task.code
            if task.code in {"N1", "N2"}:
                _close_claim(claims, task, "GOVERNANCE_INVALIDATED", event_id)
                target = "B0"
                changes.update(
                    dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
                    task_fence=_increment(task.task_fence, "/task_fence"),
                    active_claim_id=None,
                )
            elif task.code in {"N3", "N4"}:
                target = "B1"
                changes.update(
                    dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
                    task_fence=_increment(task.task_fence, "/task_fence"),
                    reviewer_assignment_id=None,
                )
                if task.code == "N4":
                    _close_review(reviews, task, "GOVERNANCE_REVOKED", event_id)
            tasks[task_id] = _with_code(task, target, **changes)
        state = replace(
            state,
            repository_generation=next_generation,
            repository_bundle_sha256=next_bundle,
        )
    else:
        event_id = _expect_events(intent, 1)[0]
        task = _subject(intent, tasks)
        _require_current(task, state)

        if operation == "CLAIM":
            if task.code != "N0":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = intent.args(("actor",))
            claim_id = _uuid(intent.generated_id, "/generated_id")
            if claim_id in claims:
                _deny("TRANSITION_CLAIM_EXISTS", "/generated_id")
            fence = _increment(task.task_fence, "/task_fence")
            tasks[task.task_id] = _with_code(
                task, "N1",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
                task_fence=fence, active_claim_id=claim_id,
            )
            claims[claim_id] = ClaimRecord(
                claim_id, task.task_id, task.attempt, fence, "OPEN",
                _identity(args["actor"], "/arguments/actor"), event_id,
            )
        elif operation == "START":
            if task.code != "N1":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = _worker_args(intent)
            _check_worker(task, args)
            tasks[task.task_id] = _with_code(
                task, "N2",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            )
        elif operation == "CONTINUE":
            if task.code != "N2":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = _worker_args(intent, "progress_evidence_sha256")
            _check_worker(task, args)
            tasks[task.task_id] = _with_code(
                task, "N2",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                continuation_count=_increment(task.continuation_count, "/continuation_count"),
            )
        elif operation in {"YIELD", "FAIL", "COMPLETE"}:
            allowed = {"YIELD": {"N1", "N2"}, "FAIL": {"N1", "N2"}, "COMPLETE": {"N2"}}
            if task.code not in allowed[operation]:
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            if operation == "YIELD":
                args = _worker_args(intent, "yield_evidence_sha256")
                target, claim_status = "N0", "YIELDED"
            elif operation == "FAIL":
                args = intent.args(("claim_id", "failure_code", "failure_evidence_sha256", "fence"))
                _uuid(args["claim_id"], "/arguments/claim_id")
                _strict_int(args["fence"], 0, "/arguments/fence")
                _text(args["failure_code"], _REASON, "/arguments/failure_code")
                _digest(args["failure_evidence_sha256"], "/arguments/failure_evidence_sha256")
                target, claim_status = "F0", "FAILED"
            else:
                args = intent.args(("claim_id", "close", "completion_evidence_sha256", "fence"))
                _uuid(args["claim_id"], "/arguments/claim_id")
                _strict_int(args["fence"], 0, "/arguments/fence")
                if type(args["close"]) is not bool:
                    _deny("TRANSITION_CLOSE_TYPE", "/arguments/close")
                _digest(args["completion_evidence_sha256"], "/arguments/completion_evidence_sha256")
                target, claim_status = ("C0" if args["close"] else "N3"), "COMPLETED"
            _check_worker(task, args)
            _close_claim(claims, task, claim_status, event_id)
            tasks[task.task_id] = _with_code(
                task, target,
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
                task_fence=_increment(task.task_fence, "/task_fence"),
                active_claim_id=None,
            )
        elif operation == "RECOVER":
            if task.code != "N1":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = intent.args(("claim_id", "liveness_evidence_sha256"))
            _uuid(args["claim_id"], "/arguments/claim_id")
            _digest(args["liveness_evidence_sha256"], "/arguments/liveness_evidence_sha256")
            if args["claim_id"] != task.active_claim_id:
                _deny("TRANSITION_CLAIM_CAS", "/arguments/claim_id")
            _close_claim(claims, task, "RECOVERED", event_id)
            tasks[task.task_id] = _with_code(
                task, "N0",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                dispatch_generation=_increment(task.dispatch_generation, "/dispatch_generation"),
                task_fence=_increment(task.task_fence, "/task_fence"), active_claim_id=None,
            )
        elif operation == "ASSIGN_REVIEW":
            if task.code != "N3":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = intent.args(("actor", "role"))
            actor = _identity(args["actor"], "/arguments/actor")
            role = _identity(args["role"], "/arguments/role")
            if actor == task.owner:
                _deny("TRANSITION_REVIEW_ACTOR_NOT_INDEPENDENT", "/arguments/actor")
            if role == task.owner_role:
                _deny("TRANSITION_REVIEW_ROLE_NOT_INDEPENDENT", "/arguments/role")
            assignment_id = _uuid(intent.generated_id, "/generated_id")
            if assignment_id in reviews:
                _deny("TRANSITION_REVIEW_EXISTS", "/generated_id")
            tasks[task.task_id] = _with_code(
                task, "N4",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                reviewer_assignment_id=assignment_id,
            )
            reviews[assignment_id] = ReviewRecord(
                assignment_id, task.task_id, task.attempt, actor, role, "OPEN", event_id
            )
        elif operation in {"APPROVE", "REJECT", "REMEDIATE"}:
            if task.code != "N4":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = intent.args(("assignment_id", "decision_sha256"))
            assignment_id = _uuid(args["assignment_id"], "/arguments/assignment_id")
            decision_sha256 = _digest(args["decision_sha256"], "/arguments/decision_sha256")
            if assignment_id != task.reviewer_assignment_id:
                _deny("TRANSITION_REVIEW_CAS", "/arguments/assignment_id")
            target = {"APPROVE": "N7", "REJECT": "N5", "REMEDIATE": "N6"}[operation]
            status = {
                "APPROVE": "APPROVED", "REJECT": "REJECTED",
                "REMEDIATE": "REMEDIATION_REQUIRED",
            }[operation]
            _close_review(reviews, task, status, event_id)
            tasks[task.task_id] = _with_code(
                task, target,
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
                reviewer_assignment_id=None,
            )
            decisions[(task.task_id, task.attempt)] = ReviewDecision(
                task.task_id, task.attempt, operation, decision_sha256, event_id
            )
        elif operation == "ROUTE":
            if task.code != "N7":
                _deny("TRANSITION_SOURCE_STATE", "/task_id")
            args = intent.args(("routing_evidence_sha256",))
            _digest(args["routing_evidence_sha256"], "/arguments/routing_evidence_sha256")
            tasks[task.task_id] = _with_code(
                task, "N8",
                scheduler_generation=_increment(task.scheduler_generation, "/scheduler_generation"),
            )
        else:
            _deny("TRANSITION_OPERATION_OUTSIDE_CORE", "/operation")

    return ReducerState(
        repository_generation=state.repository_generation,
        repository_bundle_sha256=state.repository_bundle_sha256,
        tasks=_replace_sorted(tasks),
        claims=_replace_sorted(claims),
        reviews=_replace_sorted(reviews),
        decisions=tuple(decisions[key] for key in sorted(decisions)),
        remediation_links=_replace_sorted(links),
    )


__all__ = [
    "INT64_MAX", "ClaimRecord", "ReducerState", "RemediationLinkRecord",
    "ReviewDecision", "ReviewRecord", "TaskState", "TransitionIntent",
    "TransitionViolation", "reduce_transition",
]
