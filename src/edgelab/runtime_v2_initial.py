"""Private pure reducer for a runtime-format-2 NEW initial image.

This module is deliberately disconnected from the public verifier.  It
validates the presently compiled NEW-genesis inputs and derives selectors and
all fifteen supplied tables for comparison.  It validates the closure's
compiled shape and self-digest, but cannot establish exact generated closure
identity until semantic sources are frozen and the release is compiled.  It
therefore never exposes derived identity from an unsupported candidate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable

from .runtime_v2_bootstrap import (
    BootstrapValidationError,
    SUPPORTED_SCHEMA_REGISTRY_SHA256,
    SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
    validate_attachment,
    validate_manifest,
    validate_selector,
    validate_supported_schema_registry,
    validate_supported_storage_descriptor,
)
from .runtime_v2_codec import (
    CanonicalJsonError,
    attachment_digest,
    blob_digest,
    canonical_json,
    event_digest,
    manifest_digest,
    parse_canonical_json,
    schema_document_digest,
    selector_digest,
    selector_history_digest,
    table_root,
)
from .runtime_v2_closure import (
    ClosureValidationError,
    validate_verifier_dependency_closure,
)
from .runtime_v2_genesis import (
    GenesisValidationError,
    PAYLOAD_SCHEMA_ID,
    REQUEST_SCHEMA_ID,
    RESPONSE_SCHEMA_ID,
    validate_new_genesis_request,
    validate_new_genesis_response,
    validate_runtime_genesis_envelope,
    validate_runtime_genesis_payload,
)
from .runtime_v2_image import (
    MAX_EVENTS,
    MAX_TOTAL_ROOT_WORK_BYTES,
    RuntimeImage,
    TableSnapshot,
    inspect_runtime_image_host,
)
from .runtime_v2_group import (
    BlobValue,
    ClaimGroupPatch,
    GroupValidationError,
    ImportGroupPatch,
    InitializeGroupPatch,
    RemediationGroupPatch,
    SnapshotGroupPatch,
    _FOLLOWUP_PROFILES,
    _ReplayCursor,
    WorkerGroupPatch,
    reduce_claim_group,
    reduce_initialize_group,
    reduce_import_group,
    reduce_remediation_group,
    reduce_snapshot_group,
    reduce_worker_group,
)
from .runtime_v2_transition import (
    ReducerState,
    TransitionViolation,
    _TransitionWorkspace,
)


MAX_FINDINGS = 128
SCHEMA_DOCUMENT_PINS = (
    (
        "urn:edgelab:m0-3a-command-request:2",
        "8c7b7cf050700f696e44d89899365bdc80620dd1071dad7aa08707c91f88388e",
    ),
    (
        "urn:edgelab:m0-3a-event-envelope:2",
        "ae3655e0b94610e54ad00b514de1eeb78e9abd54f5828fd93387583b76f2b553",
    ),
    (
        "urn:edgelab:m0-3a-event-payload:2",
        "1b26427cde4998e23ec503df3a46b527893a2f40c27e7d0efdadf5474e8e30e4",
    ),
    (
        "urn:edgelab:m0-3a-legacy-v1-projection:1",
        "15689e50b3abe3895c546ddc606fe9b754ab993804b13aedd85e8e789374ba53",
    ),
    (
        "urn:edgelab:m0-3a-legacy-v1-row-archive:1",
        "fcd734fdda399047738bb139ed3971e5906eaaa7063435f4902a259d2a9d3a9c",
    ),
    (
        "urn:edgelab:m0-3a-response-projection:2",
        "9a01e5c47f628c4a80082f6ac1276ecae345c47c42923789d0743d4fd41f0a61",
    ),
    (
        "urn:edgelab:m0-3a-runtime-checkpoint:2",
        "2c9fc0fed41a49342ec91a8b5d17dd3f3e23e7612a07257af5f1d6acd6d4c05a",
    ),
    (
        "urn:edgelab:m0-3a-runtime-export:2",
        "c9b345e83d99173f41c52fd818471b428ff0a7503ce9340e76531d7cb58b079a",
    ),
    (
        "urn:edgelab:m0-3a-task-state:2",
        "c8b9a47df5b91ae467f3008c8c7c27bdf2df089a3fbc25d684f53e56bc37ede8",
    ),
)
_KNOWN_BLOB_ROLES = frozenset(schema_id for schema_id, _ in SCHEMA_DOCUMENT_PINS)


@dataclass(frozen=True, order=True, slots=True)
class InitialViolation:
    code: str
    artifact: str
    coordinate: str


@dataclass(frozen=True, slots=True)
class InitialReductionReport:
    """A closed deny-only result from private NEW-image reduction."""

    status: str
    violations: tuple[InitialViolation, ...]
    authorizing_use: str = field(default="DENY", init=False)

    def __post_init__(self) -> None:
        if self.status not in {"INVALID", "UNSUPPORTED"}:
            raise ValueError("unsupported initial reduction status")
        if not self.violations or tuple(sorted(set(self.violations))) != self.violations:
            raise ValueError("violations must be nonempty, unique, and sorted")

    def __bool__(self) -> bool:
        raise TypeError("initial reduction reports are not authorization booleans")


class _Sink:
    __slots__ = ("_items", "_truncated")

    def __init__(self) -> None:
        self._items: set[InitialViolation] = set()
        self._truncated = False

    def add(self, code: str, artifact: str, coordinate: str) -> None:
        def bounded(value: str, maximum: int) -> str:
            if len(value) <= maximum:
                return value
            suffix = f"#sha256={sha256(value.encode('utf-8')).hexdigest()}"
            return value[:maximum - len(suffix)] + suffix

        finding = InitialViolation(
            bounded(code, 128),
            bounded(artifact, 256),
            bounded(coordinate, 512),
        )
        if finding in self._items:
            return
        if len(self._items) >= MAX_FINDINGS - 1:
            self._truncated = True
            return
        self._items.add(finding)

    def result(self) -> tuple[InitialViolation, ...]:
        items = set(self._items)
        if self._truncated:
            items.add(InitialViolation("FINDINGS_TRUNCATED", "reducer", "/findings"))
        return tuple(sorted(items))


def _invalid(sink: _Sink) -> InitialReductionReport:
    findings = sink.result()
    if not findings:
        findings = (InitialViolation("INVALID", "reducer", "/"),)
    return InitialReductionReport("INVALID", findings)


def _parse(raw: bytes, artifact: str, sink: _Sink) -> Any | None:
    try:
        return parse_canonical_json(raw)
    except CanonicalJsonError:
        sink.add("CANONICAL_JSON", artifact, "/")
        return None


def _validate(
    value: Any,
    artifact: str,
    validator: Callable[[Any], None],
    sink: _Sink,
) -> None:
    try:
        validator(value)
    except (BootstrapValidationError, GenesisValidationError) as error:
        sink.add(error.code, artifact, error.coordinate)


def _bind(actual: Any, expected: Any, artifact: str, coordinate: str, sink: _Sink) -> None:
    if type(actual) is not type(expected) or actual != expected:
        sink.add("BINDING_MISMATCH", artifact, coordinate)


def _digest_match(actual: Any, expected: str, artifact: str, coordinate: str, sink: _Sink) -> None:
    if type(actual) is not str or actual != expected:
        sink.add("DIGEST_MISMATCH", artifact, coordinate)


def _schema_bundle(image: RuntimeImage, registry: Any, sink: _Sink) -> None:
    observed = tuple(
        (record.schema_id, record.document_sha256)
        for record in image.schema_documents
    )
    if observed != SCHEMA_DOCUMENT_PINS:
        sink.add("SCHEMA_DOCUMENT_INVENTORY", "schema_documents", "/")
    documents = registry.get("documents") if type(registry) is dict else None
    registry_inventory = (
        tuple(
            (item.get("schema_id"), item.get("document_sha256"))
            if type(item) is dict else (None, None)
            for item in documents
        )
        if type(documents) is list else None
    )
    if registry_inventory != SCHEMA_DOCUMENT_PINS:
        sink.add("SCHEMA_REGISTRY_DOCUMENTS", "schema_registry", "/documents")
    for index, record in enumerate(image.schema_documents):
        document = _parse(record.canonical_json, record.schema_id, sink)
        if document is None:
            continue
        try:
            observed_digest = schema_document_digest(document)
        except CanonicalJsonError:
            sink.add("SCHEMA_DOCUMENT_VALUE", record.schema_id, "/")
            continue
        expected_id, expected_digest = SCHEMA_DOCUMENT_PINS[index]
        if record.schema_id != expected_id:
            sink.add("SCHEMA_DOCUMENT_ID", "schema_documents", f"/{index}/schema_id")
        if record.document_sha256 != expected_digest or observed_digest != expected_digest:
            sink.add("SCHEMA_DOCUMENT_DIGEST", record.schema_id, "/")


def _closure(raw: bytes, sink: _Sink) -> dict[str, Any] | None:
    try:
        return validate_verifier_dependency_closure(raw)
    except ClosureValidationError as error:
        sink.add(error.code, "verifier_dependency_closure", error.coordinate)
        return None


def _blob_catalog(image: RuntimeImage, sink: _Sink) -> dict[str, BlobValue]:
    values: dict[str, BlobValue] = {}
    for index, record in enumerate(image.blobs):
        if record.schema_id not in _KNOWN_BLOB_ROLES:
            sink.add("BLOB_ROLE", "blobs", f"/{index}/schema_id")
            continue
        if record.sha256 in values:
            sink.add("BLOB_DIGEST_DUPLICATE", "blobs", f"/{index}/sha256")
            continue
        value = _parse(record.canonical_json, record.schema_id, sink)
        if value is None:
            continue
        try:
            derived = blob_digest(value)
        except CanonicalJsonError:
            sink.add("BLOB_VALUE", record.schema_id, "/")
            continue
        _digest_match(record.sha256, derived, record.schema_id, "/sha256", sink)
        values[record.sha256] = BlobValue(
            record.schema_id, value, record.canonical_json.decode("ascii")
        )
    return values


def _resolve_blob(
    catalog: dict[str, BlobValue], digest: Any, schema_id: str,
    artifact: str, coordinate: str, sink: _Sink,
) -> tuple[Any, str] | None:
    if type(digest) is not str:
        sink.add("BLOB_REFERENCE", artifact, coordinate)
        return None
    item = catalog.get(digest)
    if item is None:
        role_candidates = tuple(
            (candidate_digest, candidate)
            for candidate_digest, candidate in catalog.items()
            if candidate.schema_id == schema_id
        )
        if len(role_candidates) == 1:
            candidate_digest, candidate = role_candidates[0]
            sink.add("DIGEST_MISMATCH", artifact, coordinate)
            sink.add("BINDING_MISMATCH", artifact, coordinate)
            return candidate.value, candidate_digest
        sink.add("GENESIS_BLOB_INVENTORY", "blobs", "/")
        return None
    if item.schema_id != schema_id:
        sink.add("GENESIS_BLOB_INVENTORY", "blobs", "/")
        return None
    return item.value, digest


def _expected_tables(
    *,
    image: RuntimeImage,
    catalog: dict[str, BlobValue],
    events: tuple[dict[str, Any], ...],
    final_state: ReducerState | None,
    attempt_rows: tuple[tuple[Any, ...], ...],
    idempotency_rows: tuple[tuple[Any, ...], ...],
    manifest_sha: str,
    attachment_sha: str,
    selector1_sha: str,
    history_sha: str,
    reachable_digests: set[str] | None = None,
    snapshot_rows: tuple[tuple[Any, ...], ...] = (),
    latest_checkpoint_sha: str | None = None,
    active_selector_generation: int = 1,
    active_selector_sha: str | None = None,
) -> dict[str, tuple[tuple[Any, ...], ...]]:
    genesis = events[0]
    head = events[-1]
    runtime_id = genesis["runtime_id"]
    chain_id = genesis["chain_id"]
    created_at = genesis["occurred_at"]
    event_id = genesis["event_id"]
    event_sha = genesis["event_sha256"]
    repository_generation = (
        final_state.repository_generation if final_state is not None else 0
    )
    repository_bundle = (
        final_state.repository_bundle_sha256
        if final_state is not None else genesis["repository_bundle_sha256"]
    )
    retained_digests = set(catalog) if reachable_digests is None else reachable_digests
    blobs = tuple(
        (digest, catalog[digest].schema_id, catalog[digest].canonical_text)
        for digest in sorted(retained_digests)
    )
    schema_rows = tuple(
        (
            record.schema_id,
            record.document_sha256,
            record.canonical_json.decode("ascii"),
        )
        for record in image.schema_documents
    )
    rows: dict[str, tuple[tuple[Any, ...], ...]] = {
        name: () for name in (
            "attempts", "blobs", "claims", "events", "idempotency",
            "legacy_archive", "metadata", "migrations", "remediation_links",
            "reviews", "schema_documents", "schema_registry", "seals",
            "snapshots", "tasks",
        )
    }
    rows["blobs"] = blobs
    rows["events"] = tuple(
        (event["global_sequence"], event["event_id"], event["event_sha256"], canonical_json(event).decode("ascii"))
        for event in events
    )
    rows["metadata"] = ((
        "runtime", runtime_id, chain_id, 2, 2, "NEW", created_at,
        manifest_sha, attachment_sha, SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
        SUPPORTED_SCHEMA_REGISTRY_SHA256, event_id, event_sha,
        repository_generation,
        repository_bundle, head["global_sequence"], head["event_id"],
        head["event_sha256"], latest_checkpoint_sha,
        active_selector_generation,
        selector1_sha if active_selector_sha is None else active_selector_sha,
        history_sha, None, "UNANCHORED", "UNKNOWN", "DENY",
    ),)
    rows["schema_documents"] = schema_rows
    rows["schema_registry"] = ((
        "registry", SUPPORTED_SCHEMA_REGISTRY_SHA256,
        image.schema_registry.decode("ascii"),
    ),)
    rows["seals"] = ((
        "RUNTIME_GENESIS_IDENTITY", runtime_id, chain_id,
        "RUNTIME_GENESIS_IDENTITY", attachment_sha, event_id, event_sha,
        manifest_sha, event_id, created_at,
    ),)
    rows["snapshots"] = tuple(sorted(
        snapshot_rows, key=lambda row: (row[1], row[2], row[0])
    ))
    if final_state is not None:
        rows["attempts"] = attempt_rows
        rows["claims"] = tuple(
            (
                claim.claim_id, claim.task_id, claim.attempt, claim.fence,
                claim.status, claim.actor, claim.opened_event_id,
                claim.closed_event_id,
            )
            for claim in final_state.claims
        )
        rows["reviews"] = tuple(
            (
                review.assignment_id,
                review.task_id,
                review.attempt,
                review.actor,
                review.role,
                review.status,
                review.opened_event_id,
                review.closed_event_id,
            )
            for review in final_state.reviews
        )
        rows["remediation_links"] = tuple(
            (
                link.link_id, link.source_task_id, link.source_attempt,
                link.child_task_id, link.child_attempt,
                link.source_event_id, link.child_event_id,
                link.decision_sha256, link.link_sha256,
            )
            for link in final_state.remediation_links
        )
        rows["tasks"] = tuple(
            (
                task.task_id, task.attempt, task.workflow, task.execution,
                task.review, task.scheduler_generation, task.dispatch_generation,
                task.task_fence, task.active_claim_id,
                task.reviewer_assignment_id, task.continuation_count,
                task.repository_generation, task.decision_receipt_digest,
                task.owner, task.owner_role, task.reviewer,
                task.predecessor_task, task.successor_task,
            )
            for task in final_state.tasks
        )
    rows["idempotency"] = tuple(sorted(idempotency_rows))
    return rows


def _commit_group_patch(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    patch: InitializeGroupPatch | ClaimGroupPatch | WorkerGroupPatch,
    semantic_event: dict[str, Any],
    commit_event: dict[str, Any],
) -> None:
    """Atomically advance private replay indexes after full group validation."""
    observed_pair = (
        semantic_event["event_id"], semantic_event["event_sha256"],
        commit_event["event_id"], commit_event["event_sha256"],
    )
    if patch.event_pair != observed_pair:
        raise GroupValidationError("GROUP_PATCH_PAIR", "/events")
    cursor.check_pair(semantic_event, commit_event)
    cursor.check_attempt_advance(
        semantic_event,
        opens_attempt=patch.opens_attempt,
        predecessor_attempt=patch.predecessor_attempt,
    )
    workspace.commit(patch.transition)
    cursor.advance_pair(
        semantic_event,
        commit_event,
        opens_attempt=patch.opens_attempt,
        predecessor_attempt=patch.predecessor_attempt,
    )


def _commit_remediation_patch(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    patch: RemediationGroupPatch,
    source_event: dict[str, Any],
    child_event: dict[str, Any],
    commit_event: dict[str, Any],
) -> None:
    """Atomically advance a validated two-task remediation transaction."""
    observed = (
        source_event["event_id"], source_event["event_sha256"],
        child_event["event_id"], child_event["event_sha256"],
        commit_event["event_id"], commit_event["event_sha256"],
    )
    if patch.event_triplet != observed:
        raise GroupValidationError("GROUP_PATCH_TRIPLET", "/events")
    cursor.check_remediation(source_event, child_event, commit_event)
    workspace.commit(patch.transition)
    cursor.advance_remediation(source_event, child_event, commit_event)


def _commit_import_patch(
    *,
    cursor: _ReplayCursor,
    workspace: _TransitionWorkspace,
    patch: ImportGroupPatch,
    semantic_events: tuple[dict[str, Any], ...],
    commit_event: dict[str, Any],
) -> None:
    """Atomically advance a validated variable-width repository import."""
    observed = tuple(
        (event["event_id"], event["event_sha256"])
        for event in semantic_events + (commit_event,)
    )
    if patch.event_sequence != observed:
        raise GroupValidationError("GROUP_PATCH_SEQUENCE", "/events")
    cursor.check_import(semantic_events, commit_event)
    workspace.commit(patch.transition)
    cursor.advance_import(
        semantic_events,
        commit_event,
        repository_generation=patch.transition.after.repository_generation,
        repository_bundle_sha256=(
            patch.transition.after.repository_bundle_sha256
        ),
    )


def reduce_initial_runtime_image(candidate: object) -> InitialReductionReport:
    """Reduce a candidate NEW genesis image without ever authorizing it."""
    sink = _Sink()
    preflight = inspect_runtime_image_host(candidate)
    for violation in preflight.violations:
        sink.add(violation.code, violation.artifact, violation.coordinate)
    if preflight.image is None:
        return _invalid(sink)
    image = preflight.image

    storage = _parse(image.storage_descriptor, "storage_descriptor", sink)
    closure = _closure(image.verifier_dependency_closure, sink)
    manifest = _parse(image.manifest, "manifest", sink)
    attachment = _parse(image.attachment, "attachment", sink)
    registry = _parse(image.schema_registry, "schema_registry", sink)

    if storage is not None:
        _validate(storage, "storage_descriptor", validate_supported_storage_descriptor, sink)
    if registry is not None:
        _validate(registry, "schema_registry", validate_supported_schema_registry, sink)
        _schema_bundle(image, registry, sink)
    if attachment is not None:
        _validate(attachment, "attachment", validate_attachment, sink)
    if manifest is not None:
        _validate(manifest, "manifest", validate_manifest, sink)
    closure_sha = (
        closure["verifier_dependency_closure_sha256"]
        if closure is not None else None
    )

    if sink.result():
        return _invalid(sink)
    assert type(manifest) is dict
    if manifest["source_kind"] != "NEW":
        return InitialReductionReport(
            "UNSUPPORTED",
            (InitialViolation("V1_MIGRATION_NOT_SUPPORTED", "manifest", "/source_kind"),),
        )
    compiled_event_count = (
        len(image.events) == 1 or 3 <= len(image.events) <= MAX_EVENTS
    )
    if not compiled_event_count:
        sink.add("COMPILED_EVENT_CARDINALITY", "events", "/")
    if not 2 <= len(image.selector_history) <= 50_001:
        sink.add("SELECTOR_CARDINALITY", "selector_history", "/")

    blobs = _blob_catalog(image, sink)
    parsed_events = tuple(
        _parse(raw, f"events[{index}]", sink)
        for index, raw in enumerate(image.events)
    ) if compiled_event_count else ()
    event = parsed_events[0] if parsed_events else None
    selectors = tuple(
        _parse(raw, f"selector_history[{index}]", sink)
        for index, raw in enumerate(image.selector_history)
    ) if 2 <= len(image.selector_history) <= 50_001 else ()
    if sink.result():
        return _invalid(sink)

    selector0, selector1 = selectors[:2]
    _validate(event, "event", validate_runtime_genesis_envelope, sink)
    _validate(selector0, "selector_history[0]", validate_selector, sink)
    _validate(selector1, "selector_history[1]", validate_selector, sink)
    for index, selector in enumerate(selectors[2:], start=2):
        _validate(selector, f"selector_history[{index}]", validate_selector, sink)
    if sink.result():
        return _invalid(sink)

    assert type(event) is dict
    request_item = _resolve_blob(
        blobs, event["transaction"]["request_sha256"], REQUEST_SCHEMA_ID,
        "event", "/transaction/request_sha256", sink,
    )
    response_item = _resolve_blob(
        blobs, event["transaction"]["response_sha256"], RESPONSE_SCHEMA_ID,
        "event", "/transaction/response_sha256", sink,
    )
    payload_item = _resolve_blob(
        blobs, event["payload_ref"]["sha256"], PAYLOAD_SCHEMA_ID,
        "event", "/payload_ref/sha256", sink,
    )
    if sink.result():
        return _invalid(sink)
    assert request_item is not None and response_item is not None and payload_item is not None
    request, request_sha = request_item
    response, response_sha = response_item
    payload, payload_sha = payload_item
    _validate(request, "request", validate_new_genesis_request, sink)
    _validate(response, "response", validate_new_genesis_response, sink)
    _validate(payload, "payload", validate_runtime_genesis_payload, sink)
    if sink.result():
        return _invalid(sink)

    assert all(type(value) is dict for value in (
        storage, closure, manifest, attachment, registry, request, response,
        payload, event, selector0, selector1,
    ))
    assert closure_sha is not None
    runtime_id = event["runtime_id"]
    chain_id = event["chain_id"]
    repository_bundle = event["repository_bundle_sha256"]
    payload_data = payload["data"]
    attachment_sha = attachment_digest(attachment)
    manifest_sha = manifest_digest(manifest)
    derived_event_sha = event_digest(event)

    for artifact, value in (
        ("attachment", attachment), ("manifest", manifest), ("request", request),
        ("response", response), ("payload", payload_data),
    ):
        _bind(value["runtime_id"], runtime_id, artifact, "/runtime_id", sink)
        _bind(value["chain_id"], chain_id, artifact, "/chain_id", sink)
    for artifact, value in (("request", request), ("payload", payload_data), ("event", event)):
        _bind(value["repository_generation"], 0, artifact, "/repository_generation", sink)
        _bind(
            value["repository_bundle_sha256"], repository_bundle,
            artifact, "/repository_bundle_sha256", sink,
        )
    for artifact, values in (
        ("request", request["arguments"]), ("payload", payload_data), ("manifest", manifest),
    ):
        _digest_match(
            values["attachment_sha256"], attachment_sha,
            artifact, "/attachment_sha256", sink,
        )
        _digest_match(
            values["storage_schema_sha256"], SUPPORTED_STORAGE_DESCRIPTOR_SHA256,
            artifact, "/storage_schema_sha256", sink,
        )
        _digest_match(
            values["schema_registry_sha256"], SUPPORTED_SCHEMA_REGISTRY_SHA256,
            artifact, "/schema_registry_sha256", sink,
        )
    _digest_match(
        payload_data["verifier_dependency_closure_sha256"], closure_sha,
        "payload", "/data/verifier_dependency_closure_sha256", sink,
    )
    _digest_match(
        event["transaction"]["request_sha256"], request_sha,
        "event", "/transaction/request_sha256", sink,
    )
    _digest_match(
        event["transaction"]["response_sha256"], response_sha,
        "event", "/transaction/response_sha256", sink,
    )
    _digest_match(
        event["payload_ref"]["sha256"], payload_sha,
        "event", "/payload_ref/sha256", sink,
    )
    _digest_match(event["event_sha256"], derived_event_sha, "event", "/event_sha256", sink)
    _bind(manifest["genesis_event_id"], event["event_id"], "manifest", "/genesis_event_id", sink)
    _digest_match(
        manifest["genesis_event_sha256"], derived_event_sha,
        "manifest", "/genesis_event_sha256", sink,
    )
    for artifact, coordinate, timestamp in (
        ("attachment", "/created_at", attachment["created_at"]),
        ("manifest", "/created_at", manifest["created_at"]),
        ("selector_history[1]", "/written_at", selector1["written_at"]),
    ):
        _bind(timestamp, event["occurred_at"], artifact, coordinate, sink)

    selector0_sha = selector_digest(selector0)
    _digest_match(
        selector0["selector_sha256"], selector0_sha,
        "selector_history[0]", "/selector_sha256", sink,
    )
    expected_selector1 = {
        "schema_version": 1,
        "selector_format_version": 1,
        "selector_generation": 1,
        "active_runtime_format_version": 2,
        "active_runtime_id": runtime_id,
        "active_database_path": "runtime.v2.sqlite",
        "active_attachment_path": "attachment.v2.json",
        "active_manifest_path": "runtime.v2.manifest.json",
        "active_manifest_sha256": manifest_sha,
        "latest_v2_checkpoint_sha256": None,
        "selector_history_path": "selectors/00000000000000000001.json",
        "prior_selector_path": "selectors/00000000000000000000.json",
        "prior_selector_sha256": selector0_sha,
        "cutover_state": "V2_ACTIVE",
        "currentness_status": "UNKNOWN",
        "authorizing_use": "DENY",
        "written_at": event["occurred_at"],
        "selector_sha256": selector1["selector_sha256"],
    }
    expected_selector1["selector_sha256"] = selector_digest(expected_selector1)
    if selector1 != expected_selector1:
        sink.add("SELECTOR_DERIVATION", "selector_history[1]", "/")
    selector1_sha = expected_selector1["selector_sha256"]
    history_sha = selector_history_digest([selector0, selector1])

    if sink.result():
        return _invalid(sink)
    final_patch: (
        InitializeGroupPatch | ClaimGroupPatch | WorkerGroupPatch
        | RemediationGroupPatch | ImportGroupPatch | SnapshotGroupPatch | None
    ) = None
    idempotency_rows: list[tuple[Any, ...]] = []
    snapshot_rows: list[tuple[Any, ...]] = []
    active_selectors = [selector0, selector1]
    latest_checkpoint_sha: str | None = None
    prior_export_sha: str | None = None
    checkpoint_sequence = 0
    export_sequence = 0
    snapshot_ids: set[str] = set()
    snapshot_document_digests: set[str] = set()
    expected_reachable = {request_sha, response_sha, payload_sha}
    root_work = preflight.final_supplied_root_work_bytes or 0
    cursor = _ReplayCursor(event)
    workspace = _TransitionWorkspace(
        ReducerState(event["repository_generation"], event["repository_bundle_sha256"])
    )
    semantic_index = 1
    first_type = (
        parsed_events[1].get("event_type")
        if len(parsed_events) >= 3 and type(parsed_events[1]) is dict
        else None
    )
    if len(parsed_events) >= 3 and first_type == "TASK_INITIALIZED":
        try:
            initialize_patch = reduce_initialize_group(
                genesis_event=event,
                cursor=cursor,
                workspace=workspace,
                semantic_event=parsed_events[1],
                commit_event=parsed_events[2],
                catalog=blobs,
            )
        except GroupValidationError as error:
            sink.add(error.code, "transaction_group", error.coordinate)
            return _invalid(sink)
        try:
            _commit_group_patch(
                cursor=cursor,
                workspace=workspace,
                patch=initialize_patch,
                semantic_event=parsed_events[1],
                commit_event=parsed_events[2],
            )
        except (GroupValidationError, TransitionViolation) as error:
            sink.add(error.code, "transaction_group", error.coordinate)
            return _invalid(sink)
        final_patch = initialize_patch
        idempotency_rows.append(initialize_patch.idempotency_row)
        expected_reachable.update(initialize_patch.reachable_blob_digests)
        semantic_index = 3
    if len(parsed_events) >= 3:
        while semantic_index < len(parsed_events):
            semantic_candidate = parsed_events[semantic_index]
            event_type = (
                semantic_candidate.get("event_type")
                if type(semantic_candidate) is dict
                else None
            )
            if type(event_type) is str and event_type in {
                "RUNTIME_CHECKPOINTED", "RUNTIME_SNAPSHOT_EXPORTED",
            }:
                if semantic_index + 1 >= len(parsed_events):
                    sink.add(
                        "GROUP_EVENT_COUNT", "snapshot_transaction_group",
                        f"/events/{semantic_index}",
                    )
                    return _invalid(sink)
                try:
                    cut_state = workspace.freeze()
                    cut_history_sha = selector_history_digest(active_selectors)
                    cut_rows = _expected_tables(
                        image=image,
                        catalog=blobs,
                        events=tuple(
                            parsed_events[index]
                            for index in range(semantic_index)
                        ),
                        final_state=cut_state,
                        attempt_rows=cursor.attempt_rows(),
                        idempotency_rows=tuple(idempotency_rows),
                        manifest_sha=manifest_sha,
                        attachment_sha=attachment_sha,
                        selector1_sha=selector1_sha,
                        history_sha=cut_history_sha,
                        reachable_digests=expected_reachable,
                        snapshot_rows=tuple(snapshot_rows),
                        latest_checkpoint_sha=latest_checkpoint_sha,
                        active_selector_generation=len(active_selectors) - 1,
                        active_selector_sha=active_selectors[-1]["selector_sha256"],
                    )
                    cut_roots = {
                        name: table_root(
                            name, [list(row) for row in cut_rows[name]]
                        )
                        for name in cut_rows
                    }
                    root_work += sum(
                        len(b"EDGELAB\0TABLE\0V2\0")
                        + len(name.encode("utf-8")) + 1
                        + len(canonical_json([list(row) for row in cut_rows[name]]))
                        for name in cut_rows
                    )
                    if root_work > MAX_TOTAL_ROOT_WORK_BYTES:
                        sink.add(
                            "TOTAL_ROOT_WORK_LIMIT", "snapshot_cuts", "/",
                        )
                        return _invalid(sink)
                    kind = (
                        "CHECKPOINT"
                        if event_type == "RUNTIME_CHECKPOINTED" else "EXPORT"
                    )
                    patch = reduce_snapshot_group(
                        cursor=cursor,
                        semantic_event=semantic_candidate,
                        commit_event=parsed_events[semantic_index + 1],
                        catalog=blobs,
                        cut_roots=cut_roots,
                        manifest_sha256=manifest_sha,
                        selectors=tuple(active_selectors),
                        snapshot_kind=kind,
                        snapshot_sequence=(
                            checkpoint_sequence
                            if kind == "CHECKPOINT" else export_sequence
                        ),
                        prior_document_sha256=(
                            latest_checkpoint_sha
                            if kind == "CHECKPOINT" else prior_export_sha
                        ),
                        source_checkpoint_sha256=latest_checkpoint_sha,
                    )
                    observed = (
                        semantic_candidate["event_id"],
                        semantic_candidate["event_sha256"],
                        parsed_events[semantic_index + 1]["event_id"],
                        parsed_events[semantic_index + 1]["event_sha256"],
                    )
                    if patch.event_pair != observed:
                        raise GroupValidationError("GROUP_PATCH_PAIR", "/events")
                    if patch.snapshot_row[0] in snapshot_ids:
                        raise GroupValidationError(
                            "GROUP_SNAPSHOT_ID_DUPLICATE", "/snapshots",
                        )
                    if patch.snapshot_row[4] in snapshot_document_digests:
                        raise GroupValidationError(
                            "GROUP_SNAPSHOT_DIGEST_DUPLICATE", "/snapshots",
                        )
                    cursor.advance_pair(
                        semantic_candidate,
                        parsed_events[semantic_index + 1],
                        opens_attempt=False,
                        predecessor_attempt=None,
                    )
                except (GroupValidationError, TransitionViolation) as error:
                    sink.add(
                        error.code, "snapshot_transaction_group",
                        error.coordinate,
                    )
                    return _invalid(sink)
                final_patch = patch
                idempotency_rows.append(patch.idempotency_row)
                snapshot_rows.append(patch.snapshot_row)
                snapshot_ids.add(patch.snapshot_row[0])
                snapshot_document_digests.add(patch.snapshot_row[4])
                expected_reachable.update(patch.reachable_blob_digests)
                if kind == "CHECKPOINT":
                    latest_checkpoint_sha = patch.snapshot_row[4]
                    checkpoint_sequence += 1
                    assert patch.next_selector is not None
                    selector_index = len(active_selectors)
                    if (
                        selector_index >= len(selectors)
                        or selectors[selector_index] != patch.next_selector
                    ):
                        sink.add(
                            "SELECTOR_DERIVATION",
                            f"selector_history[{selector_index}]", "/",
                        )
                        return _invalid(sink)
                    active_selectors.append(patch.next_selector)
                else:
                    prior_export_sha = patch.snapshot_row[4]
                    export_sequence += 1
                semantic_index += 2
                continue
            if event_type == "REMEDIATION_CREATED":
                if semantic_index + 2 >= len(parsed_events):
                    sink.add(
                        "GROUP_EVENT_COUNT", "remediation_transaction_group",
                        f"/events/{semantic_index}",
                    )
                    return _invalid(sink)
                try:
                    patch = reduce_remediation_group(
                        cursor=cursor,
                        workspace=workspace,
                        source_event=semantic_candidate,
                        child_event=parsed_events[semantic_index + 1],
                        commit_event=parsed_events[semantic_index + 2],
                        catalog=blobs,
                    )
                except GroupValidationError as error:
                    sink.add(
                        error.code, "remediation_transaction_group",
                        error.coordinate,
                    )
                    return _invalid(sink)
                try:
                    _commit_remediation_patch(
                        cursor=cursor,
                        workspace=workspace,
                        patch=patch,
                        source_event=semantic_candidate,
                        child_event=parsed_events[semantic_index + 1],
                        commit_event=parsed_events[semantic_index + 2],
                    )
                except (GroupValidationError, TransitionViolation) as error:
                    sink.add(
                        error.code, "remediation_transaction_group",
                        error.coordinate,
                    )
                    return _invalid(sink)
                final_patch = patch
                idempotency_rows.append(patch.idempotency_row)
                expected_reachable.update(patch.reachable_blob_digests)
                semantic_index += 3
                continue
            if type(event_type) is str and event_type in {
                "REPOSITORY_GENERATION_APPLIED",
                "REPOSITORY_GENERATION_ADVANCED",
            }:
                transaction = semantic_candidate.get("transaction")
                event_count = (
                    transaction.get("event_count")
                    if type(transaction) is dict else None
                )
                if (
                    type(event_count) is not int
                    or event_count < 2
                    or semantic_index + event_count > len(parsed_events)
                ):
                    sink.add(
                        "GROUP_EVENT_COUNT", "import_transaction_group",
                        f"/events/{semantic_index}",
                    )
                    return _invalid(sink)
                semantic_events = tuple(
                    parsed_events[semantic_index:semantic_index + event_count - 1]
                )
                commit_event = parsed_events[semantic_index + event_count - 1]
                try:
                    patch = reduce_import_group(
                        cursor=cursor,
                        workspace=workspace,
                        semantic_events=semantic_events,
                        commit_event=commit_event,
                        catalog=blobs,
                    )
                except GroupValidationError as error:
                    sink.add(
                        error.code, "import_transaction_group",
                        error.coordinate,
                    )
                    return _invalid(sink)
                try:
                    _commit_import_patch(
                        cursor=cursor,
                        workspace=workspace,
                        patch=patch,
                        semantic_events=semantic_events,
                        commit_event=commit_event,
                    )
                except (GroupValidationError, TransitionViolation) as error:
                    sink.add(
                        error.code, "import_transaction_group",
                        error.coordinate,
                    )
                    return _invalid(sink)
                final_patch = patch
                idempotency_rows.append(patch.idempotency_row)
                expected_reachable.update(patch.reachable_blob_digests)
                semantic_index += event_count
                continue
            if semantic_index + 1 >= len(parsed_events):
                sink.add(
                    "GROUP_EVENT_COUNT", "transaction_group",
                    f"/events/{semantic_index}",
                )
                return _invalid(sink)
            if event_type == "CLAIM_ISSUED":
                reducer = reduce_claim_group
                artifact = "claim_transaction_group"
            elif type(event_type) is str and event_type in _FOLLOWUP_PROFILES:
                reducer = reduce_worker_group
                artifact = "worker_transaction_group"
            else:
                sink.add(
                    "GROUP_FOLLOWUP_OPERATION",
                    "transaction_group",
                    f"/events/{semantic_index}/event_type",
                )
                return _invalid(sink)
            try:
                patch = reducer(
                    cursor=cursor,
                    workspace=workspace,
                    semantic_event=semantic_candidate,
                    commit_event=parsed_events[semantic_index + 1],
                    catalog=blobs,
                )
            except GroupValidationError as error:
                sink.add(error.code, artifact, error.coordinate)
                return _invalid(sink)
            try:
                _commit_group_patch(
                    cursor=cursor,
                    workspace=workspace,
                    patch=patch,
                    semantic_event=semantic_candidate,
                    commit_event=parsed_events[semantic_index + 1],
                )
            except (GroupValidationError, TransitionViolation) as error:
                sink.add(error.code, artifact, error.coordinate)
                return _invalid(sink)
            final_patch = patch
            idempotency_rows.append(patch.idempotency_row)
            expected_reachable.update(patch.reachable_blob_digests)
            semantic_index += 2
        if set(blobs) != expected_reachable:
            sink.add("BLOB_REACHABILITY", "blobs", "/")
            return _invalid(sink)
    elif set(blobs) != expected_reachable:
        sink.add("BLOB_REACHABILITY", "blobs", "/")
        return _invalid(sink)

    if len(active_selectors) != len(selectors):
        sink.add("SELECTOR_CARDINALITY", "selector_history", "/")
        return _invalid(sink)
    if len(image.checkpoint_copies) > checkpoint_sequence:
        sink.add("CHECKPOINT_COPY_CARDINALITY", "checkpoint_copies", "/")
        return _invalid(sink)
    registered_copies = {
        blobs[row[5]].canonical_text.encode("ascii"): row
        for row in snapshot_rows
        if row[1] == "CHECKPOINT"
    }
    prior_copy_sequence = -1
    seen_copy_bytes: set[bytes] = set()
    for index, raw_copy in enumerate(image.checkpoint_copies):
        row = registered_copies.get(raw_copy)
        if row is None:
            sink.add(
                "CHECKPOINT_COPY_UNREGISTERED", "checkpoint_copies",
                f"/{index}",
            )
            continue
        if raw_copy in seen_copy_bytes or row[2] <= prior_copy_sequence:
            sink.add(
                "CHECKPOINT_COPY_ORDER", "checkpoint_copies", f"/{index}",
            )
            continue
        seen_copy_bytes.add(raw_copy)
        prior_copy_sequence = row[2]
    if sink.result():
        return _invalid(sink)

    try:
        final_state = workspace.freeze() if final_patch is not None else None
    except TransitionViolation as error:
        sink.add(error.code, "transition_workspace", error.coordinate)
        return _invalid(sink)
    expected_rows = _expected_tables(
        image=image,
        catalog=blobs,
        events=tuple(parsed_events),
        final_state=final_state,
        attempt_rows=cursor.attempt_rows(),
        idempotency_rows=tuple(idempotency_rows),
        manifest_sha=manifest_sha,
        attachment_sha=attachment_sha,
        selector1_sha=selector1_sha,
        history_sha=selector_history_digest(active_selectors),
        reachable_digests=expected_reachable,
        snapshot_rows=tuple(snapshot_rows),
        latest_checkpoint_sha=latest_checkpoint_sha,
        active_selector_generation=len(active_selectors) - 1,
        active_selector_sha=active_selectors[-1]["selector_sha256"],
    )
    for snapshot in image.table_snapshots:
        assert type(snapshot) is TableSnapshot
        expected = expected_rows[snapshot.table]
        if snapshot.rows != expected:
            sink.add("TABLE_DERIVATION", snapshot.table, "/rows")
    if sink.result():
        return _invalid(sink)

    return InitialReductionReport(
        status="UNSUPPORTED",
        violations=(InitialViolation(
            "CLOSURE_NOT_COMPILED",
            "verifier_dependency_closure",
            "/",
        ),),
    )


__all__ = (
    "InitialReductionReport",
    "InitialViolation",
    "SCHEMA_DOCUMENT_PINS",
    "reduce_initial_runtime_image",
)
