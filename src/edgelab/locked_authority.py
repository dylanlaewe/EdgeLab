"""Read actual scheduler authority coherently without authorizing any action.

This is a diagnostic substrate, not a currentness resolver or an execution gate.
Every result embeds a closed M0.2 verification denial.  Positive authority can
only be added by a separately reviewed contract that defines the missing source
mappings and evidence bindings.
"""
from __future__ import annotations

import json
import sqlite3
import stat
from dataclasses import asdict
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .transactional_scheduler import RuntimeUnavailable, Scheduler, digest


_LIMITATIONS = (
    "diagnostic-only; never authorizes scheduler, paper, live, or capital action",
    "historical evidence is not composed or verified by this reader",
    "positive currentness and generation mappings remain undefined",
    "caller-supplied snapshots, bindings, and receipts are not accepted",
    "stored decision_receipt_digest remains caller-supplied and non-authoritative",
    "historical INVALID means unavailable gate input, not a finding that preserved evidence is false",
    "auxiliary scheduler history is checked for consistency but is not yet fully event-bound",
)


class _ReadFailure(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sidecars_absent(scheduler: Scheduler) -> bool:
    return not any(
        sidecar.exists()
        for sidecar in (
            scheduler.db.with_name(scheduler.db.name + "-wal"),
            scheduler.db.with_name(scheduler.db.name + "-shm"),
        )
    )


def _result(task_id: str, *, authority: dict[str, Any] | None, failure: str | None) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "observation_status": "COHERENT_DENY_ONLY" if authority is not None else "UNAVAILABLE",
        "task_id": task_id,
        "authority": authority,
        "authority_sha256": digest(authority) if authority is not None else None,
        "failure_reason": failure,
        "verification": {
            "historical_status": "INVALID",
            "currentness_status": "UNKNOWN",
            "runtime_compatible": False,
            "verifier_status": "FAIL",
            "generation_match": False,
            "authorizing_use": "DENY",
            "reason_code": "VERIFIER_FAILURE",
        },
        "limitations": list(_LIMITATIONS),
    }
    return record


def _checked_result(
    scheduler: Scheduler,
    task_id: str,
    *,
    authority: dict[str, Any] | None,
    failure: str | None,
) -> dict[str, Any]:
    record = _result(task_id, authority=authority, failure=failure)
    try:
        schema = json.loads(
            (scheduler.root / "schemas/m0-3a-locked-authority-read.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(schema).validate(record)
        return record
    except ValidationError:
        fallback = _result(task_id, authority=None, failure="AUTHORITY_INVALID")
        try:
            Draft202012Validator(schema).validate(fallback)
            return fallback
        except (SchemaError, ValidationError):
            return _result(task_id, authority=None, failure="INTERNAL_FAILURE")
    except (OSError, json.JSONDecodeError, SchemaError):
        return _result(task_id, authority=None, failure="INTERNAL_FAILURE")


def _meta_snapshot(scheduler: Scheduler, connection: sqlite3.Connection) -> dict[str, Any]:
    try:
        snapshot = {
            key: scheduler._meta(connection, key)
            for key in (
                "schema_version",
                "runtime_id",
                "attachment_digest",
                "repository_generation",
                "bundle_digest",
                "global_head_id",
                "global_head_digest",
                "available",
            )
        }
    except (sqlite3.Error, TypeError, json.JSONDecodeError) as error:
        raise _ReadFailure("AUTHORITY_INVALID") from error
    sha_fields = ("attachment_digest", "bundle_digest", "global_head_digest")
    if (
        snapshot["schema_version"] != 1
        or not isinstance(snapshot["runtime_id"], str)
        or not snapshot["runtime_id"]
        or any(
            not isinstance(snapshot[field], str)
            or len(snapshot[field]) != 64
            or any(character not in "0123456789abcdef" for character in snapshot[field])
            for field in sha_fields
        )
        or type(snapshot["repository_generation"]) is not int
        or snapshot["repository_generation"] < 0
        or not isinstance(snapshot["global_head_id"], str)
        or not snapshot["global_head_id"]
        or snapshot["available"] is not True
    ):
        raise _ReadFailure("AUTHORITY_INVALID")
    return snapshot


def _claim_snapshot(connection: sqlite3.Connection, task: sqlite3.Row) -> dict[str, Any] | None:
    active = list(
        connection.execute(
            "SELECT claim_id,task_id,attempt,fence,status,actor FROM claims "
            "WHERE task_id=? AND status='ACTIVE' ORDER BY claim_id",
            (task["task_id"],),
        )
    )
    claim_id = task["claim_id"]
    if claim_id is None:
        if active:
            raise _ReadFailure("CLAIM_INCONSISTENT")
        return None
    claim = connection.execute(
        "SELECT claim_id,task_id,attempt,fence,status,actor FROM claims WHERE claim_id=?",
        (claim_id,),
    ).fetchone()
    if (
        claim is None
        or len(active) != 1
        or active[0]["claim_id"] != claim_id
        or claim["task_id"] != task["task_id"]
        or claim["attempt"] != task["attempt"]
        or claim["fence"] != task["task_fence"]
        or claim["status"] != "ACTIVE"
    ):
        raise _ReadFailure("CLAIM_INCONSISTENT")
    event = connection.execute(
        "SELECT after_json,payload FROM task_events WHERE task_id=? AND event_type='CLAIM_ISSUED' "
        "ORDER BY task_seq DESC LIMIT 1",
        (task["task_id"],),
    ).fetchone()
    try:
        after = json.loads(event["after_json"])
        request = json.loads(event["payload"])["request"]["request"]
    except (TypeError, KeyError, json.JSONDecodeError) as error:
        raise _ReadFailure("CLAIM_INCONSISTENT") from error
    if after.get("active_claim_id") != claim_id or request.get("actor") != claim["actor"]:
        raise _ReadFailure("CLAIM_INCONSISTENT")
    return dict(claim)


def _attempts_snapshot(connection: sqlite3.Connection, task: sqlite3.Row) -> list[dict[str, Any]]:
    attempts = [
        dict(row)
        for row in connection.execute(
            "SELECT task_id,attempt,predecessor_attempt FROM attempts WHERE task_id=? ORDER BY attempt",
            (task["task_id"],),
        )
    ]
    expected = list(range(1, task["attempt"] + 1))
    if [row["attempt"] for row in attempts] != expected or any(
        row["task_id"] != task["task_id"]
        or row["predecessor_attempt"] != (None if row["attempt"] == 1 else row["attempt"] - 1)
        for row in attempts
    ):
        raise _ReadFailure("ATTEMPT_INCONSISTENT")
    return attempts


def _review_snapshot(connection: sqlite3.Connection, task: sqlite3.Row) -> dict[str, Any] | None:
    active = list(
        connection.execute(
            "SELECT assignment_id,task_id,actor,role,status FROM reviews "
            "WHERE task_id=? AND status='ACTIVE' ORDER BY assignment_id",
            (task["task_id"],),
        )
    )
    reviewer_id = task["reviewer_id"]
    if reviewer_id is None:
        if active or task["review"] == "REVIEWING":
            raise _ReadFailure("REVIEW_INCONSISTENT")
        return None
    review = connection.execute(
        "SELECT assignment_id,task_id,actor,role,status FROM reviews WHERE assignment_id=?",
        (reviewer_id,),
    ).fetchone()
    if (
        review is None
        or len(active) != 1
        or active[0]["assignment_id"] != reviewer_id
        or review["task_id"] != task["task_id"]
        or review["status"] != "ACTIVE"
        or task["review"] != "REVIEWING"
        or not isinstance(review["actor"], str)
        or not review["actor"]
        or not isinstance(review["role"], str)
        or not review["role"]
    ):
        raise _ReadFailure("REVIEW_INCONSISTENT")
    event = connection.execute(
        "SELECT after_json,payload FROM task_events WHERE task_id=? AND event_type='REVIEW_ASSIGNED' "
        "ORDER BY task_seq DESC LIMIT 1",
        (task["task_id"],),
    ).fetchone()
    try:
        after = json.loads(event["after_json"])
        request = json.loads(event["payload"])["request"]["request"]
    except (TypeError, KeyError, json.JSONDecodeError) as error:
        raise _ReadFailure("REVIEW_INCONSISTENT") from error
    if (
        after.get("reviewer_assignment_id") != reviewer_id
        or request.get("actor") != review["actor"]
        or request.get("role") != review["role"]
    ):
        raise _ReadFailure("REVIEW_INCONSISTENT")
    return dict(review)


def _read_once(scheduler: Scheduler, task_id: str, repository: Any) -> dict[str, Any]:
    try:
        connection = scheduler.connect(read_only=True)
    except (RuntimeUnavailable, sqlite3.Error) as error:
        raise _ReadFailure("RUNTIME_UNAVAILABLE") from error
    try:
        connection.execute("BEGIN")
        try:
            scheduler._verify(connection, repair_permissions=False)
        except RuntimeError as error:
            if isinstance(error, RuntimeUnavailable):
                raise _ReadFailure("AUTHORITY_INVALID") from error
            raise _ReadFailure("RUNTIME_UNAVAILABLE") from error
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise _ReadFailure("AUTHORITY_INVALID") from error

        task = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None:
            raise _ReadFailure("TASK_UNKNOWN")
        meta = _meta_snapshot(scheduler, connection)
        if meta["bundle_digest"] != repository.digest:
            raise _ReadFailure("BUNDLE_STALE")
        if task["repository_generation"] != meta["repository_generation"]:
            raise _ReadFailure("GENERATION_INCONSISTENT")

        claim = _claim_snapshot(connection, task)
        attempts = _attempts_snapshot(connection, task)
        review = _review_snapshot(connection, task)
        try:
            attachment = json.loads(scheduler.attachment.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise _ReadFailure("AUTHORITY_INVALID") from error
        if digest(attachment) != meta["attachment_digest"]:
            raise _ReadFailure("AUTHORITY_INVALID")

        return {
            "repository": {
                **asdict(repository),
            },
            "runtime": meta,
            "attachment": {
                key: attachment[key]
                for key in (
                    "attachment_schema_version",
                    "attachment_id",
                    "canonical_project_id",
                    "repository_identity",
                    "expected_remote",
                    "repository_marker_digest",
                    "m0_2_freeze_commit",
                    "checkout_realpath",
                    "git_common_dir_identity",
                    "created_at",
                )
            },
            "task": {
                "task_id": task["task_id"],
                "tuple": scheduler.tuple(task),
            },
            "claim": claim,
            "attempts": attempts,
            "review": review,
        }
    except sqlite3.Error as error:
        raise _ReadFailure("AUTHORITY_INVALID") from error
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def read_locked_authority(scheduler: Scheduler, task_id: str) -> dict[str, Any]:
    """Return a coherent, actual-authority observation that always denies use.

    The public API deliberately has no parameters for snapshots, source roots,
    currentness bindings, receipts, or authorization policy.
    """
    if not isinstance(task_id, str) or not task_id:
        return _checked_result(scheduler, str(task_id), authority=None, failure="TASK_UNKNOWN")
    paths = (
        (scheduler.dir, 0o700, "directory"),
        (scheduler.db, 0o600, "file"),
        (scheduler.attachment, 0o600, "file"),
        (scheduler.lock_path, 0o600, "file"),
    )
    try:
        safe_shape = all(
            (path.is_dir() if kind == "directory" else path.is_file())
            and stat.S_IMODE(path.stat().st_mode) == mode
            for path, mode, kind in paths
        ) and _sidecars_absent(scheduler)
    except OSError:
        safe_shape = False
    if not safe_shape:
        return _checked_result(scheduler, task_id, authority=None, failure="RUNTIME_UNAVAILABLE")

    try:
        try:
            with scheduler.locked("locked-authority-read", repair_permissions=False):
                if not _sidecars_absent(scheduler):
                    raise _ReadFailure("RUNTIME_UNAVAILABLE")
                try:
                    first_bundle = scheduler.bundle()
                except (RuntimeUnavailable, OSError) as error:
                    raise _ReadFailure("REPOSITORY_UNAVAILABLE") from error
                first = _read_once(scheduler, task_id, first_bundle)

                try:
                    second_bundle = scheduler.bundle()
                except (RuntimeUnavailable, OSError) as error:
                    raise _ReadFailure("REPOSITORY_UNAVAILABLE") from error
                if second_bundle != first_bundle:
                    raise _ReadFailure("RACE_DETECTED")
                second = _read_once(scheduler, task_id, second_bundle)
                if second != first:
                    raise _ReadFailure("RACE_DETECTED")

                try:
                    final_bundle = scheduler.bundle()
                except (RuntimeUnavailable, OSError) as error:
                    raise _ReadFailure("REPOSITORY_UNAVAILABLE") from error
                if final_bundle != first_bundle:
                    raise _ReadFailure("RACE_DETECTED")
                if not _sidecars_absent(scheduler):
                    raise _ReadFailure("RUNTIME_UNAVAILABLE")
                return _checked_result(scheduler, task_id, authority=first, failure=None)
        except RuntimeUnavailable as error:
            code = "LOCK_UNAVAILABLE" if str(error) == "cooperative lock held" else "RUNTIME_UNAVAILABLE"
            raise _ReadFailure(code) from error
    except _ReadFailure as error:
        return _checked_result(scheduler, task_id, authority=None, failure=error.code)
    except OSError:
        return _checked_result(scheduler, task_id, authority=None, failure="RUNTIME_UNAVAILABLE")
    except (RuntimeError, sqlite3.Error, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return _checked_result(scheduler, task_id, authority=None, failure="INTERNAL_FAILURE")
