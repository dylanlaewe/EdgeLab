#!/usr/bin/env python3
"""Capture or compare H-M0-188 fresh synthetic-task context."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.decision_time_context import (
    capture_context,
    compare_context,
    format_human,
)
from src.edgelab.transactional_scheduler import Scheduler, canonical, digest


TASK_ID = "T-SYNTHETIC-001"


def _write(path: Path, value: dict) -> bytes:
    raw = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _fresh_runtime(scheduler: Scheduler) -> None:
    if scheduler.db.exists() or scheduler.attachment.exists():
        scheduler.startup()
        return
    scheduler.initialize()
    initialized = scheduler.create_task(
        TASK_ID,
        digest({"class": "synthetic-non-authorizing-origin", "task_id": TASK_ID}),
        owner="synthetic-director",
    )
    before = initialized["tuple"]
    scheduler.transition(
        "CLAIM",
        TASK_ID,
        {
            "expected": before,
            "repository_generation": before["repository_generation"],
            "receipt_digest": before["decision_receipt_digest"],
            "actor": "synthetic-context-capture",
        },
        operation_key="h-m0-188-claim",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="H-M0-188 decision-time context capture and comparison")
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--runtime-dir", required=True, type=Path)
    capture.add_argument("--output", required=True, type=Path)
    capture.add_argument("--task-id", default=TASK_ID)
    capture.add_argument("--format", choices=("text", "json"), default="text")
    compare = sub.add_parser("compare")
    compare.add_argument("--runtime-dir", required=True, type=Path)
    compare.add_argument("--artifact", required=True, type=Path)
    compare.add_argument("--expected-sha256", required=True)
    compare.add_argument("--output", type=Path)
    compare.add_argument("--format", choices=("text", "json"), default="text")
    demo = sub.add_parser("demo")
    demo.add_argument("--runtime-dir", required=True, type=Path)
    demo.add_argument("--artifact", required=True, type=Path)
    demo.add_argument("--comparison", required=True, type=Path)
    demo.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()

    scheduler = Scheduler(ROOT, args.runtime_dir)
    if args.command == "capture":
        result = capture_context(scheduler, args.task_id)
        raw = _write(args.output, result)
        digest_value = hashlib.sha256(raw).hexdigest()
        payload = {"artifact": result, "artifact_raw_sha256": digest_value}
        print(json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else format_human(result) + "Raw artifact SHA-256: " + digest_value)
        return 0
    if args.command == "compare":
        raw = args.artifact.read_bytes()
        result = compare_context(scheduler, raw, args.expected_sha256)
        if args.output:
            _write(args.output, result)
        print(json.dumps(result, indent=2, sort_keys=True) if args.format == "json" else format_human(result), end="\n" if args.format == "json" else "")
        return 0 if result["status"] == "UNCHANGED_CONTEXT_UNKNOWN_DENY" else 2

    _fresh_runtime(scheduler)
    context = capture_context(scheduler, TASK_ID)
    raw = _write(args.artifact, context)
    expected = hashlib.sha256(raw).hexdigest()
    comparison = compare_context(scheduler, raw, expected)
    _write(args.comparison, comparison)
    payload = {"context": context, "artifact_raw_sha256": expected, "comparison": comparison}
    print(json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else format_human(context) + format_human(comparison) + "Raw artifact SHA-256: " + expected)
    return 0 if comparison["status"] == "UNCHANGED_CONTEXT_UNKNOWN_DENY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
