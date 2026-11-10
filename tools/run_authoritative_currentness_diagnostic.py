#!/usr/bin/env python3
"""Run the read-only H-M0-187 currentness diagnostic."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.authoritative_currentness_diagnostic import (
    DEFAULT_CAPTURE_ID,
    DEFAULT_TASK_ID,
    diagnose_authoritative_currentness,
    format_human,
)
from src.edgelab.transactional_scheduler import Scheduler


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only historical/current authority diagnostic"
    )
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID)
    parser.add_argument("--capture-id", default=DEFAULT_CAPTURE_ID)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args()
    scheduler = Scheduler(ROOT, args.runtime_dir)
    result = diagnose_authoritative_currentness(
        scheduler, args.task_id, args.capture_id
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_human(result), end="")
    return 0 if result["status"] == "COHERENT_UNKNOWN_DENY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
