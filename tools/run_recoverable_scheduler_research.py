#!/usr/bin/env python3
"""Create or cold-resume the H-M0-186 local synthetic workflow."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.recoverable_scheduler_research import (
    INTERRUPTION_POINTS,
    format_human,
    run_recoverable_scheduler_research,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or cold-resume deterministic scheduler research"
    )
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="open an existing runtime through Scheduler.startup/replay",
    )
    parser.add_argument(
        "--interrupt-after",
        choices=INTERRUPTION_POINTS,
        help="end this process after the named transition is durable",
    )
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args()
    result = run_recoverable_scheduler_research(
        args.runtime_dir,
        resume=args.resume,
        interrupt_after=args.interrupt_after,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_human(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
