#!/usr/bin/env python3
"""Run the retained H-M0-183 fictional scientific experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.synthetic_research_experiment import (
    format_human,
    run_synthetic_research_experiment,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a deterministic local-only fictional EdgeLab experiment"
    )
    parser.add_argument(
        "--runtime-dir",
        required=True,
        type=Path,
        help="new runtime directory outside the repository",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args()
    result = run_synthetic_research_experiment(args.runtime_dir)
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_human(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
