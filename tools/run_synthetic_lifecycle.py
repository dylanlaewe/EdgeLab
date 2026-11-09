#!/usr/bin/env python3
"""Run the local-only M0.3A synthetic lifecycle composition."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.edgelab.synthetic_lifecycle import run_synthetic_lifecycle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runtime-dir",
        required=True,
        type=Path,
        help="new runtime directory outside the repository",
    )
    args = parser.parse_args()
    print(json.dumps(run_synthetic_lifecycle(args.runtime_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
