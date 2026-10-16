#!/usr/bin/env python3
"""Print a diagnostic DENY-only authority observation for one runtime task."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from src.edgelab.locked_authority import read_locked_authority
from src.edgelab.transactional_scheduler import Scheduler
from src.edgelab.validate import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args()
    result = read_locked_authority(Scheduler(ROOT, args.runtime_dir), args.task_id)
    schema = json.loads((ROOT / "schemas/m0-3a-locked-authority-read.v1.schema.json").read_text())
    Draft202012Validator(schema).validate(result)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["observation_status"] == "COHERENT_DENY_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
