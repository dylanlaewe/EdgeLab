#!/usr/bin/env python3
"""Print a sealed historical/runtime binding candidate that always denies."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from src.edgelab.authority_binding import compose_authority_binding, verify_binding_integrity
from src.edgelab.transactional_scheduler import Scheduler
from src.edgelab.validate import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--capture-id", required=True)
    args = parser.parse_args()
    result = compose_authority_binding(
        Scheduler(ROOT, args.runtime_dir),
        args.task_id,
        args.capture_id,
    )
    schema_path = ROOT / "schemas/m0-3a-authority-binding-candidate.v1.schema.json"
    schema = json.loads(schema_path.read_text())
    seal_path = ROOT / "schemas/m0-3a-historical-decision-seal.v1.schema.json"
    seal_schema = json.loads(seal_path.read_text())
    Draft202012Validator(
        schema,
        resolver=RefResolver(
            schema_path.parent.as_uri() + "/",
            schema,
            store={seal_schema["$id"]: seal_schema, seal_path.as_uri(): seal_schema},
        ),
    ).validate(result)
    if not verify_binding_integrity(result):
        raise RuntimeError("authority binding semantic verification failed")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] == "BOUND_DENY_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
