#!/usr/bin/env python3
"""Verify a complete historical test log against a reviewed outcome baseline.

This tool does not turn the historical tier into a green gate.  A successful
verification means only that every observed module, count, exit status, and
non-pass identity and diagnostic matches the explicitly reviewed baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

if __package__ in {None, ""}:
    from run_test_tier import HISTORICAL_MODULES, ROOT
else:
    from tools.run_test_tier import HISTORICAL_MODULES, ROOT


BASELINE = ROOT / "tests" / "fixtures" / "historical-outcomes.v1.json"
ALLOWED_DISPOSITIONS = {
    "PASS",
    "REVIEWED_PRESERVED_RED",
    "REVIEWED_CURRENT_TREE_COUPLING",
    "REVIEWED_MIXED_RED",
}
HEADER = re.compile(r"^\[(\d+)/(\d+)\] (tests\.[A-Za-z0-9_]+)$", re.MULTILINE)
RAN = re.compile(r"^Ran (\d+) tests? in [^\n]+$", re.MULTILINE)
FINAL = re.compile(r"^(OK(?: \([^\n]+\))?|FAILED(?: \([^\n]+\))?)$", re.MULTILINE)
TRACEBACK = re.compile(
    r"^=+\n(FAIL|ERROR): (.*?)\n-+\n(.*?)"
    r"(?=^=+\n(?:FAIL|ERROR): |^-+\nRan )",
    re.MULTILINE | re.DOTALL,
)


class HistoricalOutcomeError(RuntimeError):
    """The observation or baseline is incomplete, malformed, or mismatched."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _diagnostic_sha256(diagnostic: str) -> str:
    normalized = diagnostic.replace(str(ROOT.resolve()), "<ROOT>")
    normalized = "\n".join(line.rstrip() for line in normalized.strip().splitlines())
    return sha256_bytes(normalized.encode("utf-8"))


def _summary_counts(summary: str) -> dict[str, int]:
    counts = {
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    if "(" not in summary:
        return counts
    details = summary.split("(", 1)[1].rsplit(")", 1)[0]
    aliases = {
        "failures": "failures",
        "errors": "errors",
        "skipped": "skipped",
        "expected failures": "expected_failures",
        "unexpected successes": "unexpected_successes",
    }
    for item in details.split(", "):
        name, separator, raw_count = item.rpartition("=")
        if not separator or name not in aliases or not raw_count.isdigit():
            raise HistoricalOutcomeError(f"Unsupported unittest summary field: {item!r}")
        counts[aliases[name]] = int(raw_count)
    return counts


def parse_observation(text: str) -> list[dict[str, Any]]:
    """Parse the combined stdout/stderr from one complete historical run."""
    banner = f"EdgeLab test tier: historical ({len(HISTORICAL_MODULES)} isolated modules)"
    if text.count(banner) != 1:
        raise HistoricalOutcomeError("Exact historical tier banner is missing or duplicated")
    headers = list(HEADER.finditer(text))
    expected_modules = list(HISTORICAL_MODULES)
    observed_modules = [match.group(3) for match in headers]
    if observed_modules != expected_modules:
        raise HistoricalOutcomeError(
            "Historical module order or completeness mismatch: "
            f"expected {expected_modules!r}, observed {observed_modules!r}"
        )
    if any(int(match.group(1)) != index for index, match in enumerate(headers, 1)):
        raise HistoricalOutcomeError("Historical module indices are not contiguous")
    if any(int(match.group(2)) != len(expected_modules) for match in headers):
        raise HistoricalOutcomeError("Historical module totals do not match the manifest")

    outcomes: list[dict[str, Any]] = []
    for index, match in enumerate(headers):
        module = match.group(3)
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        segment = text[match.end():end]
        ran = RAN.findall(segment)
        finals = FINAL.findall(segment)
        trailers = re.findall(
            rf"^{re.escape(module)}: exit (-?\d+) in [^\n]+$", segment, re.MULTILINE
        )
        if len(ran) != 1 or len(finals) != 1 or len(trailers) != 1:
            raise HistoricalOutcomeError(
                f"{module} must contain exactly one test count, final summary, and exit trailer"
            )
        counts = _summary_counts(finals[0])
        exit_code = int(trailers[0])
        if (finals[0].startswith("OK")) != (exit_code == 0):
            raise HistoricalOutcomeError(f"{module} summary and exit code disagree")
        nonpasses = [
            {
                "outcome": outcome,
                "test_identity": identity,
                "diagnostic_sha256": _diagnostic_sha256(diagnostic),
            }
            for outcome, identity, diagnostic in TRACEBACK.findall(segment)
        ]
        if sum(counts[name] for name in ("failures", "errors")) != len(nonpasses):
            raise HistoricalOutcomeError(
                f"{module} failure/error count does not match traceback identities"
            )
        outcomes.append(
            {
                "module": module,
                "tests": int(ran[0]),
                "exit_code": exit_code,
                **counts,
                "nonpasses": nonpasses,
            }
        )
    nonzero = [(record["module"], record["exit_code"]) for record in outcomes if record["exit_code"]]
    aggregate = re.findall(
        r"^Tier historical completed with failures in [^\n]+:\n"
        r"((?:  tests\.[A-Za-z0-9_]+: exit -?\d+\n)+)",
        text,
        re.MULTILINE,
    )
    if nonzero:
        if len(aggregate) != 1:
            raise HistoricalOutcomeError("Historical aggregate failure summary is missing or duplicated")
        aggregate_outcomes = [
            (module, int(exit_code))
            for module, exit_code in re.findall(
                r"^  (tests\.[A-Za-z0-9_]+): exit (-?\d+)$",
                aggregate[0],
                re.MULTILINE,
            )
        ]
        if aggregate_outcomes != nonzero:
            raise HistoricalOutcomeError("Historical aggregate failure summary disagrees with modules")
    elif not re.search(r"^Tier historical passed: \d+ modules in [^\n]+$", text, re.MULTILINE):
        raise HistoricalOutcomeError("Historical aggregate pass summary is missing")
    return outcomes


def load_baseline(path: Path = BASELINE) -> dict[str, Any]:
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HistoricalOutcomeError(f"Cannot read historical baseline: {error}") from error
    if baseline.get("schema_version") != 1:
        raise HistoricalOutcomeError("Unsupported historical baseline schema")
    records = baseline.get("module_outcomes")
    if not isinstance(records, list) or len(records) != len(HISTORICAL_MODULES):
        raise HistoricalOutcomeError("Historical baseline has incomplete module outcomes")
    modules = [record.get("module") for record in records if isinstance(record, dict)]
    if modules != list(HISTORICAL_MODULES):
        raise HistoricalOutcomeError("Historical baseline module order differs from manifest")
    if baseline.get("total_modules") != len(records):
        raise HistoricalOutcomeError("Historical baseline total_modules is inconsistent")
    integer_fields = (
        "tests",
        "exit_code",
        "failures",
        "errors",
        "skipped",
        "expected_failures",
        "unexpected_successes",
    )
    for record in records:
        expected_path = f"tests/{record['module'].rsplit('.', 1)[1]}.py"
        if record.get("source_path") != expected_path:
            raise HistoricalOutcomeError(
                f"Historical baseline source path is invalid for {record.get('module')}"
            )
        if any(type(record.get(field)) is not int for field in integer_fields):
            raise HistoricalOutcomeError(
                f"Historical baseline has invalid numeric fields for {record.get('module')}"
            )
        if record["tests"] <= 0:
            raise HistoricalOutcomeError(
                f"Historical baseline cannot accept a zero-test module: {record.get('module')}"
            )
        if record["exit_code"] not in {0, 1}:
            raise HistoricalOutcomeError(
                f"Historical baseline has an unsupported exit code for {record.get('module')}"
            )
        if not isinstance(record.get("nonpasses"), list):
            raise HistoricalOutcomeError(
                f"Historical baseline nonpasses are invalid for {record.get('module')}"
            )
        if record["failures"] + record["errors"] != len(record["nonpasses"]):
            raise HistoricalOutcomeError(
                f"Historical baseline nonpass count is inconsistent for {record.get('module')}"
            )
        for nonpass in record["nonpasses"]:
            if (
                not isinstance(nonpass, dict)
                or nonpass.get("outcome") not in {"FAIL", "ERROR"}
                or not isinstance(nonpass.get("test_identity"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(nonpass.get("diagnostic_sha256")))
            ):
                raise HistoricalOutcomeError(
                    f"Historical baseline has an invalid nonpass identity for {record.get('module')}"
                )
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("source_sha256"))):
            raise HistoricalOutcomeError(
                f"Historical baseline source hash is invalid for {record.get('module')}"
            )
        disposition = record.get("review_disposition")
        if disposition not in ALLOWED_DISPOSITIONS:
            raise HistoricalOutcomeError(
                f"Unsupported review disposition for {record.get('module')}: {disposition!r}"
            )
        if (record.get("exit_code") == 0) != (disposition == "PASS"):
            raise HistoricalOutcomeError(
                f"Review disposition contradicts exit status for {record.get('module')}"
            )
        if not isinstance(record.get("review_note"), str) or not record["review_note"]:
            raise HistoricalOutcomeError(
                f"Historical baseline review note is missing for {record.get('module')}"
            )
    if baseline.get("total_tests") != sum(record["tests"] for record in records):
        raise HistoricalOutcomeError("Historical baseline total_tests is inconsistent")
    if baseline.get("nonzero_modules") != sum(record["exit_code"] != 0 for record in records):
        raise HistoricalOutcomeError("Historical baseline nonzero_modules is inconsistent")
    runner = baseline.get("runner")
    capture = baseline.get("capture")
    if (
        not isinstance(runner, dict)
        or runner.get("path") != "tools/run_test_tier.py"
        or not re.fullmatch(r"[0-9a-f]{64}", str(runner.get("sha256")))
        or not isinstance(capture, dict)
        or not re.fullmatch(r"[0-9a-f]{64}", str(capture.get("log_sha256")))
    ):
        raise HistoricalOutcomeError("Historical baseline runner or capture metadata is invalid")
    return baseline


def _outcome_projection(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "module",
        "tests",
        "exit_code",
        "failures",
        "errors",
        "skipped",
        "expected_failures",
        "unexpected_successes",
        "nonpasses",
    )
    return [{field: record.get(field) for field in fields} for record in records]


def verify_current_sources(baseline: dict[str, Any], root: Path = ROOT) -> None:
    expected_runner = baseline.get("runner", {})
    runner_path = root / expected_runner.get("path", "")
    if not runner_path.is_file() or sha256_file(runner_path) != expected_runner.get("sha256"):
        raise HistoricalOutcomeError("Current tier runner differs from the audited runner")
    for record in baseline["module_outcomes"]:
        path = root / record.get("source_path", "")
        if not path.is_file() or sha256_file(path) != record.get("source_sha256"):
            raise HistoricalOutcomeError(
                f"Current historical test source differs from audit: {record['module']}"
            )


def verify_source_commit(baseline: dict[str, Any], root: Path = ROOT) -> None:
    commit = baseline.get("source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise HistoricalOutcomeError("Baseline source_commit is not a full commit SHA")
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise HistoricalOutcomeError(f"Baseline source commit is unavailable: {commit}")
    sources = [baseline["runner"], *baseline["module_outcomes"]]
    for source in sources:
        path = source.get("path", source.get("source_path"))
        expected_hash = source.get("sha256", source.get("source_sha256"))
        result = subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if result.returncode or sha256_bytes(result.stdout) != expected_hash:
            raise HistoricalOutcomeError(
                f"Audited source hash does not match source_commit: {path}"
            )


def verify(
    log_path: Path,
    *,
    baseline_path: Path = BASELINE,
    exact_capture: bool = False,
) -> dict[str, Any]:
    baseline = load_baseline(baseline_path)
    verify_source_commit(baseline)
    raw = log_path.read_bytes()
    if exact_capture and sha256_bytes(raw) != baseline.get("capture", {}).get("log_sha256"):
        raise HistoricalOutcomeError("Log bytes differ from the reviewed exact capture")
    observed = parse_observation(raw.decode("utf-8"))
    expected = baseline["module_outcomes"]
    if _outcome_projection(observed) != _outcome_projection(expected):
        raise HistoricalOutcomeError("Historical outcomes differ from the reviewed baseline")
    if sum(record["tests"] for record in observed) != baseline.get("total_tests"):
        raise HistoricalOutcomeError("Historical total test count differs from baseline")
    verify_current_sources(baseline)
    return baseline


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Combined stdout/stderr from the historical tier")
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument(
        "--exact-capture",
        action="store_true",
        help="Require the raw log hash recorded during baseline review",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        baseline = verify(
            args.log,
            baseline_path=args.baseline,
            exact_capture=args.exact_capture,
        )
    except (HistoricalOutcomeError, OSError, UnicodeDecodeError) as error:
        print(f"Historical outcome verification denied: {error}", file=sys.stderr)
        return 1
    nonzero = sum(record["exit_code"] != 0 for record in baseline["module_outcomes"])
    print(
        "Historical outcomes match the reviewed non-green baseline: "
        f"{len(baseline['module_outcomes'])} modules, {baseline['total_tests']} tests, "
        f"{nonzero} reviewed nonzero modules."
    )
    print("This verification is not a green test result or an approval authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
