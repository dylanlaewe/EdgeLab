# H-M0-083 native engineering review — v1

## Boundary

This records the separate read-only native engineering review of the runnable
developer alpha. It is not formal Skeptic/project approval, does not clear a
STOP, release Data, authorize a lifecycle transition, or permit paper/live or
capital activity.

- Writer: `/root`
- Reviewer: `/root/alpha_reviewer`
- Claim commit: `d728fca0b56f2f3d446673c97520f0a9fef615e5`
- Reviewed implementation: `2372a7c213844e653da4c5c29783094fa5210e63`

## Round one findings

The reviewer found two actionable defects in the actual working-tree candidate:

1. **HIGH — output path safety.** `--output` unconditionally used
   `Path.write_text`, so a caller could replace a governed repository artifact.
2. **MEDIUM — current STOP selection.** The report filtered all historical OPEN
   versions instead of selecting each STOP's highest numeric version.

The reviewer made no edits. The sole writer accepted both findings.

## Repairs

The writer added exclusive output creation outside the resolved repository
root, with explicit rejection of repository paths, aliases and existing files.
Focused tests cover direct targets, file aliases, outside creation and attempted
overwrite.

STOP processing now validates unique artifact paths and `(id, version)` pairs,
filename/identity agreement, positive numeric versions and contiguous version
history, then selects the maximum version for each ID before determining OPEN
heads. A resolved-successor regression proves an OPEN predecessor is not
reported as current.

## Round two reproduction

The reviewer independently reproduced:

- direct repository and symlinked-parent/target aliases deny with exit 2 and no
  write;
- an outside target is created once and a second write denies without changing
  its bytes;
- STOP-M0-001 v1 OPEN plus v2 RESOLVED reports only the other current OPEN STOP;
- duplicate identities and version gaps deny;
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest -v
  tests.test_alpha`: 8 tests passed;
- `compileall` and `git diff --check`: passed;
- current text/JSON output retained all non-authorization boundaries.

## Disposition

**ACCEPTED for the bounded H-M0-083 native engineering scope after repair.** No
remaining actionable engineering defect was reported. Formal Skeptic and
project approval remain separate.
