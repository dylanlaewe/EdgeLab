# H-M0-187 — Authoritative currentness diagnostic

## Outcome

H-M0-187 implements a read-only diagnostic that composes the accepted M0.2
historical-verification path with actual canonical-repository and persisted
Scheduler v1 observations. It advances currentness evidence without claiming a
complete currentness result: the retained result is fixed to
`VALID / UNKNOWN / FAIL / generation_match=false / DENY`.

The diagnostic calls Scheduler startup/replay, `compose_authority_binding`,
`verify_binding_integrity`, `read_locked_authority`, and an independent
canonical-source inventory. It reads and rechecks the repository and locked
runtime observations. It accepts no caller snapshot, receipt, repository root,
source mapping, generation, claim, fence, or verification result.

## Runnable command

The diagnostic itself is read-only. The following creates a disposable actual
H-M0-186 runtime, cold-recovers it after Quant, and uses existing Scheduler v1
operations to add and claim the exact retained historical subject before
running the diagnostic:

```sh
runtime_dir=$(mktemp -d /tmp/edgelab-hm0187.XXXXXX)
rmdir "$runtime_dir"
.venv/bin/python tools/run_recoverable_scheduler_research.py \
  --runtime-dir "$runtime_dir" --interrupt-after QUANT --format text
.venv/bin/python tools/run_recoverable_scheduler_research.py \
  --runtime-dir "$runtime_dir" --resume --format text
.venv/bin/python - "$runtime_dir" <<'PY'
from pathlib import Path
import sys
from src.edgelab.authority_binding import CANONICAL_ROOT
from src.edgelab.transactional_scheduler import Scheduler
s = Scheduler(CANONICAL_ROOT, Path(sys.argv[1]))
s.create_task("T-SYNTHETIC-001", "untrusted-diagnostic-receipt", "synthetic-diagnostic-owner")
c = s.connect(read_only=True)
row = c.execute("select * from tasks where task_id='T-SYNTHETIC-001'").fetchone()
c.close()
s.transition("CLAIM", "T-SYNTHETIC-001", {
    "expected": s.tuple(row),
    "repository_generation": row["repository_generation"],
    "receipt_digest": row["receipt_digest"],
    "actor": "diagnostic-synthetic-worker",
}, operation_key="diagnostic-subject-claim")
PY
.venv/bin/python tools/run_authoritative_currentness_diagnostic.py \
  --runtime-dir "$runtime_dir" --format text
```

The setup writes only to the disposable runtime. The diagnostic performs no
runtime or repository mutation.

## Trusted sources actually read

The closed result identifies nine exact source projections:

1. byte-pinned `docs/M0.3A_AUTHORITY_SOURCE_MAPPING.v1.md`;
2. self-verified `docs/M0.2_STAGE1_TRUST_ROOT.v1.json`;
3. self-verified `docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json`;
4. the selected authentic Stage-1 capture sidecar;
5. its verified persisted-graph digest;
6. the current canonical Scheduler bundle source inventory;
7. `docs/project-state.json` bytes;
8. the complete `reports/stops/*.json` inventory; and
9. the twice-read locked Scheduler authority digest.

The retained run observes implementation commit
`0baa73938595c1f1edef260d0beb687e80eea293`, the canonical origin remote,
83 versioned STOP files, and these active OPEN records:

- `STOP-M0-001.v1`;
- `STOP-M0-3A-001.v1`;
- `STOP-M0-3A-002.v81`.

The historical capture resolves `T-SYNTHETIC-001`, attempt 1. The actual
persisted subject is the same task/attempt with one active synthetic claim at
fence 1. The task's receipt string is retained as observed data but explicitly
classified unauthenticated.

## Verified versus unknown dimensions

Ten dimensions are verified within their bounded meaning:

- accepted historical replay and raw-result match;
- historical task/attempt binding to the locked subject;
- canonical root, remote, HEAD, source inventory, and Scheduler bundle;
- current project-state source bytes;
- complete current STOP inventory and active OPEN references;
- attachment/runtime binding;
- Scheduler replay/materialization coherence;
- task and attempt-history coherence;
- claim/fence coherence; and
- current runtime/task repository-generation coherence.

Six security-critical comparisons remain `UNKNOWN` because the accepted source
mapping does not define them:

- historical-to-current project and STOP equality;
- assignment and handoff head equality;
- dependency and capability equality;
- historical-to-current Git reachability equality;
- authenticated M0.2 receipt/input-bundle binding; and
- historical-to-runtime generation equality.

Current coherence does not fill these gaps. In particular, current repository
generation agreement is not historical generation equality.

## Failure and race evidence

Focused tests reject missing historical evidence, task substitution, attempt
change, stale imported repository generation, repository/STOP substitution,
missing required mapping, changed runtime state between observation and
recheck, changed repository evidence between reads, and upstream positive
authority substitution.

The returned artifact is also closed semantically. Its verifier checks the
accepted authority-binding integrity, authority digest, task/capture/attempt
and bundle equations, exact 16 dimension records and 10/6 partitions, nine
trusted-source projections, exact limitations/invalidators, and result digest.
Resealed attacks adding nested `authorization=ALLOW`, promoting an unknown
dimension, substituting the mapping locator/digest, rewriting limitations, or
rewriting invalidators all reject.

## Tests and independent review

- Corrected focused H-M0-187 suite: 11/11 passed in 28.986 seconds.
- Final H-M0-187 plus H-M0-186/H-M0-184/H-M0-183/H-M0-179/Scheduler v1
  preservation matrix: 103/103 passed in 99.017 seconds.
- Independent reviewer reproduced 11/11 in 28.497 seconds, an actual cold Quant
  recovery, the CLI result, all five resealed attacks, and `git diff --check`.
- Production repository validation passed 622 governed records before
  completion records.
- Completion-tree production validation passed 624 governed records and
  published history at the actual clock.

Initial review found that generic nested result objects allowed resealed
semantic substitutions. The first correction added closed current-observation
schemas and semantic integrity equations. Re-review then found two unbound
explanatory lists; exact limitations and invalidators were added. Final
read-only re-review returned PASS with no remaining demonstrated defect. This
is engineering review only, not formal 05 Skeptic approval.

The retained result raw SHA-256 is
`30b446c11b430b4e74c17c83162861c799cfebaa1e9ad4f586bd84bd08948d26`;
its internal digest is
`eaa38ed022b57161867c91ac2dc1b73c245d24ba8b4244ed5e3a6c7742dc12d1`.

## Remaining authenticated R-gate requirements

An authenticated R-gate still requires a separately accepted contract that:

1. maps every project, STOP, assignment, handoff, dependency, capability,
   inventory, Git/reachability, and generation field from authoritative current
   sources into the historical binding;
2. defines an immutable authenticated M0.2 receipt and exact input bundle,
   replacing Scheduler v1's caller-supplied receipt string;
3. defines atomic repository/runtime resolution and generation recheck for the
   complete snapshot, including conflict and missing-source semantics;
4. defines the comparison equations and consumer transition that may return
   `CURRENT`, `PASS`, generation match, and `ALLOW` only when every required
   dimension succeeds; and
5. receives the required owner authorization, independent authenticated review,
   and applicable STOP clearance before any scheduler transition consumes it.

No such authority is inferred here. Data remains `BLOCKED`; all STOPs remain
`OPEN`; M0 remains blocked; M1 remains unreleased; executor remains
`MOCK_ONLY`; live remains `LOCKED`; kill remains `ENGAGED`; deployable capital
remains `$0.00`.
