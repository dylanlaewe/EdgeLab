# H-M0-184 — Scheduler-coordinated synthetic research

## Outcome

H-M0-184 moves the retained H-M0-183 fictional scientific stages inside actual
H-M0-179 transactional-scheduler task windows. It does not add an executor,
agent framework, operational authority, formal review, or new scheduler state.
The final result remains `INSUFFICIENT_DATA`; all authority remains `DENY`.

Runnable command:

```sh
runtime_dir=$(mktemp -d /tmp/edgelab-hm0184.XXXXXX)
rmdir "$runtime_dir"
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_scheduler_coordinated_research.py --runtime-dir "$runtime_dir" --format text
```

Use `--format json` for the closed machine-readable result.

## Actual scheduler-driven stages

The scheduler initializes and claims `T-SYNTHETIC-SCIENCE-PIPELINE-001`, then
records the following replay-verified events:

1. `TASK_CONTINUED` at task sequence 4 binds the exact Research input package
   and preregistration output digest.
2. `TASK_CONTINUED` at sequence 5 binds the Research digest as Data input and
   the validated timestamped synthetic Data digest as output.
3. `TASK_CONTINUED` at sequence 6 binds the Data digest as Quant input and the
   exact H-M0-183 Quant result digest as output.
4. `TASK_COMPLETED` binds the same Quant digest.
5. `REVIEW_ASSIGNED` creates a distinct active `synthetic-skeptic` assignment
   with role `05 Skeptic synthetic non-formal`.
6. The adversarial calculation runs while that task is actually `REVIEWING`;
   `REVIEW_APPROVED` binds the exact synthetic challenge digest. Approval means
   the scheduler recorded the correctness of the `INSUFFICIENT_DATA` conclusion,
   not that a strategy, governance decision, or formal Skeptic review passed.
7. `DIRECTOR_ROUTED` binds the Quant/Skeptic route digest for downstream local
   consideration.

Only after the exact pipeline history replays and matches does the coordinator
create and claim `T-SYNTHETIC-SCIENCE-RISK-001`. Its task-origin receipt binds
the complete stable pipeline-history digest plus exact Quant and Skeptic
digests. Risk evaluates while its task is `IN_PROGRESS`, then closes with its
DENY evidence digest.

Only after that history replays does the coordinator create and claim
`T-SYNTHETIC-SCIENCE-DIRECTOR-001`. Its receipt binds the Risk-history, Risk-
evidence, and pipeline-history digests. Director evaluates while its task is
`IN_PROGRESS`, records `INSUFFICIENT_DATA`, and closes with the exact conclusion
digest.

The final stable histories contain 10 pipeline events, 4 Risk events, and 4
Director events. Scheduler replay passes after every dependency boundary and at
completion. Random runtime identities are excluded from the deterministic
scientific projection.

## Scientific evidence and adversarial behavior

H-M0-184 reuses H-M0-183's input and scientific functions and requires every
stage record to equal the retained H-M0-183 stage before it can be recorded.
The result remains 12 fictional observations, a 7-5 record, `2.180000` fictional
units net, `0.181667` ROI, and a 95% Wilson interval of `0.319511`–`0.806740`.
The sample remains below the preregistered minimum of 20 and uncertainty
contains the cost-adjusted break-even rate. The future-leakage negative control
is rejected. No real edge is demonstrated.

Focused attacks prove:

- missing Data history prevents the Risk task from being created;
- altered Quant output rejects before a Quant scheduler event is recorded;
- future-leaking Data prevents Data and all later stages;
- an inconsistent synthetic review digest fails the pipeline-history check;
- Risk and Director run only inside claimed `IN_PROGRESS` tasks;
- the synthetic Skeptic runs only inside its active `REVIEWING` assignment;
- a missing result schema fails before runtime creation;
- task-event mutation is rejected by scheduler replay;
- repeat direct and CLI runs reproduce the retained result exactly.

The retained result SHA-256 is
`10e0585d5193fb166d51aa587109b4bf9f22e5ad5dae9a57ec112da71c51c06d`.

## Exact scheduler limitation

Scheduler v1 has no native general prerequisite/dependency edge and no typed
scientific-evidence table. H-M0-184 therefore uses only existing supported
mechanisms: event payloads, continuation order, claims, native review history,
task-origin receipt strings, locked-authority observations, export, and replay.
The coordinator computes and verifies content-bound downstream receipts, but
the scheduler itself does not interpret them as a general dependency graph.
Remediation links are not misused. This limitation is explicit in the result and
no stronger scheduler capability is claimed.

## Validation and review

- Focused H-M0-184 suite: 13/13 passed in 19.740 seconds; read-only reviewer
  reproduced 13/13 in 17.944 seconds.
- Final combined H-M0-184, H-M0-183, H-M0-179, transactional scheduler,
  locked-authority, and authority-binding suites: 80/80 passed in 58.428 seconds.
- Independent reviewer separately reproduced H-M0-179/H-M0-183 preservation:
  18/18 passed.
- Fresh JSON CLI output matched the retained result exactly.
- Production validation passed 613 governed records before completion records;
  M0 capital remained LOCKED and no scientific or operational approval was
  granted.
- `compileall` and `git diff --check` passed.

Initial engineering review found that the synthetic Skeptic calculation ran in
`REVIEW_PENDING` before assignment. The implementation was corrected so the
calculation occurs during a live `REVIEWING` assignment. Re-review independently
observed that state, one active synthetic reviewer, and no downstream task, and
returned PASS with no remaining demonstrated defect. This is engineering review
only, not formal 05 Skeptic approval.

Data remains `BLOCKED`; every STOP remains `OPEN`; M0 remains blocked; M1
remains unreleased; executor remains `MOCK_ONLY`; public authorization remains
`DENY`; live remains `LOCKED`; kill remains `ENGAGED`; deployable capital
remains `$0.00`.
