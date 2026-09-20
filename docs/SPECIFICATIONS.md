# Record specifications — version 1

All JSON records include `schema_version: 1`; scientific entities use immutable `(id, version)` identities. Schemas disallow undeclared fields and require every defined field. Explicit `null` means unknown/not applicable only where allowed; record the reason in the relevant narrative field. Timestamp fields require RFC 3339 offsets; persist UTC for new records. IDs/references must never be reused for different evidence. JSON Schema validation alone does not establish truth, independence or eligibility.

| Record | Location | Contract and additional semantics |
|---|---|---|
| Source | `data/sources/` | `source.schema.json`: identity, access evidence, URL, terms review, coverage, timestamps, reliability, costs, rate limits, restrictions and unknowns. PERMITTED requires documented permission for each intended use, reviewed before ingestion and again after terms change. No sources are pre-approved. |
| Hypothesis | `research/hypotheses/` | `hypothesis.schema.json`: all preregistration fields, costs, multiple-testing plan and unresolved thresholds. Freeze before results access; unknown thresholds block confirmation. Supersession never overwrites a failed version. |
| Experiment | `research/experiments/` | `experiment.schema.json`: mode, frozen protocol, exact hypothesis, dataset manifests, commit/config/environment, seed/explanation, splits, trial inventory, costs, diagnostics and failures. CONFIRMATORY requires a registered hypothesis, no unresolved thresholds and protocol frozen before execution. Evidence of first results access must eventually be independently auditable; dates asserted in JSON alone are insufficient. Null result artifacts are allowed for pending runs only. |
| Strategy | `strategies/` | `strategy.schema.json`: exact hypothesis, state, experiments, reviews, transition events, policy and STOP references. State is a materialized view of accepted events, never an authorization by itself. Non-IDEA requires a hypothesis. |
| Audit | `reports/audit/` | `audit.schema.json`: actor/role, subject version, timestamp, event type, before/after, rationale, evidence, code/config and correlation ID. One file per event; corrections supersede. Git is reviewable but not tamper-proof; durable authenticated append-only storage is unresolved. |
| Handoff | `docs/handoffs/` | `handoff.schema.json`: full request, outcome, test evidence, blockers, recipient and acceptance criteria. Claim and completion create versions. |
| STOP | `reports/stops/` | `stop.schema.json`: scope, severity, evidence, remediation and resolution reference. OPEN blocks affected dependents transitively. Resolution needs independent evidence under operating rules. |
| Bankroll | `portfolio/bankroll.json` | `bankroll.schema.json`: USD integer minor units, conceptual total 5000, deployable/reserved 0, LOCKED. Paper balance is null until separately approved paper initialization. No deposit or live balance is claimed. |
| Risk | `portfolio/risk-policy.json` | `risk-policy.schema.json`: M0 immutable safety constraints, zero live limits, engaged kill switch, unresolved policy decisions and all thirteen capital gates. Zero limits implement prohibition, not empirically chosen sizing. |

## Data lineage contract (specification; validator pending)

A dataset manifest must contain dataset ID/version, source ID/version, source URL/endpoint, retrieval timestamp, publication/event timestamps (nullable with reason), immutable snapshot location and SHA-256, parser and normalization versions, transformation code/config, row count, quality report, corrections/supersession and parent manifest hashes. Observation lineage separates `source_claim`, `observed_fact`, `inference` (method/version), and `settled_outcome`.

For each decision input record `available_at`, its evidence, and `decision_at`; enforce `available_at <= decision_at`. A later retrieval does not prove earlier availability. Unknown availability disqualifies confirmation. Feature manifests include the latest availability among their inputs and the point-in-time join policy. Keep closing prices, outcomes and later corrections in separate evaluation inputs. No dataset is currently eligible; Data owns implementation and adversarial fixtures.

## Reproducibility and evaluation contract

Snapshot the full trial inventory including discarded and failed runs. Freeze population, train/validation/test and temporal boundaries, information cutoff, metrics, sample expectations, rejection rules, cost assumptions and sensitivity plan. Reproduction requires immutable inputs and exact environment, commit, configuration and seed (or deterministic justification). Costs address vig, commissions, spreads, slippage, delay, rejections, limits, liquidity, minimum sizes and unavailable quotes where applicable, with explicit not-applicable rationales.

Report sample count, odds/implied and break-even probabilities, ROI, EV estimates, CLV, calibration, uncertainty, variance, volatility, drawdown, risk-adjusted results, out-of-sample/walk-forward/forward behavior, sensitivity and regime stability as applicable. Missing metrics retain explanations, never invented numbers. Thresholds require methodological justification and preregistration; M0 supplies none.

## Accounting and risk contract (future implementation)

Model ledger entries as immutable signed integer minor-unit movements with unique idempotency keys, timestamp, currency, source, evidence and reconciliation state. Reserved capital cannot exceed reconciled cash; available capital accounts for pending positions and remains zero while locked. Never mix paper and live ledgers. Rounding and settlement corrections need explicit policy and compensating entries, not historical edits.

Before future deployment, Risk must define position/daily/strategy/correlated/source exposure, drawdown and sizing policy; source duplication and correlated markets cannot count as diversification. Freshness, price tolerances, settlement health, strategy drift and execution failure limits must have justified values and tests. Unknown critical limits deny deployment. Loss-chasing sizing is prohibited.

## Data remediation contracts — H-M0-003 v4

The earlier pending Data section is implemented by `src/edgelab/data_integrity.py`
and the availability, permission, membership, observation, feature and manifest
schemas (each schema_version 1). Existing nine schemas and published originals
remain unchanged. These contracts validate synthetic engineering evidence; they
confer no confirmation, paper, source acquisition or operational approval.

- Typed references carry canonical repository path, kind, ID, version and byte
  SHA-256. The referenced registry, filename, identity, schema and digest must
  agree. Missing files, aliases/symlinks, escapes and wrong types reject. Blobs
  carry path, media type and byte SHA-256; code/configuration are inert inputs.
- All versioned registries require `[A-Za-z0-9][A-Za-z0-9_-]*` IDs and
  `<id>.v<version>.json` filenames. Versions start at 1 with no gaps. Singleton
  portfolio configuration is exempt from versioned filenames. Audit/hypothesis
  corrections require same-ID previous-version supersession; new Data records
  also bind that predecessor's digest. Graphs reject orphans and cycles.
- Legacy handoff dependency IDs are checked as an acyclic assignment graph.
  They are not an exact prerequisite release: downstream claims must still cite
  the completed handoff version and full landing SHA required by Git protocol.
- Observations bind source/version/URL, raw snapshot, parser/normalizer code and
  versions, config, retrieved/publication/event/correction times, classification,
  and value. Unknown timestamps retain a reason. Availability evidence binds the
  exact raw digest and source. Capture time cannot prove earlier availability;
  archived-publication evidence requires a stored snapshot, but its external
  truth still requires independent review. Later corrections/publications cannot
  masquerade as earlier available facts or precede their own retrieval.
- Features use `as_of`, exact parent hashes, code/config/version and latest input
  availability. Unknown availability propagates. Closing prices and settled
  outcomes are evaluation-only, including through feature ancestry. Decision
  manifests reject unknown/late availability and evaluation inputs/parents.
- Manifests bind inputs, canonical membership, decision time, snapshot and quality
  report. Ordered snapshot rows must equal `{sample, value}` reconstructed from
  membership and inputs; counts must agree. This verifies assembly, not arbitrary
  transform execution. The frozen synthetic fixture and positive test explicitly
  execute only test-authored parser/normalizer code. Validators never execute
  artifact-supplied commands. Quant owns general reproduction bundles.
- Membership digests hash sorted canonical JSON sample keys containing namespace,
  event_id and outcome_id, independently of dataset names. `sample_keys` exposes
  intersections for Research/Quant. Input entity identities must be canonicalized
  upstream; undisclosed aliasing or falsified namespace assignments cannot be
  inferred from JSON alone. Quant owns exposure/overlap eligibility decisions.
- `registry_checks` returns exact record-path → parent-path sets for Data typed
  references, supersession and experiment manifests. `quarantine` accepts only
  `{kind: records, targets: [exact paths]}` or `{kind: global, targets: []}` and
  propagates transitively, retaining previous quarantine. Missing scope rejects.
  This primitive does not reinterpret legacy free-text STOP scopes or clear
  anything. Risk owns complete operational graph construction, authoritative STOP
  reduction, explicit descendant release, and eligibility. H03 remains open.
- Completed observed times are checked against an injectable aware `now` (UTC
  current time by default), with zero positive skew allowance. Scheduled event
  times and permission expiry may be future. Old conceptual declarations remain
  valid history; they do not establish fresh operational funds. Risk owns
  justified operational freshness rules.
- PERMITTED sources need typed permission records binding source/version/URL,
  exact reviewed terms snapshot, review time, validity interval and intended uses.
  Unknown/denied, expired, altered, missing or mismatched evidence rejects. This
  is substantiation, not authenticated legal review or permission to ingest.
  Terms changes require a new source/permission version and review; unseen remote
  terms changes and forged evidence are not detected without external monitoring.
- Project-state schema validates the current summary shape, nonnegative counts
  and LOCKED capital state. It is not an event-derived state reducer. Risk owns
  reconciliation and Director alone owns the real summary updates.

### Published-history boundary and downstream API

`verify_history(root, baseline, expected_inventory=None)` requires a verifier-
selected full Git commit SHA. No HEAD/ref fallback is accepted. It compares every
published byte under reports/, docs/handoffs/, schemas/, research/, strategies/
and data/ with the candidate; deletions/mutations reject. New records may append.
The initial pinned reference is
`4e99cfac90e0af601158c1528c70574dd5dafeda`, a preservation baseline, not approval.

`history_inventory` returns path → SHA-256 at that commit. `verify_checkpoint`
requires the verifier's independently accepted checkpoint digest and predecessor
digest, binds its baseline and inventory, and verifies preservation. Checkpoints
are never auto-accepted. The verifier must establish predecessor continuity and
external acceptance before supplying those trusted values. Without that boundary,
assurance is unavailable and acceptance must deny. A shared-account writer can
change the verifier or its chosen baseline; these APIs do not resist OS compromise,
collusion or forged externally asserted facts. No protected operational baseline
or reviewer trust channel has been provisioned.

`validate_repository(..., baseline=None)` checks current structure and returns a
record count; an omitted baseline intentionally provides **no history assurance**.
Use `verify_history` or pass an externally selected baseline for acceptance. The
CLI defaults to the pinned initial preservation commit and also performs history
comparison. Neither API is an operational eligibility endpoint. Existing original
Skeptic probes remain unchanged; see the Data completion report for all failures
and the distinction between intended denials and fixture incompatibilities.

## Research exposure and preregistration contracts — v1 (H-M0-004)

Additive `exposure` and `preregistration` registries live at
`research/exposures/` and `research/preregistrations/`. Published v1 hypothesis,
experiment, Data schemas and both Skeptic suites are unchanged. Legacy records
remain readable, **not upgraded to fresh confirmation**. Repository validation
checks the new records when present; it does not yet require them for legacy
experiments. Quant owns that compulsory experiment binding and complete trial
inventory. A successful legacy validation is not confirmation eligibility.

An exposure binds an actor's declared results access/custody to Data's exact
membership path, kind, ID, version and byte SHA-256. It records purpose
(EXPLORATORY, CONFIRMATORY_ACCESS or HOLDOUT_CUSTODY), EXAMINED/UNEXAMINED/UNKNOWN,
first results-access time, coverage end, a content-bound JSON evidence snapshot,
ancestors and an exact predecessor for corrections. UNKNOWN is preservable with
a reason, but blocks freshness. EXAMINED requires first access; UNEXAMINED requires
custody and no access time. Observation coverage cannot run beyond record time.
Membership must exist by the recorded exposure time. These are consistency checks
on declared timestamps, not authenticated custody or proof of historical truth.

A preregistration binds the full hypothesis bytes (including all rules, metrics,
cost assumptions and rejection criteria), structured justified decimal thresholds,
a hashed analysis plan, an unexamined holdout exposure and exploratory ancestors.
Unknown hypothesis thresholds deny freezing. Holdout custody must be recorded by
and cover the freeze instant. Hypothesis registration must precede or equal freeze.
The closure of disclosed ancestors **and all prior exposure versions** is checked;
UNKNOWN denies, and any EXAMINED canonical sample intersection denies. Dataset or
membership renaming/order changes cannot evade overlap. Sample identity is Data's
`sample_keys`: canonical namespace/event_id/outcome_id; digest is Data's
`membership_digest`. Research introduces no alternative identity system.

`validate_research(root, kind, record, now=...)` performs semantic contract checks;
`validate_record` supplies shape/clock validation for exact resolution, while
`validate_repository` additionally invokes Research semantics and Data's registry
graph. It remains a structural validator with no operational approval result.

`check_confirmation_contract(root, registration_ref, frozen_sha256=...,
access_ref=..., disclosure_refs=..., now=...)` checks a proposed first result access
against a verifier-held frozen registration digest. Omitting/mismatching that pin
fails closed. The caller must select the pin from prior accepted evidence outside
the submission, using the existing Data checkpoint/history trust boundary; copying
the candidate's digest is not assurance. The registration transitively binds full
hypothesis, thresholds, plan and exposure bytes. First access must strictly follow
freeze, and its membership reference must equal the holdout's **entire reference**,
not merely its label, cardinality or sample digest. A same-membership renamed
reference is rejected at this binding surface; in contamination comparisons it is
recognized as overlap. Extra disclosures, access ancestors and prior access
versions are also checked. Any supplied examined overlap is conservatively denied,
even if later than the proposed first access; reusable/repeated-access semantics
are deliberately not authorized. Return status is CONSISTENT_SUPPLIED_EVIDENCE,
operational_authorization=false and history_completeness=CALLER_MUST_ESTABLISH.

Quant must bind actual experiment inputs/splits to this exact population, inventory
all successful and failed trials/exposures, include new accesses since registration,
and enforce reuse denial across experiments and hypothesis versions. It must reject
missing contracts for confirmatory eligibility and integrate immutable reproduction
bundles. These interfaces do not scan the repository to discover hidden trials or
prove disclosures complete. Hypothesis supersession never erases exposure; future
Quant checks must carry that lineage into the supplied disclosure set. Risk owns
STOP, authority, lifecycle and operational gating. Research cannot self-approve.

Synthetic frozen examples and same/renamed/partial contamination cases are in
`tests/fixtures/research-protocol/cases.json`; copy its research/data trees and the
repository schemas into an isolated test root. Fixture digests are test-author pins,
not externally accepted checkpoints. The fixture's zero equality-error threshold
is a deterministic test assertion, not a scientific sample-size/profit threshold.
No real strategy or custody evidence is asserted. External trust, truthful upstream
identity mapping and complete off-system exploration disclosure remain unprovisioned.
All contracts are scoped SYNTHETIC_PROTOCOL_ONLY; STOP-M0-001 stays OPEN.

## Research authoritative history — v2 (R01 / H-M0-011)

This section supersedes v1's caller-only history behavior. The user explicitly
expanded H-M0-011 beyond supplied predecessor traversal to contradictory Research
history already in EdgeLab. Record schemas remain v1 and published artifacts stay
unchanged; freshness assessment is an intentionally stricter API contract.

`registration_exposure_refs` collects custody and exploratory disclosures from
**every preregistration predecessor**. `validate_research` compares their exposure
ancestry and prior exposure versions with the **current** holdout, rather than only
validating each predecessor against its former holdout. Known examined overlap or
UNKNOWN evidence denies; changing versions or dropping current declarations cannot
remove those disclosures. Unknown prior registrations remain invalid, not repaired
by a new version. Data exact-reference, chronology, cycle and version rules remain.

`check_confirmation_contract` now requires two verifier-owned keyword arguments:
`history_baseline` (full Git commit SHA) and `history_inventory` (the full Data
`history_inventory` mapping for that checkpoint). These accompany the existing
`frozen_sha256`. Missing arguments fail closed; there is no fallback to current HEAD,
candidate-provided ancestry or the old CONSISTENT_SUPPLIED_EVIDENCE success. Data's
`verify_history` checks the exact checkpoint/inventory and preservation of every
protected file. The frozen registration must be in that checkpoint with its exact
digest; the proposed first-access record must **not** already be in it. A recorded
historical access cannot be exempted by presenting it again as a new access.

The caller must select a current, complete accepted checkpoint using the existing
external acceptance/predecessor policy, before the proposed first access. These
arguments are verifier inputs, never submission fields. This API does not provision
that trust channel or promote a Git commit to accepted evidence. Synthetic tests
explicitly create verifier checkpoints in disposable repositories; production code
contains no checkpoint-creation/auto-acceptance path.

After preservation checks, Research enumerates all records in BOTH authoritative
Research registries: `research/exposures/*.json` and
`research/preregistrations/*.json`. It collects all exposures and cumulative
registration disclosures, including unreferenced records, unrelated IDs, old
versions and additions after the checkpoint. The submitter cannot choose this
comparison set through `disclosure_refs`. Current explicit disclosures remain
additional evidence, not the boundary of the search. Exactly the proposed
first-access reference is excluded at the top level; its ancestors/predecessors
are not excluded. Any UNKNOWN exposure conservatively denies even if apparently
disjoint. Any EXAMINED canonical sample intersection denies regardless of source
label or purported time: this is first-access consistency, not repeated-run policy.

Research JSON carrying an exposure/preregistration kind outside its typed registry,
nested/malformed/untyped registry records, non-JSON registry files and symlinks under
research/ deny rather than being silently omitted. Tests and reports remain archived
fixtures/evidence, not active Research registries. Other research JSON is parsed to
detect misplaced typed records, but legacy experiment fields are not interpreted as
exposure records; Quant must supply typed execution/exposure evidence from them.
The whole repository's structural/graph validation must pass. A hash snapshot of the
Research registries is compared before returning, and accepted history is rechecked.
This detects changed checked records, not arbitrary concurrent/adversarial filesystem
races or an execution-time transaction.

Success is `CONSISTENT_AUTHORITATIVE_RESEARCH_EVIDENCE`, with
`history_completeness=VERIFIED_RESEARCH_REGISTRIES_ONLY`, the exact checkpoint SHA,
Research record byte hashes and Data membership digest. It always returns
`operational_authorization=false`. Structural repository validation without these
verifier inputs is still not a freshness result or approval.

This is a bounded Research-evidence assessment, not Quant's complete trial scanner.
Quant retains mandatory experiment integration, complete execution-time inventories,
actual input/split membership binding, reproduction and confirmation enforcement.
It must establish checkpoint currency, ingest all execution observations, prevent
races at execution and invoke this contract with verifier-owned evidence. Risk still
owns STOP/lifecycle/authorization. Neither R01 nor H04/H05 is closed by Research.

No local code proves undisclosed external access, authentic custody, honest upstream
canonical identity assignment, or integrity of an adversary-controlled verifier.
The supplied checkpoint must represent the verifier's accepted history; deliberately
substituting an old/forged checkpoint is outside that trust assumption. Current local
additions are checked, but a record erased before ever entering any trusted checkpoint
cannot be reconstructed. No global omniscience or operational trust is claimed.

Compatibility: published v1 Research/Skeptic helpers omit history inputs and now
fail during positive fixture setup. Their files must remain unchanged. These setup
errors are not evidence that their attacks were reached; R01 v2 owner successors
use independently pinned synthetic checkpoints and reproduce attacks at intended
semantic surfaces. Independent review must disposition this migration.

## Quant experiment integrity contracts — v1 (H-M0-005)

Quant adds four immutable typed registries without changing the legacy experiment
schema: `research/experiment-protocols/` (`quant-protocol`), `research/trials/`
(`trial`), `research/trial-inventories/` (`trial-inventory`) and
`research/reproductions/` (`reproduction`). Legacy experiments remain readable but
cannot establish fresh confirmation eligibility. Repository validation checks the
new records' structure and internal semantics; it is still not a confirmation or
operational eligibility endpoint.

A frozen Quant protocol binds the exact Research preregistration bytes and the
verifier-selected pre-access checkpoint digest. It binds ordered exact Data
manifest references for train, validation, test and holdout; required split roles;
content-hashed code, configuration, environment and deterministic settings; seed
policy; and execution assumptions. Every manifest must exist by the protocol
freeze. Canonical sample identities must be disjoint across splits. The holdout is
one exact manifest whose membership reference equals the preregistered custody
membership reference; a renamed, reordered or rehashed equivalent is overlap for
contamination checks but is not the exact frozen execution input.

Each trial records its attempt ordinal and ATTEMPTED, SUCCEEDED, FAILED or CANCELLED
state. It repeats the actual ordered split references, code/configuration/environment,
randomness and deterministic settings so substitutions are detectable. Successful
trials require content-bound outputs, metrics and confirmatory-access evidence;
failure and cancellation reasons remain preserved. Nonterminal attempts cannot
claim results. Access must occur during the recorded execution interval. A current
trial inventory must exactly enumerate every typed trial in the accepted Quant
registry, with byte hashes and status counts. Older versioned inventories remain
valid historical snapshots but cannot substitute for the current complete one.
Omitted failures, cancellations, attempts or repeated trials therefore deny a
fresh claim at the Quant gate. Activity never recorded in an accepted/local
registry remains outside local detection.

`experiment_identity` hashes the exact protocol/preregistration, actual split,
code, configuration, environment, randomness, access, output, metric, trial and
inventory references. A reproduction record binds that identity and separate
reproduced output/metric blobs. `verify_reproduction` requires a verifier-supplied
callable and compares its bytes to the bound artifacts. It never executes a command
or program supplied by an experiment record. This verifies determinism only within
the recorded environment and the verifier's runner assumptions; external services,
hardware and nondeterministic dependencies are not magically made deterministic.

### Current accepted state and check/use boundary

`CurrentStateAuthority` is a verifier-controlled interface, not a repository
allowlist. Its state contains a pre-access checkpoint, a latest current checkpoint,
monotonic generation metadata and a canonical state digest. Both checkpoints use
Data's exact full-SHA history inventories. The current checkpoint must descend from
the pre-access checkpoint and exactly match the live Research exposure/
preregistration and Quant registries. Missing authority, altered state, rollback,
stale caller digest, deleted/replaced accepted bytes, unaccepted additions or a
mismatched registry fail closed. The frozen protocol binds the pre-access checkpoint;
the post-execution assessment binds the independently supplied current generation.
Thus a later accepted exposure cannot be hidden by resubmitting an older otherwise
valid checkpoint when the authority reports the newer generation.

`assess_confirmation` invokes Research's checkpoint-aware
`check_confirmation_contract`, validates actual Data manifests and all four split
memberships, verifies the complete accepted trial inventory, and denies any prior
trial whose declared train, validation, test or holdout inputs intersect the
proposed confirmatory holdout's canonical membership. This rule applies even when
the prior trial failed, was cancelled, remains incomplete or has no results-access
record: absence of access evidence does not prove absence of consumption. Renaming,
reordering, repackaging, partial overlap, membership correction/versioning and
split-role relabeling do not restore freshness. The check is deliberately scoped to
the proposed confirmatory holdout and to trials started no later than its proposed
first access; it does not prohibit unrelated population reuse or retroactively
invalidate freshness because of later work. The assessment then performs
content/deterministic reproduction. It returns a
machine-readable `SCIENTIFIC_INTEGRITY_CONSISTENT` result only after a second byte
and current-state check. Every positive result explicitly sets operational, paper,
live and Risk authorization false.

`commit_confirmation_claim` then calls the authority's `commit_if_current` with
the assessed state digest. The authority adapter must perform an atomic compare and
commit; a plain recheck is not sufficient. Under that interface, evidence accepted
between assessment and claim commit invalidates the commit. The adapter must return
a schema-valid structured commitment whose self-digest binds its authority ID,
monotonic generation, unique commitment ID, timestamp, limitations, assessment
digest, accepted-state digest, experiment identity and exact claim-reference
identity. `verify_authority_commitment` locally verifies all of those bindings and
rejects opaque strings, missing fields, replay against another assessment or state,
cross-authority substitution and stale generations. `committed_at` is a completed
fact under the shared clock contract: it must be a valid offset-aware timestamp no
later than the verifier-supplied evaluation time. Recomputing the self-digest does
not make a future-dated commitment temporally plausible.

That structured record is a locally verifiable content commitment, not proof of
external authentication. Quant does not establish authority authenticity, replay
persistence, global commitment-ID uniqueness, key custody, adapter honesty,
controller authentication, durable storage or true external atomicity. Those are
Risk/external-trust responsibilities. No production authority, persistent replay
registry or signature trust root is provisioned; absence therefore denies. The
included in-memory adapter exists only in tests and proves binding behavior under
the stated external-trust assumption.

Risk may consume the returned assessment digest, exact evidence references,
experiment identity, current-state digest and explicit false authorization fields.
Risk still owns trust policy, lifecycle/promotion, STOP enforcement, paper/live
eligibility, bankroll, kill switches and every capital decision. A positive Quant
assessment is necessary scientific-integrity evidence only. It says nothing about
profitability and cannot clear `STOP-M0-001`.
