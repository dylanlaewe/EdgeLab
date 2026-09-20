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
