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
