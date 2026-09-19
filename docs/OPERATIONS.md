# Operating the laboratory

## Start and ownership

Read root instructions, constitution, your role contract, project state, open STOPs, then relevant queued handoffs. Repository evidence outranks remembered chat context. Director assigns bounded scopes; recipients record CLAIMED and their identity in a new handoff version before making overlapping edits. Only one owner edits a shared artifact at a time. Conflicts go to Director, never silent overwrites.

Use JSON records matching `schemas/`. IDs are stable and unique within record type; version increments create new files (`<id>.v<version>.json`). References identify exact file versions and, for external data, content hashes. Do not edit published research, audit events or raw observations in place. Correct by supersession with rationale. Current project state and initial portfolio configuration are mutable, with changes preserved in Git; future money movement requires ledger events.

## Handoffs

One JSON artifact per assignment/version under `docs/handoffs/`. Include sender, recipient, request, work done, evidence, changed files, actual test commands/results, unknowns, blockers, next action and acceptance criteria. A fresh session must be able to reproduce the work. BLOCKED is a valid completion report, not evidence approval. COMPLETED requires acceptance criteria met. Dependency IDs prevent work from proceeding before prerequisites exist. Director integrates accepted work and updates project state. Git commits preserve completed engineering milestones; pushes share them.

## Scientific workflow

Scout documents permitted access; Data verifies feasibility and temporal lineage. Research registers a frozen confirmatory protocol before Quant examines its confirmatory outcomes. Quant records all trials, costs, splits, uncertainty and failure. Skeptic independently attempts reproduction and falsification. Risk reviews controls and forward evidence. No author approves their own evidence. Distinct role labels are insufficient: reviewers must be distinct accountable actors with conflict disclosures. Authentication/enforcement is pending M0 work.

Exploration never counts as confirmation. Any material post-outcome change creates a new hypothesis version and fresh unexamined confirmatory data. Unknown thresholds may be drafted but block confirmatory execution until justified and frozen. Store negative findings with the same rigor as positive ones. `docs/LIFECYCLE.md` defines promotion prerequisites.

## STOP and kill switch

Any agent may create an OPEN STOP (`schemas/stop.schema.json`) with reason, affected components, evidence, severity and remediation. Write an audit event and handoff to Director and affected owners. Halt dependent work including promotion and use of contaminated derived artifacts. Unaffected documentation and remediation can continue. Missing or unreadable safety state blocks affected activity.

Resolution requires a separate audit event documenting tests, evidence, the issuing role's review (or documented independent substitute), affected domain owner approval, and Risk approval if capital is implicated. Preserve the original STOP; publish a superseding resolved record referring to that event. A Director status change alone cannot resolve a STOP. Downstream artifacts remain quarantined until revalidated.

The kill switch is latched and initially ENGAGED. Its eventual operational scope is all new exposure (including queued requests and risk-increasing replacements). Recheck safety immediately before execution; a trigger must invalidate pending authorization. Settlement and reconciliation may continue without adding exposure. Triggers include stale/malformed/missing data, stale or discrepant prices, exposure breaches, drawdown, degradation, unavailable markets, inconsistent balances, settlement or execution failures and failed health checks. Reset requires recorded remediation and Risk authorization; it cannot erase STOPs, skip gates or authorize live execution. M0 has no reset or execution API.

## Development and testing

Inspect state, choose a coherent scope, implement, validate, inspect diff, update artifacts, commit and push without force. Preserve unrelated work. Never commit credentials. Run the README checks. Sensitive future logic needs positive and adversarial tests: odds/payout rounding, integer money, correlated exposure, settlement idempotency, timezone boundaries, late corrections, lineage, skipped stages, identity spoofing, stale reviews, STOP propagation and kill-switch races. Test failures are blockers, never hidden.

JSON Schema checks shape only. The current validator additionally checks the initial capital lock, record IDs, reference existence where implemented, and basic confirmatory ordering. It is not the future scientific approval engine or a tamper-proof audit log. All external access and live execution remain unimplemented.
