# Strategy lifecycle — normative design, enforcement pending

Every transition requires an immutable audit event identifying exact strategy/hypothesis versions, actor, reviewer identities, evidence hashes, reason, prior/new state and policy version. Missing, stale, unverified, conflicting or STOP-affected evidence denies promotion. Evidence is scoped to the reviewed version; changed data/code/config invalidate affected reviews. No stage skips. No role can supply all independent approvals. The current schema only recognizes states; it does not execute these transitions.

| From → To | Proposer / required evidence and review |
|---|---|
| IDEA → REGISTERED | Research: complete frozen hypothesis, falsification criteria, Data feasibility review. |
| REGISTERED → RESEARCHING | Quant: accepted protocol, no unresolved thresholds, eligible temporal dataset, immutable reproduction inputs and declared trial inventory. |
| RESEARCHING → BACKTESTED | Quant: completed reproducible results including failures, obtainable prices, costs and uncertainty. Completion is not proof of edge. |
| BACKTESTED → ROBUSTNESS_REVIEW | Quant: frozen robustness plan and full trial inventory available. |
| ROBUSTNESS_REVIEW → ADVERSARIAL_REVIEW | Quant: completed sensitivity, holdout/walk-forward and bias analysis; all registered criteria addressed. |
| ADVERSARIAL_REVIEW → PAPER_ELIGIBLE | Independent Skeptic pass plus Risk approval of paper controls and frozen forward protocol; unresolved material findings deny promotion. |
| PAPER_ELIGIBLE → PAPER_TRADING | Risk: separate paper ledger, tested settlement, exposure controls, monitoring and kill switch; Data confirms feed readiness. |
| PAPER_TRADING → LIVE_CANDIDATE | Quant: preregistered forward criteria met; independent Skeptic review and Risk assessment of sufficient evidence. **Unavailable in M0.** |
| LIVE_CANDIDATE → LIVE_APPROVED | Risk: all thirteen AGENTS §21 gates verified, independent reviews, complete operational tests, strategy-specific scoped approval with expiry. **Unavailable in M0.** |
| LIVE_APPROVED → LIVE | Risk: fresh account reconciliation, permitted execution access, valid approval and limits, healthy data, no STOPs and disengaged authorized kill switch. **Unavailable in M0.** |

Any nonterminal state may become REJECTED with evidence-linked rejection; an agent may propose rejection, with the responsible domain owner recording its rationale. Any nonterminal state may become RETIRED by documented owner decision and Risk disposition of any exposure. Neither terminal state has outgoing transitions for that version. A separately versioned hypothesis/strategy starts at IDEA and retains lineage.

Any active nonterminal state may be SUSPENDED immediately by a material STOP, Risk veto, failed health check or degradation finding. Store the previous state. SUSPENDED cannot resume merely by editing state: remediate, obtain independent domain review and Risk approval when applicable, revalidate every gate through the previous state and record a resume event. Resume cannot advance beyond the prior state; insufficient evidence leaves it suspended or creates a new version. During M0, no resume path to a live state is permitted.

Paper/live monitoring must eventually include CLV degradation, drawdown, changed sources/market regimes, execution degradation and model drift. Suspension can act under uncertainty. Existing liabilities still require controlled settlement/reconciliation; a stop does not erase them.
