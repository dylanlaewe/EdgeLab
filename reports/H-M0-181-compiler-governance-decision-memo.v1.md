# H-M0-181 — Compiler governance decision memo

## Decision requested

The owner must choose whether to adopt
`GOV-M0-3A-COMPILER-EQUIVALENCE-001.v1` as the permitted process for evaluating
compiler-generated witnesses for the single registered
`DRAFT_2020_12_EXACT_LOCATION_MINLENGTH_V1` family.

Recommended decision: **approve the process for formal evaluation, not the
evidence.** This would authorize creation of the versioned registry,
compiler-closure manifest, external reviewer trust setup and formal review
package. It would not accept the 25 candidates, change V55, or clear any gate.

## Formal authority finding

There is no currently provisioned formal 05 Skeptic appointment mechanism.
Repository rules require a distinct accountable actor with conflict disclosure
and explicitly state that authentication/enforcement is pending M0. Existing
authority-policy and attestation code assumes an external authenticated source;
it does not establish one and is not wired into compiler governance review.

The minimum missing setup is an owner-designated out-of-band trust root plus a
signature/source-verifying adapter, a signed current policy mapping a distinct
actor to `05 Skeptic` and exact compiler-review scope, a revocation/conflict
channel, and a signed exact-subject attestation verified by repository tooling.
A role label, Codex subagent, Git author string, self-digest or repository-only
appointment is insufficient.

The current v1 policy and attestation schemas cannot carry signature, key,
algorithm, certificate or detached-signature references. The setup therefore
also requires versioned signed-record successors or typed detached-signature
envelopes binding complete canonical record bytes, signer/key identity,
algorithm, external credential or certificate chain, and
revocation/current-generation evidence. Validation must authenticate these
against the out-of-band root; the `VERIFIED_EXTERNAL` literal is not proof.

Formal approval therefore remains unavailable. The proposal is pending and the
read-only native review requested for H-M0-181 can assess internal consistency
only.

## Exact acceptance sequence

1. Owner approves the proposal version and bounded family scope.
2. Owner provisions the external trust mechanism; no reviewer is presumed.
3. Engineering publishes the versioned rule registry and compiler-closure
   manifest without changing accepted classifications.
4. A separately authenticated 05 Skeptic claims and independently reviews the
   exact proposal, compiler, registry and output.
5. Only after an exact formal approval may a separate V55-successor package be
   prepared and re-reviewed. Counts remain unchanged until that later package
   is accepted and published.

## Next authorized engineering deliverable

While formal review is unavailable, the next bounded non-operational M0.3A code
increment is a **candidate-package verifier and versioned rule-registry
substrate for the existing `minLength` prototype only**:

- a closed registry schema and one candidate-only registry entry matching the
  H-M0-180 rule exactly;
- a compiler-closure identity manifest;
- a standalone verifier that checks registry/compiler/census/predecessor/ledger
  bindings and always returns `CANDIDATE_VALID / DENY` or invalid;
- adversarial substitution and deterministic-reproduction tests; and
- no new family, accepted evidence, V56, release closure, public runtime
  attachment, currentness or R-gate behavior.

This increment prepares a stable formal-review subject without presuming the
governance decision or reviewer identity.

## Unchanged state

H-M0-179 and H-M0-180 remain complete. V55 remains 87 classified / 634
unclassified. Data remains BLOCKED; all STOPs remain OPEN; M0 remains blocked;
M1 remains unreleased; authorization remains `DENY`; executor remains
`MOCK_ONLY`; live remains `LOCKED`; kill remains `ENGAGED`; deployable capital
remains USD 0.
