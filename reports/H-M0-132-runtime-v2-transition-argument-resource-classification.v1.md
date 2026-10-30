# H-M0-132 — Runtime-v2 transition-argument resource classification

Commit `0db28547a02690c2158f58b835c2b83cd8b07564` classifies the
complete direct `MAX_ARGUMENTS` family. The classification is limited to the
exact built-in tuple supplied as `TransitionIntent.arguments` after the joint
exact container-type guard and before event cardinality, member shape,
ordering, uniqueness, and operation validation. It binds the sole definition
and sole direct comparison atomically. All sibling, aggregate, diagnostic,
representation, authorization, and public-verifier semantics remain outside
this claim.

Classification v9 byte-binds its v8 predecessor and retains all seven v8
constraints exactly. It adds two unique transition-argument sites, increasing
the cumulative inventory to eight constraints and twenty-four classified
sites. Its schema SHA-256 is
`5d53e9141dfee5758b4b4e841e43d33c0cc1299ed41ff812a5db9728de6d1d77`,
manifest raw SHA-256 is
`81e9c23c36af0ad0123fbaad56a12e96746a32ccd9b249686499cbb44f6be259`,
and domain-separated self-digest is
`57320a77af9e8b63aa6f4c295c5b6f3102ab9bd2e7300b59d07cf6ac93b483e4`.

Dedicated evidence proves `M-1`, `M`, and `M+1` behavior. Admitted tuples
retain exact supplied identity and ordering; overflow raises the exact
`TRANSITION_RESOURCE_ARGUMENTS:/arguments` denial before malformed members
are inspected. The evidence also covers hostile tuple subclasses and plain
non-tuples, later malformed/order/duplicate denial at the admitted maximum,
sibling event independence, deterministic repeated rejection, unchanged
immutable state, and the fact that construction does not authorize a
transition.

Readiness attacks refresh ordinary discovery identities before challenging
the hard pins and reject same-valued or changed definitions, comparator,
subject, maximum-symbol, bypass, extra-load/store, exact-type, diagnostic,
downstream-validation, `_deny`, and built-in-`len` shadowing mutations. The
checker resolves the class-qualified `TransitionIntent.__post_init__` method
rather than accepting another same-named method.

Two independent bounded engineering reviews challenged the completed slice.
The Skeptic found an evidence subject-name mismatch and a missing explicit
`len`-shadowing mutation; both were repaired, all dependent identities were
refreshed, and the final reviews returned ACCEPT. These reviews are not
authenticated formal STOP-clearance authority.

Validation passed 39 focused readiness and transition-argument tests normally
and under optimized Python; 415 tests passed across the 28-module fast tier;
and 455 governed records validated before publication. The readiness CLI
still reports `BLOCKED / DENY`, writes no release artifact, and retains all
four blockers.

Only twenty-four of 697 census sites are semantically classified; 673 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains
OPEN. No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
