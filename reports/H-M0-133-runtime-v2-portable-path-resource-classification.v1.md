# H-M0-133 — Runtime-v2 portable-path resource classification

Commit `3012e5665290eacde96b73f7878dfe78e54d34ad` classifies the
complete direct `_PORTABLE_PATH_MAX` family. The classification is limited to
the inclusive 4,096-character total-path predicate over exact built-in strings
admitted by `_PATH` and supplied to the private `_path` helper. It binds the
sole definition and sole direct comparison atomically. Component length,
portability, full path validity, filesystem truth, closure validity, sibling,
aggregate, authorization, and public-verifier semantics remain outside this
claim.

Classification v10 byte-binds its v9 predecessor and retains all eight v9
constraints exactly. It adds two unique portable-path sites, increasing the
cumulative inventory to nine constraints and twenty-six classified sites. Its
schema SHA-256 is
`268206397a113786c985099c9afc9e134dee4027ebb9f8a0f5d6b190ce125bd5`,
manifest raw SHA-256 is
`6517b015ebb9b50507feffed682cbb4beecb90ff57935d20ee9792f67c71a4e1`,
and domain-separated self-digest is
`c7fda664d8a192e63269094e3f9180e475f67adcbcf19592fb6db3572a7e6642`.

Dedicated evidence proves `M-1`, `M`, and `M+1` behavior using valid ASCII
paths whose components remain within the separate 255-character limit.
Admitted paths retain exact supplied identity and value; overflow raises exact
`PATH_LENGTH` at the caller coordinate. Evidence also covers hostile string
subclasses, non-strings, pre-bound pattern rejection, independent component
and portability rules, deterministic repeated rejection, and absence of any
external or authorizing effect.

Readiness attacks refresh ordinary discovery identities before challenging
the hard pins and reject same-valued or changed definitions, comparator,
subject, maximum-symbol, bypass, extra-load/store, pattern-precondition,
diagnostic, ordering, `_fail`, and built-in-`len` shadowing mutations. The
checker pins the complete `_path` function and closure-module ASTs, so call-set
and transitive helper drift also fail closed.

Two independent bounded engineering reviews reproduced every schema,
manifest, evidence, source-site, AST, predecessor, and self-digest identity and
returned ACCEPT. These reviews are engineering evidence only; they are not an
authenticated formal STOP-clearance authority.

Validation passed 40 focused readiness and portable-path tests normally and
under optimized Python; 426 tests passed across the 29-module fast tier; and
461 governed records plus published history validated after evidence
publication. Eighteen alpha and observatory tests also passed. The readiness
CLI still reports `BLOCKED / DENY`, writes no release artifact, and retains all
four blockers.

Only twenty-six of 697 census sites are semantically classified; 671 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains OPEN.
No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
