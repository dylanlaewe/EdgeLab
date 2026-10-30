# H-M0-134 — Runtime-v2 portable-component resource classification

Commit `7aeabae5c55ad99aecaf6450f955d8fbde528f5b` classifies the
complete direct `_PORTABLE_COMPONENT_MAX` family. The classification is
limited to the inclusive 255-character admission predicate over exact
slash-separated components of exact built-in strings admitted by `_PATH` and
the preceding total-path maximum. It binds the sole definition, sole generator
comparison, literal slash split, exact two-arm ordering, and
`any(generator)` short-circuit semantics atomically.

Classification v11 byte-binds its v10 predecessor and retains all nine v10
constraints exactly. It adds two unique portable-component sites, increasing
the cumulative inventory to ten constraints and twenty-eight classified
sites. Its schema SHA-256 is
`a2f3d5cb2a7621b1cec5b92d847f8370aba9226626d8dd133302ac5b6ad96049`,
manifest raw SHA-256 is
`f427f01f2626ba148f7eb13439d7923fa430b4aaa97cfe7596b3695d2ecd9a0b`,
and domain-separated self-digest is
`9dd7186a350c36035d831c5ac9df1003e2c9b71a286ebd67873c170282c68d4e`.

Dedicated evidence proves 254-, 255-, and 256-character boundaries; first,
middle, and last component overflow; separator exclusion; exact supplied
identity on admission; hostile string and invalid-pattern preconditions;
independent total-path and later portability rules; deterministic coordinate
preservation; and absence of authorizing effect. Instrumented short-circuit
tests prove total overflow never enters component inspection, component
overflow stops at the first failing component, and complete admission inspects
every component in split order.

Readiness attacks refresh ordinary discovery identities before challenging
the hard pins. They reject same-valued definitions, changed maxima, comparator
or subject substitution, `>=`, `all`, generator filters, reordered or
transformed components, split drift, bypassed or swapped arms, altered
diagnostics, extra loads/stores, and source-level `len` or `any` shadowing.
The checker also pins the complete `_path` function and closure-module ASTs.

Three independent bounded engineering reviews reproduced the schema,
manifest, evidence, source-site, AST, predecessor, ancestry, and self-digest
identities and returned ACCEPT. These are engineering reviews only; they are
not authenticated formal STOP-clearance authority.

Validation passed 43 focused readiness and portable-component tests normally
and under optimized Python; 438 tests passed across the 30-module fast tier;
and 464 governed records plus published history validated. The readiness CLI
still reports `BLOCKED / DENY`, writes no release artifact, and retains all
four blockers.

Only twenty-eight of 697 census sites are semantically classified; 669 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains OPEN.
No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
