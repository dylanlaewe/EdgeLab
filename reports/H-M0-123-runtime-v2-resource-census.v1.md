# H-M0-123 — Runtime-v2 resource-bound discovery census

Commit `32fdbfb2a08125a9e50578b8baf873ac3274ee6a` converts the previously
open-ended resource-inventory concern into a reproducible fixed-input
discovery census. The deny-only release-readiness report now records 394
source-bound AST candidates and 296 numeric JSON-Schema bound candidates over
exactly ten source artifacts and fifteen schema inputs.

Source records bind path, owning qualified name, normalized AST digest, node
kind, occurrence, expression, and a domain-separated site ID; function
defaults also bind their owning parameter. Diagnostic line numbers are excluded
from identity. The census covers module numeric assignments, comparisons,
fixed bound-helper calls, numeric function defaults and slices, table specs,
and explicit regex quantifiers within its documented syntactic scope.

Schema records bind schema ID, audited raw input identity, escaped JSON
pointer, numeric bound keyword, and value. The five bootstrap, nine retained,
and dependency-closure schemas are exact-tested as the only schema inputs; the
two content assets are explicitly excluded from schema treatment and retained
as successor reconciliation work. Source sites, schema sites, and the complete
schema-input identity list each receive domain-separated digests.

Adversarial tests detect added source bounds, changed schema maxima, regex
width drift, and raw-source changes while proving that comment-only line drift
does not change semantic site identity. Independent Skeptic and diff reviews
verified determinism, unique identities, exact schema scope, normal and
optimized behavior, and the absence of any authority escape.

This is a candidate lower bound, not a complete semantic resource manifest.
Every site remains `UNCLASSIFIED`, coverage remains `INCOMPLETE`, and
`RESOURCE_INVENTORY_INCOMPLETE` remains unconditional. Validation passed 13
focused tests normally and under `python -O`, 365 tests across the 22-module
fast tier, and 428 governed records before publication.

No closure, carrier, public-verifier connection, STOP clearance, writer,
database, selector cutover, operational authority, or capital path was added.
The readiness result remains `BLOCKED / DENY`; private valid candidates remain
`UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; capital remains LOCKED with deployable
USD 0 and the kill switch ENGAGED.
