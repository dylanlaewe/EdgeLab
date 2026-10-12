# Frozen dependency predicate coverage

| Predicate | Positive/negative evidence |
|---|---|
| Scheduler ref equals versioned head | satisfied DISPATCH / scheduler-head DENY |
| Completed and exactly one completion | satisfied DISPATCH / zero, multiple, BLOCKED DENY |
| Typed completion path | satisfied DISPATCH / path DENY |
| Parsed completion mapping fields | satisfied DISPATCH / task ID, attempt, task ref, status, content SHA DENY |
| SHA of exact task bytes | satisfied DISPATCH / task-byte DENY |
| Completion serialization is provenance | whitespace-only completion remains DISPATCH with identical receipt |
