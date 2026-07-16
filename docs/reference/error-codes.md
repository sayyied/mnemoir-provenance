# Error codes

Boundary errors are stable short codes such as unauthorized scope, path traversal denied, symlink denied, stale state/hash, approval required, target unreachable, SQLite locked, read-back mismatch, recovery required, and unsupported operation.

Errors omit raw private content and absolute paths. Operators should retry only documented transient contention; authorization and boundary denials require changed input or policy.
