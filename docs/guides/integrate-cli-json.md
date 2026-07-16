# Integrate through CLI JSON

Invoke `mnemoir` as a local subprocess with explicit `MNEMOIR_DB` and controlled input paths. Standard output is machine-readable JSON; diagnostics and nonzero exit codes indicate stable failures. Set timeouts and cancel the process if the host abandons a request.

Use idempotency keys for mutations. Exercise success, empty/degraded, approval-required, and denied paths before production use.
