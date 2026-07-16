# Security policy

## Supported versions

Only the latest published or explicitly distributed candidate is supported. This 0.2.0-rc.1 tree is a private candidate until publication is separately authorized.

## Reporting

Do not open an issue containing credentials, private memory, local paths, databases, or exploit details. During private release staging, external distribution and external reporting are not open; authorized reviewers should use an already trusted private channel. Before public visibility is enabled, GitHub private vulnerability reporting must be enabled and this policy reverified. If the confidential channel is unavailable, retain the report locally and disclose no sensitive detail in a public issue.

## Security boundaries

Mnemoir Provenance is local-first but still processes untrusted text and filesystem inputs. Controlled adapters reject traversal, symlink escape, backup trees, unsupported files, and implicit live stores. The loopback UI validates host/origin, uses a per-process mutation token, and is not a remote service. Live working-memory mutation requires exact target/hash/operation/policy/expiry authorization, private transaction state, read-back, and receipts.

No telemetry or network listener is enabled by installation alone. See `docs/operations/threat-model.md`.
