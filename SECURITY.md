# Security policy

## Supported versions

Only the latest published release is supported. The supported release is 0.2.0.

## Reporting

Do not open an issue containing credentials, private memory, local paths, databases, or exploit details. Use [GitHub private vulnerability reporting](https://github.com/sayyied/mnemoir-provenance/security/advisories/new) for confidential reports. If that channel is unavailable, retain the report locally and disclose no sensitive detail in a public issue.

## Security boundaries

Mnemoir Provenance is local-first but still processes untrusted text and filesystem inputs. Controlled adapters reject traversal, symlink escape, backup trees, unsupported files, and implicit live stores. The loopback UI validates host/origin, uses a per-process mutation token, and is not a remote service. Live working-memory mutation requires exact target/hash/operation/policy/expiry authorization, private transaction state, read-back, and receipts.

No telemetry or network listener is enabled by installation alone. See `docs/operations/threat-model.md`.
