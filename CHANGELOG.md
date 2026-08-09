# Changelog

All notable user-visible changes are recorded here.

## 0.2.5 — 2026-08-08

- Hardened legacy-sentinel retirement to require the complete immutable sentinel signature, preserving any operator-modified source even when its historical ID and three display fields remain unchanged.
- Expanded fail-closed dependency detection to cover direct source columns and schema-supported polymorphic source references, including privacy, policy, grant, audit, sync, job, retrieval, and provenance records.

## 0.2.4 — 2026-08-08

- Removed the legacy synthetic unavailable-source sentinel from production defaults so healthy configured sources no longer make every recall appear degraded.
- Added a conservative existing-database upgrade that retires only the exact data-free legacy sentinel and preserves nonmatching or source-backed records.
- Preserved explicit degraded-coverage behavior through dedicated synthetic tests rather than a permanently unhealthy production source.
- Corrected synthetic degraded-source fixture wiring and the local retrieval benchmark query so those proofs exercise real degradation and retrieval rather than passing through the retired sentinel.

## 0.2.3 — 2026-08-08

- Added one fail-closed Hermes execution-context policy across initialization, recall, synchronization, overflow/writeback, lifecycle hooks, and all 12 provider tools.
- Preserved trusted-primary cited recall and proposal/audit behavior while making cron, flush, subagent, background/review, unknown, and contradictory contexts zero-mutation.
- Hardened provider configuration to owner-only `0600` atomic, symlink-safe, ownership-validated, readback-verified persistence with concurrent-writer serialization and failure cleanup.
- Bounded compatibility to Python 3.11/3.12 and Hermes Agent 0.19.1, with CI pinned to exact official revision `0a62610f10cc34d696b2239b2c69fa1ba0f1ca63`.
- Completed public operator guidance for all 12 retained `cmc_*` tool identifiers, local plaintext storage, retention/removal, disablement, writeback defaults, and advanced list configuration.

## 0.2.2 — 2026-08-01

- Corrected Hermes writeback health reporting so profile-scoped historical partial trims stop counting as unresolved after a later successful write, while genuine recovery-required states remain visible.
- Put `python -m pip install mnemoir-provenance` first and separated standalone, development, Hermes shared/existing-runtime, generic Python, and JSON CLI onboarding.
- Hardened explicit Hermes plugin installation so it alone creates the restrictive default storage parent; provider discovery remains side-effect-free.
- Added non-mutating package/plugin/provider/storage diagnostics, including actionable same-interpreter failure.
- Added the closed-schema `mnemoir plugin bootstrap-profile` flow for controlled cited recall with idempotent evidence, no automatic promotion, and no writeback.
- Added disable/data-retention, migration/rollback, empty/degraded, denial, timeout, and troubleshooting guidance.

## 0.2.0 — 2026-07-16

- Added the history-free Mnemoir Provenance package identity.
- Added source-grounded recall, explicit coverage/degradation, scoped curation, version history, bounded autonomy, and local operator surfaces.
- Added controlled source adapters and optional Hermes reference integration.
- Added authorized overflow trim/writeback with read-back, receipts, reconciliation, and rollback.

This was the first public release of Mnemoir Provenance.
