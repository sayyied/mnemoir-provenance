# Changelog

All notable user-visible changes are recorded here.

## 0.2.1 — public Beta release

- Put `python -m pip install mnemoir-provenance` first and separated standalone, development, Hermes shared/existing-runtime, generic Python, and JSON CLI onboarding.
- Hardened explicit Hermes plugin installation so it alone creates the restrictive default storage parent; provider discovery remains side-effect-free.
- Added non-mutating package/plugin/provider/storage diagnostics, including actionable same-interpreter failure.
- Added the closed-schema `mnemoir plugin bootstrap-profile` flow for controlled cited recall with idempotent evidence, no automatic promotion, and no writeback.
- Added disable/data-retention, migration/rollback, empty/degraded, denial, timeout, and troubleshooting guidance.

This prepares a local Mnemoir Provenance 0.2.1 candidate. It has not been published.

## 0.2.0 — 2026-07-16

- Added the history-free Mnemoir Provenance package identity.
- Added source-grounded recall, explicit coverage/degradation, scoped curation, version history, bounded autonomy, and local operator surfaces.
- Added controlled source adapters and optional Hermes reference integration.
- Added authorized overflow trim/writeback with read-back, receipts, reconciliation, and rollback.

This was the first public release of Mnemoir Provenance.
