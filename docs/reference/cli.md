# CLI reference

Run `mnemoir --help` and `mnemoir <group> --help` for the authoritative command tree. Major groups cover sources/ingest/recall, proposals/memories, retrieval/scoring, Council, autonomy, operator/wiki, health/service/UI, controlled adapters, overflow, and optional Hermes integration.

Commands emit JSON. Exit 0 means the requested operation completed within its documented state; nonzero indicates invalid input, denial, or failure. Approval-required can be a successful policy outcome without executing the effect.
