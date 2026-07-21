# CLI reference

Run `mnemoir --help` and `mnemoir <group> --help` for the authoritative command tree. Major groups cover sources/ingest/recall, proposals/memories, retrieval/scoring, Council, autonomy, operator/wiki, health/service/UI, controlled adapters, overflow, and optional Hermes integration. Plugin onboarding adds `mnemoir plugin install --hermes-home`, non-mutating `mnemoir plugin status --hermes-home [--hermes-python]`, and the exact `mnemoir plugin bootstrap-profile --hermes-home --profile-root --profile-id --verify-query [--db-path]` contract.

Commands emit JSON. Exit 0 means the requested operation completed within its documented state. Bootstrap preflight exits 2, ingest failure exits 3, and recall/no-cited-match exits 4; successful ingest is preserved on no-cited-match. Approval-required can be a successful policy outcome without executing the effect.
