# Configuration reference

Database: `MNEMOIR_DB`. Controlled document root: `MNEMOIR_ROOT`. UI defaults to loopback and a configurable port. Retrieval mode, limits, and context budget are passed explicitly to APIs/CLI. Projection and controlled adapter roots are explicit paths.

The Hermes provider stores its JSON configuration as an owner-owned regular file at mode 0600 and rejects symlinks, special files, wrong ownership, malformed JSON, and insecure mode. Scalar settings include `db_path`, `mode`, `recall_mode`, `sync_turn_policy`, `writeback_mode`, `ingest_on_start`, and `context_budget_chars`. Advanced list settings are `controlled_profile_roots`, `controlled_turn_roots`, `controlled_honcho_import_roots`, `controlled_session_search_roots`, and `controlled_obsidian_vault_roots`.

Live writeback policy is adapter-owned and operation-authorized; it has no safe one-flag shortcut. The default is `propose_only`, which does not mutate working-memory Markdown.
