# Overflow, trim, and writeback

Compact host working memory and durable canonical memory serve different purposes. Mnemoir measures pressure, proposes deterministic compaction, preserves evidence, obtains scoped authorization, checks the exact target hash, writes private transaction state, atomically replaces where supported, reads back, reconciles, and retains rollback data.

The reference Hermes policy uses character budgets for `MEMORY.md` and `USER.md`; these are adapter defaults, not universal limits. Controlled-fixture proposal mode does not mutate live files.
