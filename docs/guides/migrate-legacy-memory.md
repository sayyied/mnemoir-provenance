# Migrate legacy memory

Inventory source families, provider IDs, database paths, authority, and licenses. The historical private Hermes provider `council_memory_core` and public provider `mnemoir_provenance` are separate. The 0.2.1 candidate does not rewrite config, select the public provider, copy/rename an old DB, or rename legacy `cmc_*` tools.

Before deliberate migration, stop writers through the operator's approved procedure, make and verify an SQLite-consistent backup, choose an explicit target DB, copy/import through a controlled path, reconcile table/source/evidence counts and hashes, run cited plus empty/degraded recall, and read back active versions. Keep the old provider selection and old DB intact until rollback is no longer needed. Do not grant live API access to a legacy backend merely to simplify migration.
