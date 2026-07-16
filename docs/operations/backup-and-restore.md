# Backup and restore

Use SQLite-consistent backup methods while writers are coordinated. Keep database backups private and test restore into an isolated path. Writeback transaction backups are operation-scoped recovery material, not general database backups.

After restore, run schema initialization/migrations, health, cited recall, version read-back, and source reconciliation before resuming mutations.
