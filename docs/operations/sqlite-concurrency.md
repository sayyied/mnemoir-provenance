# SQLite concurrency

Connections enable foreign keys, WAL where available, and a bounded busy timeout. Keep transactions short. Retry only known transient busy/locked errors with bounded backoff.

Do not retry policy denial, stale hash, path identity change, or authorization expiry as database contention.
