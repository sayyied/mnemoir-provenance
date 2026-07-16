# SQLite locked

Identify concurrent long transactions, verify WAL/busy-timeout support, keep writes short, and use bounded retry only for known busy/locked codes. If contention persists, stop new mutations and inspect process ownership before recovery.

Do not delete lock/WAL files blindly.
