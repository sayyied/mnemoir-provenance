# Memory and proposal states

Proposals: proposed, edited, approved, rejected, written. Memories: active or tombstoned, with an integer current version. Lifecycle operations include create, review, write, revise/supersede, tombstone, and rollback.

State transitions reject stale or illegal requests and retain audit history.
