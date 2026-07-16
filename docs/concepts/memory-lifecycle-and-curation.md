# Memory lifecycle and curation

Proposal states are proposed, edited, approved, rejected, and written. Review records actor and reason. Approved writes create immutable memory versions tied to evidence. Supersession, tombstone, and rollback preserve correction history.

Writes are idempotent where a stable operation key is supplied, and every mutation is followed by authoritative read-back.
