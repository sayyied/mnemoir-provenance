# Data model

The canonical store is local SQLite. Its tables are organized around a small number of lifecycle concerns, and stable identifiers plus content hashes make idempotency and provenance inspectable.

**In one sentence:** Mnemoir stores a complete, hash-addressable history of sources, observations, evidence, decisions, and mutations — so any record can be traced to what supported it and what changed it.

## The canonical tables

- **Sources:** source registry and snapshots — identity, authority, health, privacy, scope.
- **Observations:** raw events, source-identified and hashed.
- **Evidence:** provenance edges connecting source, event, evidence, proposal, memory, review, and output.
- **Actors and scopes:** typed boundaries for tenant, profile, project, session, actor, council, source, and global scope.
- **Decisions:** proposals and reviews with attributable actor and reason.
- **Memory:** memories and immutable versions, with supersession, tombstone, and rollback history.
- **Retrieval:** retrieval logs and adaptive/thermal scores.
- **Coordination:** Council objectives, assignments, evidence packets, reviews, and handoffs.
- **Autonomy:** bounded jobs, ticks, plans, budgets, and receipts.
- **Maintenance:** audits, benchmarks, experiments, and writeback transactions.

## Identity and idempotency

Stable identifiers and content hashes make operations idempotent where a stable operation key is supplied, and make lineage inspectable end to end. Timestamps intentionally create new lifecycle records where chronology matters, rather than silently overwriting a prior state.

## What is available today?

| Concern | Stored canonically? | Derived views? |
|---|---:|---|
| Sources, events, evidence | yes | no |
| Proposals, reviews | yes | no |
| Memories, versions | yes | Markdown/Obsidian projection (non-canonical) |
| Scores, retrieval logs | yes | no |
| Writeback transactions | yes (private journal) | no |

## Fail-closed boundaries

Connections enable foreign keys and WAL where available, with a bounded busy timeout. A missing authority, an unknown scope, or a stale hash fails closed with a stable reason. Reconciliation handles interrupted writeback states; an unknown target hash is not retried as transient contention.

## Next steps

- Read [Schemas](../reference/schemas.md) for the released JSON schemas and the canonical SQL resource.
- Read [Memory and proposal states](../reference/memory-states.md) for the lifecycle state machine.
- Read [Scope and privacy matrix](../reference/scope-and-privacy-matrix.md) for how typed boundaries are evaluated.
- Read [SQLite concurrency](../operations/sqlite-concurrency.md) for connection and contention behavior.
