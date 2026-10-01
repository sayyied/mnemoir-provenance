# Mental model

Mnemoir is built from a small set of record types that most systems collapse into a single opaque "memory" object. Keeping them separate is what makes provenance, review, and recovery possible.

**In one sentence:** Mnemoir tracks where a claim came from, what supported it, who decided it was durable, and what changed afterward — as distinct, inspectable records.

## The record types

| Record | Role | What it is not |
|---|---|---|
| Source | A registered origin with authority, health, and privacy policy | Not a guarantee of correctness |
| Raw event | A source-identified, hashed observation | Not accepted memory |
| Evidence | Retrievable support tied to a source and event | Not a universal truth certificate |
| Proposal | A candidate memory awaiting review | Not a written memory |
| Memory | An approved, versioned durable record | Not immutable across revisions |
| Version | One immutable revision of a memory | Not a separate memory |
| Receipt | A record of a decision or mutation | Not the thing it describes |

A citation points at supporting evidence. It is lineage, not a truth certificate: a highly ranked or frequently recalled memory is not authoritative merely because it ranks high.

## The invariants that hold across all of them

- **Observations are not memories.** An event becomes a durable memory only through a recorded proposal, review, and approved write.
- **Recall is cited or empty.** When no eligible evidence matches, the correct result is empty with visible coverage — not an uncited fallback.
- **Heat is attention, not truth.** Adaptive and thermal scores can reorder recall; source authority, scope, privacy, and provenance remain independent gates.
- **SQLite is canonical.** Markdown and wiki projections are derived views; editing a projection does not mutate memory.

## What is available today?

| Surface | Reads | Mutates | Boundary |
|---|---:|---:|---|
| Cited recall | evidence | no | Cited or empty/degraded; no uncited substitute |
| Proposal review | proposals | no | A proposal is a decision record, not a write |
| Approved write | memory | yes | Immutable version plus authoritative read-back |

## Fail-closed boundaries

Mnemoir abstains rather than substitutes when no eligible evidence remains; reports degraded or unavailable sources instead of hiding them; and keeps unknown scope, missing authority, or a missing citation as stable, visible denials.

## Next steps

- Read [Source grounding and provenance](source-grounding-and-provenance.md) for how citations carry source identity, pointer, hash, and time.
- Read [Memory lifecycle and curation](memory-lifecycle-and-curation.md) for proposal, review, write, revision, tombstone, and rollback.
- Read [Retrieval and context packing](retrieval-and-context-packing.md) for how recall is ranked and bounded.
- Read [Adaptive and thermal scoring](adaptive-thermal-scoring.md) for what heat does and does not decide.
