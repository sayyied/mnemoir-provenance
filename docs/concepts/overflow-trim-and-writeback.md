# Keep working memory small without losing its history

Working memory should stay small enough to steer the current session. Durable memory should keep useful history beyond the session. Overflow handling connects them: it can shorten bounded working-memory files without silently throwing their removed content away.

**In one sentence:** Mnemoir keeps active context compact while preserving trimmed material as private, cited evidence that can still be found later.

## Why this matters

Long-running agents accumulate instructions, preferences, decisions, and context. When compact prompt files grow toward their limits, useful facts compete for attention and manual cleanup risks deleting context that should remain discoverable. A blind truncate or rewrite may make the file smaller, but it gives you no trustworthy record of what changed, what was removed, or how to recover it.

Mnemoir treats overflow as a governed memory lifecycle instead of a text-deletion shortcut.

## Two kinds of memory

- **Working memory** is the small, high-signal context a host loads for the current interaction. In the Hermes reference adapter, this includes `MEMORY.md` and `USER.md`.
- **Durable Mnemoir memory** is the local SQLite-backed evidence, provenance, proposals, approved memories, versions, and receipts that can outlive one prompt or session.

Trimming moves pressure out of working memory without pretending the removed material never existed. Removed blocks are preserved as private evidence with source pointers and hashes; they are not automatically promoted into approved durable memories.

## The overflow lifecycle

1. **Measure pressure.** Mnemoir counts characters, reports warning/trigger state, and hashes the exact source snapshot. Status output is leak-safe: it returns counts, hashes, and redacted pointers rather than file contents.
2. **Build a deterministic trim plan.** The planner computes a target size and identifies removable blocks. Protected blocks are retained; if the target cannot be reached safely, the operation reports that instead of forcing deletion.
3. **Bind authorization to one exact operation.** A write capability is scoped to the operation, profile, target, allowed root, policy version, expiry, and source hash. In coordinator mode, explicit operator configuration is the durable bounded authorization; installing Mnemoir alone does not enable live writeback.
4. **Prepare recovery data before mutation.** Mnemoir writes a private journal, backup, and authenticated pending-evidence spool using restrictive local permissions.
5. **Replace safely and verify.** The executor locks the target, checks that its identity and hash still match, writes a temporary file, atomically replaces the target where supported, syncs it, and reads it back. A concurrent edit or stale hash stops the operation rather than overwriting newer work.
6. **Preserve evidence and retain rollback.** Only after read-back succeeds are removed blocks committed as private cited evidence. The receipt records the before/after hashes and operation state. Rollback is a separate authorized transaction bound to the exact post-write state.

## Reference Hermes policy

The included Hermes adapter uses these defaults:

| Target | Capacity | Warning | Trim trigger | Trim target |
|---|---:|---:|---:|---:|
| `MEMORY.md` | 2,200 characters | 80% | 90% | 50% |
| `USER.md` | 1,375 characters | 80% | 90% | 50% |

These are adapter defaults, not universal limits. A host can define a different policy for its own bounded working-memory targets.

For example, a 2,050-character `MEMORY.md` is above the default 90% trigger. Rather than chopping off text, Mnemoir plans toward 1,100 characters, binds the plan to the current file hash, preserves removed blocks as evidence, verifies the replacement, and retains a rollback path. If the file changes after measurement, the stale plan is rejected.

## What is available today?

| Surface | Reads live files? | Mutates files? | Current boundary |
|---|---:|---:|---|
| Controlled-fixture pressure status | No | No | Temporary caller-supplied fixtures only |
| Proposal planner | No | No | Uses already-ingested SQLite records |
| Live overflow status | Yes | No | Explicitly configured Hermes roots; status only |
| Authorized live writeback | Yes | Yes | Hermes `MEMORY.md`/`USER.md` plus a configured private transaction root |
| Overflow coordinator | Yes | Yes | Disabled unless a durable `writeback_mode=live_overflow_trim` policy is configured; scheduling is host-owned |

A proposal is not authorization and does not mutate a file. Authorized live operation requires an explicitly configured target adapter, policy, private journal/backup root, and authorization issuer or operator-enabled bounded coordinator policy. It is not enabled by package installation or provider discovery.

## Fail-closed boundaries

Mnemoir refuses or blocks the operation when the target is outside its allowed root, a path component is a symlink, the target is not a regular supported file, private backup permissions are unsafe, the source hash changed, protected blocks make the target unreachable, or recovery sees an unknown file state. Scheduling and service persistence remain the host's responsibility.

## Important operational boundaries

- The live implementation performs deterministic **block-level trimming**, not semantic summarization.
- Same-directory replacement and filesystem synchronization protect the target file, but the file replacement and SQLite evidence commit are not one atomic transaction. Reconciliation handles interrupted intermediate states.
- Rollback requires retained private recovery data, a new scoped authorization, and an exact match to the expected post-write hash. Some failures require manual recovery.
- Backups and removed blocks may contain sensitive plaintext. Operators own filesystem permissions, retention, and secure deletion.
- Mnemoir rejects unexpected hashes and path identities rather than overwriting concurrent edits, but it is not an operating-system sandbox.

The feature is local-first: it does not require a remote memory service, silently enable writeback, or turn trimmed evidence into unquestioned truth.

## Next steps

- Follow [Operate overflow safely](../guides/operate-overflow.md) for the operator sequence.
- Read [Overflow coordinator](../operations/overflow-coordinator.md) before enabling bounded live coordination.
- Use [Recover and roll back writeback](../guides/recover-and-rollback-writeback.md) for interrupted operations and restoration.
- Review the [Threat model](../operations/threat-model.md) for host and filesystem responsibilities.
- Use [Overflow and trim problems](../troubleshooting/overflow-and-trim.md) and [Writeback and rollback problems](../troubleshooting/writeback-and-rollback.md) for recovery guidance.
