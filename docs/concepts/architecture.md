# Architecture

Mnemoir is an in-process Python library over local SQLite. There is no daemon, hosted service, or required network listener; the value comes from a small set of domain operations that every surface calls.

**In one sentence:** one canonical SQLite store, one set of domain operations, and several thin surfaces (Python, JSON CLI, loopback UI, optional Hermes adapter) that do not fork the logic.

## The layers

| Layer | Responsibility | Boundary |
|---|---|---|
| Canonical store | SQLite: sources, events, evidence, proposals, memories, versions, receipts | Authoritative; everything else is derived |
| Domain operations | Ingest, recall, curation, scoring, overflow, coordination | Called by every surface; no per-surface logic fork |
| Surfaces | Python API, JSON CLI, loopback UI, optional Hermes adapter | Thin views over the domain operations |
| Controlled adapters | Ingest explicit caller-supplied exports | Separate from live private stores |
| Derived views | Markdown / Obsidian projection | Non-canonical; no write-back by default |

## Where the trust boundaries are

- **Local-first.** The base library starts no daemon or listener. `mnemoir ui` binds loopback only.
- **No remote memory by default.** No hosted memory, remote embedding, or third-party API is on the default path.
- **Explicit inputs.** Adapters accept caller-supplied controlled exports; they do not crawl live private stores.
- **One writer at a time.** Canonical mutations are followed by authoritative read-back; concurrent or stale state fails closed.

## What is available today?

| Surface | Reads live files? | Mutates? | Current boundary |
|---|---:|---:|---|
| Python API | no (canonical store) | yes (authorized ops) | In-process; host owns path, scope, approvals |
| JSON CLI | no | yes (authorized ops) | Machine-readable; stable exit codes |
| Loopback UI | yes (read view) | no | Same-process view over canonical APIs |
| Hermes adapter | yes (profile files) | opt-in | `writeback_mode=propose_only` by default |

## Fail-closed boundaries

Unknown or unconfigured child state is not hidden under a top-level healthy. A surface that cannot reach the store, a source, or a required policy reports degraded or denied rather than substituting. The loopback UI is a thin view: it does not add authority the canonical API does not already grant.

## Next steps

- Read [Data model](data-model.md) for the canonical tables and identity rules.
- Read [Integrate with Python](../guides/integrate-python.md) or [Integrate through CLI JSON](../guides/integrate-cli-json.md) for the two non-Hermes surfaces.
- Read [Security model](../operations/security-model.md) for filesystem and boundary rules.
- Read [Local deployment](../operations/local-deployment.md) for the loopback UI and service commands.
