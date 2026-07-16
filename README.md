# Mnemoir Provenance

**Source-grounded memory for agents that learn over time.**

Mnemoir Provenance (pronounced “nem-wahr”) is a local-first, source-grounded memory core for agents, assistants, and multi-agent systems. It preserves citations, correction history, source coverage, and recoverable maintenance receipts so memory remains inspectable as it evolves.

> Candidate 0.2.0-rc.1 is private and unpublished. Name and trademark status is documented below; no clearance is claimed.

Mnemoir Provenance is an independent project. The qualified working name distinguishes it from other agent-memory projects; confusingly similar marks, common-law use, non-US rights, and later filings still require appropriate review before launch.

## Why it is different

- Cited recall reports which sources were searched and which were missing or degraded.
- Evidence, proposals, review, and durable writes are separate operations.
- Revisions, supersession, tombstones, and rollback preserve history.
- Overflow maintenance is preconditioned, authorized, auditable, and recoverable.
- The core works through Python or a JSON CLI; Hermes is an optional reference adapter.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
export MNEMOIR_DB="$PWD/demo.sqlite"
mnemoir ingest --limit 5
mnemoir recall "source grounded memory" --limit 3
```

The response is JSON. A healthy result includes `cited_results` and `source_coverage`; insufficient evidence returns an explicit empty or degraded state instead of an uncited fallback.

## Mental model

```text
sources -> raw events -> evidence -> proposals -> versioned memories
   |                                               |
   +------ cited recall + coverage + receipts -----+
```

Canonical state is SQLite. Markdown/wiki output is derived and never becomes canonical merely because it is readable.

## Integration paths

- [Python API](docs/guides/integrate-python.md)
- [CLI JSON](docs/guides/integrate-cli-json.md)
- [Generic harness](docs/guides/integrate-generic-harness.md)
- [Hermes reference adapter](docs/guides/integrate-hermes.md)
- [Working-memory adapters](docs/guides/write-working-memory-adapter.md)

## Documentation

Start at [docs/index.md](docs/index.md). Security boundaries are in [SECURITY.md](SECURITY.md) and [the threat model](docs/operations/threat-model.md). Overflow and writeback are explained in [the operations guide](docs/guides/operate-overflow.md).

## Name and trademark status

A USPTO Trademark Search wordmark query for `Mnemoir` returned no live, dead, or exact-result records on 2026-07-16. This bounded exact-query observation is not a legal opinion, name reservation, or comprehensive clearance. Confusingly similar marks, common-law use, non-US rights, and later filings still require appropriate review before launch.

## Boundaries

This project is local/self-hosted software, not a hosted service. Installation does not grant access to arbitrary files, enable live writeback, start a network service, configure a host, or promote memory automatically. Citations identify evidence; they do not guarantee truth. Ranking heat affects attention, not authority.

## License

MIT. See [LICENSE](LICENSE).
