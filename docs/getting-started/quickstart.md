# Quickstart

Create a directory containing `docs/demo.md` with synthetic text. Set `MNEMOIR_ROOT` to that directory and `MNEMOIR_DB` to a writable SQLite file. Run `mnemoir sources`, `mnemoir ingest --limit 5`, then `mnemoir recall "your query" --limit 3`.

Expected output is JSON with `cited_results`, citation pointers/hashes, and `source_coverage`. No matching evidence produces zero results. A missing registered source produces `degraded` coverage rather than an uncited substitute.

Verify the installed Python path with `python examples/quickstart/python_quickstart.py`. Delete only the synthetic directory to tear down.
