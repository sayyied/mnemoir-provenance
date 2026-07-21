#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import tempfile

from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.ingest import ingest_repo_docs
from mnemoir_provenance.recall import recall
from mnemoir_provenance.sources import register_sources

with tempfile.TemporaryDirectory(prefix="mnemoir-quickstart-") as temp:
    root = Path(temp)
    (root / "docs").mkdir()
    (root / "docs" / "index.md").write_text("Synthetic evidence: the project keeps cited local memory.\n", encoding="utf-8")
    with connect(root / "mnemoir.sqlite") as conn:
        initialize_database(conn)
        register_sources(conn, root)
        ingest_repo_docs(conn, root, limit=5)
        cited = recall(conn, "cited local memory", limit=3)
        empty = recall(conn, "zzzz-no-overlap-9f76b2", limit=3)
        assert cited["cited_results"]
        assert not empty["cited_results"]
        print(
            json.dumps(
                {
                    "status": "ok",
                    "hermes_required": False,
                    "database_owned_by_host": True,
                    "source_scope_explicit": True,
                    "cited_result_count": len(cited["cited_results"]),
                    "empty_result_count": len(empty["cited_results"]),
                    "coverage": cited["source_coverage"],
                },
                sort_keys=True,
            )
        )
