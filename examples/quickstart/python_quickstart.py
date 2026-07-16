#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
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
        result = recall(conn, "cited local memory", limit=3)
        assert result["cited_results"]
        print(result)
