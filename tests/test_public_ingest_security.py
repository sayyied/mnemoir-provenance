from __future__ import annotations

import os
from pathlib import Path

import pytest

from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.ingest import ControlledReadError, _read_controlled_regular_text, ingest_repo_docs
from mnemoir_provenance.sources import configured_sources


def _root_with_index(tmp_path: Path, content: str = "SAFE IN-ROOT CONTENT\n") -> tuple[Path, Path]:
    root = tmp_path / "root"
    docs = root / "docs"
    docs.mkdir(parents=True)
    index = docs / "index.md"
    index.write_text(content, encoding="utf-8")
    return root, index


def test_public_ingest_accepts_an_in_root_regular_file(tmp_path):
    root, _ = _root_with_index(tmp_path)
    with connect(tmp_path / "db.sqlite") as conn:
        initialize_database(conn)
        result = ingest_repo_docs(conn, root, limit=5)
        stored = conn.execute("SELECT content, source_pointer FROM raw_events").fetchall()
    assert result["status"] == "ok"
    assert [(row["content"], row["source_pointer"]) for row in stored] == [("SAFE IN-ROOT CONTENT", "docs/index.md")]


def test_public_ingest_rejects_final_symlink_without_importing_outside_bytes(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE_SENTINEL_PRIVATE_CONTENT\n", encoding="utf-8")
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "index.md").symlink_to(outside)
    with connect(tmp_path / "db.sqlite") as conn:
        initialize_database(conn)
        result = ingest_repo_docs(conn, root, limit=5)
        stored = conn.execute("SELECT content FROM raw_events").fetchall()
    assert result["status"] == "degraded"
    assert stored == []
    assert configured_sources(root)[0].health == "unavailable"


def test_public_ingest_rejects_parent_directory_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.md").write_text("OUTSIDE PARENT CONTENT\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "docs").symlink_to(outside, target_is_directory=True)
    with connect(tmp_path / "db.sqlite") as conn:
        initialize_database(conn)
        result = ingest_repo_docs(conn, root, limit=5)
        count = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    assert result["status"] == "degraded"
    assert count == 0


def test_public_controlled_reader_rejects_broken_symlink(tmp_path):
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "index.md").symlink_to(tmp_path / "missing.md")
    with pytest.raises(ControlledReadError):
        _read_controlled_regular_text(root, "docs/index.md")


def test_public_controlled_reader_rejects_special_file(tmp_path):
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    os.mkfifo(root / "docs" / "index.md")
    with pytest.raises(ControlledReadError, match="configured_path_not_regular"):
        _read_controlled_regular_text(root, "docs/index.md")


def test_public_controlled_reader_rejects_hard_link(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE HARDLINK CONTENT\n", encoding="utf-8")
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    os.link(outside, root / "docs" / "index.md")
    with pytest.raises(ControlledReadError, match="configured_path_hardlink_denied"):
        _read_controlled_regular_text(root, "docs/index.md")


def test_public_controlled_reader_rejects_symlinked_root(tmp_path):
    real_root, _ = _root_with_index(tmp_path)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ControlledReadError):
        _read_controlled_regular_text(linked_root, "docs/index.md")


def test_public_open_descriptor_prevents_path_swap_from_changing_read_bytes(tmp_path, monkeypatch):
    root, index = _root_with_index(tmp_path, "ORIGINAL SAFE CONTENT\n")
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE SWAP CONTENT\n", encoding="utf-8")
    real_read = os.read
    swapped = False

    def swap_then_read(fd: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            index.unlink()
            index.symlink_to(outside)
        return real_read(fd, size)

    monkeypatch.setattr(os, "read", swap_then_read)
    text = _read_controlled_regular_text(root, "docs/index.md")
    assert text == "ORIGINAL SAFE CONTENT\n"
    assert "OUTSIDE SWAP CONTENT" not in text
