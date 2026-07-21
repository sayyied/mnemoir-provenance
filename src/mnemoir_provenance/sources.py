"""Configured local source registry for Mnemoir Provenance compat 01."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import sqlite3
import stat
from typing import Any

from .db import json_dumps, now_utc, row_to_dict


@dataclass(frozen=True)
class SourceConfig:
    source_id: str
    source_type: str
    display_name: str
    external_ref: str
    authority_level: str
    read_authority: str
    write_authority: str
    health: str
    overflow_kind: str | None = None
    profile_id: str | None = None
    freshness_seconds: int | None = None
    failure_reason: str | None = None
    provenance_rules: dict[str, Any] | None = None
    privacy_policy: dict[str, Any] | None = None


def _controlled_regular_file_available(repo_root: Path, relative_path: str) -> bool:
    """Return a non-authoritative health snapshot without following links."""
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        return False
    try:
        root_metadata = repo_root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            return False
        current = repo_root
        for index, component in enumerate(rel.parts):
            current = current / component
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                return False
            final = index == len(rel.parts) - 1
            if final:
                return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            if not stat.S_ISDIR(metadata.st_mode):
                return False
    except OSError:
        return False
    return False


def configured_sources(repo_root: Path) -> list[SourceConfig]:
    docs_available = _controlled_regular_file_available(repo_root, "docs/index.md")
    missing_available = _controlled_regular_file_available(repo_root, "data/configured-local-source-missing.txt")
    docs_health = "healthy" if docs_available else "unavailable"
    return [
        SourceConfig(
            source_id="repo_docs_canonical",
            source_type="repo_docs",
            display_name="Canonical repository documentation",
            external_ref="repo://docs",
            authority_level="primary",
            read_authority="read_only",
            write_authority="none",
            health=docs_health,
            freshness_seconds=0 if docs_health == "healthy" else None,
            failure_reason=None if docs_health == "healthy" else "canonical docs index missing",
            provenance_rules={"pointer_policy": "relative_repo_path", "source_family": "repo_docs"},
            privacy_policy={"default_visibility": "internal", "redact_absolute_paths": True},
        ),
        SourceConfig(
            source_id="local_file_configured_missing",
            source_type="file",
            display_name="Configured local file source unavailable sentinel",
            external_ref="file://configured-local-source-missing.txt",
            authority_level="secondary",
            read_authority="read_only",
            write_authority="none",
            health="healthy" if missing_available else "unavailable",
            freshness_seconds=0 if missing_available else None,
            failure_reason=None if missing_available else "configured local file source is unavailable",
            provenance_rules={"pointer_policy": "relative_repo_path", "source_family": "file"},
            privacy_policy={"default_visibility": "private", "redact_absolute_paths": True},
        ),
    ]


def register_sources(conn: sqlite3.Connection, repo_root: Path) -> list[dict[str, Any]]:
    timestamp = now_utc()
    configs = configured_sources(repo_root)
    for source in configs:
        conn.execute(
            """
            INSERT INTO sources(
              source_id, source_type, display_name, external_ref, profile_id,
              overflow_kind, read_authority, write_authority, authority_level,
              health, last_sync_at, freshness_seconds, failure_reason,
              provenance_rules_json, privacy_policy_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO UPDATE SET
              source_type=excluded.source_type,
              display_name=excluded.display_name,
              external_ref=excluded.external_ref,
              profile_id=excluded.profile_id,
              overflow_kind=excluded.overflow_kind,
              read_authority=excluded.read_authority,
              write_authority=excluded.write_authority,
              authority_level=excluded.authority_level,
              health=excluded.health,
              last_sync_at=excluded.last_sync_at,
              freshness_seconds=excluded.freshness_seconds,
              failure_reason=excluded.failure_reason,
              provenance_rules_json=excluded.provenance_rules_json,
              privacy_policy_json=excluded.privacy_policy_json,
              updated_at=excluded.updated_at
            """,
            (
                source.source_id,
                source.source_type,
                source.display_name,
                source.external_ref,
                source.profile_id,
                source.overflow_kind,
                source.read_authority,
                source.write_authority,
                source.authority_level,
                source.health,
                timestamp if source.health == "healthy" else None,
                source.freshness_seconds,
                source.failure_reason,
                json_dumps(source.provenance_rules or {}),
                json_dumps(source.privacy_policy or {}),
                timestamp,
                timestamp,
            ),
        )
    conn.commit()
    return list_sources(conn)


def list_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT source_id, source_type, display_name, external_ref, profile_id,
               overflow_kind, read_authority, write_authority, authority_level,
               health, last_sync_at, freshness_seconds, failure_reason
        FROM sources
        ORDER BY authority_level, source_type, source_id
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]
