"""Read-only local ingestion for Mnemoir Provenance compat 01."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, sha256_text, stable_id
from .sources import register_sources

DOC_SOURCE_ID = "repo_docs_canonical"
INGEST_PATHS = [
    "docs/index.md",
    "docs/status/current.md",
    "docs/product/capability-ledger.md",
    "docs/verification/acceptance-map.md",
    "docs/contracts/source-registry-alignment.md",
    "docs/contracts/recall-query.md",
]


@dataclass(frozen=True)
class IngestRecord:
    relative_path: str
    content: str
    line_start: int
    line_end: int
    occurred_at: str


def ensure_system_actor(conn: sqlite3.Connection) -> None:
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, created_at, updated_at)
        VALUES ('actor_system_compat01', 'system', 'Mnemoir Provenance compat 01', 'mnemoir-compat01', 'compat01', ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (timestamp, timestamp),
    )


def _file_records(path: Path, relative_path: str) -> list[IngestRecord]:
    text = path.read_text(encoding="utf-8")
    occurred_at = now_utc()
    records: list[IngestRecord] = []
    current: list[str] = []
    start_line = 1
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            if not current:
                start_line = line_no
            current.append(line)
        elif current:
            records.append(IngestRecord(relative_path, "\n".join(current), start_line, line_no - 1, occurred_at))
            current = []
    if current:
        records.append(IngestRecord(relative_path, "\n".join(current), start_line, start_line + len(current) - 1, occurred_at))
    return records


def configured_repo_doc_records(repo_root: Path) -> list[IngestRecord]:
    records: list[IngestRecord] = []
    for rel in INGEST_PATHS:
        path = repo_root / rel
        if path.exists():
            records.extend(_file_records(path, rel))
    return records


def ingest_repo_docs(conn: sqlite3.Connection, repo_root: Path, limit: int = 25) -> dict[str, Any]:
    ensure_system_actor(conn)
    sources = register_sources(conn, repo_root)
    source_state = {source["source_id"]: source for source in sources}
    docs_source = source_state.get(DOC_SOURCE_ID)
    if not docs_source or docs_source["health"] != "healthy":
        write_audit_event(
            conn,
            event_type="ingest.repo_docs",
            target_type="source",
            target_id=DOC_SOURCE_ID,
            status="degraded",
            metadata={"reason": "repo docs source unavailable", "inserted_raw_events": 0},
        )
        conn.commit()
        return {"status": "degraded", "inserted_raw_events": 0, "inserted_evidence_items": 0, "sources": sources}

    before_raw = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    before_evidence = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
    records = configured_repo_doc_records(repo_root)[:limit]
    timestamp = now_utc()
    snapshot_ids: dict[str, str] = {}
    inserted_raw = 0
    inserted_evidence = 0

    for record in records:
        content_hash = sha256_text(record.content)
        snapshot_id = snapshot_ids.get(record.relative_path)
        if snapshot_id is None:
            snapshot_hash = sha256_text((repo_root / record.relative_path).read_text(encoding="utf-8"))
            snapshot_id = stable_id("snapshot", DOC_SOURCE_ID, record.relative_path, snapshot_hash)
            snapshot_ids[record.relative_path] = snapshot_id
            conn.execute(
                """
                INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, DOC_SOURCE_ID, snapshot_hash, record.relative_path, timestamp, json_dumps({"path": record.relative_path})),
            )

        event_id = stable_id("event", DOC_SOURCE_ID, record.relative_path, record.line_start, record.line_end, content_hash)
        event_hash = sha256_text(json_dumps({"event_id": event_id, "content_hash": content_hash, "source": DOC_SOURCE_ID}))
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO raw_events(
              event_id, source_id, snapshot_id, speaker_actor_id, event_type,
              content, content_hash, occurred_at, ingested_at, visibility,
              privacy_class, source_pointer, line_start, line_end, provenance_json,
              event_hash
            ) VALUES (?, ?, ?, ?, 'file_block', ?, ?, ?, ?, 'internal', 'internal', ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                DOC_SOURCE_ID,
                snapshot_id,
                "actor_system_compat01",
                record.content,
                content_hash,
                record.occurred_at,
                timestamp,
                record.relative_path,
                record.line_start,
                record.line_end,
                json_dumps({"relative_path": record.relative_path, "line_start": record.line_start, "line_end": record.line_end}),
                event_hash,
            ),
        )
        inserted_raw += cur.rowcount if cur.rowcount > 0 else 0

        evidence_id = stable_id("evidence", event_id)
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO evidence_items(
              evidence_id, kind, source_id, raw_event_id, uri, locator_json,
              quote_text, content_hash, trust_score, privacy_class, observed_at, created_at
            ) VALUES (?, 'document', ?, ?, ?, ?, ?, ?, 0.75, 'internal', ?, ?)
            """,
            (
                evidence_id,
                DOC_SOURCE_ID,
                event_id,
                f"repo://{record.relative_path}",
                json_dumps({"path": record.relative_path, "line_start": record.line_start, "line_end": record.line_end}),
                record.content[:500],
                content_hash,
                record.occurred_at,
                timestamp,
            ),
        )
        inserted_evidence += cur.rowcount if cur.rowcount > 0 else 0

    after_raw = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    after_evidence = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
    audit_id = write_audit_event(
        conn,
        event_type="ingest.repo_docs",
        target_type="source",
        target_id=DOC_SOURCE_ID,
        status="ok" if records else "degraded",
        metadata={
            "attempted_records": len(records),
            "inserted_raw_events": inserted_raw,
            "inserted_evidence_items": inserted_evidence,
            "raw_event_count_before": before_raw,
            "raw_event_count_after": after_raw,
            "evidence_count_before": before_evidence,
            "evidence_count_after": after_evidence,
            "source_ids": [source["source_id"] for source in sources],
        },
    )
    conn.commit()
    return {
        "status": "ok" if records else "degraded",
        "attempted_records": len(records),
        "inserted_raw_events": inserted_raw,
        "inserted_evidence_items": inserted_evidence,
        "raw_event_count_before": before_raw,
        "raw_event_count_after": after_raw,
        "evidence_count_before": before_evidence,
        "evidence_count_after": after_evidence,
        "audit_id": audit_id,
        "sources": sources,
    }
