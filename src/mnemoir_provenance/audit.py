"""Audit receipts for Mnemoir Provenance compat 01."""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id


def write_audit_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    target_type: str,
    target_id: str | None,
    status: str,
    metadata: dict[str, Any] | None = None,
    error: str | None = None,
    actor_id: str | None = None,
    correlation_id: str | None = None,
) -> str:
    timestamp = now_utc()
    metadata_json = json_dumps(metadata or {})
    previous = conn.execute(
        "SELECT audit_hash FROM audit_events WHERE audit_hash IS NOT NULL ORDER BY occurred_at DESC, audit_id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["audit_hash"] if previous else None
    audit_id = f"audit_{uuid.uuid4().hex}"
    audit_hash = sha256_text(json_dumps({
        "audit_id": audit_id,
        "event_type": event_type,
        "target_type": target_type,
        "target_id": target_id,
        "status": status,
        "metadata": metadata or {},
        "previous_audit_hash": previous_hash,
        "occurred_at": timestamp,
    }))
    conn.execute(
        """
        INSERT INTO audit_events(
          audit_id, occurred_at, event_type, actor_id, target_type, target_id,
          status, error, previous_audit_hash, audit_hash, correlation_id, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit_id,
            timestamp,
            event_type,
            actor_id,
            target_type,
            target_id,
            status,
            error,
            previous_hash,
            audit_hash,
            correlation_id,
            metadata_json,
        ),
    )
    return audit_id


def list_audit_events(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT audit_id, occurred_at, event_type, target_type, target_id, status,
               error, correlation_id, metadata_json
        FROM audit_events
        ORDER BY occurred_at DESC, audit_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        item = row_to_dict(row)
        item["metadata"] = __import__("json").loads(item.pop("metadata_json"))
        events.append(item)
    return events
