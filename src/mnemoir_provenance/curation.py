"""Memory curation and writeback runtime for Mnemoir Provenance compat 02."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

CURATION_SOURCE_ID = "mnemoir_provenance_canonical"
OPERATOR_ACTOR_ID = "actor_operator_compat02"
_ALLOWED_PROPOSAL_STATUSES = {"proposed", "approved", "rejected", "edited", "written"}


class CurationError(ValueError):
    """Domain error that should be reported as fail-closed CLI JSON."""


def _json_loads(text: str | None, default: Any) -> Any:
    return json.loads(text) if text else default


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _proposal_status(conn: sqlite3.Connection, proposal_id: str) -> str:
    row = conn.execute("SELECT status FROM memory_proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
    if row is None:
        raise CurationError("proposal_not_found")
    return row["status"]


def ensure_compat02_runtime(conn: sqlite3.Connection) -> None:
    """Install compat 02 seed actor/source rows without touching Hermes profile files."""
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, created_at, updated_at)
        VALUES (?, 'system', 'Mnemoir Provenance compat 02 Operator', 'mnemoir-compat02', 'compat02', ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (OPERATOR_ACTOR_ID, timestamp, timestamp),
    )
    conn.execute(
        """
        INSERT INTO sources(
          source_id, source_type, display_name, external_ref, read_authority,
          write_authority, authority_level, health, last_sync_at, freshness_seconds,
          provenance_rules_json, privacy_policy_json, created_at, updated_at
        ) VALUES (?, 'council_core', 'Mnemoir Provenance canonical memory store',
                  'council-core://canonical-memory-store', 'read_sensitive', 'write_allowed',
                  'primary', 'healthy', ?, 0, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET
          write_authority=excluded.write_authority,
          health=excluded.health,
          updated_at=excluded.updated_at
        """,
        (
            CURATION_SOURCE_ID,
            timestamp,
            json_dumps({"phase": "compat02", "write_policy": "approved_proposals_only"}),
            json_dumps({"redact_absolute_paths": True, "default_visibility": "private"}),
            timestamp,
            timestamp,
        ),
    )


def _validate_refs(conn: sqlite3.Connection, source_event_ids: list[str], evidence_ids: list[str]) -> None:
    if not source_event_ids and not evidence_ids:
        raise CurationError("missing_source_evidence")
    for event_id in source_event_ids:
        if conn.execute("SELECT 1 FROM raw_events WHERE event_id = ?", (event_id,)).fetchone() is None:
            raise CurationError("source_event_not_found")
    for evidence_id in evidence_ids:
        if conn.execute("SELECT 1 FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone() is None:
            raise CurationError("evidence_not_found")


def _check_write_authority(conn: sqlite3.Connection, target_source_id: str) -> None:
    row = conn.execute("SELECT write_authority, health FROM sources WHERE source_id = ?", (target_source_id,)).fetchone()
    if row is None:
        raise CurationError("write_target_not_found")
    if row["write_authority"] != "write_allowed" or row["health"] in {"unauthorized", "disabled", "unavailable"}:
        raise CurationError("write_target_denied")


def create_proposal(
    conn: sqlite3.Connection,
    *,
    title: str,
    summary: str,
    body: str,
    evidence_ids: list[str] | None = None,
    source_event_ids: list[str] | None = None,
    target_source_id: str = CURATION_SOURCE_ID,
    memory_id: str | None = None,
    memory_type: str = "semantic",
    scope: str = "global",
    privacy_class: str = "private",
    actor_id: str = OPERATOR_ACTOR_ID,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    ensure_compat02_runtime(conn)
    evidence_ids = evidence_ids or []
    source_event_ids = source_event_ids or []
    _validate_refs(conn, source_event_ids, evidence_ids)
    if memory_id and conn.execute("SELECT 1 FROM memories WHERE memory_id = ?", (memory_id,)).fetchone() is None:
        raise CurationError("memory_not_found")
    timestamp = now_utc()
    content_hash = sha256_text(json_dumps({"title": title, "summary": summary, "body": body, "evidence_ids": evidence_ids, "source_event_ids": source_event_ids, "memory_id": memory_id}))
    proposal_id = stable_id("proposal", target_source_id, memory_id or "new", content_hash, idempotency_key or timestamp)
    existing = conn.execute("SELECT status FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if existing is not None:
        return {"status": "ok", "proposal_id": proposal_id, "proposal_status": existing["status"], "audit_id": None, "idempotency_status": "existing"}
    conn.execute(
        """
        INSERT INTO memory_proposals(
          proposal_id, status, target_source_id, memory_id, title, summary, body,
          memory_type, scope, privacy_class, source_event_ids_json, evidence_ids_json,
          operator_actor_id, content_hash, created_at, updated_at
        ) VALUES (?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proposal_id,
            target_source_id,
            memory_id,
            title,
            summary,
            body,
            memory_type,
            scope,
            privacy_class,
            json_dumps(source_event_ids),
            json_dumps(evidence_ids),
            actor_id,
            content_hash,
            timestamp,
            timestamp,
        ),
    )
    audit_id = write_audit_event(
        conn,
        event_type="memory_proposal.create",
        target_type="memory_proposal",
        target_id=proposal_id,
        status="ok",
        actor_id=actor_id,
        metadata={"status": "proposed", "evidence_count": len(evidence_ids), "source_event_count": len(source_event_ids)},
    )
    conn.commit()
    return {"status": "ok", "proposal_id": proposal_id, "proposal_status": "proposed", "audit_id": audit_id}


def list_proposals(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT proposal_id, status, target_source_id, memory_id, title, summary,
               memory_type, scope, privacy_class, operator_actor_id, reviewer_actor_id,
               created_at, updated_at, reviewed_at, written_at
        FROM memory_proposals
        ORDER BY updated_at DESC, proposal_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def inspect_proposal(conn: sqlite3.Connection, proposal_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if row is None:
        raise CurationError("proposal_not_found")
    result = row_to_dict(row)
    result["source_event_ids"] = _json_loads(result.pop("source_event_ids_json"), [])
    result["evidence_ids"] = _json_loads(result.pop("evidence_ids_json"), [])
    return result


def review_proposal(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    action: str,
    reviewer_actor_id: str,
    reason: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    ensure_compat02_runtime(conn)
    reviewer = conn.execute(
        "SELECT kind, is_active FROM actors WHERE actor_id = ?",
        (reviewer_actor_id,),
    ).fetchone()
    if reviewer is None:
        raise CurationError("reviewer_not_found")
    if not reviewer["is_active"]:
        raise CurationError("reviewer_inactive")
    if reviewer["kind"] not in {"human", "agent", "system"}:
        raise CurationError("reviewer_unauthorized")
    current = _proposal_status(conn, proposal_id)
    if current == "written":
        raise CurationError("proposal_already_written")
    if current == "rejected":
        raise CurationError("proposal_already_rejected")
    if action not in {"approve", "reject", "edit"}:
        raise CurationError("invalid_review_action")
    timestamp = now_utc()
    if action == "approve":
        if current not in {"proposed", "edited", "approved"}:
            raise CurationError("illegal_transition")
        next_status = "approved"
        updates = "status = ?, reviewer_actor_id = ?, review_reason = ?, reviewed_at = ?, updated_at = ?"
        params: tuple[Any, ...] = (next_status, reviewer_actor_id, reason, timestamp, timestamp, proposal_id)
    elif action == "reject":
        if current not in {"proposed", "edited", "approved"}:
            raise CurationError("illegal_transition")
        next_status = "rejected"
        updates = "status = ?, reviewer_actor_id = ?, review_reason = ?, reviewed_at = ?, updated_at = ?"
        params = (next_status, reviewer_actor_id, reason, timestamp, timestamp, proposal_id)
    else:
        if current not in {"proposed", "approved", "edited"}:
            raise CurationError("illegal_transition")
        row = conn.execute("SELECT title, summary, body FROM memory_proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
        next_status = "edited"
        new_title = title if title is not None else row["title"]
        new_summary = summary if summary is not None else row["summary"]
        new_body = body if body is not None else row["body"]
        content_hash = sha256_text(json_dumps({"title": new_title, "summary": new_summary, "body": new_body}))
        updates = "status = ?, reviewer_actor_id = ?, review_reason = ?, title = ?, summary = ?, body = ?, content_hash = ?, reviewed_at = ?, updated_at = ?"
        params = (next_status, reviewer_actor_id, reason, new_title, new_summary, new_body, content_hash, timestamp, timestamp, proposal_id)
    conn.execute(f"UPDATE memory_proposals SET {updates} WHERE proposal_id = ?", params)
    audit_id = write_audit_event(
        conn,
        event_type=f"memory_proposal.{action}",
        target_type="memory_proposal",
        target_id=proposal_id,
        status="ok",
        actor_id=reviewer_actor_id,
        metadata={"from_status": current, "to_status": next_status, "reason": reason},
    )
    conn.commit()
    return {"status": "ok", "proposal_id": proposal_id, "proposal_status": next_status, "audit_id": audit_id}


def write_memory(conn: sqlite3.Connection, *, proposal_id: str, actor_id: str = OPERATOR_ACTOR_ID, _commit: bool = True) -> dict[str, Any]:
    ensure_compat02_runtime(conn)
    row = conn.execute("SELECT * FROM memory_proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
    if row is None:
        raise CurationError("proposal_not_found")
    if row["status"] == "written" and row["memory_id"]:
        existing = read_memory(conn, row["memory_id"])
        return {"status": "ok", "proposal_id": proposal_id, "memory_id": row["memory_id"], "version": existing["memory"]["current_version"], "audit_id": None, "read_back": existing, "idempotency_status": "existing"}
    if row["status"] != "approved":
        raise CurationError("proposal_not_approved")
    target_source_id = row["target_source_id"]
    _check_write_authority(conn, target_source_id)
    evidence_ids = _json_loads(row["evidence_ids_json"], [])
    source_event_ids = _json_loads(row["source_event_ids_json"], [])
    _validate_refs(conn, source_event_ids, evidence_ids)
    timestamp = now_utc()
    before_memory_id = row["memory_id"]
    if before_memory_id:
        existing = conn.execute("SELECT * FROM memories WHERE memory_id = ?", (before_memory_id,)).fetchone()
        if existing is None:
            raise CurationError("memory_not_found")
        memory_id = before_memory_id
        next_version = int(existing["current_version"]) + 1
        previous_hash_row = conn.execute(
            "SELECT version_hash FROM memory_versions WHERE memory_id = ? AND version = ?",
            (memory_id, existing["current_version"]),
        ).fetchone()
        previous_hash = previous_hash_row["version_hash"] if previous_hash_row else None
        conn.execute(
            """
            UPDATE memories
            SET current_version = ?, status = 'active', confidence = ?, privacy_class = ?, updated_at = ?
            WHERE memory_id = ?
            """,
            (next_version, 0.7, row["privacy_class"], timestamp, memory_id),
        )
        change_type = "revise"
        from_status = existing["status"]
    else:
        memory_id = stable_id("memory", row["proposal_id"], row["content_hash"])
        next_version = 1
        previous_hash = None
        conn.execute(
            """
            INSERT INTO memories(
              memory_id, scope, owner_actor_id, memory_type, status, current_version,
              confidence, salience, novelty, stability, privacy_class, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'active', 1, 0.7, 0.2, 0.2, 0.5, ?, ?, ?)
            """,
            (memory_id, row["scope"], row["operator_actor_id"] or actor_id, row["memory_type"], row["privacy_class"], timestamp, timestamp),
        )
        change_type = "create"
        from_status = None
    version_hash = sha256_text(json_dumps({"memory_id": memory_id, "version": next_version, "title": row["title"], "summary": row["summary"], "body": row["body"]}))
    conn.execute(
        """
        INSERT INTO memory_versions(
          memory_id, version, title, summary, body, change_type, changed_by_actor_id,
          reason, confidence, version_hash, previous_version_hash, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.7, ?, ?, ?, ?)
        """,
        (
            memory_id,
            next_version,
            row["title"],
            row["summary"],
            row["body"],
            change_type,
            actor_id,
            f"written from proposal {proposal_id}",
            version_hash,
            previous_hash,
            json_dumps({"proposal_id": proposal_id, "target_source_id": target_source_id, "source_event_ids": source_event_ids}),
            timestamp,
        ),
    )
    for evidence_id in evidence_ids:
        conn.execute(
            """
            INSERT OR IGNORE INTO memory_evidence(memory_id, version, evidence_id, role, weight, created_at)
            VALUES (?, ?, ?, 'primary', 1.0, ?)
            """,
            (memory_id, next_version, evidence_id, timestamp),
        )
    audit_id = write_audit_event(
        conn,
        event_type="memory.write",
        target_type="memory",
        target_id=memory_id,
        status="ok",
        actor_id=actor_id,
        metadata={"proposal_id": proposal_id, "version": next_version, "change_type": change_type, "evidence_count": len(evidence_ids)},
    )
    conn.execute(
        """
        INSERT INTO memory_lifecycle_events(lifecycle_id, memory_id, from_status, to_status, reason, actor_id, audit_id, occurred_at)
        VALUES (?, ?, ?, 'active', ?, ?, ?, ?)
        """,
        (stable_id("lifecycle", memory_id, "write", next_version, timestamp), memory_id, from_status, "proposal_write", actor_id, audit_id, timestamp),
    )
    conn.execute("UPDATE memory_proposals SET status = 'written', memory_id = ?, written_at = ?, updated_at = ? WHERE proposal_id = ?", (memory_id, timestamp, timestamp, proposal_id))
    if _commit:
        conn.commit()
    return {"status": "ok", "proposal_id": proposal_id, "memory_id": memory_id, "version": next_version, "audit_id": audit_id, "read_back": read_memory(conn, memory_id)}


def read_memory(conn: sqlite3.Connection, memory_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None:
        raise CurationError("memory_not_found")
    memory = row_to_dict(row)
    version = conn.execute(
        "SELECT * FROM memory_versions WHERE memory_id = ? AND version = ?",
        (memory_id, memory["current_version"]),
    ).fetchone()
    versions = conn.execute(
        "SELECT version, title, summary, body, change_type, version_hash, previous_version_hash, created_at FROM memory_versions WHERE memory_id = ? ORDER BY version",
        (memory_id,),
    ).fetchall()
    evidence = conn.execute(
        "SELECT evidence_id, role, weight FROM memory_evidence WHERE memory_id = ? AND version = ? ORDER BY evidence_id",
        (memory_id, memory["current_version"]),
    ).fetchall()
    lifecycle = conn.execute(
        "SELECT from_status, to_status, reason, audit_id, occurred_at FROM memory_lifecycle_events WHERE memory_id = ? ORDER BY occurred_at, lifecycle_id",
        (memory_id,),
    ).fetchall()
    return {
        "status": "ok",
        "memory": memory,
        "current_version": row_to_dict(version) if version else None,
        "versions": [row_to_dict(item) for item in versions],
        "evidence": [row_to_dict(item) for item in evidence],
        "lifecycle": [row_to_dict(item) for item in lifecycle],
    }


def tombstone_memory(conn: sqlite3.Connection, *, memory_id: str, actor_id: str = OPERATOR_ACTOR_ID, reason: str = "operator_tombstone") -> dict[str, Any]:
    row = conn.execute("SELECT status FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None:
        raise CurationError("memory_not_found")
    if row["status"] == "tombstoned":
        raise CurationError("memory_already_tombstoned")
    timestamp = now_utc()
    audit_id = write_audit_event(
        conn,
        event_type="memory.tombstone",
        target_type="memory",
        target_id=memory_id,
        status="ok",
        actor_id=actor_id,
        metadata={"from_status": row["status"], "to_status": "tombstoned", "reason": reason},
    )
    conn.execute("UPDATE memories SET status = 'tombstoned', updated_at = ? WHERE memory_id = ?", (timestamp, memory_id))
    conn.execute(
        """
        INSERT INTO memory_lifecycle_events(lifecycle_id, memory_id, from_status, to_status, reason, actor_id, audit_id, occurred_at)
        VALUES (?, ?, ?, 'tombstoned', ?, ?, ?, ?)
        """,
        (stable_id("lifecycle", memory_id, "tombstone", timestamp), memory_id, row["status"], reason, actor_id, audit_id, timestamp),
    )
    conn.commit()
    return {"status": "ok", "memory_id": memory_id, "memory_status": "tombstoned", "audit_id": audit_id, "read_back": read_memory(conn, memory_id)}


def rollback_memory(conn: sqlite3.Connection, *, memory_id: str, version: int, actor_id: str = OPERATOR_ACTOR_ID, reason: str = "operator_rollback") -> dict[str, Any]:
    row = conn.execute("SELECT status, current_version FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None:
        raise CurationError("memory_not_found")
    target = conn.execute("SELECT version FROM memory_versions WHERE memory_id = ? AND version = ?", (memory_id, version)).fetchone()
    if target is None:
        raise CurationError("memory_version_not_found")
    timestamp = now_utc()
    audit_id = write_audit_event(
        conn,
        event_type="memory.rollback",
        target_type="memory",
        target_id=memory_id,
        status="ok",
        actor_id=actor_id,
        metadata={"from_version": row["current_version"], "to_version": version, "from_status": row["status"], "to_status": "active", "reason": reason},
    )
    conn.execute("UPDATE memories SET current_version = ?, status = 'active', updated_at = ? WHERE memory_id = ?", (version, timestamp, memory_id))
    conn.execute(
        """
        INSERT INTO memory_lifecycle_events(lifecycle_id, memory_id, from_status, to_status, reason, actor_id, audit_id, occurred_at)
        VALUES (?, ?, ?, 'active', ?, ?, ?, ?)
        """,
        (stable_id("lifecycle", memory_id, "rollback", version, timestamp), memory_id, row["status"], reason, actor_id, audit_id, timestamp),
    )
    conn.commit()
    return {"status": "ok", "memory_id": memory_id, "memory_status": "active", "version": version, "audit_id": audit_id, "read_back": read_memory(conn, memory_id)}


def proposal_from_cli_args(args: Any) -> dict[str, Any]:
    return {
        "title": args.title,
        "summary": args.summary,
        "body": args.body,
        "evidence_ids": _split_csv(args.evidence_ids),
        "source_event_ids": _split_csv(args.source_event_ids),
        "target_source_id": args.target_source_id,
        "memory_id": args.memory_id,
        "memory_type": args.memory_type,
        "scope": args.scope,
        "privacy_class": args.privacy_class,
    }
