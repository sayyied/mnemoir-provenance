"""Council state and evidence lifecycle runtime for Mnemoir Provenance compat 05."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

COUNCIL_OPERATOR_ACTOR_ID = "actor_operator_compat05"
DEFAULT_PROJECT_ID = "project_mnemoir_provenance"

COUNCIL_MEMBERS: tuple[tuple[str, str, str, str], ...] = (
    ("actor_operator", "human", "Operator", "operator"),
    ("actor_orchestrator", "agent", "Orchestrator", "orchestrator"),
    ("actor_engineer", "agent", "Engineer", "engineering"),
    ("actor_researcher", "agent", "Researcher", "research"),
    ("actor_storyteller", "agent", "Storyteller", "narrative"),
    ("actor_finance", "agent", "Finance Reviewer", "finance"),
    ("actor_wellness", "agent", "Wellness Reviewer", "wellness"),
    ("actor_quality_reviewer", "agent", "Quality Reviewer", "quality_veto"),
)

OBJECTIVE_STATUSES = {"open", "in_progress", "blocked", "review", "closed", "archived"}
ASSIGNMENT_STATUSES = {"open", "claimed", "in_progress", "blocked", "complete", "closed"}
REVIEW_OUTCOMES = {"approve", "revise", "reject", "veto", "blocked", "handoff_required", "abstain"}
HANDOFF_STATUSES = {"open", "ready", "blocked", "accepted", "closed", "superseded"}
RECORD_KINDS = {"blocker", "risk", "decision", "proposal"}
REF_TABLES = {
    "evidence": ("evidence_items", "evidence_id"),
    "raw_event": ("raw_events", "event_id"),
    "memory": ("memories", "memory_id"),
    "retrieval_query": ("retrieval_queries", "query_id"),
    "audit": ("audit_events", "audit_id"),
    "artifact": (None, None),
}


class CouncilError(ValueError):
    """Domain error reported by the CLI as fail-closed JSON."""


def _json_loads(text: str | None, default: Any) -> Any:
    return json.loads(text) if text else default


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _require_actor(conn: sqlite3.Connection, actor_id: str) -> None:
    if conn.execute("SELECT 1 FROM actors WHERE actor_id = ?", (actor_id,)).fetchone() is None:
        raise CouncilError("actor_not_found")


def _require_objective(conn: sqlite3.Connection, objective_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM council_objectives WHERE objective_id = ?", (objective_id,)).fetchone()
    if row is None:
        raise CouncilError("objective_not_found")
    return row


def _require_assignment(conn: sqlite3.Connection, assignment_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM council_assignments WHERE assignment_id = ?", (assignment_id,)).fetchone()
    if row is None:
        raise CouncilError("assignment_not_found")
    return row


def _require_evidence_packet(conn: sqlite3.Connection, packet_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM council_evidence_packets WHERE packet_id = ?", (packet_id,)).fetchone()
    if row is None:
        raise CouncilError("evidence_packet_not_found")
    return row


def _ensure_project(conn: sqlite3.Connection) -> None:
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO projects(project_id, name, slug, owner_actor_id, status, privacy_class, created_at, updated_at)
        VALUES (?, 'Mnemoir Provenance', 'mnemoir-provenance', 'actor_operator', 'active', 'private', ?, ?)
        ON CONFLICT(project_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (DEFAULT_PROJECT_ID, timestamp, timestamp),
    )


def ensure_council_runtime(conn: sqlite3.Connection) -> None:
    """Seed leak-safe Council actors, project, and role bindings."""
    timestamp = now_utc()
    for actor_id, kind, display_name, _role in COUNCIL_MEMBERS:
        conn.execute(
            """
            INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, NULL, '{}', '{}', ?, ?, ?)
            ON CONFLICT(actor_id) DO UPDATE SET display_name=excluded.display_name, updated_at=excluded.updated_at
            """,
            (actor_id, kind, display_name, display_name.lower(), json_dumps({"phase": "compat05", "profile_internal_leakage": False}), timestamp, timestamp),
        )
    if conn.execute("SELECT 1 FROM actors WHERE actor_id = ?", (COUNCIL_OPERATOR_ACTOR_ID,)).fetchone() is None:
        conn.execute(
            """
            INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
            VALUES (?, 'system', 'Mnemoir Provenance compat 05 Operator', 'mnemoir-compat05', NULL, '{}', '{}', ?, ?, ?)
            """,
            (COUNCIL_OPERATOR_ACTOR_ID, json_dumps({"phase": "compat05"}), timestamp, timestamp),
        )
    _ensure_project(conn)
    for actor_id, _kind, _display_name, role in COUNCIL_MEMBERS:
        binding_id = stable_id("role", DEFAULT_PROJECT_ID, actor_id, role)
        conn.execute(
            """
            INSERT INTO council_role_bindings(binding_id, project_id, actor_id, role, status, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', '{}', ?, ?)
            ON CONFLICT(project_id, actor_id, role) DO UPDATE SET status='active', updated_at=excluded.updated_at
            """,
            (binding_id, DEFAULT_PROJECT_ID, actor_id, role, timestamp, timestamp),
        )
    conn.commit()


def list_members(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    rows = conn.execute(
        """
        SELECT rb.binding_id, rb.project_id, rb.actor_id, a.kind, a.display_name, rb.role, rb.status, rb.created_at, rb.updated_at
        FROM council_role_bindings rb
        JOIN actors a ON a.actor_id = rb.actor_id
        WHERE rb.status != 'deleted'
        ORDER BY a.kind DESC, a.display_name
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def bind_role(conn: sqlite3.Connection, *, actor_id: str, role: str, project_id: str = DEFAULT_PROJECT_ID, actor_id_operator: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    ensure_council_runtime(conn)
    _require_actor(conn, actor_id)
    timestamp = now_utc()
    binding_id = stable_id("role", project_id, actor_id, role)
    conn.execute(
        """
        INSERT INTO council_role_bindings(binding_id, project_id, actor_id, role, status, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', '{}', ?, ?)
        ON CONFLICT(project_id, actor_id, role) DO UPDATE SET status='active', updated_at=excluded.updated_at
        """,
        (binding_id, project_id, actor_id, role, timestamp, timestamp),
    )
    audit_id = write_audit_event(conn, event_type="council.member.bind_role", target_type="council_role_binding", target_id=binding_id, status="ok", actor_id=actor_id_operator, metadata={"actor_id": actor_id, "role": role, "project_id": project_id})
    conn.commit()
    return {"status": "ok", "binding_id": binding_id, "actor_id": actor_id, "role": role, "audit_id": audit_id}


def create_objective(conn: sqlite3.Connection, *, title: str, body: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID, owner_actor_id: str | None = None, project_id: str = DEFAULT_PROJECT_ID, priority: int = 0, status: str = "open") -> dict[str, Any]:
    ensure_council_runtime(conn)
    if status not in OBJECTIVE_STATUSES:
        raise CouncilError("invalid_objective_status")
    _require_actor(conn, actor_id)
    if owner_actor_id:
        _require_actor(conn, owner_actor_id)
    timestamp = now_utc()
    content_hash = sha256_text(json_dumps({"title": title, "body": body, "actor_id": actor_id, "owner_actor_id": owner_actor_id, "project_id": project_id, "timestamp": timestamp}))
    objective_id = stable_id("objective", project_id, title, content_hash)
    conn.execute(
        """
        INSERT INTO council_objectives(objective_id, project_id, title, body, status, priority, created_by_actor_id, owner_actor_id, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
        """,
        (objective_id, project_id, title, body, status, priority, actor_id, owner_actor_id, timestamp, timestamp),
    )
    audit_id = write_audit_event(conn, event_type="council.objective.create", target_type="council_objective", target_id=objective_id, status="ok", actor_id=actor_id, metadata={"objective_status": status, "owner_actor_id": owner_actor_id, "priority": priority})
    _write_lifecycle(conn, objective_id=objective_id, event_type="objective.create", actor_id=actor_id, from_status=None, to_status=status, audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "objective_id": objective_id, "objective_status": status, "audit_id": audit_id}


def list_objectives(conn: sqlite3.Connection, *, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    if status:
        rows = conn.execute("SELECT * FROM council_objectives WHERE status = ? ORDER BY updated_at DESC, objective_id DESC LIMIT ?", (status, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM council_objectives ORDER BY updated_at DESC, objective_id DESC LIMIT ?", (limit,)).fetchall()
    return [_objective_dict(row) for row in rows]


def show_objective(conn: sqlite3.Connection, objective_id: str) -> dict[str, Any]:
    ensure_council_runtime(conn)
    return {"status": "ok", "objective": _objective_dict(_require_objective(conn, objective_id))}


def search_objectives(conn: sqlite3.Connection, query: str, *, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    pattern = f"%{query}%"
    params: list[Any] = [pattern, pattern]
    sql = "SELECT * FROM council_objectives WHERE (title LIKE ? OR body LIKE ?)"
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY updated_at DESC, objective_id DESC LIMIT ?"
    params.append(limit)
    return [_objective_dict(row) for row in conn.execute(sql, params).fetchall()]


def update_objective_status(conn: sqlite3.Connection, *, objective_id: str, status: str, reason: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    ensure_council_runtime(conn)
    if status not in OBJECTIVE_STATUSES:
        raise CouncilError("invalid_objective_status")
    _require_actor(conn, actor_id)
    row = _require_objective(conn, objective_id)
    timestamp = now_utc()
    conn.execute("UPDATE council_objectives SET status = ?, updated_at = ? WHERE objective_id = ?", (status, timestamp, objective_id))
    audit_id = write_audit_event(conn, event_type=f"council.objective.{status}", target_type="council_objective", target_id=objective_id, status="ok", actor_id=actor_id, metadata={"from_status": row["status"], "to_status": status, "reason": reason})
    _write_lifecycle(conn, objective_id=objective_id, event_type=f"objective.{status}", actor_id=actor_id, from_status=row["status"], to_status=status, reason=reason, audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "objective_id": objective_id, "objective_status": status, "audit_id": audit_id}


def create_assignment(conn: sqlite3.Connection, *, objective_id: str, title: str, body: str, assigned_actor_id: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID, due_at: str | None = None, priority: int = 0) -> dict[str, Any]:
    ensure_council_runtime(conn)
    _require_objective(conn, objective_id)
    _require_actor(conn, actor_id)
    _require_actor(conn, assigned_actor_id)
    timestamp = now_utc()
    assignment_id = stable_id("assignment", objective_id, assigned_actor_id, title, timestamp)
    conn.execute(
        """
        INSERT INTO council_assignments(assignment_id, objective_id, title, body, status, assigned_actor_id, created_by_actor_id, priority, due_at, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, '{}', ?, ?)
        """,
        (assignment_id, objective_id, title, body, assigned_actor_id, actor_id, priority, due_at, timestamp, timestamp),
    )
    audit_id = write_audit_event(conn, event_type="council.assignment.create", target_type="council_assignment", target_id=assignment_id, status="ok", actor_id=actor_id, metadata={"objective_id": objective_id, "assigned_actor_id": assigned_actor_id})
    _write_lifecycle(conn, objective_id=objective_id, assignment_id=assignment_id, event_type="assignment.create", actor_id=actor_id, from_status=None, to_status="open", audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "assignment_id": assignment_id, "assignment_status": "open", "audit_id": audit_id}


def list_assignments(conn: sqlite3.Connection, *, objective_id: str | None = None, status: str | None = None, actor_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    clauses: list[str] = []
    params: list[Any] = []
    if objective_id:
        clauses.append("objective_id = ?")
        params.append(objective_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if actor_id:
        clauses.append("assigned_actor_id = ?")
        params.append(actor_id)
    sql = "SELECT * FROM council_assignments"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY updated_at DESC, assignment_id DESC LIMIT ?"
    params.append(limit)
    return [_row_with_metadata(row) for row in conn.execute(sql, params).fetchall()]


def update_assignment_status(conn: sqlite3.Connection, *, assignment_id: str, status: str, reason: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    ensure_council_runtime(conn)
    if status not in ASSIGNMENT_STATUSES:
        raise CouncilError("invalid_assignment_status")
    _require_actor(conn, actor_id)
    row = _require_assignment(conn, assignment_id)
    timestamp = now_utc()
    conn.execute("UPDATE council_assignments SET status = ?, updated_at = ? WHERE assignment_id = ?", (status, timestamp, assignment_id))
    audit_id = write_audit_event(conn, event_type=f"council.assignment.{status}", target_type="council_assignment", target_id=assignment_id, status="ok", actor_id=actor_id, metadata={"objective_id": row["objective_id"], "from_status": row["status"], "to_status": status, "reason": reason})
    _write_lifecycle(conn, objective_id=row["objective_id"], assignment_id=assignment_id, event_type=f"assignment.{status}", actor_id=actor_id, from_status=row["status"], to_status=status, reason=reason, audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "assignment_id": assignment_id, "assignment_status": status, "audit_id": audit_id}


def create_record(conn: sqlite3.Connection, *, objective_id: str, kind: str, title: str, body: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID, severity: str | None = None) -> dict[str, Any]:
    ensure_council_runtime(conn)
    if kind not in RECORD_KINDS:
        raise CouncilError("invalid_record_kind")
    _require_objective(conn, objective_id)
    _require_actor(conn, actor_id)
    timestamp = now_utc()
    record_id = stable_id(f"council_{kind}", objective_id, title, timestamp)
    conn.execute(
        """
        INSERT INTO council_records(record_id, objective_id, kind, title, body, status, created_by_actor_id, severity, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, '{}', ?, ?)
        """,
        (record_id, objective_id, kind, title, body, actor_id, severity, timestamp, timestamp),
    )
    audit_id = write_audit_event(conn, event_type=f"council.{kind}.create", target_type="council_record", target_id=record_id, status="ok", actor_id=actor_id, metadata={"objective_id": objective_id, "kind": kind, "severity": severity})
    _write_lifecycle(conn, objective_id=objective_id, record_id=record_id, event_type=f"{kind}.create", actor_id=actor_id, to_status="open", audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "record_id": record_id, "record_kind": kind, "audit_id": audit_id}


def _validate_refs(conn: sqlite3.Connection, refs: list[dict[str, Any]]) -> None:
    if not refs:
        raise CouncilError("missing_evidence_reference")
    for ref in refs:
        ref_type = ref.get("ref_type")
        ref_id = ref.get("ref_id")
        if not ref_type or not ref_id or ref_type not in REF_TABLES:
            raise CouncilError("invalid_evidence_reference")
        table, column = REF_TABLES[ref_type]
        if table is None:
            if "artifact_uri" not in ref and "content_hash" not in ref:
                raise CouncilError("artifact_reference_missing_locator")
            continue
        if conn.execute(f"SELECT 1 FROM {table} WHERE {column} = ?", (ref_id,)).fetchone() is None:
            raise CouncilError(f"{ref_type}_reference_not_found")


def _parse_refs_json(refs_json: str | None) -> list[dict[str, Any]]:
    refs = _json_loads(refs_json, [])
    if not isinstance(refs, list):
        raise CouncilError("invalid_evidence_reference")
    return refs


def attach_evidence(conn: sqlite3.Connection, *, objective_id: str, title: str, summary: str, refs: list[dict[str, Any]], actor_id: str = COUNCIL_OPERATOR_ACTOR_ID, assignment_id: str | None = None) -> dict[str, Any]:
    ensure_council_runtime(conn)
    _require_objective(conn, objective_id)
    _require_actor(conn, actor_id)
    if assignment_id:
        assignment = _require_assignment(conn, assignment_id)
        if assignment["objective_id"] != objective_id:
            raise CouncilError("assignment_objective_mismatch")
    _validate_refs(conn, refs)
    timestamp = now_utc()
    packet_id = stable_id("evidence_packet", objective_id, title, sha256_text(json_dumps(refs)), timestamp)
    conn.execute(
        """
        INSERT INTO council_evidence_packets(packet_id, objective_id, assignment_id, title, summary, refs_json, created_by_actor_id, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'attached', ?, ?)
        """,
        (packet_id, objective_id, assignment_id, title, summary, json_dumps(refs), actor_id, timestamp, timestamp),
    )
    for ref in refs:
        link_id = stable_id("evidence_ref", packet_id, ref["ref_type"], ref["ref_id"])
        conn.execute(
            """
            INSERT INTO council_evidence_refs(link_id, packet_id, ref_type, ref_id, role, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (link_id, packet_id, ref["ref_type"], ref["ref_id"], ref.get("role", "supporting"), json_dumps({k: v for k, v in ref.items() if k not in {"ref_type", "ref_id", "role"}}), timestamp),
        )
    audit_id = write_audit_event(conn, event_type="council.evidence.attach", target_type="council_evidence_packet", target_id=packet_id, status="ok", actor_id=actor_id, metadata={"objective_id": objective_id, "assignment_id": assignment_id, "ref_count": len(refs)})
    _write_lifecycle(conn, objective_id=objective_id, assignment_id=assignment_id, evidence_packet_id=packet_id, event_type="evidence.attach", actor_id=actor_id, to_status="attached", audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "packet_id": packet_id, "evidence_ref_count": len(refs), "audit_id": audit_id}


def list_evidence(conn: sqlite3.Connection, *, objective_id: str | None = None, assignment_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    clauses: list[str] = []
    params: list[Any] = []
    if objective_id:
        clauses.append("objective_id = ?")
        params.append(objective_id)
    if assignment_id:
        clauses.append("assignment_id = ?")
        params.append(assignment_id)
    sql = "SELECT * FROM council_evidence_packets"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY updated_at DESC, packet_id DESC LIMIT ?"
    params.append(limit)
    packets = []
    for row in conn.execute(sql, params).fetchall():
        item = _row_with_refs(row)
        item["refs"] = [_row_with_metadata(ref) for ref in conn.execute("SELECT * FROM council_evidence_refs WHERE packet_id = ? ORDER BY ref_type, ref_id", (row["packet_id"],)).fetchall()]
        packets.append(item)
    return packets


def record_review(conn: sqlite3.Connection, *, objective_id: str, outcome: str, rationale: str, reviewer_actor_id: str, evidence_packet_id: str | None = None, assignment_id: str | None = None) -> dict[str, Any]:
    ensure_council_runtime(conn)
    if outcome not in REVIEW_OUTCOMES:
        raise CouncilError("invalid_review_outcome")
    _require_objective(conn, objective_id)
    _require_actor(conn, reviewer_actor_id)
    if assignment_id:
        assignment = _require_assignment(conn, assignment_id)
        if assignment["objective_id"] != objective_id:
            raise CouncilError("assignment_objective_mismatch")
    if evidence_packet_id:
        packet = _require_evidence_packet(conn, evidence_packet_id)
        if packet["objective_id"] != objective_id:
            raise CouncilError("evidence_objective_mismatch")
    timestamp = now_utc()
    review_id = stable_id("review", objective_id, reviewer_actor_id, outcome, timestamp)
    conn.execute(
        """
        INSERT INTO council_reviews(review_id, objective_id, assignment_id, evidence_packet_id, reviewer_actor_id, outcome, rationale, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?)
        """,
        (review_id, objective_id, assignment_id, evidence_packet_id, reviewer_actor_id, outcome, rationale, timestamp),
    )
    audit_status = "warning" if outcome in {"revise", "reject", "veto", "blocked", "handoff_required"} else "ok"
    audit_id = write_audit_event(conn, event_type=f"council.review.{outcome}", target_type="council_review", target_id=review_id, status=audit_status, actor_id=reviewer_actor_id, metadata={"objective_id": objective_id, "assignment_id": assignment_id, "evidence_packet_id": evidence_packet_id, "outcome": outcome})
    _write_lifecycle(conn, objective_id=objective_id, assignment_id=assignment_id, evidence_packet_id=evidence_packet_id, review_id=review_id, event_type=f"review.{outcome}", actor_id=reviewer_actor_id, to_status=outcome, reason=rationale, audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "review_id": review_id, "review_outcome": outcome, "audit_id": audit_id}


def list_reviews(conn: sqlite3.Connection, *, objective_id: str | None = None, outcome: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    clauses: list[str] = []
    params: list[Any] = []
    if objective_id:
        clauses.append("objective_id = ?")
        params.append(objective_id)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    sql = "SELECT * FROM council_reviews"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC, review_id DESC LIMIT ?"
    params.append(limit)
    return [_row_with_metadata(row) for row in conn.execute(sql, params).fetchall()]


def create_handoff(conn: sqlite3.Connection, *, objective_id: str, title: str, summary: str, from_actor_id: str, to_actor_id: str | None = None, compat: str | None = None, evidence_packet_ids: list[str] | None = None, status: str = "ready") -> dict[str, Any]:
    ensure_council_runtime(conn)
    if status not in HANDOFF_STATUSES:
        raise CouncilError("invalid_handoff_status")
    _require_objective(conn, objective_id)
    _require_actor(conn, from_actor_id)
    if to_actor_id:
        _require_actor(conn, to_actor_id)
    evidence_packet_ids = evidence_packet_ids or []
    for packet_id in evidence_packet_ids:
        packet = _require_evidence_packet(conn, packet_id)
        if packet["objective_id"] != objective_id:
            raise CouncilError("evidence_objective_mismatch")
    timestamp = now_utc()
    handoff_id = stable_id("handoff", objective_id, title, from_actor_id, timestamp)
    conn.execute(
        """
        INSERT INTO council_handoffs(handoff_id, objective_id, phase, title, summary, status, from_actor_id, to_actor_id, evidence_packet_ids_json, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
        """,
        (handoff_id, objective_id, compat, title, summary, status, from_actor_id, to_actor_id, json_dumps(evidence_packet_ids), timestamp, timestamp),
    )
    audit_id = write_audit_event(conn, event_type="council.handoff.create", target_type="council_handoff", target_id=handoff_id, status="ok", actor_id=from_actor_id, metadata={"objective_id": objective_id, "phase": compat, "handoff_status": status, "evidence_packet_count": len(evidence_packet_ids)})
    _write_lifecycle(conn, objective_id=objective_id, handoff_id=handoff_id, event_type="handoff.create", actor_id=from_actor_id, to_status=status, audit_id=audit_id)
    conn.commit()
    return {"status": "ok", "handoff_id": handoff_id, "handoff_status": status, "audit_id": audit_id}


def list_handoffs(conn: sqlite3.Connection, *, objective_id: str | None = None, compat: str | None = None, status: str | None = None, actor_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    clauses: list[str] = []
    params: list[Any] = []
    if objective_id:
        clauses.append("objective_id = ?")
        params.append(objective_id)
    if compat:
        clauses.append("phase = ?")
        params.append(compat)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if actor_id:
        clauses.append("(from_actor_id = ? OR to_actor_id = ?)")
        params.extend([actor_id, actor_id])
    sql = "SELECT * FROM council_handoffs"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY updated_at DESC, handoff_id DESC LIMIT ?"
    params.append(limit)
    return [_row_with_handoff(row) for row in conn.execute(sql, params).fetchall()]


def show_handoff(conn: sqlite3.Connection, handoff_id: str) -> dict[str, Any]:
    ensure_council_runtime(conn)
    row = conn.execute("SELECT * FROM council_handoffs WHERE handoff_id = ?", (handoff_id,)).fetchone()
    if row is None:
        raise CouncilError("handoff_not_found")
    return {"status": "ok", "handoff": _row_with_handoff(row)}


def search_handoffs(conn: sqlite3.Connection, *, query: str | None = None, project_id: str | None = None, compat: str | None = None, actor_id: str | None = None, status: str | None = None, objective_id: str | None = None, evidence_packet_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    ensure_council_runtime(conn)
    clauses: list[str] = []
    params: list[Any] = []
    joins = "JOIN council_objectives o ON o.objective_id = h.objective_id"
    if query:
        clauses.append("(h.title LIKE ? OR h.summary LIKE ? OR o.title LIKE ? OR o.body LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like, like])
    if project_id:
        clauses.append("o.project_id = ?")
        params.append(project_id)
    if compat:
        clauses.append("h.phase = ?")
        params.append(compat)
    if actor_id:
        clauses.append("(h.from_actor_id = ? OR h.to_actor_id = ?)")
        params.extend([actor_id, actor_id])
    if status:
        clauses.append("h.status = ?")
        params.append(status)
    if objective_id:
        clauses.append("h.objective_id = ?")
        params.append(objective_id)
    rows = conn.execute(f"SELECT h.* FROM council_handoffs h {joins} " + ("WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY h.updated_at DESC, h.handoff_id DESC LIMIT ?", (*params, limit)).fetchall()
    handoffs = [_row_with_handoff(row) for row in rows]
    if evidence_packet_id:
        handoffs = [item for item in handoffs if evidence_packet_id in item.get("evidence_packet_ids", [])]
    return handoffs[:limit]


def lifecycle(conn: sqlite3.Connection, objective_id: str) -> dict[str, Any]:
    ensure_council_runtime(conn)
    objective = _objective_dict(_require_objective(conn, objective_id))
    assignments = list_assignments(conn, objective_id=objective_id, limit=200)
    evidence = list_evidence(conn, objective_id=objective_id, limit=200)
    reviews = list_reviews(conn, objective_id=objective_id, limit=200)
    handoffs = list_handoffs(conn, objective_id=objective_id, limit=200)
    records = [_row_with_metadata(row) for row in conn.execute("SELECT * FROM council_records WHERE objective_id = ? ORDER BY created_at, record_id", (objective_id,)).fetchall()]
    events = [_row_with_metadata(row) for row in conn.execute("SELECT * FROM council_lifecycle_events WHERE objective_id = ? ORDER BY occurred_at, lifecycle_event_id", (objective_id,)).fetchall()]
    audits = [row_to_dict(row) for row in conn.execute("""
        SELECT audit_id, occurred_at, event_type, actor_id, target_type, target_id, status
        FROM audit_events
        WHERE event_type LIKE 'council.%' AND (target_id = ? OR metadata_json LIKE ?)
        ORDER BY occurred_at, audit_id
        """, (objective_id, f"%{objective_id}%")).fetchall()]
    verdicts = [review["outcome"] for review in reviews]
    return {
        "status": "ok",
        "objective": objective,
        "assignments": assignments,
        "records": records,
        "evidence_packets": evidence,
        "reviews": reviews,
        "handoffs": handoffs,
        "lifecycle_events": events,
        "audit_events": audits,
        "blocked_or_stale_visible": objective["status"] == "blocked" or any(a["status"] == "blocked" for a in assignments) or any(r["outcome"] in {"blocked", "veto", "revise", "reject"} for r in reviews),
        "dissent_preserved": any(outcome in {"veto", "revise", "reject", "blocked"} for outcome in verdicts),
        "truth_authority": "evidence_provenance_policy_audit_not_council_verdict",
    }


def _write_lifecycle(
    conn: sqlite3.Connection,
    *,
    objective_id: str,
    event_type: str,
    actor_id: str,
    assignment_id: str | None = None,
    evidence_packet_id: str | None = None,
    review_id: str | None = None,
    handoff_id: str | None = None,
    record_id: str | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    reason: str | None = None,
    audit_id: str | None = None,
) -> str:
    timestamp = now_utc()
    lifecycle_event_id = stable_id("council_lifecycle", objective_id, event_type, actor_id, timestamp, assignment_id or "", evidence_packet_id or "", review_id or "", handoff_id or "", record_id or "")
    conn.execute(
        """
        INSERT INTO council_lifecycle_events(lifecycle_event_id, objective_id, assignment_id, evidence_packet_id, review_id, handoff_id, record_id, event_type, actor_id, from_status, to_status, reason, audit_id, occurred_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (lifecycle_event_id, objective_id, assignment_id, evidence_packet_id, review_id, handoff_id, record_id, event_type, actor_id, from_status, to_status, reason, audit_id, timestamp),
    )
    return lifecycle_event_id


def _objective_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = _row_with_metadata(row)
    item["profile_internal_leakage"] = False
    return item


def _row_with_metadata(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    if "metadata_json" in item:
        item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    return item


def _row_with_refs(row: sqlite3.Row) -> dict[str, Any]:
    item = _row_with_metadata(row)
    if "refs_json" in item:
        item["source_refs"] = _json_loads(item.pop("refs_json"), [])
    return item


def _row_with_handoff(row: sqlite3.Row) -> dict[str, Any]:
    item = _row_with_metadata(row)
    if "evidence_packet_ids_json" in item:
        item["evidence_packet_ids"] = _json_loads(item.pop("evidence_packet_ids_json"), [])
    return item


def refs_from_cli_args(ref_type: str | None, ref_id: str | None, refs_json: str | None = None) -> list[dict[str, Any]]:
    refs = _parse_refs_json(refs_json) if refs_json else []
    if ref_type or ref_id:
        if not ref_type or not ref_id:
            raise CouncilError("invalid_evidence_reference")
        refs.append({"ref_type": ref_type, "ref_id": ref_id, "role": "primary"})
    return refs


def csv_from_cli(value: str | None) -> list[str]:
    return _split_csv(value)
