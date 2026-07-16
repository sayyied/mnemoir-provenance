"""Local operator aggregation surface for Mnemoir Provenance compat 08."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from .curation import list_proposals
from .hermes_provider import provider_status
from .recall import recall
from .scope import scope_status
from .sources import list_sources
from .wiki_projection import projection_status

_FORBIDDEN_RE = re.compile(r"(/home/[A-Za-z0-9_./-]+|api[_-]?key\s*=|token\s*=|password\s*=|secret\s*=|sk-[A-Za-z0-9]|\.hermes/profiles)", re.IGNORECASE)


class OperatorSurfaceError(ValueError):
    """Fail-closed operator surface error."""


def _clean_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _clean_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_value(v) for v in value]
    if isinstance(value, str):
        return _FORBIDDEN_RE.sub("[REDACTED]", value)
    return value


def _assert_safe(payload: Any) -> None:
    text = str(payload)
    if _FORBIDDEN_RE.search(text):
        raise OperatorSurfaceError("operator_output_leak_detected")


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def source_health(conn: sqlite3.Connection) -> dict[str, Any]:
    sources = list_sources(conn)
    degraded = [s for s in sources if s.get("health") != "healthy"]
    result = {
        "status": "degraded" if degraded else "ok",
        "source_count": len(sources),
        "degraded_count": len(degraded),
        "sources": sources,
        "silent_substitution_allowed": False,
    }
    result = _clean_value(result)
    _assert_safe(result)
    return result


def recall_status(conn: sqlite3.Connection, query: str, *, limit: int = 5) -> dict[str, Any]:
    result = recall(conn, query, limit=limit)
    output = {"status": result["status"], "recall": result, "backed_by_backend_records": True}
    output = _clean_value(output)
    _assert_safe(output)
    return output


def proposals_status(conn: sqlite3.Connection, *, limit: int = 20) -> dict[str, Any]:
    proposals = list_proposals(conn, limit=limit)
    approval_needed = [p for p in proposals if p.get("status") in {"proposed", "edited", "approved"}]
    result = {"status": "ok", "proposal_count": len(proposals), "approval_needed_count": len(approval_needed), "proposals": proposals}
    result = _clean_value(result)
    _assert_safe(result)
    return result


def council_status(conn: sqlite3.Connection, *, limit: int = 50) -> dict[str, Any]:
    queues = {
        "objectives": _rows(conn, "SELECT objective_id, title, status, owner_actor_id, updated_at FROM council_objectives ORDER BY updated_at DESC LIMIT ?", (limit,)),
        "assignments": _rows(conn, "SELECT assignment_id, objective_id, title, status, assigned_actor_id, updated_at FROM council_assignments ORDER BY updated_at DESC LIMIT ?", (limit,)),
        "records": _rows(conn, "SELECT record_id, objective_id, kind, title, status, severity, updated_at FROM council_records ORDER BY updated_at DESC LIMIT ?", (limit,)),
        "reviews": _rows(conn, "SELECT review_id, objective_id, assignment_id, evidence_packet_id, reviewer_actor_id, outcome, created_at FROM council_reviews ORDER BY created_at DESC LIMIT ?", (limit,)),
        "handoffs": _rows(conn, "SELECT handoff_id, objective_id, phase, title, status, from_actor_id, to_actor_id, updated_at FROM council_handoffs ORDER BY updated_at DESC LIMIT ?", (limit,)),
    }
    open_items = [item for group in ["objectives", "assignments", "records", "handoffs"] for item in queues[group] if item.get("status") in {"open", "blocked", "ready", "review", "in_progress"}]
    result = {"status": "ok", "queues": queues, "open_or_blocked_count": len(open_items), "truth_authority": "evidence_provenance_policy_audit_not_council_verdict"}
    result = _clean_value(result)
    _assert_safe(result)
    return result


def autonomy_status(conn: sqlite3.Connection, *, limit: int = 50) -> dict[str, Any]:
    ticks = _rows(
        conn,
        """
        SELECT tick_id, job_id, objective, trigger_type, actor_id, status, approval_class,
               receipt_audit_id, created_at, finished_at
        FROM autonomy_ticks
        ORDER BY created_at DESC, tick_id DESC
        LIMIT ?
        """,
        (limit,),
    )
    failures = [t for t in ticks if t.get("status") in {"failed", "cancelled", "paused"}]
    approvals = [t for t in ticks if t.get("approval_class") == "approval_required"]
    receipts = [t for t in ticks if t.get("receipt_audit_id")]
    result = {"status": "ok", "tick_count": len(ticks), "failure_count": len(failures), "approval_needed_count": len(approvals), "receipt_count": len(receipts), "ticks": ticks}
    result = _clean_value(result)
    _assert_safe(result)
    return result


def approval_needed(conn: sqlite3.Connection, *, limit: int = 50) -> dict[str, Any]:
    proposal_items = [
        {"kind": "memory_proposal", "id": p["proposal_id"], "status": p["status"], "title": p.get("title")}
        for p in list_proposals(conn, limit=limit)
        if p.get("status") in {"proposed", "edited", "approved"}
    ]
    tick_items = [
        {"kind": "autonomy_tick", "id": row["tick_id"], "status": row["status"], "approval_class": row["approval_class"]}
        for row in _rows(conn, "SELECT tick_id, status, approval_class FROM autonomy_ticks WHERE approval_class='approval_required' OR status IN ('failed','paused') ORDER BY created_at DESC LIMIT ?", (limit,))
    ]
    review_items = [
        {"kind": "council_review", "id": row["review_id"], "status": row["outcome"], "objective_id": row["objective_id"]}
        for row in _rows(conn, "SELECT review_id, objective_id, outcome FROM council_reviews WHERE outcome IN ('revise','veto','blocked','handoff_required') ORDER BY created_at DESC LIMIT ?", (limit,))
    ]
    result = {"status": "ok", "approval_needed_count": len(proposal_items) + len(tick_items) + len(review_items), "items": proposal_items + tick_items + review_items}
    result = _clean_value(result)
    _assert_safe(result)
    return result


def hermes_status(conn: sqlite3.Connection) -> dict[str, Any]:
    result = provider_status(conn)
    result["real_profile_reads_performed"] = False
    result["markdown_writeback_performed"] = False
    result["writeback_allowed"] = False
    result = _clean_value(result)
    _assert_safe(result)
    return result


def projection_surface_status(output_root: str | Path | None = None) -> dict[str, Any]:
    result = projection_status(output_root)
    result = _clean_value(result)
    _assert_safe(result)
    return result


def operator_overview(conn: sqlite3.Connection, *, query: str = "Council memory", projection_root: str | Path | None = None, limit: int = 5) -> dict[str, Any]:
    result = {
        "status": "ok",
        "source_health": source_health(conn),
        "recall": recall_status(conn, query, limit=limit),
        "proposals": proposals_status(conn, limit=limit),
        "council": council_status(conn, limit=limit),
        "autonomy": autonomy_status(conn, limit=limit),
        "hermes": hermes_status(conn),
        "projection": projection_surface_status(projection_root),
        "approval_needed": approval_needed(conn, limit=limit),
        "scope": scope_status(conn, limit=limit),
        "mock_dashboard_state_used": False,
    }
    result = _clean_value(result)
    _assert_safe(result)
    return result
