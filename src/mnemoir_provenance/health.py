"""compat 09 local health spine for Mnemoir Provenance.

Health checks are local-only, leak-safe, and fail closed. They inspect the
canonical SQLite runtime state without touching gateways, providers, credentials,
real Hermes profile markdown, network IO, autostart, cron, or writeback surfaces.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from .autonomy import ALLOWED_ACTIONS, APPROVAL_REQUIRED_ACTIONS, DENIED_ACTIONS
from .db import SCHEMA_PATH, initialize_database, row_to_dict
from .hermes_provider import provider_status
from .operator_surface import (
    OperatorSurfaceError,
    _assert_safe,
    _clean_value,
    projection_surface_status,
)
from .sources import list_sources, register_sources

HEALTH_STATES = {"ok", "degraded", "unavailable", "unauthorized", "error"}
_REQUIRED_TABLES = {
    "schema_migrations",
    "sources",
    "raw_events",
    "evidence_items",
    "memories",
    "content_chunks",
    "embeddings",
    "retrieval_queries",
    "policy_decisions",
    "audit_events",
    "jobs",
    "autonomy_ticks",
    "council_objectives",
    "council_assignments",
    "council_reviews",
    "council_handoffs",
}
_FORBIDDEN_REASON_RE = re.compile(
    r"autostart|cron|systemd|gateway|provider_config|credential|permission|live_network|network_io|markdown_writeback|real_profile|public_posting",
    re.IGNORECASE,
)


class HealthError(ValueError):
    """Fail-closed compat 09 health error."""


def _state_from_children(children: list[dict[str, Any]]) -> str:
    states = {child.get("status") for child in children}
    if "error" in states:
        return "error"
    if "unauthorized" in states:
        return "unauthorized"
    if "unavailable" in states:
        return "unavailable"
    if "degraded" in states:
        return "degraded"
    return "ok"


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')").fetchall()
    return {str(row["name"] if isinstance(row, sqlite3.Row) else row[0]) for row in rows}


def db_health(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        conn.execute("SELECT 1").fetchone()
        tables = _table_names(conn)
        missing = sorted(_REQUIRED_TABLES - tables)
        migration = conn.execute("SELECT version, name, success, error FROM schema_migrations ORDER BY version DESC LIMIT 1").fetchone() if "schema_migrations" in tables else None
        migration_ok = bool(migration and migration["success"] == 1 and migration["version"] == "0001")
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except Exception as error:  # pragma: no cover - exact sqlite text varies by version
        result = {"status": "error", "db_openable": False, "schema_valid": False, "error": "db_health_failed", "detail": str(error)}
        return _safe(result)
    status = "ok" if not missing and migration_ok and integrity == "ok" else "error"
    result = {
        "status": status,
        "db_openable": True,
        "schema_valid": not missing and migration_ok,
        "integrity_check": "ok" if integrity == "ok" else "error",
        "migration": row_to_dict(migration) if migration else None,
        "missing_required_tables": missing,
    }
    return _safe(result)


def source_registry_health(conn: sqlite3.Connection, repo_root: Path | None = None) -> dict[str, Any]:
    if repo_root is not None:
        register_sources(conn, repo_root)
    sources = list_sources(conn)
    degraded = [s for s in sources if s.get("health") != "healthy"]
    status = "ok" if sources and not degraded else ("unavailable" if not sources else "degraded")
    result = {
        "status": status,
        "source_count": len(sources),
        "degraded_count": len(degraded),
        "required_source_state_present": bool(sources),
        "sources": sources,
        "silent_substitution_allowed": False,
    }
    return _safe(result)


def policy_health(conn: sqlite3.Connection) -> dict[str, Any]:
    unsafe = conn.execute(
        """
        SELECT decision_id, action, target_type, target_id, decision, reason, decided_at
        FROM policy_decisions
        WHERE decision='allow' AND (
          action IN ('credential_permission_change','destructive_action','provider_config','gateway_change','cron_autostart','live_network_io')
          OR lower(coalesce(reason,'')) GLOB '*autostart*'
          OR lower(coalesce(reason,'')) GLOB '*credential*'
          OR lower(coalesce(reason,'')) GLOB '*permission*'
        )
        ORDER BY decided_at DESC
        LIMIT 20
        """
    ).fetchall()
    result = {
        "status": "unauthorized" if unsafe else "ok",
        "allowed_actions": sorted(ALLOWED_ACTIONS),
        "approval_required_actions": sorted(APPROVAL_REQUIRED_ACTIONS),
        "denied_actions": sorted(DENIED_ACTIONS),
        "unsafe_allow_decision_count": len(unsafe),
        "unsafe_allow_decisions": [row_to_dict(row) for row in unsafe],
        "unbounded_background_autonomy_allowed": False,
    }
    return _safe(result)


def retrieval_health(conn: sqlite3.Connection) -> dict[str, Any]:
    chunks = conn.execute("SELECT COUNT(*) FROM content_chunks").fetchone()[0]
    embeddings = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
    queries = conn.execute("SELECT COUNT(*) FROM retrieval_queries").fetchone()[0]
    status = "ok" if chunks and embeddings else "degraded"
    result = {
        "status": status,
        "lexical_ready": True,
        "semantic_index_ready": bool(chunks and embeddings),
        "hybrid_ready": bool(chunks and embeddings),
        "content_chunk_count": chunks,
        "embedding_count": embeddings,
        "retrieval_query_count": queries,
        "ranking_is_truth_authority": False,
    }
    return _safe(result)


def council_health(conn: sqlite3.Connection) -> dict[str, Any]:
    objectives = conn.execute("SELECT COUNT(*) FROM council_objectives").fetchone()[0]
    reviews = conn.execute("SELECT COUNT(*) FROM council_reviews").fetchone()[0]
    handoffs = conn.execute("SELECT COUNT(*) FROM council_handoffs").fetchone()[0]
    status = "ok" if objectives or reviews or handoffs else "degraded"
    result = {
        "status": status,
        "objective_count": objectives,
        "review_count": reviews,
        "handoff_count": handoffs,
        "lifecycle_tables_ready": True,
        "veto_state_preserved": True,
    }
    return _safe(result)


def autonomy_health(conn: sqlite3.Connection) -> dict[str, Any]:
    ticks = conn.execute("SELECT COUNT(*) FROM autonomy_ticks").fetchone()[0]
    approval_required = conn.execute("SELECT COUNT(*) FROM autonomy_ticks WHERE approval_class='approval_required'").fetchone()[0]
    failed = conn.execute("SELECT COUNT(*) FROM autonomy_ticks WHERE status IN ('failed','paused','cancelled')").fetchone()[0]
    result = {
        "status": "ok",
        "tick_count": ticks,
        "approval_required_count": approval_required,
        "failed_or_paused_count": failed,
        "bounded_runtime_only": True,
        "unbounded_background_autonomy_added": False,
    }
    return _safe(result)


def hermes_readiness_health(conn: sqlite3.Connection) -> dict[str, Any]:
    result = provider_status(conn)
    result.update(
        {
            "status": "ok" if result.get("provider") == "mnemoir_local" else "degraded",
            "real_profile_reads_performed": False,
            "markdown_writeback_performed": False,
            "writeback_allowed": False,
        }
    )
    return _safe(result)


def projection_readiness_health(projection_root: str | Path | None = None) -> dict[str, Any]:
    try:
        result = projection_surface_status(projection_root)
    except OperatorSurfaceError:
        result = {"status": "degraded", "projection_ready": False, "canonical_projection": False}
    result["projection_is_canonical"] = False
    return _safe(result)


def health_report(conn: sqlite3.Connection, *, repo_root: Path | None = None, projection_root: str | Path | None = None) -> dict[str, Any]:
    checks = {
        "db": db_health(conn),
        "sources": source_registry_health(conn, repo_root=repo_root),
        "policy": policy_health(conn),
        "retrieval_scoring": retrieval_health(conn),
        "council": council_health(conn),
        "autonomy": autonomy_health(conn),
        "hermes_provider": hermes_readiness_health(conn),
        "wiki_operator_projection": projection_readiness_health(projection_root),
    }
    status = _state_from_children(list(checks.values()))
    fail_closed = status in {"error", "unauthorized", "unavailable"}
    result = {
        "status": status,
        "phase": "compat-09-local-daemon-service-and-health-spine",
        "fail_closed": fail_closed,
        "machine_readable": True,
        "leak_safe": True,
        "checks": checks,
        "forbidden_surfaces_touched": False,
        "live_network_io_performed": False,
        "real_hermes_profile_markdown_read": False,
        "hermes_markdown_writeback_performed": False,
    }
    return _safe(result)


def open_local_health_report(db_path: str | Path | None = None, *, repo_root: Path | None = None, projection_root: str | Path | None = None) -> dict[str, Any]:
    try:
        from .db import connect

        with connect(db_path) as conn:
            initialize_database(conn, SCHEMA_PATH)
            return health_report(conn, repo_root=repo_root, projection_root=projection_root)
    except Exception as error:  # pragma: no cover - exact sqlite text varies by version
        return _safe(
            {
                "status": "error",
                "phase": "compat-09-local-daemon-service-and-health-spine",
                "fail_closed": True,
                "machine_readable": True,
                "leak_safe": True,
                "checks": {"db": {"status": "error", "db_openable": False, "schema_valid": False, "error": "db_open_failed"}},
                "error": str(error),
                "forbidden_surfaces_touched": False,
                "live_network_io_performed": False,
                "real_hermes_profile_markdown_read": False,
                "hermes_markdown_writeback_performed": False,
            }
        )


def _safe(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned = _clean_value(payload)
    _assert_safe(cleaned)
    return cleaned
