"""compat 11 actor/profile/session/project scoped visibility runtime.

Scope decisions are local, DB-backed, and leak-safe. Hermes profile bindings are
metadata-only: this module never reads real Hermes markdown and never exposes
profile roots or profile-internal paths.
"""

from __future__ import annotations

import re
import sqlite3
import time
from typing import Any

from .audit import write_audit_event
from .council import DEFAULT_PROJECT_ID, ensure_council_runtime
from .db import json_dumps, now_utc, row_to_dict, stable_id

VISIBILITY_STATES = {"allowed", "denied", "degraded", "unauthorized", "unavailable", "error"}
_DECISION_TO_DB = {
    "allowed": "allow",
    "denied": "deny",
    "degraded": "degrade",
    "unauthorized": "deny",
    "unavailable": "degrade",
    "error": "deny",
}
_AUDIT_STATUS = {
    "allowed": "ok",
    "denied": "denied",
    "degraded": "degraded",
    "unauthorized": "denied",
    "unavailable": "degraded",
    "error": "error",
}
_TARGET_TABLES = {
    "actor": ("actors", "actor_id"),
    "project": ("projects", "project_id"),
    "session": ("sessions", "session_id"),
    "source": ("sources", "source_id"),
    "memory": ("memories", "memory_id"),
    "council": ("council_objectives", "objective_id"),
}
_FORBIDDEN_RE = re.compile(
    r"(/home/[A-Za-z0-9_./-]+|\.hermes/profiles|api[_-]?key\s*=|token\s*=|password\s*=|secret\s*=|sk-[A-Za-z0-9])",
    re.IGNORECASE,
)


class ScopeError(ValueError):
    """Fail-closed compat 11 scope error."""


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str):
        return _FORBIDDEN_RE.sub("[REDACTED]", value)
    return value


def _assert_safe(payload: Any) -> None:
    if _FORBIDDEN_RE.search(str(payload)):
        raise ScopeError("scope_output_leak_detected")


def _actor_exists(conn: sqlite3.Connection, actor_id: str) -> bool:
    return conn.execute("SELECT 1 FROM actors WHERE actor_id=? AND is_active=1", (actor_id,)).fetchone() is not None


def _target_exists(conn: sqlite3.Connection, target_type: str, target_id: str) -> bool:
    table_col = _TARGET_TABLES.get(target_type)
    if not table_col:
        return False
    table, column = table_col
    return conn.execute(f"SELECT 1 FROM {table} WHERE {column}=?", (target_id,)).fetchone() is not None


def ensure_scope_runtime(conn: sqlite3.Connection) -> None:
    """Seed compat 11 metadata-only scope posture without real profile IO."""
    ensure_council_runtime(conn)
    timestamp = now_utc()
    policy_id = "policy_compat11_local_scope_visibility"
    conn.execute(
        """
        INSERT INTO privacy_policies(policy_id, policy_type, name, rule_json, priority, enabled, created_at, updated_at)
        VALUES (?, 'access', 'compat 11 local scoped visibility', ?, 110, 1, ?, ?)
        ON CONFLICT(policy_id) DO UPDATE SET rule_json=excluded.rule_json, updated_at=excluded.updated_at
        """,
        (
            policy_id,
            json_dumps(
                {
                    "phase": "compat11",
                    "states": sorted(VISIBILITY_STATES),
                    "fail_closed": True,
                    "profile_internals_exposed": False,
                    "real_hermes_profile_markdown_read": False,
                    "remote_access": False,
                }
            ),
            timestamp,
            timestamp,
        ),
    )
    # Operator/operator can inspect the canonical Mnemoir project by default. Other
    # actor/profile/session/source grants remain explicit test/runtime rows.
    conn.execute(
        """
        INSERT OR IGNORE INTO access_grants(grant_id, actor_id, scope_type, scope_id, permission, policy_id, created_at)
        VALUES (?, 'actor_operator', 'project', ?, 'read', ?, ?)
        """,
        (stable_id("grant", "actor_operator", "project", DEFAULT_PROJECT_ID, "read"), DEFAULT_PROJECT_ID, policy_id, timestamp),
    )
    conn.commit()


def bind_profile_metadata(
    conn: sqlite3.Connection,
    *,
    profile_id: str,
    actor_id: str,
    display_name: str | None = None,
    health: str = "healthy",
) -> dict[str, Any]:
    """Represent a Hermes profile binding without reading markdown or paths."""
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        decision = _record_visibility_decision(conn, actor_id=actor_id, target_type="profile", target_id="redacted", state="unauthorized", reason="invalid_profile_id", request={"profile_id": "redacted"})
        return decision
    ensure_scope_runtime(conn)
    timestamp = now_utc()
    if not _actor_exists(conn, actor_id):
        conn.execute(
            """
            INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
            VALUES (?, 'agent', ?, ?, NULL, ?, '{}', ?, ?, ?)
            """,
            (
                actor_id,
                display_name or f"Scoped profile actor {profile_id}",
                f"scoped:{profile_id}",
                json_dumps({"profile_binding": "redacted", "profile_id": profile_id}),
                json_dumps({"phase": "compat11", "profile_binding_metadata_only": True, "profile_path_redacted": True}),
                timestamp,
                timestamp,
            ),
        )
    source_id = f"hermes_profile_binding:{profile_id}"
    conn.execute(
        """
        INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind,
                            read_authority, write_authority, authority_level, health, failure_reason,
                            provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, 'hermes_profile_memory', ?, ?, ?, NULL, 'read_only', 'propose_only', 'secondary', ?, NULL, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET display_name=excluded.display_name, profile_id=excluded.profile_id,
          health=excluded.health, provenance_rules_json=excluded.provenance_rules_json,
          privacy_policy_json=excluded.privacy_policy_json, updated_at=excluded.updated_at
        """,
        (
            source_id,
            display_name or f"Hermes profile binding {profile_id}",
            f"hermes-profile://{profile_id}/metadata",
            profile_id,
            health,
            json_dumps({"phase": "compat11", "binding": "metadata_only", "path_policy": "redacted", "markdown_read_performed": False}),
            json_dumps({"profile_internals_exposed": False, "real_markdown_read_allowed": False}),
            timestamp,
            timestamp,
        ),
    )
    grant_id = grant_scope(conn, actor_id=actor_id, scope_type="source", scope_id=source_id, permission="read", commit=False)["grant_id"]
    audit_id = write_audit_event(
        conn,
        event_type="compat11.profile_binding.metadata",
        target_type="source",
        target_id=source_id,
        status="ok" if health == "healthy" else "degraded",
        actor_id=actor_id,
        metadata={"profile_id": profile_id, "grant_id": grant_id, "metadata_only": True, "profile_path_redacted": True, "real_markdown_read": False},
    )
    conn.commit()
    result = {"status": "ok" if health == "healthy" else "degraded", "profile_id": profile_id, "actor_id": actor_id, "source_id": source_id, "grant_id": grant_id, "audit_id": audit_id, "profile_binding_metadata_only": True, "profile_internals_exposed": False, "real_hermes_profile_markdown_read": False}
    result = _clean(result)
    _assert_safe(result)
    return result


def grant_scope(
    conn: sqlite3.Connection,
    *,
    actor_id: str,
    scope_type: str,
    scope_id: str,
    permission: str = "read",
    policy_id: str = "policy_compat11_local_scope_visibility",
    commit: bool = True,
) -> dict[str, Any]:
    ensure_scope_runtime(conn)
    if scope_type not in {"global", "actor", "project", "session", "source", "memory", "council"}:
        raise ScopeError("invalid_scope_type")
    if permission not in {"read", "write", "delete", "admin", "export", "sync", "approve"}:
        raise ScopeError("invalid_permission")
    if not _actor_exists(conn, actor_id):
        raise ScopeError("actor_not_found")
    timestamp = now_utc()
    grant_id = stable_id("grant", actor_id, scope_type, scope_id, permission)
    conn.execute(
        """
        INSERT INTO access_grants(grant_id, actor_id, scope_type, scope_id, permission, policy_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(actor_id, scope_type, scope_id, permission) DO UPDATE SET policy_id=excluded.policy_id
        """,
        (grant_id, actor_id, scope_type, scope_id, permission, policy_id, timestamp),
    )
    audit_id = write_audit_event(conn, event_type="compat11.scope.grant", target_type=scope_type, target_id=scope_id, status="ok", actor_id=actor_id, metadata={"grant_id": grant_id, "permission": permission})
    if commit:
        conn.commit()
    result = {"status": "ok", "grant_id": grant_id, "actor_id": actor_id, "scope_type": scope_type, "scope_id": scope_id, "permission": permission, "audit_id": audit_id}
    result = _clean(result)
    _assert_safe(result)
    return result


def decide_visibility(
    conn: sqlite3.Connection,
    *,
    actor_id: str | None,
    target_type: str,
    target_id: str | None,
    permission: str = "read",
) -> dict[str, Any]:
    """Return a DB-backed explicit visibility decision for actor/profile/session/project scope."""
    ensure_scope_runtime(conn)
    request = {"actor_id": actor_id, "target_type": target_type, "target_id": target_id, "permission": permission}
    if not actor_id or not target_id or not target_type:
        return _record_visibility_decision(conn, actor_id=actor_id, target_type=target_type or "missing", target_id=target_id, state="error", reason="missing_visibility_input", request=request)
    if target_type not in _TARGET_TABLES:
        return _record_visibility_decision(conn, actor_id=actor_id, target_type=target_type, target_id=target_id, state="unauthorized", reason="unclassified_visibility_target_denied", request=request)
    if not _actor_exists(conn, actor_id):
        return _record_visibility_decision(conn, actor_id=None, target_type=target_type, target_id=target_id, state="unauthorized", reason="requesting_actor_not_found", request=request)
    if not _target_exists(conn, target_type, target_id):
        return _record_visibility_decision(conn, actor_id=actor_id, target_type=target_type, target_id=target_id, state="unavailable", reason="target_unavailable", request=request)

    status = "allowed"
    reason = "explicit_scope_grant"
    if target_type == "source":
        source = conn.execute("SELECT health, read_authority FROM sources WHERE source_id=?", (target_id,)).fetchone()
        if source["read_authority"] == "none":
            status, reason = "denied", "source_read_authority_none"
        elif source["health"] in {"unauthorized", "disabled"}:
            status, reason = "unauthorized", f"source_{source['health']}"
        elif source["health"] in {"unavailable", "unknown"}:
            status, reason = "unavailable", f"source_{source['health']}"
        elif source["health"] == "degraded":
            status, reason = "degraded", "source_degraded_with_explicit_grant"
    if status == "allowed" or status == "degraded":
        if not _has_grant(conn, actor_id=actor_id, target_type=target_type, target_id=target_id, permission=permission):
            if target_type == "actor" and actor_id == target_id and permission == "read":
                reason = "actor_self_visibility"
            else:
                status, reason = "denied", "missing_explicit_scope_grant"
    return _record_visibility_decision(conn, actor_id=actor_id, target_type=target_type, target_id=target_id, state=status, reason=reason, request=request)


def _has_grant(conn: sqlite3.Connection, *, actor_id: str, target_type: str, target_id: str, permission: str) -> bool:
    scope_type = "council" if target_type == "council" else target_type
    rows = conn.execute(
        """
        SELECT 1 FROM access_grants
        WHERE actor_id=? AND permission=? AND expires_at IS NULL AND (
          (scope_type=? AND scope_id=?) OR (scope_type='global' AND scope_id='*')
        )
        LIMIT 1
        """,
        (actor_id, permission, scope_type, target_id),
    ).fetchone()
    return rows is not None


def _record_visibility_decision(
    conn: sqlite3.Connection,
    *,
    actor_id: str | None,
    target_type: str,
    target_id: str | None,
    state: str,
    reason: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    timestamp = now_utc()
    state = state if state in VISIBILITY_STATES else "error"
    action = "compat11_visibility_read"
    decision_id = stable_id("visibility", actor_id or "none", target_type, target_id or "none", state, reason, timestamp)
    result_json = {
        "phase": "compat11",
        "visibility_state": state,
        "reason": reason,
        "profile_internals_exposed": False,
        "real_hermes_profile_markdown_read": False,
        "remote_access_used": False,
    }
    conn.execute(
        """
        INSERT INTO policy_decisions(decision_id, actor_id, action, target_type, target_id, decision, reason, request_json, result_json, decided_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (decision_id, actor_id, action, target_type, target_id, _DECISION_TO_DB[state], reason, json_dumps(_clean(request)), json_dumps(result_json), timestamp),
    )
    audit_id = write_audit_event(
        conn,
        event_type="compat11.scope.visibility_decision",
        target_type=target_type,
        target_id=target_id,
        status=_AUDIT_STATUS[state],
        actor_id=actor_id,
        metadata={"policy_decision_id": decision_id, "visibility_state": state, "reason": reason, "permission": request.get("permission"), "profile_internals_exposed": False, "real_markdown_read": False},
    )
    conn.commit()
    result = {"status": state, "visibility_state": state, "actor_id": actor_id, "target_type": target_type, "target_id": target_id, "permission": request.get("permission", "read"), "decision_id": decision_id, "audit_id": audit_id, "reason": reason, "profile_internals_exposed": False, "real_hermes_profile_markdown_read": False}
    result = _clean(result)
    _assert_safe(result)
    return result


def authorized_sources_for_profile(
    conn: sqlite3.Connection,
    *,
    profile_id: str,
    actor_id: str | None = None,
    session_id: str | None = None,
    project_id: str | None = None,
    source_families: tuple[str, ...] = ("hermes_markdown_overflow", "hermes_profile_memory", "session_search", "obsidian_wiki"),
) -> dict[str, Any]:
    """Return leak-safe source authorization for profile-scoped recall.

    This is a read-filtering decision surface only. It never reads Hermes markdown,
    never falls back to public/repo sources, and never mutates provider config.
    """
    ensure_scope_runtime(conn)
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        raise ScopeError("invalid_profile_id")
    if actor_id is None:
        row = conn.execute("SELECT actor_id FROM actors WHERE profile_name=? AND is_active=1 ORDER BY actor_id LIMIT 1", (profile_id,)).fetchone()
        actor_id = row["actor_id"] if row else stable_id("actor", "hermes_profile", profile_id)

    allowed_families = tuple(source_families)
    family_placeholders = ",".join("?" for _ in allowed_families)
    candidates: dict[str, dict[str, Any]] = {}

    def add_candidate(row: sqlite3.Row, reason: str) -> None:
        item = row_to_dict(row)
        item["authorization_reason"] = reason
        candidates[item["source_id"]] = item

    for row in conn.execute(
        f"""
        SELECT source_id, source_type, profile_id, overflow_kind, read_authority, health, failure_reason
        FROM sources
        WHERE profile_id=? AND source_type IN ({family_placeholders})
        ORDER BY source_id
        """,
        (profile_id, *allowed_families),
    ).fetchall():
        add_candidate(row, "profile_owned_source")

    for row in conn.execute(
        f"""
        SELECT s.source_id, s.source_type, s.profile_id, s.overflow_kind, s.read_authority, s.health, s.failure_reason
        FROM access_grants g JOIN sources s ON s.source_id = g.scope_id
        WHERE g.actor_id=? AND g.scope_type='source' AND g.permission='read' AND g.expires_at IS NULL
          AND s.source_type IN ({family_placeholders})
        ORDER BY s.source_id
        """,
        (actor_id, *allowed_families),
    ).fetchall():
        add_candidate(row, "explicit_source_grant")

    if session_id:
        for row in conn.execute(
            f"""
            SELECT s.source_id, s.source_type, s.profile_id, s.overflow_kind, s.read_authority, s.health, s.failure_reason
            FROM access_grants g
            JOIN sessions se ON se.session_id = g.scope_id
            JOIN sources s ON s.source_id = se.source_id
            WHERE g.actor_id=? AND g.scope_type='session' AND g.scope_id=? AND g.permission='read' AND g.expires_at IS NULL
              AND s.source_type IN ({family_placeholders})
            ORDER BY s.source_id
            """,
            (actor_id, session_id, *allowed_families),
        ).fetchall():
            add_candidate(row, "explicit_session_grant")

    if project_id:
        for row in conn.execute(
            f"""
            SELECT DISTINCT s.source_id, s.source_type, s.profile_id, s.overflow_kind, s.read_authority, s.health, s.failure_reason
            FROM access_grants g
            JOIN sessions se ON se.project_id = g.scope_id
            JOIN sources s ON s.source_id = se.source_id
            WHERE g.actor_id=? AND g.scope_type='project' AND g.scope_id=? AND g.permission='read' AND g.expires_at IS NULL
              AND s.source_type IN ({family_placeholders})
            ORDER BY s.source_id
            """,
            (actor_id, project_id, *allowed_families),
        ).fetchall():
            add_candidate(row, "explicit_project_grant")

    healthy: list[str] = []
    degraded: list[dict[str, Any]] = []
    denied: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    timestamp = now_utc()
    for source_id, item in sorted(candidates.items()):
        if item["read_authority"] == "none":
            state, reason = "denied", "source_read_authority_none"
            denied.append({"source_id": source_id, "reason": reason})
        elif item["health"] == "healthy":
            state, reason = "allowed", item["authorization_reason"]
            healthy.append(source_id)
        else:
            state = "unavailable" if item["health"] in {"unavailable", "unknown"} else ("unauthorized" if item["health"] in {"unauthorized", "disabled"} else "degraded")
            reason = item.get("failure_reason") or f"source_{item['health']}"
            degraded.append({"source_id": source_id, "health": item["health"], "failure_reason": reason})
        decision_id = stable_id("profile_recall_source", actor_id, profile_id, source_id, state, timestamp, len(decisions), time.perf_counter_ns())
        conn.execute(
            """
            INSERT INTO policy_decisions(decision_id, actor_id, action, target_type, target_id, decision, reason, request_json, result_json, decided_at)
            VALUES (?, ?, 'compat15_g03_profile_recall_source_filter', 'source', ?, ?, ?, ?, ?, ?)
            """,
            (decision_id, actor_id, source_id, _DECISION_TO_DB.get(state, "deny"), reason, json_dumps(_clean({"profile_id": profile_id, "source_families": list(allowed_families)})), json_dumps({"visibility_state": state, "reason": reason, "profile_path_redacted": True, "real_hermes_profile_markdown_read": False, "silent_fallback_allowed": False}), timestamp),
        )
        audit_id = write_audit_event(conn, event_type="compat15.g03.profile_recall_source_filter", target_type="source", target_id=source_id, status=_AUDIT_STATUS.get(state, "error"), actor_id=actor_id, metadata={"policy_decision_id": decision_id, "profile_id": profile_id, "source_family": item["source_type"], "decision": state, "reason": reason, "leak_safe": True})
        decisions.append({"source_id": source_id, "decision": state, "reason": reason, "decision_id": decision_id, "audit_id": audit_id, "source_family": item["source_type"]})

    status = "ok" if healthy and not degraded and not denied else ("degraded" if healthy or degraded else "unavailable")
    coverage = {"searched_source_ids": healthy, "missing_or_degraded_sources": degraded, "denied_sources": denied, "coverage_status": "degraded" if degraded or denied else ("ok" if healthy else "unavailable")}
    result = {"status": status, "profile_id": profile_id, "actor_id": actor_id, "authorized_source_ids": healthy, "source_coverage": coverage, "source_filter_applied": True, "fallback_sources_allowed": False, "source_families_allowed": list(allowed_families), "decisions": decisions, "profile_paths_redacted": True, "real_hermes_profile_markdown_read": False, "hermes_provider_config_mutated": False}
    result = _clean(result)
    _assert_safe(result)
    conn.commit()
    return result


def scope_status(conn: sqlite3.Connection, *, limit: int = 50) -> dict[str, Any]:
    ensure_scope_runtime(conn)
    grants = [row_to_dict(row) for row in conn.execute(
        """
        SELECT grant_id, actor_id, scope_type, scope_id, permission, policy_id, created_at
        FROM access_grants
        ORDER BY created_at DESC, grant_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()]
    decisions = [row_to_dict(row) for row in conn.execute(
        """
        SELECT decision_id, actor_id, action, target_type, target_id, decision, reason, decided_at
        FROM policy_decisions
        WHERE action='compat11_visibility_read'
        ORDER BY decided_at DESC, decision_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()]
    profiles = [row_to_dict(row) for row in conn.execute(
        """
        SELECT source_id, source_type, external_ref, profile_id, read_authority, write_authority, authority_level, health, failure_reason
        FROM sources
        WHERE source_type IN ('hermes_profile_memory','hermes_markdown_overflow')
        ORDER BY source_id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()]
    result = {
        "status": "ok",
        "schema": "compat11_scope_view_v1",
        "visibility_states": sorted(VISIBILITY_STATES),
        "grant_count": len(grants),
        "decision_count": len(decisions),
        "profile_binding_count": len(profiles),
        "access_grants": grants,
        "visibility_decisions": decisions,
        "profile_bindings": profiles,
        "profile_binding_metadata_only": True,
        "profile_internals_exposed": False,
        "real_hermes_profile_markdown_read": False,
        "leak_safe": True,
    }
    result = _clean(result)
    _assert_safe(result)
    return result
