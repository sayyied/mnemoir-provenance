"""Thin same-process adapter for the local Mnemoir operator UI.

The adapter owns no state. Every read and mutation is performed against the
canonical SQLite database through existing domain functions, then passed through
the established leak-safe operator sanitizer.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Callable

from .autonomy import AutonomyError, kill_tick, pause_tick, receipt, resume_tick, run_tick
from .benchmark import benchmark_status
from .council import CouncilError, lifecycle, list_evidence
from .curation import (
    CurationError,
    create_proposal,
    inspect_proposal,
    list_proposals,
    read_memory,
    review_proposal,
    rollback_memory,
    tombstone_memory,
    write_memory,
)
from .db import connect, initialize_database, row_to_dict
from .operator_api import operator_api_view
from .operator_surface import _assert_safe, _clean_value
from .service import ServiceError, service_restart, service_start, service_status, service_stop


class LocalUIError(ValueError):
    """Leak-safe UI adapter error carrying a stable public code."""

    def __init__(self, code: str, *, status: int = 400, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.detail = detail


# Stable compatibility name used by the HTTP bridge.
LocalUIAdapterError = LocalUIError


_SEVERITY = {"error": 6, "unauthorized": 5, "unavailable": 4, "degraded": 3, "blocked": 3, "attention": 2, "ok": 1, "healthy": 1, "empty": 0}
_ADVERSE_REVIEW = {"revise", "reject", "veto", "blocked", "handoff_required"}
_ATTENTION_TICKS = {"failed", "paused", "cancelled", "blocked"}


def _semantic_status(value: Any) -> str:
    status = str(value or "unavailable").lower()
    if status in {"unknown", "uninitialized", "missing", "not_configured"}:
        return "unavailable"
    if status in {"stopped", "paused", "approval_required", "pending"}:
        return "attention"
    return status


def _safe(payload: Any) -> Any:
    cleaned = _clean_value(payload)
    _assert_safe(cleaned)
    return cleaned


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def _status_error(error: Exception) -> LocalUIError:
    code = str(error) or "operation_failed"
    if code in {"proposal_not_found", "memory_not_found", "memory_version_not_found", "tick_not_found", "objective_not_found"}:
        return LocalUIError(code, status=404)
    if code in {"proposal_not_approved", "illegal_transition", "proposal_already_written", "proposal_already_rejected", "memory_already_tombstoned"}:
        return LocalUIError(code, status=409)
    if "unauthorized" in code or "denied" in code:
        return LocalUIError(code, status=403)
    return LocalUIError(code, status=400)


class LocalUIAdapter:
    """Canonical DB-backed read/action boundary used by the loopback server."""

    def __init__(self, db_path: str | Path | None = None, *, projection_root: str | Path | None = None, repo_root: str | Path | None = None):
        self.db_path = db_path
        self.projection_root = str(projection_root) if projection_root else None
        self.repo_root = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parents[2]

    def _open(self) -> sqlite3.Connection:
        conn = connect(self.db_path)
        initialize_database(conn)
        return conn

    def read(self, view: str, *, query: str = "Council memory", record_id: str | None = None, limit: int = 50) -> dict[str, Any]:
        if limit < 1 or limit > 200:
            raise LocalUIError("invalid_limit")
        try:
            with self._open() as conn:
                if view == "home":
                    payload = self._home(conn, query=query, limit=limit)
                elif view == "recall":
                    if not query.strip():
                        raise LocalUIError("query_required")
                    payload = operator_api_view(conn, "recall", query=query.strip()[:500], limit=min(limit, 20))
                    self._enrich_recall(conn, payload)
                elif view == "memory":
                    payload = self._memory(conn, record_id=record_id, limit=limit)
                elif view == "council":
                    payload = self._council(conn, record_id=record_id, limit=limit)
                elif view == "autonomy":
                    payload = self._autonomy(conn, record_id=record_id, limit=limit)
                elif view == "system":
                    payload = self._system(conn, limit=limit)
                else:
                    raise LocalUIError("unknown_view", status=404)
        except LocalUIError:
            raise
        except (CurationError, CouncilError, AutonomyError, ServiceError) as error:
            raise _status_error(error) from error
        except sqlite3.Error as error:
            raise LocalUIError("database_operation_failed", status=503) from error
        return _safe(payload)

    def view(self, destination: str, *, query: str = "Council memory", limit: int = 50) -> dict[str, Any]:
        """Return the stable browser envelope for one reachable destination."""
        if destination == "council":
            data = {"council": self.read("council", limit=limit), "autonomy": self.read("autonomy", limit=limit)}
            return _safe({"status": "ok", "view": destination, "data": data})
        data = self.read(destination, query=query, limit=limit)
        if destination == "recall" and isinstance(data, dict) and "data" in data:
            return data
        return _safe({"status": "ok", "view": destination, "data": data})

    def detail(self, kind: str, record_id: str) -> dict[str, Any]:
        """Load canonical detail for a UI drill-down; no summary-store exists."""
        if not record_id or len(record_id) > 300:
            raise LocalUIError("invalid_record_id")
        if kind == "proposal":
            data = self.read("memory", record_id=record_id)
            data = data.get("proposal", data)
        elif kind == "memory":
            loaded = self.read("memory", record_id=record_id)
            data = loaded.get("memory_record", loaded)
        elif kind == "objective":
            loaded = self.read("council", record_id=record_id)
            data = loaded.get("lifecycle", loaded)
        elif kind == "tick":
            data = self.read("autonomy", record_id=record_id)
        else:
            raise LocalUIError("unknown_detail_kind", status=404)
        return _safe({"status": "ok", "kind": kind, "record_id": record_id, "data": data})

    def mutate(self, action: str, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise LocalUIError("invalid_json_body")
        try:
            with self._open() as conn:
                handlers: dict[str, Callable[[sqlite3.Connection, dict[str, Any]], dict[str, Any]]] = {
                    "proposal.create": self._proposal_create,
                    "proposal.edit": lambda c, d: self._proposal_review(c, d, "edit"),
                    "proposal.approve": lambda c, d: self._proposal_review(c, d, "approve"),
                    "proposal.reject": lambda c, d: self._proposal_review(c, d, "reject"),
                    "memory.write": self._memory_write,
                    "memory.tombstone": self._memory_tombstone,
                    "memory.rollback": self._memory_rollback,
                    "autonomy.run": self._autonomy_run,
                    "autonomy.pause": lambda c, d: self._autonomy_control(c, d, "pause"),
                    "autonomy.resume": lambda c, d: self._autonomy_control(c, d, "resume"),
                    "autonomy.kill": lambda c, d: self._autonomy_control(c, d, "kill"),
                    "service.start": lambda c, d: service_start(c, repo_root=self.repo_root, projection_root=self.projection_root),
                    "service.stop": lambda c, d: service_stop(c, reason=self._text(d, "reason", default="operator_ui_stop"), repo_root=self.repo_root, projection_root=self.projection_root),
                    "service.restart": lambda c, d: service_restart(c, reason=self._text(d, "reason", default="operator_ui_restart"), repo_root=self.repo_root, projection_root=self.projection_root),
                }
                handler = handlers.get(action)
                if handler is None:
                    raise LocalUIError("unknown_action", status=404)
                result = handler(conn, data)
        except LocalUIError:
            raise
        except (CurationError, CouncilError, AutonomyError, ServiceError) as error:
            raise _status_error(error) from error
        except sqlite3.Error as error:
            raise LocalUIError("database_operation_failed", status=503) from error
        readback = result.get("read_back")
        return _safe({"status": result.get("status", "ok"), "action": action, "result": result, "readback": readback, "receipt_id": result.get("audit_id") or result.get("receipt_audit_id"), "authoritative_readback": readback is not None})

    def _enrich_recall(self, conn: sqlite3.Connection, payload: dict[str, Any]) -> None:
        """Add leak-safe display metadata without changing recall authority."""
        recall = payload.get("data", {}).get("recall", {})
        results = recall.get("cited_results", [])
        source_ids = sorted({str(row.get("source_id")) for row in results if row.get("source_id")})
        if not source_ids:
            return
        placeholders = ",".join("?" for _ in source_ids)
        sources = {
            row["source_id"]: row
            for row in _rows(
                conn,
                f"SELECT source_id, display_name, source_type, health, freshness_seconds, authority_level FROM sources WHERE source_id IN ({placeholders})",
                tuple(source_ids),
            )
        }
        for result in results:
            source = sources.get(result.get("source_id"), {})
            result["source_label"] = source.get("display_name") or result.get("source_id") or "Unknown source"
            result["source_type"] = source.get("source_type") or "unknown"
            result["source_health"] = _semantic_status(source.get("health"))
            result["freshness_seconds"] = source.get("freshness_seconds")
            result["authority_level"] = source.get("authority_level") or "unclassified"
            result["provenance_trail"] = [
                value
                for value in (result.get("target_id"), result.get("proposal_id"), result.get("memory_version"))
                if value not in (None, "")
            ]

    def _home(self, conn: sqlite3.Connection, *, query: str, limit: int) -> dict[str, Any]:
        views = {name: operator_api_view(conn, name, query=query, projection_root=self.projection_root, limit=limit)["data"] for name in ("sources", "proposals", "council", "autonomy", "hermes", "projection", "approval-needed", "scope")}
        service = service_status(conn, repo_root=self.repo_root, projection_root=self.projection_root)
        attention = list(views["approval-needed"].get("items", []))
        existing = {(item.get("kind"), item.get("id")) for item in attention}
        for review in views["council"].get("queues", {}).get("reviews", []):
            if review.get("outcome") in _ADVERSE_REVIEW and ("council_review", review.get("review_id")) not in existing:
                attention.append({"kind": "council_review", "id": review.get("review_id"), "status": review.get("outcome"), "objective_id": review.get("objective_id")})
        for tick in views["autonomy"].get("ticks", []):
            if tick.get("status") in _ATTENTION_TICKS and ("autonomy_tick", tick.get("tick_id")) not in existing:
                attention.append({"kind": "autonomy_tick", "id": tick.get("tick_id"), "status": tick.get("status")})
        child_states = [_semantic_status(views["sources"].get("status")), _semantic_status(views["hermes"].get("status")), _semantic_status(views["projection"].get("status")), _semantic_status(service.get("status"))]
        if attention:
            child_states.append("attention")
        severity = max((state for state in child_states if state), key=lambda state: _SEVERITY.get(str(state), 6), default="healthy")
        return {"status": "ok", "severity": severity, "severity_order": ["error", "unauthorized", "unavailable", "degraded", "attention", "healthy"], "attention_count": len(attention), "attention": attention, "views": views, "service": service, "severity_derived_from_children": True}

    def _memory(self, conn: sqlite3.Connection, *, record_id: str | None, limit: int) -> dict[str, Any]:
        if record_id:
            if record_id.startswith("proposal_"):
                return {"status": "ok", "kind": "proposal", "proposal": inspect_proposal(conn, record_id)}
            return {"status": "ok", "kind": "memory", "memory_record": read_memory(conn, record_id)}
        memories = _rows(conn, "SELECT memory_id, memory_type, scope, status, current_version, confidence, privacy_class, updated_at FROM memories ORDER BY updated_at DESC LIMIT ?", (limit,))
        proposals = list_proposals(conn, limit=limit)
        audit_events = _rows(conn, "SELECT audit_id, event_type, target_type, target_id, status, occurred_at FROM audit_events WHERE target_type IN ('memory','memory_proposal') ORDER BY occurred_at DESC LIMIT ?", (limit,))
        return {"status": "ok", "proposal_count": len(proposals), "memory_count": len(memories), "proposals": proposals, "memories": memories, "audit_events": audit_events}

    def _council(self, conn: sqlite3.Connection, *, record_id: str | None, limit: int) -> dict[str, Any]:
        if record_id:
            return {"status": "ok", "kind": "objective_lifecycle", "lifecycle": lifecycle(conn, record_id)}
        base = operator_api_view(conn, "council", limit=limit)["data"]
        base["evidence_packets"] = list_evidence(conn, limit=limit)
        return base

    def _autonomy(self, conn: sqlite3.Connection, *, record_id: str | None, limit: int) -> dict[str, Any]:
        if record_id:
            return receipt(conn, record_id)
        base = operator_api_view(conn, "autonomy", limit=limit)["data"]
        base["jobs"] = _rows(conn, "SELECT job_id, kind, status, idempotency_key, created_at, started_at, finished_at, error FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
        base["policy_decisions"] = _rows(conn, "SELECT decision_id, actor_id, action, target_type, target_id, decision, reason, decided_at FROM policy_decisions ORDER BY decided_at DESC LIMIT ?", (limit,))
        return base

    def _system(self, conn: sqlite3.Connection, *, limit: int) -> dict[str, Any]:
        views = {name: operator_api_view(conn, name, projection_root=self.projection_root, limit=limit)["data"] for name in ("sources", "scope", "hermes", "projection")}
        benchmarks = benchmark_status(conn, limit=min(limit, 20))
        writebacks = _rows(conn, "SELECT operation_id, profile_id, target_path_hash, state, operation_type, proposal_id, evidence_state, audit_state, rollback_available, created_at, updated_at, completed_at, error_code FROM writeback_operations ORDER BY created_at DESC LIMIT ?", (limit,))
        service = service_status(conn, repo_root=self.repo_root, projection_root=self.projection_root)
        child_states = [_semantic_status(views[name].get("status")) for name in views]
        child_states.extend((_semantic_status(benchmarks.get("status")), _semantic_status(service.get("status"))))
        overall = max((state for state in child_states if state), key=lambda state: _SEVERITY.get(str(state), 6), default="healthy")
        return {"status": overall, "sources": views["sources"], "scope": views["scope"], "hermes": views["hermes"], "projection": views["projection"], "benchmark": benchmarks, "service": service, "writeback_operations": writebacks, "private_paths_exposed": False}

    @staticmethod
    def _text(data: dict[str, Any], key: str, *, required: bool = False, default: str = "", maximum: int = 10000) -> str:
        value = data.get(key, default)
        if not isinstance(value, str) or (required and not value.strip()) or len(value) > maximum:
            raise LocalUIError(f"invalid_{key}")
        return value.strip()

    @staticmethod
    def _ids(data: dict[str, Any], key: str) -> list[str]:
        value = data.get(key, [])
        if isinstance(value, str):
            value = [item.strip() for item in value.split(",") if item.strip()]
        if not isinstance(value, list) or len(value) > 100 or any(not isinstance(item, str) or not item or len(item) > 200 for item in value):
            raise LocalUIError(f"invalid_{key}")
        return value

    @staticmethod
    def _expected(conn: sqlite3.Connection, table: str, id_column: str, identifier: str, expected_status: Any) -> None:
        if expected_status is None:
            return
        row = conn.execute(f"SELECT status FROM {table} WHERE {id_column}=?", (identifier,)).fetchone()
        if row is None:
            raise LocalUIError("record_not_found", status=404)
        if row["status"] != expected_status:
            raise LocalUIError("stale_state", status=409, detail=f"authoritative_status={row['status']}")

    def _proposal_create(self, conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
        return create_proposal(conn, title=self._text(data, "title", required=True, maximum=300), summary=self._text(data, "summary", required=True, maximum=2000), body=self._text(data, "body", required=True), evidence_ids=self._ids(data, "evidence_ids"), source_event_ids=self._ids(data, "source_event_ids"), memory_id=self._text(data, "memory_id", maximum=200) or None, memory_type=self._text(data, "memory_type", default="semantic", maximum=50), scope=self._text(data, "scope", default="global", maximum=50), privacy_class=self._text(data, "privacy_class", default="private", maximum=50))

    def _proposal_review(self, conn: sqlite3.Connection, data: dict[str, Any], action: str) -> dict[str, Any]:
        proposal_id = self._text(data, "proposal_id", required=True, maximum=200)
        self._expected(conn, "memory_proposals", "proposal_id", proposal_id, data.get("expected_status"))
        result = review_proposal(conn, proposal_id=proposal_id, action=action, reviewer_actor_id=self._text(data, "reviewer_actor_id", default="actor_operator_compat02", maximum=200), reason=self._text(data, "reason", maximum=2000) or None, title=self._text(data, "title", maximum=300) or None, summary=self._text(data, "summary", maximum=2000) or None, body=self._text(data, "body") or None)
        result["read_back"] = inspect_proposal(conn, proposal_id)
        return result

    def _memory_write(self, conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
        proposal_id = self._text(data, "proposal_id", required=True, maximum=200)
        self._expected(conn, "memory_proposals", "proposal_id", proposal_id, data.get("expected_status"))
        return write_memory(conn, proposal_id=proposal_id)

    def _memory_tombstone(self, conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
        memory_id = self._text(data, "memory_id", required=True, maximum=200)
        self._expected(conn, "memories", "memory_id", memory_id, data.get("expected_status"))
        return tombstone_memory(conn, memory_id=memory_id, reason=self._text(data, "reason", default="operator_ui_tombstone", maximum=2000))

    def _memory_rollback(self, conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
        memory_id = self._text(data, "memory_id", required=True, maximum=200)
        self._expected(conn, "memories", "memory_id", memory_id, data.get("expected_status"))
        version = data.get("version")
        if not isinstance(version, int) or version < 1:
            raise LocalUIError("invalid_version")
        return rollback_memory(conn, memory_id=memory_id, version=version, reason=self._text(data, "reason", default="operator_ui_rollback", maximum=2000))

    def _autonomy_run(self, conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
        tick_id = self._text(data, "tick_id", required=True, maximum=200)
        self._expected(conn, "autonomy_ticks", "tick_id", tick_id, data.get("expected_status"))
        return run_tick(conn, tick_id=tick_id)

    def _autonomy_control(self, conn: sqlite3.Connection, data: dict[str, Any], control: str) -> dict[str, Any]:
        tick_id = self._text(data, "tick_id", required=True, maximum=200)
        self._expected(conn, "autonomy_ticks", "tick_id", tick_id, data.get("expected_status"))
        reason = self._text(data, "reason", default=f"operator_ui_{control}", maximum=2000)
        fn = {"pause": pause_tick, "resume": resume_tick, "kill": kill_tick}[control]
        result = fn(conn, tick_id, reason=reason)
        result["read_back"] = receipt(conn, tick_id)
        return result
