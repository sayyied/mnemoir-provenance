"""compat 09 local managed service runtime for Mnemoir Provenance.

This is an equivalent managed runtime over the canonical local SQLite DB. It does
not install autostart, cron, systemd, gateways, provider config, credentials, or
permissions, and it does not start an unbounded background process.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id
from .health import health_report
from .operator_surface import _assert_safe, _clean_value

SERVICE_JOB_KIND = "compat09_local_service_runtime"
SERVICE_IDEMPOTENCY_KEY = "mnemoir-provenance-local-service"


class ServiceError(ValueError):
    """Fail-closed compat 09 service error."""


def _service_job(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM jobs WHERE kind=? AND idempotency_key=? ORDER BY created_at DESC LIMIT 1",
        (SERVICE_JOB_KIND, SERVICE_IDEMPOTENCY_KEY),
    ).fetchone()


def _job_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    payload = row_to_dict(row)
    for key in ["input_json", "input_refs_json", "output_json", "output_refs_json"]:
        if isinstance(payload.get(key), str):
            import json

            payload[key.removesuffix("_json")] = json.loads(payload.pop(key))
    return payload


def service_status(conn: sqlite3.Connection, *, repo_root=None, projection_root=None) -> dict[str, Any]:
    health = health_report(conn, repo_root=repo_root, projection_root=projection_root)
    job = _service_job(conn)
    service_state = "stopped"
    if job is not None:
        if job["status"] == "running":
            service_state = "running"
        elif job["status"] == "cancelled":
            service_state = "stopped"
        elif job["status"] in {"failed", "blocked"}:
            service_state = "error"
    result = {
        "status": "ok" if service_state == "running" and health["status"] in {"ok", "degraded"} else ("degraded" if health["status"] == "degraded" else health["status"]),
        "service_state": service_state,
        "managed_runtime": "local_db_job_spine",
        "background_process_started": False,
        "autostart_installed": False,
        "cron_installed": False,
        "system_service_installed": False,
        "restart_persistence_supported": True,
        "job": _job_payload(job),
        "health": health,
    }
    return _safe(result)


def service_start(conn: sqlite3.Connection, *, repo_root=None, projection_root=None) -> dict[str, Any]:
    health = health_report(conn, repo_root=repo_root, projection_root=projection_root)
    if health["status"] in {"error", "unavailable", "unauthorized"}:
        audit_id = write_audit_event(
            conn,
            event_type="service.start.blocked",
            target_type="service_runtime",
            target_id=SERVICE_IDEMPOTENCY_KEY,
            status="denied" if health["status"] == "unauthorized" else "error",
            metadata={"health_status": health["status"], "fail_closed": True},
            error="health_fail_closed",
        )
        conn.commit()
        result = {"status": health["status"], "service_state": "blocked", "fail_closed": True, "audit_id": audit_id, "health": health}
        return _safe(result)

    now = now_utc()
    job_id = stable_id("job", SERVICE_JOB_KIND, SERVICE_IDEMPOTENCY_KEY)
    input_payload = {
        "phase": "compat-09-local-daemon-service-and-health-spine",
        "runtime": "local_db_job_spine",
        "forbidden_surfaces_touched": False,
        "background_process_started": False,
        "idempotency_key_hash": sha256_text(SERVICE_IDEMPOTENCY_KEY),
    }
    existing = _service_job(conn)
    if existing is None:
        conn.execute(
            """
            INSERT INTO jobs(job_id, kind, input_json, status, idempotency_key, created_at, started_at)
            VALUES (?, ?, ?, 'running', ?, ?, ?)
            """,
            (job_id, SERVICE_JOB_KIND, json_dumps(input_payload), SERVICE_IDEMPOTENCY_KEY, now, now),
        )
        idempotency_status = "created"
    else:
        job_id = existing["job_id"]
        conn.execute(
            """
            UPDATE jobs
            SET status='running', error=NULL, input_json=?, output_json='{}', started_at=?, finished_at=NULL
            WHERE job_id=?
            """,
            (json_dumps(input_payload), now, job_id),
        )
        idempotency_status = "restarted" if existing["status"] != "running" else "existing"
    audit_id = write_audit_event(
        conn,
        event_type="service.start",
        target_type="service_runtime",
        target_id=job_id,
        status="ok" if health["status"] == "ok" else "degraded",
        metadata={"health_status": health["status"], "idempotency_status": idempotency_status},
    )
    conn.commit()
    result = service_status(conn, repo_root=repo_root, projection_root=projection_root)
    result.update({"audit_id": audit_id, "idempotency_status": idempotency_status})
    return _safe(result)


def service_stop(conn: sqlite3.Connection, *, reason: str = "operator_stop", repo_root=None, projection_root=None) -> dict[str, Any]:
    job = _service_job(conn)
    if job is None:
        result = service_status(conn, repo_root=repo_root, projection_root=projection_root)
        result.update({"idempotency_status": "not_running"})
        return _safe(result)
    now = now_utc()
    conn.execute(
        "UPDATE jobs SET status='cancelled', error=?, output_json=?, finished_at=? WHERE job_id=?",
        (reason, json_dumps({"stopped": True, "reason": reason}), now, job["job_id"]),
    )
    audit_id = write_audit_event(
        conn,
        event_type="service.stop",
        target_type="service_runtime",
        target_id=job["job_id"],
        status="ok",
        metadata={"reason": reason},
    )
    conn.commit()
    result = service_status(conn, repo_root=repo_root, projection_root=projection_root)
    result.update({"audit_id": audit_id, "idempotency_status": "stopped"})
    return _safe(result)


def service_restart(conn: sqlite3.Connection, *, reason: str = "operator_restart", repo_root=None, projection_root=None) -> dict[str, Any]:
    stopped = service_stop(conn, reason=reason, repo_root=repo_root, projection_root=projection_root)
    started = service_start(conn, repo_root=repo_root, projection_root=projection_root)
    result = {"status": started["status"], "service_state": started["service_state"], "stop": stopped, "start": started, "restart_persistence_proved": started.get("job", {}).get("job_id") == stopped.get("job", {}).get("job_id") if stopped.get("job") else True}
    return _safe(result)


def _safe(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned = _clean_value(payload)
    _assert_safe(cleaned)
    return cleaned
