"""Bounded autonomy tick runtime for Mnemoir Provenance compat 06."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .audit import write_audit_event
from .council import COUNCIL_OPERATOR_ACTOR_ID, create_record, ensure_council_runtime
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

ALLOWED_ACTIONS = {"read_only_recall", "council_record_create"}
APPROVAL_REQUIRED_ACTIONS = {"memory_proposal", "wiki_draft", "file_write", "tool_execution", "external_send"}
DENIED_ACTIONS = {"credential_permission_change", "destructive_action", "provider_config", "gateway_change", "cron_autostart", "live_network_io"}
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "deduped"}


class AutonomyError(ValueError):
    """Domain error reported by the CLI as fail-closed JSON."""


def _json_loads(text: str | None, default: Any) -> Any:
    return json.loads(text) if text else default


def _objective_exists(conn: sqlite3.Connection, objective_id: str) -> bool:
    return conn.execute("SELECT 1 FROM council_objectives WHERE objective_id = ?", (objective_id,)).fetchone() is not None


def _assignment_exists(conn: sqlite3.Connection, assignment_id: str) -> bool:
    return conn.execute("SELECT 1 FROM council_assignments WHERE assignment_id = ?", (assignment_id,)).fetchone() is not None


def _get_tick(conn: sqlite3.Connection, tick_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM autonomy_ticks WHERE tick_id = ?", (tick_id,)).fetchone()
    if row is None:
        raise AutonomyError("tick_not_found")
    return row


def _classify(action_type: str) -> tuple[str, str]:
    if action_type in ALLOWED_ACTIONS:
        return "none", "allowed"
    if action_type in APPROVAL_REQUIRED_ACTIONS:
        return "approval_required", "approval_required"
    if action_type in DENIED_ACTIONS:
        return "denied", "denied"
    return "denied", "unclassified"


def _write_policy_decision(
    conn: sqlite3.Connection,
    *,
    action_type: str,
    target_type: str,
    target_id: str | None,
    decision: str,
    reason: str,
    request: dict[str, Any],
    result: dict[str, Any] | None = None,
    actor_id: str = COUNCIL_OPERATOR_ACTOR_ID,
) -> str:
    timestamp = now_utc()
    decision_id = stable_id("policy", action_type, target_type, target_id or "none", decision, reason, sha256_text(json_dumps(request)), sha256_text(json_dumps(result or {})), timestamp)
    conn.execute(
        """
        INSERT INTO policy_decisions(decision_id, actor_id, action, target_type, target_id, decision, reason, request_json, result_json, decided_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (decision_id, actor_id, action_type, target_type, target_id, decision, reason, json_dumps(request), json_dumps(result or {}), timestamp),
    )
    return decision_id


def _write_job(
    conn: sqlite3.Connection,
    *,
    kind: str,
    input_payload: dict[str, Any],
    idempotency_key: str,
    status: str = "queued",
) -> str:
    timestamp = now_utc()
    job_id = stable_id("job", kind, idempotency_key, sha256_text(json_dumps(input_payload)))
    conn.execute(
        """
        INSERT INTO jobs(job_id, kind, input_json, status, idempotency_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id) DO UPDATE SET input_json=excluded.input_json
        """,
        (job_id, kind, json_dumps(input_payload), status, idempotency_key, timestamp),
    )
    return job_id


def plan_tick(
    conn: sqlite3.Connection,
    *,
    objective_id: str,
    trigger_type: str = "manual",
    action_type: str = "council_record_create",
    idempotency_key: str,
    objective: str | None = None,
    assignment_id: str | None = None,
    action_title: str | None = None,
    action_body: str | None = None,
    max_seconds: int = 30,
    max_cost: float = 0.0,
    source_context: dict[str, Any] | None = None,
    actor_id: str = COUNCIL_OPERATOR_ACTOR_ID,
) -> dict[str, Any]:
    ensure_council_runtime(conn)
    if not idempotency_key:
        raise AutonomyError("missing_idempotency_key")
    if max_seconds <= 0 or max_cost < 0:
        raise AutonomyError("invalid_budget")
    if not _objective_exists(conn, objective_id):
        raise AutonomyError("objective_not_found")
    if assignment_id and not _assignment_exists(conn, assignment_id):
        raise AutonomyError("assignment_not_found")
    existing = conn.execute("SELECT * FROM autonomy_ticks WHERE idempotency_key = ? ORDER BY created_at DESC, tick_id DESC LIMIT 1", (idempotency_key,)).fetchone()
    if existing is not None:
        return {"status": "ok", "tick": _tick_dict(conn, existing), "idempotency_status": "existing"}
    approval_class, policy_reason = _classify(action_type)
    objective_text = objective or f"Bounded local autonomy tick for {objective_id}"
    plan = {
        "action_type": action_type,
        "objective_id": objective_id,
        "assignment_id": assignment_id,
        "title": action_title or "Autonomy tick next action",
        "body": action_body or "Bounded autonomy tick produced a local Council proposal record.",
        "record_kind": "proposal",
    }
    context = source_context or {"objective_id": objective_id, "assignment_id": assignment_id}
    input_payload = {
        "trigger": {"type": trigger_type},
        "objective": objective_text,
        "source_context": context,
        "action_plan": plan,
        "policy_classification": {"approval_class": approval_class, "reason": policy_reason},
        "budget": {"max_seconds": max_seconds, "max_cost": max_cost},
        "idempotency_key_hash": sha256_text(idempotency_key),
    }
    job_id = _write_job(conn, kind="autonomy_tick", input_payload=input_payload, idempotency_key=idempotency_key)
    timestamp = now_utc()
    tick_id = stable_id("tick", idempotency_key, objective_id, action_type)
    conn.execute(
        """
        INSERT INTO autonomy_ticks(tick_id, job_id, objective, trigger_type, actor_id, status, approval_class, budget_json, idempotency_key, created_at)
        VALUES (?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?)
        """,
        (tick_id, job_id, objective_text, trigger_type, actor_id, approval_class, json_dumps({"max_seconds": max_seconds, "max_cost": max_cost}), idempotency_key, timestamp),
    )
    decision = "allow" if approval_class == "none" else ("require_approval" if approval_class == "approval_required" else "deny")
    decision_id = _write_policy_decision(conn, action_type=action_type, target_type="council_objective", target_id=objective_id, decision=decision, reason=policy_reason, request=input_payload, actor_id=actor_id)
    audit_id = write_audit_event(conn, event_type="autonomy.tick.plan", target_type="autonomy_tick", target_id=tick_id, status="ok", actor_id=actor_id, metadata={"job_id": job_id, "policy_decision_id": decision_id, "approval_class": approval_class, "idempotency_key_hash": sha256_text(idempotency_key)})
    conn.commit()
    return {"status": "ok", "tick": receipt(conn, tick_id)["tick"], "audit_id": audit_id, "idempotency_status": "created"}


def run_tick(conn: sqlite3.Connection, *, tick_id: str, actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    ensure_council_runtime(conn)
    tick = _get_tick(conn, tick_id)
    if tick["status"] == "paused":
        return _blocked_receipt(conn, tick, actor_id=actor_id, reason="tick_paused", status="paused")
    if tick["status"] == "cancelled":
        return _blocked_receipt(conn, tick, actor_id=actor_id, reason="tick_cancelled", status="cancelled")
    if tick["status"] == "succeeded":
        return {"status": "deduped", "tick": receipt(conn, tick_id)["tick"], "idempotency_status": "already_succeeded"}
    if tick["status"] in {"failed", "deduped"}:
        return {"status": tick["status"], "tick": receipt(conn, tick_id)["tick"], "idempotency_status": "terminal"}
    duplicate = conn.execute("SELECT * FROM autonomy_ticks WHERE idempotency_key = ? AND status = 'succeeded' AND tick_id != ? ORDER BY finished_at DESC LIMIT 1", (tick["idempotency_key"], tick_id)).fetchone()
    if duplicate is not None:
        return _dedupe_tick(conn, tick, duplicate, actor_id=actor_id)
    budget = _json_loads(tick["budget_json"], {})
    if int(budget.get("max_seconds", 0)) <= 0 or float(budget.get("max_cost", -1)) < 0:
        return _fail_tick(conn, tick, actor_id=actor_id, reason="budget_exhausted", action_type="budget")
    payload = _job_input(conn, tick)
    action_plan = payload.get("action_plan", {})
    action_type = str(action_plan.get("action_type", ""))
    approval_class, policy_reason = _classify(action_type)
    if approval_class == "approval_required":
        return _approval_required_tick(conn, tick, payload, actor_id=actor_id, reason=policy_reason)
    if approval_class == "denied":
        return _fail_tick(conn, tick, actor_id=actor_id, reason=policy_reason, action_type=action_type)
    if action_type != "council_record_create":
        return _fail_tick(conn, tick, actor_id=actor_id, reason="unsupported_allowed_action", action_type=action_type)
    objective_id = str(action_plan.get("objective_id") or "")
    if not objective_id or not _objective_exists(conn, objective_id):
        return _fail_tick(conn, tick, actor_id=actor_id, reason="objective_not_found", action_type=action_type)
    timestamp = now_utc()
    conn.execute("UPDATE autonomy_ticks SET status = 'running', started_at = ? WHERE tick_id = ?", (timestamp, tick_id))
    conn.execute("UPDATE jobs SET status = 'running', started_at = ? WHERE job_id = ?", (timestamp, tick["job_id"]))
    record = create_record(conn, objective_id=objective_id, kind="proposal", title=str(action_plan.get("title") or "Autonomy tick next action"), body=str(action_plan.get("body") or "Bounded autonomy tick produced a local Council proposal record."), actor_id=actor_id, severity="low")
    output = {
        "executed": True,
        "action_type": action_type,
        "result_type": "council_record",
        "record_id": record["record_id"],
        "record_kind": record["record_kind"],
        "source_context": payload.get("source_context", {}),
    }
    receipt_id = write_audit_event(conn, event_type="autonomy.tick.run", target_type="autonomy_tick", target_id=tick_id, status="ok", actor_id=actor_id, metadata={"job_id": tick["job_id"], "result_type": "council_record", "record_id": record["record_id"], "idempotency_key_hash": sha256_text(str(tick["idempotency_key"]))})
    finished = now_utc()
    conn.execute("UPDATE jobs SET status = 'succeeded', output_json = ?, output_refs_json = ?, finished_at = ? WHERE job_id = ?", (json_dumps(output), json_dumps([{"ref_type": "council_record", "ref_id": record["record_id"]}]), finished, tick["job_id"]))
    conn.execute("UPDATE autonomy_ticks SET status = 'succeeded', receipt_audit_id = ?, finished_at = ? WHERE tick_id = ?", (receipt_id, finished, tick_id))
    conn.commit()
    return {"status": "ok", "tick": receipt(conn, tick_id)["tick"], "receipt_audit_id": receipt_id, "result": output}


def plan_and_run_tick(conn: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
    planned = plan_tick(conn, **kwargs)
    tick_id = planned["tick"]["tick_id"]
    if planned.get("idempotency_status") == "existing" and planned["tick"]["status"] == "succeeded":
        return {"status": "deduped", "tick": planned["tick"], "idempotency_status": "existing_succeeded"}
    return run_tick(conn, tick_id=tick_id)


def pause_tick(conn: sqlite3.Connection, tick_id: str, *, reason: str = "operator_pause", actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    tick = _get_tick(conn, tick_id)
    if tick["status"] in TERMINAL_STATUSES:
        raise AutonomyError("tick_terminal")
    conn.execute("UPDATE autonomy_ticks SET status = 'paused' WHERE tick_id = ?", (tick_id,))
    audit_id = write_audit_event(conn, event_type="autonomy.tick.pause", target_type="autonomy_tick", target_id=tick_id, status="ok", actor_id=actor_id, metadata={"reason": reason})
    conn.commit()
    return {"status": "ok", "tick_id": tick_id, "tick_status": "paused", "audit_id": audit_id}


def resume_tick(conn: sqlite3.Connection, tick_id: str, *, reason: str = "operator_resume", actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    tick = _get_tick(conn, tick_id)
    if tick["status"] != "paused":
        raise AutonomyError("tick_not_paused")
    conn.execute("UPDATE autonomy_ticks SET status = 'planned' WHERE tick_id = ?", (tick_id,))
    audit_id = write_audit_event(conn, event_type="autonomy.tick.resume", target_type="autonomy_tick", target_id=tick_id, status="ok", actor_id=actor_id, metadata={"reason": reason})
    conn.commit()
    return {"status": "ok", "tick_id": tick_id, "tick_status": "planned", "audit_id": audit_id}


def kill_tick(conn: sqlite3.Connection, tick_id: str, *, reason: str = "operator_kill", actor_id: str = COUNCIL_OPERATOR_ACTOR_ID) -> dict[str, Any]:
    tick = _get_tick(conn, tick_id)
    if tick["status"] in {"succeeded", "deduped"}:
        raise AutonomyError("tick_already_completed")
    timestamp = now_utc()
    conn.execute("UPDATE autonomy_ticks SET status = 'cancelled', finished_at = ? WHERE tick_id = ?", (timestamp, tick_id))
    if tick["job_id"]:
        conn.execute("UPDATE jobs SET status = 'cancelled', error = ?, finished_at = ? WHERE job_id = ?", (reason, timestamp, tick["job_id"]))
    audit_id = write_audit_event(conn, event_type="autonomy.tick.kill", target_type="autonomy_tick", target_id=tick_id, status="ok", actor_id=actor_id, metadata={"reason": reason})
    conn.commit()
    return {"status": "ok", "tick_id": tick_id, "tick_status": "cancelled", "audit_id": audit_id}


def list_ticks(conn: sqlite3.Connection, *, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    if status:
        rows = conn.execute("SELECT * FROM autonomy_ticks WHERE status = ? ORDER BY created_at DESC, tick_id DESC LIMIT ?", (status, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM autonomy_ticks ORDER BY created_at DESC, tick_id DESC LIMIT ?", (limit,)).fetchall()
    return [_tick_dict(conn, row) for row in rows]


def status(conn: sqlite3.Connection, tick_id: str) -> dict[str, Any]:
    return {"status": "ok", "tick": _tick_dict(conn, _get_tick(conn, tick_id))}


def receipt(conn: sqlite3.Connection, tick_id: str) -> dict[str, Any]:
    tick = _get_tick(conn, tick_id)
    item = _tick_dict(conn, tick)
    if tick["receipt_audit_id"]:
        audit = conn.execute("SELECT audit_id, occurred_at, event_type, target_type, target_id, status, error, metadata_json FROM audit_events WHERE audit_id = ?", (tick["receipt_audit_id"],)).fetchone()
        item["receipt_audit"] = _audit_dict(audit) if audit else None
    item["audit_chain"] = [_audit_dict(row) for row in conn.execute("SELECT audit_id, occurred_at, event_type, target_type, target_id, status, error, metadata_json FROM audit_events WHERE target_type = 'autonomy_tick' AND target_id = ? ORDER BY occurred_at, audit_id", (tick_id,)).fetchall()]
    return {"status": "ok", "tick": item}


def _tick_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["budget"] = _json_loads(item.pop("budget_json"), {})
    if item.get("job_id"):
        job = conn.execute("SELECT job_id, kind, input_json, status, output_json, output_refs_json, idempotency_key, created_at, started_at, finished_at FROM jobs WHERE job_id = ?", (item["job_id"],)).fetchone()
        if job:
            job_dict = row_to_dict(job)
            job_dict["input"] = _json_loads(job_dict.pop("input_json"), {})
            job_dict["output"] = _json_loads(job_dict.pop("output_json"), {})
            job_dict["output_refs"] = _json_loads(job_dict.pop("output_refs_json"), [])
            item["job"] = job_dict
    item["leakage_safe"] = True
    item["truth_authority"] = "policy_provenance_audit_not_heat_or_verdict"
    return item


def _job_input(conn: sqlite3.Connection, tick: sqlite3.Row) -> dict[str, Any]:
    row = conn.execute("SELECT input_json FROM jobs WHERE job_id = ?", (tick["job_id"],)).fetchone()
    if row is None:
        raise AutonomyError("job_not_found")
    return _json_loads(row["input_json"], {})


def _audit_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = row_to_dict(row)
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    return item


def _approval_required_tick(conn: sqlite3.Connection, tick: sqlite3.Row, payload: dict[str, Any], *, actor_id: str, reason: str) -> dict[str, Any]:
    action_type = str(payload.get("action_plan", {}).get("action_type", ""))
    objective_id = str(payload.get("action_plan", {}).get("objective_id", ""))
    decision_id = _write_policy_decision(conn, action_type=action_type, target_type="council_objective", target_id=objective_id, decision="require_approval", reason=reason, request=payload, result={"executed": False, "approval_required": True}, actor_id=actor_id)
    output = {"executed": False, "approval_required": True, "policy_decision_id": decision_id, "proposal": {"action_type": action_type, "objective_id": objective_id, "reason": reason}}
    audit_id = write_audit_event(conn, event_type="autonomy.tick.approval_required", target_type="autonomy_tick", target_id=tick["tick_id"], status="warning", actor_id=actor_id, metadata={"job_id": tick["job_id"], "policy_decision_id": decision_id, "action_type": action_type})
    finished = now_utc()
    conn.execute("UPDATE jobs SET status = 'blocked', output_json = ?, finished_at = ? WHERE job_id = ?", (json_dumps(output), finished, tick["job_id"]))
    conn.execute("UPDATE autonomy_ticks SET status = 'failed', receipt_audit_id = ?, finished_at = ? WHERE tick_id = ?", (audit_id, finished, tick["tick_id"]))
    conn.commit()
    return {"status": "approval_required", "tick": receipt(conn, tick["tick_id"])["tick"], "approval_request": output}


def _fail_tick(conn: sqlite3.Connection, tick: sqlite3.Row, *, actor_id: str, reason: str, action_type: str) -> dict[str, Any]:
    payload = _job_input(conn, tick)
    objective_id = str(payload.get("action_plan", {}).get("objective_id", ""))
    decision_id = _write_policy_decision(conn, action_type=action_type or "unclassified", target_type="council_objective", target_id=objective_id or None, decision="deny", reason=reason, request=payload, result={"executed": False}, actor_id=actor_id)
    output = {"executed": False, "reason": reason, "policy_decision_id": decision_id}
    audit_id = write_audit_event(conn, event_type="autonomy.tick.denied", target_type="autonomy_tick", target_id=tick["tick_id"], status="denied", actor_id=actor_id, metadata={"job_id": tick["job_id"], "policy_decision_id": decision_id, "reason": reason, "action_type": action_type})
    finished = now_utc()
    conn.execute("UPDATE jobs SET status = 'failed', error = ?, output_json = ?, finished_at = ? WHERE job_id = ?", (reason, json_dumps(output), finished, tick["job_id"]))
    conn.execute("UPDATE autonomy_ticks SET status = 'failed', receipt_audit_id = ?, finished_at = ? WHERE tick_id = ?", (audit_id, finished, tick["tick_id"]))
    conn.commit()
    return {"status": "error", "error": reason, "tick": receipt(conn, tick["tick_id"])["tick"], "receipt_audit_id": audit_id}


def _blocked_receipt(conn: sqlite3.Connection, tick: sqlite3.Row, *, actor_id: str, reason: str, status: str) -> dict[str, Any]:
    audit_id = write_audit_event(conn, event_type=f"autonomy.tick.{reason}", target_type="autonomy_tick", target_id=tick["tick_id"], status="denied", actor_id=actor_id, metadata={"reason": reason})
    conn.execute("UPDATE autonomy_ticks SET receipt_audit_id = ? WHERE tick_id = ?", (audit_id, tick["tick_id"]))
    conn.commit()
    return {"status": status, "error": reason, "tick": receipt(conn, tick["tick_id"])["tick"], "executed": False}


def _dedupe_tick(conn: sqlite3.Connection, tick: sqlite3.Row, duplicate: sqlite3.Row, *, actor_id: str) -> dict[str, Any]:
    audit_id = write_audit_event(conn, event_type="autonomy.tick.deduped", target_type="autonomy_tick", target_id=tick["tick_id"], status="ok", actor_id=actor_id, metadata={"deduped_against_tick_id": duplicate["tick_id"], "idempotency_key_hash": sha256_text(str(tick["idempotency_key"]))})
    finished = now_utc()
    conn.execute("UPDATE autonomy_ticks SET status = 'deduped', receipt_audit_id = ?, finished_at = ? WHERE tick_id = ?", (audit_id, finished, tick["tick_id"]))
    if tick["job_id"]:
        conn.execute("UPDATE jobs SET status = 'succeeded', output_json = ?, finished_at = ? WHERE job_id = ?", (json_dumps({"executed": False, "deduped_against_tick_id": duplicate["tick_id"]}), finished, tick["job_id"]))
    conn.commit()
    return {"status": "deduped", "tick": receipt(conn, tick["tick_id"])["tick"], "deduped_against_tick_id": duplicate["tick_id"]}
