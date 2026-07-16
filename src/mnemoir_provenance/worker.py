"""Explicitly invoked bounded compat 17B lifecycle worker.

No daemon, scheduler, autostart, network, or background process is installed.
Claims, leases, attempts, and receipts are durable SQLite state.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .curation import CurationError, write_memory
from .db import json_dumps, now_utc, row_to_dict, stable_id

WORK_KIND = "compat17b_promote_proposal"


class WorkerError(ValueError):
    pass


def _future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def enqueue_promotion(conn: sqlite3.Connection, proposal_id: str) -> dict[str, Any]:
    if conn.execute("SELECT 1 FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone() is None:
        raise WorkerError("proposal_not_found")
    job_id = stable_id("job", WORK_KIND, proposal_id)
    now = now_utc()
    conn.execute("""INSERT OR IGNORE INTO jobs(job_id, kind, input_json, status, idempotency_key, created_at)
                    VALUES (?, ?, ?, 'queued', ?, ?)""", (job_id, WORK_KIND, json_dumps({"proposal_id": proposal_id}), f"promote:{proposal_id}", now))
    conn.commit()
    row = conn.execute("SELECT status FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    return {"status": "ok", "job_id": job_id, "job_status": row["status"]}


def request_stop(conn: sqlite3.Connection, reason: str = "operator_stop") -> dict[str, Any]:
    now = now_utc()
    conn.execute("""INSERT INTO worker_control(worker_name, stop_requested, reason, updated_at)
                    VALUES ('compat17b',1,?,?) ON CONFLICT(worker_name) DO UPDATE SET stop_requested=1,reason=excluded.reason,updated_at=excluded.updated_at""", (reason, now))
    conn.commit()
    return {"status": "ok", "worker": "compat17b", "stop_requested": True}


def clear_stop(conn: sqlite3.Connection) -> None:
    conn.execute("""INSERT INTO worker_control(worker_name, stop_requested, reason, updated_at)
                    VALUES ('compat17b',0,NULL,?) ON CONFLICT(worker_name) DO UPDATE SET stop_requested=0,reason=NULL,updated_at=excluded.updated_at""", (now_utc(),))
    conn.commit()


def _claim(conn: sqlite3.Connection, worker_id: str, lease_seconds: int) -> sqlite3.Row | None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute("SELECT stop_requested FROM worker_control WHERE worker_name='compat17b'").fetchone() not in (None,):
            control = conn.execute("SELECT stop_requested FROM worker_control WHERE worker_name='compat17b'").fetchone()
            if control and control["stop_requested"]:
                conn.commit()
                return None
        now = now_utc()
        row = conn.execute("""SELECT * FROM jobs WHERE kind=? AND
          (status='queued' OR (status='running' AND job_id IN
            (SELECT job_id FROM worker_claims WHERE lease_expires_at<=?)))
          ORDER BY priority DESC, created_at, job_id LIMIT 1""", (WORK_KIND, now)).fetchone()
        if row is None:
            conn.commit()
            return None
        claim_id = f"claim_{uuid.uuid4().hex}"
        previous_claim = conn.execute("SELECT attempt FROM worker_claims WHERE job_id=?", (row["job_id"],)).fetchone()
        receipt_attempt = conn.execute("SELECT MAX(attempt) FROM worker_receipts WHERE job_id=?", (row["job_id"],)).fetchone()[0]
        attempt = max(
            (int(previous_claim["attempt"]) + 1) if previous_claim else 1,
            (int(receipt_attempt) + 1) if receipt_attempt is not None else 1,
        )
        conn.execute("DELETE FROM worker_claims WHERE job_id=?", (row["job_id"],))
        conn.execute("""INSERT INTO worker_claims(claim_id,job_id,worker_id,lease_expires_at,claimed_at,attempt)
                        VALUES (?,?,?,?,?,?)""",
                     (claim_id, row["job_id"], worker_id, _future(lease_seconds), now, attempt))
        conn.execute("UPDATE jobs SET status='running', started_at=COALESCE(started_at,?), error=NULL WHERE job_id=?", (now, row["job_id"]))
        conn.commit()
        return conn.execute("SELECT j.*,c.claim_id,c.attempt FROM jobs j JOIN worker_claims c ON c.job_id=j.job_id WHERE j.job_id=?", (row["job_id"],)).fetchone()
    except Exception:
        conn.rollback()
        raise


def _load_proposal_id(claim: sqlite3.Row) -> str:
    return str(json.loads(claim["input_json"])["proposal_id"])


def _owns_live_attempt(conn: sqlite3.Connection, *, job_id: str, claim_id: str, worker_id: str, attempt: int) -> bool:
    return conn.execute(
        """SELECT 1 FROM worker_claims
           WHERE job_id=? AND claim_id=? AND worker_id=? AND attempt=? AND lease_expires_at>?""",
        (job_id, claim_id, worker_id, attempt, now_utc()),
    ).fetchone() is not None


def run_bounded_worker(conn: sqlite3.Connection, *, batch_limit: int = 10, lease_seconds: int = 60, worker_id: str | None = None) -> dict[str, Any]:
    if not 1 <= int(batch_limit) <= 100:
        raise WorkerError("invalid_batch_limit")
    if not 5 <= int(lease_seconds) <= 3600:
        raise WorkerError("invalid_lease_seconds")
    worker_id = worker_id or f"worker_{uuid.uuid4().hex}"
    processed: list[dict[str, Any]] = []
    for _ in range(int(batch_limit)):
        claim = _claim(conn, worker_id, int(lease_seconds))
        if claim is None:
            break
        job_id, claim_id, attempt = claim["job_id"], claim["claim_id"], int(claim["attempt"])
        receipt_id = stable_id("worker_receipt", claim_id, attempt)
        proposal_id = "invalid"
        try:
            proposal_id = _load_proposal_id(claim)
            conn.execute("BEGIN IMMEDIATE")
            if not _owns_live_attempt(conn, job_id=job_id, claim_id=claim_id, worker_id=worker_id, attempt=attempt):
                conn.rollback()
                continue
            output = write_memory(conn, proposal_id=proposal_id, _commit=False)
            if not _owns_live_attempt(conn, job_id=job_id, claim_id=claim_id, worker_id=worker_id, attempt=attempt):
                conn.rollback()
                continue
            status, error = "succeeded", None
            safe_output = {"proposal_id": proposal_id, "memory_id": output["memory_id"], "version": output["version"], "idempotency_status": output.get("idempotency_status", "created")}
        except Exception as exc:
            conn.rollback()
            proposal_id = locals().get("proposal_id", "invalid")
            status, error, safe_output = "failed", type(exc).__name__, {"proposal_id": proposal_id, "error_category": type(exc).__name__}
            conn.execute("BEGIN IMMEDIATE")
            if not _owns_live_attempt(conn, job_id=job_id, claim_id=claim_id, worker_id=worker_id, attempt=attempt):
                conn.rollback()
                continue
        now = now_utc()
        conn.execute("""INSERT INTO worker_receipts(receipt_id,job_id,claim_id,worker_id,attempt,status,output_json,error,started_at,finished_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""", (receipt_id, job_id, claim_id, worker_id, attempt, status, json_dumps(safe_output), error, claim["started_at"] or now, now))
        conn.execute("UPDATE jobs SET status=?, output_json=?, error=?, finished_at=? WHERE job_id=?", (status, json_dumps(safe_output), error, now, job_id))
        conn.execute("DELETE FROM worker_claims WHERE claim_id=?", (claim_id,))
        conn.commit()
        processed.append({"job_id": job_id, "receipt_id": receipt_id, "status": status, **safe_output})
    return {"status": "ok", "worker_id": worker_id, "batch_limit": int(batch_limit), "processed_count": len(processed), "receipts": processed, "bounded": True, "background_process_started": False}


def worker_status(conn: sqlite3.Connection, limit: int = 20) -> dict[str, Any]:
    rows = conn.execute("SELECT * FROM worker_receipts ORDER BY finished_at DESC, receipt_id DESC LIMIT ?", (limit,)).fetchall()
    control = conn.execute("SELECT * FROM worker_control WHERE worker_name='compat17b'").fetchone()
    return {"status": "ok", "worker": "compat17b", "execution_model": "explicit_bounded_invocation", "installed_daemon": False, "stop_requested": bool(control and control["stop_requested"]), "receipts": [row_to_dict(row) for row in rows]}
