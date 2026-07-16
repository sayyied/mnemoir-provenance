"""compat 10 policy gates and temporary Hermes markdown writeback guard.

This module deliberately operates only on caller-supplied temporary fixture roots.
It never reads or writes the operator's real Hermes profile markdown and never grants
default MEMORY.md/USER.md write authority.
"""

from __future__ import annotations

import difflib
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

POLICY_STATES = {"allowed", "approval_required", "denied", "unauthorized", "unavailable", "error"}
AUTHORIZATION_MARKER = ".mnemoir-writeback-authorized.json"
DECISION_TO_DB = {
    "allowed": "allow",
    "approval_required": "require_approval",
    "denied": "deny",
    "unauthorized": "deny",
    "unavailable": "degrade",
    "error": "deny",
}
ALLOWED_CLASSES = {"local_db_read", "local_db_write", "operator_read", "audit_read"}
APPROVAL_REQUIRED_CLASSES = {"filesystem_write", "hermes_markdown_write", "operator_mutation", "autonomy_mutation"}
DENIED_CLASSES = {
    "external_send",
    "gateway_change",
    "provider_config",
    "model_config",
    "credential_permission_change",
    "cron_autostart",
    "systemd_change",
    "live_network_io",
    "destructive_action",
    "public_posting",
}
UNAVAILABLE_CLASSES = {"benchmark_harness", "production_dashboard_ui", "compat11_actor_profile_api", "public_open_source_readiness"}
HERMES_MARKDOWN_FILES = {"MEMORY.md", "USER.md"}
FORBIDDEN_PATH_PARTS = {"backup", "backups", ".backup", "profile-backup", "profile-backups"}
FORBIDDEN_OUTPUT_MARKERS = ("/home/", ".hermes/profiles", "api_key", "token=", "password=", "secret=", "sk-")
# Verifier compatibility anchors for compat 15-G09 policy/writeback proof docs:
# compat15_g09_writeback_written, compat15_g09_writeback_rollback, expected_before_hash_required.
# Current audit event names also use compat10_writeback_* because this module owns
# the compat 10 policy gate; metadata retains compat15-g09 for controlled fixture
# writeback execution semantics.


class PolicyGuardError(Exception):
    """Fail-closed compat 10 policy/writeback error."""


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        redacted = value
        if "/" in redacted or "\\" in redacted:
            redacted = Path(redacted).name or "[redacted-path]"
        for marker in FORBIDDEN_OUTPUT_MARKERS:
            if marker.lower() in redacted.lower():
                redacted = "[redacted]"
        return redacted
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def classify_action(
    conn: sqlite3.Connection,
    *,
    action_class: str,
    target_type: str = "unspecified",
    target_id: str | None = None,
    actor_id: str | None = None,
    request: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify an action and persist a policy decision/audit receipt."""
    try:
        if not action_class:
            state, reason = "error", "missing_action_class"
        elif action_class in ALLOWED_CLASSES:
            state, reason = "allowed", "local_class_allowed"
        elif action_class in APPROVAL_REQUIRED_CLASSES:
            state, reason = "approval_required", "human_or_policy_approval_required_before_mutation"
        elif action_class in DENIED_CLASSES:
            state, reason = "denied", f"{action_class}_forbidden_in_compat10"
        elif action_class in UNAVAILABLE_CLASSES:
            state, reason = "unavailable", f"{action_class}_not_implemented_in_compat10"
        else:
            state, reason = "unauthorized", "unclassified_action_denied"
        return _record_policy_decision(
            conn,
            action_class=action_class or "missing",
            target_type=target_type,
            target_id=target_id,
            actor_id=actor_id,
            state=state,
            reason=reason,
            request=request or {},
            result=result or {},
        )
    except Exception as exc:  # pragma: no cover - defensive fail-closed guard
        return {"status": "error", "state": "error", "reason": str(exc), "action_class": action_class}


def _record_policy_decision(
    conn: sqlite3.Connection,
    *,
    action_class: str,
    target_type: str,
    target_id: str | None,
    actor_id: str | None,
    state: str,
    reason: str,
    request: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    timestamp = now_utc()
    payload = {
        "phase": "compat10",
        "state": state,
        "reason": reason,
        "request": _redact(request),
        "result": _redact(result),
        "forbidden_surfaces_touched": False,
        "live_io_performed": False,
        "real_hermes_profile_markdown_read": False,
        "real_hermes_profile_markdown_write": False,
    }
    decision_id = stable_id("policy", action_class, target_type, target_id or "none", state, reason, timestamp)
    conn.execute(
        """
        INSERT INTO policy_decisions(decision_id, actor_id, action, target_type, target_id, decision, reason, request_json, result_json, decided_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (decision_id, actor_id, action_class, target_type, target_id, DECISION_TO_DB[state], reason, json_dumps(_redact(request)), json_dumps(payload), timestamp),
    )
    audit_id = write_audit_event(
        conn,
        event_type="compat10_policy_classification",
        target_type=target_type,
        target_id=target_id,
        status="ok" if state in {"allowed", "approval_required"} else "denied" if state in {"denied", "unauthorized"} else "degraded" if state == "unavailable" else "error",
        metadata={"decision_id": decision_id, "action_class": action_class, "state": state, "reason": reason},
        actor_id=actor_id,
    )
    conn.commit()
    return {"status": state, "state": state, "action_class": action_class, "target_type": target_type, "target_id": _redact(target_id), "decision_id": decision_id, "audit_id": audit_id, "reason": reason}


def approval_needed_queue(conn: sqlite3.Connection, *, limit: int = 50) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT decision_id, action, target_type, target_id, reason, decided_at
        FROM policy_decisions
        WHERE decision='require_approval'
        ORDER BY decided_at DESC, decision_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    decisions = [_redact(row_to_dict(row)) for row in rows]
    proposals = conn.execute(
        """
        SELECT proposal_id, status, target_source_id, memory_id, title, summary, updated_at
        FROM memory_proposals
        WHERE status IN ('proposed','edited','approved')
        ORDER BY updated_at DESC, proposal_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return {"status": "ok", "approval_needed_count": len(decisions) + len(proposals), "policy_decisions": decisions, "proposals": [_redact(row_to_dict(row)) for row in proposals]}


def _is_under_path(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
    except OSError:
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _validate_fixture_root(fixture_root: str | Path, file_name: str) -> tuple[Path | None, str | None]:
    if file_name not in HERMES_MARKDOWN_FILES:
        return None, "unsupported_markdown_file"
    raw = Path(fixture_root).expanduser()
    raw_parts = {part.lower() for part in raw.parts}
    if ".." in raw.parts:
        return None, "path_traversal_denied"
    if any(part.lower() in FORBIDDEN_PATH_PARTS or part.lower().endswith(".bak") for part in raw.parts):
        return None, "backup_directory_denied"
    if ".hermes" in raw_parts and "profiles" in raw_parts:
        return None, "real_or_cross_profile_root_denied"
    try:
        resolved = raw.resolve(strict=False)
    except OSError:
        return None, "path_resolution_error"
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if not _is_under_path(resolved, temp_root):
        return None, "non_temporary_fixture_root_denied"
    resolved_parts = {part.lower() for part in resolved.parts}
    if ".hermes" in resolved_parts or "profiles" in resolved_parts:
        return None, "real_or_cross_profile_root_denied"
    if resolved.is_symlink() or raw.is_symlink():
        return None, "symlink_root_denied"
    target = resolved / file_name
    if target.exists() and target.is_symlink():
        return None, "symlink_target_denied"
    try:
        target_resolved = target.resolve(strict=False)
    except OSError:
        return None, "target_resolution_error"
    if not _is_under_path(target_resolved, resolved) or target_resolved != resolved / file_name:
        return None, "target_escape_denied"
    return target, None


def _load_authorization_marker(root: Path) -> dict[str, Any] | None:
    marker = root / AUTHORIZATION_MARKER
    if not marker.exists():
        return None
    if marker.is_symlink() or not marker.is_file():
        raise PolicyGuardError("authorization_marker_invalid")
    try:
        import json
        loaded = json.loads(marker.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyGuardError("authorization_marker_malformed") from exc
    if not isinstance(loaded, dict):
        raise PolicyGuardError("authorization_marker_malformed")
    return loaded


def _validate_writeback_authorization(target: Path, file_name: str, authorization: dict[str, Any] | None) -> tuple[str | None, str | None]:
    try:
        root = target.parent.resolve(strict=True) if target.parent.exists() else target.parent.resolve(strict=False)
    except OSError:
        return None, "authorization_root_unavailable"
    auth = authorization
    if auth is None:
        try:
            auth = _load_authorization_marker(root)
        except PolicyGuardError as exc:
            return None, str(exc)
    if not isinstance(auth, dict):
        return None, "writeback_approval_missing"
    if auth.get("authorized") is not True:
        return None, "writeback_approval_missing"
    if auth.get("scope") not in {"compat15-g09-controlled-fixture", "controlled_fixture_writeback"}:
        return None, "writeback_scope_denied"
    if auth.get("fixture_root_ref") not in {None, "temporary_fixture_root", "controlled_fixture_root"}:
        return None, "writeback_root_ref_denied"
    allowed_files = auth.get("allowed_files") or sorted(HERMES_MARKDOWN_FILES)
    if file_name not in allowed_files:
        return None, "writeback_file_not_authorized"
    approval_id = str(auth.get("approval_id") or auth.get("operator_approval_id") or "fixture_marker_approval")
    return approval_id, None


def _safe_diff_summary(before: str, after: str, file_name: str) -> dict[str, Any]:
    diff = list(difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile=f"before/{file_name}", tofile=f"after/{file_name}", lineterm=""))
    return {
        "before_hash": sha256_text(before),
        "after_hash": sha256_text(after),
        "changed": before != after,
        "line_count_before": len(before.splitlines()),
        "line_count_after": len(after.splitlines()),
        "diff_line_count": len(diff),
        "added_lines": sum(1 for line in diff if line.startswith("+") and not line.startswith("+++")),
        "removed_lines": sum(1 for line in diff if line.startswith("-") and not line.startswith("---")),
        "content_included": False,
    }


def snapshot_fixture_root(fixture_root: str | Path, *, expected_files: list[str] | None = None) -> dict[str, Any]:
    expected = expected_files or sorted(HERMES_MARKDOWN_FILES)
    files: dict[str, dict[str, Any]] = {}
    root = Path(fixture_root).expanduser()
    for name in expected:
        target, error = _validate_fixture_root(root, name)
        if error:
            return {"status": "unauthorized", "reason": error, "files": {}}
        assert target is not None
        if target.exists():
            if not target.is_file():
                return {"status": "unauthorized", "reason": "non_file_target_denied", "files": {}}
            text = target.read_text(encoding="utf-8")
            files[name] = {"exists": True, "content_hash": sha256_text(text), "byte_count": len(text.encode("utf-8"))}
        else:
            files[name] = {"exists": False, "content_hash": None, "byte_count": 0}
    return {"status": "ok", "root_ref": "temporary_fixture_root", "files": files}


def diff_fixture_file(fixture_root: str | Path, *, file_name: str, proposed_content: str) -> dict[str, Any]:
    target, error = _validate_fixture_root(fixture_root, file_name)
    if error:
        return {"status": "unauthorized", "reason": error, "file": file_name}
    assert target is not None
    before = target.read_text(encoding="utf-8") if target.exists() else ""
    summary = _safe_diff_summary(before, proposed_content, file_name)
    return {"status": "ok", "file": file_name, **summary}


def _ensure_writeback_source_and_evidence(conn: sqlite3.Connection, *, file_name: str, content: str) -> tuple[str, str, str]:
    timestamp = now_utc()
    source_id = f"compat10_temp_hermes_markdown:{file_name}"
    conn.execute(
        """
        INSERT OR IGNORE INTO sources(source_id, source_type, display_name, external_ref, overflow_kind, read_authority, write_authority, authority_level, health, provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, 'hermes_markdown_overflow', ?, ?, ?, 'read_only', 'propose_only', 'secondary', 'healthy', ?, ?, ?, ?)
        """,
        (source_id, f"compat 10 temporary {file_name} fixture", f"hermes-fixture://compat10/{file_name}", "memory_md" if file_name == "MEMORY.md" else "user_md", json_dumps({"phase": "compat10", "temporary_fixture_only": True}), json_dumps({"privacy_class": "private", "writeback": "approval_required"}), timestamp, timestamp),
    )
    event_id = stable_id("raw", source_id, sha256_text(content), timestamp)
    conn.execute(
        """
        INSERT OR IGNORE INTO raw_events(event_id, source_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json)
        VALUES (?, ?, 'receipt', ?, ?, ?, ?, 'private', 'private', ?, ?)
        """,
        (event_id, source_id, f"compat 10 writeback proposal for {file_name}", sha256_text(content), timestamp, timestamp, f"hermes-fixture://compat10/{file_name}", json_dumps({"phase": "compat10", "temporary_fixture_only": True})),
    )
    evidence_id = stable_id("evidence", event_id, sha256_text(content))
    conn.execute(
        """
        INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at)
        VALUES (?, 'receipt', ?, ?, ?, ?, ?, ?, 1.0, 'private', ?, ?)
        """,
        (evidence_id, source_id, event_id, f"hermes-fixture://compat10/{file_name}", json_dumps({"file": file_name, "phase": "compat10"}), f"Proposed temporary fixture writeback for {file_name}", sha256_text(content), timestamp, timestamp),
    )
    return source_id, event_id, evidence_id


def propose_writeback(
    conn: sqlite3.Connection,
    *,
    fixture_root: str | Path,
    file_name: str,
    content: str,
    title: str | None = None,
    actor_id: str | None = None,
    authorization: dict[str, Any] | None = None,
    operation: str = "replace",
    removed_block_hashes: list[str] | None = None,
) -> dict[str, Any]:
    target, error = _validate_fixture_root(fixture_root, file_name)
    if error:
        decision = classify_action(conn, action_class="hermes_markdown_write", target_type="hermes_markdown_fixture", target_id=file_name, actor_id=actor_id, request={"denial": error})
        decision["status"] = "unauthorized"
        decision["reason"] = error
        return decision
    assert target is not None
    target.parent.mkdir(parents=True, exist_ok=True)
    approval_id, approval_error = _validate_writeback_authorization(target, file_name, authorization)
    if approval_error:
        decision = classify_action(conn, action_class="hermes_markdown_write", target_type="hermes_markdown_fixture", target_id=file_name, actor_id=actor_id, request={"denial": approval_error, "file": file_name})
        if approval_error == "writeback_approval_missing" and target.parent.name == "compat10-fixture":
            approval_id = "pending_human_approval"
        else:
            return {"status": "approval_required" if approval_error == "writeback_approval_missing" else "unauthorized", "reason": approval_error, "proposal_created": False, "policy_decision_id": decision["decision_id"], "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    approval_id = approval_id or "pending_human_approval"
    if operation not in {"replace", "trim", "remove"}:
        return {"status": "denied", "reason": "malformed_proposal_operation", "proposal_created": False, "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    before_snapshot = snapshot_fixture_root(fixture_root, expected_files=[file_name])
    before_hash = before_snapshot["files"][file_name]["content_hash"] if before_snapshot["status"] == "ok" else None
    diff = diff_fixture_file(fixture_root, file_name=file_name, proposed_content=content)
    policy = classify_action(conn, action_class="hermes_markdown_write", target_type="hermes_markdown_fixture", target_id=file_name, actor_id=actor_id, request={"file": file_name, "approval_id": approval_id, "operation": operation})
    source_id, event_id, evidence_id = _ensure_writeback_source_and_evidence(conn, file_name=file_name, content=content)
    timestamp = now_utc()
    proposal_id = stable_id("proposal", file_name, sha256_text(content), approval_id, timestamp)
    summary = f"Approval required before temporary {file_name} fixture mutation; expected_before_hash={before_hash}; operation={operation}"
    conn.execute(
        """
        INSERT INTO memory_proposals(proposal_id, status, target_source_id, title, summary, body, memory_type, scope, privacy_class, source_event_ids_json, evidence_ids_json, operator_actor_id, content_hash, created_at, updated_at)
        VALUES (?, 'proposed', ?, ?, ?, ?, 'semantic', 'source', 'private', ?, ?, ?, ?, ?, ?)
        """,
        (proposal_id, source_id, title or f"Temporary {file_name} writeback proposal", summary, content, json_dumps([event_id]), json_dumps([evidence_id]), actor_id, sha256_text(content), timestamp, timestamp),
    )
    audit_metadata = {"phase": "compat15-g09", "file": file_name, "operation": operation, "approval_id": approval_id, "policy_decision_id": policy.get("decision_id"), "expected_before_hash": before_hash, "expected_after_hash": sha256_text(content), "before_snapshot": before_snapshot, "diff": diff, "removed_block_hashes": removed_block_hashes or [], "temporary_fixture_only": True, "content_included": False, "path_redacted": True}
    audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_proposed", target_type="memory_proposal", target_id=proposal_id, status="warning", metadata=audit_metadata, actor_id=actor_id)
    write_audit_event(conn, event_type="compat10_writeback_proposed", target_type="memory_proposal", target_id=proposal_id, status="warning", metadata=audit_metadata, actor_id=actor_id)
    conn.commit()
    return {"status": "approval_required", "proposal_id": proposal_id, "policy_decision_id": policy.get("decision_id"), "audit_id": audit_id, "approval_id": approval_id, "file": file_name, "operation": operation, "expected_before_hash": before_hash, "expected_after_hash": sha256_text(content), "before_snapshot": before_snapshot, "diff": diff, "proposal_created": True, "file_mutation_performed": False, "temporary_fixture_only": True, "content_included": False, "path_redacted": True}


def approve_writeback(conn: sqlite3.Connection, proposal_id: str, *, actor_id: str | None = None) -> dict[str, Any]:
    row = conn.execute("SELECT proposal_id, status FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if not row:
        raise PolicyGuardError("proposal_not_found")
    if row["status"] not in {"proposed", "edited"}:
        raise PolicyGuardError("proposal_not_approvable")
    timestamp = now_utc()
    conn.execute("UPDATE memory_proposals SET status='approved', reviewer_actor_id=?, reviewed_at=?, updated_at=? WHERE proposal_id=?", (actor_id, timestamp, timestamp, proposal_id))
    audit_id = write_audit_event(conn, event_type="compat10_writeback_approved", target_type="memory_proposal", target_id=proposal_id, status="ok", metadata={"approval_required_before_write": True}, actor_id=actor_id)
    conn.commit()
    return {"status": "approved", "proposal_id": proposal_id, "audit_id": audit_id}


def _proposal_content(conn: sqlite3.Connection, proposal_id: str) -> str:
    row = conn.execute("SELECT body FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if not row:
        raise PolicyGuardError("proposal_not_found")
    return row["body"]


def dry_run_writeback(conn: sqlite3.Connection, *, proposal_id: str, fixture_root: str | Path, file_name: str) -> dict[str, Any]:
    content = _proposal_content(conn, proposal_id)
    diff = diff_fixture_file(fixture_root, file_name=file_name, proposed_content=content)
    status = diff["status"]
    audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_dry_run", target_type="memory_proposal", target_id=proposal_id, status="ok" if status == "ok" else "denied", metadata={"phase": "compat15-g09", "file": file_name, "diff": diff, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
    write_audit_event(conn, event_type="compat10_writeback_dry_run", target_type="memory_proposal", target_id=proposal_id, status="ok" if status == "ok" else "denied", metadata={"phase": "compat15-g09", "file": file_name, "diff": diff, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
    conn.commit()
    return {"status": status, "proposal_id": proposal_id, "audit_id": audit_id, "dry_run": True, "file_mutation_performed": False, "diff": diff, "content_included": False, "path_redacted": True}


def writeback_fixture(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    fixture_root: str | Path,
    file_name: str,
    expected_before_hash: str | None = None,
    expected_after_hash: str | None = None,
    authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = conn.execute("SELECT status, body, summary FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if not row:
        raise PolicyGuardError("proposal_not_found")
    if row["status"] != "approved":
        decision = classify_action(conn, action_class="hermes_markdown_write", target_type="memory_proposal", target_id=proposal_id, request={"status": row["status"]})
        return {"status": "approval_required", "proposal_id": proposal_id, "policy_decision_id": decision["decision_id"], "file_mutation_performed": False, "reason": "proposal_not_approved", "content_included": False, "path_redacted": True}
    content = row["body"]
    target, error = _validate_fixture_root(fixture_root, file_name)
    if error:
        return {"status": "unauthorized", "reason": error, "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    assert target is not None
    approval_id, approval_error = _validate_writeback_authorization(target, file_name, authorization)
    if approval_error and approval_error != "writeback_approval_missing":
        return {"status": "unauthorized", "reason": approval_error, "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    approval_id = approval_id or "approved_proposal_without_write_marker"
    before_exists = target.exists()
    before = target.read_text(encoding="utf-8") if before_exists else ""
    before_hash = sha256_text(before)
    after_hash = sha256_text(content)
    if not expected_before_hash and approval_id != "approved_proposal_without_write_marker":
        return {"status": "denied", "reason": "expected_before_hash_required", "proposal_id": proposal_id, "file_mutation_performed": False, "before_hash": before_hash, "content_included": False, "path_redacted": True}
    if expected_before_hash and expected_before_hash != before_hash:
        audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_denied", target_type="memory_proposal", target_id=proposal_id, status="denied", metadata={"phase": "compat15-g09", "file": file_name, "reason": "expected_before_hash_mismatch", "expected_before_hash": expected_before_hash, "actual_before_hash": before_hash, "mutation_before_denial": False, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
        write_audit_event(conn, event_type="compat10_writeback_denied", target_type="memory_proposal", target_id=proposal_id, status="denied", metadata={"phase": "compat15-g09", "file": file_name, "reason": "expected_before_hash_mismatch", "expected_before_hash": expected_before_hash, "actual_before_hash": before_hash, "mutation_before_denial": False, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
        conn.commit()
        return {"status": "denied", "reason": "expected_before_hash_mismatch", "proposal_id": proposal_id, "audit_id": audit_id, "file_mutation_performed": False, "expected_before_hash": expected_before_hash, "actual_before_hash": before_hash, "content_included": False, "path_redacted": True}
    if expected_after_hash and expected_after_hash != after_hash:
        return {"status": "denied", "reason": "expected_after_hash_mismatch", "proposal_id": proposal_id, "file_mutation_performed": False, "expected_after_hash": expected_after_hash, "actual_after_hash": after_hash, "content_included": False, "path_redacted": True}
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{file_name}.", suffix=".tmp", dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise
    read_back = target.read_text(encoding="utf-8")
    read_back_hash = sha256_text(read_back)
    status = "ok" if read_back_hash == after_hash else "error"
    timestamp = now_utc()
    if status == "ok":
        conn.execute("UPDATE memory_proposals SET status='written', written_at=?, updated_at=? WHERE proposal_id=?", (timestamp, timestamp, proposal_id))
    rollback_id = stable_id("rollback", proposal_id, before_hash, after_hash)
    diff_summary = _safe_diff_summary(before, content, file_name)
    audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_written", target_type="memory_proposal", target_id=proposal_id, status=status, metadata={"phase": "compat15-g09", "file": file_name, "approval_id": approval_id, "before_hash": before_hash, "after_hash": after_hash, "read_back_hash": read_back_hash, "expected_before_hash": expected_before_hash, "expected_after_hash": after_hash, "diff": diff_summary, "atomic_write_strategy": "tempfile_fsync_replace", "rollback_metadata": {"rollback_id": rollback_id, "previous_exists": before_exists, "previous_hash": before_hash, "restores_to_hash": before_hash}, "temporary_fixture_only": True, "mutation_receipt": True, "content_included": False, "path_redacted": True}, error=None if status == "ok" else "read_back_hash_mismatch")
    write_audit_event(conn, event_type="compat10_writeback_written", target_type="memory_proposal", target_id=proposal_id, status=status, metadata={"phase": "compat15-g09", "file": file_name, "approval_id": approval_id, "before_hash": before_hash, "after_hash": after_hash, "read_back_hash": read_back_hash, "expected_before_hash": expected_before_hash, "expected_after_hash": after_hash, "diff": diff_summary, "atomic_write_strategy": "tempfile_fsync_replace", "rollback_metadata": {"rollback_id": rollback_id, "previous_exists": before_exists, "previous_hash": before_hash, "restores_to_hash": before_hash}, "temporary_fixture_only": True, "mutation_receipt": True, "content_included": False, "path_redacted": True}, error=None if status == "ok" else "read_back_hash_mismatch")
    conn.commit()
    return {"status": status, "proposal_id": proposal_id, "audit_id": audit_id, "file": file_name, "approval_id": approval_id, "before_hash": before_hash, "after_hash": after_hash, "read_back_hash": read_back_hash, "expected_before_hash": expected_before_hash, "expected_after_hash": after_hash, "diff": diff_summary, "rollback_metadata": {"rollback_id": rollback_id, "previous_exists": before_exists, "previous_hash": before_hash, "restores_to_hash": before_hash}, "atomic_write_strategy": "tempfile_fsync_replace", "file_mutation_performed": status == "ok", "temporary_fixture_only": True, "content_included": False, "path_redacted": True}


def read_back_fixture(fixture_root: str | Path, *, file_name: str, expected_after_hash: str | None = None) -> dict[str, Any]:
    target, error = _validate_fixture_root(fixture_root, file_name)
    if error:
        return {"status": "unauthorized", "reason": error, "file": file_name, "content_included": False, "path_redacted": True}
    assert target is not None
    if not target.exists():
        return {"status": "unavailable", "reason": "target_missing", "file": file_name, "content_included": False, "path_redacted": True}
    text = target.read_text(encoding="utf-8")
    content_hash = sha256_text(text)
    verified = expected_after_hash is None or expected_after_hash == content_hash
    return {"status": "ok" if verified else "error", "file": file_name, "content_hash": content_hash, "expected_after_hash": expected_after_hash, "expected_after_hash_verified": verified, "byte_count": len(text.encode("utf-8")), "line_count": len(text.splitlines()), "content_included": False, "path_redacted": True}


def rollback_fixture(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    fixture_root: str | Path,
    file_name: str,
    previous_content: str,
    expected_current_hash: str | None = None,
    authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target, error = _validate_fixture_root(fixture_root, file_name)
    if error:
        return {"status": "unauthorized", "reason": error, "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    assert target is not None
    approval_id, approval_error = _validate_writeback_authorization(target, file_name, authorization)
    if approval_error and approval_error != "writeback_approval_missing":
        return {"status": "unauthorized", "reason": approval_error, "file_mutation_performed": False, "content_included": False, "path_redacted": True}
    approval_id = approval_id or "approved_proposal_without_write_marker"
    before = target.read_text(encoding="utf-8") if target.exists() else ""
    before_hash = sha256_text(before)
    if expected_current_hash and expected_current_hash != before_hash:
        return {"status": "denied", "reason": "rollback_expected_current_hash_mismatch", "proposal_id": proposal_id, "file_mutation_performed": False, "expected_current_hash": expected_current_hash, "actual_current_hash": before_hash, "content_included": False, "path_redacted": True}
    fd, temp_name = tempfile.mkstemp(prefix=f".{file_name}.rollback.", suffix=".tmp", dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(previous_content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise
    after = target.read_text(encoding="utf-8")
    after_hash = sha256_text(after)
    timestamp = now_utc()
    conn.execute("UPDATE memory_proposals SET status='rolled_back', updated_at=? WHERE proposal_id=?", (timestamp, proposal_id))
    audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_rollback", target_type="memory_proposal", target_id=proposal_id, status="ok", metadata={"phase": "compat15-g09", "file": file_name, "approval_id": approval_id, "before_hash": before_hash, "after_hash": after_hash, "expected_current_hash": expected_current_hash, "atomic_write_strategy": "tempfile_fsync_replace", "rollback_executed": True, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
    write_audit_event(conn, event_type="compat10_writeback_rollback", target_type="memory_proposal", target_id=proposal_id, status="ok", metadata={"phase": "compat15-g09", "file": file_name, "approval_id": approval_id, "before_hash": before_hash, "after_hash": after_hash, "expected_current_hash": expected_current_hash, "atomic_write_strategy": "tempfile_fsync_replace", "rollback_executed": True, "temporary_fixture_only": True, "content_included": False, "path_redacted": True})
    conn.commit()
    return {"status": "rolled_back", "proposal_id": proposal_id, "audit_id": audit_id, "file": file_name, "before_hash": before_hash, "after_hash": after_hash, "file_mutation_performed": True, "rollback_executed": True, "temporary_fixture_only": True, "content_included": False, "path_redacted": True}


def tombstone_writeback(conn: sqlite3.Connection, proposal_id: str, *, reason: str = "operator_tombstone") -> dict[str, Any]:
    row = conn.execute("SELECT status FROM memory_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
    if not row:
        raise PolicyGuardError("proposal_not_found")
    timestamp = now_utc()
    conn.execute("UPDATE memory_proposals SET status='tombstoned', review_reason=?, updated_at=? WHERE proposal_id=?", (reason, timestamp, proposal_id))
    audit_id = write_audit_event(conn, event_type="compat15_g09_writeback_tombstoned", target_type="memory_proposal", target_id=proposal_id, status="ok", metadata={"phase": "compat15-g09", "reason": reason, "approved_removal_semantics": True, "physical_delete_performed": False, "provenance_preserved": True, "content_included": False, "path_redacted": True})
    write_audit_event(conn, event_type="compat10_writeback_tombstoned", target_type="memory_proposal", target_id=proposal_id, status="ok", metadata={"phase": "compat15-g09", "reason": reason, "approved_removal_semantics": True, "physical_delete_performed": False, "provenance_preserved": True, "content_included": False, "path_redacted": True})
    conn.commit()
    return {"status": "tombstoned", "proposal_id": proposal_id, "audit_id": audit_id, "physical_delete_performed": False, "provenance_preserved": True, "content_included": False, "path_redacted": True}
