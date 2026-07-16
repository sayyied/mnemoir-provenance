"""compat 15.0.1 learning event and outcome ledger.

This module records source-linked, privacy-safe learning outcomes only. It does
not generate candidate algorithms, run experiments, promote scoring changes, or
rewrite behavior. The ledger is evidence for later gated lanes.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

LEARNING_LEDGER_ACTOR_ID = "actor_operator_compat15_0_1"

_ALLOWED_EVENT_TYPES = {
    "recall.outcome",
    "context_pack.outcome",
    "proposal_review.outcome",
    "memory_correction.outcome",
    "contradiction.outcome",
    "stale_memory.outcome",
    "scoring_feedback.outcome",
    "writeback_policy.outcome",
    "benchmark_regression.outcome",
    "operator_label.outcome",
}

_ALLOWED_OUTCOME_LABELS = {
    "positive_recall",
    "retrieval_miss",
    "wrong_source_selected",
    "stale_ranked_high",
    "contradiction_not_suppressed",
    "contradiction_correctly_suppressed",
    "useful_memory_reinforced",
    "useful_memory_cooled_too_fast",
    "noisy_signal_consolidated_too_early",
    "context_dropped_needed_citation",
    "context_budget_success",
    "over_trimmed_useful_memory",
    "profile_scope_too_strict",
    "profile_scope_too_loose",
    "proposal_true_positive",
    "proposal_false_positive",
    "unsupported_hot_suppressed",
    "unsupported_hot_leaked",
    "policy_correctly_blocked",
    "policy_false_block",
    "benchmark_regression",
}

_ALLOWED_FAILURE_CLASSES = {
    "retrieval_miss",
    "wrong_source_selected",
    "stale_ranked_high",
    "contradiction_not_suppressed",
    "useful_memory_cooled_too_fast",
    "noisy_signal_consolidated_too_early",
    "context_dropped_needed_citation",
    "over_trimmed_useful_memory",
    "profile_scope_too_strict",
    "profile_scope_too_loose",
    "proposal_false_positive",
    "unsupported_hot_leaked",
    "policy_false_block",
    "benchmark_regression",
}

_ALLOWED_SEVERITIES = {"info", "watch", "warning", "critical"}
_SEVERITY_RANK = {"info": 0, "watch": 1, "warning": 2, "critical": 3}
_SECRET_OR_PRIVATE_MARKERS = re.compile(
    r"(api[_-]?key|token|secret|password|credential|auth\.json|sk-[A-Za-z0-9]|"
    r"MEMORY\.md|USER\.md|\.hermes/profiles|-----BEGIN|provider|gateway|cron|systemd|autostart|candidate|promotion)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(^|\s)/(home|Users|var|etc|root|tmp|mnt|opt)/[^\s]+")


class LearningError(ValueError):
    """Domain error that should be reported as fail-closed CLI JSON."""


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


def _safe_string(value: str) -> str | dict[str, Any]:
    if _SECRET_OR_PRIVATE_MARKERS.search(value) or _ABSOLUTE_PATH.search(value) or len(value) > 96:
        return {"redacted": True, "sha256": sha256_text(value), "chars": len(value)}
    return value


def _sanitize_metadata(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    if isinstance(value, list):
        return [_sanitize_metadata(item) for item in value]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = str(key)
            if _SECRET_OR_PRIVATE_MARKERS.search(safe_key) or _ABSOLUTE_PATH.search(safe_key):
                safe_key = f"redacted_key_{sha256_text(safe_key)[:12]}"
            sanitized[safe_key] = _sanitize_metadata(item)
        return sanitized
    return _safe_string(str(value))


def _safe_id_list(values: list[str] | tuple[str, ...] | None) -> list[str]:
    if not values:
        return []
    safe: list[str] = []
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        safe.append(text if not (_SECRET_OR_PRIVATE_MARKERS.search(text) or _ABSOLUTE_PATH.search(text)) else f"hash:{sha256_text(text)}")
    return safe


def _validate_event(event_type: str, outcome_label: str, failure_class: str | None, severity: str) -> None:
    if event_type not in _ALLOWED_EVENT_TYPES:
        raise LearningError("invalid_learning_event_type")
    if outcome_label not in _ALLOWED_OUTCOME_LABELS:
        raise LearningError("invalid_learning_outcome_label")
    if failure_class is not None and failure_class not in _ALLOWED_FAILURE_CLASSES:
        raise LearningError("invalid_learning_failure_class")
    if severity not in _ALLOWED_SEVERITIES:
        raise LearningError("invalid_learning_severity")


def ensure_compat15_0_1_runtime(conn: sqlite3.Connection) -> None:
    """Install the local learning-ledger actor row without external side effects."""
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, created_at, updated_at)
        VALUES (?, 'system', 'Mnemoir Provenance compat 15.0.1 Learning Ledger Operator', 'mnemoir-compat15-0-1', 'compat15-0-1', ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (LEARNING_LEDGER_ACTOR_ID, timestamp, timestamp),
    )


def _event_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["evidence_ids"] = _json_loads(item.pop("evidence_ids_json"), [])
    item["related_ids"] = _json_loads(item.pop("related_ids_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["privacy_boundary"] = {
        "raw_input_stored": False,
        "raw_output_stored": False,
        "hash_only_payloads": True,
        "observation_only": True,
    }
    return item


def record_learning_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    outcome_label: str,
    failure_class: str | None = None,
    severity: str = "info",
    profile_id: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    query_id: str | None = None,
    memory_id: str | None = None,
    proposal_id: str | None = None,
    source_id: str | None = None,
    raw_event_id: str | None = None,
    evidence_ids: list[str] | tuple[str, ...] | None = None,
    related_ids: dict[str, Any] | None = None,
    input_text: str | None = None,
    output_text: str | None = None,
    metadata: dict[str, Any] | None = None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Persist one privacy-safe learning event and refresh deterministic clusters."""
    _validate_event(event_type, outcome_label, failure_class, severity)
    ensure_compat15_0_1_runtime(conn)
    timestamp = occurred_at or now_utc()
    safe_evidence_ids = _safe_id_list(evidence_ids)
    safe_related_ids = _sanitize_metadata(related_ids or {})
    safe_metadata = _sanitize_metadata(metadata or {})
    input_hash = sha256_text(input_text) if input_text is not None else None
    output_hash = sha256_text(output_text) if output_text is not None else None
    learning_event_id = stable_id(
        "learn",
        event_type,
        outcome_label,
        failure_class or "",
        severity,
        profile_id or "",
        actor_id or "",
        session_id or "",
        query_id or "",
        memory_id or "",
        proposal_id or "",
        source_id or "",
        raw_event_id or "",
        json_dumps(safe_evidence_ids),
        json_dumps(safe_related_ids),
        input_hash or "",
        output_hash or "",
        timestamp,
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO learning_events(
          learning_event_id, event_type, outcome_label, failure_class, severity,
          profile_id, actor_id, session_id, query_id, memory_id, proposal_id,
          source_id, raw_event_id, evidence_ids_json, related_ids_json,
          input_hash, output_hash, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            learning_event_id,
            event_type,
            outcome_label,
            failure_class,
            severity,
            profile_id,
            actor_id,
            session_id,
            query_id,
            memory_id,
            proposal_id,
            source_id,
            raw_event_id,
            json_dumps(safe_evidence_ids),
            json_dumps(safe_related_ids),
            input_hash,
            output_hash,
            json_dumps(safe_metadata),
            timestamp,
        ),
    )
    _refresh_failure_clusters(conn)
    conn.commit()
    return {"status": "ok", "learning_event": learning_event(conn, learning_event_id)}


def learning_event(conn: sqlite3.Connection, learning_event_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM learning_events WHERE learning_event_id = ?", (learning_event_id,)).fetchone()
    if row is None:
        raise LearningError("learning_event_not_found")
    return _event_payload(row)


def list_learning_events(
    conn: sqlite3.Connection,
    *,
    event_type: str | None = None,
    outcome_label: str | None = None,
    failure_class: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if outcome_label:
        clauses.append("outcome_label = ?")
        params.append(outcome_label)
    if failure_class:
        clauses.append("failure_class = ?")
        params.append(failure_class)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM learning_events{where} ORDER BY created_at DESC, learning_event_id DESC LIMIT ?",
        (*params, max(1, min(int(limit), 500))),
    ).fetchall()
    return [_event_payload(row) for row in rows]


def _cluster_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["sample_event_ids"] = _json_loads(item.pop("sample_event_ids_json"), [])
    item["source_coverage"] = _json_loads(item.pop("source_coverage_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["observation_only"] = True
    return item


def _refresh_failure_clusters(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT failure_class, event_type, COALESCE(profile_id, '') AS profile_scope,
               COALESCE(session_id, '') AS session_scope, COUNT(*) AS event_count,
               MIN(created_at) AS first_seen_at, MAX(created_at) AS last_seen_at
        FROM learning_events
        WHERE failure_class IS NOT NULL
        GROUP BY failure_class, event_type, COALESCE(profile_id, ''), COALESCE(session_id, '')
        ORDER BY failure_class, event_type, profile_scope, session_scope
        """
    ).fetchall()
    touched: set[str] = set()
    timestamp = now_utc()
    for row in rows:
        failure_class = row["failure_class"]
        event_type = row["event_type"]
        profile_scope = row["profile_scope"] or None
        session_scope = row["session_scope"] or None
        cluster_id = stable_id("learncluster", failure_class, event_type, profile_scope or "", session_scope or "")
        event_rows = conn.execute(
            """
            SELECT learning_event_id, severity, source_id
            FROM learning_events
            WHERE failure_class = ? AND event_type = ?
              AND COALESCE(profile_id, '') = ? AND COALESCE(session_id, '') = ?
            ORDER BY created_at DESC, learning_event_id DESC
            """,
            (failure_class, event_type, row["profile_scope"], row["session_scope"]),
        ).fetchall()
        severity_max = max((event["severity"] for event in event_rows), key=lambda value: _SEVERITY_RANK[value])
        source_coverage: dict[str, int] = {}
        for event in event_rows:
            key = event["source_id"] or "unlinked"
            source_coverage[key] = source_coverage.get(key, 0) + 1
        sample_ids = [event["learning_event_id"] for event in event_rows[:5]]
        metadata = {
            "group_by": ["failure_class", "event_type", "profile_id", "session_id"],
            "event_type": event_type,
            "profile_scope": profile_scope,
            "session_scope": session_scope,
            "phase": "15.0.1",
            "observation_only": True,
        }
        existing = conn.execute("SELECT status FROM learning_failure_clusters WHERE cluster_id = ?", (cluster_id,)).fetchone()
        status = existing["status"] if existing else ("watch" if _SEVERITY_RANK[severity_max] >= _SEVERITY_RANK["warning"] else "open")
        conn.execute(
            """
            INSERT INTO learning_failure_clusters(
              cluster_id, failure_class, event_count, severity_max, first_seen_at, last_seen_at,
              sample_event_ids_json, source_coverage_json, status, metadata_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
              event_count=excluded.event_count,
              severity_max=excluded.severity_max,
              first_seen_at=excluded.first_seen_at,
              last_seen_at=excluded.last_seen_at,
              sample_event_ids_json=excluded.sample_event_ids_json,
              source_coverage_json=excluded.source_coverage_json,
              metadata_json=excluded.metadata_json,
              updated_at=excluded.updated_at
            """,
            (
                cluster_id,
                failure_class,
                int(row["event_count"]),
                severity_max,
                row["first_seen_at"],
                row["last_seen_at"],
                json_dumps(sample_ids),
                json_dumps(source_coverage),
                status,
                json_dumps(metadata),
                timestamp,
            ),
        )
        touched.add(cluster_id)
    # Mark clusters with no current events resolved, preserving auditability.
    existing_ids = [r["cluster_id"] for r in conn.execute("SELECT cluster_id FROM learning_failure_clusters").fetchall()]
    for cluster_id in existing_ids:
        if cluster_id not in touched:
            conn.execute("UPDATE learning_failure_clusters SET status = 'resolved', updated_at = ? WHERE cluster_id = ?", (timestamp, cluster_id))


def learning_failure_clusters(conn: sqlite3.Connection, *, limit: int = 50) -> list[dict[str, Any]]:
    _refresh_failure_clusters(conn)
    rows = conn.execute(
        """
        SELECT * FROM learning_failure_clusters
        ORDER BY event_count DESC,
                 CASE severity_max WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 WHEN 'watch' THEN 1 ELSE 0 END DESC,
                 last_seen_at DESC,
                 cluster_id DESC
        LIMIT ?
        """,
        (max(1, min(int(limit), 500)),),
    ).fetchall()
    return [_cluster_payload(row) for row in rows]


def allowed_learning_event_types() -> list[str]:
    return sorted(_ALLOWED_EVENT_TYPES)


def allowed_learning_outcome_labels() -> list[str]:
    return sorted(_ALLOWED_OUTCOME_LABELS)


def allowed_learning_failure_classes() -> list[str]:
    return sorted(_ALLOWED_FAILURE_CLASSES)
