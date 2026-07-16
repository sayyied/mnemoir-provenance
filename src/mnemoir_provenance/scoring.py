"""Deterministic adaptive memory scoring for Mnemoir Provenance compat 03.

Heat is not truth: this module uses thermal/energy signals only to drive
attention, review, consolidation, suppression, and retention pressure. Authority
remains provenance/citation/policy/correction-bound.
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, stable_id

SCORE_ACTOR_ID = "actor_operator_compat03"
_ALLOWED_SCENARIOS = {
    "duplicate_fact",
    "correction",
    "contradiction",
    "repeated_preference",
    "stale_project_state",
    "retrieval_success",
    "unsupported_hot_signal",
    "weak_signal",
    "decay",
}
_REVIEW_STATUSES = {"stale", "contradicted", "quarantined", "superseded", "corrected"}
_SCORE_FIELDS = (
    "confidence",
    "salience",
    "novelty",
    "contradiction_score",
    "stability",
    "drift_score",
    "retention_strength",
    "retrieval_success_rate",
)


class ScoringError(ValueError):
    """Domain error that should be reported as fail-closed CLI JSON."""


@dataclass(frozen=True)
class ScoreState:
    confidence: float
    salience: float
    novelty: float
    contradiction_score: float
    stability: float
    drift_score: float
    retention_strength: float
    retrieval_success_rate: float
    recall_count: int
    status: str
    last_recalled_at: str | None
    updated_at: str


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 6)))


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _days_between(start: str | None, end: str) -> float:
    if not start:
        return 0.0
    delta = _parse_timestamp(end) - _parse_timestamp(start)
    return max(0.0, delta.total_seconds() / 86400.0)


def _load_memory(conn: sqlite3.Connection, memory_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None:
        raise ScoringError("memory_not_found")
    return row


def ensure_compat03_runtime(conn: sqlite3.Connection) -> None:
    """Install compat 03 seed actor rows without touching external profiles."""
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, created_at, updated_at)
        VALUES (?, 'system', 'Mnemoir Provenance compat 03 Scoring Operator', 'mnemoir-compat03', 'compat03', ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (SCORE_ACTOR_ID, timestamp, timestamp),
    )


def _state_from_row(row: sqlite3.Row) -> ScoreState:
    return ScoreState(
        confidence=float(row["confidence"]),
        salience=float(row["salience"]),
        novelty=float(row["novelty"]),
        contradiction_score=float(row["contradiction_score"]),
        stability=float(row["stability"]),
        drift_score=float(row["drift_score"]),
        retention_strength=float(row["retention_strength"]),
        retrieval_success_rate=float(row["retrieval_success_rate"]),
        recall_count=int(row["recall_count"]),
        status=str(row["status"]),
        last_recalled_at=row["last_recalled_at"],
        updated_at=str(row["updated_at"]),
    )


def _state_dict(state: ScoreState) -> dict[str, Any]:
    return {
        "confidence": state.confidence,
        "salience": state.salience,
        "novelty": state.novelty,
        "contradiction_score": state.contradiction_score,
        "stability": state.stability,
        "drift_score": state.drift_score,
        "retention_strength": state.retention_strength,
        "retrieval_success_rate": state.retrieval_success_rate,
        "recall_count": state.recall_count,
        "status": state.status,
        "last_recalled_at": state.last_recalled_at,
        "updated_at": state.updated_at,
    }


def _energy(state: ScoreState, cluster_mass: float = 0.0) -> float:
    value = (
        state.salience * 0.22
        + state.contradiction_score * 0.26
        + state.drift_score * 0.18
        + (1.0 - state.novelty) * 0.08
        + state.retention_strength * 0.12
        + state.retrieval_success_rate * 0.08
        + cluster_mass * 0.06
    )
    return _clamp(value)


def _clean_recall_eligible(state: ScoreState, evidence_count: int) -> bool:
    if state.status in _REVIEW_STATUSES or evidence_count <= 0:
        return False
    if state.confidence < 0.5 or state.contradiction_score >= 0.55 or state.drift_score >= 0.7:
        return False
    return True


def _review_reasons(state: ScoreState, evidence_count: int, cluster_mass: float) -> list[str]:
    reasons: list[str] = []
    if evidence_count <= 0:
        reasons.append("missing_citation_support")
    if state.status in _REVIEW_STATUSES:
        reasons.append(f"status_{state.status}")
    if state.contradiction_score >= 0.55:
        reasons.append("high_contradiction")
    if state.drift_score >= 0.55:
        reasons.append("stale_or_drift_heavy")
    if state.salience >= 0.75 and state.confidence < 0.5:
        reasons.append("unsupported_hot_signal")
    if cluster_mass >= 0.65 and state.confidence >= 0.5 and state.contradiction_score < 0.4:
        reasons.append("consolidation_ready")
    if not reasons:
        energy = _energy(state, cluster_mass)
        if energy >= 0.55:
            reasons.append("review_pressure")
    return reasons


def _version_count(conn: sqlite3.Connection, memory_id: str) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM memory_versions WHERE memory_id = ?", (memory_id,)).fetchone()[0])


def _evidence_count(conn: sqlite3.Connection, memory_id: str) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM memory_evidence WHERE memory_id = ?", (memory_id,)).fetchone()[0])


def _cluster_mass(conn: sqlite3.Connection, memory_id: str) -> float:
    row = conn.execute("SELECT cluster_id FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None or not row["cluster_id"]:
        return 0.0
    cluster = conn.execute("SELECT metadata_json FROM memory_clusters WHERE cluster_id = ?", (row["cluster_id"],)).fetchone()
    if cluster is None:
        return 0.0
    metadata = json.loads(cluster["metadata_json"] or "{}")
    return _clamp(float(metadata.get("thermal_cluster_mass", 0.0)))


def _bump_cluster_mass(conn: sqlite3.Connection, memory_id: str, delta: float, timestamp: str) -> float:
    row = conn.execute("SELECT cluster_id, scope, owner_actor_id, project_id FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
    if row is None:
        raise ScoringError("memory_not_found")
    cluster_id = row["cluster_id"]
    if not cluster_id:
        cluster_id = stable_id("cluster", memory_id)
        conn.execute(
            """
            INSERT INTO memory_clusters(cluster_id, scope, owner_actor_id, project_id, title, status, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                cluster_id,
                row["scope"],
                row["owner_actor_id"],
                row["project_id"],
                f"Thermal cluster for {memory_id}",
                json_dumps({"thermal_cluster_mass": 0.0, "signal_count": 0}),
                timestamp,
                timestamp,
            ),
        )
        conn.execute("UPDATE memories SET cluster_id = ?, updated_at = ? WHERE memory_id = ?", (cluster_id, timestamp, memory_id))
    cluster = conn.execute("SELECT metadata_json FROM memory_clusters WHERE cluster_id = ?", (cluster_id,)).fetchone()
    metadata = json.loads(cluster["metadata_json"] or "{}")
    mass = _clamp(float(metadata.get("thermal_cluster_mass", 0.0)) + delta)
    metadata["thermal_cluster_mass"] = mass
    metadata["signal_count"] = int(metadata.get("signal_count", 0)) + 1
    metadata["last_signal_at"] = timestamp
    conn.execute(
        "UPDATE memory_clusters SET metadata_json = ?, updated_at = ? WHERE cluster_id = ?",
        (json_dumps(metadata), timestamp, cluster_id),
    )
    return mass


def _score_summary(conn: sqlite3.Connection, memory_id: str, state: ScoreState | None = None) -> dict[str, Any]:
    if state is None:
        state = _state_from_row(_load_memory(conn, memory_id))
    evidence_count = _evidence_count(conn, memory_id)
    cluster_mass = _cluster_mass(conn, memory_id)
    reasons = _review_reasons(state, evidence_count, cluster_mass)
    return {
        "memory_id": memory_id,
        **{field: getattr(state, field) for field in _SCORE_FIELDS},
        "recall_count": state.recall_count,
        "last_recalled_at": state.last_recalled_at,
        "status": state.status,
        "thermal_cluster_mass": cluster_mass,
        "memory_energy": _energy(state, cluster_mass),
        "review_pressure": _clamp(_energy(state, cluster_mass) if reasons else 0.0),
        "review_reasons": reasons,
        "clean_recall_eligible": _clean_recall_eligible(state, evidence_count),
        "truth_authority": "provenance_policy_correction_bound",
        "heat_is_truth_authority": False,
        "evidence_count": evidence_count,
        "version_count": _version_count(conn, memory_id),
    }


def score_summary(conn: sqlite3.Connection, memory_id: str) -> dict[str, Any]:
    """Return the current score summary for a memory."""
    _load_memory(conn, memory_id)
    return _score_summary(conn, memory_id)


def apply_scoring_scenario(
    conn: sqlite3.Connection,
    *,
    memory_id: str,
    scenario: str,
    occurred_at: str | None = None,
    actor_id: str = SCORE_ACTOR_ID,
    related_memory_id: str | None = None,
    evidence_id: str | None = None,
    weight: float = 1.0,
) -> dict[str, Any]:
    """Apply one deterministic scoring scenario and persist audit/history receipts."""
    if scenario not in _ALLOWED_SCENARIOS:
        raise ScoringError("invalid_scoring_scenario")
    if not 0.0 <= weight <= 5.0:
        raise ScoringError("invalid_scoring_weight")
    ensure_compat03_runtime(conn)
    timestamp = occurred_at or now_utc()
    row = _load_memory(conn, memory_id)
    before = _state_from_row(row)
    after = _state_from_row(row)
    cluster_delta = 0.0
    lifecycle_status: str | None = None
    lifecycle_reason: str | None = None
    correction_id: str | None = None

    if related_memory_id:
        _load_memory(conn, related_memory_id)

    if scenario == "duplicate_fact":
        after = ScoreState(
            confidence=_clamp(before.confidence + 0.03 * weight),
            salience=_clamp(before.salience + 0.05 * weight),
            novelty=_clamp(before.novelty - 0.35 * weight),
            contradiction_score=before.contradiction_score,
            stability=_clamp(before.stability + 0.08 * weight),
            drift_score=before.drift_score,
            retention_strength=_clamp(before.retention_strength + 0.08 * weight),
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status=before.status,
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        cluster_delta = 0.24 * weight
        if related_memory_id:
            conn.execute(
                """
                INSERT OR IGNORE INTO memory_relationships(from_memory_id, to_memory_id, relationship_type, confidence, created_at)
                VALUES (?, ?, 'duplicates', ?, ?)
                """,
                (memory_id, related_memory_id, 0.9, timestamp),
            )
        lifecycle_reason = "duplicate_fact_consolidation_pressure"
    elif scenario == "correction":
        after = ScoreState(
            confidence=_clamp(before.confidence - 0.2 * weight),
            salience=_clamp(before.salience + 0.38 * weight),
            novelty=before.novelty,
            contradiction_score=_clamp(before.contradiction_score + 0.55 * weight),
            stability=_clamp(before.stability - 0.2 * weight),
            drift_score=_clamp(before.drift_score + 0.35 * weight),
            retention_strength=before.retention_strength,
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status="contradicted",
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        lifecycle_status = "contradicted"
        lifecycle_reason = "explicit_correction_review_supersession"
        correction_id = stable_id("correction", memory_id, scenario, timestamp)
        conn.execute(
            """
            INSERT INTO memory_corrections(correction_id, memory_id, from_version, correction_type, status, rationale, proposed_by_actor_id, evidence_id, created_at)
            VALUES (?, ?, ?, 'contradiction', 'proposed', ?, ?, ?, ?)
            """,
            (correction_id, memory_id, row["current_version"], lifecycle_reason, actor_id, evidence_id, timestamp),
        )
    elif scenario == "contradiction":
        after = ScoreState(
            confidence=_clamp(before.confidence - 0.12 * weight),
            salience=_clamp(before.salience + 0.26 * weight),
            novelty=before.novelty,
            contradiction_score=_clamp(before.contradiction_score + 0.45 * weight),
            stability=_clamp(before.stability - 0.12 * weight),
            drift_score=_clamp(before.drift_score + 0.25 * weight),
            retention_strength=before.retention_strength,
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status="contradicted",
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        lifecycle_status = "contradicted"
        lifecycle_reason = "contradiction_review_required"
        if related_memory_id:
            conn.execute(
                """
                INSERT OR IGNORE INTO memory_relationships(from_memory_id, to_memory_id, relationship_type, confidence, created_at)
                VALUES (?, ?, 'contradicts', ?, ?)
                """,
                (memory_id, related_memory_id, 0.85, timestamp),
            )
    elif scenario == "repeated_preference":
        after = ScoreState(
            confidence=_clamp(before.confidence + 0.1 * weight),
            salience=_clamp(before.salience + 0.12 * weight),
            novelty=_clamp(before.novelty - 0.08 * weight),
            contradiction_score=_clamp(before.contradiction_score - 0.08 * weight),
            stability=_clamp(before.stability + 0.22 * weight),
            drift_score=_clamp(before.drift_score - 0.1 * weight),
            retention_strength=_clamp(before.retention_strength + 0.26 * weight),
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status="active" if before.status == "stale" else before.status,
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        cluster_delta = 0.18 * weight
        lifecycle_reason = "repeated_confirmed_preference_retention_pressure"
    elif scenario == "stale_project_state":
        after = ScoreState(
            confidence=_clamp(before.confidence - 0.25 * weight),
            salience=_clamp(before.salience + 0.14 * weight),
            novelty=before.novelty,
            contradiction_score=_clamp(before.contradiction_score + 0.12 * weight),
            stability=_clamp(before.stability - 0.18 * weight),
            drift_score=_clamp(before.drift_score + 0.6 * weight),
            retention_strength=_clamp(before.retention_strength - 0.18 * weight),
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status="stale",
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        lifecycle_status = "stale"
        lifecycle_reason = "stale_project_state_suppression"
    elif scenario == "retrieval_success":
        total = before.recall_count + 1
        updated_success = ((before.retrieval_success_rate * before.recall_count) + 1.0) / total
        after = ScoreState(
            confidence=before.confidence,
            salience=_clamp(before.salience + 0.08 * weight),
            novelty=before.novelty,
            contradiction_score=before.contradiction_score,
            stability=_clamp(before.stability + 0.05 * weight),
            drift_score=before.drift_score,
            retention_strength=_clamp(before.retention_strength + 0.12 * weight),
            retrieval_success_rate=_clamp(updated_success),
            recall_count=total,
            status=before.status,
            last_recalled_at=timestamp,
            updated_at=timestamp,
        )
        lifecycle_reason = "retrieval_feedback_retention_pressure"
        feedback_id = stable_id("feedback", memory_id, timestamp, weight)
        conn.execute(
            """
            INSERT INTO retrieval_feedback(feedback_id, target_type, target_id, actor_id, rating, feedback_text, created_at)
            VALUES (?, 'memory', ?, ?, 2, 'useful', ?)
            """,
            (feedback_id, memory_id, actor_id, timestamp),
        )
    elif scenario == "unsupported_hot_signal":
        after = ScoreState(
            confidence=_clamp(before.confidence - 0.28 * weight),
            salience=_clamp(before.salience + 0.7 * weight),
            novelty=before.novelty,
            contradiction_score=_clamp(before.contradiction_score + 0.25 * weight),
            stability=_clamp(before.stability - 0.12 * weight),
            drift_score=_clamp(before.drift_score + 0.2 * weight),
            retention_strength=before.retention_strength,
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status="quarantined",
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        lifecycle_status = "quarantined"
        lifecycle_reason = "unsupported_hot_signal_review_suppression"
    elif scenario == "weak_signal":
        after = ScoreState(
            confidence=_clamp(before.confidence + 0.02 * weight),
            salience=_clamp(before.salience + 0.08 * weight),
            novelty=_clamp(before.novelty - 0.03 * weight),
            contradiction_score=before.contradiction_score,
            stability=_clamp(before.stability + 0.03 * weight),
            drift_score=before.drift_score,
            retention_strength=_clamp(before.retention_strength + 0.05 * weight),
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status=before.status,
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        cluster_delta = 0.22 * weight
        lifecycle_reason = "weak_signal_cluster_mass_accumulation"
    elif scenario == "decay":
        elapsed_days = _days_between(before.updated_at, timestamp)
        decay = 1.0 - math.exp(-elapsed_days / 30.0) if elapsed_days else 0.0
        after = ScoreState(
            confidence=before.confidence,
            salience=_clamp(before.salience * (1.0 - 0.4 * decay)),
            novelty=before.novelty,
            contradiction_score=_clamp(before.contradiction_score * (1.0 - 0.15 * decay)),
            stability=before.stability,
            drift_score=_clamp(before.drift_score + 0.2 * decay),
            retention_strength=_clamp(before.retention_strength * (1.0 - 0.3 * decay)),
            retrieval_success_rate=before.retrieval_success_rate,
            recall_count=before.recall_count,
            status=before.status,
            last_recalled_at=before.last_recalled_at,
            updated_at=timestamp,
        )
        lifecycle_reason = "deterministic_cooling_decay"

    cluster_mass = _bump_cluster_mass(conn, memory_id, cluster_delta, timestamp) if cluster_delta else _cluster_mass(conn, memory_id)
    conn.execute(
        """
        UPDATE memories
        SET confidence = ?, salience = ?, novelty = ?, contradiction_score = ?, stability = ?,
            drift_score = ?, retention_strength = ?, retrieval_success_rate = ?, status = ?,
            last_recalled_at = ?, recall_count = ?, updated_at = ?
        WHERE memory_id = ?
        """,
        (
            after.confidence,
            after.salience,
            after.novelty,
            after.contradiction_score,
            after.stability,
            after.drift_score,
            after.retention_strength,
            after.retrieval_success_rate,
            after.status,
            after.last_recalled_at,
            after.recall_count,
            after.updated_at,
            memory_id,
        ),
    )
    audit_id = write_audit_event(
        conn,
        event_type="memory_score.update",
        target_type="memory",
        target_id=memory_id,
        status="ok",
        actor_id=actor_id,
        metadata={
            "scenario": scenario,
            "before": _state_dict(before),
            "after": _state_dict(after),
            "cluster_mass": cluster_mass,
            "cluster_delta": _clamp(cluster_delta),
            "related_memory_id": related_memory_id,
            "evidence_id": evidence_id,
            "correction_id": correction_id,
            "rule_version": "compat03_deterministic_v1",
            "heat_is_truth_authority": False,
            "truth_authority": "citations_provenance_correction_policy",
        },
    )
    if lifecycle_status:
        conn.execute(
            """
            INSERT INTO memory_lifecycle_events(lifecycle_id, memory_id, from_status, to_status, reason, actor_id, audit_id, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_id("lifecycle", memory_id, scenario, timestamp),
                memory_id,
                before.status,
                lifecycle_status,
                lifecycle_reason,
                actor_id,
                audit_id,
                timestamp,
            ),
        )
    conn.commit()
    summary = _score_summary(conn, memory_id)
    return {
        "status": "ok",
        "memory_id": memory_id,
        "scenario": scenario,
        "audit_id": audit_id,
        "score_summary": summary,
        "score_delta": {
            field: round(float(getattr(after, field)) - float(getattr(before, field)), 6)
            for field in _SCORE_FIELDS
        },
    }


def score_history(conn: sqlite3.Connection, memory_id: str, limit: int = 20) -> list[dict[str, Any]]:
    _load_memory(conn, memory_id)
    rows = conn.execute(
        """
        SELECT audit_id, occurred_at, event_type, status, metadata_json
        FROM audit_events
        WHERE event_type = 'memory_score.update' AND target_type = 'memory' AND target_id = ?
        ORDER BY occurred_at DESC, audit_id DESC
        LIMIT ?
        """,
        (memory_id, limit),
    ).fetchall()
    history: list[dict[str, Any]] = []
    for row in rows:
        item = row_to_dict(row)
        metadata = json.loads(item.pop("metadata_json") or "{}")
        item["scenario"] = metadata.get("scenario")
        item["rule_version"] = metadata.get("rule_version")
        item["before"] = metadata.get("before")
        item["after"] = metadata.get("after")
        item["cluster_mass"] = metadata.get("cluster_mass")
        item["heat_is_truth_authority"] = False
        history.append(item)
    return history


def review_queue(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT memory_id FROM memories
        WHERE status != 'tombstoned'
        ORDER BY updated_at DESC, memory_id DESC
        LIMIT 500
        """
    ).fetchall()
    queue: list[dict[str, Any]] = []
    for row in rows:
        summary = _score_summary(conn, row["memory_id"])
        if summary["review_reasons"]:
            queue.append(summary)
    queue.sort(key=lambda item: (item["review_pressure"], item["memory_energy"], item["memory_id"]), reverse=True)
    return queue[:limit]


def ranked_memories(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    """Return score-aware memory ordering without semantic/vector retrieval.

    This is a bounded compat 03 operator view over existing canonical memory rows.
    It does not search embeddings, synthesize answers, or grant truth authority;
    low-support/stale/contradicted/quarantined memories are penalized.
    """
    rows = conn.execute(
        """
        SELECT memory_id FROM memories
        WHERE status != 'tombstoned'
        ORDER BY updated_at DESC, memory_id DESC
        LIMIT 500
        """
    ).fetchall()
    ranked: list[dict[str, Any]] = []
    for row in rows:
        summary = _score_summary(conn, row["memory_id"])
        score = (
            summary["confidence"] * 0.26
            + summary["retrieval_success_rate"] * 0.18
            + summary["retention_strength"] * 0.18
            + summary["stability"] * 0.16
            + summary["salience"] * 0.08
            + summary["novelty"] * 0.04
            - summary["contradiction_score"] * 0.2
            - summary["drift_score"] * 0.18
            - (0.4 if not summary["clean_recall_eligible"] else 0.0)
        )
        item = dict(summary)
        item["score_aware_rank_score"] = round(score, 6)
        item["ranking_channel"] = "compat03_score_fields_only"
        item["semantic_vector_retrieval_used"] = False
        ranked.append(item)
    ranked.sort(key=lambda item: (item["score_aware_rank_score"], item["memory_id"]), reverse=True)
    return ranked[:limit]


def decay_memory(conn: sqlite3.Connection, *, memory_id: str, occurred_at: str, actor_id: str = SCORE_ACTOR_ID) -> dict[str, Any]:
    return apply_scoring_scenario(conn, memory_id=memory_id, scenario="decay", occurred_at=occurred_at, actor_id=actor_id)
