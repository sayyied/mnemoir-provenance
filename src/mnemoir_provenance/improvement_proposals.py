"""compat 15.0.3 self-generated improvement proposals and gated promotion.

This module is intentionally local and deterministic. It creates bounded memory
model configuration proposals from compat 15.0.1 learning failure clusters, links
or runs compat 15.0.2 offline experiments, requires explicit review before local
promotion, and records reversible rollback metadata. It does not rewrite code,
change live Hermes configuration, read live profiles, or contact external APIs.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from typing import Any

from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id
from .experiments import (
    candidate_experiment,
    default_fixture_suite,
    define_memory_model_version,
    list_memory_model_versions,
    memory_model_version,
    run_candidate_experiment,
)
from .learning import learning_failure_clusters


class ImprovementProposalError(ValueError):
    """Domain error reported by the CLI as fail-closed JSON."""


_ALLOWED_PROPOSAL_STATUSES = {"draft", "experiment_ready", "recommended", "rejected", "approved", "promoted", "rolled_back", "blocked"}
_ALLOWED_REVIEW_DECISIONS = {"approve", "reject", "block"}
_ALLOWED_PROMOTION_STATUSES = {"approved_pending", "active_local", "rolled_back", "blocked"}
_ALLOWED_KNOBS = {
    "scoring_weights",
    "decay_half_life_days",
    "retention_threshold",
    "contradiction_penalty",
    "stale_penalty",
    "cluster_mass_threshold",
    "source_authority_weights",
    "retrieval_success_weights",
    "query_type_routing",
    "context_budget_chars",
    "review_queue_threshold",
    "rank_adjustments",
    "offline_metric_adjustments",
}
_TARGET_METRICS_BY_FAILURE = {
    "retrieval_miss": ["recall_at_k", "mrr", "ndcg"],
    "wrong_source_selected": ["recall_at_k", "mrr", "ndcg"],
    "context_dropped_needed_citation": ["context_budget_success"],
    "stale_ranked_high": ["stale_suppression"],
    "contradiction_not_suppressed": ["contradiction_suppression"],
    "proposal_false_positive": ["accepted_proposal_precision"],
    "unsupported_hot_leaked": ["unsupported_hot_suppression"],
    "benchmark_regression": ["recall_at_k", "mrr", "ndcg"],
    "useful_memory_cooled_too_fast": ["recall_at_k", "mrr"],
    "noisy_signal_consolidated_too_early": ["accepted_proposal_precision", "memory_bloat_rate"],
    "over_trimmed_useful_memory": ["context_budget_success", "recall_at_k"],
    "profile_scope_too_strict": ["recall_at_k"],
    "profile_scope_too_loose": ["cross_profile_leakage"],
    "policy_false_block": ["context_budget_success"],
}
_SECRET_OR_PRIVATE_MARKERS = re.compile(
    r"(api[_-]?key|token|secret|password|credential|auth\.json|sk-[A-Za-z0-9]|"
    r"MEMORY\.md|USER\.md|\.hermes/profiles|-----BEGIN|provider_auth|gateway|cron|systemd|autostart|honcho api)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(^|\s)/(home|Users|var|etc|root|tmp|mnt|opt)/[^\s]+")


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


def _safe_string(value: str) -> str | dict[str, Any]:
    if _SECRET_OR_PRIVATE_MARKERS.search(value) or _ABSOLUTE_PATH.search(value) or len(value) > 96:
        return {"redacted": True, "sha256": sha256_text(value), "chars": len(value)}
    return value


def _sanitize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        if isinstance(value, float) and not math.isfinite(value):
            return 0.0
        return value
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            safe_key = str(key)
            if _SECRET_OR_PRIVATE_MARKERS.search(safe_key) or _ABSOLUTE_PATH.search(safe_key):
                safe_key = f"redacted_key_{sha256_text(safe_key)[:12]}"
            sanitized[safe_key] = _sanitize(item)
        return sanitized
    return _safe_string(str(value))


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ImprovementProposalError(f"{label}_must_be_json_object")
    return value


def _proposal_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["evidence"] = _json_loads(item.pop("evidence_json"), {})
    item["expected_impact"] = _json_loads(item.pop("expected_impact_json"), {})
    item["risk"] = _json_loads(item.pop("risk_json"), {})
    item["safety_requirements"] = _json_loads(item.pop("safety_requirements_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["leak_safety"] = {
        "raw_private_content_stored": False,
        "evidence_is_ids_hashes_metrics_redacted_summaries_only": True,
        "arbitrary_code_patch_created": False,
        "active_behavior_changed_without_review": False,
    }
    return item


def _promotion_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["rollback_metadata"] = _json_loads(item.pop("rollback_metadata_json"), {})
    item["audit"] = _json_loads(item.pop("audit_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["local_only"] = True
    item["live_config_mutated"] = False
    return item


def _default_baseline_config() -> dict[str, Any]:
    return {
        "scoring_weights": {"retrieval_success": 1.0, "source_authority": 1.0},
        "decay_half_life_days": 30,
        "retention_threshold": 0.35,
        "contradiction_penalty": 1.0,
        "stale_penalty": 1.0,
        "cluster_mass_threshold": 0.7,
        "source_authority_weights": {"primary": 1.0, "secondary": 0.7, "derived": 0.4, "untrusted": 0.1},
        "retrieval_success_weights": {"positive_recall": 1.0, "retrieval_miss": -1.0},
        "query_type_routing": {"default": "hybrid"},
        "context_budget_chars": 6000,
        "review_queue_threshold": 0.65,
    }


def _baseline_model(conn: sqlite3.Connection, created_at: str | None) -> dict[str, Any]:
    active = active_local_memory_model_version(conn)
    if active:
        return active
    existing = list_memory_model_versions(conn, kind="baseline", limit=1)
    if existing:
        return existing[0]
    return define_memory_model_version(
        conn,
        kind="baseline",
        config=_default_baseline_config(),
        metadata={"phase": "15.0.3", "default_local_baseline": True},
        created_at=created_at,
    )["memory_model_version"]


def _bounded_candidate_delta(failure_class: str, event_count: int) -> dict[str, Any]:
    strength = min(0.2, max(0.05, event_count * 0.025))
    delta: dict[str, Any] = {
        "cluster_mass_threshold": round(min(0.95, 0.7 + strength), 3),
        "review_queue_threshold": round(max(0.4, 0.65 - strength / 2), 3),
        "offline_metric_adjustments": {},
    }
    if failure_class in {"retrieval_miss", "wrong_source_selected", "benchmark_regression", "useful_memory_cooled_too_fast"}:
        delta.update({
            "scoring_weights": {"retrieval_success": round(1.0 + strength, 3), "source_authority": 1.05},
            "retrieval_success_weights": {"positive_recall": round(1.0 + strength, 3), "retrieval_miss": round(-1.0 - strength, 3)},
            "rank_adjustments": {"recall_case": -1},
        })
    elif failure_class == "context_dropped_needed_citation":
        delta.update({"context_budget_chars": 7200, "offline_metric_adjustments": {"context_budget_success": 0.05}})
    elif failure_class == "stale_ranked_high":
        delta.update({"stale_penalty": round(1.0 + strength, 3), "offline_metric_adjustments": {"stale_suppression": 0.05}})
    elif failure_class == "contradiction_not_suppressed":
        delta.update({"contradiction_penalty": round(1.0 + strength, 3), "offline_metric_adjustments": {"contradiction_suppression": 0.05}})
    elif failure_class == "unsupported_hot_leaked":
        delta.update({"scoring_weights": {"unsupported_hot_signal": -1.0}, "offline_metric_adjustments": {"unsupported_hot_suppression": 0.05}})
    elif failure_class == "proposal_false_positive":
        delta.update({"review_queue_threshold": 0.8, "offline_metric_adjustments": {"accepted_proposal_precision": 0.05}})
    else:
        delta.update({"scoring_weights": {"source_authority": round(1.0 + strength, 3)}, "rank_adjustments": {"recall_case": -1}})
    return {key: value for key, value in delta.items() if key in _ALLOWED_KNOBS}


def _merge_config(base: dict[str, Any], delta: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in delta.items():
        if key not in _ALLOWED_KNOBS:
            raise ImprovementProposalError("unsupported_candidate_config_knob")
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def _proposal_evidence(cluster: dict[str, Any]) -> dict[str, Any]:
    source_coverage = cluster.get("source_coverage") or {}
    safe_sources = {str(key): int(value) for key, value in sorted(source_coverage.items()) if not _ABSOLUTE_PATH.search(str(key))}
    return {
        "failure_cluster_id": cluster["cluster_id"],
        "failure_class": cluster["failure_class"],
        "event_count": int(cluster["event_count"]),
        "severity_max": cluster["severity_max"],
        "sample_event_ids": list(cluster.get("sample_event_ids") or [])[:5],
        "source_coverage": safe_sources,
        "cluster_metrics": {
            "first_seen_at": cluster.get("first_seen_at"),
            "last_seen_at": cluster.get("last_seen_at"),
            "status": cluster.get("status"),
        },
        "redacted_summary": f"Recurring {cluster['failure_class']} cluster with {int(cluster['event_count'])} events.",
        "raw_private_content_included": False,
    }


def generate_improvement_proposals(
    conn: sqlite3.Connection,
    *,
    min_cluster_events: int = 2,
    profile_id: str | None = None,
    created_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = created_at or now_utc()
    baseline = _baseline_model(conn, timestamp)
    proposals: list[dict[str, Any]] = []
    for cluster in learning_failure_clusters(conn, limit=500):
        metadata = cluster.get("metadata") or {}
        if profile_id and metadata.get("profile_scope") != profile_id:
            continue
        if int(cluster.get("event_count") or 0) < int(min_cluster_events):
            continue
        if cluster.get("status") == "resolved":
            continue
        delta = _bounded_candidate_delta(cluster["failure_class"], int(cluster["event_count"]))
        candidate_config = _merge_config(baseline["config"], delta)
        candidate = define_memory_model_version(
            conn,
            kind="candidate",
            config=candidate_config,
            parent_model_version_id=baseline["model_version_id"],
            metadata={
                "phase": "15.0.3",
                "failure_cluster_id": cluster["cluster_id"],
                "bounded_candidate_config_delta": delta,
                "arbitrary_code_patch_created": False,
            },
            created_at=timestamp,
        )["memory_model_version"]
        evidence = _proposal_evidence(cluster)
        target_metrics = _TARGET_METRICS_BY_FAILURE.get(cluster["failure_class"], ["recall_at_k"])
        expected_impact = {"target_metrics": target_metrics, "candidate_config_delta": delta, "requires_offline_experiment": True}
        risk = {"risk_level": "medium" if cluster["severity_max"] in {"warning", "critical"} else "low", "bounded_knobs_only": True, "code_rewrite": False}
        safety = {
            "requires_zero_safety_gate_regression": True,
            "fail_closed_metrics": ["cross_profile_leakage", "unauthorized_writes", "contradiction_suppression", "stale_suppression", "leak_safety_regressions"],
            "promotion_requires_review_approval": True,
        }
        proposal_id = stable_id("improve", cluster["cluster_id"], baseline["model_version_id"], candidate["model_version_id"])
        conn.execute(
            """
            INSERT OR IGNORE INTO improvement_proposals(
              proposal_id, proposal_type, status, failure_cluster_id, baseline_model_version_id,
              candidate_model_version_id, experiment_id, evidence_json, expected_impact_json,
              risk_json, safety_requirements_json, created_at, updated_at, metadata_json
            ) VALUES (?, 'memory_model_config', 'draft', ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proposal_id,
                cluster["cluster_id"],
                baseline["model_version_id"],
                candidate["model_version_id"],
                json_dumps(_sanitize(evidence)),
                json_dumps(_sanitize(expected_impact)),
                json_dumps(_sanitize(risk)),
                json_dumps(_sanitize(safety)),
                timestamp,
                timestamp,
                json_dumps({"phase": "15.0.3", "profile_filter": profile_id, "live_behavior_changed": False}),
            ),
        )
        proposals.append(improvement_proposal(conn, proposal_id))
    conn.commit()
    return proposals


def improvement_proposal(conn: sqlite3.Connection, proposal_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM improvement_proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
    if row is None:
        raise ImprovementProposalError("improvement_proposal_not_found")
    return _proposal_payload(row)


def list_improvement_proposals(conn: sqlite3.Connection, *, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if status:
        if status not in _ALLOWED_PROPOSAL_STATUSES:
            raise ImprovementProposalError("invalid_improvement_proposal_status")
        where = " WHERE status = ?"
        params.append(status)
    rows = conn.execute(
        f"SELECT * FROM improvement_proposals{where} ORDER BY updated_at DESC, proposal_id DESC LIMIT ?",
        (*params, max(1, min(int(limit), 500))),
    ).fetchall()
    return [_proposal_payload(row) for row in rows]


def run_or_attach_proposal_experiment(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    fixture_suite: dict[str, Any] | None = None,
    experiment_id: str | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    proposal = improvement_proposal(conn, proposal_id)
    timestamp = started_at or now_utc()
    if experiment_id:
        experiment = candidate_experiment(conn, experiment_id)
        if experiment["baseline_model_version_id"] != proposal["baseline_model_version_id"] or experiment["candidate_model_version_id"] != proposal["candidate_model_version_id"]:
            raise ImprovementProposalError("experiment_model_version_mismatch")
    else:
        result = run_candidate_experiment(
            conn,
            baseline_model_version_id=proposal["baseline_model_version_id"],
            candidate_model_version_id=proposal["candidate_model_version_id"],
            fixture_suite=fixture_suite or default_fixture_suite(),
            metadata={"phase": "15.0.3", "proposal_id": proposal_id, "offline_only": True},
            started_at=timestamp,
        )
        experiment = result["experiment"]
    conn.execute(
        "UPDATE improvement_proposals SET experiment_id = ?, status = 'experiment_ready', updated_at = ? WHERE proposal_id = ? AND status IN ('draft','experiment_ready','blocked')",
        (experiment["experiment_id"], timestamp, proposal_id),
    )
    conn.commit()
    return {"status": "ok", "proposal": improvement_proposal(conn, proposal_id), "experiment": experiment}


def evaluate_promotion_recommendation(conn: sqlite3.Connection, proposal_id: str) -> dict[str, Any]:
    proposal = improvement_proposal(conn, proposal_id)
    timestamp = now_utc()
    if not proposal.get("experiment_id"):
        conn.execute("UPDATE improvement_proposals SET status = 'blocked', updated_at = ?, metadata_json = ? WHERE proposal_id = ?", (timestamp, json_dumps({**proposal.get("metadata", {}), "blocked_reason": "no_offline_experiment"}), proposal_id))
        conn.commit()
        return {"status": "blocked", "reason": "no_offline_experiment", "proposal": improvement_proposal(conn, proposal_id)}
    experiment = candidate_experiment(conn, proposal["experiment_id"])
    target_metrics = proposal["expected_impact"].get("target_metrics") or ["recall_at_k"]
    deltas = experiment.get("metric_deltas") or {}
    safety_pass = experiment.get("safety_gate_status") == "pass"
    improved = any(float(deltas.get(metric, 0.0)) > 0.0 for metric in target_metrics if metric not in {"cross_profile_leakage", "unauthorized_writes", "memory_bloat_rate", "harmful_recall_rate"})
    status = "recommended" if experiment.get("status") == "pass" and safety_pass and improved else "blocked"
    recommendation = {
        "target_metrics": target_metrics,
        "metric_deltas": {metric: deltas.get(metric, 0.0) for metric in target_metrics},
        "target_metric_improved": improved,
        "zero_safety_gate_regression": safety_pass,
        "experiment_id": experiment["experiment_id"],
        "promotion_requires_review_approval": True,
        "active_behavior_changed": False,
    }
    conn.execute(
        "UPDATE improvement_proposals SET status = ?, updated_at = ?, metadata_json = ? WHERE proposal_id = ?",
        (status, timestamp, json_dumps({**proposal.get("metadata", {}), "promotion_recommendation": recommendation}), proposal_id),
    )
    conn.commit()
    return {"status": status, "recommendation": recommendation, "proposal": improvement_proposal(conn, proposal_id), "experiment": experiment}


def review_improvement_proposal(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    decision: str,
    reviewer_id: str,
    notes: str | None = None,
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    if decision not in _ALLOWED_REVIEW_DECISIONS:
        raise ImprovementProposalError("invalid_review_decision")
    proposal = improvement_proposal(conn, proposal_id)
    if decision == "approve" and proposal["status"] != "recommended":
        raise ImprovementProposalError("approval_requires_recommended_proposal")
    new_status = {"approve": "approved", "reject": "rejected", "block": "blocked"}[decision]
    timestamp = reviewed_at or now_utc()
    conn.execute(
        """
        UPDATE improvement_proposals
        SET status = ?, reviewed_at = ?, reviewer_id = ?, review_decision = ?, review_notes_hash = ?, updated_at = ?
        WHERE proposal_id = ?
        """,
        (new_status, timestamp, reviewer_id, decision, sha256_text(notes or "") if notes is not None else None, timestamp, proposal_id),
    )
    conn.commit()
    return {"status": "ok", "proposal": improvement_proposal(conn, proposal_id)}


def _active_promotion(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM model_promotions WHERE status = 'active_local' ORDER BY promoted_at DESC, promotion_id DESC LIMIT 1").fetchone()
    return _promotion_payload(row) if row else None


def promote_memory_model_version(
    conn: sqlite3.Connection,
    *,
    proposal_id: str,
    approved_by: str,
    promoted_at: str | None = None,
) -> dict[str, Any]:
    proposal = improvement_proposal(conn, proposal_id)
    if proposal["status"] != "approved" or proposal.get("review_decision") != "approve":
        raise ImprovementProposalError("promotion_requires_explicit_review_approval")
    timestamp = promoted_at or now_utc()
    current = _active_promotion(conn)
    from_model = current["to_model_version_id"] if current else proposal["baseline_model_version_id"]
    promotion_id = stable_id("promotion", proposal_id, from_model, proposal["candidate_model_version_id"], timestamp)
    rollback_metadata = {
        "from_model_version_id": from_model,
        "to_model_version_id": proposal["candidate_model_version_id"],
        "rollback_command": f"improve rollback {promotion_id}",
        "restores_prior_local_model_version": True,
    }
    audit = {
        "proposal_id": proposal_id,
        "experiment_id": proposal.get("experiment_id"),
        "approved_review_decision": proposal.get("review_decision"),
        "explicit_review_approval_required": True,
        "silent_promotion": False,
        "live_config_mutated": False,
    }
    if current:
        conn.execute("UPDATE model_promotions SET status = 'rolled_back', rolled_back_at = ?, metadata_json = ? WHERE promotion_id = ?", (timestamp, json_dumps({**current.get("metadata", {}), "superseded_by_promotion_id": promotion_id}), current["promotion_id"]))
    conn.execute(
        """
        INSERT INTO model_promotions(
          promotion_id, proposal_id, from_model_version_id, to_model_version_id, status,
          approved_by, approved_at, promoted_at, rollback_metadata_json, audit_json, metadata_json
        ) VALUES (?, ?, ?, ?, 'active_local', ?, ?, ?, ?, ?, ?)
        """,
        (promotion_id, proposal_id, from_model, proposal["candidate_model_version_id"], approved_by, proposal.get("reviewed_at") or timestamp, timestamp, json_dumps(rollback_metadata), json_dumps(audit), json_dumps({"phase": "15.0.3", "local_only": True})),
    )
    conn.execute("UPDATE improvement_proposals SET status = 'promoted', updated_at = ? WHERE proposal_id = ?", (timestamp, proposal_id))
    conn.commit()
    return {"status": "ok", "promotion": model_promotion(conn, promotion_id), "active_model_version": active_local_memory_model_version(conn)}


def model_promotion(conn: sqlite3.Connection, promotion_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM model_promotions WHERE promotion_id = ?", (promotion_id,)).fetchone()
    if row is None:
        raise ImprovementProposalError("model_promotion_not_found")
    return _promotion_payload(row)


def rollback_memory_model_promotion(
    conn: sqlite3.Connection,
    *,
    promotion_id: str,
    reviewer_id: str,
    rolled_back_at: str | None = None,
) -> dict[str, Any]:
    promotion = model_promotion(conn, promotion_id)
    if promotion["status"] != "active_local":
        raise ImprovementProposalError("rollback_requires_active_local_promotion")
    timestamp = rolled_back_at or now_utc()
    restored_id = stable_id("promotionrollback", promotion_id, promotion["from_model_version_id"], timestamp)
    rollback_audit = {
        "rolled_back_promotion_id": promotion_id,
        "reviewer_id": reviewer_id,
        "restored_model_version_id": promotion["from_model_version_id"],
        "rolled_back_from_model_version_id": promotion["to_model_version_id"],
        "live_config_mutated": False,
    }
    conn.execute("UPDATE model_promotions SET status = 'rolled_back', rolled_back_at = ?, audit_json = ?, metadata_json = ? WHERE promotion_id = ?", (timestamp, json_dumps({**promotion.get("audit", {}), "rollback": rollback_audit}), json_dumps({**promotion.get("metadata", {}), "rolled_back_by": reviewer_id}), promotion_id))
    conn.execute(
        """
        INSERT INTO model_promotions(
          promotion_id, proposal_id, from_model_version_id, to_model_version_id, status,
          approved_by, approved_at, promoted_at, rolled_back_at,
          rollback_metadata_json, audit_json, metadata_json
        ) VALUES (?, ?, ?, ?, 'active_local', ?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            restored_id,
            promotion["proposal_id"],
            promotion["to_model_version_id"],
            promotion["from_model_version_id"],
            reviewer_id,
            timestamp,
            timestamp,
            json_dumps({"restored_from_rollback_of": promotion_id, "rollback_command": f"improve rollback {restored_id}"}),
            json_dumps(rollback_audit),
            json_dumps({"phase": "15.0.3", "rollback_restoration": True, "local_only": True}),
        ),
    )
    conn.execute("UPDATE improvement_proposals SET status = 'rolled_back', updated_at = ? WHERE proposal_id = ?", (timestamp, promotion["proposal_id"]))
    conn.commit()
    return {"status": "ok", "rolled_back_promotion": model_promotion(conn, promotion_id), "restoration_promotion": model_promotion(conn, restored_id), "active_model_version": active_local_memory_model_version(conn)}


def active_local_memory_model_version(conn: sqlite3.Connection) -> dict[str, Any] | None:
    active = _active_promotion(conn)
    if not active:
        return None
    model = memory_model_version(conn, active["to_model_version_id"])
    model["active_promotion_id"] = active["promotion_id"]
    model["active_local_only"] = True
    model["live_behavior_changed"] = False
    return model


def improvement_status(conn: sqlite3.Connection) -> dict[str, Any]:
    counts = {row["status"]: row["count"] for row in conn.execute("SELECT status, COUNT(*) AS count FROM improvement_proposals GROUP BY status").fetchall()}
    promotions = {row["status"]: row["count"] for row in conn.execute("SELECT status, COUNT(*) AS count FROM model_promotions GROUP BY status").fetchall()}
    return {
        "status": "ok",
        "proposal_counts": counts,
        "promotion_counts": promotions,
        "active_local_memory_model_version": active_local_memory_model_version(conn),
        "boundaries": {
            "local_cmc_storage_only": True,
            "live_profile_mutated": False,
            "live_config_mutated": False,
            "code_rewrite_performed": False,
            "compat15_1_started": False,
            "compat15_2_started": False,
        },
    }
