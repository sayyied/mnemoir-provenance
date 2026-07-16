"""compat 15.0.2 offline candidate experiment harness.

This module evaluates leak-safe candidate memory-model configs against a
baseline over caller-supplied or built-in deterministic fixtures. It is strictly
offline: it does not create improvement proposals, promote model versions,
change active scoring/ranking/decay/routing/context/writeback behavior, read
live profiles, or contact live services.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from typing import Any

from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id

_ALLOWED_KINDS = {"baseline", "candidate"}
_ALLOWED_STATUSES = {
    "baseline",
    "candidate",
    "rejected",
    "experiment_only",
}
_EXPERIMENT_STATUSES = {"pass", "fail", "blocked", "error"}
_SAFETY_STATUSES = {"pass", "fail", "blocked"}
_METRIC_KEYS = [
    "recall_at_k",
    "mrr",
    "ndcg",
    "stale_suppression",
    "contradiction_suppression",
    "accepted_proposal_precision",
    "memory_bloat_rate",
    "harmful_recall_rate",
    "unsupported_hot_suppression",
    "context_budget_success",
    "cross_profile_leakage",
    "unauthorized_writes",
]
_RATE_METRICS = set(_METRIC_KEYS)
_BAD_METRICS = {"memory_bloat_rate", "harmful_recall_rate", "cross_profile_leakage", "unauthorized_writes"}
_FAIL_CLOSED_REGRESSION_METRICS = {
    "cross_profile_leakage",
    "unauthorized_writes",
    "contradiction_suppression",
    "stale_suppression",
    "leak_safety_regressions",
}
_SECRET_OR_PRIVATE_MARKERS = re.compile(
    r"(api[_-]?key|token|secret|password|credential|auth\.json|sk-[A-Za-z0-9]|"
    r"MEMORY\.md|USER\.md|\.hermes/profiles|-----BEGIN|provider_auth|gateway|cron|systemd|autostart|honcho api)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(r"(^|\s)/(home|Users|var|etc|root|tmp|mnt|opt)/[^\s]+")


class ExperimentError(ValueError):
    """Domain error that should be returned as fail-closed JSON by the CLI."""


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
        raise ExperimentError(f"{label}_must_be_json_object")
    return value


def _expect_cases(fixture_suite: dict[str, Any]) -> list[dict[str, Any]]:
    cases = fixture_suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ExperimentError("fixture_suite_cases_required")
    normalized: list[dict[str, Any]] = []
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ExperimentError("fixture_case_must_be_json_object")
        case_id = str(case.get("case_id") or f"case_{idx:03d}")
        case_type = str(case.get("case_type") or "retrieval")
        if _SECRET_OR_PRIVATE_MARKERS.search(case_id) or _ABSOLUTE_PATH.search(case_id):
            raise ExperimentError("fixture_case_id_not_leak_safe")
        normalized.append({**case, "case_id": case_id, "case_type": case_type})
    return normalized


def _clamp_rate(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    if not math.isfinite(number):
        number = default
    return max(0.0, min(1.0, number))


def _rank_metrics(rank: int | None, k: int) -> dict[str, float]:
    if rank is None or rank < 1:
        return {"recall_at_k": 0.0, "mrr": 0.0, "ndcg": 0.0}
    hit = rank <= k
    return {
        "recall_at_k": 1.0 if hit else 0.0,
        "mrr": 1.0 / rank if hit else 0.0,
        "ndcg": (1.0 / math.log2(rank + 1)) if hit else 0.0,
    }


def _case_metric_defaults(case: dict[str, Any], side: str, k: int) -> dict[str, float]:
    side_payload = _expect_object(case.get(side), f"{side}_result")
    metrics = {key: 0.0 for key in _METRIC_KEYS}
    rank_key = "rank" if "rank" in side_payload else f"{side}_rank"
    rank = side_payload.get(rank_key, case.get(rank_key))
    if rank is None and side == "baseline":
        rank = case.get("baseline_rank")
    if rank is not None:
        metrics.update(_rank_metrics(int(rank), k))
    explicit_metrics = _expect_object(side_payload.get("metrics"), f"{side}_metrics")
    for key, value in explicit_metrics.items():
        if key in metrics:
            metrics[key] = _clamp_rate(value)
    # Safe deterministic convenience fields for non-retrieval gates.
    field_map = {
        "stale_suppressed": "stale_suppression",
        "contradiction_suppressed": "contradiction_suppression",
        "accepted_proposal_correct": "accepted_proposal_precision",
        "unsupported_hot_suppressed": "unsupported_hot_suppression",
        "context_budget_success": "context_budget_success",
        "cross_profile_leakage": "cross_profile_leakage",
        "unauthorized_write": "unauthorized_writes",
        "harmful_recall": "harmful_recall_rate",
        "memory_bloat": "memory_bloat_rate",
    }
    for source_key, metric_key in field_map.items():
        if source_key in side_payload:
            value = side_payload[source_key]
        elif f"{side}_{source_key}" in case:
            value = case[f"{side}_{source_key}"]
        else:
            continue
        if metric_key in _BAD_METRICS:
            metrics[metric_key] = 1.0 if bool(value) else 0.0
        else:
            metrics[metric_key] = 1.0 if bool(value) else 0.0
    return metrics


def _apply_adjustments(metrics: dict[str, float], adjustments: dict[str, Any]) -> dict[str, float]:
    adjusted = dict(metrics)
    for key, delta in adjustments.items():
        if key in adjusted:
            adjusted[key] = _clamp_rate(adjusted[key] + float(delta))
    return adjusted


def _candidate_case_metrics(case: dict[str, Any], baseline_metrics: dict[str, float], candidate_config: dict[str, Any], k: int) -> dict[str, float]:
    if case.get("candidate") is not None:
        return _case_metric_defaults(case, "candidate", k)
    candidate = dict(baseline_metrics)
    global_adjustments = _expect_object(candidate_config.get("offline_metric_adjustments"), "offline_metric_adjustments")
    candidate = _apply_adjustments(candidate, global_adjustments)
    by_case = _expect_object(candidate_config.get("case_metric_adjustments"), "case_metric_adjustments")
    case_adjustments = _expect_object(by_case.get(case["case_id"]), "case_metric_adjustments_case") if case["case_id"] in by_case else {}
    candidate = _apply_adjustments(candidate, case_adjustments)
    rank_adjustments = _expect_object(candidate_config.get("rank_adjustments"), "rank_adjustments")
    if case["case_id"] in rank_adjustments:
        base_rank = case.get("baseline_rank") or _expect_object(case.get("baseline"), "baseline_result").get("rank")
        if base_rank is not None:
            rank = max(1, int(base_rank) + int(rank_adjustments[case["case_id"]]))
            candidate.update(_rank_metrics(rank, k))
    forced_safety = set(candidate_config.get("force_safety_regressions") or [])
    if "cross_profile_leakage" in forced_safety:
        candidate["cross_profile_leakage"] = 1.0
    if "unauthorized_writes" in forced_safety:
        candidate["unauthorized_writes"] = 1.0
    if "contradiction_suppression" in forced_safety:
        candidate["contradiction_suppression"] = 0.0
    if "stale_suppression" in forced_safety:
        candidate["stale_suppression"] = 0.0
    return candidate


def _aggregate(case_metrics: list[dict[str, float]]) -> dict[str, float]:
    if not case_metrics:
        return {key: 0.0 for key in _METRIC_KEYS}
    return {
        key: round(sum(metrics.get(key, 0.0) for metrics in case_metrics) / len(case_metrics), 6)
        for key in _METRIC_KEYS
    }


def _delta(candidate: dict[str, float], baseline: dict[str, float]) -> dict[str, float]:
    return {key: round(candidate.get(key, 0.0) - baseline.get(key, 0.0), 6) for key in _METRIC_KEYS}


def _safety_findings(baseline: dict[str, float], candidate: dict[str, float], candidate_config: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    def add(metric: str, reason: str) -> None:
        findings.append({
            "metric": metric,
            "reason": reason,
            "baseline": baseline.get(metric, 0.0),
            "candidate": candidate.get(metric, 0.0),
        })

    if candidate.get("cross_profile_leakage", 0.0) > 0.0 or candidate.get("cross_profile_leakage", 0.0) > baseline.get("cross_profile_leakage", 0.0):
        add("cross_profile_leakage", "fail_closed_cross_profile_leakage")
    if candidate.get("unauthorized_writes", 0.0) > 0.0 or candidate.get("unauthorized_writes", 0.0) > baseline.get("unauthorized_writes", 0.0):
        add("unauthorized_writes", "fail_closed_unauthorized_write")
    for metric in ["contradiction_suppression", "stale_suppression"]:
        if candidate.get(metric, 0.0) < baseline.get(metric, 0.0):
            add(metric, f"fail_closed_{metric}_regression")
    leak_regressions = int(candidate_config.get("leak_safety_regressions", 0) or 0)
    if leak_regressions > 0:
        findings.append({"metric": "leak_safety_regressions", "reason": "fail_closed_leak_safety_regression", "baseline": 0, "candidate": leak_regressions})
    if candidate.get("harmful_recall_rate", 0.0) > baseline.get("harmful_recall_rate", 0.0):
        add("harmful_recall_rate", "harmful_recall_regression")
    return {
        "safety_gate_status": "fail" if findings else "pass",
        "findings": findings,
        "fail_closed_metrics": sorted(_FAIL_CLOSED_REGRESSION_METRICS),
        "promotion_allowed": False,
        "active_behavior_changed": False,
    }


def _model_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["config"] = _json_loads(item.pop("config_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["leak_safety"] = {
        "raw_private_content_stored": False,
        "config_hash_only_id_material": True,
        "live_behavior_changed": False,
    }
    return item


def _experiment_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["metrics"] = _json_loads(item.pop("metrics_json"), {})
    item["metric_deltas"] = _json_loads(item.pop("metric_deltas_json"), {})
    item["safety_findings"] = _json_loads(item.pop("safety_findings_json"), {})
    item["rollback_metadata"] = _json_loads(item.pop("rollback_metadata_json"), {})
    item["metadata"] = _json_loads(item.pop("metadata_json"), {})
    item["offline_only"] = True
    item["promotion_created"] = False
    item["active_behavior_changed"] = False
    return item


def _case_payload(row: sqlite3.Row) -> dict[str, Any]:
    item = row_to_dict(row)
    item["baseline_result"] = _json_loads(item.pop("baseline_result_json"), {})
    item["candidate_result"] = _json_loads(item.pop("candidate_result_json"), {})
    item["metric_deltas"] = _json_loads(item.pop("metric_deltas_json"), {})
    item["safety_flags"] = _json_loads(item.pop("safety_flags_json"), {})
    item["raw_private_content_stored"] = False
    return item


def define_memory_model_version(
    conn: sqlite3.Connection,
    *,
    kind: str,
    config: dict[str, Any],
    parent_model_version_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if kind not in _ALLOWED_KINDS:
        raise ExperimentError("invalid_memory_model_kind")
    safe_config = _expect_object(_sanitize(config), "config")
    safe_metadata = _expect_object(_sanitize(metadata or {}), "metadata")
    timestamp = created_at or now_utc()
    config_json = json_dumps(safe_config)
    config_hash = sha256_text(config_json)
    status = "baseline" if kind == "baseline" else "candidate"
    model_version_id = stable_id("model", kind, parent_model_version_id or "", config_hash, timestamp)
    conn.execute(
        """
        INSERT OR IGNORE INTO memory_model_versions(
          model_version_id, kind, parent_model_version_id, config_json,
          config_hash, status, created_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (model_version_id, kind, parent_model_version_id, config_json, config_hash, status, timestamp, json_dumps(safe_metadata)),
    )
    conn.commit()
    return {"status": "ok", "memory_model_version": memory_model_version(conn, model_version_id)}


def memory_model_version(conn: sqlite3.Connection, model_version_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM memory_model_versions WHERE model_version_id = ?", (model_version_id,)).fetchone()
    if row is None:
        raise ExperimentError("memory_model_version_not_found")
    return _model_payload(row)


def list_memory_model_versions(conn: sqlite3.Connection, *, kind: str | None = None, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if kind:
        if kind not in _ALLOWED_KINDS:
            raise ExperimentError("invalid_memory_model_kind")
        clauses.append("kind = ?")
        params.append(kind)
    if status:
        if status not in _ALLOWED_STATUSES:
            raise ExperimentError("invalid_memory_model_status")
        clauses.append("status = ?")
        params.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(f"SELECT * FROM memory_model_versions{where} ORDER BY created_at DESC, model_version_id DESC LIMIT ?", (*params, limit)).fetchall()
    return [_model_payload(row) for row in rows]


def run_candidate_experiment(
    conn: sqlite3.Connection,
    *,
    baseline_model_version_id: str,
    candidate_model_version_id: str,
    fixture_suite: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    baseline_model = memory_model_version(conn, baseline_model_version_id)
    candidate_model = memory_model_version(conn, candidate_model_version_id)
    if baseline_model["kind"] != "baseline":
        raise ExperimentError("baseline_model_version_must_have_baseline_kind")
    if candidate_model["kind"] != "candidate":
        raise ExperimentError("candidate_model_version_must_have_candidate_kind")
    safe_suite = _expect_object(_sanitize(fixture_suite), "fixture_suite")
    cases = _expect_cases(safe_suite)
    timestamp = started_at or now_utc()
    completed_at = timestamp
    suite_id = str(safe_suite.get("fixture_suite_id") or safe_suite.get("suite_id") or stable_id("fixture_suite", json_dumps(safe_suite)))
    k = int(safe_suite.get("k", 5) or 5)
    suite_hash = sha256_text(json_dumps(safe_suite))
    experiment_id = stable_id(
        "experiment",
        baseline_model_version_id,
        candidate_model_version_id,
        suite_id,
        suite_hash,
        timestamp,
    )
    safe_metadata = _expect_object(_sanitize(metadata or {}), "metadata")
    conn.execute(
        """
        INSERT OR REPLACE INTO candidate_experiments(
          experiment_id, baseline_model_version_id, candidate_model_version_id,
          fixture_suite_id, status, safety_gate_status, started_at, completed_at,
          metrics_json, metric_deltas_json, safety_findings_json,
          rollback_metadata_json, metadata_json
        ) VALUES (?, ?, ?, ?, 'blocked', 'blocked', ?, ?, '{}', '{}', '{}', '{}', ?)
        """,
        (
            experiment_id,
            baseline_model_version_id,
            candidate_model_version_id,
            suite_id,
            timestamp,
            completed_at,
            json_dumps({**safe_metadata, "fixture_suite_hash": suite_hash, "initial_insert_for_case_fk": True}),
        ),
    )
    case_rows: list[dict[str, Any]] = []
    baseline_case_metrics: list[dict[str, float]] = []
    candidate_case_metrics: list[dict[str, float]] = []
    candidate_config = candidate_model["config"]
    for case in cases:
        baseline_metrics = _case_metric_defaults(case, "baseline", k)
        candidate_metrics = _candidate_case_metrics(case, baseline_metrics, candidate_config, k)
        baseline_case_metrics.append(baseline_metrics)
        candidate_case_metrics.append(candidate_metrics)
        deltas = _delta(candidate_metrics, baseline_metrics)
        safety_flags = _safety_findings(baseline_metrics, candidate_metrics, candidate_config)
        case_status = "fail" if safety_flags["safety_gate_status"] == "fail" else "pass"
        experiment_case_id = stable_id("experiment_case", experiment_id, case["case_id"], json_dumps(baseline_metrics), json_dumps(candidate_metrics))
        baseline_result = {"metrics": baseline_metrics, "raw_private_content_stored": False}
        candidate_result = {"metrics": candidate_metrics, "raw_private_content_stored": False, "active_behavior_changed": False}
        conn.execute(
            """
            INSERT OR REPLACE INTO candidate_experiment_cases(
              experiment_case_id, experiment_id, case_id, case_type,
              baseline_result_json, candidate_result_json, metric_deltas_json,
              safety_flags_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                experiment_case_id,
                experiment_id,
                case["case_id"],
                case["case_type"],
                json_dumps(baseline_result),
                json_dumps(candidate_result),
                json_dumps(deltas),
                json_dumps(safety_flags),
                case_status,
                timestamp,
            ),
        )
        case_rows.append({
            "experiment_case_id": experiment_case_id,
            "case_id": case["case_id"],
            "case_type": case["case_type"],
            "baseline_result": baseline_result,
            "candidate_result": candidate_result,
            "metric_deltas": deltas,
            "safety_flags": safety_flags,
            "status": case_status,
            "created_at": timestamp,
        })
    baseline_metrics = _aggregate(baseline_case_metrics)
    candidate_metrics = _aggregate(candidate_case_metrics)
    deltas = _delta(candidate_metrics, baseline_metrics)
    findings = _safety_findings(baseline_metrics, candidate_metrics, candidate_config)
    safety_gate_status = findings["safety_gate_status"]
    status = "pass" if safety_gate_status == "pass" else "fail"
    safe_metadata = _expect_object(_sanitize(metadata or {}), "metadata")
    metrics = {
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "k": k,
        "case_count": len(cases),
        "required_metric_keys": _METRIC_KEYS,
    }
    rollback_metadata = {
        "offline_only": True,
        "active_model_version_changed": False,
        "promotion_created": False,
        "rollback_required": False,
        "baseline_model_version_id": baseline_model_version_id,
    }
    conn.execute(
        """
        UPDATE candidate_experiments
        SET status = ?,
            safety_gate_status = ?,
            completed_at = ?,
            metrics_json = ?,
            metric_deltas_json = ?,
            safety_findings_json = ?,
            rollback_metadata_json = ?,
            metadata_json = ?
        WHERE experiment_id = ?
        """,
        (
            status,
            safety_gate_status,
            completed_at,
            json_dumps(metrics),
            json_dumps(deltas),
            json_dumps(findings),
            json_dumps(rollback_metadata),
            json_dumps({**safe_metadata, "fixture_suite_hash": suite_hash}),
            experiment_id,
        ),
    )
    conn.commit()
    experiment = candidate_experiment(conn, experiment_id)
    experiment["cases"] = case_rows
    return {"status": status, "experiment": experiment}


def candidate_experiment(conn: sqlite3.Connection, experiment_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM candidate_experiments WHERE experiment_id = ?", (experiment_id,)).fetchone()
    if row is None:
        raise ExperimentError("candidate_experiment_not_found")
    return _experiment_payload(row)


def list_candidate_experiments(conn: sqlite3.Connection, *, candidate_model_version_id: str | None = None, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if candidate_model_version_id:
        clauses.append("candidate_model_version_id = ?")
        params.append(candidate_model_version_id)
    if status:
        if status not in _EXPERIMENT_STATUSES:
            raise ExperimentError("invalid_candidate_experiment_status")
        clauses.append("status = ?")
        params.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(f"SELECT * FROM candidate_experiments{where} ORDER BY started_at DESC, experiment_id DESC LIMIT ?", (*params, limit)).fetchall()
    return [_experiment_payload(row) for row in rows]


def candidate_experiment_cases(conn: sqlite3.Connection, experiment_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM candidate_experiment_cases WHERE experiment_id = ? ORDER BY case_id ASC LIMIT ?",
        (experiment_id, limit),
    ).fetchall()
    return [_case_payload(row) for row in rows]


def default_fixture_suite() -> dict[str, Any]:
    """Return a small safe fixture suite used by CLI smoke and focused tests."""
    return {
        "fixture_suite_id": "compat15_0_2_builtin_safe_suite_v1",
        "k": 3,
        "cases": [
            {"case_id": "recall_case", "case_type": "retrieval", "baseline": {"rank": 2}},
            {"case_id": "stale_case", "case_type": "stale_suppression", "baseline": {"stale_suppressed": True}},
            {"case_id": "contradiction_case", "case_type": "contradiction_suppression", "baseline": {"contradiction_suppressed": True}},
            {"case_id": "proposal_case", "case_type": "proposal_precision", "baseline": {"accepted_proposal_correct": True}},
            {"case_id": "budget_case", "case_type": "context_budget", "baseline": {"context_budget_success": True}},
            {"case_id": "unsupported_hot_case", "case_type": "unsupported_hot", "baseline": {"unsupported_hot_suppressed": True}},
            {"case_id": "safety_case", "case_type": "safety", "baseline": {"cross_profile_leakage": False, "unauthorized_write": False, "harmful_recall": False, "memory_bloat": False}},
        ],
    }
