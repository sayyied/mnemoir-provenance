"""Leak-safe Hermes markdown overflow pressure status for controlled fixtures.

compat 15-G02 deliberately measures only caller-supplied temporary fixtures. It
never reads live Hermes profile MEMORY.md/USER.md by default and never mutates
markdown files.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, sha256_text, stable_id

MARKDOWN_LIMITS: dict[str, int] = {"MEMORY.md": 2200, "USER.md": 1375}
MARKDOWN_KINDS: dict[str, str] = {"MEMORY.md": "memory_md", "USER.md": "user_md"}
WARNING_THRESHOLD = 0.80
TRIGGER_THRESHOLD = 0.90
TRIM_TARGET_RATIO = 0.50
FORBIDDEN_COMPONENTS = {"backup", "backups", ".backup", "profile-backup", "profile-backups"}


class OverflowPolicyError(Exception):
    """Fail-closed overflow pressure policy error."""


@dataclass(frozen=True)
class OverflowPolicy:
    warning_threshold: float = WARNING_THRESHOLD
    trigger_threshold: float = TRIGGER_THRESHOLD
    trim_target_ratio: float = TRIM_TARGET_RATIO
    limits: dict[str, int] | None = None

    def limit_for(self, file_name: str) -> int:
        limits = self.limits or MARKDOWN_LIMITS
        if file_name not in limits:
            raise OverflowPolicyError("unsupported_markdown_file")
        value = int(limits[file_name])
        if value <= 0:
            raise OverflowPolicyError("invalid_markdown_limit")
        return value


DEFAULT_POLICY = OverflowPolicy()


@dataclass(frozen=True)
class AutoPromotePolicy:
    """Thresholds for the high-signal auto-promote gate.

    The gate is conservative and fail-closed: it reuses the same protection
    thresholds the overflow planner already treats as ``higher_approval_required``
    so that a block auto-promotes only when it would not otherwise need a human.
    """

    high_retention_threshold: float = 0.75
    established_stability_threshold: float = 0.75
    contradiction_threshold: float = 0.55
    min_age_days: float = 7.0
    min_stability: float = 0.45


DEFAULT_AUTO_PROMOTE_POLICY = AutoPromotePolicy()


def evaluate_auto_promote(
    *,
    high_signal: bool,
    flags: set[str],
    retention_strength: float,
    stability: float,
    contradiction_score: float,
    conflicting_memory_relationships: int,
    memory_statuses: list[str],
    age_days: float | None,
    duplicate_rank: int,
    policy: AutoPromotePolicy = DEFAULT_AUTO_PROMOTE_POLICY,
) -> dict[str, Any]:
    """Pure decision for whether a high-signal block may auto-promote to durable
    memory.

    No I/O: every input is a plain value (``age_days`` is computed by the caller,
    ``flags`` by :func:`_content_flags`). Fail-closed: any protection condition
    yields ``promote=False``. The protection conditions mirror the overflow
    planner's ``higher_approval_required`` reasons, so auto-promotion never
    bypasses a condition that would otherwise require a human.
    """
    protected_reasons: list[str] = []
    if "sensitive" in flags:
        protected_reasons.append("sensitive_or_secret_content")
    if "policy_protected" in flags:
        protected_reasons.append("policy_protected")
    if "high_retention" in flags:
        protected_reasons.append("high_retention")
    if retention_strength >= policy.high_retention_threshold:
        protected_reasons.append("high_retention_strength")
    if stability >= policy.established_stability_threshold:
        protected_reasons.append("established_stability")
    if (
        contradiction_score >= policy.contradiction_threshold
        or conflicting_memory_relationships > 0
        or "contradicted" in memory_statuses
    ):
        protected_reasons.append("conflicting_or_contradicted")
    if age_days is not None and age_days < policy.min_age_days:
        protected_reasons.append("recent_entry")

    result: dict[str, Any] = {
        "surface": "auto_promote_gate",
        "high_signal": bool(high_signal),
        "flags": sorted(flags),
        "retention_strength": float(retention_strength),
        "stability": float(stability),
        "contradiction_score": float(contradiction_score),
        "conflicting_memory_relationships": int(conflicting_memory_relationships),
        "duplicate_rank": int(duplicate_rank),
        "age_days": None if age_days is None else float(age_days),
        "promote": False,
        "status": "pending",
        "reasons": [],
        "io_performed": False,
        "content_included": False,
    }

    if protected_reasons:
        result["status"] = "protected"
        result["reasons"] = protected_reasons
        return result
    if not high_signal:
        result["status"] = "not_high_signal"
        result["reasons"] = ["not_flagged_high_signal"]
        return result
    if duplicate_rank > 0:
        result["status"] = "duplicate"
        result["reasons"] = ["duplicate_content"]
        return result
    if stability < policy.min_stability:
        result["status"] = "insufficient_stability"
        result["reasons"] = ["stability_below_promotion_minimum"]
        return result
    result["promote"] = True
    result["status"] = "promoted"
    result["reasons"] = ["high_signal_stable_unique"]
    return result


def is_high_signal_content(content: str) -> bool:
    """Pure high-signal predicate for a block or completed-turn body.

    True when the content is substantive (>=3 words longer than 3 chars) and not
    protected by the gate's protection flags (no ``sensitive`` /
    ``policy_protected`` / ``high_retention``). Used both by the overflow
    auto-promote path and the ``propose_high_signal`` completed-turn policy.
    """
    flags = _content_flags(content, "private", {}, {})
    if flags & {"sensitive", "policy_protected", "high_retention"}:
        return False
    words = [word for word in content.lower().split() if len(word) > 3]
    return len(words) >= 3


def _high_signal_for_block(conn: sqlite3.Connection, *, event_id: str, content: str, flags: set[str]) -> bool:
    """Deterministic, leak-safe high-signal predicate for one trimmed block.

    A removed block is a high-signal *promotion candidate* when it is not
    protected by the gate's protection flags (no ``sensitive`` /
    ``policy_protected`` / ``high_retention``) and it carries a substantive,
    non-boilerplate body. The gate's stability/recency/duplicate/contradiction
    inputs (computed from the block's linked memories) decide the promotable
    band downstream, so this predicate only gates *entry* into the candidate
    set; it never promotes on its own. Idempotence is guaranteed separately by
    the stable ``memory_id`` in :func:`promote_high_signal_blocks`.
    """
    return is_high_signal_content(content)


def promote_high_signal_blocks(
    conn: sqlite3.Connection,
    *,
    operation_id: str,
    profile_id: str,
    file_name: str,
    removed_blocks: list[str],
    before_hash: str,
    after_hash: str,
    policy: AutoPromotePolicy = DEFAULT_AUTO_PROMOTE_POLICY,
) -> dict[str, Any]:
    """Gate and promote the high-signal subset of a just-committed overflow trim.

    Called by the live-overflow writeback path *after* the removed blocks are
    committed as cited evidence, and still inside the same
    ``WritebackAuthorization`` scope (the trim is already hash-bound to
    ``before_hash``/``after_hash``). It runs the pure :func:`evaluate_auto_promote`
    gate on each removed block and, for the gated subset only, writes an active
    durable memory. Every promotion is idempotent (stable memory id) and
    fail-closed: a gate error or write error leaves the block evidence-only and
    is reported, never raised. No markdown is read or written here.
    """
    source_id = f"live_overflow_trim:{profile_id}:{file_name}"
    promoted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    total = len(removed_blocks)
    for index, block in enumerate(removed_blocks, 1):
        content_hash = sha256_text(block)
        event_id = stable_id("live_overflow_removed", source_id, content_hash, str(index), before_hash)
        evidence_id = stable_id("evidence", event_id, content_hash)
        flags = _content_flags(block, "private", {}, {})
        signals = _memory_signals(conn, event_id)
        # Age is the block's *established* age: the oldest linked durable
        # memory's creation time. A block with no linked memory is not yet
        # established (age None; it is still gated down by stability below).
        age_days = None
        if signals["linked_memory_ids"]:
            placeholders = ",".join("?" for _ in signals["linked_memory_ids"])
            oldest = conn.execute(
                f"SELECT MIN(created_at) AS c FROM memories WHERE memory_id IN ({placeholders})",
                tuple(signals["linked_memory_ids"]),
            ).fetchone()
            oldest_time = _parse_time(oldest["c"] if oldest else None)
            if oldest_time is not None:
                age_days = max(0.0, (datetime.now(timezone.utc) - oldest_time).total_seconds() / 86400.0)
        # Position-aware duplicate rank (0 for the first occurrence, 1 for the
        # second, ...), matching the overflow planner's duplicate semantics.
        duplicate_rank = sum(1 for j in range(1, index) if sha256_text(removed_blocks[j - 1]) == content_hash)
        high_signal = _high_signal_for_block(conn, event_id=event_id, content=block, flags=flags)
        decision = evaluate_auto_promote(
            high_signal=high_signal,
            flags=flags,
            retention_strength=signals["max_retention_strength"],
            stability=signals["max_stability"],
            contradiction_score=signals["max_contradiction_score"],
            conflicting_memory_relationships=signals["conflicting_memory_relationships"],
            memory_statuses=signals["memory_statuses"],
            age_days=age_days,
            duplicate_rank=duplicate_rank,
            policy=policy,
        )
        entry = {
            "block_index": index,
            "source_event_id": event_id,
            "evidence_id": evidence_id,
            "content_hash": content_hash,
            "gate_status": decision["status"],
            "gate_reasons": decision["reasons"],
            "high_signal": decision["high_signal"],
        }
        if not decision["promote"]:
            skipped.append(entry)
            continue
        memory_id = stable_id("memory", "overflow_auto_promote", operation_id, content_hash, str(index))
        existing = conn.execute("SELECT 1 FROM memories WHERE memory_id = ?", (memory_id,)).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO memories(
                  memory_id, scope, owner_actor_id, memory_type, status, current_version,
                  confidence, salience, novelty, stability, privacy_class, created_at, updated_at
                ) VALUES (?, ?, ?, 'semantic', 'active', 1, 0.7, 0.2, 0.2, ?, 'private', ?, ?)
                """,
                (memory_id, "actor", None, decision["stability"], now_utc(), now_utc()),
            )
            version_hash = sha256_text(json_dumps({"memory_id": memory_id, "version": 1, "title": "Overflow auto-promote", "summary": block, "body": block}))
            conn.execute(
                """
                INSERT INTO memory_versions(
                  memory_id, version, title, summary, body, change_type, changed_by_actor_id,
                  reason, confidence, version_hash, previous_version_hash, metadata_json, created_at
                ) VALUES (?, 1, ?, ?, ?, 'create', NULL, ?, 0.7, ?, NULL, ?, ?)
                """,
                (
                    memory_id,
                    "Overflow auto-promote",
                    block,
                    block,
                    "auto-promoted from overflow trim " + operation_id,
                    version_hash,
                    json_dumps(
                        {
                            "operation": "overflow_auto_promote",
                            "operation_id": operation_id,
                            "before_hash": before_hash,
                            "after_hash": after_hash,
                            "source_event_id": event_id,
                            "evidence_id": evidence_id,
                            "gate_status": decision["status"],
                            "gate_reasons": decision["reasons"],
                            "path_redacted": True,
                        }
                    ),
                    now_utc(),
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO memory_evidence(memory_id, version, evidence_id, role, weight, created_at) VALUES (?, 1, ?, 'primary', 1.0, ?)",
                (memory_id, evidence_id, now_utc()),
            )
            write_audit_event(
                conn,
                event_type="memory.auto_promote",
                target_type="memory",
                target_id=memory_id,
                status="ok",
                actor_id=None,
                metadata={
                    "operation_id": operation_id,
                    "profile_id": profile_id,
                    "file_basename": file_name,
                    "source_event_id": event_id,
                    "evidence_id": evidence_id,
                    "gate_status": decision["status"],
                    "gate_reasons": decision["reasons"],
                    "content_hash": content_hash,
                    "content_included": False,
                    "path_redacted": True,
                },
            )
        entry["memory_id"] = memory_id
        entry["promoted"] = True
        promoted.append(entry)
    conn.commit()
    return {
        "status": "ok",
        "surface": "overflow_auto_promote",
        "operation_id": operation_id,
        "profile_id": profile_id,
        "file_basename": file_name,
        "policy_version": "auto_promote_gate_v1",
        "removed_block_count": total,
        "promoted_count": len(promoted),
        "skipped_count": len(skipped),
        "promoted": promoted,
        "skipped": skipped,
        "io_performed": True,
        "content_included": False,
        "path_redacted": True,
    }


def _safe_profile_id(profile_id: str) -> str:
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        raise OverflowPolicyError("unauthorized_profile_id")
    return profile_id


def _contains_forbidden_component(path: Path) -> bool:
    lowered = [part.lower() for part in path.parts]
    if any(part in FORBIDDEN_COMPONENTS or part.endswith(".bak") for part in lowered):
        return True
    # G02 status is controlled-fixture only. Deny Hermes profile roots before file read.
    parts = set(lowered)
    if ".hermes" in parts and "profiles" in parts:
        return True
    return False


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise OverflowPolicyError("symlink_path_denied")
        except OSError as exc:  # pragma: no cover - defensive platform edge
            raise OverflowPolicyError("path_unreadable") from exc


def _is_under_temp(path: Path) -> bool:
    try:
        tmp = Path(tempfile.gettempdir()).resolve(strict=True)
        resolved = path.resolve(strict=False)
        return resolved == tmp or tmp in resolved.parents
    except OSError:
        return False


def _validate_fixture_root(fixture_root: str | Path) -> Path:
    raw = Path(fixture_root).expanduser()
    if ".." in raw.parts:
        raise OverflowPolicyError("path_traversal_denied")
    if _contains_forbidden_component(raw):
        raise OverflowPolicyError("real_or_cross_profile_root_denied")
    _assert_no_symlink_components(raw)
    root = raw.resolve(strict=False)
    if _contains_forbidden_component(root):
        raise OverflowPolicyError("real_or_cross_profile_root_denied")
    if not _is_under_temp(root):
        raise OverflowPolicyError("non_temporary_fixture_root_denied")
    if not root.exists() or not root.is_dir():
        raise OverflowPolicyError("fixture_root_unavailable")
    return root


def _validate_markdown_path(root: Path, file_name: str, *, require_exists: bool) -> Path:
    if file_name not in MARKDOWN_LIMITS:
        raise OverflowPolicyError("unsupported_markdown_file")
    path = root / file_name
    if ".." in path.parts:
        raise OverflowPolicyError("path_traversal_denied")
    _assert_no_symlink_components(path)
    resolved = path.resolve(strict=False)
    expected = root.resolve(strict=True) / file_name
    if resolved != expected:
        raise OverflowPolicyError("fixture_boundary_denied")
    if require_exists:
        if not path.exists():
            raise OverflowPolicyError("markdown_source_missing")
        if not path.is_file():
            raise OverflowPolicyError("markdown_source_not_file")
    return path


def _redacted_ref(profile_id: str, file_name: str) -> str:
    return f"controlled-fixture://{profile_id}/{file_name}"


def _pressure_state(current_chars: int, limit_chars: int, policy: OverflowPolicy) -> str:
    ratio = current_chars / limit_chars
    if current_chars > limit_chars:
        return "over_limit"
    if ratio >= policy.trigger_threshold:
        return "trigger"
    if ratio >= policy.warning_threshold:
        return "warning"
    return "below_warning"


def compute_markdown_pressure(
    *,
    file_name: str,
    text: str,
    profile_id: str = "controlled_fixture",
    policy: OverflowPolicy = DEFAULT_POLICY,
    source_mtime: float | None = None,
) -> dict[str, Any]:
    """Compute deterministic pressure metrics from already-authorized text."""
    _safe_profile_id(profile_id)
    limit = policy.limit_for(file_name)
    current = len(text)
    percent = round((current / limit) * 100, 2)
    trim_target = math.floor(limit * policy.trim_target_ratio)
    state = _pressure_state(current, limit, policy)
    now = time.time()
    freshness_seconds = None if source_mtime is None else max(0, int(now - source_mtime))
    return {
        "status": "ok",
        "profile_id": profile_id,
        "overflow_kind": MARKDOWN_KINDS[file_name],
        "file_basename": file_name,
        "source_ref": _redacted_ref(profile_id, file_name),
        "capacity_limit_chars": limit,
        "current_chars": current,
        "percent_full": percent,
        "warning_threshold_percent": round(policy.warning_threshold * 100, 2),
        "trigger_threshold_percent": round(policy.trigger_threshold * 100, 2),
        "trim_target_percent": round(policy.trim_target_ratio * 100, 2),
        "trim_target_chars": trim_target,
        "excess_chars": max(0, current - limit),
        "chars_to_trim_to_target": max(0, current - trim_target),
        "pressure_state": state,
        "warning_state": state in {"warning", "trigger", "over_limit"},
        "trigger_state": state in {"trigger", "over_limit"},
        "over_limit_state": state == "over_limit",
        "source_snapshot_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "freshness_seconds": freshness_seconds,
        "degraded": False,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
    }


def evaluate_overflow_thresholds(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the threshold subset for API/plugin callers."""
    return {
        "file_basename": payload["file_basename"],
        "pressure_state": payload["pressure_state"],
        "warning_state": payload["warning_state"],
        "trigger_state": payload["trigger_state"],
        "over_limit_state": payload["over_limit_state"],
        "percent_full": payload["percent_full"],
        "excess_chars": payload["excess_chars"],
        "chars_to_trim_to_target": payload["chars_to_trim_to_target"],
    }


def _degraded_file_status(profile_id: str, file_name: str, reason: str, policy: OverflowPolicy) -> dict[str, Any]:
    limit = policy.limit_for(file_name)
    return {
        "status": "degraded",
        "profile_id": profile_id,
        "overflow_kind": MARKDOWN_KINDS[file_name],
        "file_basename": file_name,
        "source_ref": _redacted_ref(profile_id, file_name),
        "capacity_limit_chars": limit,
        "current_chars": None,
        "percent_full": None,
        "warning_threshold_percent": round(policy.warning_threshold * 100, 2),
        "trigger_threshold_percent": round(policy.trigger_threshold * 100, 2),
        "trim_target_percent": round(policy.trim_target_ratio * 100, 2),
        "trim_target_chars": math.floor(limit * policy.trim_target_ratio),
        "excess_chars": None,
        "chars_to_trim_to_target": None,
        "pressure_state": "unavailable",
        "warning_state": False,
        "trigger_state": False,
        "over_limit_state": False,
        "source_snapshot_hash": None,
        "freshness_seconds": None,
        "degraded": True,
        "failure_reason": reason,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
    }


def _json_loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _source_file_name(row: sqlite3.Row) -> str:
    if row["overflow_kind"] == "memory_md":
        return "MEMORY.md"
    if row["overflow_kind"] == "user_md":
        return "USER.md"
    raise OverflowPolicyError("unsupported_markdown_file")


def _safe_source_pointer(pointer: str | None, profile_id: str, file_name: str) -> str:
    if not pointer or "/" not in pointer:
        return _redacted_ref(profile_id, file_name)
    if "//" in pointer and not pointer.startswith("hermes-profile://"):
        return _redacted_ref(profile_id, file_name)
    # Keep only the redacted logical pointer form. Never return filesystem paths.
    if pointer.startswith(f"hermes-profile://{profile_id}/{file_name}"):
        return pointer
    return _redacted_ref(profile_id, file_name)


def _content_flags(content: str, privacy_class: str, provenance: dict[str, Any], source_privacy: dict[str, Any]) -> set[str]:
    lowered = content.lower()
    flags: set[str] = set()
    if privacy_class in {"sensitive", "secret"} or any(term in lowered for term in ("token", "secret", "password", "credential", "api_key", "sk-")):
        flags.add("sensitive")
    if provenance.get("protected") or provenance.get("policy_protected") or source_privacy.get("protected"):
        flags.add("policy_protected")
    if provenance.get("high_retention") or source_privacy.get("high_retention"):
        flags.add("high_retention")
    return flags


def _memory_signals(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT m.memory_id, m.status, m.stability, m.retention_strength, m.contradiction_score, m.privacy_class, m.retention_policy_id
        FROM evidence_items e
        JOIN memory_evidence me ON me.evidence_id = e.evidence_id
        JOIN memories m ON m.memory_id = me.memory_id
        WHERE e.raw_event_id = ?
        ORDER BY m.memory_id
        """,
        (event_id,),
    ).fetchall()
    memory_ids = [row["memory_id"] for row in rows]
    related_conflicts = 0
    if memory_ids:
        placeholders = ",".join("?" for _ in memory_ids)
        related_conflicts = int(
            conn.execute(
                f"""
                SELECT COUNT(*) FROM memory_relationships
                WHERE relationship_type='contradicts'
                  AND (from_memory_id IN ({placeholders}) OR to_memory_id IN ({placeholders}))
                """,
                tuple(memory_ids + memory_ids),
            ).fetchone()[0]
        )
    evidence_rows = conn.execute(
        "SELECT evidence_id FROM evidence_items WHERE raw_event_id = ? ORDER BY evidence_id",
        (event_id,),
    ).fetchall()
    provenance_rows = conn.execute(
        "SELECT edge_id FROM provenance_edges WHERE from_id = ? OR to_id = ? ORDER BY edge_id",
        (event_id, event_id),
    ).fetchall()
    max_stability = max([float(row["stability"]) for row in rows] or [0.0])
    max_retention = max([float(row["retention_strength"]) for row in rows] or [0.0])
    max_contradiction = max([float(row["contradiction_score"]) for row in rows] or [0.0])
    statuses = {row["status"] for row in rows}
    retention_policy_ids = [row["retention_policy_id"] for row in rows if row["retention_policy_id"]]
    protected_policy_count = 0
    if retention_policy_ids:
        placeholders = ",".join("?" for _ in retention_policy_ids)
        protected_policy_count = int(
            conn.execute(
                f"SELECT COUNT(*) FROM retention_policies WHERE retention_policy_id IN ({placeholders}) AND purge_strategy='retain'",
                tuple(retention_policy_ids),
            ).fetchone()[0]
        )
    return {
        "evidence_ids": [row["evidence_id"] for row in evidence_rows],
        "provenance_edge_ids": [row["edge_id"] for row in provenance_rows],
        "linked_memory_ids": memory_ids,
        "max_stability": max_stability,
        "max_retention_strength": max_retention,
        "max_contradiction_score": max_contradiction,
        "memory_statuses": sorted(statuses),
        "conflicting_memory_relationships": related_conflicts,
        "protected_retention_policy_count": protected_policy_count,
    }


def _candidate_action(
    *,
    duplicate_rank: int,
    flags: set[str],
    age_days: float | None,
    signals: dict[str, Any],
    stale_days: int,
) -> tuple[str, str, list[str]]:
    reasons: list[str] = []
    if "sensitive" in flags:
        reasons.append("sensitive_or_secret_content_requires_higher_approval")
    if "policy_protected" in flags or signals["protected_retention_policy_count"]:
        reasons.append("policy_protected_entry_requires_higher_approval")
    if signals["max_retention_strength"] >= 0.75:
        reasons.append("high_retention_strength_requires_higher_approval")
    if signals["max_stability"] >= 0.75:
        reasons.append("high_stability_requires_higher_approval")
    if signals["max_contradiction_score"] >= 0.55 or signals["conflicting_memory_relationships"] > 0 or "contradicted" in signals["memory_statuses"]:
        reasons.append("conflicting_or_contradicted_entry_requires_review_preservation")
    if age_days is not None and age_days < 7:
        reasons.append("recent_entry_preserved")
    if reasons:
        return "protect", "higher_approval_required", reasons
    if duplicate_rank > 0:
        return "compact", "proposed", ["duplicate_content_candidate"]
    if age_days is not None and age_days >= stale_days:
        if signals["max_retention_strength"] <= 0.35 and signals["max_stability"] <= 0.45:
            return "remove", "proposed", ["stale_low_retention_candidate"]
        return "compact", "proposed", ["stale_compaction_candidate"]
    return "retain", "review_not_required", ["below_trim_candidate_threshold"]


def plan_overflow_trim(
    conn: sqlite3.Connection,
    *,
    profile_id: str,
    policy: OverflowPolicy = DEFAULT_POLICY,
    reference_time: str | None = None,
    stale_days: int = 30,
) -> dict[str, Any]:
    """Create a deterministic, source-grounded trim/compaction proposal plan.

    The planner consumes only already-ingested Mnemoir source/raw_event/evidence rows
    for Hermes markdown overflow sources belonging to ``profile_id``. It never
    reads or writes markdown files, never mutates Hermes config, and never returns
    raw private content.
    """
    profile_id = _safe_profile_id(profile_id)
    now = _parse_time(reference_time) or datetime.now(timezone.utc)
    sources = conn.execute(
        """
        SELECT source_id, overflow_kind, external_ref, health, read_authority, write_authority, privacy_policy_json
        FROM sources
        WHERE source_type='hermes_markdown_overflow' AND profile_id=?
        ORDER BY overflow_kind, source_id
        """,
        (profile_id,),
    ).fetchall()
    if not sources:
        return {
            "status": "degraded",
            "profile_id": profile_id,
            "provider": "mnemoir_local",
            "surface": "overflow_trim_compaction_plan",
            "failure_reason": "authorized_overflow_sources_unavailable",
            "sources": [],
            "candidates": [],
            "summary": {"target_reachable": False, "target_pressure_status": "unavailable", "review_required": True},
            "file_mutation_performed": False,
            "content_included": False,
            "path_redacted": True,
            "real_profile_markdown_read": False,
            "real_profile_markdown_writeback": False,
            "hermes_provider_config_mutated": False,
        }

    candidates: list[dict[str, Any]] = []
    source_summaries: list[dict[str, Any]] = []
    duplicate_seen: dict[str, int] = {}
    aggregate_before = 0
    aggregate_after = 0
    any_unreachable = False
    any_degraded = False

    for source in sources:
        file_name = _source_file_name(source)
        source_health = source["health"]
        if source_health != "healthy" or source["read_authority"] == "none":
            any_degraded = True
            limit = policy.limit_for(file_name)
            source_summaries.append({
                "source_id": source["source_id"],
                "file_basename": file_name,
                "source_ref": _redacted_ref(profile_id, file_name),
                "status": "degraded",
                "failure_reason": "authorized_source_not_healthy",
                "current_chars": None,
                "target_chars": math.floor(limit * policy.trim_target_ratio),
                "projected_after_chars": None,
                "target_reachable": False,
            })
            continue
        events = conn.execute(
            """
            SELECT event_id, source_id, content, content_hash, occurred_at, ingested_at, privacy_class, source_pointer, provenance_json
            FROM raw_events
            WHERE source_id=? AND event_type='memory_block' AND write_status='committed'
            ORDER BY line_start, line_end, event_id
            """,
            (source["source_id"],),
        ).fetchall()
        if not events:
            any_degraded = True
        source_before = sum(len(row["content"]) for row in events)
        source_removed = 0
        limit = policy.limit_for(file_name)
        target = math.floor(limit * policy.trim_target_ratio)
        source_privacy = _json_loads(source["privacy_policy_json"], {})
        for row in events:
            content_hash = row["content_hash"]
            duplicate_rank = duplicate_seen.get(content_hash, 0)
            duplicate_seen[content_hash] = duplicate_rank + 1
            provenance = _json_loads(row["provenance_json"], {})
            flags = _content_flags(row["content"], row["privacy_class"], provenance, source_privacy)
            occurred = _parse_time(row["occurred_at"]) or _parse_time(row["ingested_at"])
            age_days = None if occurred is None else max(0.0, (now - occurred).total_seconds() / 86400.0)
            signals = _memory_signals(conn, row["event_id"])
            action, review_status, rationale = _candidate_action(
                duplicate_rank=duplicate_rank,
                flags=flags,
                age_days=age_days,
                signals=signals,
                stale_days=stale_days,
            )
            projected_removed = len(row["content"]) if action in {"compact", "remove"} else 0
            source_removed += projected_removed
            candidates.append({
                "candidate_id": hashlib.sha256(f"{source['source_id']}:{row['event_id']}:{content_hash}".encode("utf-8")).hexdigest()[:24],
                "source_id": source["source_id"],
                "source_event_id": row["event_id"],
                "evidence_ids": signals["evidence_ids"],
                "provenance_edge_ids": signals["provenance_edge_ids"],
                "source_pointer": _safe_source_pointer(row["source_pointer"], profile_id, file_name),
                "file_basename": file_name,
                "content_hash": content_hash,
                "content_chars": len(row["content"]),
                "proposed_action": action,
                "rationale": rationale,
                "review_status": review_status,
                "requires_higher_approval": review_status == "higher_approval_required",
                "projected_chars_removed": projected_removed,
                "rollback_metadata": {
                    "source_event_id": row["event_id"],
                    "content_hash": content_hash,
                    "source_pointer": _safe_source_pointer(row["source_pointer"], profile_id, file_name),
                    "markdown_writeback_performed": False,
                },
                "content_included": False,
            })
        source_after = max(0, source_before - source_removed)
        source_status = _pressure_state(source_before, limit, policy)
        after_status = _pressure_state(source_after, limit, policy)
        target_reachable = source_after <= target
        any_unreachable = any_unreachable or not target_reachable
        aggregate_before += source_before
        aggregate_after += source_after
        source_summaries.append({
            "source_id": source["source_id"],
            "file_basename": file_name,
            "source_ref": _redacted_ref(profile_id, file_name),
            "status": "ok" if events else "degraded",
            "current_chars": source_before,
            "pressure_state_before": source_status,
            "target_chars": target,
            "projected_after_chars": source_after,
            "pressure_state_after": after_status,
            "target_reachable": target_reachable,
            "candidate_count": sum(1 for item in candidates if item["source_id"] == source["source_id"]),
            "proposed_trim_chars": source_removed,
        })

    candidates.sort(key=lambda item: (item["file_basename"], item["source_id"], item["proposed_action"], item["content_hash"], item["source_event_id"]))
    target_status = "partial" if any_unreachable else ("degraded" if any_degraded else "reachable")
    plan_seed = json.dumps({
        "profile_id": profile_id,
        "sources": [(s["source_id"], s["file_basename"], s.get("projected_after_chars")) for s in source_summaries],
        "candidates": [(c["source_event_id"], c["proposed_action"], c["content_hash"]) for c in candidates],
    }, sort_keys=True)
    return {
        "status": "partial" if any_unreachable else ("degraded" if any_degraded else "ok"),
        "profile_id": profile_id,
        "provider": "mnemoir_local",
        "surface": "overflow_trim_compaction_plan",
        "plan_id": hashlib.sha256(plan_seed.encode("utf-8")).hexdigest()[:24],
        "policy": {
            "warning_threshold_percent": round(policy.warning_threshold * 100, 2),
            "trigger_threshold_percent": round(policy.trigger_threshold * 100, 2),
            "trim_target_percent": round(policy.trim_target_ratio * 100, 2),
            "limits": {name: policy.limit_for(name) for name in ("MEMORY.md", "USER.md")},
        },
        "sources": source_summaries,
        "candidates": candidates,
        "summary": {
            "source_count": len(source_summaries),
            "candidate_count": len(candidates),
            "protect_count": sum(1 for c in candidates if c["proposed_action"] == "protect"),
            "compact_count": sum(1 for c in candidates if c["proposed_action"] == "compact"),
            "remove_count": sum(1 for c in candidates if c["proposed_action"] == "remove"),
            "retain_count": sum(1 for c in candidates if c["proposed_action"] == "retain"),
            "projected_before_chars": aggregate_before,
            "projected_after_chars": aggregate_after,
            "projected_trim_chars": max(0, aggregate_before - aggregate_after),
            "target_reachable": not any_unreachable and not any_degraded,
            "target_pressure_status": target_status,
            "review_required": any(c["review_status"] in {"proposed", "higher_approval_required"} for c in candidates),
        },
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "hermes_provider_config_mutated": False,
    }


def propose_overflow_compaction(conn: sqlite3.Connection, *, profile_id: str, **kwargs: Any) -> dict[str, Any]:
    """Alias for the proposal-only planner; no markdown mutation is performed."""
    return plan_overflow_trim(conn, profile_id=profile_id, **kwargs)


def overflow_compaction_plan_for_profile(conn: sqlite3.Connection, profile_id: str, **kwargs: Any) -> dict[str, Any]:
    """Provider-friendly alias for profile-scoped overflow compaction planning."""
    return plan_overflow_trim(conn, profile_id=profile_id, **kwargs)


def overflow_status(
    fixture_root: str | Path,
    *,
    profile_id: str = "controlled_fixture",
    policy: OverflowPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    """Measure controlled-fixture MEMORY.md/USER.md pressure without mutation.

    Boundary denial happens before any file content is read. Returned status is
    leak-safe and contains only file basenames, redacted source refs, counts, hashes,
    and state metadata.
    """
    profile_id = _safe_profile_id(profile_id)
    try:
        root = _validate_fixture_root(fixture_root)
    except OverflowPolicyError as exc:
        return {
            "status": "unauthorized",
            "profile_id": profile_id,
            "provider": "mnemoir_local",
            "surface": "overflow_pressure_status",
            "failure_reason": str(exc),
            "sources": [],
            "file_mutation_performed": False,
            "content_included": False,
            "path_redacted": True,
        }

    sources: list[dict[str, Any]] = []
    for file_name in ("MEMORY.md", "USER.md"):
        try:
            path = _validate_markdown_path(root, file_name, require_exists=False)
            if not path.exists():
                sources.append(_degraded_file_status(profile_id, file_name, "markdown_source_missing", policy))
                continue
            if not path.is_file():
                sources.append(_degraded_file_status(profile_id, file_name, "markdown_source_not_file", policy))
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                sources.append(_degraded_file_status(profile_id, file_name, "markdown_source_unreadable", policy))
                continue
            sources.append(compute_markdown_pressure(file_name=file_name, text=text, profile_id=profile_id, policy=policy, source_mtime=path.stat().st_mtime))
        except OverflowPolicyError as exc:
            sources.append(_degraded_file_status(profile_id, file_name, str(exc), policy))

    status = "degraded" if any(item["status"] != "ok" for item in sources) else "ok"
    if any(item.get("over_limit_state") for item in sources):
        aggregate_state = "over_limit"
    elif any(item.get("trigger_state") for item in sources):
        aggregate_state = "trigger"
    elif any(item.get("warning_state") for item in sources):
        aggregate_state = "warning"
    elif status == "degraded":
        aggregate_state = "degraded"
    else:
        aggregate_state = "below_warning"
    return {
        "status": status,
        "profile_id": profile_id,
        "provider": "mnemoir_local",
        "surface": "overflow_pressure_status",
        "aggregate_pressure_state": aggregate_state,
        "policy": {
            "warning_threshold_percent": round(policy.warning_threshold * 100, 2),
            "trigger_threshold_percent": round(policy.trigger_threshold * 100, 2),
            "trim_target_percent": round(policy.trim_target_ratio * 100, 2),
            "limits": {name: policy.limit_for(name) for name in ("MEMORY.md", "USER.md")},
        },
        "sources": sources,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
    }
