"""Hermes-compatible local provider surface for Mnemoir Provenance compat 07.

This module intentionally works only with explicitly supplied profile roots. It never
reads the operator's real Hermes profile by default and never writes Hermes markdown.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
from typing import Any

from .audit import write_audit_event
from .curation import create_proposal
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id
from .ingest import ensure_system_actor
from .overflow_policy import overflow_compaction_plan_for_profile as controlled_overflow_plan
from .overflow_policy import overflow_status as controlled_overflow_status
from .policy_guard import propose_writeback, rollback_fixture, writeback_fixture
from .recall import recall
from .retrieval_hardening import classify_query_type, extract_answer_bearing_window
from .scope import authorized_sources_for_profile

MARKDOWN_FILES: dict[str, str] = {"memory_md": "MEMORY.md", "user_md": "USER.md"}
FORBIDDEN_PROFILE_COMPONENTS = {"backup", "backups", ".backup", "profile-backup", "profile-backups"}
_COMPLETED_TURN_REQUIRED_FIELDS = {"user_content", "assistant_content"}
DEFAULT_CONTEXT_BUDGET_CHARS = 4000
MIN_CONTEXT_BUDGET_CHARS = 64
MAX_CONTEXT_BUDGET_CHARS = 50000
_LOW_CONFIDENCE_THRESHOLD = 0.5


class HermesProviderError(Exception):
    """Fail-closed Hermes provider boundary error."""


@dataclass(frozen=True)
class HermesMarkdownSource:
    profile_id: str
    profile_root: Path
    overflow_kind: str

    @property
    def file_basename(self) -> str:
        return MARKDOWN_FILES[self.overflow_kind]

    @property
    def source_id(self) -> str:
        return f"hermes_profile_memory:{self.profile_id}:{self.file_basename}"

    @property
    def path(self) -> Path:
        return self.profile_root / self.file_basename

    @property
    def external_ref(self) -> str:
        return f"hermes-profile://{self.profile_id}/{self.file_basename}"


def _redacted_pointer(profile_id: str, file_basename: str, line_start: int | None = None, line_end: int | None = None) -> str:
    pointer = f"hermes-profile://{profile_id}/{file_basename}"
    if line_start is not None and line_end is not None:
        pointer += f"#L{line_start}-L{line_end}"
    return pointer


def _safe_profile_id(profile_id: str) -> str:
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        raise HermesProviderError("unauthorized_profile_id")
    return profile_id


def _contains_forbidden_component(path: Path) -> bool:
    return any(part.lower() in FORBIDDEN_PROFILE_COMPONENTS or part.lower().endswith(".bak") for part in path.parts)


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise HermesProviderError("symlink_profile_path_denied")
        except OSError as exc:  # pragma: no cover - platform defensive
            raise HermesProviderError("profile_path_unreadable") from exc


def _is_under_path(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
    except OSError:
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _is_under_temp(path: Path) -> bool:
    try:
        return _is_under_path(path, Path(tempfile.gettempdir()).resolve(strict=True))
    except OSError:
        return False


def _contains_live_hermes_profile(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".hermes" in parts and "profiles" in parts


def _controlled_allowed_roots(allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None) -> list[Path]:
    roots: list[Path] = []
    for item in allowed_profile_roots or []:
        raw = Path(item).expanduser()
        if ".." in raw.parts or _contains_forbidden_component(raw):
            continue
        resolved = raw.resolve(strict=False)
        if _contains_forbidden_component(resolved) or _contains_live_hermes_profile(resolved):
            continue
        roots.append(resolved)
    return roots


def _validated_profile_root(profile_root: str | Path, *, allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> Path:
    raw = Path(profile_root).expanduser()
    if ".." in raw.parts:
        raise HermesProviderError("path_traversal_denied")
    if _contains_forbidden_component(raw):
        raise HermesProviderError("backup_profile_path_denied")
    if _contains_live_hermes_profile(raw):
        raise HermesProviderError("live_hermes_profile_root_denied")
    _assert_no_symlink_components(raw)
    root = raw.resolve(strict=False)
    if _contains_forbidden_component(root):
        raise HermesProviderError("backup_profile_path_denied")
    if _contains_live_hermes_profile(root):
        raise HermesProviderError("live_hermes_profile_root_denied")
    allowed_roots = _controlled_allowed_roots(allowed_profile_roots)
    if not _is_under_temp(root) and not any(_is_under_path(root, allowed) for allowed in allowed_roots):
        raise HermesProviderError("non_controlled_profile_root_denied")
    if not root.exists() or not root.is_dir():
        raise HermesProviderError("profile_root_unavailable")
    return root


def _source(profile_id: str, profile_root: str | Path, overflow_kind: str, *, allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> HermesMarkdownSource:
    if overflow_kind not in MARKDOWN_FILES:
        raise HermesProviderError("unsupported_overflow_kind")
    return HermesMarkdownSource(_safe_profile_id(profile_id), _validated_profile_root(profile_root, allowed_profile_roots=allowed_profile_roots), overflow_kind)


def _validate_source_path(source: HermesMarkdownSource, *, require_exists: bool) -> Path:
    path = source.path
    if ".." in path.parts:
        raise HermesProviderError("path_traversal_denied")
    if _contains_forbidden_component(path):
        raise HermesProviderError("backup_profile_path_denied")
    _assert_no_symlink_components(path)
    resolved_root = source.profile_root.resolve(strict=True)
    resolved_path = path.resolve(strict=False)
    if resolved_path != resolved_root / source.file_basename:
        raise HermesProviderError("profile_boundary_denied")
    if require_exists:
        if not path.exists():
            raise HermesProviderError("markdown_source_missing")
        if not path.is_file():
            raise HermesProviderError("markdown_source_not_file")
    return path


def _read_markdown_no_follow(source: HermesMarkdownSource) -> str:
    """Read one validated regular file while detecting root replacement."""
    root_before = os.stat(source.profile_root, follow_symlinks=False)
    path = _validate_source_path(source, require_exists=True)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HermesProviderError("markdown_source_not_regular_file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_mode) != (opened.st_dev, opened.st_ino, opened.st_mode):
            os.close(descriptor)
            raise HermesProviderError("markdown_source_replaced_during_open")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise HermesProviderError("markdown_source_read_denied") from exc
    root_after = os.stat(source.profile_root, follow_symlinks=False)
    if (root_before.st_dev, root_before.st_ino) != (root_after.st_dev, root_after.st_ino):
        raise HermesProviderError("profile_root_replaced_during_read")
    return text


def _classify_privacy(overflow_kind: str, block: str) -> str:
    lowered = block.lower()
    if overflow_kind == "user_md":
        return "sensitive" if any(term in lowered for term in ["token", "secret", "password", "credential"]) else "private"
    if any(term in lowered for term in ["token", "secret", "password", "credential"]):
        return "sensitive"
    return "private"


def _markdown_blocks(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: list[str] = []
    start_line = 1
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            if not current:
                start_line = line_no
            current.append(line)
        elif current:
            blocks.append({"content": "\n".join(current), "line_start": start_line, "line_end": line_no - 1})
            current = []
    if current:
        blocks.append({"content": "\n".join(current), "line_start": start_line, "line_end": start_line + len(current) - 1})
    return blocks




def _controlled_allowed_turn_roots(allowed_turn_roots: list[str | Path] | tuple[str | Path, ...] | None) -> list[Path]:
    roots: list[Path] = []
    for item in allowed_turn_roots or []:
        raw = Path(item).expanduser()
        if ".." in raw.parts or _contains_forbidden_component(raw):
            continue
        resolved = raw.resolve(strict=False)
        if _contains_forbidden_component(resolved) or _contains_live_hermes_profile(resolved):
            continue
        roots.append(resolved)
    return roots


def _validated_turn_fixture_path(turn_fixture_path: str | Path, *, allowed_turn_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> Path:
    raw = Path(turn_fixture_path).expanduser()
    if ".." in raw.parts:
        raise HermesProviderError("path_traversal_denied")
    if _contains_forbidden_component(raw):
        raise HermesProviderError("backup_turn_path_denied")
    if _contains_live_hermes_profile(raw):
        raise HermesProviderError("live_hermes_profile_turn_path_denied")
    _assert_no_symlink_components(raw)
    path = raw.resolve(strict=False)
    if _contains_forbidden_component(path):
        raise HermesProviderError("backup_turn_path_denied")
    if _contains_live_hermes_profile(path):
        raise HermesProviderError("live_hermes_profile_turn_path_denied")
    allowed_roots = _controlled_allowed_turn_roots(allowed_turn_roots)
    if not _is_under_temp(path) and not any(_is_under_path(path, allowed) for allowed in allowed_roots):
        raise HermesProviderError("non_controlled_turn_source_denied")
    if not path.exists():
        raise HermesProviderError("completed_turn_source_missing")
    if not path.is_file():
        raise HermesProviderError("completed_turn_source_not_file")
    if path.suffix.lower() not in {".json", ".jsonl"}:
        raise HermesProviderError("unsupported_completed_turn_fixture_type")
    return path


def _safe_turn_ref(profile_id: str, session_id: str, turn_id: str) -> str:
    session_ref = stable_id("session_ref", session_id or "session")
    return f"completed-turn://{profile_id}/{session_ref}/{turn_id}"


def _safe_turn_status_base(profile_id: str) -> dict[str, Any]:
    return {
        "provider": "mnemoir_local",
        "surface": "completed_turn_sync_proposal",
        "profile_id": profile_id,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "hermes_provider_config_mutated": False,
        "honcho_api_called": False,
        "provider_activation_performed": False,
        "automatic_memory_promotion": False,
        "markdown_writeback_performed": False,
    }


def _load_completed_turn_fixture(turn_fixture_path: str | Path, *, allowed_turn_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    path = _validated_turn_fixture_path(turn_fixture_path, allowed_turn_roots=allowed_turn_roots)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HermesProviderError("completed_turn_source_unavailable") from exc
    if not isinstance(payload, dict):
        raise HermesProviderError("completed_turn_fixture_invalid")
    if not _COMPLETED_TURN_REQUIRED_FIELDS <= set(payload):
        raise HermesProviderError("completed_turn_fixture_missing_required_fields")
    metadata = {"fixture_ref": "controlled_completed_turn_fixture", "fixture_hash": sha256_text(json_dumps(payload)), "path_redacted": True}
    return payload, metadata


_HONCHO_RECORD_TEXT_FIELDS = ("content", "text", "body", "memory", "summary", "claim")


def _controlled_allowed_honcho_roots(allowed_honcho_roots: list[str | Path] | tuple[str | Path, ...] | None) -> list[Path]:
    roots: list[Path] = []
    for item in allowed_honcho_roots or []:
        raw = Path(item).expanduser()
        if ".." in raw.parts or _contains_forbidden_component(raw):
            continue
        resolved = raw.resolve(strict=False)
        if _contains_forbidden_component(resolved) or _contains_live_hermes_profile(resolved):
            continue
        roots.append(resolved)
    return roots


def _validated_honcho_fixture_path(honcho_fixture_path: str | Path, *, allowed_honcho_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> Path:
    raw = Path(honcho_fixture_path).expanduser()
    if ".." in raw.parts:
        raise HermesProviderError("path_traversal_denied")
    if _contains_forbidden_component(raw):
        raise HermesProviderError("backup_honcho_import_path_denied")
    if _contains_live_hermes_profile(raw):
        raise HermesProviderError("live_hermes_profile_honcho_import_path_denied")
    _assert_no_symlink_components(raw)
    path = raw.resolve(strict=False)
    if _contains_forbidden_component(path):
        raise HermesProviderError("backup_honcho_import_path_denied")
    if _contains_live_hermes_profile(path):
        raise HermesProviderError("live_hermes_profile_honcho_import_path_denied")
    allowed_roots = _controlled_allowed_honcho_roots(allowed_honcho_roots)
    if not _is_under_temp(path) and not any(_is_under_path(path, allowed) for allowed in allowed_roots):
        raise HermesProviderError("non_controlled_honcho_import_source_denied")
    if not path.exists():
        raise HermesProviderError("honcho_import_source_missing")
    if not path.is_file():
        raise HermesProviderError("honcho_import_source_not_file")
    if path.suffix.lower() not in {".json", ".jsonl"}:
        raise HermesProviderError("unsupported_honcho_import_fixture_type")
    return path


def _safe_honcho_status_base(profile_id: str) -> dict[str, Any]:
    return {
        "provider": "mnemoir_local",
        "surface": "honcho_legacy_import_boundary",
        "profile_id": profile_id,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
        "redacted_pointers_only": True,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "hermes_provider_config_mutated": False,
        "honcho_api_called": False,
        "honcho_api_required": False,
        "provider_activation_performed": False,
        "automatic_memory_promotion": False,
        "markdown_writeback_performed": False,
        "review_required": True,
    }


def _load_honcho_fixture(honcho_fixture_path: str | Path, *, allowed_honcho_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    path = _validated_honcho_fixture_path(honcho_fixture_path, allowed_honcho_roots=allowed_honcho_roots)
    try:
        if path.suffix.lower() == ".jsonl":
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            payload: dict[str, Any] = {"records": records}
        else:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            payload = loaded if isinstance(loaded, dict) else {"records": loaded}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HermesProviderError("honcho_import_source_unavailable") from exc
    if not isinstance(payload, dict):
        raise HermesProviderError("honcho_import_fixture_invalid")
    metadata = {"fixture_ref": "controlled_honcho_legacy_fixture", "fixture_hash": sha256_text(json_dumps(payload)), "path_redacted": True}
    return payload, metadata


def _honcho_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = payload.get("records") or payload.get("memories") or payload.get("messages") or payload.get("items")
    if not isinstance(candidates, list):
        raise HermesProviderError("honcho_import_fixture_missing_records")
    records: list[dict[str, Any]] = []
    for index, item in enumerate(candidates, start=1):
        if not isinstance(item, dict):
            raise HermesProviderError("honcho_import_record_invalid")
        text = ""
        for field in _HONCHO_RECORD_TEXT_FIELDS:
            value = item.get(field)
            if isinstance(value, str) and value.strip():
                text = value
                break
        if not text.strip():
            raise HermesProviderError("honcho_import_record_missing_content")
        raw_id = str(item.get("id") or item.get("memory_id") or item.get("message_id") or f"record-{index}")
        session = str(item.get("session_id") or item.get("thread_id") or payload.get("session_id") or "legacy_honcho")
        occurred_at = str(item.get("created_at") or item.get("timestamp") or item.get("updated_at") or now_utc())
        privacy_class = str(item.get("privacy_class") or "private")
        if privacy_class not in {"public", "internal", "private", "sensitive", "secret"}:
            privacy_class = "private"
        records.append({
            "record_index": index,
            "record_id": stable_id("honcho_record", raw_id),
            "session_key": session,
            "occurred_at": occurred_at,
            "privacy_class": privacy_class,
            "content": text,
            "content_hash": sha256_text(text),
            "metadata_hash": sha256_text(json_dumps({k: v for k, v in item.items() if k not in _HONCHO_RECORD_TEXT_FIELDS})),
        })
    return records


def _honcho_pointer(profile_id: str, source_id: str, record: dict[str, Any]) -> str:
    session_ref = stable_id("session_ref", record["session_key"])
    return f"honcho-legacy://{profile_id}/{source_id}/{session_ref}/{record['record_id']}"


def import_honcho_legacy_fixture(conn: sqlite3.Connection, *, profile_id: str, honcho_fixture_path: str | Path | None = None, allowed_honcho_roots: list[str | Path] | tuple[str | Path, ...] | None = None, actor_id: str | None = None) -> dict[str, Any]:
    """Import an explicitly supplied local Honcho export fixture as legacy evidence.

    This boundary is dry-run/proposal-only from a live-Hermes perspective: it never
    calls Honcho APIs, reads live profile markdown, writes markdown, mutates Hermes
    config, activates providers, or promotes memories without review.
    """
    profile_id = _safe_profile_id(profile_id)
    base = _safe_honcho_status_base(profile_id)
    if honcho_fixture_path is None:
        audit_id = write_audit_event(conn, event_type="honcho.legacy.import", target_type="source", target_id="honcho:redacted", actor_id=actor_id, status="degraded", metadata={"profile_id": profile_id, "failure_reason": "honcho_import_source_missing", "content_read": False, "path_redacted": True, "honcho_api_called": False})
        conn.commit()
        base.update({"status": "degraded", "failure_reason": "honcho_import_source_missing", "records_imported": 0, "proposal_count": 0, "audit_id": audit_id})
        return base
    try:
        payload, source_metadata = _load_honcho_fixture(honcho_fixture_path, allowed_honcho_roots=allowed_honcho_roots)
        records = _honcho_records(payload)
    except HermesProviderError as error:
        status = "denied" if "denied" in str(error) or "live_hermes" in str(error) else "degraded"
        audit_id = write_audit_event(conn, event_type="honcho.legacy.import", target_type="source", target_id="honcho:redacted", actor_id=actor_id, status=status, metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": status != "denied", "path_redacted": True, "honcho_api_called": False})
        conn.commit()
        base.update({"status": "unauthorized" if status == "denied" else "degraded", "failure_reason": str(error), "records_imported": 0, "proposal_count": 0, "audit_id": audit_id})
        return base

    ensure_system_actor(conn)
    actor = actor_id or ensure_hermes_actor(conn, profile_id)
    timestamp = now_utc()
    source_id = stable_id("source", "honcho_legacy", profile_id, source_metadata["fixture_hash"])
    external_ref = f"honcho-legacy://{profile_id}/{source_id}"
    conn.execute("""
        INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, failure_reason, provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, 'honcho', ?, ?, ?, 'honcho', 'read_only', 'propose_only', 'secondary', 'healthy', ?, 0, NULL, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET health='healthy', last_sync_at=excluded.last_sync_at, freshness_seconds=0, failure_reason=NULL, updated_at=excluded.updated_at
        """, (source_id, f"Controlled Honcho legacy import ({profile_id})", external_ref, profile_id, timestamp, json_dumps({"adapter": "honcho_legacy_import_boundary", "controlled_local_fixture_only": True, "path_redacted": True, "live_api_calls_allowed": False}), json_dumps({"default_visibility": "private", "raw_import_status_output_allowed": False, "profile_path_redacted": True}), timestamp, timestamp))
    snapshot_id = stable_id("snapshot", source_id, source_metadata["fixture_hash"])
    conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, source_metadata["fixture_hash"], external_ref, timestamp, json_dumps(source_metadata)))
    inserted_raw = inserted_evidence = inserted_provenance = 0
    record_summaries: list[dict[str, Any]] = []
    raw_event_ids: list[str] = []
    evidence_ids: list[str] = []
    proposal_ids: list[str] = []
    edge_ids: list[str] = []
    for record in records:
        session_row_id = stable_id("session", source_id, record["session_key"])
        session_ref = f"{external_ref}/{stable_id('session_ref', record['session_key'])}"
        conn.execute("""
            INSERT INTO sessions(session_id, source_id, external_ref, title, started_at, status, privacy_class, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, 'Controlled Honcho legacy import session', ?, 'closed', ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET status='closed', updated_at=excluded.updated_at
            """, (session_row_id, source_id, session_ref, timestamp, record["privacy_class"], json_dumps({"profile_id": profile_id, "legacy_session_hash": sha256_text(record["session_key"]), "path_redacted": True}), timestamp, timestamp))
        pointer = _honcho_pointer(profile_id, source_id, record)
        event_id = stable_id("event", source_id, record["record_id"], record["content_hash"])
        event_hash = sha256_text(json_dumps({"event_id": event_id, "source_id": source_id, "content_hash": record["content_hash"]}))
        cur = conn.execute("""
            INSERT OR IGNORE INTO raw_events(event_id, session_id, source_id, snapshot_id, speaker_actor_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json, write_status, event_hash)
            VALUES (?, ?, ?, ?, ?, 'import', ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)
            """, (event_id, session_row_id, source_id, snapshot_id, actor, record["content"], record["content_hash"], record["occurred_at"], timestamp, record["privacy_class"], record["privacy_class"], pointer, json_dumps({"profile_id": profile_id, "legacy_record_id": record["record_id"], "metadata_hash": record["metadata_hash"], "path_redacted": True, "controlled_input_only": True, "review_required": True}), event_hash))
        if cur.rowcount > 0:
            inserted_raw += 1
        evidence_id = stable_id("evidence", event_id)
        cur = conn.execute("""
            INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at)
            VALUES (?, 'memory', ?, ?, ?, ?, ?, ?, 0.6, ?, ?, ?)
            """, (evidence_id, source_id, event_id, pointer, json_dumps({"profile_id": profile_id, "legacy_record_id": record["record_id"], "path_redacted": True, "content_hash_only": True}), "Controlled Honcho legacy evidence; raw private content omitted from status output.", record["content_hash"], record["privacy_class"], timestamp, timestamp))
        if cur.rowcount > 0:
            inserted_evidence += 1
        for edge in [("source", source_id, "raw_event", event_id, "produced"), ("raw_event", event_id, "evidence", evidence_id, "quotes")]:
            edge_id = stable_id("edge", *edge)
            cur = conn.execute("INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)", (edge_id, *edge, json_dumps({"adapter": "honcho_legacy_import_boundary", "path_redacted": True}), timestamp))
            if cur.rowcount > 0:
                inserted_provenance += 1
            edge_ids.append(edge_id)
        proposal = create_proposal(conn, title="Honcho legacy memory continuity proposal", summary="Review controlled Honcho legacy record for possible durable memory continuity.", body=f"Proposal generated from controlled Honcho legacy import evidence. content_hash={record['content_hash']} metadata_hash={record['metadata_hash']}", evidence_ids=[evidence_id], source_event_ids=[event_id], privacy_class=record["privacy_class"], actor_id=actor)
        raw_event_ids.append(event_id)
        evidence_ids.append(evidence_id)
        proposal_ids.append(proposal["proposal_id"])
        record_summaries.append({"record_id": record["record_id"], "raw_event_id": event_id, "evidence_id": evidence_id, "proposal_id": proposal["proposal_id"], "content_hash": record["content_hash"], "source_pointer": pointer, "content_included": False, "path_redacted": True, "review_required": True})
    audit_id = write_audit_event(conn, event_type="honcho.legacy.import", target_type="source", target_id=source_id, actor_id=actor, status="ok", metadata={"profile_id": profile_id, "source_id": source_id, "snapshot_hash": source_metadata["fixture_hash"], "records_imported": len(records), "raw_event_ids": raw_event_ids, "evidence_ids": evidence_ids, "proposal_ids": proposal_ids, "content_hashes": [item["content_hash"] for item in record_summaries], "content_included": False, "path_redacted": True, "honcho_api_called": False, "automatic_memory_promotion": False, "markdown_writeback_performed": False, "review_required": True})
    conn.commit()
    base.update({"status": "ok", "source_id": source_id, "snapshot_hash": source_metadata["fixture_hash"], "records_imported": len(records), "inserted_raw_events": inserted_raw, "inserted_evidence_items": inserted_evidence, "inserted_provenance_edges": inserted_provenance, "proposal_count": len(proposal_ids), "raw_event_ids": raw_event_ids, "evidence_ids": evidence_ids, "provenance_edge_ids": edge_ids, "proposal_ids": proposal_ids, "record_summaries": record_summaries, "source_ref": external_ref, "audit_id": audit_id})
    return base


def _normalize_turn_payload(payload: dict[str, Any], *, profile_id: str, session_id: str | None = None) -> dict[str, Any]:
    profile_id = _safe_profile_id(profile_id)
    user_content = str(payload.get("user_content") or "")
    assistant_content = str(payload.get("assistant_content") or "")
    if not user_content.strip() and not assistant_content.strip():
        raise HermesProviderError("completed_turn_content_empty")
    raw_turn_id = str(payload.get("turn_id") or payload.get("id") or stable_id("turn", profile_id, session_id or "session", sha256_text(user_content), sha256_text(assistant_content)))
    turn_id = stable_id("turn", profile_id, session_id or payload.get("session_id") or "session", raw_turn_id)
    session = str(session_id or payload.get("session_id") or "controlled_session")
    messages = payload.get("messages") if isinstance(payload.get("messages"), list) else []
    combined = json_dumps({"turn_id": turn_id, "session_id": session, "user_content": user_content, "assistant_content": assistant_content, "messages": messages})
    return {"turn_id": turn_id, "session_id": session, "user_content": user_content, "assistant_content": assistant_content, "messages_count": len(messages), "content": combined, "content_hash": sha256_text(combined), "user_content_hash": sha256_text(user_content), "assistant_content_hash": sha256_text(assistant_content)}


def propose_completed_turn_sync(conn: sqlite3.Connection, *, profile_id: str, turn_payload: dict[str, Any] | None = None, turn_fixture_path: str | Path | None = None, allowed_turn_roots: list[str | Path] | tuple[str | Path, ...] | None = None, session_id: str | None = None, actor_id: str | None = None) -> dict[str, Any]:
    """Create source-grounded proposal rows from a controlled completed-turn input.

    This is proposal-only: it never promotes memories, writes markdown, reads live
    profile markdown, mutates Hermes config, calls Honcho, or activates a provider.
    """
    profile_id = _safe_profile_id(profile_id)
    base = _safe_turn_status_base(profile_id)
    source_metadata: dict[str, Any] = {"input_mode": "controlled_payload", "path_redacted": True}
    if turn_fixture_path is not None:
        try:
            turn_payload, source_metadata = _load_completed_turn_fixture(turn_fixture_path, allowed_turn_roots=allowed_turn_roots)
        except HermesProviderError as error:
            status = "denied" if "denied" in str(error) or "live_hermes" in str(error) else "degraded"
            audit_id = write_audit_event(conn, event_type="hermes.turn.sync.proposal", target_type="source", target_id="completed_turn:redacted", actor_id=actor_id, status=status, metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": False, "path_redacted": True})
            conn.commit()
            base.update({"status": "unauthorized" if status == "denied" else "degraded", "failure_reason": str(error), "proposal_created": False, "audit_id": audit_id})
            return base
    if turn_payload is None:
        audit_id = write_audit_event(conn, event_type="hermes.turn.sync.proposal", target_type="source", target_id="completed_turn:redacted", actor_id=actor_id, status="degraded", metadata={"profile_id": profile_id, "failure_reason": "completed_turn_source_missing", "content_read": False, "path_redacted": True})
        conn.commit()
        base.update({"status": "degraded", "failure_reason": "completed_turn_source_missing", "proposal_created": False, "audit_id": audit_id})
        return base
    try:
        turn = _normalize_turn_payload(turn_payload, profile_id=profile_id, session_id=session_id)
    except HermesProviderError as error:
        audit_id = write_audit_event(conn, event_type="hermes.turn.sync.proposal", target_type="source", target_id="completed_turn:redacted", actor_id=actor_id, status="degraded", metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": turn_fixture_path is not None, "path_redacted": True})
        conn.commit()
        base.update({"status": "degraded", "failure_reason": str(error), "proposal_created": False, "audit_id": audit_id})
        return base

    ensure_system_actor(conn)
    actor = actor_id or ensure_hermes_actor(conn, profile_id)
    timestamp = now_utc()
    source_id = stable_id("source", "completed_turn", profile_id, turn["session_id"])
    external_ref = _safe_turn_ref(profile_id, turn["session_id"], turn["turn_id"])
    conn.execute("""
        INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, failure_reason, provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, 'hermes_profile_memory', ?, ?, ?, 'session', 'read_only', 'propose_only', 'secondary', 'healthy', ?, 0, NULL, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET health='healthy', last_sync_at=excluded.last_sync_at, freshness_seconds=0, failure_reason=NULL, updated_at=excluded.updated_at
        """, (source_id, f"Controlled completed turn source ({profile_id})", external_ref, profile_id, timestamp, json_dumps({"adapter": "completed_turn_sync", "controlled_input_only": True, "path_redacted": True, "fallback_to_repo_docs_allowed": False}), json_dumps({"default_visibility": "private", "raw_turn_status_output_allowed": False, "profile_path_redacted": True}), timestamp, timestamp))
    session_row_id = stable_id("session", source_id, turn["session_id"])
    conn.execute("""
        INSERT INTO sessions(session_id, source_id, external_ref, title, started_at, status, privacy_class, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, 'Controlled completed turn fixture', ?, 'closed', 'private', ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET status='closed', updated_at=excluded.updated_at
        """, (session_row_id, source_id, external_ref, timestamp, json_dumps({"profile_id": profile_id, "session_key_hash": sha256_text(turn["session_id"]), "path_redacted": True}), timestamp, timestamp))
    snapshot_id = stable_id("snapshot", source_id, turn["content_hash"])
    conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, turn["content_hash"], external_ref, timestamp, json_dumps(source_metadata)))
    event_id = stable_id("event", source_id, turn["turn_id"], turn["content_hash"])
    event_hash = sha256_text(json_dumps({"event_id": event_id, "source_id": source_id, "content_hash": turn["content_hash"]}))
    conn.execute("""
        INSERT OR IGNORE INTO raw_events(event_id, session_id, source_id, snapshot_id, speaker_actor_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json, event_hash)
        VALUES (?, ?, ?, ?, ?, 'message', ?, ?, ?, ?, 'private', 'private', ?, ?, ?)
        """, (event_id, session_row_id, source_id, snapshot_id, actor, turn["content"], turn["content_hash"], timestamp, timestamp, external_ref, json_dumps({"profile_id": profile_id, "turn_id": turn["turn_id"], "messages_count": turn["messages_count"], "path_redacted": True, "controlled_input_only": True}), event_hash))
    evidence_id = stable_id("evidence", event_id)
    conn.execute("""
        INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at)
        VALUES (?, 'message', ?, ?, ?, ?, ?, ?, 0.7, 'private', ?, ?)
        """, (evidence_id, source_id, event_id, external_ref, json_dumps({"profile_id": profile_id, "turn_id": turn["turn_id"], "path_redacted": True, "content_hash_only": True}), "Controlled completed-turn evidence; raw transcript omitted from status output.", turn["content_hash"], timestamp, timestamp))
    edge_ids: list[str] = []
    for edge in [("source", source_id, "raw_event", event_id, "produced"), ("raw_event", event_id, "evidence", evidence_id, "quotes")]:
        edge_id = stable_id("edge", *edge)
        conn.execute("INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)", (edge_id, *edge, json_dumps({"adapter": "completed_turn_sync", "path_redacted": True}), timestamp))
        edge_ids.append(edge_id)
    proposal = create_proposal(
        conn,
        title="Completed turn memory proposal",
        summary="Review completed turn for possible durable memory.",
        body=f"User: {turn['user_content']}\nAssistant: {turn['assistant_content']}",
        evidence_ids=[evidence_id], source_event_ids=[event_id], privacy_class="private",
        memory_type="episodic", scope="actor", actor_id=actor,
        idempotency_key=f"completed-turn:{profile_id}:{turn['session_id']}:{turn['turn_id']}:{turn['content_hash']}",
    )
    audit_id = write_audit_event(conn, event_type="hermes.turn.sync.proposal", target_type="memory_proposal", target_id=proposal["proposal_id"], actor_id=actor, status="ok", metadata={"profile_id": profile_id, "source_id": source_id, "raw_event_id": event_id, "evidence_id": evidence_id, "provenance_edge_ids": edge_ids, "proposal_id": proposal["proposal_id"], "content_hash": turn["content_hash"], "user_content_hash": turn["user_content_hash"], "assistant_content_hash": turn["assistant_content_hash"], "content_included": False, "path_redacted": True, "automatic_memory_promotion": False, "markdown_writeback_performed": False})
    conn.commit()
    base.update({"status": "ok", "proposal_created": True, "source_id": source_id, "session_id": session_row_id, "raw_event_id": event_id, "evidence_id": evidence_id, "provenance_edge_ids": edge_ids, "proposal_id": proposal["proposal_id"], "proposal_status": proposal["proposal_status"], "content_hash": turn["content_hash"], "user_content_hash": turn["user_content_hash"], "assistant_content_hash": turn["assistant_content_hash"], "source_ref": external_ref, "audit_id": audit_id})
    return base

def ensure_hermes_actor(conn: sqlite3.Connection, profile_id: str) -> str:
    timestamp = now_utc()
    actor_id = stable_id("actor", "hermes_profile", profile_id)
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
        VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET display_name=excluded.display_name, handle=excluded.handle, updated_at=excluded.updated_at
        """,
        (
            actor_id,
            f"Hermes profile {profile_id}",
            f"hermes:{profile_id}",
            profile_id,
            json_dumps({"profile_id": profile_id, "profile_binding": "redacted"}),
            json_dumps({}),
            json_dumps({"source_family": "hermes_markdown_overflow", "profile_path_redacted": True}),
            timestamp,
            timestamp,
        ),
    )
    return actor_id


def register_profile_sources(conn: sqlite3.Connection, profile_id: str, profile_root: str | Path, *, allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> dict[str, Any]:
    """Register MEMORY.md and USER.md as redacted, profile-scoped read-only sources."""
    ensure_system_actor(conn)
    actor_id = ensure_hermes_actor(conn, _safe_profile_id(profile_id))
    timestamp = now_utc()
    registered: list[dict[str, Any]] = []
    for overflow_kind in ("memory_md", "user_md"):
        try:
            source = _source(profile_id, profile_root, overflow_kind, allowed_profile_roots=allowed_profile_roots)
            path = _validate_source_path(source, require_exists=False)
            if path.exists() and path.is_file():
                health = "healthy"
                failure_reason = None
                freshness_seconds = 0
            else:
                health = "unavailable"
                failure_reason = "configured Hermes markdown source missing"
                freshness_seconds = None
        except HermesProviderError as error:
            source = HermesMarkdownSource(_safe_profile_id(profile_id), Path("/redacted-denied-profile-root"), overflow_kind)
            health = "unauthorized"
            failure_reason = str(error)
            freshness_seconds = None
        conn.execute(
            """
            INSERT INTO sources(
              source_id, source_type, display_name, external_ref, profile_id, overflow_kind,
              read_authority, write_authority, authority_level, health, last_sync_at,
              freshness_seconds, failure_reason, provenance_rules_json, privacy_policy_json, created_at, updated_at
            ) VALUES (?, 'hermes_markdown_overflow', ?, ?, ?, ?, 'read_only', 'propose_only', 'secondary', ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO UPDATE SET
              display_name=excluded.display_name,
              external_ref=excluded.external_ref,
              profile_id=excluded.profile_id,
              overflow_kind=excluded.overflow_kind,
              read_authority=excluded.read_authority,
              write_authority=excluded.write_authority,
              authority_level=excluded.authority_level,
              health=excluded.health,
              last_sync_at=excluded.last_sync_at,
              freshness_seconds=excluded.freshness_seconds,
              failure_reason=excluded.failure_reason,
              provenance_rules_json=excluded.provenance_rules_json,
              privacy_policy_json=excluded.privacy_policy_json,
              updated_at=excluded.updated_at
            """,
            (
                source.source_id,
                f"Hermes {source.file_basename} overflow ({profile_id})",
                source.external_ref,
                profile_id,
                overflow_kind,
                health,
                timestamp if health == "healthy" else None,
                freshness_seconds,
                failure_reason,
                json_dumps({
                    "adapter": "hermes_markdown_overflow",
                    "path_policy": "profile_scoped_redacted",
                    "file_basename": source.file_basename,
                    "line_block_references": True,
                    "no_silent_fallback": True,
                }),
                json_dumps({
                    "default_visibility": "private" if overflow_kind == "memory_md" else "sensitive",
                    "redact_absolute_paths": True,
                    "profile_path_redacted": True,
                    "raw_prompt_internals_allowed": False,
                }),
                timestamp,
                timestamp,
            ),
        )
        registered.append({
            "source_id": source.source_id,
            "source_type": "hermes_markdown_overflow",
            "profile_id": profile_id,
            "overflow_kind": overflow_kind,
            "file_basename": source.file_basename,
            "external_ref": source.external_ref,
            "read_authority": "read_only",
            "write_authority": "propose_only",
            "health": health,
            "freshness_seconds": freshness_seconds,
            "failure_reason": failure_reason,
            "path_policy": "profile_scoped_redacted",
        })
    audit_id = write_audit_event(
        conn,
        event_type="hermes.sources.register",
        target_type="source",
        target_id=f"hermes_profile:{profile_id}",
        actor_id=actor_id,
        status="degraded" if any(item["health"] != "healthy" for item in registered) else "ok",
        metadata={"profile_id": profile_id, "registered_source_ids": [item["source_id"] for item in registered], "path_policy": "profile_scoped_redacted", "registration_nonce": time.time_ns()},
    )
    conn.commit()
    return {"status": "degraded" if any(item["health"] != "healthy" for item in registered) else "ok", "profile_id": profile_id, "sources": registered, "audit_id": audit_id}


def ingest_profile_markdown(conn: sqlite3.Connection, profile_id: str, profile_root: str | Path, *, allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None = None, _acquired_texts: dict[str, str] | None = None) -> dict[str, Any]:
    """Read-only ingest authorized controlled-profile MEMORY.md/USER.md blocks into local DB."""
    registration = register_profile_sources(conn, profile_id, profile_root, allowed_profile_roots=allowed_profile_roots)
    timestamp = now_utc()
    actor_id = ensure_hermes_actor(conn, profile_id)
    before_raw = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    before_evidence = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
    inserted_raw = 0
    inserted_evidence = 0
    inserted_provenance = 0
    degraded: list[dict[str, Any]] = []
    ingested_sources: list[str] = []
    source_summaries: list[dict[str, Any]] = []

    for item in registration["sources"]:
        source_id = item["source_id"]
        overflow_kind = item["overflow_kind"]
        if item["health"] != "healthy":
            degraded_item = {"source_id": source_id, "health": item["health"], "failure_reason": item["failure_reason"], "file_basename": item["file_basename"], "content_included": False, "path_redacted": True}
            degraded.append(degraded_item)
            source_summaries.append(degraded_item)
            continue
        try:
            source = _source(profile_id, profile_root, overflow_kind, allowed_profile_roots=allowed_profile_roots)
            text = _acquired_texts[overflow_kind] if _acquired_texts is not None else _read_markdown_no_follow(source)
        except (HermesProviderError, UnicodeDecodeError, OSError) as error:
            failure_reason = type(error).__name__ if not isinstance(error, HermesProviderError) else str(error)
            conn.execute("UPDATE sources SET health='degraded', failure_reason=?, updated_at=? WHERE source_id=?", (failure_reason, timestamp, source_id))
            degraded_item = {"source_id": source_id, "health": "degraded", "failure_reason": failure_reason, "file_basename": item["file_basename"], "content_included": False, "path_redacted": True}
            degraded.append(degraded_item)
            source_summaries.append(degraded_item)
            continue

        snapshot_hash = sha256_text(text)
        snapshot_id = stable_id("snapshot", source_id, snapshot_hash)
        block_hashes: list[str] = []
        conn.execute(
            """
            INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (snapshot_id, source_id, snapshot_hash, source.external_ref, timestamp, json_dumps({"profile_id": profile_id, "file_basename": source.file_basename, "path_redacted": True})),
        )
        for block_index, block in enumerate(_markdown_blocks(text), start=1):
            content = block["content"]
            content_hash = sha256_text(content)
            block_hashes.append(content_hash)
            privacy_class = _classify_privacy(overflow_kind, content)
            event_id = stable_id("event", source_id, block["line_start"], block["line_end"], content_hash)
            pointer = _redacted_pointer(profile_id, source.file_basename, block["line_start"], block["line_end"])
            event_hash = sha256_text(json_dumps({"event_id": event_id, "source_id": source_id, "content_hash": content_hash}))
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO raw_events(
                  event_id, source_id, snapshot_id, speaker_actor_id, event_type,
                  content, content_hash, occurred_at, ingested_at, visibility,
                  privacy_class, source_pointer, line_start, line_end, provenance_json, event_hash
                ) VALUES (?, ?, ?, ?, 'memory_block', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    source_id,
                    snapshot_id,
                    actor_id,
                    content,
                    content_hash,
                    timestamp,
                    timestamp,
                    privacy_class,
                    privacy_class,
                    pointer,
                    block["line_start"],
                    block["line_end"],
                    json_dumps({"profile_id": profile_id, "overflow_kind": overflow_kind, "file_basename": source.file_basename, "block_index": block_index, "path_redacted": True}),
                    event_hash,
                ),
            )
            if cur.rowcount > 0:
                inserted_raw += 1
            evidence_id = stable_id("evidence", event_id)
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO evidence_items(
                  evidence_id, kind, source_id, raw_event_id, uri, locator_json,
                  quote_text, content_hash, trust_score, privacy_class, observed_at, created_at
                ) VALUES (?, 'document', ?, ?, ?, ?, ?, ?, 0.65, ?, ?, ?)
                """,
                (
                    evidence_id,
                    source_id,
                    event_id,
                    source.external_ref,
                    json_dumps({"profile_id": profile_id, "overflow_kind": overflow_kind, "file_basename": source.file_basename, "line_start": block["line_start"], "line_end": block["line_end"], "path_redacted": True}),
                    content[:500],
                    content_hash,
                    privacy_class,
                    timestamp,
                    timestamp,
                ),
            )
            if cur.rowcount > 0:
                inserted_evidence += 1
            for edge in [
                ("source", source_id, "raw_event", event_id, "produced"),
                ("raw_event", event_id, "evidence", evidence_id, "quotes"),
            ]:
                edge_id = stable_id("edge", *edge)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)
                    """,
                    (edge_id, *edge, json_dumps({"adapter": "hermes_markdown_overflow", "path_redacted": True}), timestamp),
                )
                if cur.rowcount > 0:
                    inserted_provenance += 1
        ingested_sources.append(source_id)
        source_summaries.append({
            "source_id": source_id,
            "health": "healthy",
            "file_basename": source.file_basename,
            "snapshot_hash": snapshot_hash,
            "block_count": len(block_hashes),
            "content_hashes": block_hashes,
            "external_ref": source.external_ref,
            "content_included": False,
            "path_redacted": True,
        })
        conn.execute("UPDATE sources SET health='healthy', last_sync_at=?, freshness_seconds=0, failure_reason=NULL, updated_at=? WHERE source_id=?", (timestamp, timestamp, source_id))

    after_raw = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    after_evidence = conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
    status = "degraded" if degraded else "ok"
    audit_id = write_audit_event(
        conn,
        event_type="hermes.markdown.ingest",
        target_type="source",
        target_id=f"hermes_profile:{profile_id}",
        actor_id=actor_id,
        status=status,
        metadata={
            "profile_id": profile_id,
            "ingested_source_ids": ingested_sources,
            "degraded_sources": degraded,
            "source_summaries": source_summaries,
            "inserted_raw_events": inserted_raw,
            "inserted_evidence_items": inserted_evidence,
            "inserted_provenance_edges": inserted_provenance,
            "raw_event_count_before": before_raw,
            "raw_event_count_after": after_raw,
            "evidence_count_before": before_evidence,
            "evidence_count_after": after_evidence,
            "writeback_performed": False,
            "path_policy": "profile_scoped_redacted",
        },
    )
    conn.commit()
    return {
        "status": status,
        "profile_id": profile_id,
        "ingested_source_ids": ingested_sources,
        "degraded_sources": degraded,
        "source_summaries": source_summaries,
        "inserted_raw_events": inserted_raw,
        "inserted_evidence_items": inserted_evidence,
        "inserted_provenance_edges": inserted_provenance,
        "raw_event_count_before": before_raw,
        "raw_event_count_after": after_raw,
        "evidence_count_before": before_evidence,
        "evidence_count_after": after_evidence,
        "audit_id": audit_id,
        "file_mutation_performed": False,
        "content_included": False,
        "path_redacted": True,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "hermes_provider_config_mutated": False,
        "honcho_api_called": False,
    }


def _read_regular_at(root_fd: int, name: str, *, error_prefix: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise HermesProviderError(f"{error_prefix}_symlink_denied")
        if not stat.S_ISREG(before.st_mode):
            raise HermesProviderError(f"{error_prefix}_not_regular")
        descriptor = os.open(name, flags, dir_fd=root_fd)
    except OSError as exc:
        raise HermesProviderError(f"{error_prefix}_read_denied") from exc
    try:
        metadata = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode) != (metadata.st_dev, metadata.st_ino, metadata.st_mode):
            raise HermesProviderError(f"{error_prefix}_replaced_during_open")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _assert_profile_root_binding(root: Path, root_fd: int, error: str) -> None:
    try:
        path_metadata = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        raise HermesProviderError(error) from exc
    opened = os.fstat(root_fd)
    if not stat.S_ISDIR(path_metadata.st_mode) or (path_metadata.st_dev, path_metadata.st_ino) != (opened.st_dev, opened.st_ino):
        raise HermesProviderError(error)


def acquire_profile_markdown(conn: sqlite3.Connection, *, profile_id: str, profile_root: str | Path, approved: bool = False, allowed_profile_roots: list[str | Path] | tuple[str | Path, ...] | None = None) -> dict[str, Any]:
    """Explicit synthetic-only profile acquisition with a root/profile binding."""
    if not approved:
        raise HermesProviderError("profile_acquisition_approval_required")
    root = _validated_profile_root(profile_root, allowed_profile_roots=allowed_profile_roots)
    root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, root_flags)
    except OSError as exc:
        raise HermesProviderError("profile_root_open_denied") from exc
    try:
        try:
            _assert_profile_root_binding(root, root_fd, "profile_root_replaced_during_binding_read")
            marker_bytes = _read_regular_at(root_fd, ".mnemoir-profile.json", error_prefix="profile_binding")
            _assert_profile_root_binding(root, root_fd, "profile_root_replaced_during_binding_read")
            binding = json.loads(marker_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HermesProviderError("profile_binding_invalid") from exc
        if not isinstance(binding, dict) or binding.get("profile_id") != _safe_profile_id(profile_id) or binding.get("synthetic_only") is not True:
            raise HermesProviderError("profile_binding_mismatch")
        acquired: dict[str, str] = {}
        for overflow_kind, basename in MARKDOWN_FILES.items():
            data = _read_regular_at(root_fd, basename, error_prefix="markdown_source")
            _assert_profile_root_binding(root, root_fd, "profile_root_replaced_during_read")
            try:
                acquired[overflow_kind] = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HermesProviderError("markdown_source_read_denied") from exc
    finally:
        os.close(root_fd)
    result = ingest_profile_markdown(conn, profile_id, root, allowed_profile_roots=allowed_profile_roots, _acquired_texts=acquired)
    if result.get("degraded_sources"):
        reason = result["degraded_sources"][0].get("failure_reason") or "source_degraded"
        raise HermesProviderError(f"profile_acquisition_denied:{reason}")
    result.update({"acquisition": "explicit_approved_synthetic", "profile_binding_validated": True, "writeback_invoked": False})
    return result


def provider_status(conn: sqlite3.Connection, profile_id: str | None = None) -> dict[str, Any]:
    params: tuple[Any, ...] = ()
    where = "WHERE source_type IN ('hermes_markdown_overflow','session_search','obsidian_wiki')"
    if profile_id:
        where += " AND profile_id=?"
        params = (profile_id,)
    rows = conn.execute(
        f"""
        SELECT source_id, source_type, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, failure_reason
        FROM sources
        {where}
        ORDER BY profile_id, overflow_kind
        """,
        params,
    ).fetchall()
    return {
        "status": "ok",
        "provider": "mnemoir_local",
        "provider_surface": "local_context_and_tools",
        "markdown_writeback": "disabled_by_default",
        "write_authority": "propose_only",
        "live_io_performed": False,
        "sources": [row_to_dict(row) for row in rows],
    }


def markdown_writeback_status(profile_id: str) -> dict[str, Any]:
    _safe_profile_id(profile_id)
    return {
        "status": "denied",
        "profile_id": profile_id,
        "markdown_writeback": "disabled_by_default",
        "write_authority": "propose_only",
        "file_mutation_performed": False,
        "required_separate_authorization": "proposal_diff_expected_before_hash_atomic_write_audit_readback_rollback_controls",
        "controlled_fixture_execution_available": True,
        "controlled_fixture_root_required": True,
        "content_included": False,
        "path_redacted": True,
    }


def controlled_markdown_writeback_propose(conn: sqlite3.Connection, *, profile_id: str, fixture_root: str | Path, file_name: str, content: str, authorization: dict[str, Any] | None = None, actor_id: str | None = None, operation: str = "replace") -> dict[str, Any]:
    _safe_profile_id(profile_id)
    result = propose_writeback(conn, fixture_root=fixture_root, file_name=file_name, content=content, authorization=authorization, actor_id=actor_id, operation=operation)
    result.update({"provider": "mnemoir_local", "surface": "controlled_markdown_writeback_execution", "profile_id": profile_id, "real_profile_markdown_writeback": False, "hermes_provider_config_mutated": False, "honcho_api_called": False})
    return result


def controlled_markdown_writeback_execute(conn: sqlite3.Connection, *, profile_id: str, proposal_id: str, fixture_root: str | Path, file_name: str, expected_before_hash: str, expected_after_hash: str | None = None, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
    _safe_profile_id(profile_id)
    result = writeback_fixture(conn, proposal_id=proposal_id, fixture_root=fixture_root, file_name=file_name, expected_before_hash=expected_before_hash, expected_after_hash=expected_after_hash, authorization=authorization)
    result.update({"provider": "mnemoir_local", "surface": "controlled_markdown_writeback_execution", "profile_id": profile_id, "real_profile_markdown_writeback": False, "hermes_provider_config_mutated": False, "honcho_api_called": False})
    return result


def controlled_markdown_writeback_rollback(conn: sqlite3.Connection, *, profile_id: str, proposal_id: str, fixture_root: str | Path, file_name: str, previous_content: str, expected_current_hash: str | None = None, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
    _safe_profile_id(profile_id)
    result = rollback_fixture(conn, proposal_id=proposal_id, fixture_root=fixture_root, file_name=file_name, previous_content=previous_content, expected_current_hash=expected_current_hash, authorization=authorization)
    result.update({"provider": "mnemoir_local", "surface": "controlled_markdown_writeback_rollback", "profile_id": profile_id, "real_profile_markdown_writeback": False, "hermes_provider_config_mutated": False, "honcho_api_called": False})
    return result


def overflow_pressure_status(profile_id: str, fixture_root: str | Path) -> dict[str, Any]:
    """Leak-safe pressure status for caller-supplied controlled fixtures only."""
    return controlled_overflow_status(fixture_root, profile_id=_safe_profile_id(profile_id))


def overflow_compaction_plan_status(conn: sqlite3.Connection, profile_id: str, **kwargs: Any) -> dict[str, Any]:
    """Provider-visible, proposal-only overflow trim/compaction plan from Mnemoir rows."""
    return controlled_overflow_plan(conn, _safe_profile_id(profile_id), **kwargs)


def recall_for_profile(
    conn: sqlite3.Connection,
    query_text: str,
    *,
    profile_id: str,
    limit: int = 5,
    session_id: str | None = None,
    project_id: str | None = None,
    source_families: tuple[str, ...] = ("hermes_markdown_overflow", "hermes_profile_memory"),
) -> dict[str, Any]:
    """Run cited recall after deterministic profile source authorization."""
    authorization = authorized_sources_for_profile(
        conn,
        profile_id=_safe_profile_id(profile_id),
        session_id=session_id,
        project_id=project_id,
        source_families=source_families,
    )
    result = recall(
        conn,
        query_text,
        limit=limit,
        source_ids=authorization["authorized_source_ids"],
        source_coverage=authorization["source_coverage"],
        profile_id=profile_id,
        session_id=session_id,
        project_id=project_id,
    )
    result["profile_scope"] = authorization
    if authorization["status"] != "ok" and result["status"] == "abstain":
        result["status"] = "degraded"
    return result


def context_packet_for_profile(
    conn: sqlite3.Connection,
    query_text: str,
    *,
    profile_id: str,
    limit: int = 5,
    session_id: str | None = None,
    project_id: str | None = None,
    source_families: tuple[str, ...] = ("hermes_markdown_overflow", "hermes_profile_memory"),
    context_budget_chars: int | None = None,
) -> dict[str, Any]:
    return context_packet(
        conn,
        query_text,
        profile_id=profile_id,
        limit=limit,
        session_id=session_id,
        project_id=project_id,
        source_families=source_families,
        context_budget_chars=context_budget_chars,
    )


def _normalize_context_budget(context_budget_chars: int | None) -> int:
    if context_budget_chars is None:
        return DEFAULT_CONTEXT_BUDGET_CHARS
    try:
        budget = int(context_budget_chars)
    except (TypeError, ValueError) as exc:
        raise HermesProviderError("invalid_context_budget") from exc
    if budget < 1:
        raise HermesProviderError("invalid_context_budget")
    return max(MIN_CONTEXT_BUDGET_CHARS, min(MAX_CONTEXT_BUDGET_CHARS, budget))


def _safe_json_len(payload: Any) -> int:
    return len(json_dumps(payload))


def _context_item_annotations(conn: sqlite3.Connection, item: dict[str, Any]) -> dict[str, Any]:
    if item.get("target_type") == "memory":
        eligibility = item.get("eligibility") or {}
        return {
            "stale": False, "conflicting": False, "degraded": False,
            "missing_source": False, "low_confidence": False, "signals": [],
            "source_health": "healthy", "write_status": "canonical_active",
            "evidence_count": 1, "min_trust_score": None,
            "eligibility": eligibility,
        }
    row = conn.execute(
        """
        SELECT re.write_status, re.source_pointer, re.privacy_class, s.health, s.failure_reason,
               s.freshness_seconds, s.last_sync_at, s.source_type
        FROM raw_events re
        LEFT JOIN sources s ON s.source_id = re.source_id
        WHERE re.event_id = ?
        """,
        (item.get("target_id"),),
    ).fetchone()
    evidence_row = conn.execute(
        "SELECT MIN(trust_score) AS min_trust, COUNT(*) AS evidence_count FROM evidence_items WHERE raw_event_id = ?",
        (item.get("target_id"),),
    ).fetchone()
    conflict_count = conn.execute(
        """
        SELECT COUNT(*) FROM provenance_edges
        WHERE relation_type='contradicts'
          AND ((from_type='raw_event' AND from_id=?) OR (to_type='raw_event' AND to_id=?))
        """,
        (item.get("target_id"), item.get("target_id")),
    ).fetchone()[0]
    health = row["health"] if row and row["health"] is not None else "missing"
    write_status = row["write_status"] if row and row["write_status"] is not None else "missing"
    min_trust = evidence_row["min_trust"] if evidence_row and evidence_row["min_trust"] is not None else None
    degraded = health != "healthy" or write_status in {"quarantined", "redacted", "tombstoned"}
    missing_source = row is None or not item.get("source_id") or not item.get("source_pointer") or health == "missing"
    low_confidence = min_trust is not None and float(min_trust) < _LOW_CONFIDENCE_THRESHOLD
    stale = health in {"degraded", "unavailable", "unauthorized", "disabled", "missing"} or write_status in {"tombstoned", "redacted", "quarantined"}
    conflicting = conflict_count > 0
    signals: list[str] = []
    if stale:
        signals.append("stale_or_unhealthy_source")
    if conflicting:
        signals.append("conflicting_evidence")
    if degraded:
        signals.append("degraded_candidate")
    if missing_source:
        signals.append("missing_source_pointer")
    if low_confidence:
        signals.append("low_confidence")
    return {
        "stale": stale,
        "conflicting": conflicting,
        "degraded": degraded,
        "missing_source": missing_source,
        "low_confidence": low_confidence,
        "signals": signals,
        "source_health": health,
        "write_status": write_status,
        "evidence_count": int(evidence_row["evidence_count"] or 0) if evidence_row else 0,
        "min_trust_score": None if min_trust is None else float(min_trust),
    }


def _compact_context_item(item: dict[str, Any], *, snippet: str, truncated: bool, snippet_char_limit: int | None) -> dict[str, Any]:
    citation = item["citation"]
    compact_citation = {
        "source_id": citation.get("source_id") or item.get("source_id"),
        "source_pointer": citation.get("source_pointer"),
        "line_start": citation.get("line_start"),
        "line_end": citation.get("line_end"),
        "content_hash": citation.get("content_hash"),
        "occurred_at": citation.get("occurred_at"),
    }
    if item.get("target_type") == "memory":
        compact_citation["proposal_id"] = citation.get("proposal_id")
        compact_citation["memory_version"] = citation.get("memory_version")
    return {
        "rank": item["rank"],
        "packing_order": item["rank"],
        "target_type": item["target_type"],
        "target_id": item["target_id"],
        "source_id": item["source_id"],
        "citation": compact_citation,
        "annotations": item.get("annotations", {}),
        "evidence_window": item.get("evidence_window", {}),
        "snippet": snippet,
        "truncated": truncated,
        "snippet_char_limit": snippet_char_limit,
    }


def _pack_cited_context(candidates: list[dict[str, Any]], *, context_budget_chars: int) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    omissions: list[dict[str, Any]] = []
    truncation_count = 0
    for item in sorted(candidates, key=lambda value: int(value.get("rank") or 0)):
        snippet = str(item.get("snippet") or "")
        accepted = None
        for char_limit in [None, 500, 240, 120, 60, 20, 0]:
            trial_snippet = snippet if char_limit is None else snippet[:char_limit]
            trial = _compact_context_item(item, snippet=trial_snippet, truncated=char_limit is not None and len(snippet) > len(trial_snippet), snippet_char_limit=char_limit)
            if _safe_json_len({"items": selected + [trial]}) <= context_budget_chars:
                accepted = trial
                break
        if accepted is None:
            omissions.append({"rank": item.get("rank"), "target_id": item.get("target_id"), "source_id": item.get("source_id"), "reason": "context_budget_exhausted"})
            continue
        if accepted["truncated"]:
            truncation_count += 1
        selected.append(accepted)
    payload = {"items": selected}
    used = _safe_json_len(payload)
    omission_reasons = Counter(str(item["reason"]) for item in omissions)
    status = "ok"
    if omissions or truncation_count:
        status = "degraded"
    if not selected and candidates:
        status = "blocked"
    return {
        "items": selected,
        "packed_payload": json_dumps(payload),
        "budget": {
            "limit_chars": context_budget_chars,
            "used_chars": used,
            "remaining_chars": max(0, context_budget_chars - used),
            "accounting": "json_dumps_char_count",
            "default_applied": context_budget_chars == DEFAULT_CONTEXT_BUDGET_CHARS,
        },
        "status": status,
        "candidate_count": len(candidates),
        "packed_count": len(selected),
        "omitted_count": len(omissions),
        "omission_reasons": dict(omission_reasons),
        "omissions": omissions,
        "truncation_count": truncation_count,
        "summarization": {"used": False, "mode": "deterministic_snippet_truncation", "uncited_summaries_allowed": False},
    }


def context_packet(
    conn: sqlite3.Connection,
    query_text: str,
    *,
    profile_id: str | None = None,
    limit: int = 5,
    session_id: str | None = None,
    project_id: str | None = None,
    source_families: tuple[str, ...] = ("hermes_markdown_overflow", "hermes_profile_memory"),
    context_budget_chars: int | None = None,
) -> dict[str, Any]:
    start = time.monotonic()
    context_budget = _normalize_context_budget(context_budget_chars)
    if profile_id:
        result = recall_for_profile(conn, query_text, profile_id=profile_id, limit=limit, session_id=session_id, project_id=project_id, source_families=source_families)
    else:
        result = recall(conn, query_text, limit=limit)
    candidate_items = []
    for item in result.get("cited_results", []):
        candidate_items.append({
            "rank": item["rank"],
            "target_type": item["target_type"],
            "target_id": item["target_id"],
            "source_id": item["source_id"],
            "citation": {
                "source_id": item["source_id"],
                "source_pointer": item["source_pointer"] or f"redacted-missing-source-pointer:{item['content_hash']}",
                "line_start": item["line_start"],
                "line_end": item["line_end"],
                "content_hash": item["content_hash"],
                "occurred_at": item["occurred_at"],
                "proposal_id": item.get("proposal_id"),
                "memory_version": item.get("memory_version"),
            },
            "snippet": extract_answer_bearing_window(item["snippet"], query_text)["window"] or item["snippet"],
            "evidence_window": extract_answer_bearing_window(item["snippet"], query_text),
            "annotations": _context_item_annotations(conn, item),
        })
    packed = _pack_cited_context(candidate_items, context_budget_chars=context_budget)
    cited_items = packed["items"]
    warnings = []
    coverage = dict(result.get("source_coverage", {}))
    missing_or_degraded = list(coverage.get("missing_or_degraded_sources", []))
    if profile_id and not missing_or_degraded:
        # Preserve compat 07 provider visibility that configured Hermes markdown
        # coverage can be degraded without exposing another profile's identifier
        # or substituting that source into the profile-scoped recall set.
        global_degraded_count = conn.execute(
            """
            SELECT COUNT(*) FROM sources
            WHERE source_type='hermes_markdown_overflow'
              AND read_authority!='none'
              AND health!='healthy'
            """
        ).fetchone()[0]
        if global_degraded_count:
            missing_or_degraded.append({
                "source_id": "redacted_unavailable_profile_source",
                "health": "unavailable",
                "failure_reason": "configured Hermes markdown source unavailable",
            })
            coverage["missing_or_degraded_sources"] = missing_or_degraded
            coverage["coverage_status"] = "degraded"
            if result.get("status") == "ok":
                result["status"] = "degraded"
    if missing_or_degraded:
        warnings.append("source_coverage_degraded")
    if packed["status"] in {"degraded", "blocked"}:
        warnings.append(f"context_budget_{packed['status']}")
    if packed["omitted_count"]:
        warnings.append("context_omissions_recorded")
    if packed["truncation_count"]:
        warnings.append("context_truncation_recorded")
    candidate_annotation_present = any(any(item.get("annotations", {}).get(flag) for flag in ("stale", "conflicting", "degraded", "missing_source", "low_confidence")) for item in cited_items)
    if candidate_annotation_present:
        warnings.append("context_candidate_annotations_present")
    if not cited_items:
        warnings.append("no_cited_context_available")
    packet_id = f"context_{time.time_ns()}_{stable_id('nonce', query_text, id(result))[-12:]}"
    packet_status = result["status"]
    if packed["status"] == "blocked":
        packet_status = "blocked"
    elif packed["status"] == "degraded" and packet_status == "ok":
        packet_status = "degraded"
    elif candidate_annotation_present and packet_status == "ok":
        packet_status = "degraded"
    packet = {
        "status": packet_status,
        "provider": "mnemoir_local",
        "packet_id": packet_id,
        "profile_id": profile_id,
        "query_id": result["query_id"],
        "query_hash": result["query_hash"],
        "context_policy": {
            "uncited_context_allowed": False,
            "heat_is_truth_authority": False,
            "silent_fallback_allowed": False,
            "profile_paths_redacted": True,
            "profile_source_filter_required": bool(profile_id),
            "fallback_to_repo_docs_allowed": False if profile_id else None,
            "fallback_to_honcho_allowed": False if profile_id else None,
            "fallback_to_session_search_allowed": False if profile_id else None,
            "fallback_to_obsidian_allowed": False if profile_id else None,
            "budget_authorization_before_packing_required": True,
            "uncited_summarization_allowed": False,
        },
        "warnings": warnings,
        "query_routing": classify_query_type(query_text).__dict__,
        "evidence_window_policy": {"extractive_only": True, "fabrication_allowed": False, "citation_metadata_preserved": True},
        "source_coverage": coverage,
        "profile_scope": result.get("profile_scope"),
        "cited_context": cited_items,
        "packed_context": {
            "payload_json": packed["packed_payload"],
            "budget": packed["budget"],
            "status": packed["status"],
            "candidate_count": packed["candidate_count"],
            "packed_count": packed["packed_count"],
            "omitted_count": packed["omitted_count"],
            "omission_reasons": packed.get("omission_reasons", {}),
            "omissions": packed.get("omissions", []),
            "truncation_count": packed["truncation_count"],
            "summarization": packed["summarization"],
            "profile_scope_filter_before_packing": bool(profile_id),
        },
        "latency_ms": int((time.monotonic() - start) * 1000),
    }
    write_audit_event(
        conn,
        event_type="hermes.context.packet",
        target_type="retrieval_query",
        target_id=result["query_id"],
        status="degraded" if packet["status"] == "degraded" else ("warning" if not cited_items else "ok"),
        metadata={"packet_id": packet_id, "profile_id": profile_id, "cited_count": len(cited_items), "warnings": warnings, "source_filter_applied": bool(profile_id), "context_budget": packed["budget"], "context_omitted_count": packed["omitted_count"], "context_truncation_count": packed["truncation_count"]},
    )
    conn.commit()
    return packet


def tool_manifest() -> dict[str, Any]:
    return {
        "status": "ok",
        "provider": "mnemoir_local",
        "tools": [
            {"name": "context", "description": "Return cited, source-grounded local context packet."},
            {"name": "search", "description": "Run cited local recall through Mnemoir Provenance."},
            {"name": "sources", "description": "Inspect redacted Hermes markdown source health."},
            {"name": "overflow_pressure", "description": "Inspect controlled-fixture MEMORY.md/USER.md overflow pressure without reading live profile markdown or mutating files."},
            {"name": "overflow_plan", "description": "Plan reviewable trim/compaction candidates from already-ingested Mnemoir overflow rows without reading or writing markdown files."},
            {"name": "ingest_profile", "description": "Read-only ingest explicitly supplied temp profile MEMORY.md/USER.md."},
            {"name": "sync_turn_proposal", "description": "Create proposal-only memory candidates from controlled completed-turn fixtures."},
            {"name": "import_honcho_legacy", "description": "Import controlled local Honcho export fixtures as source-grounded draft/proposal legacy records without live Honcho API calls."},
            {"name": "writeback_status", "description": "Report default denied/propose_only markdown writeback posture."},
            {"name": "controlled_markdown_writeback", "description": "Execute approved reversible markdown writeback only against explicit temporary controlled fixtures with expected-before-hash, audit, read-back, and rollback controls."},
        ],
        "forbidden_surfaces": ["gateway_restart", "provider_config_mutation", "credential_access", "cron_autostart", "live_network_io", "markdown_writeback_default"],
    }
