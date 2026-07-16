"""Controlled additional source adapters for compat 15-G11 / GAP-009.

These adapters ingest only caller-supplied controlled fixtures. They never read
live session_search databases, live Hermes profiles, Honcho APIs, or unrestricted
Obsidian vaults, and status payloads expose hashes/counts/redacted pointers only.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, sha256_text, stable_id
from .ingest import ensure_system_actor
from .scope import grant_scope

PRIVACY_CLASSES = {"public", "internal", "private", "sensitive", "secret"}
BACKUP_PARTS = {"backup", "backups", ".backup", "archive", "archives"}
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n?", re.S)
LINK_RE = re.compile(r"\[\[([^\]]+)\]\]")


class SourceAdapterError(ValueError):
    """Fail-closed controlled adapter boundary error."""


def _safe_profile_id(profile_id: str) -> str:
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        raise SourceAdapterError("unauthorized_profile_id")
    return profile_id


def _contains_live_profile(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".hermes" in parts and "profiles" in parts


def _contains_backup(path: Path) -> bool:
    return any(part.lower() in BACKUP_PARTS or part.lower().endswith((".bak", ".backup", "~")) for part in path.parts)


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise SourceAdapterError("symlink_adapter_path_denied")
        except OSError as exc:  # pragma: no cover
            raise SourceAdapterError("adapter_path_unreadable") from exc


def _is_under(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
    except OSError:
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _is_controlled(path: Path, roots: list[str | Path] | tuple[str | Path, ...] | None) -> bool:
    try:
        if _is_under(path, Path(tempfile.gettempdir()).resolve(strict=True)):
            return True
    except OSError:
        pass
    for item in roots or []:
        raw = Path(item).expanduser()
        if ".." in raw.parts or _contains_backup(raw) or _contains_live_profile(raw):
            continue
        if _is_under(path, raw.resolve(strict=False)):
            return True
    return False


def _validate_controlled_path(path_value: str | Path, *, allowed_roots: list[str | Path] | tuple[str | Path, ...] | None, require_dir: bool, suffixes: set[str] | None = None) -> Path:
    raw = Path(path_value).expanduser()
    if ".." in raw.parts:
        raise SourceAdapterError("path_traversal_denied")
    if _contains_backup(raw):
        raise SourceAdapterError("backup_adapter_path_denied")
    if _contains_live_profile(raw):
        raise SourceAdapterError("live_hermes_profile_adapter_path_denied")
    _assert_no_symlink_components(raw)
    path = raw.resolve(strict=False)
    if _contains_backup(path):
        raise SourceAdapterError("backup_adapter_path_denied")
    if _contains_live_profile(path):
        raise SourceAdapterError("live_hermes_profile_adapter_path_denied")
    if not _is_controlled(path, allowed_roots):
        raise SourceAdapterError("non_controlled_adapter_source_denied")
    if not path.exists():
        raise SourceAdapterError("adapter_source_missing")
    if require_dir and not path.is_dir():
        raise SourceAdapterError("adapter_source_not_directory")
    if not require_dir and not path.is_file():
        raise SourceAdapterError("adapter_source_not_file")
    if suffixes is not None and path.suffix.lower() not in suffixes:
        raise SourceAdapterError("unsupported_adapter_fixture_type")
    return path


def _status_base(profile_id: str, surface: str) -> dict[str, Any]:
    return {
        "provider": "mnemoir_local",
        "surface": surface,
        "profile_id": profile_id,
        "content_included": False,
        "path_redacted": True,
        "redacted_pointers_only": True,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "hermes_provider_config_mutated": False,
        "honcho_api_called": False,
        "session_search_db_read": False,
        "vault_absolute_paths_exposed": False,
        "automatic_memory_promotion": False,
        "markdown_writeback_performed": False,
        "review_required": True,
    }


def _ensure_actor(conn: sqlite3.Connection, profile_id: str, actor_id: str | None) -> str:
    timestamp = now_utc()
    resolved = actor_id or stable_id("actor", "hermes_profile", profile_id)
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
        VALUES (?, 'agent', ?, ?, ?, ?, '{}', ?, ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (resolved, f"Hermes profile {profile_id}", f"hermes:{profile_id}", profile_id, json_dumps({"profile_id": profile_id, "profile_binding": "redacted"}), json_dumps({"profile_path_redacted": True}), timestamp, timestamp),
    )
    return resolved


def _register_source(conn: sqlite3.Connection, *, source_id: str, source_type: str, display_name: str, external_ref: str, profile_id: str, overflow_kind: str, fixture_hash: str, adapter: str, timestamp: str) -> None:
    conn.execute(
        """
        INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, failure_reason, provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'read_only', 'propose_only', 'secondary', 'healthy', ?, 0, NULL, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET health='healthy', last_sync_at=excluded.last_sync_at, freshness_seconds=0, failure_reason=NULL, updated_at=excluded.updated_at
        """,
        (
            source_id,
            source_type,
            display_name,
            external_ref,
            profile_id,
            overflow_kind,
            timestamp,
            json_dumps({"adapter": adapter, "controlled_fixture_only": True, "path_redacted": True, "priority_conflict_policy": "support_or_propose_only_no_silent_override", "fixture_hash": fixture_hash}),
            json_dumps({"default_visibility": "private", "profile_scoped_authorization_required": True, "raw_status_output_allowed": False, "redact_absolute_paths": True}),
            timestamp,
            timestamp,
        ),
    )


def _insert_event_graph(conn: sqlite3.Connection, *, source_id: str, snapshot_id: str, session_id: str | None, actor_id: str, content: str, content_hash: str, occurred_at: str, privacy_class: str, pointer: str, event_type: str, evidence_kind: str, provenance: dict[str, Any], adapter: str, timestamp: str) -> tuple[str, str, list[str], int, int]:
    event_id = stable_id("event", source_id, pointer, content_hash)
    event_hash = sha256_text(json_dumps({"event_id": event_id, "source_id": source_id, "content_hash": content_hash}))
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO raw_events(event_id, session_id, source_id, snapshot_id, speaker_actor_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json, write_status, event_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)
        """,
        (event_id, session_id, source_id, snapshot_id, actor_id, event_type, content, content_hash, occurred_at, timestamp, privacy_class, privacy_class, pointer, json_dumps(provenance), event_hash),
    )
    inserted_raw = 1 if cur.rowcount > 0 else 0
    evidence_id = stable_id("evidence", event_id)
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.6, ?, ?, ?)
        """,
        (evidence_id, evidence_kind, source_id, event_id, pointer, json_dumps({**provenance, "content_hash_only": True}), "Controlled adapter evidence; raw private content omitted from status output.", content_hash, privacy_class, occurred_at, timestamp),
    )
    inserted_evidence = 1 if cur.rowcount > 0 else 0
    edge_ids: list[str] = []
    for edge in [("source", source_id, "raw_event", event_id, "produced"), ("raw_event", event_id, "evidence", evidence_id, "quotes")]:
        edge_id = stable_id("edge", *edge)
        conn.execute("INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)", (edge_id, *edge, json_dumps({"adapter": adapter, "path_redacted": True, "priority_conflict_policy": "support_or_propose_only_no_silent_override"}), timestamp))
        edge_ids.append(edge_id)
    return event_id, evidence_id, edge_ids, inserted_raw, inserted_evidence


def _load_session_records(path: Path) -> tuple[list[dict[str, Any]], str]:
    try:
        if path.suffix.lower() == ".jsonl":
            payload: Any = {"messages": [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]}
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceAdapterError("session_search_fixture_malformed") from exc
    if isinstance(payload, list):
        payload = {"messages": payload}
    if not isinstance(payload, dict):
        raise SourceAdapterError("session_search_fixture_invalid")
    records: list[dict[str, Any]] = []
    raw_sessions = payload.get("sessions")
    sessions: list[Any] = raw_sessions if isinstance(raw_sessions, list) else []
    for session_index, session in enumerate(sessions, start=1):
        if not isinstance(session, dict):
            raise SourceAdapterError("session_search_session_invalid")
        session_key = str(session.get("session_id") or session.get("id") or f"session-{session_index}")
        title_hash = sha256_text(str(session.get("title") or "Controlled session_search transcript"))
        raw_messages = session.get("messages")
        messages: list[Any] = raw_messages if isinstance(raw_messages, list) else []
        for message_index, message in enumerate(messages, start=1):
            records.append(_normalize_session_message(message, session_key, title_hash, message_index))
    top_messages = payload.get("messages") or payload.get("records") or payload.get("items")
    if isinstance(top_messages, list):
        session_key = str(payload.get("session_id") or "controlled_session_search_export")
        title_hash = sha256_text(str(payload.get("title") or "Controlled session_search transcript"))
        for message_index, message in enumerate(top_messages, start=1):
            records.append(_normalize_session_message(message, session_key, title_hash, message_index))
    if not records:
        raise SourceAdapterError("session_search_fixture_missing_messages")
    return records, sha256_text(json_dumps(payload))


def _normalize_session_message(message: Any, session_key: str, title_hash: str, index: int) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise SourceAdapterError("session_search_message_invalid")
    content = str(message.get("content") or message.get("text") or message.get("message") or "")
    if not content.strip():
        raise SourceAdapterError("session_search_message_missing_content")
    privacy = str(message.get("privacy_class") or "private")
    if privacy not in PRIVACY_CLASSES:
        privacy = "private"
    return {
        "record_id": stable_id("session_search_record", session_key, message.get("id") or message.get("message_id") or index),
        "session_key": session_key,
        "title_hash": title_hash,
        "role": str(message.get("role") or message.get("speaker") or "unknown")[:32],
        "occurred_at": str(message.get("created_at") or message.get("timestamp") or message.get("when") or now_utc()),
        "privacy_class": privacy,
        "content": content,
        "content_hash": sha256_text(content),
        "metadata_hash": sha256_text(json_dumps({k: v for k, v in message.items() if k not in {"content", "text", "message"}})),
    }


def import_session_search_fixture(conn: sqlite3.Connection, *, profile_id: str, session_fixture_path: str | Path | None = None, allowed_session_roots: list[str | Path] | tuple[str | Path, ...] | None = None, actor_id: str | None = None) -> dict[str, Any]:
    profile_id = _safe_profile_id(profile_id)
    base = _status_base(profile_id, "session_search_import_adapter")
    if session_fixture_path is None:
        audit_id = write_audit_event(conn, event_type="session_search.import", target_type="source", target_id="session_search:redacted", actor_id=actor_id, status="degraded", metadata={"profile_id": profile_id, "failure_reason": "session_search_fixture_missing", "content_read": False, "path_redacted": True, "session_search_db_read": False})
        conn.commit()
        base.update({"status": "degraded", "failure_reason": "session_search_fixture_missing", "records_imported": 0, "audit_id": audit_id})
        return base
    try:
        path = _validate_controlled_path(session_fixture_path, allowed_roots=allowed_session_roots, require_dir=False, suffixes={".json", ".jsonl"})
        records, fixture_hash = _load_session_records(path)
    except SourceAdapterError as error:
        denied = any(marker in str(error) for marker in ["denied", "live_hermes", "traversal", "symlink", "backup"])
        audit_id = write_audit_event(conn, event_type="session_search.import", target_type="source", target_id="session_search:redacted", actor_id=actor_id, status="denied" if denied else "degraded", metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": False, "path_redacted": True, "session_search_db_read": False})
        conn.commit()
        base.update({"status": "unauthorized" if denied else "degraded", "failure_reason": str(error), "records_imported": 0, "audit_id": audit_id})
        return base
    ensure_system_actor(conn)
    actor = _ensure_actor(conn, profile_id, actor_id)
    timestamp = now_utc()
    source_id = stable_id("source", "session_search", profile_id, fixture_hash)
    external_ref = f"session-search://{profile_id}/{source_id}"
    _register_source(conn, source_id=source_id, source_type="session_search", display_name=f"Controlled session_search export ({profile_id})", external_ref=external_ref, profile_id=profile_id, overflow_kind="session", fixture_hash=fixture_hash, adapter="session_search_import_adapter", timestamp=timestamp)
    grant_scope(conn, actor_id=actor, scope_type="source", scope_id=source_id, permission="read", commit=False)
    snapshot_id = stable_id("snapshot", source_id, fixture_hash)
    conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, fixture_hash, external_ref, timestamp, json_dumps({"fixture_hash": fixture_hash, "path_redacted": True, "adapter": "session_search_import_adapter"})))
    inserted_raw = inserted_evidence = 0
    edge_ids: list[str] = []
    summaries: list[dict[str, Any]] = []
    for record in records:
        session_row_id = stable_id("session", source_id, record["session_key"])
        session_ref = f"{external_ref}/{stable_id('session_ref', record['session_key'])}"
        conn.execute("INSERT INTO sessions(session_id, source_id, external_ref, title, started_at, status, privacy_class, metadata_json, created_at, updated_at) VALUES (?, ?, ?, 'Controlled session_search import session', ?, 'closed', ?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET status='closed', updated_at=excluded.updated_at", (session_row_id, source_id, session_ref, timestamp, record["privacy_class"], json_dumps({"profile_id": profile_id, "session_key_hash": sha256_text(record["session_key"]), "title_hash": record["title_hash"], "path_redacted": True}), timestamp, timestamp))
        pointer = f"session-search://{profile_id}/{stable_id('session_ref', record['session_key'])}/{record['record_id']}"
        event_id, evidence_id, edges, raw_count, evidence_count = _insert_event_graph(conn, source_id=source_id, snapshot_id=snapshot_id, session_id=session_row_id, actor_id=actor, content=record["content"], content_hash=record["content_hash"], occurred_at=record["occurred_at"], privacy_class=record["privacy_class"], pointer=pointer, event_type="message", evidence_kind="message", provenance={"profile_id": profile_id, "record_id": record["record_id"], "role": record["role"], "metadata_hash": record["metadata_hash"], "controlled_input_only": True, "path_redacted": True, "review_required": True}, adapter="session_search_import_adapter", timestamp=timestamp)
        inserted_raw += raw_count
        inserted_evidence += evidence_count
        edge_ids.extend(edges)
        summaries.append({"record_id": record["record_id"], "raw_event_id": event_id, "evidence_id": evidence_id, "content_hash": record["content_hash"], "source_pointer": pointer, "privacy_class": record["privacy_class"], "content_included": False, "path_redacted": True})
    audit_id = write_audit_event(conn, event_type="session_search.import", target_type="source", target_id=source_id, actor_id=actor, status="ok", metadata={"profile_id": profile_id, "source_id": source_id, "import_batch_id": snapshot_id, "records_imported": len(records), "content_hashes": [s["content_hash"] for s in summaries], "content_included": False, "path_redacted": True, "session_search_db_read": False, "priority_conflict_policy": "support_or_propose_only_no_silent_override"})
    conn.commit()
    base.update({"status": "ok", "source_id": source_id, "import_batch_id": snapshot_id, "snapshot_hash": fixture_hash, "records_imported": len(records), "inserted_raw_events": inserted_raw, "inserted_evidence_items": inserted_evidence, "inserted_provenance_edges": len(edge_ids), "record_summaries": summaries, "provenance_edge_ids": edge_ids, "source_ref": external_ref, "audit_id": audit_id, "source_priority_conflict_policy": "support_or_propose_only_no_silent_override", "proposal_policy": "evidence_only_review_proposal_deferred", "proposal_staged_count": 0, "canonical_promotion_count": 0, "active_memory_bloat_prevented": True})
    return base


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    meta: dict[str, Any] = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip("'\"")
    return meta, text[match.end():]


def import_obsidian_vault_fixture(conn: sqlite3.Connection, *, profile_id: str, vault_root: str | Path | None = None, allowed_vault_roots: list[str | Path] | tuple[str | Path, ...] | None = None, actor_id: str | None = None, include_derived_projection: bool = False) -> dict[str, Any]:
    profile_id = _safe_profile_id(profile_id)
    base = _status_base(profile_id, "obsidian_vault_import_adapter")
    if vault_root is None:
        audit_id = write_audit_event(conn, event_type="obsidian_vault.import", target_type="source", target_id="obsidian:redacted", actor_id=actor_id, status="degraded", metadata={"profile_id": profile_id, "failure_reason": "obsidian_vault_fixture_missing", "content_read": False, "path_redacted": True})
        conn.commit()
        base.update({"status": "degraded", "failure_reason": "obsidian_vault_fixture_missing", "records_imported": 0, "audit_id": audit_id})
        return base
    try:
        root = _validate_controlled_path(vault_root, allowed_roots=allowed_vault_roots, require_dir=True)
        degraded: list[dict[str, Any]] = []
        loaded: list[dict[str, Any]] = []
        snapshot_parts: list[str] = []
        for path in sorted(root.rglob("*.md")):
            rel_path = path.relative_to(root)
            rel = rel_path.as_posix()
            if path.is_symlink():
                degraded.append({"relative_pointer": rel, "reason": "symlink_file_skipped", "content_read": False})
                continue
            if _contains_backup(rel_path):
                degraded.append({"relative_pointer": rel, "reason": "backup_file_skipped", "content_read": False})
                continue
            if not include_derived_projection and any(part.lower() in {"generated", "projection", "wiki_projection", "derived"} for part in rel_path.parts):
                degraded.append({"relative_pointer": rel, "reason": "derived_projection_skipped", "content_read": False})
                continue
            text = path.read_text(encoding="utf-8")
            frontmatter, body = _parse_frontmatter(text)
            privacy = str(frontmatter.get("privacy_class") or "private")
            if privacy not in PRIVACY_CLASSES:
                privacy = "private"
            content_hash = sha256_text(text)
            snapshot_parts.append(f"{rel}:{content_hash}")
            loaded.append({"relative_path": rel, "content": text, "content_hash": content_hash, "body_hash": sha256_text(body), "frontmatter_hash": sha256_text(json_dumps(frontmatter)), "frontmatter_keys": sorted(frontmatter), "links": sorted(set(LINK_RE.findall(text))), "privacy_class": privacy})
        if not loaded:
            raise SourceAdapterError("obsidian_vault_fixture_no_markdown")
        fixture_hash = sha256_text("\n".join(sorted(snapshot_parts)))
    except (SourceAdapterError, OSError, UnicodeDecodeError) as error:
        denied = any(marker in str(error) for marker in ["denied", "live_hermes", "traversal", "symlink", "backup"])
        audit_id = write_audit_event(conn, event_type="obsidian_vault.import", target_type="source", target_id="obsidian:redacted", actor_id=actor_id, status="denied" if denied else "degraded", metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": False, "path_redacted": True})
        conn.commit()
        base.update({"status": "unauthorized" if denied else "degraded", "failure_reason": str(error), "records_imported": 0, "audit_id": audit_id})
        return base
    ensure_system_actor(conn)
    actor = _ensure_actor(conn, profile_id, actor_id)
    timestamp = now_utc()
    source_id = stable_id("source", "obsidian_wiki", profile_id, fixture_hash)
    external_ref = f"obsidian-vault://{profile_id}/{source_id}"
    _register_source(conn, source_id=source_id, source_type="obsidian_wiki", display_name=f"Controlled Obsidian vault import ({profile_id})", external_ref=external_ref, profile_id=profile_id, overflow_kind="wiki", fixture_hash=fixture_hash, adapter="obsidian_vault_import_adapter", timestamp=timestamp)
    grant_scope(conn, actor_id=actor, scope_type="source", scope_id=source_id, permission="read", commit=False)
    snapshot_id = stable_id("snapshot", source_id, fixture_hash)
    conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, fixture_hash, external_ref, timestamp, json_dumps({"fixture_hash": fixture_hash, "path_redacted": True, "adapter": "obsidian_vault_import_adapter", "derived_projection_imported": include_derived_projection})))
    inserted_raw = inserted_evidence = 0
    edge_ids: list[str] = []
    summaries: list[dict[str, Any]] = []
    for note in loaded:
        pointer = f"obsidian-vault://{profile_id}/{source_id}/{note['relative_path']}"
        event_id, evidence_id, edges, raw_count, evidence_count = _insert_event_graph(conn, source_id=source_id, snapshot_id=snapshot_id, session_id=None, actor_id=actor, content=note["content"], content_hash=note["content_hash"], occurred_at=timestamp, privacy_class=note["privacy_class"], pointer=pointer, event_type="file_block", evidence_kind="document", provenance={"profile_id": profile_id, "relative_path": note["relative_path"], "frontmatter_hash": note["frontmatter_hash"], "frontmatter_keys": note["frontmatter_keys"], "link_count": len(note["links"]), "links_hash": sha256_text(json_dumps(note["links"])), "controlled_input_only": True, "path_redacted": True, "derived_projection_imported": include_derived_projection, "review_required": True}, adapter="obsidian_vault_import_adapter", timestamp=timestamp)
        inserted_raw += raw_count
        inserted_evidence += evidence_count
        edge_ids.extend(edges)
        summaries.append({"relative_pointer": note["relative_path"], "raw_event_id": event_id, "evidence_id": evidence_id, "content_hash": note["content_hash"], "frontmatter_hash": note["frontmatter_hash"], "link_count": len(note["links"]), "source_pointer": pointer, "content_included": False, "path_redacted": True})
    audit_id = write_audit_event(conn, event_type="obsidian_vault.import", target_type="source", target_id=source_id, actor_id=actor, status="degraded" if degraded else "ok", metadata={"profile_id": profile_id, "source_id": source_id, "import_batch_id": snapshot_id, "records_imported": len(loaded), "degraded_inputs": degraded, "content_hashes": [s["content_hash"] for s in summaries], "content_included": False, "path_redacted": True, "vault_absolute_paths_exposed": False, "derived_projection_imported": include_derived_projection, "priority_conflict_policy": "support_or_propose_only_no_silent_override"})
    conn.commit()
    base.update({"status": "degraded" if degraded else "ok", "source_id": source_id, "import_batch_id": snapshot_id, "snapshot_hash": fixture_hash, "records_imported": len(loaded), "inserted_raw_events": inserted_raw, "inserted_evidence_items": inserted_evidence, "inserted_provenance_edges": len(edge_ids), "record_summaries": summaries, "degraded_inputs": degraded, "provenance_edge_ids": edge_ids, "source_ref": external_ref, "audit_id": audit_id, "derived_wiki_projection_distinct": True, "derived_projection_imported": include_derived_projection, "source_priority_conflict_policy": "support_or_propose_only_no_silent_override", "proposal_policy": "evidence_only_review_proposal_deferred", "proposal_staged_count": 0, "canonical_promotion_count": 0, "active_memory_bloat_prevented": True})
    return base
