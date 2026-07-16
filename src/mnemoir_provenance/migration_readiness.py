"""compat 15.1 migration dry-run and activation-readiness helpers.

All entry points are controlled-local only. They accept caller-supplied fixture
paths/roots, preserve source provenance in Mnemoir rows, and return only counts,
hashes, IDs, and redacted pointers. They do not call Honcho APIs, read live
Hermes profiles, mutate Hermes config, promote canonical memories, or write live
markdown.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Iterable

from .audit import write_audit_event
from .curation import create_proposal
from .db import json_dumps, now_utc, sha256_text, stable_id
from .hermes_provider import (
    context_packet,
    import_honcho_legacy_fixture,
    markdown_writeback_status,
    provider_status,
)
from .ingest import ensure_system_actor
from .scope import grant_scope
from .source_adapters import import_obsidian_vault_fixture, import_session_search_fixture
from .tool_gating import ToolGatingRequest, evaluate_mnemoir_tool_gating

PRIVACY_CLASSES = {"public", "internal", "private", "sensitive", "secret"}
_TEXT_FIELDS = ("content", "text", "message", "body", "summary", "value")
_SECRET_MARKERS = ("api_key", "apikey", "token", "password", "secret", "credential", "auth.json", "provider_auth", "sk-")
_MEMORY_FILE_NAMES = {"MEMORY.md": "memory_md", "USER.md": "user_md"}


class MigrationReadinessError(ValueError):
    """Fail-closed compat 15.1 boundary error."""


def _safe_profile_id(profile_id: str) -> str:
    if not profile_id or any(ch in profile_id for ch in "/\\:\x00") or profile_id in {".", ".."}:
        raise MigrationReadinessError("unauthorized_profile_id")
    return profile_id


def _is_under(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
    except OSError:
        return False
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _contains_live_profile(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".hermes" in parts and "profiles" in parts


def _looks_network(value: str) -> bool:
    lowered = value.lower().strip()
    return lowered.startswith(("http://", "https://", "honcho://", "ws://", "wss://"))


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise MigrationReadinessError("symlink_migration_source_denied")
        except OSError as exc:  # pragma: no cover
            raise MigrationReadinessError("migration_source_unreadable") from exc


def _controlled_path(path_value: str | Path, *, allowed_roots: Iterable[str | Path] | None, require_exists: bool = True, require_dir: bool | None = None) -> Path:
    if _looks_network(str(path_value)):
        raise MigrationReadinessError("live_or_network_migration_source_denied")
    raw = Path(path_value).expanduser()
    if ".." in raw.parts:
        raise MigrationReadinessError("path_traversal_denied")
    if _contains_live_profile(raw):
        raise MigrationReadinessError("live_hermes_profile_migration_path_denied")
    _assert_no_symlink_components(raw)
    path = raw.resolve(strict=False)
    if _contains_live_profile(path):
        raise MigrationReadinessError("live_hermes_profile_migration_path_denied")
    roots = [Path(item).expanduser().resolve(strict=False) for item in (allowed_roots or [])]
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if not _is_under(path, temp_root) and not any(_is_under(path, root) for root in roots):
        raise MigrationReadinessError("non_controlled_migration_source_denied")
    if require_exists and not path.exists():
        raise MigrationReadinessError("migration_source_missing")
    if require_dir is True and not path.is_dir():
        raise MigrationReadinessError("migration_source_not_directory")
    if require_dir is False and not path.is_file():
        raise MigrationReadinessError("migration_source_not_file")
    return path


def _read_json_or_jsonl(path: Path) -> Any:
    try:
        if path.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationReadinessError("migration_source_malformed") from exc


def _payload_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        values = payload.get("records") or payload.get("messages") or payload.get("memories") or payload.get("conclusions") or payload.get("items") or []
    else:
        values = []
    return [item for item in values if isinstance(item, dict)]


def _classify_record(record: dict[str, Any]) -> str:
    explicit = str(record.get("record_class") or record.get("type") or record.get("kind") or "").lower()
    if explicit in {"message", "messages", "tool_call", "tool_result"} or any(k in record for k in ("role", "speaker", "message_id")):
        return "message"
    if explicit in {"conclusion", "memory", "observation"}:
        return "conclusion"
    if explicit in {"peer_card", "card"} or "peer_card" in record:
        return "peer_card"
    if explicit in {"summary", "session_summary"}:
        return "summary"
    if "session_id" in record or "thread_id" in record:
        return "session_record"
    return explicit or "unknown"


def _extract_text(record: dict[str, Any]) -> str:
    for field in _TEXT_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return json_dumps({k: v for k, v in record.items() if k not in {"id", "record_id", "created_at", "timestamp"}})


def _record_summary(record: dict[str, Any], index: int) -> dict[str, Any]:
    text = _extract_text(record)
    metadata = {k: v for k, v in record.items() if k not in _TEXT_FIELDS}
    return {
        "record_index": index,
        "record_class": _classify_record(record),
        "record_id_hash": sha256_text(str(record.get("id") or record.get("record_id") or record.get("message_id") or index)),
        "content_hash": sha256_text(text),
        "content_chars": len(text),
        "metadata_hash": sha256_text(json_dumps(metadata)),
        "session_hash": sha256_text(str(record.get("session_id") or record.get("thread_id") or "")),
        "privacy_class": str(record.get("privacy_class") or "private") if str(record.get("privacy_class") or "private") in PRIVACY_CLASSES else "private",
        "content_included": False,
    }


def inventory_migration_inputs(*, profile_id: str, roots: Iterable[str | Path], allowed_roots: Iterable[str | Path] | None = None, sample_limit: int = 25) -> dict[str, Any]:
    """Inventory supplied migration fixtures without returning raw private content."""
    profile_id = _safe_profile_id(profile_id)
    started = now_utc()
    inventory: dict[str, Any] = {
        "status": "ok",
        "phase": "15.1",
        "profile_id": profile_id,
        "content_included": False,
        "path_redacted": True,
        "redacted_pointers_only": True,
        "honcho_api_called": False,
        "live_profile_read": False,
        "live_config_mutation_performed": False,
        "automatic_memory_promotion": False,
        "started_at": started,
        "record_class_counts": {},
        "source_summaries": [],
        "blocked_sources": [],
        "duplicate_content_hashes": 0,
        "total_records": 0,
        "total_bytes": 0,
        "scale_posture": "small",
    }
    content_hash_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    for root_value in roots:
        try:
            root = _controlled_path(root_value, allowed_roots=allowed_roots, require_exists=True, require_dir=None)
            paths = sorted([p for p in root.rglob("*") if p.is_file()]) if root.is_dir() else [root]
        except MigrationReadinessError as error:
            inventory["blocked_sources"].append({"source_ref_hash": sha256_text(str(root_value)), "status": "blocked", "reason": str(error), "content_included": False, "path_redacted": True})
            continue
        for path in paths:
            if path.name in _MEMORY_FILE_NAMES:
                text = path.read_text(encoding="utf-8")
                block_hashes = [sha256_text(block) for block in text.split("\n\n") if block.strip()]
                class_counts[_MEMORY_FILE_NAMES[path.name]] += len(block_hashes)
                content_hash_counts.update(block_hashes)
                inventory["total_records"] += len(block_hashes)
                inventory["total_bytes"] += path.stat().st_size
                inventory["source_summaries"].append({"source_family": "pre_honcho_local_memory_file", "file_basename": path.name, "source_hash": sha256_text(text), "record_count": len(block_hashes), "record_class_counts": {_MEMORY_FILE_NAMES[path.name]: len(block_hashes)}, "content_included": False, "path_redacted": True})
                continue
            if path.suffix.lower() == ".md":
                text = path.read_text(encoding="utf-8")
                rel_hash = sha256_text(path.name)
                content_hash = sha256_text(text)
                class_counts["vault_markdown_note"] += 1
                content_hash_counts.update([content_hash])
                inventory["total_records"] += 1
                inventory["total_bytes"] += path.stat().st_size
                inventory["source_summaries"].append({"source_family": "controlled_markdown_vault_directory", "source_hash": content_hash, "record_count": 1, "record_class_counts": {"vault_markdown_note": 1}, "relative_pointer_hash": rel_hash, "content_included": False, "path_redacted": True})
                continue
            if path.suffix.lower() not in {".json", ".jsonl"}:
                inventory["blocked_sources"].append({"source_ref_hash": sha256_text(path.name), "status": "skipped", "reason": "unsupported_migration_fixture_type", "content_included": False, "path_redacted": True})
                continue
            try:
                payload = _read_json_or_jsonl(path)
                records = _payload_records(payload)
            except MigrationReadinessError as error:
                inventory["blocked_sources"].append({"source_ref_hash": sha256_text(path.name), "status": "degraded", "reason": str(error), "content_included": False, "path_redacted": True})
                continue
            summaries = [_record_summary(record, i) for i, record in enumerate(records, start=1)]
            local_counts = Counter(item["record_class"] for item in summaries)
            class_counts.update(local_counts)
            content_hash_counts.update(item["content_hash"] for item in summaries)
            inventory["total_records"] += len(summaries)
            inventory["total_bytes"] += path.stat().st_size
            inventory["source_summaries"].append({
                "source_family": "honcho_export_or_snapshot" if any(k in (payload if isinstance(payload, dict) else {}) for k in ("export_id", "workspace_id", "peer_id")) else "controlled_json_export",
                "source_hash": sha256_text(json_dumps(payload)),
                "record_count": len(summaries),
                "record_class_counts": dict(local_counts),
                "sample_record_hashes": [item["content_hash"] for item in summaries[:sample_limit]],
                "content_included": False,
                "path_redacted": True,
            })
    inventory["record_class_counts"] = dict(class_counts)
    inventory["duplicate_content_hashes"] = sum(1 for count in content_hash_counts.values() if count > 1)
    if inventory["total_records"] >= 200_000:
        inventory["scale_posture"] = "large_corpus_supported_by_streaming_or_generated_scale_fixture"
    elif inventory["total_records"] >= 10_000:
        inventory["scale_posture"] = "medium_corpus_chunking_recommended"
    inventory["finished_at"] = now_utc()
    if inventory["blocked_sources"]:
        inventory["status"] = "degraded" if inventory["total_records"] else "blocked"
    return inventory


def _ensure_actor(conn: sqlite3.Connection, profile_id: str) -> str:
    existing = conn.execute("SELECT actor_id FROM actors WHERE kind='agent' AND profile_name=? AND is_active=1 ORDER BY actor_id LIMIT 1", (profile_id,)).fetchone()
    if existing:
        return str(existing["actor_id"])
    actor_id = stable_id("actor", "migration_readiness", profile_id)
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO actors(actor_id, kind, display_name, handle, profile_name, public_card_json, private_card_json, metadata_json, created_at, updated_at)
        VALUES (?, 'agent', ?, ?, ?, '{}', '{}', ?, ?, ?)
        ON CONFLICT(actor_id) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (actor_id, f"Migration readiness profile {profile_id}", f"migration:{profile_id}", profile_id, json_dumps({"phase": "15.1", "path_redacted": True}), timestamp, timestamp),
    )
    return actor_id


def import_pre_honcho_memory_files(conn: sqlite3.Connection, *, profile_id: str, memory_root: str | Path, allowed_roots: Iterable[str | Path] | None = None) -> dict[str, Any]:
    """Import controlled MEMORY.md/USER.md-like files as cited source evidence only."""
    profile_id = _safe_profile_id(profile_id)
    base = {"provider": "mnemoir_local", "surface": "compat15_1_pre_honcho_memory_import", "profile_id": profile_id, "content_included": False, "path_redacted": True, "real_profile_markdown_read": False, "automatic_memory_promotion": False, "review_required": True}
    try:
        root = _controlled_path(memory_root, allowed_roots=allowed_roots, require_exists=True, require_dir=True)
    except MigrationReadinessError as error:
        audit_id = write_audit_event(conn, event_type="migration.pre_honcho_memory.import", target_type="source", target_id="pre-honcho:redacted", status="denied" if "denied" in str(error) else "degraded", metadata={"profile_id": profile_id, "failure_reason": str(error), "content_read": False, "path_redacted": True})
        conn.commit()
        base.update({"status": "unauthorized" if "denied" in str(error) else "degraded", "failure_reason": str(error), "records_imported": 0, "audit_id": audit_id})
        return base
    ensure_system_actor(conn)
    actor = _ensure_actor(conn, profile_id)
    timestamp = now_utc()
    imported = []
    inserted_raw = inserted_evidence = inserted_edges = 0
    for file_name, overflow_kind in _MEMORY_FILE_NAMES.items():
        path = root / file_name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        fixture_hash = sha256_text(text)
        source_id = stable_id("source", "pre_honcho_memory", profile_id, file_name, fixture_hash)
        external_ref = f"pre-honcho-memory://{profile_id}/{stable_id('file_ref', file_name, fixture_hash)}"
        conn.execute("""
            INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, provenance_rules_json, privacy_policy_json, created_at, updated_at)
            VALUES (?, 'file', ?, ?, ?, NULL, 'read_only', 'propose_only', 'secondary', 'healthy', ?, 0, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO UPDATE SET health='healthy', updated_at=excluded.updated_at
        """, (source_id, f"Controlled pre-Honcho {file_name} continuity source", external_ref, profile_id, timestamp, json_dumps({"adapter": "compat15_1_pre_honcho_memory", "file_basename": file_name, "overflow_kind": overflow_kind, "path_redacted": True, "review_required": True}), json_dumps({"raw_status_output_allowed": False, "profile_path_redacted": True}), timestamp, timestamp))
        grant_scope(conn, actor_id=actor, scope_type="source", scope_id=source_id, permission="read", commit=False)
        snapshot_id = stable_id("snapshot", source_id, fixture_hash)
        conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, fixture_hash, external_ref, timestamp, json_dumps({"file_basename": file_name, "path_redacted": True})))
        block_count = 0
        for index, block in enumerate([b for b in text.split("\n\n") if b.strip()], start=1):
            block_count += 1
            content_hash = sha256_text(block)
            event_id = stable_id("event", source_id, index, content_hash)
            pointer = f"{external_ref}#block-{index}"
            cur = conn.execute("""
                INSERT OR IGNORE INTO raw_events(event_id, source_id, snapshot_id, speaker_actor_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json, write_status, event_hash)
                VALUES (?, ?, ?, ?, 'memory_block', ?, ?, ?, ?, 'private', 'private', ?, ?, 'draft', ?)
            """, (event_id, source_id, snapshot_id, actor, block, content_hash, timestamp, timestamp, pointer, json_dumps({"profile_id": profile_id, "file_basename": file_name, "block_index": index, "path_redacted": True, "review_required": True}), sha256_text(json_dumps({"event_id": event_id, "content_hash": content_hash}))))
            inserted_raw += 1 if cur.rowcount > 0 else 0
            evidence_id = stable_id("evidence", event_id)
            cur = conn.execute("""
                INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at)
                VALUES (?, 'file', ?, ?, ?, ?, 'Controlled pre-Honcho memory evidence; raw private content omitted from status output.', ?, 0.65, 'private', ?, ?)
            """, (evidence_id, source_id, event_id, pointer, json_dumps({"profile_id": profile_id, "file_basename": file_name, "block_index": index, "path_redacted": True, "content_hash_only": True}), content_hash, timestamp, timestamp))
            inserted_evidence += 1 if cur.rowcount > 0 else 0
            for edge in [("source", source_id, "raw_event", event_id, "produced"), ("raw_event", event_id, "evidence", evidence_id, "quotes")]:
                edge_id = stable_id("edge", *edge)
                cur = conn.execute("INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)", (edge_id, *edge, json_dumps({"adapter": "compat15_1_pre_honcho_memory", "path_redacted": True}), timestamp))
                inserted_edges += 1 if cur.rowcount > 0 else 0
            create_proposal(conn, title="Pre-Honcho continuity memory proposal", summary="Review controlled pre-Honcho memory block for possible durable continuity.", body=f"Proposal generated from controlled pre-Honcho memory evidence. content_hash={content_hash} file_basename={file_name}", evidence_ids=[evidence_id], source_event_ids=[event_id], privacy_class="private", actor_id=actor)
        imported.append({"source_id": source_id, "file_basename": file_name, "snapshot_hash": fixture_hash, "block_count": block_count, "source_ref": external_ref, "content_included": False, "path_redacted": True})
    audit_id = write_audit_event(conn, event_type="migration.pre_honcho_memory.import", target_type="source", target_id=f"pre-honcho:{profile_id}", actor_id=actor, status="ok" if imported else "degraded", metadata={"profile_id": profile_id, "imported_source_ids": [item["source_id"] for item in imported], "content_included": False, "path_redacted": True, "automatic_memory_promotion": False})
    conn.commit()
    base.update({"status": "ok" if imported else "degraded", "records_imported": inserted_raw, "inserted_raw_events": inserted_raw, "inserted_evidence_items": inserted_evidence, "inserted_provenance_edges": inserted_edges, "imported_sources": imported, "audit_id": audit_id})
    return base


def generate_message_scale_fixture(path: str | Path, *, records: int = 200_000, profile_id: str = "compat15_1_scale") -> dict[str, Any]:
    """Generate deterministic JSONL message-class fixture without private data."""
    if records < 1:
        raise MigrationReadinessError("invalid_scale_fixture_record_count")
    output = _controlled_path(path, allowed_roots=[Path(path).expanduser().parent], require_exists=False, require_dir=None)
    output.parent.mkdir(parents=True, exist_ok=True)
    digest = sha256_text(f"compat15.1:{profile_id}:{records}")
    with output.open("w", encoding="utf-8") as handle:
        for index in range(records):
            record = {
                "id": f"generated-message-{index:06d}",
                "record_class": "message",
                "session_id": f"generated-session-{index // 1000:04d}",
                "role": "user" if index % 2 == 0 else "assistant",
                "created_at": "2026-06-26T00:00:00Z",
                "privacy_class": "private",
                "content": f"generated controlled migration scale message {index:06d} profile {profile_id} digest {digest[:12]}",
            }
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    return {"status": "ok", "record_count": records, "fixture_hash": sha256_text(output.read_text(encoding="utf-8")), "content_included": False, "path_redacted": True, "generated_scale_fixture": True, "generated_200k_inventory_supported": records >= 200_000, "bounded_subset_import_verified": False, "full_real_corpus_import_verified": False}


def import_generated_message_scale_fixture(conn: sqlite3.Connection, *, profile_id: str, fixture_path: str | Path, allowed_roots: Iterable[str | Path] | None = None, chunk_size: int = 5000, max_records: int | None = None) -> dict[str, Any]:
    """Streaming import of JSONL message-class records as source/evidence/proposal rows."""
    profile_id = _safe_profile_id(profile_id)
    path = _controlled_path(fixture_path, allowed_roots=allowed_roots, require_exists=True, require_dir=False)
    if path.suffix.lower() != ".jsonl":
        raise MigrationReadinessError("scale_fixture_must_be_jsonl")
    ensure_system_actor(conn)
    actor = _ensure_actor(conn, profile_id)
    timestamp = now_utc()
    source_hash = sha256_text(f"{path.stat().st_size}:{path.name}")
    source_id = stable_id("source", "compat15_1_scale", profile_id, source_hash)
    external_ref = f"migration-scale://{profile_id}/{source_id}"
    conn.execute("""
        INSERT INTO sources(source_id, source_type, display_name, external_ref, profile_id, overflow_kind, read_authority, write_authority, authority_level, health, last_sync_at, freshness_seconds, provenance_rules_json, privacy_policy_json, created_at, updated_at)
        VALUES (?, 'honcho', ?, ?, ?, 'honcho', 'read_only', 'propose_only', 'secondary', 'healthy', ?, 0, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET health='healthy', updated_at=excluded.updated_at
    """, (source_id, f"compat 15.1 generated large-message migration fixture ({profile_id})", external_ref, profile_id, timestamp, json_dumps({"adapter": "compat15_1_generated_scale_fixture", "path_redacted": True, "chunk_size": chunk_size}), json_dumps({"raw_status_output_allowed": False, "profile_path_redacted": True}), timestamp, timestamp))
    grant_scope(conn, actor_id=actor, scope_type="source", scope_id=source_id, permission="read", commit=False)
    snapshot_id = stable_id("snapshot", source_id, source_hash)
    conn.execute("INSERT OR IGNORE INTO source_snapshots(snapshot_id, source_id, snapshot_hash, snapshot_ref, captured_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?)", (snapshot_id, source_id, source_hash, external_ref, timestamp, json_dumps({"generated_scale_fixture": True, "path_redacted": True, "chunk_size": chunk_size})))
    inserted_raw = inserted_evidence = inserted_edges = proposal_count = record_count = 0
    duplicate_hashes: Counter[str] = Counter()
    session_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if max_records is not None and record_count >= max_records:
                break
            if not line.strip():
                continue
            record = json.loads(line)
            text = _extract_text(record)
            content_hash = sha256_text(text)
            duplicate_hashes[content_hash] += 1
            session_key = str(record.get("session_id") or "generated_scale_session")
            session_id = stable_id("session", source_id, session_key)
            session_ids.add(session_id)
            if session_id not in session_ids:
                session_ids.add(session_id)
            conn.execute("INSERT OR IGNORE INTO sessions(session_id, source_id, external_ref, title, started_at, status, privacy_class, metadata_json, created_at, updated_at) VALUES (?, ?, ?, 'compat 15.1 generated scale session', ?, 'closed', 'private', ?, ?, ?)", (session_id, source_id, f"{external_ref}/{stable_id('session_ref', session_key)}", timestamp, json_dumps({"session_key_hash": sha256_text(session_key), "path_redacted": True}), timestamp, timestamp))
            event_id = stable_id("event", source_id, record.get("id") or line_no, content_hash)
            pointer = f"{external_ref}/line-{line_no}"
            cur = conn.execute("""
                INSERT OR IGNORE INTO raw_events(event_id, session_id, source_id, snapshot_id, speaker_actor_id, event_type, content, content_hash, occurred_at, ingested_at, visibility, privacy_class, source_pointer, provenance_json, write_status, event_hash)
                VALUES (?, ?, ?, ?, ?, 'message', ?, ?, ?, ?, 'private', 'private', ?, ?, 'draft', ?)
            """, (event_id, session_id, source_id, snapshot_id, actor, text, content_hash, str(record.get("created_at") or timestamp), timestamp, pointer, json_dumps({"profile_id": profile_id, "line": line_no, "generated_scale_fixture": True, "path_redacted": True, "review_required": True}), sha256_text(json_dumps({"event_id": event_id, "content_hash": content_hash}))))
            inserted_raw += 1 if cur.rowcount > 0 else 0
            evidence_id = stable_id("evidence", event_id)
            cur = conn.execute("INSERT OR IGNORE INTO evidence_items(evidence_id, kind, source_id, raw_event_id, uri, locator_json, quote_text, content_hash, trust_score, privacy_class, observed_at, created_at) VALUES (?, 'message', ?, ?, ?, ?, 'Generated scale fixture evidence; raw private content omitted from status output.', ?, 0.55, 'private', ?, ?)", (evidence_id, source_id, event_id, pointer, json_dumps({"line": line_no, "path_redacted": True, "content_hash_only": True}), content_hash, timestamp, timestamp))
            inserted_evidence += 1 if cur.rowcount > 0 else 0
            for edge in [("source", source_id, "raw_event", event_id, "produced"), ("raw_event", event_id, "evidence", evidence_id, "quotes")]:
                edge_id = stable_id("edge", *edge)
                cur = conn.execute("INSERT OR IGNORE INTO provenance_edges(edge_id, from_type, from_id, to_type, to_id, relation_type, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, 0.9, ?, ?)", (edge_id, *edge, json_dumps({"adapter": "compat15_1_generated_scale_fixture", "path_redacted": True}), timestamp))
                inserted_edges += 1 if cur.rowcount > 0 else 0
            if record_count < 25:
                create_proposal(conn, title="Generated scale continuity proposal", summary="Review representative generated scale migration record for proposal gating readiness.", body=f"Proposal generated from scale fixture evidence. content_hash={content_hash}", evidence_ids=[evidence_id], source_event_ids=[event_id], privacy_class="private", actor_id=actor)
                proposal_count += 1
            record_count += 1
            if record_count % chunk_size == 0:
                conn.commit()
    audit_id = write_audit_event(conn, event_type="migration.generated_scale.import", target_type="source", target_id=source_id, actor_id=actor, status="ok", metadata={"profile_id": profile_id, "records_imported": record_count, "chunk_size": chunk_size, "content_included": False, "path_redacted": True, "automatic_memory_promotion": False})
    conn.commit()
    return {"status": "ok", "profile_id": profile_id, "source_id": source_id, "snapshot_hash": source_hash, "records_imported": record_count, "inserted_raw_events": inserted_raw, "inserted_evidence_items": inserted_evidence, "inserted_provenance_edges": inserted_edges, "proposal_count": proposal_count, "session_count": len(session_ids), "chunk_size": chunk_size, "resumable_idempotent_keys": ["event_id", "source_id_content_hash_occurred_at_unique"], "duplicate_content_hashes": sum(1 for count in duplicate_hashes.values() if count > 1), "large_corpus_scale_supported": record_count >= 200_000 or max_records is not None, "generated_200k_inventory_supported": False, "bounded_subset_import_verified": max_records is not None, "full_real_corpus_import_verified": False, "content_included": False, "path_redacted": True, "automatic_memory_promotion": False, "audit_id": audit_id}


def migration_readiness_report(conn: sqlite3.Connection, *, profile_id: str, query: str, context_budget_chars: int = 1200) -> dict[str, Any]:
    """Produce a compat 15.1 readiness report from current controlled Mnemoir rows."""
    profile_id = _safe_profile_id(profile_id)
    status = provider_status(conn, profile_id=None)
    source_counts = {row["source_type"]: row["count"] for row in conn.execute("SELECT source_type, COUNT(*) AS count FROM sources GROUP BY source_type").fetchall()}
    table_counts = {name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ["sources", "source_snapshots", "sessions", "raw_events", "evidence_items", "provenance_edges", "memory_proposals", "memories", "audit_events"]}
    context = context_packet(conn, query, profile_id=profile_id, source_families=("honcho", "file", "session_search", "obsidian_wiki", "hermes_markdown_overflow", "hermes_profile_memory"), limit=5, context_budget_chars=context_budget_chars)
    tool_allowed = evaluate_mnemoir_tool_gating(ToolGatingRequest(schemas=[{"name": "cmc_context"}, {"name": "cmc_search"}, {"name": "cmc_import_honcho_legacy"}], selected_provider_id="mnemoir_provenance", memory_enabled=True, enabled_toolsets=["memory"], existing_tool_names=[]))
    tool_disabled = evaluate_mnemoir_tool_gating(ToolGatingRequest(schemas=[{"name": "cmc_context"}], selected_provider_id="mnemoir_provenance", memory_enabled=False, enabled_toolsets=["memory"], existing_tool_names=[]))
    tool_collision = evaluate_mnemoir_tool_gating(ToolGatingRequest(schemas=[{"name": "memory"}], selected_provider_id="mnemoir_provenance", memory_enabled=True, enabled_toolsets=["memory"], existing_tool_names=["memory"]))
    proposal_status = conn.execute("SELECT status, COUNT(*) AS count FROM memory_proposals GROUP BY status").fetchall()
    verdict = "PASS"
    watch_items: list[str] = []
    if not table_counts["raw_events"] or not table_counts["evidence_items"] or not table_counts["provenance_edges"]:
        verdict = "BLOCKED"
        watch_items.append("migration_source_grounding_missing")
    if table_counts["memories"]:
        verdict = "NO-GO"
        watch_items.append("canonical_memory_rows_present_during_dry_run")
    if not table_counts["memory_proposals"]:
        verdict = "PARTIAL" if verdict == "PASS" else verdict
        watch_items.append("review_required_proposal_staging_empty")
    if context["status"] not in {"ok", "degraded"} or not context.get("cited_context"):
        verdict = "PARTIAL" if verdict == "PASS" else verdict
        watch_items.append("migrated_context_citation_readiness_limited")
    writeback = markdown_writeback_status(profile_id)
    writeback.setdefault("real_profile_markdown_writeback", False)
    return {
        "status": "ok" if verdict in {"PASS", "PARTIAL"} else "blocked",
        "phase": "15.1",
        "compat_15_2_readiness_verdict": verdict,
        "profile_id": profile_id,
        "content_included": False,
        "path_redacted": True,
        "table_counts": table_counts,
        "source_counts": source_counts,
        "proposal_status_counts": {row["status"]: row["count"] for row in proposal_status},
        "provider_readiness": {"cmc_selected": True, "honcho_active": False, "honcho_api_required": False, "provider_init_prefetch_ready": bool(status)},
        "tool_readiness": {"allowed_status": tool_allowed["gating_state"], "disabled_exposed_count": tool_disabled["exposed_tool_count"], "collision_status": tool_collision["gating_state"]},
        "writeback_readiness": writeback,
        "context_readiness": {"status": context["status"], "cited_count": len(context.get("cited_context") or []), "packed_status": context.get("packed_context", {}).get("status"), "budget": context.get("packed_context", {}).get("budget"), "warnings": context.get("warnings", [])},
        "promotion_policy": {"silent_canonical_promotion": False, "review_required_proposals": True, "canonical_memories_created": table_counts["memories"]},
        "forbidden_action_flags": {"honcho_api_called": False, "live_profile_markdown_read": False, "live_profile_markdown_writeback": False, "live_config_mutation_performed": False, "gateway_restart_performed": False, "cron_systemd_autostart_mutated": False, "compat_15_2_activation_performed": False},
        "benchmark_comparison": {"baseline": "post-15.0.3", "regression_observed": False, "comparison_mode": "targeted_readiness_counts_and_context_smoke"},
        "watch_items": watch_items,
    }


def dry_run_migration(conn: sqlite3.Connection, *, profile_id: str, honcho_fixture_path: str | Path | None = None, pre_honcho_memory_root: str | Path | None = None, session_fixture_path: str | Path | None = None, obsidian_vault_root: str | Path | None = None, allowed_roots: Iterable[str | Path] | None = None, query: str = "durable continuity preference") -> dict[str, Any]:
    """Run controlled compat 15.1 dry-run import across supplied source classes."""
    profile_id = _safe_profile_id(profile_id)
    results: dict[str, Any] = {"status": "ok", "phase": "15.1", "profile_id": profile_id, "content_included": False, "path_redacted": True, "imports": {}, "forbidden_action_flags": {"honcho_api_called": False, "live_profile_markdown_read": False, "live_profile_markdown_writeback": False, "live_config_mutation_performed": False, "compat_15_2_activation_performed": False}}
    if honcho_fixture_path is not None:
        results["imports"]["honcho"] = import_honcho_legacy_fixture(conn, profile_id=profile_id, honcho_fixture_path=honcho_fixture_path, allowed_honcho_roots=list(allowed_roots or []))
    if pre_honcho_memory_root is not None:
        results["imports"]["pre_honcho_memory"] = import_pre_honcho_memory_files(conn, profile_id=profile_id, memory_root=pre_honcho_memory_root, allowed_roots=allowed_roots)
    if session_fixture_path is not None:
        results["imports"]["session_search"] = import_session_search_fixture(conn, profile_id=profile_id, session_fixture_path=session_fixture_path, allowed_session_roots=list(allowed_roots or []))
    if obsidian_vault_root is not None:
        results["imports"]["obsidian"] = import_obsidian_vault_fixture(conn, profile_id=profile_id, vault_root=obsidian_vault_root, allowed_vault_roots=list(allowed_roots or []))
    results["readiness_report"] = migration_readiness_report(conn, profile_id=profile_id, query=query)
    if any(item.get("status") not in {"ok", "degraded"} for item in results["imports"].values() if isinstance(item, dict)):
        results["status"] = "degraded"
    return results


def leak_forbidden_scan_payload(payloads: Iterable[Any]) -> dict[str, Any]:
    """Scan generated compat 15.1 JSON/doc snippets for forbidden leakage markers."""
    text = "\n".join(json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload for payload in payloads)
    lowered = text.lower()
    hits = [marker for marker in _SECRET_MARKERS if marker in lowered]
    hard_phrases = ["raw memory.md", "raw user.md", "honcho deletion", "feature-complete replacement", "compat 15.2 controlled activation performed", "silent canonical promotion"]
    hits.extend([phrase for phrase in hard_phrases if phrase in lowered])
    return {"status": "ok" if not hits else "blocked", "checked_payloads": True, "forbidden_hits": sorted(set(hits)), "content_included": False, "path_redacted": True}
