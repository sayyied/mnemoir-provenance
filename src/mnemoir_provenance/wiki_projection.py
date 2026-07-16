"""Derived Obsidian/LLM Wiki projection for Mnemoir Provenance compat 08.

Generated pages are non-canonical, caller-rooted output only. They never read
from or write to Hermes markdown and never mutate canonical records.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .db import now_utc, row_to_dict, sha256_text

GENERATOR_VERSION = "compat08-wiki-projection-v1"
PAGE_WARNING = "NON-CANONICAL DERIVED OUTPUT — canonical storage remains the Mnemoir Provenance SQLite DB."
WRITEBACK_WARNING = "NO WRITEBACK — editing this generated page must not mutate DB records or Hermes markdown."
_PAGE_ORDER = [
    ("memory-index.md", "Memory Index"),
    ("sources-health.md", "Sources and Health"),
    ("council-state.md", "Council Actors and State"),
    ("decisions-reviews.md", "Decisions and Reviews"),
    ("open-loops.md", "Open Loops"),
    ("failures-degraded.md", "Failures and Degraded States"),
    ("autonomy-receipts.md", "Autonomy Receipts"),
    ("hermes-provider-status.md", "Hermes Provider and Markdown Source Status"),
    ("projection-manifest.md", "Projection Manifest and Log"),
]
_FORBIDDEN_RE = re.compile(
    r"(/home/[A-Za-z0-9_./-]+|api[_-]?key\s*=|token\s*=|password\s*=|secret\s*=|sk-[A-Za-z0-9]|\.hermes/profiles|auth(?:orization)?\s*=)",
    re.IGNORECASE,
)


class ProjectionError(ValueError):
    """Fail-closed projection boundary error."""


def _json_loads(text: str | None, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except json.JSONDecodeError:
        return default


def _clean(value: Any, *, limit: int = 180) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ").strip()
    text = _FORBIDDEN_RE.sub("[REDACTED]", text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _assert_safe(text: str, label: str) -> None:
    match = _FORBIDDEN_RE.search(text)
    if match:
        raise ProjectionError(f"projection_leak_detected:{label}")


def _page_header(title: str, generated_at: str) -> str:
    return "\n".join(
        [
            "---",
            f"title: {_clean(title)}",
            f"generated_at: {generated_at}",
            f"generator_version: {GENERATOR_VERSION}",
            "canonical_storage: mnemoir_provenance_sqlite_db",
            "non_canonical: true",
            "writeback_allowed: false",
            "---",
            "",
            f"# {title}",
            "",
            f"> {PAGE_WARNING}",
            f"> {WRITEBACK_WARNING}",
            "",
        ]
    )


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def _memory_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = _rows(
        conn,
        """
        SELECT m.memory_id, m.status, m.scope, m.memory_type, m.privacy_class,
               m.confidence, m.salience, m.contradiction_score, m.updated_at,
               mv.version, mv.title, mv.summary,
               GROUP_CONCAT(me.evidence_id) AS evidence_ids
        FROM memories m
        LEFT JOIN memory_versions mv ON mv.memory_id = m.memory_id AND mv.version = m.current_version
        LEFT JOIN memory_evidence me ON me.memory_id = m.memory_id AND me.version = m.current_version
        GROUP BY m.memory_id
        ORDER BY m.updated_at DESC, m.memory_id
        LIMIT 200
        """,
    )
    for row in rows:
        row["evidence_ids"] = [item for item in str(row.get("evidence_ids") or "").split(",") if item]
    return rows


def _source_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(
        conn,
        """
        SELECT source_id, source_type, display_name, external_ref, profile_id, overflow_kind,
               read_authority, write_authority, authority_level, health, freshness_seconds, failure_reason
        FROM sources
        ORDER BY health != 'healthy', authority_level, source_type, source_id
        LIMIT 300
        """,
    )


def _council_rows(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    return {
        "actors": _rows(conn, "SELECT actor_id, kind, display_name, is_active FROM actors ORDER BY kind, display_name LIMIT 100"),
        "objectives": _rows(conn, "SELECT objective_id, title, status, priority, owner_actor_id, updated_at FROM council_objectives ORDER BY updated_at DESC, objective_id LIMIT 100"),
        "assignments": _rows(conn, "SELECT assignment_id, objective_id, title, status, assigned_actor_id, updated_at FROM council_assignments ORDER BY updated_at DESC, assignment_id LIMIT 100"),
        "records": _rows(conn, "SELECT record_id, objective_id, kind, title, status, severity, updated_at FROM council_records ORDER BY updated_at DESC, record_id LIMIT 100"),
        "reviews": _rows(conn, "SELECT review_id, objective_id, assignment_id, evidence_packet_id, reviewer_actor_id, outcome, created_at FROM council_reviews ORDER BY created_at DESC, review_id LIMIT 100"),
        "handoffs": _rows(conn, "SELECT handoff_id, objective_id, phase, title, status, from_actor_id, to_actor_id, updated_at FROM council_handoffs ORDER BY updated_at DESC, handoff_id LIMIT 100"),
    }


def _autonomy_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(
        conn,
        """
        SELECT tick_id, job_id, objective, trigger_type, actor_id, status, approval_class,
               receipt_audit_id, created_at, finished_at
        FROM autonomy_ticks
        ORDER BY created_at DESC, tick_id
        LIMIT 100
        """,
    )


def _audit_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(
        conn,
        "SELECT audit_id, occurred_at, event_type, target_type, target_id, status FROM audit_events ORDER BY occurred_at DESC, audit_id DESC LIMIT 120",
    )


def _evidence_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _rows(
        conn,
        """
        SELECT evidence_id, raw_event_id, source_id, kind, uri, quote_text, privacy_class, observed_at, created_at
        FROM evidence_items
        ORDER BY created_at DESC, evidence_id
        LIMIT 200
        """,
    )


def _section_list(title: str, rows: list[dict[str, Any]], id_fields: list[str], fields: list[str]) -> str:
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["- No canonical rows found for this section.", ""])
        return "\n".join(lines)
    for row in rows:
        ids = [f"{field}=`{_clean(row.get(field), limit=120)}`" for field in id_fields if row.get(field)]
        attrs = [f"{field}: {_clean(row.get(field))}" for field in fields if row.get(field) is not None]
        lines.append(f"- {'; '.join(ids)}")
        if attrs:
            lines.append(f"  - {'; '.join(attrs)}")
    lines.append("")
    return "\n".join(lines)


def build_projection_pages(conn: sqlite3.Connection, *, generated_at: str | None = None) -> dict[str, str]:
    generated_at = generated_at or now_utc()
    memories = _memory_rows(conn)
    sources = _source_rows(conn)
    council = _council_rows(conn)
    autonomy = _autonomy_rows(conn)
    audits = _audit_rows(conn)
    evidence = _evidence_rows(conn)
    degraded_sources = [s for s in sources if s.get("health") != "healthy"]
    open_loops = [m for m in memories if m.get("memory_type") in {"open_loop", "task", "commitment", "warning", "failure"} or m.get("status") in {"stale", "contradicted"}]
    approval_needed = [t for t in autonomy if t.get("approval_class") == "approval_required" or t.get("status") in {"failed", "paused"}]
    pages: dict[str, str] = {}
    pages["memory-index.md"] = _page_header("Memory Index", generated_at) + _section_list("Canonical memories", memories, ["memory_id"], ["status", "memory_type", "scope", "privacy_class", "title", "summary", "evidence_ids"]) + _section_list("Evidence and raw-event anchors", evidence, ["evidence_id", "raw_event_id", "source_id"], ["kind", "privacy_class", "quote_text", "uri"])
    pages["sources-health.md"] = _page_header("Sources and Health", generated_at) + _section_list("Registered sources", sources, ["source_id"], ["source_type", "authority_level", "read_authority", "write_authority", "health", "failure_reason", "external_ref"])
    pages["council-state.md"] = _page_header("Council Actors and State", generated_at) + _section_list("Actors", council["actors"], ["actor_id"], ["kind", "display_name", "is_active"]) + _section_list("Objectives", council["objectives"], ["objective_id"], ["title", "status", "owner_actor_id"]) + _section_list("Assignments", council["assignments"], ["assignment_id", "objective_id"], ["title", "status", "assigned_actor_id"])
    pages["decisions-reviews.md"] = _page_header("Decisions and Reviews", generated_at) + _section_list("Council records", council["records"], ["record_id", "objective_id"], ["kind", "title", "status", "severity"]) + _section_list("Reviews", council["reviews"], ["review_id", "objective_id"], ["outcome", "reviewer_actor_id", "evidence_packet_id"]) + _section_list("Handoffs", council["handoffs"], ["handoff_id", "objective_id"], ["phase", "title", "status", "from_actor_id", "to_actor_id"])
    pages["open-loops.md"] = _page_header("Open Loops", generated_at) + _section_list("Open memory/council loops", open_loops, ["memory_id"], ["status", "memory_type", "title", "summary"])
    pages["failures-degraded.md"] = _page_header("Failures and Degraded States", generated_at) + _section_list("Degraded sources", degraded_sources, ["source_id"], ["health", "failure_reason", "source_type"]) + _section_list("Approval/failure ticks", approval_needed, ["tick_id", "job_id"], ["status", "approval_class", "receipt_audit_id"])
    pages["autonomy-receipts.md"] = _page_header("Autonomy Receipts", generated_at) + _section_list("Autonomy ticks and receipts", autonomy, ["tick_id", "job_id"], ["status", "approval_class", "receipt_audit_id", "trigger_type"])
    hermes_sources = [s for s in sources if s.get("source_type") == "hermes_markdown_overflow"]
    pages["hermes-provider-status.md"] = _page_header("Hermes Provider and Markdown Source Status", generated_at) + "## Provider posture\n\n- provider=`mnemoir_local`; markdown_writeback=`disabled_by_default`; live_io_performed=`false`; real_profile_reads=`false`\n\n" + _section_list("Hermes markdown sources", hermes_sources, ["source_id"], ["profile_id", "overflow_kind", "health", "write_authority", "failure_reason"])
    manifest_lines = _page_header("Projection Manifest and Log", generated_at)
    manifest_lines += "## Pages\n\n" + "\n".join(f"- page=`{name}`; title={title}; non_canonical=true; writeback_allowed=false" for name, title in _PAGE_ORDER) + "\n\n"
    manifest_lines += _section_list("Recent audit anchors", audits, ["audit_id"], ["event_type", "target_type", "target_id", "status"])
    pages["projection-manifest.md"] = manifest_lines
    for name, text in pages.items():
        _assert_safe(text, name)
    return pages


def write_projection(conn: sqlite3.Connection, output_root: str | Path, *, generated_at: str | None = None) -> dict[str, Any]:
    root = Path(output_root).expanduser()
    if root.exists() and not root.is_dir():
        raise ProjectionError("projection_output_root_not_directory")
    root.mkdir(parents=True, exist_ok=True)
    pages = build_projection_pages(conn, generated_at=generated_at)
    written = []
    for page_name, body in pages.items():
        page_path = root / page_name
        page_path.write_text(body, encoding="utf-8")
        written.append({"page": page_name, "sha256": sha256_text(body), "bytes": len(body.encode("utf-8"))})
    manifest = {
        "status": "ok",
        "generated_at": generated_at or now_utc(),
        "generator_version": GENERATOR_VERSION,
        "canonical_storage": "mnemoir_provenance_sqlite_db",
        "non_canonical": True,
        "writeback_allowed": False,
        "pages": written,
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True)
    _assert_safe(manifest_text, "projection-manifest.json")
    (root / "projection-manifest.json").write_text(manifest_text + "\n", encoding="utf-8")
    (root / "projection-log.jsonl").write_text(json.dumps({"event": "projection.generated", **manifest}, sort_keys=True) + "\n", encoding="utf-8")
    return {k: v for k, v in manifest.items() if k != "pages"} | {"page_count": len(written), "pages": written}


def projection_status(output_root: str | Path | None = None) -> dict[str, Any]:
    if not output_root:
        return {"status": "unknown", "projection_configured": False, "non_canonical": True, "writeback_allowed": False}
    root = Path(output_root).expanduser()
    manifest_path = root / "projection-manifest.json"
    if not manifest_path.exists():
        return {"status": "missing", "projection_configured": True, "manifest_present": False, "non_canonical": True, "writeback_allowed": False}
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {
        "status": data.get("status", "unknown"),
        "projection_configured": True,
        "manifest_present": True,
        "generator_version": data.get("generator_version"),
        "generated_at": data.get("generated_at"),
        "page_count": len(data.get("pages", [])),
        "non_canonical": True,
        "writeback_allowed": False,
    }
