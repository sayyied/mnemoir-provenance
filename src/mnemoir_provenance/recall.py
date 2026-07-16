"""Cited lexical recall for source evidence and eligible canonical memories."""
from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid
from typing import Any

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text
from .sources import list_sources

TERM_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def _fts_query(query_text: str) -> str:
    terms: list[str] = []
    for term in TERM_RE.findall(query_text.lower()):
        if term not in terms:
            terms.append(term)
    return '""' if not terms else " OR ".join(f'"{term}"' for term in terms[:12])


def _coverage(sources: list[dict[str, Any]]) -> dict[str, Any]:
    searched = [s["source_id"] for s in sources if s["read_authority"] != "none" and s["health"] == "healthy"]
    missing = [{"source_id": s["source_id"], "health": s["health"], "failure_reason": s.get("failure_reason")} for s in sources if s["read_authority"] != "none" and s["health"] != "healthy"]
    return {"searched_source_ids": searched, "missing_or_degraded_sources": missing, "coverage_status": "degraded" if missing else "ok"}


def recall(conn: sqlite3.Connection, query_text: str, limit: int = 5, *, source_ids: list[str] | None = None, source_coverage: dict[str, Any] | None = None, profile_id: str | None = None, session_id: str | None = None, project_id: str | None = None) -> dict[str, Any]:
    started = now_utc()
    monotonic_start = time.monotonic()
    if source_ids is None:
        sources = list_sources(conn)
        coverage = _coverage(sources)
    else:
        coverage = source_coverage or {"searched_source_ids": source_ids, "missing_or_degraded_sources": [], "coverage_status": "ok"}
    query_id = f"query_{uuid.uuid4().hex}"
    query_hash = sha256_text(query_text)
    fts_query = _fts_query(query_text)
    raw_rows: list[sqlite3.Row] = []
    authorized = list(coverage.get("searched_source_ids", []))
    if fts_query != '""' and authorized:
        marks = ",".join("?" for _ in authorized)
        raw_rows = conn.execute(f"""
            SELECT re.event_id, re.source_id, re.content, re.content_hash, re.occurred_at,
                   re.source_pointer, re.line_start, re.line_end, bm25(raw_events_fts) AS rank_score
            FROM raw_events_fts JOIN raw_events re ON re.rowid=raw_events_fts.rowid
            WHERE raw_events_fts MATCH ? AND re.source_id IN ({marks})
            ORDER BY rank_score ASC LIMIT ?
        """, (fts_query, *authorized, limit)).fetchall()

    memory_rows: list[sqlite3.Row] = []
    if fts_query != '""' and profile_id:
        memory_rows = conn.execute("""
            SELECT m.memory_id, m.current_version, m.scope, m.privacy_class,
                   mv.title, mv.summary, mv.body, mv.version_hash,
                   mp.proposal_id, s.source_id, re.source_pointer, re.occurred_at,
                   bm25(memories_fts) AS rank_score
            FROM memories_fts
            JOIN memories m ON m.memory_id=memories_fts.memory_id AND m.current_version=memories_fts.version
            JOIN memory_versions mv ON mv.memory_id=m.memory_id AND mv.version=m.current_version
            JOIN actors owner ON owner.actor_id=m.owner_actor_id AND owner.profile_name=?
            JOIN memory_proposals mp ON mp.proposal_id=json_extract(mv.metadata_json, '$.proposal_id')
              AND mp.memory_id=m.memory_id AND mp.status='written'
            JOIN memory_evidence me ON me.memory_id=m.memory_id AND me.version=m.current_version
            JOIN evidence_items ei ON ei.evidence_id=me.evidence_id
            JOIN sources s ON s.source_id=ei.source_id AND s.profile_id=? AND s.health='healthy' AND s.read_authority!='none'
            JOIN raw_events re ON re.event_id=ei.raw_event_id AND re.write_status='committed'
            WHERE memories_fts MATCH ? AND m.status='active'
              AND EXISTS (
                SELECT 1 FROM provenance_edges pe_source
                WHERE pe_source.from_type='source' AND pe_source.from_id=s.source_id
                  AND pe_source.to_type='raw_event' AND pe_source.to_id=re.event_id
                  AND pe_source.relation_type='produced')
              AND EXISTS (
                SELECT 1 FROM provenance_edges pe_evidence
                WHERE pe_evidence.from_type='raw_event' AND pe_evidence.from_id=re.event_id
                  AND pe_evidence.to_type='evidence' AND pe_evidence.to_id=ei.evidence_id
                  AND pe_evidence.relation_type='quotes')
              AND m.privacy_class IN ('public','internal','private')
              AND (m.scope IN ('global','actor','council')
                   OR (m.scope='session' AND ? IS NOT NULL AND re.session_id=?)
                   OR (m.scope='project' AND ? IS NOT NULL AND m.project_id=?))
              AND NOT EXISTS (
                SELECT 1 FROM memory_relationships mr
                JOIN memories newer ON newer.memory_id=mr.from_memory_id AND newer.status='active'
                WHERE mr.to_memory_id=m.memory_id AND mr.relationship_type='supersedes')
            ORDER BY rank_score ASC LIMIT ?
        """, (profile_id, profile_id, fts_query, session_id, session_id, project_id, project_id, limit)).fetchall()

    candidates: list[tuple[str, sqlite3.Row]] = [("memory", r) for r in memory_rows] + [("raw_event", r) for r in raw_rows]
    candidates.sort(key=lambda pair: float(pair[1]["rank_score"] or 0.0))
    candidates = candidates[:limit]
    status = "degraded" if coverage.get("missing_or_degraded_sources") else "ok"
    if not candidates:
        status = "degraded" if status == "degraded" else "abstained"
    latency_ms = int((time.monotonic() - monotonic_start) * 1000)
    conn.execute("""
        INSERT INTO retrieval_queries(query_id, query_text, query_hash, purpose, filters_json,
          source_coverage_json, started_at, finished_at, latency_ms, result_count, status)
        VALUES (?, ?, ?, 'answer', ?, ?, ?, ?, ?, ?, ?)
    """, (query_id, query_text, query_hash, json_dumps({"channel": "fts", "limit": limit, "profile_id": profile_id, "source_filter_applied": source_ids is not None}), json_dumps(coverage), started, now_utc(), latency_ms, len(candidates), status))

    cited: list[dict[str, Any]] = []
    for rank, (target_type, row) in enumerate(candidates, 1):
        item = row_to_dict(row)
        if target_type == "memory":
            target_id = item["memory_id"]
            snippet = "\n".join(x for x in (item["title"], item["summary"], item["body"]) if x)[:500]
            citation = {"source_id": item["source_id"], "source_pointer": item["source_pointer"], "content_hash": item["version_hash"], "occurred_at": item["occurred_at"], "proposal_id": item["proposal_id"], "memory_version": item["current_version"]}
        else:
            target_id = item["event_id"]
            snippet = item["content"][:500]
            citation = {"source_id": item["source_id"], "source_pointer": item["source_pointer"], "line_start": item["line_start"], "line_end": item["line_end"], "content_hash": item["content_hash"], "occurred_at": item["occurred_at"]}
        score = -float(item["rank_score"] or 0.0)
        conn.execute("""INSERT INTO retrieval_results(query_id, rank, target_type, target_id, channel,
          score_fts, final_score, selected, used_in_answer, citation_json)
          VALUES (?, ?, ?, ?, 'fts', ?, ?, 1, 1, ?)""", (query_id, rank, target_type, target_id, item["rank_score"], score, json_dumps(citation)))
        cited.append({"rank": rank, "target_type": target_type, "target_id": target_id, "source_id": item["source_id"], "source_pointer": item["source_pointer"], "line_start": item.get("line_start"), "line_end": item.get("line_end"), "occurred_at": item["occurred_at"], "content_hash": citation["content_hash"], "snippet": snippet, "proposal_id": item.get("proposal_id"), "memory_version": item.get("current_version"), "scope": item.get("scope"), "privacy_class": item.get("privacy_class"), "eligibility": {"profile": "allowed", "scope": "allowed", "privacy": "allowed", "provenance": "valid"}})
    audit_id = write_audit_event(conn, event_type="recall.fts", target_type="retrieval_query", target_id=query_id, status="degraded" if status == "degraded" else ("ok" if cited else "warning"), metadata={"query_hash": query_hash, "result_count": len(cited), "source_coverage": coverage, "status": status})
    conn.commit()
    return {"query_id": query_id, "status": "abstain" if status == "abstained" else status, "query_hash": query_hash, "source_coverage": coverage, "result_count": len(cited), "cited_results": cited, "audit_id": audit_id}


def retrieval_result_rows(conn: sqlite3.Connection, query_id: str) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM retrieval_results WHERE query_id=? ORDER BY rank", (query_id,)).fetchall()
    result = []
    for row in rows:
        item = row_to_dict(row)
        item["citation"] = json.loads(item.pop("citation_json"))
        result.append(item)
    return result
