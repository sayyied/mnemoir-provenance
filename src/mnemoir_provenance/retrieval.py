"""Local hybrid semantic retrieval for Mnemoir Provenance compat 04.

Semantic similarity, vector distance, heat, salience, and final ranking score are
ranking/debug signals only. They are never truth authority. Returned results must
remain cited to source-grounded rows.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Literal

from .audit import write_audit_event
from .db import json_dumps, now_utc, row_to_dict, sha256_text, stable_id
from .embeddings import (
    COMPAT04_MODEL_ID,
    COMPAT04_MODEL_DIMENSION,
    cosine_similarity,
    deterministic_embedding,
    embedding_status,
    ensure_local_embedding_model,
    vector_from_json,
    vector_to_json,
)
from .recall import _coverage, _fts_query
from .sources import list_sources

RetrievalMode = Literal["lexical", "semantic", "hybrid"]
_INDEXABLE_MEMORY_STATUSES = {"active", "corrected"}
_SUPPRESSED_MEMORY_STATUSES = {"stale", "contradicted", "superseded", "retracted", "tombstoned", "deleted", "quarantined"}


class RetrievalError(ValueError):
    """Domain error that should be reported as fail-closed CLI JSON."""


@dataclass
class Candidate:
    target_type: str
    target_id: str
    target_version: int | None
    chunk_id: str | None
    source_id: str | None
    source_pointer: str | None
    line_start: int | None
    line_end: int | None
    content_hash: str
    snippet: str
    score_fts: float
    score_vector: float
    score_recency: float
    score_rerank: float
    degraded: bool
    freshness_status: str
    inclusion_reason: str
    citation: dict[str, Any]

    @property
    def identity(self) -> tuple[str, str, int | None]:
        return (self.target_type, self.target_id, self.target_version)


def _safe_snippet(text: str, limit: int = 500) -> str:
    return text[:limit]


def _memory_citation(conn: sqlite3.Connection, memory_id: str, version: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT e.source_id, e.raw_event_id, e.uri, e.locator_json, e.content_hash, e.observed_at,
               re.source_pointer, re.line_start, re.line_end
        FROM memory_evidence me
        JOIN evidence_items e ON e.evidence_id = me.evidence_id
        LEFT JOIN raw_events re ON re.event_id = e.raw_event_id
        WHERE me.memory_id = ? AND me.version = ?
        ORDER BY me.role = 'primary' DESC, me.evidence_id
        LIMIT 1
        """,
        (memory_id, version),
    ).fetchone()
    if row is None or row["source_id"] is None:
        return None
    return {
        "source_id": row["source_id"],
        "source_pointer": row["source_pointer"] or row["uri"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "content_hash": row["content_hash"],
        "occurred_at": row["observed_at"],
        "evidence_raw_event_id": row["raw_event_id"],
    }


def _raw_event_citation(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "source_pointer": row["source_pointer"],
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "content_hash": row["content_hash"],
        "occurred_at": row["occurred_at"],
    }


def rebuild_retrieval_index(conn: sqlite3.Connection) -> dict[str, Any]:
    """Rebuild deterministic local chunks and embeddings for raw events/memories."""
    started = now_utc()
    ensure_local_embedding_model(conn)
    before = {
        "content_chunks": int(conn.execute("SELECT COUNT(*) FROM content_chunks").fetchone()[0]),
        "embeddings": int(conn.execute("SELECT COUNT(*) FROM embeddings WHERE model_id = ?", (COMPAT04_MODEL_ID,)).fetchone()[0]),
    }
    conn.execute("DELETE FROM embeddings WHERE model_id = ?", (COMPAT04_MODEL_ID,))
    conn.execute("DELETE FROM content_chunks WHERE owner_type IN ('raw_event', 'memory_version')")

    chunks = 0
    embeddings = 0
    timestamp = now_utc()
    raw_rows = conn.execute(
        """
        SELECT event_id, content, content_hash
        FROM raw_events
        WHERE write_status NOT IN ('quarantined','redacted','tombstoned')
        ORDER BY event_id
        """
    ).fetchall()
    for row in raw_rows:
        chunk_id = stable_id("chunk", "raw_event", row["event_id"], 0, row["content_hash"])
        _insert_chunk_and_embedding(
            conn,
            chunk_id=chunk_id,
            owner_type="raw_event",
            owner_id=row["event_id"],
            owner_version=None,
            chunk_index=0,
            text=row["content"],
            content_hash=row["content_hash"],
            timestamp=timestamp,
        )
        chunks += 1
        embeddings += 1

    memory_rows = conn.execute(
        """
        SELECT m.memory_id, m.current_version, m.status, mv.title, mv.summary, mv.body, mv.version_hash
        FROM memories m
        JOIN memory_versions mv ON mv.memory_id = m.memory_id AND mv.version = m.current_version
        WHERE m.status IN ('active','corrected')
        ORDER BY m.memory_id
        """
    ).fetchall()
    for row in memory_rows:
        text = "\n".join(part for part in [row["title"], row["summary"], row["body"]] if part)
        chunk_id = stable_id("chunk", "memory_version", row["memory_id"], row["current_version"], row["version_hash"])
        _insert_chunk_and_embedding(
            conn,
            chunk_id=chunk_id,
            owner_type="memory_version",
            owner_id=row["memory_id"],
            owner_version=int(row["current_version"]),
            chunk_index=0,
            text=text,
            content_hash=row["version_hash"],
            timestamp=timestamp,
        )
        chunks += 1
        embeddings += 1

    audit_id = write_audit_event(
        conn,
        event_type="retrieval.index.rebuild",
        target_type="job",
        target_id=stable_id("retrieval_rebuild", started, chunks, embeddings),
        status="ok",
        metadata={
            "model_id": COMPAT04_MODEL_ID,
            "before": before,
            "after": {"content_chunks": chunks, "embeddings": embeddings},
            "semantic_similarity_truth_authority": False,
        },
    )
    conn.commit()
    return {
        "status": "ok",
        "model_id": COMPAT04_MODEL_ID,
        "chunks_indexed": chunks,
        "embeddings_indexed": embeddings,
        "audit_id": audit_id,
        "truth_authority": "citations_provenance_policy_correction_history_not_vector_distance",
    }


def _insert_chunk_and_embedding(
    conn: sqlite3.Connection,
    *,
    chunk_id: str,
    owner_type: str,
    owner_id: str,
    owner_version: int | None,
    chunk_index: int,
    text: str,
    content_hash: str,
    timestamp: str,
) -> None:
    token_count = len(text.split())
    conn.execute(
        """
        INSERT INTO content_chunks(chunk_id, owner_type, owner_id, owner_version, chunk_index, text, token_count, content_hash, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            chunk_id,
            owner_type,
            owner_id,
            owner_version,
            chunk_index,
            text,
            token_count,
            content_hash,
            json_dumps({"phase": "compat04", "chunker": "single_record_deterministic"}),
            timestamp,
        ),
    )
    vector = deterministic_embedding(text)
    embedding_id = stable_id("embedding", chunk_id, COMPAT04_MODEL_ID, content_hash)
    target_type = "raw_event" if owner_type == "raw_event" else "memory_version"
    conn.execute(
        """
        INSERT INTO embeddings(
          embedding_id, target_type, target_id, target_version, chunk_id, model_id,
          content_hash, dims, vector_json, quantization, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'float32', ?)
        """,
        (
            embedding_id,
            target_type,
            owner_id,
            owner_version,
            chunk_id,
            COMPAT04_MODEL_ID,
            content_hash,
            COMPAT04_MODEL_DIMENSION,
            vector_to_json(vector),
            timestamp,
        ),
    )


def retrieval_status(conn: sqlite3.Connection) -> dict[str, Any]:
    return embedding_status(conn)


def retrieve(conn: sqlite3.Connection, query_text: str, *, mode: RetrievalMode = "hybrid", limit: int = 5) -> dict[str, Any]:
    if mode not in {"lexical", "semantic", "hybrid"}:
        raise RetrievalError("invalid_retrieval_mode")
    started = now_utc()
    start_monotonic = time.monotonic()
    sources = list_sources(conn)
    coverage = _coverage(sources)
    query_hash = sha256_text(query_text)
    query_id = stable_id("query", mode, query_text, started, time.perf_counter_ns())
    filters = {"mode": mode, "limit": limit, "model_id": COMPAT04_MODEL_ID}
    status_info = embedding_status(conn)
    degraded_reasons: list[str] = []
    effective_mode = mode
    if mode in {"semantic", "hybrid"} and not status_info["semantic_available"]:
        degraded_reasons.append(status_info.get("degraded_reason") or "semantic_index_unavailable")
        effective_mode = "lexical"
    lexical_candidates = _lexical_candidates(conn, query_text, limit=max(limit * 4, 10)) if effective_mode in {"lexical", "hybrid"} else []
    semantic_candidates = _semantic_candidates(conn, query_text, limit=max(limit * 4, 10)) if effective_mode in {"semantic", "hybrid"} else []
    candidates = _merge_candidates(lexical_candidates, semantic_candidates)
    ranked = _rank_candidates(candidates, mode=effective_mode)
    selected = ranked[:limit]
    if coverage["missing_or_degraded_sources"]:
        degraded_reasons.append("source_coverage_degraded")
    if mode in {"semantic", "hybrid"} and effective_mode == "lexical":
        status = "degraded"
    elif degraded_reasons:
        status = "degraded"
    elif not selected:
        status = "abstained"
    else:
        status = "ok"
    latency_ms = int((time.monotonic() - start_monotonic) * 1000)
    conn.execute(
        """
        INSERT INTO retrieval_queries(
          query_id, query_text, query_hash, purpose, filters_json, source_coverage_json,
          started_at, finished_at, latency_ms, result_count, status
        ) VALUES (?, ?, ?, 'answer', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            query_id,
            query_text,
            query_hash,
            json_dumps({**filters, "effective_mode": effective_mode, "degraded_reasons": degraded_reasons}),
            json_dumps(coverage),
            started,
            now_utc(),
            latency_ms,
            len(selected),
            status if status != "abstained" else "abstained",
        ),
    )
    results: list[dict[str, Any]] = []
    for rank, candidate in enumerate(selected, start=1):
        final_score = _final_score(candidate, effective_mode)
        channel = "fts" if effective_mode == "lexical" else ("vector" if effective_mode == "semantic" else "hybrid")
        conn.execute(
            """
            INSERT INTO retrieval_results(
              query_id, rank, target_type, target_id, target_version, channel,
              score_fts, score_vector, score_recency, score_rerank, final_score,
              selected, used_in_answer, citation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
            """,
            (
                query_id,
                rank,
                candidate.target_type,
                candidate.target_id,
                candidate.target_version,
                channel,
                candidate.score_fts,
                candidate.score_vector,
                candidate.score_recency,
                candidate.score_rerank,
                final_score,
                json_dumps(candidate.citation),
            ),
        )
        results.append(_result_payload(rank, candidate, final_score, effective_mode))
    audit_id = write_audit_event(
        conn,
        event_type="retrieval.hybrid" if mode == "hybrid" else f"retrieval.{mode}",
        target_type="retrieval_query",
        target_id=query_id,
        status="degraded" if status == "degraded" else ("ok" if selected else "warning"),
        metadata={
            "query_hash": query_hash,
            "requested_mode": mode,
            "effective_mode": effective_mode,
            "result_count": len(selected),
            "degraded_reasons": degraded_reasons,
            "semantic_similarity_truth_authority": False,
            "truth_authority": "citations_provenance_policy_correction_history",
        },
    )
    conn.commit()
    return {
        "query_id": query_id,
        "status": "abstain" if status == "abstained" else status,
        "requested_mode": mode,
        "effective_mode": effective_mode,
        "degraded_reasons": degraded_reasons,
        "query_hash": query_hash,
        "source_coverage": coverage,
        "result_count": len(results),
        "cited_results": results,
        "latency_ms": latency_ms,
        "audit_id": audit_id,
        "truth_authority": "citations_provenance_policy_correction_history_not_semantic_similarity",
        "semantic_similarity_truth_authority": False,
    }


def _lexical_candidates(conn: sqlite3.Connection, query_text: str, *, limit: int) -> list[Candidate]:
    fts_query = _fts_query(query_text)
    if fts_query == '""':
        return []
    candidates: list[Candidate] = []
    raw_rows = conn.execute(
        """
        SELECT re.event_id, re.source_id, re.content, re.content_hash, re.occurred_at,
               re.source_pointer, re.line_start, re.line_end, bm25(raw_events_fts) AS rank_score
        FROM raw_events_fts
        JOIN raw_events re ON re.rowid = raw_events_fts.rowid
        WHERE raw_events_fts MATCH ?
        ORDER BY rank_score ASC
        LIMIT ?
        """,
        (fts_query, limit),
    ).fetchall()
    for row in raw_rows:
        score = 1.0 / (1.0 + abs(float(row["rank_score"] or 0.0)))
        citation = _raw_event_citation(row)
        candidates.append(
            Candidate(
                target_type="raw_event",
                target_id=row["event_id"],
                target_version=None,
                chunk_id=None,
                source_id=row["source_id"],
                source_pointer=row["source_pointer"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                content_hash=row["content_hash"],
                snippet=_safe_snippet(row["content"]),
                score_fts=round(score, 8),
                score_vector=0.0,
                score_recency=0.5,
                score_rerank=0.0,
                degraded=False,
                freshness_status="current_or_unknown",
                inclusion_reason="exact_lexical_match",
                citation=citation,
            )
        )
    mem_rows = conn.execute(
        """
        SELECT m.memory_id, m.current_version, m.status, m.confidence, m.salience,
               m.contradiction_score, m.drift_score, m.retention_strength, m.retrieval_success_rate,
               mv.title, mv.summary, mv.body, mv.version_hash, bm25(memories_fts) AS rank_score
        FROM memories_fts
        JOIN memories m ON m.memory_id = memories_fts.memory_id
        JOIN memory_versions mv ON mv.memory_id = m.memory_id AND mv.version = m.current_version
        WHERE memories_fts MATCH ? AND m.status IN ('active','corrected')
        ORDER BY rank_score ASC
        LIMIT ?
        """,
        (fts_query, limit),
    ).fetchall()
    for row in mem_rows:
        citation = _memory_citation(conn, row["memory_id"], int(row["current_version"]))
        if not citation:
            continue
        score = 1.0 / (1.0 + abs(float(row["rank_score"] or 0.0)))
        rerank = _memory_score_component(row)
        candidates.append(
            Candidate(
                target_type="memory_version",
                target_id=row["memory_id"],
                target_version=int(row["current_version"]),
                chunk_id=None,
                source_id=citation["source_id"],
                source_pointer=citation["source_pointer"],
                line_start=citation["line_start"],
                line_end=citation["line_end"],
                content_hash=row["version_hash"],
                snippet=_safe_snippet("\n".join([row["title"], row["summary"], row["body"]])),
                score_fts=round(score, 8),
                score_vector=0.0,
                score_recency=0.5,
                score_rerank=rerank,
                degraded=False,
                freshness_status="current_or_unknown",
                inclusion_reason="exact_lexical_memory_match_with_citation",
                citation=citation,
            )
        )
    return candidates


def _semantic_candidates(conn: sqlite3.Connection, query_text: str, *, limit: int) -> list[Candidate]:
    status = embedding_status(conn)
    if not status["semantic_available"]:
        return []
    query_vector = deterministic_embedding(query_text)
    rows = conn.execute(
        """
        SELECT e.target_type, e.target_id, e.target_version, e.chunk_id, e.vector_json,
               c.owner_type, c.text, c.content_hash
        FROM embeddings e
        JOIN content_chunks c ON c.chunk_id = e.chunk_id
        WHERE e.model_id = ? AND e.vector_json IS NOT NULL
        ORDER BY e.target_type, e.target_id, e.target_version
        """,
        (COMPAT04_MODEL_ID,),
    ).fetchall()
    scored: list[tuple[float, sqlite3.Row]] = []
    for row in rows:
        score = cosine_similarity(query_vector, vector_from_json(row["vector_json"]))
        if score > 0.0:
            scored.append((score, row))
    scored.sort(key=lambda item: (item[0], item[1]["target_type"], item[1]["target_id"]), reverse=True)
    candidates: list[Candidate] = []
    for score, row in scored[:limit]:
        if row["target_type"] == "raw_event":
            raw = conn.execute(
                "SELECT * FROM raw_events WHERE event_id = ? AND write_status NOT IN ('quarantined','redacted','tombstoned')",
                (row["target_id"],),
            ).fetchone()
            if raw is None:
                continue
            citation = _raw_event_citation(raw)
            candidates.append(
                Candidate(
                    target_type="raw_event",
                    target_id=raw["event_id"],
                    target_version=None,
                    chunk_id=row["chunk_id"],
                    source_id=raw["source_id"],
                    source_pointer=raw["source_pointer"],
                    line_start=raw["line_start"],
                    line_end=raw["line_end"],
                    content_hash=raw["content_hash"],
                    snippet=_safe_snippet(raw["content"]),
                    score_fts=0.0,
                    score_vector=round(score, 8),
                    score_recency=0.5,
                    score_rerank=0.0,
                    degraded=False,
                    freshness_status="current_or_unknown",
                    inclusion_reason="local_semantic_vector_match_with_raw_event_citation",
                    citation=citation,
                )
            )
        elif row["target_type"] == "memory_version":
            mem = conn.execute(
                """
                SELECT m.*, mv.title, mv.summary, mv.body, mv.version_hash
                FROM memories m
                JOIN memory_versions mv ON mv.memory_id = m.memory_id AND mv.version = m.current_version
                WHERE m.memory_id = ? AND m.current_version = ?
                """,
                (row["target_id"], row["target_version"]),
            ).fetchone()
            if mem is None or mem["status"] in _SUPPRESSED_MEMORY_STATUSES:
                continue
            citation = _memory_citation(conn, mem["memory_id"], int(mem["current_version"]))
            if not citation:
                continue
            candidates.append(
                Candidate(
                    target_type="memory_version",
                    target_id=mem["memory_id"],
                    target_version=int(mem["current_version"]),
                    chunk_id=row["chunk_id"],
                    source_id=citation["source_id"],
                    source_pointer=citation["source_pointer"],
                    line_start=citation["line_start"],
                    line_end=citation["line_end"],
                    content_hash=mem["version_hash"],
                    snippet=_safe_snippet("\n".join([mem["title"], mem["summary"], mem["body"]])),
                    score_fts=0.0,
                    score_vector=round(score, 8),
                    score_recency=0.5,
                    score_rerank=_memory_score_component(mem),
                    degraded=False,
                    freshness_status="current_or_unknown",
                    inclusion_reason="local_semantic_vector_match_with_memory_citation",
                    citation=citation,
                )
            )
    return candidates


def _memory_score_component(row: sqlite3.Row) -> float:
    if row["status"] not in _INDEXABLE_MEMORY_STATUSES:
        return -0.5
    score = (
        float(row["confidence"]) * 0.24
        + float(row["retrieval_success_rate"]) * 0.18
        + float(row["retention_strength"]) * 0.16
        + float(row["salience"]) * 0.08
        - float(row["contradiction_score"]) * 0.24
        - float(row["drift_score"]) * 0.18
    )
    return round(score, 8)


def _merge_candidates(*groups: list[Candidate]) -> list[Candidate]:
    merged: dict[tuple[str, str, int | None], Candidate] = {}
    for group in groups:
        for candidate in group:
            existing = merged.get(candidate.identity)
            if existing is None:
                merged[candidate.identity] = candidate
                continue
            existing.score_fts = max(existing.score_fts, candidate.score_fts)
            existing.score_vector = max(existing.score_vector, candidate.score_vector)
            existing.score_rerank = max(existing.score_rerank, candidate.score_rerank)
            if "semantic" in candidate.inclusion_reason and "semantic" not in existing.inclusion_reason:
                existing.inclusion_reason = f"{existing.inclusion_reason}+{candidate.inclusion_reason}"
            if candidate.chunk_id and not existing.chunk_id:
                existing.chunk_id = candidate.chunk_id
    return list(merged.values())


def _final_score(candidate: Candidate, mode: str) -> float:
    if mode == "lexical":
        score = candidate.score_fts * 0.84 + candidate.score_rerank * 0.16
    elif mode == "semantic":
        score = candidate.score_vector * 0.78 + candidate.score_rerank * 0.22
    else:
        score = candidate.score_fts * 0.42 + candidate.score_vector * 0.42 + candidate.score_rerank * 0.16
    return round(score, 8)


def _rank_candidates(candidates: list[Candidate], *, mode: str) -> list[Candidate]:
    candidates.sort(
        key=lambda item: (
            _final_score(item, mode),
            item.score_fts,
            item.score_vector,
            item.score_rerank,
            item.target_type,
            item.target_id,
        ),
        reverse=True,
    )
    return candidates


def _result_payload(rank: int, candidate: Candidate, final_score: float, effective_mode: str) -> dict[str, Any]:
    return {
        "rank": rank,
        "target_type": candidate.target_type,
        "target_id": candidate.target_id,
        "target_version": candidate.target_version,
        "chunk_id": candidate.chunk_id,
        "source_id": candidate.source_id,
        "source_pointer": candidate.source_pointer,
        "line_start": candidate.line_start,
        "line_end": candidate.line_end,
        "content_hash": candidate.content_hash,
        "snippet": candidate.snippet,
        "explanation": {
            "mode": effective_mode,
            "inclusion_reason": candidate.inclusion_reason,
            "score_components": {
                "lexical": candidate.score_fts,
                "semantic": candidate.score_vector,
                "freshness": candidate.score_recency,
                "compat03_score_signal": candidate.score_rerank,
                "final": final_score,
            },
            "freshness_status": candidate.freshness_status,
            "degraded": candidate.degraded,
            "citation": candidate.citation,
            "truth_authority": "citation_provenance_policy_correction_history",
            "ranking_score_truth_authority": False,
            "semantic_similarity_truth_authority": False,
        },
    }


def explain(conn: sqlite3.Connection, query_text: str, *, mode: RetrievalMode = "hybrid", limit: int = 5) -> dict[str, Any]:
    result = retrieve(conn, query_text, mode=mode, limit=limit)
    return {"status": result["status"], "query_id": result["query_id"], "explanations": [item["explanation"] for item in result["cited_results"]], "result": result}


def record_feedback(conn: sqlite3.Connection, *, query_id: str, target_type: str, target_id: str, rating: int, feedback_text: str | None = None) -> dict[str, Any]:
    if rating < -2 or rating > 2:
        raise RetrievalError("invalid_feedback_rating")
    if conn.execute("SELECT 1 FROM retrieval_queries WHERE query_id = ?", (query_id,)).fetchone() is None:
        raise RetrievalError("retrieval_query_not_found")
    timestamp = now_utc()
    feedback_id = stable_id("feedback", query_id, target_type, target_id, rating, timestamp)
    conn.execute(
        """
        INSERT INTO retrieval_feedback(feedback_id, query_id, target_type, target_id, rating, feedback_text, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (feedback_id, query_id, target_type, target_id, rating, feedback_text, timestamp),
    )
    audit_id = write_audit_event(
        conn,
        event_type="retrieval.feedback",
        target_type="retrieval_query",
        target_id=query_id,
        status="ok",
        metadata={"feedback_id": feedback_id, "target_type": target_type, "target_id": target_id, "rating": rating},
    )
    conn.commit()
    return {"status": "ok", "feedback_id": feedback_id, "audit_id": audit_id}
