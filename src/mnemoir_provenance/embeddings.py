"""Strictly local deterministic embeddings for Mnemoir Provenance compat 04.

These embeddings are intentionally small, transparent, and local-only. They are a
retrieval signal, not truth authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from typing import Any

from .db import json_dumps, now_utc

COMPAT04_MODEL_ID = "local_hash_embedding_v1"
COMPAT04_MODEL_DIMENSION = 64
_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_CONCEPT_EXPANSIONS = {
    "conceptual": ["semantic", "meaning", "retrieval"],
    "concept": ["semantic", "meaning", "retrieval"],
    "meaning": ["semantic", "conceptual"],
    "find": ["retrieval", "recall", "search"],
    "remember": ["memory", "recall", "retrieval"],
    "curate": ["curation", "writeback", "proposal"],
    "mutation": ["writeback", "curation", "proposal"],
    "authority": ["provenance", "citation", "policy"],
}


class EmbeddingError(ValueError):
    """Domain error for fail-closed local embedding/index operations."""


def tokenize(text: str) -> list[str]:
    tokens = _TOKEN_RE.findall(text.lower())
    expanded: list[str] = []
    for token in tokens:
        expanded.append(token)
        expanded.extend(_CONCEPT_EXPANSIONS.get(token, []))
    return expanded


def deterministic_embedding(text: str, *, dimensions: int = COMPAT04_MODEL_DIMENSION) -> list[float]:
    """Return a deterministic unit vector using local feature hashing only."""
    if dimensions <= 0:
        raise EmbeddingError("invalid_embedding_dimension")
    vector = [0.0] * dimensions
    for token in tokenize(text):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return vector
    return [round(value / norm, 8) for value in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise EmbeddingError("embedding_dimension_mismatch")
    if not left:
        return 0.0
    return round(sum(a * b for a, b in zip(left, right)), 8)


def ensure_local_embedding_model(conn: sqlite3.Connection) -> dict[str, Any]:
    """Register the compat 04 local deterministic model."""
    timestamp = now_utc()
    conn.execute(
        """
        INSERT INTO embedding_models(
          model_id, provider, model_name, dimension, distance_metric,
          tokenizer, normalization, local_only, metadata_json, created_at
        ) VALUES (?, 'local', 'deterministic-hash-bow-v1', ?, 'cosine',
                  'unicode61-compatible-token-regex', 'l2_unit', 1, ?, ?)
        ON CONFLICT(model_id) DO UPDATE SET
          provider=excluded.provider,
          model_name=excluded.model_name,
          dimension=excluded.dimension,
          distance_metric=excluded.distance_metric,
          local_only=excluded.local_only,
          metadata_json=excluded.metadata_json
        """,
        (
            COMPAT04_MODEL_ID,
            COMPAT04_MODEL_DIMENSION,
            json_dumps(
                {
                    "phase": "compat04",
                    "network": False,
                    "truth_authority": "none_embedding_similarity_is_ranking_signal_only",
                }
            ),
            timestamp,
        ),
    )
    conn.commit()
    return embedding_status(conn)


def embedding_status(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM embedding_models WHERE model_id = ?", (COMPAT04_MODEL_ID,)).fetchone()
    chunk_count = int(conn.execute("SELECT COUNT(*) FROM content_chunks").fetchone()[0])
    embedding_count = int(conn.execute("SELECT COUNT(*) FROM embeddings WHERE model_id = ?", (COMPAT04_MODEL_ID,)).fetchone()[0])
    if row is None:
        return {
            "status": "degraded",
            "model_registered": False,
            "model_id": COMPAT04_MODEL_ID,
            "local_only": True,
            "dimension": COMPAT04_MODEL_DIMENSION,
            "chunk_count": chunk_count,
            "embedding_count": embedding_count,
            "degraded_reason": "embedding_model_not_registered",
            "semantic_available": False,
        }
    return {
        "status": "ok" if embedding_count else "degraded",
        "model_registered": True,
        "model_id": row["model_id"],
        "provider": row["provider"],
        "model_name": row["model_name"],
        "local_only": bool(row["local_only"]),
        "dimension": int(row["dimension"]),
        "distance_metric": row["distance_metric"],
        "chunk_count": chunk_count,
        "embedding_count": embedding_count,
        "degraded_reason": None if embedding_count else "index_empty",
        "semantic_available": bool(row["local_only"] and embedding_count),
        "truth_authority": "citations_provenance_policy_correction_history_not_vector_distance",
    }


def vector_to_json(vector: list[float]) -> str:
    return json.dumps(vector, separators=(",", ":"))


def vector_from_json(text: str | None) -> list[float]:
    if not text:
        raise EmbeddingError("missing_vector_json")
    vector = json.loads(text)
    if not isinstance(vector, list) or not all(isinstance(value, (int, float)) for value in vector):
        raise EmbeddingError("invalid_vector_json")
    return [float(value) for value in vector]
