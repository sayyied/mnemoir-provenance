"""compat 15.0 deterministic retrieval/evidence-selection hardening helpers.

This module is deliberately local-only and provider-free. It contains no live Hermes
profile access, no Honcho calls, and no hosted/vector database dependency.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Any, Iterable, Literal

QueryType = Literal["preference", "temporal", "multi-session", "knowledge_update", "single_session_fact", "unknown"]

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "do", "does", "did", "for", "from", "had", "has", "have",
    "how", "i", "in", "is", "it", "me", "my", "of", "on", "or", "the", "to", "was", "were", "what", "when", "where",
    "which", "who", "why", "with", "that", "this", "these", "those", "about", "after", "before", "during",
}


@dataclass(frozen=True)
class QueryRoute:
    query_type: QueryType
    scorer: str
    confidence: float
    reasons: tuple[str, ...]
    fallback_used: bool = False


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in _TOKEN_RE.findall(text or "") if len(token) > 1]


def content_tokens(text: str) -> list[str]:
    return [token for token in tokenize(text) if token not in _STOPWORDS]


def classify_query_type(query: str, *, source_type: str | None = None) -> QueryRoute:
    """Classify a query with deterministic explainable rules and safe fallback."""
    lower = (query or "").lower()
    tokens = set(tokenize(lower))
    reasons: list[str] = []
    query_type: QueryType = "unknown"
    confidence = 0.2

    if any(term in lower for term in ["prefer", "preference", "favorite", "favourite", "like best", "usually choose", "rather"]):
        query_type = "preference"
        confidence = 0.86
        reasons.append("preference_keyword")
    elif any(term in lower for term in ["latest", "most recent", "now", "currently", "updated", "change", "changed", "instead", "new", "old", "previous"]):
        query_type = "knowledge_update"
        confidence = 0.82
        reasons.append("update_keyword")
    elif any(term in lower for term in ["across sessions", "multiple sessions", "over time", "history", "total", "sum", "count", "how many times", "compare"]):
        query_type = "multi-session"
        confidence = 0.82
        reasons.append("multi_session_keyword")
    elif any(term in tokens for term in ["when", "before", "after", "date", "time", "first", "last", "earliest", "latest"]):
        query_type = "temporal"
        confidence = 0.74
        reasons.append("temporal_keyword")
    elif any(term in tokens for term in ["what", "which", "who", "where"]):
        query_type = "single_session_fact"
        confidence = 0.66
        reasons.append("fact_question_keyword")

    if source_type:
        mapped = normalize_external_question_type(source_type)
        if mapped != "unknown" and (query_type == "unknown" or confidence < 0.75):
            query_type = mapped
            confidence = max(confidence, 0.72)
            reasons.append(f"source_type:{source_type}")

    scorer = scorer_for_query_type(query_type)
    fallback_used = query_type == "unknown" or confidence < 0.5
    if fallback_used:
        scorer = "tfidf_word_1_2"
        reasons.append("safe_tfidf_fallback")
    return QueryRoute(query_type=query_type, scorer=scorer, confidence=round(confidence, 3), reasons=tuple(reasons), fallback_used=fallback_used)


def normalize_external_question_type(question_type: str | None) -> QueryType:
    value = (question_type or "").lower().replace("_", "-")
    if "preference" in value:
        return "preference"
    if "temporal" in value:
        return "temporal"
    if "multi-session" in value or "multisession" in value:
        return "multi-session"
    if "knowledge-update" in value or "knowledge" in value and "update" in value:
        return "knowledge_update"
    if "single-session" in value or value in {"single-session-user", "single-session-assistant"}:
        return "single_session_fact"
    return "unknown"


def scorer_for_query_type(query_type: QueryType) -> str:
    # Conservative compat 15.0 routing: only select strategies benchmarked in the
    # local scorer family. Preference/temporal/update queries keep the stronger
    # lexical TF-IDF path; multi-session uses RRF to protect breadth; unknown falls
    # back to TF-IDF.
    if query_type == "multi-session":
        return "rrf_overlap_tfidf"
    return "tfidf_word_1_2"


def bm25_scores(query: str, documents: Iterable[str], *, k1: float = 1.5, b: float = 0.75) -> list[float]:
    docs = [content_tokens(document) for document in documents]
    query_terms = content_tokens(query)
    if not docs or not query_terms:
        return [0.0 for _doc in docs]
    doc_count = len(docs)
    avg_len = sum(len(doc) for doc in docs) / max(doc_count, 1)
    df: Counter[str] = Counter()
    for doc in docs:
        for term in set(doc):
            df[term] += 1
    scores: list[float] = []
    for doc in docs:
        freqs = Counter(doc)
        doc_len = len(doc) or 1
        score = 0.0
        for term in query_terms:
            if not freqs.get(term):
                continue
            idf = math.log(1.0 + ((doc_count - df[term] + 0.5) / (df[term] + 0.5)))
            numerator = freqs[term] * (k1 + 1.0)
            denominator = freqs[term] + k1 * (1.0 - b + b * (doc_len / max(avg_len, 1e-9)))
            score += idf * (numerator / denominator)
        scores.append(round(score, 9))
    return scores


def rank_pairs_bm25(query: str, pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    scores = bm25_scores(query, [text for _sid, text in pairs])
    ranked = [(float(score), -index, session_id, text) for index, ((session_id, text), score) in enumerate(zip(pairs, scores))]
    ranked.sort(reverse=True)
    return [(session_id, text) for _score, _neg_index, session_id, text in ranked]


def split_sentences(text: str) -> list[str]:
    sentences = [part.strip() for part in _SENTENCE_RE.split(text or "") if part.strip()]
    return sentences or ([text.strip()] if text and text.strip() else [])


def extract_answer_bearing_window(
    text: str,
    query: str,
    *,
    answer: str | None = None,
    window_sentences: int = 1,
    max_chars: int = 500,
) -> dict[str, Any]:
    """Return an extractive cited window; never synthesize unavailable answer text."""
    sentences = split_sentences(text)
    if not sentences:
        return {"status": "degraded", "window": "", "answer_bearing": False, "fabricated": False, "reason": "empty_text"}
    answer_lower = (answer or "").strip().lower()
    query_terms = set(content_tokens(query))
    answer_terms = set(content_tokens(answer or ""))
    best_index = 0
    best_score = -1.0
    for index, sentence in enumerate(sentences):
        lower = sentence.lower()
        sentence_terms = set(content_tokens(sentence))
        score = 0.0
        if answer_lower and answer_lower in lower:
            score += 10.0
        if answer_terms:
            score += 3.0 * len(sentence_terms & answer_terms) / max(len(answer_terms), 1)
        if query_terms:
            score += len(sentence_terms & query_terms) / max(len(query_terms), 1)
        score += 0.001 * (len(sentences) - index)  # deterministic earlier tie preference
        if score > best_score:
            best_index = index
            best_score = score
    start = max(0, best_index - window_sentences)
    end = min(len(sentences), best_index + window_sentences + 1)
    window = " ".join(sentences[start:end]).strip()
    truncated = len(window) > max_chars
    if truncated:
        window = window[:max_chars].rstrip()
    answer_bearing = bool(answer_lower and answer_lower in window.lower())
    query_bearing = bool(query_terms and set(content_tokens(window)) & query_terms)
    return {
        "status": "ok" if answer_bearing or query_bearing else "degraded",
        "window": window,
        "answer_bearing": answer_bearing,
        "query_bearing": query_bearing,
        "fabricated": False,
        "source": "extractive_sentence_window",
        "sentence_start_index": start,
        "sentence_end_index": end - 1,
        "truncated": truncated,
        "max_chars": max_chars,
    }


def add_evidence_windows_to_ranked_pairs(
    ranked_pairs: list[tuple[str, str]],
    query: str,
    *,
    answer: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    for rank, (session_id, text) in enumerate(ranked_pairs[:limit], start=1):
        window = extract_answer_bearing_window(text, query, answer=answer)
        windows.append({"rank": rank, "session_id": session_id, "window": window, "source_metadata_preserved": True})
    return windows
