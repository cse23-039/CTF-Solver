"""Embedding-based RAG store for writeup and challenge similarity retrieval.

Enhancement 1: Semantic retrieval over past writeups using lightweight
sentence embeddings (no heavy ML dependency — uses hash-projection when
sentence-transformers is unavailable, upgrades automatically when installed).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
from typing import Any

try:
    import numpy as _np  # type: ignore
except Exception:  # pragma: no cover
    _np = None

try:
    import faiss as _faiss  # type: ignore
except Exception:  # pragma: no cover
    _faiss = None

_DEFAULT_DB = os.path.expanduser("~/.ctf-solver/rag_corpus.sqlite3")


def _embed_text(text: str, dim: int = 128) -> list[float]:
    """
    Produce a dense embedding vector for text.

    Priority:
    1. sentence-transformers (best quality)
    2. Hash-projection fallback (deterministic, 0 dependencies)
    """
    text = str(text or "")[:4096].strip()

    try:
        from sentence_transformers import SentenceTransformer  # type: ignore

        _embed_text._model = getattr(_embed_text, "_model", None) or SentenceTransformer("all-MiniLM-L6-v2")
        vec = _embed_text._model.encode(text, normalize_embeddings=True).tolist()
        return vec[:dim] if len(vec) >= dim else vec + [0.0] * (dim - len(vec))
    except Exception:
        pass

    vec = [0.0] * dim
    words = text.lower().split()
    for word in words:
        h = hashlib.sha256(word.encode()).digest()
        for i in range(min(dim, len(h))):
            vec[i] += (h[i] - 128) / 128.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (na * nb)


class RAGStore:
    """
    Persists challenge descriptions paired with their solved attack path.
    Supports semantic k-NN retrieval across ALL past CTFs.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or _DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()
        self._faiss_cache = None

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=8)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS writeup_embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ctf_name TEXT NOT NULL,
                    challenge_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    difficulty TEXT NOT NULL,
                    description_text TEXT NOT NULL,
                    attack_technique TEXT NOT NULL,
                    winning_tool_sequence TEXT NOT NULL,
                    solve_summary TEXT NOT NULL,
                    embedding TEXT NOT NULL,
                    created_ts INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_cat ON writeup_embeddings(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_ctf ON writeup_embeddings(ctf_name)")

    def ingest(self, record: dict[str, Any]) -> None:
        text = f"{record.get('challenge_name', '')} {record.get('description_text', '')} {record.get('category', '')}"
        emb = _embed_text(text)
        ts = int(time.time())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO writeup_embeddings
                  (ctf_name, challenge_name, category, difficulty, description_text,
                   attack_technique, winning_tool_sequence, solve_summary, embedding, created_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.get("ctf_name", "unknown")),
                    str(record.get("challenge_name", "unknown")),
                    str(record.get("category", "unknown")),
                    str(record.get("difficulty", "medium")),
                    str(record.get("description_text", ""))[:4000],
                    str(record.get("attack_technique", ""))[:500],
                    json.dumps(record.get("winning_tool_sequence", [])[:40]),
                    str(record.get("solve_summary", ""))[:3000],
                    json.dumps(emb),
                    ts,
                ),
            )

    def query(self, description: str, category: str = "", top_k: int = 3, min_similarity: float = 0.25) -> list[dict[str, Any]]:
        query_text = f"{description} {category}".strip()
        q_emb = _embed_text(query_text)

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT ctf_name, challenge_name, category, difficulty,
                       attack_technique, winning_tool_sequence, solve_summary, embedding
                FROM writeup_embeddings
                ORDER BY created_ts DESC LIMIT 2000
                """
            ).fetchall()

        # Optional FAISS fast path.
        if _faiss is not None and _np is not None and rows:
            try:
                vecs = []
                meta = []
                for row in rows:
                    emb = json.loads(row["embedding"])
                    if not isinstance(emb, list):
                        continue
                    vecs.append(emb)
                    meta.append(row)
                if vecs and meta:
                    arr = _np.asarray(vecs, dtype="float32")
                    idx = _faiss.IndexFlatIP(arr.shape[1])
                    idx.add(arr)
                    q = _np.asarray([q_emb], dtype="float32")
                    sims, ids = idx.search(q, min(max(1, int(top_k * 4)), len(meta)))
                    faiss_out: list[dict[str, Any]] = []
                    for sim, ridx in zip(sims[0], ids[0]):
                        if int(ridx) < 0 or int(ridx) >= len(meta):
                            continue
                        if float(sim) < min_similarity:
                            continue
                        r = meta[int(ridx)]
                        faiss_out.append(
                            {
                                "ctf_name": r["ctf_name"],
                                "challenge_name": r["challenge_name"],
                                "category": r["category"],
                                "difficulty": r["difficulty"],
                                "attack_technique": r["attack_technique"],
                                "winning_tool_sequence": json.loads(r["winning_tool_sequence"] or "[]"),
                                "solve_summary": r["solve_summary"][:800],
                                "similarity": round(float(sim), 4),
                            }
                        )
                    if faiss_out:
                        return faiss_out[:top_k]
            except Exception:
                pass

        scored: list[tuple[float, dict]] = []
        for row in rows:
            try:
                emb = json.loads(row["embedding"])
                sim = _cosine(q_emb, emb)
            except Exception:
                continue
            if sim >= min_similarity:
                scored.append(
                    (
                        sim,
                        {
                            "ctf_name": row["ctf_name"],
                            "challenge_name": row["challenge_name"],
                            "category": row["category"],
                            "difficulty": row["difficulty"],
                            "attack_technique": row["attack_technique"],
                            "winning_tool_sequence": json.loads(row["winning_tool_sequence"] or "[]"),
                            "solve_summary": row["solve_summary"][:800],
                            "similarity": round(sim, 4),
                        },
                    )
                )

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    def render_context_for_prompt(self, results: list[dict[str, Any]]) -> str:
        if not results:
            return ""
        lines = ["## Similar solved challenges (RAG context — use as inspiration, not as ground truth):"]
        for i, r in enumerate(results, 1):
            lines.append(
                f"\n### [{i}] {r['challenge_name']} ({r['ctf_name']}, {r['category']}, {r['difficulty']}) "
                f"— similarity {r['similarity']:.2f}"
            )
            lines.append(f"Attack technique: {r['attack_technique']}")
            if r.get("winning_tool_sequence"):
                lines.append(f"Winning tool path: {' → '.join(r['winning_tool_sequence'][:12])}")
            lines.append(f"Summary: {r['solve_summary'][:400]}")
        return "\n".join(lines)


_RAG_STORE: RAGStore | None = None


def get_rag_store(db_path: str | None = None) -> RAGStore:
    global _RAG_STORE
    if _RAG_STORE is None:
        _RAG_STORE = RAGStore(db_path)
    return _RAG_STORE


def ingest_solved_challenge(record: dict[str, Any]) -> None:
    try:
        get_rag_store().ingest(record)
    except Exception:
        pass


def retrieve_similar_challenges(description: str, category: str = "", top_k: int = 3) -> list[dict[str, Any]]:
    try:
        return get_rag_store().query(description, category=category, top_k=top_k)
    except Exception:
        return []


def render_rag_context(description: str, category: str = "", top_k: int = 3) -> str:
    results = retrieve_similar_challenges(description, category=category, top_k=top_k)
    return get_rag_store().render_context_for_prompt(results)
