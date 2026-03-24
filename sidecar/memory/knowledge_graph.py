from __future__ import annotations

import os
import sqlite3
import time


def _default_db_path() -> str:
    return os.path.expanduser("~/.ctf-solver/knowledge_corpus.sqlite3")


def _kgkey(v: str) -> str:
    return str(v or "default").strip().lower().replace(" ", "_")


class KnowledgeGraphStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or _default_db_path()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=8)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS facts (
                    ctf_key TEXT NOT NULL,
                    fact_key TEXT NOT NULL,
                    fact_value TEXT NOT NULL,
                    updated_ts INTEGER NOT NULL,
                    PRIMARY KEY (ctf_key, fact_key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edges (
                    ctf_key TEXT NOT NULL,
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    rel TEXT NOT NULL,
                    created_ts INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_ctf ON edges(ctf_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_ctf ON facts(ctf_key)")

    def upsert_fact(self, ctf_name: str, key: str, value: str) -> None:
        k = _kgkey(ctf_name)
        ts = int(time.time())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO facts(ctf_key, fact_key, fact_value, updated_ts)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ctf_key, fact_key) DO UPDATE SET
                    fact_value = excluded.fact_value,
                    updated_ts = excluded.updated_ts
                """,
                (k, key, str(value), ts),
            )
            conn.execute(
                "INSERT INTO edges(ctf_key, source_node, target_node, rel, created_ts) VALUES (?, ?, ?, ?, ?)",
                (k, f"ctf:{k}", f"fact:{k}:{key}", "has_fact", ts),
            )

    def query_context(self, ctf_name: str, query_terms: set[str], max_items: int = 8) -> list[str]:
        k = _kgkey(ctf_name)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT fact_key, fact_value FROM facts WHERE ctf_key = ? ORDER BY updated_ts DESC LIMIT 400",
                (k,),
            ).fetchall()

        out: list[tuple[int, str]] = []
        for row in rows:
            fk = str(row["fact_key"])
            fv = str(row["fact_value"])
            txt = f"{fk} {fv}".lower()
            overlap = len(query_terms & set(txt.split())) if query_terms else 1
            if overlap > 0:
                out.append((overlap, f"{fk}: {fv[:200]}"))
        out.sort(key=lambda x: x[0], reverse=True)
        return [v for _, v in out[:max_items]]

    def get_facts(self, ctf_name: str, limit: int = 500) -> dict[str, str]:
        k = _kgkey(ctf_name)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT fact_key, fact_value FROM facts WHERE ctf_key = ? ORDER BY updated_ts DESC LIMIT ?",
                (k, int(limit)),
            ).fetchall()
        out: dict[str, str] = {}
        for row in rows:
            out[str(row["fact_key"])] = str(row["fact_value"])
        return out
