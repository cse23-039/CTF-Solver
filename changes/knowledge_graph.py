"""Cross-CTF knowledge graph with similarity search.

Enhancement 4: Extends the existing per-CTF KnowledgeGraphStore with
cross-CTF pattern queries — finds matching exploit techniques, vulnerability
classes, and flag prefixes across ALL past CTFs, not just the current one.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Any


def _default_db_path() -> str:
    return os.path.expanduser("~/.ctf-solver/knowledge_corpus.sqlite3")


def _kgkey(v: str) -> str:
    return str(v or "default").strip().lower().replace(" ", "_")


class KnowledgeGraphStore:
    """Per-CTF knowledge graph with cross-CTF pattern search."""

    CROSS_CTF_KEYS = {
        "exploit_technique", "vulnerability_class", "flag_prefix",
        "winning_strategy", "category_last_strategy", "last_flag_prefix",
        "attack_surface", "crypto_primitive", "rev_approach",
        "web_vuln_class", "pwn_technique", "forensics_method",
    }

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS facts (
                    ctf_key TEXT NOT NULL,
                    fact_key TEXT NOT NULL,
                    fact_value TEXT NOT NULL,
                    updated_ts INTEGER NOT NULL,
                    PRIMARY KEY (ctf_key, fact_key)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS edges (
                    ctf_key TEXT NOT NULL,
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    rel TEXT NOT NULL,
                    created_ts INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cross_ctf_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    pattern_key TEXT NOT NULL,
                    pattern_value TEXT NOT NULL,
                    ctf_name TEXT NOT NULL,
                    challenge_name TEXT NOT NULL,
                    frequency INTEGER DEFAULT 1,
                    last_seen_ts INTEGER NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_ctf ON edges(ctf_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_ctf ON facts(ctf_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_patterns_cat ON cross_ctf_patterns(category, pattern_key)")

    def upsert_fact(self, ctf_name: str, key: str, value: str) -> None:
        k = _kgkey(ctf_name)
        ts = int(time.time())
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO facts(ctf_key, fact_key, fact_value, updated_ts)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ctf_key, fact_key) DO UPDATE SET
                    fact_value = excluded.fact_value,
                    updated_ts = excluded.updated_ts
            """, (k, key, str(value), ts))
            conn.execute(
                "INSERT INTO edges(ctf_key, source_node, target_node, rel, created_ts) VALUES (?, ?, ?, ?, ?)",
                (k, f"ctf:{k}", f"fact:{k}:{key}", "has_fact", ts),
            )
        if any(key.endswith(hk) or hk in key for hk in self.CROSS_CTF_KEYS):
            self._record_cross_ctf_pattern(
                category=self._infer_category_from_key(key),
                pattern_key=key,
                pattern_value=value,
                ctf_name=ctf_name,
                challenge_name=key,
            )

    def query_context(self, ctf_name: str, query_terms: set[str],
                      max_items: int = 8) -> list[str]:
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
        return {str(row["fact_key"]): str(row["fact_value"]) for row in rows}

    def _infer_category_from_key(self, key: str) -> str:
        key_lower = key.lower()
        if any(t in key_lower for t in ["crypto", "cipher", "rsa", "ecc"]):
            return "cryptography"
        if any(t in key_lower for t in ["pwn", "binary", "exploit", "rop", "heap"]):
            return "binary_exploitation"
        if any(t in key_lower for t in ["web", "sql", "xss", "ssrf", "jwt"]):
            return "web"
        if any(t in key_lower for t in ["rev", "reverse", "decompile", "disassemble"]):
            return "reverse_engineering"
        if any(t in key_lower for t in ["forensic", "pcap", "steg", "memory"]):
            return "forensics"
        return "general"

    def _record_cross_ctf_pattern(self, category: str, pattern_key: str,
                                   pattern_value: str, ctf_name: str,
                                   challenge_name: str) -> None:
        ts = int(time.time())
        with self._conn() as conn:
            existing = conn.execute("""
                SELECT id, frequency FROM cross_ctf_patterns
                WHERE category = ? AND pattern_key = ? AND pattern_value = ?
            """, (category, pattern_key, str(pattern_value)[:500])).fetchone()
            if existing:
                conn.execute("""
                    UPDATE cross_ctf_patterns
                    SET frequency = frequency + 1, last_seen_ts = ?
                    WHERE id = ?
                """, (ts, existing["id"]))
            else:
                conn.execute("""
                    INSERT INTO cross_ctf_patterns
                      (category, pattern_key, pattern_value, ctf_name, challenge_name, frequency, last_seen_ts)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                """, (category, pattern_key, str(pattern_value)[:500], ctf_name, challenge_name, ts))

    def cross_ctf_pattern_query(self, category: str = "",
                                 technique_hint: str = "",
                                 limit: int = 8) -> list[dict[str, Any]]:
        """Search across ALL past CTFs for matching patterns."""
        with self._conn() as conn:
            if category and technique_hint:
                rows = conn.execute("""
                    SELECT category, pattern_key, pattern_value, ctf_name,
                           challenge_name, frequency, last_seen_ts
                    FROM cross_ctf_patterns
                    WHERE (category = ? OR category = 'general')
                      AND (pattern_value LIKE ? OR pattern_key LIKE ?)
                    ORDER BY frequency DESC, last_seen_ts DESC LIMIT ?
                """, (category.lower(), f"%{technique_hint}%",
                      f"%{technique_hint}%", int(limit))).fetchall()
            elif category:
                rows = conn.execute("""
                    SELECT category, pattern_key, pattern_value, ctf_name,
                           challenge_name, frequency, last_seen_ts
                    FROM cross_ctf_patterns
                    WHERE category = ? OR category = 'general'
                    ORDER BY frequency DESC, last_seen_ts DESC LIMIT ?
                """, (category.lower(), int(limit))).fetchall()
            else:
                rows = conn.execute("""
                    SELECT category, pattern_key, pattern_value, ctf_name,
                           challenge_name, frequency, last_seen_ts
                    FROM cross_ctf_patterns
                    ORDER BY frequency DESC, last_seen_ts DESC LIMIT ?
                """, (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def render_cross_ctf_context(self, category: str = "",
                                  technique_hint: str = "") -> str:
        """Render cross-CTF patterns as a prompt injection block."""
        patterns = self.cross_ctf_pattern_query(
            category=category, technique_hint=technique_hint, limit=6,
        )
        if not patterns:
            return ""
        lines = ["## Cross-CTF pattern intelligence (from past solves):"]
        for p in patterns:
            lines.append(
                f"  [{p['category']}] {p['pattern_key']}: {p['pattern_value'][:200]} "
                f"(seen {p['frequency']}x, last in {p['ctf_name']})"
            )
        return "\n".join(lines)

    def ingest_solve_record(self, record: dict[str, Any]) -> None:
        """Bulk-ingest a solve record into the cross-CTF pattern table."""
        ctf = str(record.get("ctf_name", "unknown"))
        name = str(record.get("challenge_name", "unknown"))
        cat = str(record.get("category", "general")).lower().replace(" ", "_")
        technique = str(record.get("attack_technique", ""))
        tool_seq = record.get("winning_tool_sequence", [])
        flag_prefix = str(record.get("flag_prefix", ""))

        if technique:
            self._record_cross_ctf_pattern(cat, "exploit_technique", technique, ctf, name)
        if flag_prefix:
            self._record_cross_ctf_pattern(cat, "flag_prefix", flag_prefix, ctf, name)
        if tool_seq:
            seq_str = " → ".join(str(t) for t in tool_seq[:10])
            self._record_cross_ctf_pattern(cat, "winning_tool_sequence", seq_str, ctf, name)
        if technique:
            self.upsert_fact(ctf, f"{cat}_exploit_technique", technique)
        if flag_prefix:
            self.upsert_fact(ctf, f"{cat}_last_flag_prefix", flag_prefix)
