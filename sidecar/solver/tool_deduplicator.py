"""Session-scoped tool deduplication with argument similarity checks."""
from __future__ import annotations

import hashlib
import json
from difflib import SequenceMatcher
from typing import Any


class ToolDeduplicator:
    def __init__(self, similarity_threshold: float = 0.70, history_limit: int = 200) -> None:
        self.similarity_threshold = max(0.0, min(1.0, float(similarity_threshold)))
        self.history_limit = max(20, int(history_limit))
        self._history: list[dict[str, Any]] = []

    def _stable_args(self, args: dict[str, Any]) -> str:
        try:
            return json.dumps(args or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except Exception:
            return str(args or "")

    def _args_similarity(self, a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return float(SequenceMatcher(a=a, b=b).ratio())

    def _key_hash(self, tool_name: str, stable_args: str) -> str:
        raw = f"{tool_name}::{stable_args}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def register_or_block(self, tool_name: str, tool_args: dict[str, Any], recommended_tools: list[str] | None = None) -> dict[str, Any]:
        name = str(tool_name or "")
        args = tool_args if isinstance(tool_args, dict) else {}
        stable_args = self._stable_args(args)
        key_hash = self._key_hash(name, stable_args)

        best_sim = 0.0
        best_hash = ""
        for item in self._history:
            if item.get("tool") != name:
                continue
            sim = self._args_similarity(stable_args, str(item.get("args", "")))
            if sim > best_sim:
                best_sim = sim
                best_hash = str(item.get("hash", ""))

        blocked = best_sim >= self.similarity_threshold
        diversify = ""
        if blocked:
            for cand in (recommended_tools or []):
                c = str(cand or "")
                if c and c != name:
                    diversify = c
                    break
            if not diversify:
                diversify = "pre_solve_recon" if name != "pre_solve_recon" else "rank_hypotheses"

        self._history.append({"tool": name, "args": stable_args, "hash": key_hash})
        if len(self._history) > self.history_limit:
            self._history = self._history[-self.history_limit :]

        return {
            "blocked": blocked,
            "similarity": round(best_sim, 4),
            "hash": key_hash,
            "matched_hash": best_hash,
            "diversify_tool": diversify,
            "diversify_args": {},
        }
