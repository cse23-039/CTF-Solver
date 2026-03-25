"""Self-improving policy over tool chains using lightweight UCB."""
from __future__ import annotations

import json
import math
import os
from typing import Any


class ToolChainPolicy:
    def __init__(self, path: str) -> None:
        self.path = path
        self.state = {"chains": {}, "total": 0}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.state = {"chains": data.get("chains", {}), "total": int(data.get("total", 0) or 0)}
        except Exception:
            return

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=2)

    def update(self, chain: str, success: bool) -> None:
        key = str(chain or "").strip().lower()
        if not key:
            return
        rec = self.state["chains"].get(key, {"pulls": 0, "wins": 0})
        rec["pulls"] = int(rec.get("pulls", 0)) + 1
        rec["wins"] = int(rec.get("wins", 0)) + (1 if bool(success) else 0)
        self.state["chains"][key] = rec
        self.state["total"] = int(self.state.get("total", 0)) + 1

    def score(self, chain: str) -> float:
        key = str(chain or "").strip().lower()
        rec = self.state["chains"].get(key, {"pulls": 1, "wins": 0})
        pulls = max(1, int(rec.get("pulls", 1)))
        wins = max(0, int(rec.get("wins", 0)))
        mu = wins / pulls
        total = max(2, int(self.state.get("total", 0) or 0))
        ucb = mu + math.sqrt((2.0 * math.log(total)) / pulls)
        return float(ucb)

    def rerank(self, tools: list[str], prev_tool: str) -> list[str]:
        prev = str(prev_tool or "").strip().lower()
        if not prev:
            return list(tools)
        scored = []
        for t in tools:
            key = f"{prev}->{str(t or '').strip().lower()}"
            scored.append((self.score(key), t))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored]
