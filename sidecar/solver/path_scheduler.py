"""Path scheduling for symbolic exploration budgets."""
from __future__ import annotations

from typing import Any


def schedule_paths(paths: list[dict[str, Any]], budget: int = 16, strategy: str = "best_first") -> list[dict[str, Any]]:
    if not paths:
        return []
    scored = []
    for p in paths:
        depth = float(p.get("depth", 0.0))
        rarity = float(p.get("rarity", 0.0))
        exploit = float(p.get("exploitability", 0.0))
        solved = float(p.get("solved_ratio", 0.0))
        # Prefer rare, exploitable, shallow-enough paths and de-prioritize already-solved classes.
        score = (0.35 * rarity) + (0.35 * exploit) + (0.2 * (1.0 / (1.0 + depth))) + (0.1 * (1.0 - solved))
        q = dict(p)
        q["schedule_score"] = round(score, 6)
        scored.append(q)

    reverse = strategy != "depth_first"
    key = (lambda x: x.get("schedule_score", 0.0)) if reverse else (lambda x: x.get("depth", 0.0))
    scored.sort(key=key, reverse=reverse)
    return scored[: max(1, int(budget))]


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    paths = input_data if isinstance(input_data, list) else kwargs.get("paths", [])
    selected = schedule_paths(paths, budget=int(kwargs.get("budget", 16)), strategy=kwargs.get("strategy", "best_first"))
    return {"selected": selected, "count": len(selected)}
