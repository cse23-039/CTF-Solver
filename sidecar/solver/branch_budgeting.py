"""Multi-armed branch budgeting with UCB scoring and early-stop heuristics."""
from __future__ import annotations

import math
from typing import Any


def allocate_budget(branch_stats: list[dict[str, Any]], total_budget: int) -> list[dict[str, Any]]:
    n = max(1, len(branch_stats))
    total_budget = max(n, int(total_budget))
    pulls_sum = sum(max(1, int(b.get("pulls", 1))) for b in branch_stats)

    scored = []
    for b in branch_stats:
        pulls = max(1, int(b.get("pulls", 1)))
        wins = max(0, int(b.get("wins", 0)))
        mu = wins / pulls
        ucb = mu + math.sqrt((2.0 * math.log(max(2, pulls_sum))) / pulls)
        scored.append((ucb, b))
    scored.sort(key=lambda x: x[0], reverse=True)

    base = total_budget // n
    rem = total_budget % n
    out = []
    for i, (_, b) in enumerate(scored):
        alloc = base + (1 if i < rem else 0)
        out.append({**b, "allocated": max(1, alloc)})
    return out


def should_early_stop_branch(*, pulls: int, wins: int, min_pulls: int = 3, fail_ratio: float = 0.8) -> bool:
    pulls = int(pulls)
    wins = int(wins)
    if pulls < max(1, int(min_pulls)):
        return False
    fails = max(0, pulls - wins)
    return (fails / max(1, pulls)) >= max(0.5, min(0.98, float(fail_ratio)))
