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


def allocate_mpc_budget(
    *,
    base_iterations: int,
    expected_value: float,
    difficulty: str,
    reliability_pressure: float,
) -> dict[str, int]:
    """Allocate exploration/verification/reserve iterations with a simple MPC-like policy."""
    total = max(8, int(base_iterations))
    diff = str(difficulty or "medium").lower()
    ev = max(0.0, min(2.5, float(expected_value or 0.0)))
    pressure = max(0.0, min(1.0, float(reliability_pressure or 0.0)))

    verify_ratio = 0.22 if diff in ("hard", "insane") else 0.18
    if pressure >= 0.45:
        verify_ratio += 0.06
    if ev < 0.7:
        verify_ratio += 0.04

    reserve_ratio = 0.12 if diff in ("hard", "insane") else 0.08
    if pressure >= 0.55:
        reserve_ratio += 0.05

    explore_ratio = max(0.4, 1.0 - verify_ratio - reserve_ratio)
    if ev > 1.2 and pressure < 0.4:
        explore_ratio = min(0.7, explore_ratio + 0.08)
        verify_ratio = max(0.14, verify_ratio - 0.04)

    verify_iters = max(2, int(round(total * verify_ratio)))
    reserve_iters = max(1, int(round(total * reserve_ratio)))
    explore_iters = max(3, total - verify_iters - reserve_iters)
    normalized_total = explore_iters + verify_iters + reserve_iters
    if normalized_total != total:
        explore_iters += (total - normalized_total)

    return {
        "total": total,
        "explore": max(1, explore_iters),
        "verify": max(1, verify_iters),
        "reserve": max(1, reserve_iters),
    }
