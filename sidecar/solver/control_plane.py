"""Adaptive control plane for runtime tuning based on telemetry and confidence bands."""
from __future__ import annotations

from typing import Any


def tune_runtime_knobs(category: str, learned_overrides: dict[str, Any] | None, benchmark_tail: list[dict[str, Any]] | None) -> dict[str, Any]:
    lo = learned_overrides or {}
    rows = benchmark_tail or []

    fail_count = len([r for r in rows[-15:] if str(r.get("verdict", "")) != "pass"])
    regress_count = len([r for r in rows[-15:] if bool(r.get("regressed", False))])

    route_escalate = int(lo.get("route_escalate_score", 62))
    route_soft = int(lo.get("route_soft_escalate_score", 48))
    pivot_fruitless = int(lo.get("pivot_fruitless", 3))
    pivot_tool_failures = int(lo.get("pivot_tool_failures", 2))

    if fail_count >= 3 or regress_count >= 2:
        route_escalate = max(52, route_escalate - 4)
        route_soft = max(44, route_soft - 3)
        pivot_fruitless = max(2, pivot_fruitless - 1)
    elif fail_count == 0 and len(rows) >= 10:
        route_escalate = min(78, route_escalate + 1)
        route_soft = min(route_escalate - 4, route_soft + 1)

    enable_debate = True
    if "crypto" in str(category or "").lower() or "reverse" in str(category or "").lower():
        enable_debate = True
    if fail_count == 0 and regress_count == 0 and len(rows) >= 8:
        enable_debate = False

    return {
        "route_escalate_score": route_escalate,
        "route_soft_escalate_score": route_soft,
        "pivot_fruitless": pivot_fruitless,
        "pivot_tool_failures": pivot_tool_failures,
        "enableSelfPlayDebate": enable_debate,
    }
