"""Hierarchical council contracts for planner/attacker/verifier/skeptic/cost governor."""
from __future__ import annotations

from typing import Any


def _vote_planner(ctx: dict[str, Any]) -> tuple[str, str]:
    if int(ctx.get("fruitless", 0)) >= 3:
        return "pivot", "fruitless>=3"
    if float(ctx.get("belief_uncertainty", 1.0)) > 0.65:
        return "probe", "high_uncertainty"
    return "continue", "plan_consistent"


def _vote_attacker(ctx: dict[str, Any]) -> tuple[str, str]:
    if float(ctx.get("route_score", 0)) >= 72 and int(ctx.get("tool_failures", 0)) < 3:
        return "exploit", "high_route_score"
    if int(ctx.get("tool_failures", 0)) >= 3:
        return "recon", "tool_failures"
    return "continue", "balanced"


def _vote_verifier(ctx: dict[str, Any]) -> tuple[str, str]:
    if int(ctx.get("evidence_count", 0)) < int(ctx.get("min_evidence", 2)):
        return "block_submit", "insufficient_evidence"
    if float(ctx.get("belief_contradiction", 0.0)) > 0.35:
        return "block_submit", "high_contradiction"
    return "allow_submit", "evidence_ok"


def _vote_skeptic(ctx: dict[str, Any]) -> tuple[str, str]:
    if float(ctx.get("hallucination_risk", 0.0)) > 0.55:
        return "veto", "hallucination_risk"
    if float(ctx.get("belief_uncertainty", 1.0)) > 0.7:
        return "veto", "uncertainty_high"
    return "ok", "risk_acceptable"


def _vote_cost_governor(ctx: dict[str, Any]) -> tuple[str, str]:
    remaining = float(ctx.get("remaining_usd", 0.0))
    if remaining <= float(ctx.get("reserve_usd", 0.3)):
        return "throttle", "low_budget"
    if float(ctx.get("token_burn_velocity", 0.0)) > 1.0:
        return "throttle", "high_burn_velocity"
    return "normal", "budget_ok"


def run_council(ctx: dict[str, Any]) -> dict[str, Any]:
    planner = _vote_planner(ctx)
    attacker = _vote_attacker(ctx)
    verifier = _vote_verifier(ctx)
    skeptic = _vote_skeptic(ctx)
    cost = _vote_cost_governor(ctx)

    veto = skeptic[0] == "veto"
    throttle = cost[0] == "throttle"
    submit_blocked = verifier[0] == "block_submit"

    action = "continue"
    if veto:
        action = "disambiguate"
    elif planner[0] == "pivot":
        action = "pivot"
    elif attacker[0] == "exploit":
        action = "exploit"
    elif attacker[0] == "recon":
        action = "recon"

    return {
        "action": action,
        "veto": veto,
        "throttle": throttle,
        "submit_blocked": submit_blocked,
        "votes": {
            "planner": {"vote": planner[0], "reason": planner[1]},
            "attacker": {"vote": attacker[0], "reason": attacker[1]},
            "verifier": {"vote": verifier[0], "reason": verifier[1]},
            "skeptic": {"vote": skeptic[0], "reason": skeptic[1]},
            "cost_governor": {"vote": cost[0], "reason": cost[1]},
        },
    }
