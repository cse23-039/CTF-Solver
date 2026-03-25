"""Routing/controller helpers extracted from engine."""
from __future__ import annotations


def debate_threshold_for_difficulty(difficulty: str) -> int:
    return 65 if str(difficulty or "").lower() in ("hard", "insane") else 80


def should_trigger_debate(
    route_score: int,
    difficulty: str,
    debate_used: bool,
    debate_enabled: bool,
) -> bool:
    if debate_used or not debate_enabled:
        return False
    return int(route_score) >= debate_threshold_for_difficulty(difficulty)


def build_route_decision(route_fn, **kwargs) -> dict:
    """Small shim to centralize route decision invocation and future instrumentation."""
    return route_fn(**kwargs)
