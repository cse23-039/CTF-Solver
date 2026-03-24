"""Category-specialized adaptation profiles and thresholds."""
from __future__ import annotations

from typing import Any


DEFAULT_PROFILE = {
    "pivot_fruitless": 3,
    "pivot_tool_failures": 2,
    "route_escalate_score": 70,
    "route_soft_escalate_score": 58,
    "confidence_decay_fruitless": 0.08,
    "confidence_decay_tool_failures": 0.12,
}


PROFILES: dict[str, dict[str, Any]] = {
    "pwn": {
        **DEFAULT_PROFILE,
        "pivot_fruitless": 2,
        "pivot_tool_failures": 2,
        "route_escalate_score": 64,
        "route_soft_escalate_score": 52,
    },
    "web": {
        **DEFAULT_PROFILE,
        "pivot_fruitless": 3,
        "pivot_tool_failures": 3,
        "route_escalate_score": 72,
        "route_soft_escalate_score": 60,
    },
    "crypto": {
        **DEFAULT_PROFILE,
        "pivot_fruitless": 2,
        "pivot_tool_failures": 2,
        "route_escalate_score": 60,
        "route_soft_escalate_score": 50,
    },
    "rev": {
        **DEFAULT_PROFILE,
        "pivot_fruitless": 2,
        "pivot_tool_failures": 2,
        "route_escalate_score": 62,
        "route_soft_escalate_score": 52,
    },
    "forensics": {
        **DEFAULT_PROFILE,
        "pivot_fruitless": 4,
        "pivot_tool_failures": 3,
        "route_escalate_score": 76,
        "route_soft_escalate_score": 64,
    },
}


def infer_category_key(category: str) -> str:
    c = (category or "").lower()
    if "pwn" in c or "binary" in c:
        return "pwn"
    if "web" in c:
        return "web"
    if "crypto" in c:
        return "crypto"
    if "reverse" in c or "rev" in c:
        return "rev"
    if "forensic" in c:
        return "forensics"
    return "web"


def get_profile(category: str, learned_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    key = infer_category_key(category)
    prof = dict(PROFILES.get(key, DEFAULT_PROFILE))
    if learned_overrides:
        prof.update({k: v for k, v in learned_overrides.items() if k in prof})
    prof["category_key"] = key
    return prof


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    category = str(kwargs.get("category", input_data if isinstance(input_data, str) else "unknown"))
    return get_profile(category, learned_overrides=kwargs.get("learned_overrides"))
