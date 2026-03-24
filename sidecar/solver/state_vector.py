"""Compact state vector extraction for per-iteration policy decisions."""
from __future__ import annotations

from typing import Any


def _norm(v: float, lo: float, hi: float) -> float:
    if hi <= lo:
        return 0.0
    return max(0.0, min(1.0, (v - lo) / (hi - lo)))


def build_state_vector(
    *,
    category: str,
    phase: str,
    signal_quality: float,
    reliability_trend: float,
    contradiction_score: float,
    exploit_maturity: float,
    fruitless: int,
    tool_failures: int,
    iteration: int,
    total_iters: int,
    is_remote: bool,
    has_binary: bool,
) -> dict[str, Any]:
    progress = _norm(float(iteration), 0.0, float(max(1, total_iters)))
    f_norm = _norm(float(fruitless), 0.0, 10.0)
    tf_norm = _norm(float(tool_failures), 0.0, 10.0)
    vector = {
        "category": (category or "unknown").lower(),
        "phase": (phase or "recon").lower(),
        "signal_quality": max(0.0, min(1.0, float(signal_quality))),
        "reliability_trend": max(-1.0, min(1.0, float(reliability_trend))),
        "contradiction_score": max(0.0, min(1.0, float(contradiction_score))),
        "exploit_maturity": max(0.0, min(1.0, float(exploit_maturity))),
        "fruitless": int(fruitless),
        "tool_failures": int(tool_failures),
        "progress": progress,
        "is_remote": bool(is_remote),
        "has_binary": bool(has_binary),
        "difficulty_pressure": round((f_norm * 0.55) + (tf_norm * 0.45), 4),
    }
    return vector
