"""SLO control loop to adapt runtime behavior under pressure."""
from __future__ import annotations

from typing import Any


def compute_pressure(*, p95_latency_s: float, queue_depth: int, error_rate: float, burn_velocity: float) -> float:
    lat = min(1.0, max(0.0, float(p95_latency_s) / 900.0))
    q = min(1.0, max(0.0, float(queue_depth) / 24.0))
    err = min(1.0, max(0.0, float(error_rate)))
    burn = min(1.0, max(0.0, float(burn_velocity) / 1.5))
    return max(0.0, min(1.0, (0.35 * lat) + (0.25 * q) + (0.25 * err) + (0.15 * burn)))


def decide_controls(pressure: float) -> dict[str, Any]:
    p = max(0.0, min(1.0, float(pressure)))
    controls = {
        "pressure": round(p, 4),
        "throttle": False,
        "max_tool_calls": 3,
        "thinking_cap": 12000,
        "force_local_only": False,
    }
    if p >= 0.75:
        controls.update({"throttle": True, "max_tool_calls": 1, "thinking_cap": 4096, "force_local_only": True})
    elif p >= 0.55:
        controls.update({"throttle": True, "max_tool_calls": 2, "thinking_cap": 6000})
    elif p >= 0.35:
        controls.update({"max_tool_calls": 2, "thinking_cap": 8000})
    return controls
