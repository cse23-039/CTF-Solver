"""Detect potentially poisoned/inconsistent hint signals."""
from __future__ import annotations

import re
from typing import Any


_CONTRA_PAIRS = [
    (r"no\s+network", r"http|https|url|endpoint|server"),
    (r"static\s+only", r"remote|instance|nc\s+|socket"),
    (r"easy", r"heap|kernel|side\s*channel|lattice|rop"),
]


def detect_hint_deception(description: str, hints: list[str] | None = None) -> dict[str, Any]:
    text = "\n".join([str(description or "")] + [str(h) for h in (hints or [])]).lower()
    hits = []
    for a, b in _CONTRA_PAIRS:
        if re.search(a, text) and re.search(b, text):
            hits.append({"pattern_a": a, "pattern_b": b})
    risk = min(1.0, 0.25 * len(hits))
    return {
        "risk": round(risk, 4),
        "flags": hits,
        "suspicious": bool(risk >= 0.25),
    }
