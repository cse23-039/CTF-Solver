"""Additional memory trust controls for high-cost decision gating."""
from __future__ import annotations

import time
from typing import Any


def score_entry(rec: dict[str, Any]) -> float:
    score = 0.35
    source_strength = float(rec.get("source_strength", 0.5) or 0.5)
    reproducibility = float(rec.get("reproducibility_count", 0.0) or 0.0)
    val = rec.get("validator", {}) if isinstance(rec.get("validator", {}), dict) else {}
    val_conf = float(val.get("confidence", 0.0) or 0.0)

    score += max(0.0, min(0.35, source_strength * 0.35))
    score += max(0.0, min(0.20, reproducibility * 0.05))
    if val.get("verdict") == "pass":
        score += 0.12
    score += max(0.0, min(0.18, val_conf * 0.18))

    ts = int(rec.get("timestamp", 0) or 0)
    if ts > 0:
        age_days = max(0.0, (time.time() - ts) / 86400.0)
        score -= min(0.20, age_days * 0.003)

    return max(0.0, min(1.0, score))


def filter_for_high_cost(memory_hits: list[dict[str, Any]], min_trust: float = 0.62) -> list[dict[str, Any]]:
    out = []
    for rec in memory_hits:
        s = score_entry(rec)
        rec2 = dict(rec)
        rec2["_trust_control_score"] = round(s, 4)
        if s >= float(min_trust):
            out.append(rec2)
    return out
