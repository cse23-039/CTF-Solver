"""Cross-branch memory fusion with provenance, decay, and conflict resolution."""
from __future__ import annotations

import math
import time
from typing import Any


def _decayed_confidence(confidence: float, age_min: float, half_life_min: float) -> float:
    if half_life_min <= 0:
        return confidence
    return float(confidence) * (0.5 ** (max(0.0, age_min) / half_life_min))


def fuse(results: list[dict[str, Any]], half_life_min: float = 90.0) -> dict[str, Any]:
    now = time.time()
    fused: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        branch = str(r.get("branch", "unknown"))
        ts = float(r.get("timestamp", now))
        age_min = (now - ts) / 60.0
        for fact in r.get("facts", []):
            key = str(fact.get("key", ""))
            if not key:
                continue
            conf = float(fact.get("confidence", 0.5))
            decayed = _decayed_confidence(conf, age_min, half_life_min)
            entry = {
                "value": fact.get("value"),
                "confidence": decayed,
                "source_branch": branch,
                "age_min": round(age_min, 3),
                "provenance": fact.get("provenance", "runtime"),
            }
            fused.setdefault(key, []).append(entry)

    merged = {}
    conflicts = {}
    for key, entries in fused.items():
        entries.sort(key=lambda x: x["confidence"], reverse=True)
        best = entries[0]
        merged[key] = best
        distinct_values = {str(e.get("value")) for e in entries}
        if len(distinct_values) > 1:
            conflicts[key] = entries[:5]

    return {"merged": merged, "conflicts": conflicts, "fact_count": len(merged)}


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    items = input_data if isinstance(input_data, list) else kwargs.get("results", [])
    return fuse(items, half_life_min=float(kwargs.get("half_life_min", 90.0)))
