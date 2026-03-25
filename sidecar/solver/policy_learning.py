"""Telemetry persistence and weekly policy learning for routing/strategy priors."""
from __future__ import annotations

import json
import os
import statistics
import time
from collections import defaultdict
from typing import Any


DEFAULT_PRIORS = {
    "global": {},
    "by_category": {},
    "last_retrain_ts": 0,
}


def _norm_cat(category: str) -> str:
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


_DIFF_ORDER = ["easy", "medium", "hard", "insane"]


def _diff_idx(v: str) -> int:
    v2 = str(v or "medium").lower()
    return _DIFF_ORDER.index(v2) if v2 in _DIFF_ORDER else 1


def _load(path: str, fallback: Any) -> Any:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return fallback


def _save(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def append_iteration_telemetry(path: str, record: dict[str, Any]) -> None:
    rows = _load(path, [])
    rows.append({"ts": int(time.time()), **record})
    _save(path, rows[-20000:])


def should_retrain_weekly(priors_path: str, now_ts: int | None = None) -> bool:
    now = int(now_ts or time.time())
    priors = _load(priors_path, DEFAULT_PRIORS)
    last_ts = int(priors.get("last_retrain_ts", 0) or 0)
    return (now - last_ts) >= 7 * 24 * 3600


def retrain_priors(telemetry_path: str, priors_path: str) -> dict[str, Any]:
    rows = _load(telemetry_path, [])
    if not rows:
        priors = dict(DEFAULT_PRIORS)
        priors["last_retrain_ts"] = int(time.time())
        _save(priors_path, priors)
        return priors

    by_cat = defaultdict(list)
    for r in rows:
        by_cat[_norm_cat(str(r.get("category", "")))].append(r)

    priors = {"global": {}, "by_category": {}, "last_retrain_ts": int(time.time())}

    for cat, items in by_cat.items():
        solved_items = [x for x in items if bool(x.get("solved", False))]
        failed_items = [x for x in items if bool(x.get("failed", False)) or not bool(x.get("solved", False))]
        solve_rate = len(solved_items) / max(1, len(items))
        fail_rate = len(failed_items) / max(1, len(items))
        avg_fruitless = statistics.mean([float(x.get("fruitless", 0.0)) for x in items])
        avg_failures = statistics.mean([float(x.get("tool_failures", 0.0)) for x in items])
        avg_route = statistics.mean([float(x.get("route_score", 50.0)) for x in items])
        failed_fruitless = statistics.mean([float(x.get("fruitless", 0.0)) for x in failed_items]) if failed_items else avg_fruitless
        failed_tool_failures = statistics.mean([float(x.get("tool_failures", 0.0)) for x in failed_items]) if failed_items else avg_failures
        failed_strategy_counts: dict[str, int] = defaultdict(int)
        for x in failed_items:
            mode = str(x.get("strategy_mode", "") or "").strip()
            if mode:
                failed_strategy_counts[mode] += 1
        strategy_penalties = {
            k: round(min(0.45, (v / max(1, len(failed_items))) * 0.75), 4)
            for k, v in failed_strategy_counts.items()
        }
        dominant_failed_strategy = max(failed_strategy_counts, key=failed_strategy_counts.get) if failed_strategy_counts else ""
        diffs = []
        for x in items:
            if "predicted_difficulty" in x and "actual_iterations" in x and "max_iterations" in x:
                p = _diff_idx(str(x.get("predicted_difficulty", "medium")))
                frac = float(x.get("actual_iterations", 0.0)) / max(1.0, float(x.get("max_iterations", 1.0)))
                if frac >= 0.85:
                    a = 3
                elif frac >= 0.6:
                    a = 2
                elif frac >= 0.3:
                    a = 1
                else:
                    a = 0
                diffs.append(a - p)
        difficulty_correction = statistics.mean(diffs) if diffs else 0.0

        # Learned threshold calibration curves (bounded).
        route_escalate = max(50, min(84, int(avg_route - 3 + (10 * fail_rate))))
        route_soft = max(45, min(route_escalate - 6, route_escalate - 10))
        pivot_fruitless = max(2, min(6, int(round((0.55 * avg_fruitless) + (0.45 * failed_fruitless) + 1))))
        pivot_tool_failures = max(1, min(5, int(round((0.55 * avg_failures) + (0.45 * failed_tool_failures) + 1))))

        priors["by_category"][cat] = {
            "route_escalate_score": route_escalate,
            "route_soft_escalate_score": route_soft,
            "pivot_fruitless": pivot_fruitless,
            "pivot_tool_failures": pivot_tool_failures,
            "confidence_decay_fruitless": round(max(0.04, min(0.16, 0.06 + (avg_fruitless * 0.02))), 4),
            "confidence_decay_tool_failures": round(max(0.06, min(0.22, 0.09 + (avg_failures * 0.025))), 4),
            "difficulty_correction": round(float(difficulty_correction), 3),
            "observations": len(items),
            "solve_rate": round(solve_rate, 4),
            "fail_rate": round(fail_rate, 4),
            "failed_observations": len(failed_items),
            "dominant_failed_strategy": dominant_failed_strategy,
            "strategy_penalties": strategy_penalties,
        }

    _save(priors_path, priors)
    return priors


def get_learned_overrides(priors_path: str, category: str) -> dict[str, Any]:
    priors = _load(priors_path, DEFAULT_PRIORS)
    cat = _norm_cat(category)
    return dict(priors.get("by_category", {}).get(cat, {}))
