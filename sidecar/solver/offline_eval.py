"""Offline evaluation harness for deterministic replay/benchmark gating."""
from __future__ import annotations

import json
import os
import time
from typing import Any

from solver.benchmark_gate import evaluate


def _load_json(path: str, fallback: Any) -> Any:
    if not os.path.exists(path):
        return fallback
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return fallback


def run_offline_eval(dataset_path: str, benchmark_path: str, gates: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = _load_json(dataset_path, [])
    if not isinstance(rows, list):
        rows = []

    results = []
    for rec in rows:
        metrics = {
            "category": rec.get("category", "unknown"),
            "difficulty": rec.get("difficulty", "medium"),
            "challenge": rec.get("challenge", ""),
            "solve_rate": float(rec.get("solve_rate", 0.0) or 0.0),
            "false_flag_rate": float(rec.get("false_flag_rate", 0.0) or 0.0),
            "cost_per_flag": float(rec.get("cost_per_flag", 0.0) or 0.0),
            "time_to_first_signal": float(rec.get("time_to_first_signal", 0.0) or 0.0),
            "time_to_flag": float(rec.get("time_to_flag", 0.0) or 0.0),
        }
        results.append(evaluate(metrics, benchmark_path, gates=gates or {}))

    passed = len([r for r in results if str(r.get("verdict", "")) == "pass"])
    total = len(results)
    out = {
        "ts": int(time.time()),
        "dataset": dataset_path,
        "total": total,
        "passed": passed,
        "pass_rate": round((passed / max(1, total)), 4),
        "failed": total - passed,
    }
    return out
