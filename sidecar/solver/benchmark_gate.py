"""Benchmark gate and regression checks for policy changes."""
from __future__ import annotations

import json
import os
import time
from typing import Any


DEFAULT_GATES = {
    "min_solve_rate": 0.45,
    "max_false_flag_rate": 0.10,
    "max_cost_per_flag": 2.5,
    "max_time_to_first_signal": 180.0,
    "max_time_to_flag": 1200.0,
    "allow_regression_margin": 0.03,
}


def _load_history(path: str) -> list[dict[str, Any]]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_history(path: str, rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def evaluate(metrics: dict[str, Any], history_path: str, gates: dict[str, Any] | None = None) -> dict[str, Any]:
    g = dict(DEFAULT_GATES)
    if gates:
        g.update(gates)

    rows = _load_history(history_path)
    prev = rows[-1] if rows else None

    solve_rate = float(metrics.get("solve_rate", 0.0))
    false_flag_rate = float(metrics.get("false_flag_rate", 1.0))
    cost_per_flag = float(metrics.get("cost_per_flag", 9999.0))
    time_to_first_signal = float(metrics.get("time_to_first_signal", 9999.0))
    time_to_flag = float(metrics.get("time_to_flag", 9999.0))

    hard_ok = (
        solve_rate >= float(g["min_solve_rate"])
        and false_flag_rate <= float(g["max_false_flag_rate"])
        and cost_per_flag <= float(g["max_cost_per_flag"])
        and time_to_first_signal <= float(g["max_time_to_first_signal"])
        and time_to_flag <= float(g["max_time_to_flag"])
    )

    regressed = False
    reasons = []
    margin = float(g["allow_regression_margin"])
    if prev:
        if solve_rate + margin < float(prev.get("solve_rate", 0.0)):
            regressed = True
            reasons.append("solve_rate_regressed")
        if false_flag_rate - margin > float(prev.get("false_flag_rate", 1.0)):
            regressed = True
            reasons.append("false_flag_rate_regressed")
        if cost_per_flag - margin > float(prev.get("cost_per_flag", 9999.0)):
            regressed = True
            reasons.append("cost_per_flag_regressed")
        if time_to_first_signal - margin * 100 > float(prev.get("time_to_first_signal", 9999.0)):
            regressed = True
            reasons.append("time_to_first_signal_regressed")
        if time_to_flag - margin * 300 > float(prev.get("time_to_flag", 9999.0)):
            regressed = True
            reasons.append("time_to_flag_regressed")

    verdict = "pass" if (hard_ok and not regressed) else "fail"

    row = {
        "ts": int(time.time()),
        "verdict": verdict,
        "hard_ok": hard_ok,
        "regressed": regressed,
        "reasons": reasons,
        **metrics,
    }
    rows.append(row)
    _save_history(history_path, rows[-200:])

    return row
