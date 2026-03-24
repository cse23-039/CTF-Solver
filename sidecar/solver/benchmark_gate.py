"""Benchmark gate and regression checks for policy changes."""
from __future__ import annotations

import json
import math
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


def _cohort_key(metrics: dict[str, Any]) -> str:
    cat = str(metrics.get("category", "unknown")).lower()
    diff = str(metrics.get("difficulty", "unknown")).lower()
    return f"{cat}|{diff}"


def _rolling_baseline(rows: list[dict[str, Any]], cohort: str, window: int = 30) -> dict[str, Any]:
    cohort_rows = [r for r in rows if str(r.get("cohort", "")) == cohort][-max(3, int(window)):]
    if not cohort_rows:
        return {}

    def _vals(k: str) -> list[float]:
        return [float(r.get(k, 0.0) or 0.0) for r in cohort_rows]

    def _mean(vals: list[float]) -> float:
        return sum(vals) / max(1, len(vals))

    def _std(vals: list[float], m: float) -> float:
        if len(vals) <= 1:
            return 0.0
        return math.sqrt(sum((x - m) ** 2 for x in vals) / max(1, len(vals) - 1))

    out: dict[str, Any] = {"n": len(cohort_rows)}
    for k in ["solve_rate", "false_flag_rate", "cost_per_flag", "time_to_first_signal", "time_to_flag"]:
        vals = _vals(k)
        m = _mean(vals)
        s = _std(vals, m)
        ci = 1.96 * s / math.sqrt(max(1, len(vals)))
        out[k] = {"mean": m, "std": s, "ci95": ci}
    return out


def evaluate(metrics: dict[str, Any], history_path: str, gates: dict[str, Any] | None = None) -> dict[str, Any]:
    g = dict(DEFAULT_GATES)
    if gates:
        g.update(gates)

    rows = _load_history(history_path)
    prev = rows[-1] if rows else None
    cohort = _cohort_key(metrics)

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
    baseline = _rolling_baseline(rows, cohort, window=int(gates.get("rolling_window", 30)) if isinstance(gates, dict) else 30)
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

    if baseline:
        b_sr = baseline.get("solve_rate", {})
        b_ff = baseline.get("false_flag_rate", {})
        b_cp = baseline.get("cost_per_flag", {})
        b_t1 = baseline.get("time_to_first_signal", {})
        b_tf = baseline.get("time_to_flag", {})
        # Solve rate should stay above lower confidence bound.
        if solve_rate < float(b_sr.get("mean", 0.0)) - float(b_sr.get("ci95", 0.0)) - margin:
            regressed = True
            reasons.append("solve_rate_below_cohort_ci")
        # Cost and error-like metrics should stay below upper confidence bound.
        if false_flag_rate > float(b_ff.get("mean", 1.0)) + float(b_ff.get("ci95", 0.0)) + margin:
            regressed = True
            reasons.append("false_flag_rate_above_cohort_ci")
        if cost_per_flag > float(b_cp.get("mean", 9999.0)) + float(b_cp.get("ci95", 0.0)) + margin:
            regressed = True
            reasons.append("cost_per_flag_above_cohort_ci")
        if time_to_first_signal > float(b_t1.get("mean", 9999.0)) + float(b_t1.get("ci95", 0.0)) + margin * 120:
            regressed = True
            reasons.append("time_to_first_signal_above_cohort_ci")
        if time_to_flag > float(b_tf.get("mean", 9999.0)) + float(b_tf.get("ci95", 0.0)) + margin * 320:
            regressed = True
            reasons.append("time_to_flag_above_cohort_ci")

    verdict = "pass" if (hard_ok and not regressed) else "fail"

    row = {
        "ts": int(time.time()),
        "cohort": cohort,
        "verdict": verdict,
        "hard_ok": hard_ok,
        "regressed": regressed,
        "reasons": reasons,
        "baseline": baseline,
        **metrics,
    }
    rows.append(row)
    _save_history(history_path, rows[-200:])

    return row
