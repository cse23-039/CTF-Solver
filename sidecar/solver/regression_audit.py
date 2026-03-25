"""Replay/telemetry regression audit for solve quality and token efficiency."""
from __future__ import annotations

import json
import os
import statistics
import time
from typing import Any


def _load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _load_jsonl(path: str, limit: int = 2000) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return rows[-max(1, int(limit)) :]


def run_regression_audit(workspace: str, min_solve_rate: float = 0.6, max_false_flag_rate: float = 0.15) -> dict[str, Any]:
    solver_dir = os.path.join(workspace, ".solver")
    telem_path = os.path.join(solver_dir, "iteration_telemetry.json")
    replay_path = os.path.join(solver_dir, "decision_replay.jsonl")

    telemetry = _load_json(telem_path, [])
    replay = _load_jsonl(replay_path, limit=5000)

    solved = [r for r in telemetry if bool(r.get("solved", False))]
    failed = [r for r in telemetry if bool(r.get("failed", False))]
    total = len(telemetry)
    solve_rate = (len(solved) / max(1, total)) if total else 0.0

    route_scores = [float(r.get("route_score", 0.0) or 0.0) for r in telemetry]
    fruitless_vals = [float(r.get("fruitless", 0.0) or 0.0) for r in telemetry]
    tool_failures = [float(r.get("tool_failures", 0.0) or 0.0) for r in telemetry]

    false_flag_events = [r for r in replay if str((r.get("outcome") or {}).get("event", "")).lower() == "flag_candidate_rejected"]
    false_flag_rate = (len(false_flag_events) / max(1, total)) if total else 0.0

    verdict = "pass" if (solve_rate >= float(min_solve_rate) and false_flag_rate <= float(max_false_flag_rate)) else "fail"

    suggestions = []
    if solve_rate < float(min_solve_rate):
        suggestions.append("Increase early-route aggressiveness for hard/insane and reduce pivot latency.")
    if false_flag_rate > float(max_false_flag_rate):
        suggestions.append("Tighten validator gate and require stronger tool-evidence chain before submit.")
    if fruitless_vals and statistics.mean(fruitless_vals) > 3.0:
        suggestions.append("Raise novelty gate pressure and diversify tools earlier to cut repeated dead loops.")
    if tool_failures and statistics.mean(tool_failures) > 2.0:
        suggestions.append("Improve preflight fallback coverage and tool reliability weighting.")

    return {
        "ts": int(time.time()),
        "workspace": workspace,
        "total_records": total,
        "solved_records": len(solved),
        "failed_records": len(failed),
        "solve_rate": round(solve_rate, 4),
        "false_flag_rate": round(false_flag_rate, 4),
        "avg_route_score": round(statistics.mean(route_scores), 3) if route_scores else 0.0,
        "avg_fruitless": round(statistics.mean(fruitless_vals), 3) if fruitless_vals else 0.0,
        "avg_tool_failures": round(statistics.mean(tool_failures), 3) if tool_failures else 0.0,
        "verdict": verdict,
        "suggestions": suggestions,
        "inputs": {
            "min_solve_rate": float(min_solve_rate),
            "max_false_flag_rate": float(max_false_flag_rate),
        },
    }
