"""Counterfactual replay learning: extract missed actions from failed traces."""
from __future__ import annotations

import json
import os
import time
from typing import Any


def _load_jsonl(path: str, limit: int = 5000) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    rows.append(json.loads(s))
                except Exception:
                    continue
    except Exception:
        return []
    return rows[-max(1, int(limit)) :]


def derive_counterfactual_deltas(replay_path: str, output_path: str, limit: int = 3000) -> dict[str, Any]:
    rows = _load_jsonl(replay_path, limit=limit)
    if not rows:
        return {"rows": 0, "deltas": [], "saved": False}

    fail_rows = [r for r in rows if not bool((r.get("outcome") or {}).get("success", False))]
    action_counts: dict[str, int] = {}
    for rec in fail_rows:
        action = str((rec.get("action") or {}).get("tool", (rec.get("action") or {}).get("type", "unknown")))
        if not action:
            continue
        action_counts[action] = int(action_counts.get(action, 0)) + 1

    ranked = sorted(action_counts.items(), key=lambda kv: kv[1], reverse=True)
    deltas = []
    for name, cnt in ranked[:12]:
        deltas.append({
            "action": name,
            "penalty": round(min(0.5, 0.04 * cnt), 4),
            "reason": "frequent_failure_in_replay",
        })

    out = {
        "ts": int(time.time()),
        "rows": len(rows),
        "failed_rows": len(fail_rows),
        "deltas": deltas,
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        out["saved"] = True
    except Exception:
        out["saved"] = False
    return out
