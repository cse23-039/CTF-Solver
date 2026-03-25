"""Explainability replay log: state -> action -> outcome."""
from __future__ import annotations

import json
import os
import time
from typing import Any

from solver.storage_retention import prune_jsonl


def append_replay(path: str, state: dict[str, Any], action: dict[str, Any], outcome: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    rec = {
        "ts": int(time.time()),
        "state": state,
        "action": action,
        "outcome": outcome,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    prune_jsonl(path, max_lines=120000, max_bytes=128 * 1024 * 1024)


def replay(path: str, limit: int = 200) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-max(1, int(limit)):]
