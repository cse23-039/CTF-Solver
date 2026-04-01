"""Curriculum queue generation from failure traces."""
from __future__ import annotations

import json
import os
import time
from typing import Any


def append_curriculum_item(path: str, item: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    rows = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                rows = json.load(f)
            if not isinstance(rows, list):
                rows = []
        except Exception:
            rows = []
    rows.append({"ts": int(time.time()), **item})
    rows = rows[-5000:]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def build_failure_curriculum_item(*, category: str, difficulty: str, challenge: str, failed_tools: list[str], reason: str) -> dict[str, Any]:
    return {
        "category": category,
        "difficulty": difficulty,
        "challenge": challenge,
        "reason": reason,
        "focus": "synthetic-variation",
        "failed_tools": failed_tools[:10],
        "target": "improve_policy_on_failure_pattern",
    }
