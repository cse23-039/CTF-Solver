"""Storage retention helpers to bound long-term disk growth."""
from __future__ import annotations

import json
import os
from typing import Any


def _truncate_by_size(lines: list[str], max_bytes: int) -> list[str]:
    if max_bytes <= 0:
        return lines
    kept: list[str] = []
    total = 0
    for line in reversed(lines):
        b = len(line.encode("utf-8", errors="ignore"))
        if total + b > max_bytes:
            break
        kept.append(line)
        total += b
    kept.reverse()
    return kept


def prune_jsonl(path: str, *, max_lines: int = 50000, max_bytes: int = 64 * 1024 * 1024) -> int:
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        if len(lines) > max(1, int(max_lines)):
            lines = lines[-int(max_lines):]
        lines = _truncate_by_size(lines, int(max_bytes))
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line if line.endswith("\n") else (line + "\n"))
        return len(lines)
    except Exception:
        return 0


def prune_json_array(path: str, *, max_items: int = 10000) -> int:
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            data = data[-max(1, int(max_items)) :]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return len(data)
        return 0
    except Exception:
        return 0
