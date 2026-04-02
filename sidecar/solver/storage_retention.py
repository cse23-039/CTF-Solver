"""Storage retention helpers to bound long-term disk growth."""
from __future__ import annotations

import json
import os
import tempfile
from collections import deque
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
        max_lines_i = max(1, int(max_lines))
        max_bytes_i = max(1, int(max_bytes))
        kept: deque[tuple[str, int]] = deque(maxlen=max_lines_i)
        total_bytes = 0

        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line if raw_line.endswith("\n") else (raw_line + "\n")
                if not line.strip():
                    continue
                size = len(line.encode("utf-8", errors="ignore"))
                if len(kept) == max_lines_i:
                    _, old_size = kept.popleft()
                    total_bytes -= old_size
                kept.append((line, size))
                total_bytes += size
                while kept and total_bytes > max_bytes_i:
                    _, old_size = kept.popleft()
                    total_bytes -= old_size

        tmp_dir = os.path.dirname(path) or "."
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=tmp_dir, prefix=".prune_", suffix=".tmp") as tmp:
            tmp_path = tmp.name
            for line, _ in kept:
                tmp.write(line)
        os.replace(tmp_path, path)
        return len(kept)
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
