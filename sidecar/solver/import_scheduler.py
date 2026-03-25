"""Import/watch scheduling helpers extracted from engine for testability."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable


def _safe_ctf_name(ctf_name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', "_", str(ctf_name)).strip()[:80]


def active_solve_lock_path(base_dir: str, ctf_name: str) -> str:
    root = os.path.join(base_dir, _safe_ctf_name(ctf_name), ".solver")
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "active_solve.lock")


def try_acquire_active_solve_lock(
    base_dir: str,
    ctf_name: str,
    ttl_s: int,
    enabled: bool,
    emit_cb: Callable[..., Any],
) -> tuple[bool, str]:
    lock_path = active_solve_lock_path(base_dir, ctf_name)
    if not enabled:
        return True, lock_path

    now = int(time.time())
    if os.path.exists(lock_path):
        try:
            age = now - int(os.path.getmtime(lock_path))
            if age >= max(60, int(ttl_s)):
                os.remove(lock_path)
                emit_cb("solve_lock", action="stale_lock_cleared", path=lock_path, age_s=age)
        except Exception:
            pass

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": os.getpid(), "ts": now}, ensure_ascii=False))
        emit_cb("solve_lock", action="acquired", path=lock_path)
        return True, lock_path
    except FileExistsError:
        emit_cb("solve_lock", action="busy", path=lock_path)
        return False, lock_path
    except Exception as e:
        emit_cb("solve_lock", action="error", path=lock_path, error=str(e))
        return False, lock_path


def release_active_solve_lock(lock_path: str, enabled: bool, emit_cb: Callable[..., Any]) -> None:
    if not enabled:
        return
    try:
        if lock_path and os.path.exists(lock_path):
            os.remove(lock_path)
            emit_cb("solve_lock", action="released", path=lock_path)
    except Exception:
        pass


def priority_score(ch: dict, expected_value_fn: Callable[[dict], float]) -> float:
    try:
        ev = float(expected_value_fn(ch))
    except Exception:
        ev = 0.0
    solved_penalty = -5.0 if bool(ch.get("solved", False)) else 0.0
    new_bonus = 0.35 if bool(ch.get("is_new", False)) else 0.0
    upd_bonus = 0.15 if bool(ch.get("is_updated", False)) else 0.0
    cat = str(ch.get("category", "")).lower()
    cat_bonus = 0.10 if any(x in cat for x in ("crypto", "reverse", "web", "forensic", "pwn", "binary")) else 0.0
    return round(ev + solved_penalty + new_bonus + upd_bonus + cat_bonus, 4)


def build_queue(rows: list[dict], expected_value_fn: Callable[[dict], float]) -> list[dict]:
    q = []
    for row in rows:
        if bool(row.get("solved", False)):
            continue
        rec = dict(row)
        rec["queue_expected_value"] = priority_score(row, expected_value_fn)
        q.append(rec)
    q.sort(key=lambda x: float(x.get("queue_expected_value", 0.0)), reverse=True)
    for idx, item in enumerate(q, 1):
        item["queue_rank"] = idx
    return q


def persist_queue(base_dir: str, ctf_name: str, queue_rows: list[dict], cycle_no: int) -> str:
    root = os.path.join(base_dir, _safe_ctf_name(ctf_name))
    out_dir = os.path.join(root, ".solver")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "auto_queue.json")
    payload_out = {
        "ctf_name": ctf_name,
        "cycle": cycle_no,
        "generated_at": int(time.time()),
        "count": len(queue_rows),
        "queue": queue_rows,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload_out, f, ensure_ascii=False, indent=2)
    return path
