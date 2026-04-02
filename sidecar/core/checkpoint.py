from __future__ import annotations

import json
import os
import time
from typing import Any


def checkpoint_path(workspace: str, challenge_name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (challenge_name or "challenge"))[:80]
    root = workspace or os.environ.get("CTF_SOLVER_HOME") or os.path.expanduser("~/.ctf-solver")
    return os.path.join(root, ".solver", "checkpoints", f"{safe}.json")


def save_checkpoint(workspace: str, challenge_name: str, state: dict[str, Any]) -> str:
    path = checkpoint_path(workspace, challenge_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "ts": int(time.time()),
        "state": state,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def load_checkpoint(workspace: str, challenge_name: str) -> dict[str, Any] | None:
    path = checkpoint_path(workspace, challenge_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("state") if isinstance(data.get("state"), dict) else None
    except Exception:
        return None
    return None
