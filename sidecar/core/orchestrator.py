from __future__ import annotations

from typing import Any, Callable


def run_solve(payload: dict[str, Any], runner: Callable[[dict[str, Any]], Any]) -> Any:
    return runner(payload)
