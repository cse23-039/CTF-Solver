"""Solve execution helpers to reduce engine orchestration coupling."""
from __future__ import annotations

import threading
from typing import Any, Callable


def execute_solve_payload(run_fn: Callable[[dict[str, Any]], Any], payload: dict[str, Any]) -> Any:
    return run_fn(payload)


def launch_background_solve(
    run_fn: Callable[[dict[str, Any]], Any],
    payload: dict[str, Any],
    on_done: Callable[[], Any] | None = None,
    daemon: bool = True,
) -> threading.Thread:
    def _runner() -> None:
        try:
            run_fn(payload)
        finally:
            if on_done:
                try:
                    on_done()
                except Exception:
                    pass

    t = threading.Thread(target=_runner, daemon=daemon)
    t.start()
    return t
