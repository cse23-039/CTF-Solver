"""Symbolic orchestration manager (angr/triton/z3 routing with cache-aware pruning)."""
from __future__ import annotations

from typing import Any

from .constraint_solver import solve_constraints
from .path_scheduler import schedule_paths


def _select_backend(challenge_type: str, mode: str) -> str:
    if mode in {"angr", "triton", "z3"}:
        return mode
    low = (challenge_type or "").lower()
    if low in {"pwn", "rev", "reverse"}:
        return "angr"
    if low in {"crypto", "protocol"}:
        return "z3"
    return "triton"


def orchestrate(
    challenge_type: str,
    constraints: list[str],
    candidate_paths: list[dict[str, Any]] | None = None,
    path_budget: int = 16,
    mode: str = "auto",
    timeout_s: int = 5,
) -> dict[str, Any]:
    backend = _select_backend(challenge_type, mode)
    solve_result = solve_constraints(constraints, backend="z3" if backend in {"angr", "triton"} else backend, timeout_s=timeout_s)

    pruned = []
    if solve_result.get("status") == "unsat":
        core = set(solve_result.get("unsat_core", []))
        for p in candidate_paths or []:
            p_constraints = set(str(c) for c in p.get("constraints", []))
            if core and p_constraints.intersection(core):
                continue
            pruned.append(p)
    else:
        pruned = list(candidate_paths or [])

    scheduled = schedule_paths(pruned, budget=path_budget, strategy="best_first")
    return {
        "backend": backend,
        "solve": solve_result,
        "candidate_paths_in": len(candidate_paths or []),
        "candidate_paths_after_prune": len(pruned),
        "scheduled": scheduled,
    }


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    data = input_data if isinstance(input_data, dict) else {}
    return orchestrate(
        challenge_type=str(kwargs.get("challenge_type", data.get("challenge_type", "unknown"))),
        constraints=[str(c) for c in kwargs.get("constraints", data.get("constraints", []))],
        candidate_paths=kwargs.get("candidate_paths", data.get("candidate_paths", [])),
        path_budget=int(kwargs.get("path_budget", data.get("path_budget", 16))),
        mode=str(kwargs.get("mode", data.get("mode", "auto"))),
        timeout_s=int(kwargs.get("timeout_s", data.get("timeout_s", 5))),
    )
