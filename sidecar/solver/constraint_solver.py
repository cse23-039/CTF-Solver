"""Constraint solving facade with cache and unsat-pruning support."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def _k(constraints: list[str], backend: str) -> str:
    blob = json.dumps({"backend": backend, "constraints": constraints}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class ConstraintCache:
    max_size: int = 2048
    solved: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, key: str) -> dict[str, Any] | None:
        return self.solved.get(key)

    def put(self, key: str, value: dict[str, Any]) -> None:
        if len(self.solved) >= self.max_size:
            # Simple FIFO-ish eviction by popping first key.
            first = next(iter(self.solved.keys()))
            self.solved.pop(first, None)
        self.solved[key] = value


_CACHE = ConstraintCache()


def _find_unsat_core(constraints: list[str]) -> list[str]:
    """String-level conflict approximation when a full SMT unsat-core is unavailable."""
    core: list[str] = []
    eq_map: dict[str, set[str]] = {}
    for c in constraints:
        c_norm = c.replace(" ", "")
        if "==" in c_norm:
            left, right = c_norm.split("==", 1)
            eq_map.setdefault(left, set()).add(right)
    for left, rights in eq_map.items():
        if len(rights) > 1:
            for r in sorted(rights):
                core.append(f"{left} == {r}")
    return core


def solve_constraints(constraints: list[str], backend: str = "z3", timeout_s: int = 5) -> dict[str, Any]:
    key = _k(constraints, backend)
    cached = _CACHE.get(key)
    if cached is not None:
        out = dict(cached)
        out["cache_hit"] = True
        return out

    unsat_core = _find_unsat_core(constraints)
    status = "sat" if not unsat_core else "unsat"
    result = {
        "backend": backend,
        "timeout_s": timeout_s,
        "status": status,
        "unsat_core": unsat_core,
        "model": {} if status == "unsat" else {"note": "Connect z3 model extraction here."},
        "cache_hit": False,
    }
    _CACHE.put(key, result)
    return result


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    constraints = kwargs.get("constraints", input_data) or []
    return solve_constraints([str(c) for c in constraints], backend=kwargs.get("backend", "z3"), timeout_s=int(kwargs.get("timeout_s", 5)))
