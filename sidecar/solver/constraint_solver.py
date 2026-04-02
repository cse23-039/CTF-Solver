"""Constraint solving facade with cache and unsat-pruning support."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, cast


def _k(constraints: list[str], backend: str) -> str:
    blob = json.dumps({"backend": backend, "constraints": constraints}, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _new_solved_cache() -> dict[str, dict[str, Any]]:
    return {}


@dataclass
class ConstraintCache:
    max_size: int = 2048
    solved: dict[str, dict[str, Any]] = field(default_factory=_new_solved_cache)

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


def _solve_with_z3(constraints: list[str], timeout_s: int) -> dict[str, Any] | None:
    try:
        import z3  # type: ignore
    except Exception:
        return None

    solver = z3.Solver()
    solver.set(timeout=max(1, int(timeout_s)) * 1000)
    vars_map: dict[str, Any] = {}

    def _term(token: str):
        token = token.strip()
        if re.fullmatch(r"-?\d+", token):
            return z3.IntVal(int(token))
        if token not in vars_map:
            vars_map[token] = z3.Int(token)
        return vars_map[token]

    for constraint in constraints:
        c = str(constraint or "").strip()
        if not c:
            continue
        if c.startswith("(assert") or c.startswith("(set-") or c.startswith("(declare-"):
            solver.add(z3.parse_smt2_string(c))
            continue

        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*([A-Za-z_][A-Za-z0-9_]*|-?\d+)", c)
        if not match:
            raise ValueError(f"Unsupported constraint syntax: {c}")
        left = _term(match.group(1))
        op = match.group(2)
        right = _term(match.group(3))

        if op == "==":
            solver.add(left == right)
        elif op == "!=":
            solver.add(left != right)
        elif op == "<=":
            solver.add(left <= right)
        elif op == ">=":
            solver.add(left >= right)
        elif op == "<":
            solver.add(left < right)
        elif op == ">":
            solver.add(left > right)

    chk = solver.check()
    status = str(chk).lower()
    if status == "sat":
        model = solver.model()
        out_model: dict[str, Any] = {}
        for decl in model.decls():
            out_model[str(decl.name())] = str(model[decl])
        return {"status": "sat", "unsat_core": [], "model": out_model, "approximate": False}
    if status == "unsat":
        return {"status": "unsat", "unsat_core": [], "model": {}, "approximate": False}
    return {"status": "unknown", "unsat_core": [], "model": {}, "approximate": False}


def solve_constraints(constraints: list[str], backend: str = "z3", timeout_s: int = 5) -> dict[str, Any]:
    key = _k(constraints, backend)
    cached = _CACHE.get(key)
    if cached is not None:
        out = dict(cached)
        out["cache_hit"] = True
        return out

    z3_result = None
    if str(backend).lower() == "z3":
        try:
            z3_result = _solve_with_z3(constraints, timeout_s=timeout_s)
        except Exception:
            z3_result = None

    if z3_result is not None:
        status = str(z3_result.get("status", "unknown"))
        unsat_core = z3_result.get("unsat_core", []) if isinstance(z3_result.get("unsat_core", []), list) else []
        model = z3_result.get("model", {}) if isinstance(z3_result.get("model", {}), dict) else {}
        approximate = bool(z3_result.get("approximate", False))
    else:
        unsat_core = _find_unsat_core(constraints)
        status = "sat" if not unsat_core else "unsat"
        model = {} if status == "unsat" else {"note": "Approximate solver fallback used; install z3-solver for exact models."}
        approximate = True

    result: dict[str, Any] = {
        "backend": backend,
        "timeout_s": timeout_s,
        "status": status,
        "unsat_core": unsat_core,
        "model": model,
        "approximate": approximate,
        "cache_hit": False,
    }
    _CACHE.put(key, result)
    return result


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    raw_constraints: Any = kwargs.get("constraints", input_data)
    if raw_constraints is None:
        constraints_list: list[Any] = []
    elif isinstance(raw_constraints, (list, tuple, set)):
        constraints_list = list(cast(Iterable[Any], raw_constraints))
    else:
        constraints_list = [raw_constraints]

    backend_raw: Any = kwargs.get("backend", "z3")
    timeout_raw: Any = kwargs.get("timeout_s", 5)

    return solve_constraints(
        [str(constraint) for constraint in constraints_list],
        backend=str(backend_raw),
        timeout_s=int(timeout_raw),
    )
