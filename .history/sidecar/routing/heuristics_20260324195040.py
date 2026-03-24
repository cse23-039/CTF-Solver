"""Attack-graph heuristics with weighted A* / beam search and success priors."""
from __future__ import annotations

import heapq
from collections import defaultdict
from typing import Any


def _edge_weight(edge: dict[str, Any]) -> float:
    base_cost = float(edge.get("cost", 1.0))
    success_p = max(0.05, min(0.999, float(edge.get("success_prob", 0.5))))
    return base_cost / success_p


def _preconditions_ok(edge: dict[str, Any], capabilities: set[str]) -> bool:
    required = set(str(x) for x in edge.get("requires", []))
    return required.issubset(capabilities)


def a_star_attack_path(
    graph: dict[str, Any],
    start: str,
    goal: str,
    capabilities: set[str] | None = None,
    beam_width: int = 64,
) -> dict[str, Any]:
    capabilities = capabilities or set()
    edges_by_from: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in graph.get("edges", []):
        if isinstance(e, dict):
            edges_by_from[str(e.get("from", ""))].append(e)

    pq: list[tuple[float, float, str, list[str]]] = []
    heapq.heappush(pq, (0.0, 0.0, start, [start]))
    seen_best: dict[str, float] = {start: 0.0}

    expansions = 0
    while pq:
        f, g, node, path = heapq.heappop(pq)
        if node == goal:
            return {"path": path, "total_cost": g, "expanded": expansions}

        expansions += 1
        if expansions > max(1, beam_width) * 200:
            break

        next_edges = edges_by_from.get(node, [])
        next_edges.sort(key=_edge_weight)
        next_edges = next_edges[: max(1, beam_width)]

        for e in next_edges:
            if not _preconditions_ok(e, capabilities):
                continue
            nxt = str(e.get("to", ""))
            if not nxt:
                continue
            step = _edge_weight(e)
            ng = g + step
            if ng >= seen_best.get(nxt, float("inf")):
                continue
            seen_best[nxt] = ng
            # Lightweight heuristic: prefer paths that gain capabilities.
            h = 0.0 if nxt == goal else 0.5
            heapq.heappush(pq, (ng + h, ng, nxt, path + [nxt]))

    return {"path": [], "total_cost": None, "expanded": expansions, "reason": "no_path"}


def update_edge_success(graph: dict[str, Any], outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    by_edge = {(str(e.get("from", "")), str(e.get("to", ""))): e for e in graph.get("edges", []) if isinstance(e, dict)}
    for o in outcomes:
        key = (str(o.get("from", "")), str(o.get("to", "")))
        edge = by_edge.get(key)
        if not edge:
            continue
        p = float(edge.get("success_prob", 0.5))
        # EMA update using observed success signal in [0,1].
        obs = 1.0 if bool(o.get("success", False)) else 0.0
        edge["success_prob"] = round(0.8 * p + 0.2 * obs, 6)
    return graph


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    graph = input_data if isinstance(input_data, dict) else kwargs.get("graph", {})
    if kwargs.get("operation", "search") == "update":
        return update_edge_success(graph, kwargs.get("outcomes", []))
    return a_star_attack_path(
        graph=graph,
        start=str(kwargs.get("start", "start")),
        goal=str(kwargs.get("goal", "goal")),
        capabilities=set(str(x) for x in kwargs.get("capabilities", [])),
        beam_width=int(kwargs.get("beam_width", 64)),
    )
