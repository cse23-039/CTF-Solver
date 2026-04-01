"""Belief graph for entity/constraint/hypothesis confidence propagation."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


_SIGNAL_RE = re.compile(
    r"flag\{|leak|canary|overflow|gadget|oracle|nonce|padding|sql|ssti|xss|"
    r"format\s*string|rop|heap|race|auth|jwt|csrf|xxe|deserial",
    re.IGNORECASE,
)


@dataclass
class BeliefNode:
    key: str
    confidence: float = 0.5
    evidence_count: int = 0
    contradictions: int = 0
    tags: set[str] = field(default_factory=set)


class BeliefGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, BeliefNode] = {}
        self._edges: dict[tuple[str, str], float] = {}

    def _ensure(self, key: str) -> BeliefNode:
        k = str(key or "").strip().lower() or "unknown"
        if k not in self._nodes:
            self._nodes[k] = BeliefNode(key=k)
        return self._nodes[k]

    def upsert_hypothesis(self, name: str, confidence: float, tags: list[str] | None = None) -> None:
        node = self._ensure(name)
        node.confidence = max(0.0, min(1.0, float(confidence)))
        for t in (tags or []):
            node.tags.add(str(t).strip().lower())

    def connect(self, src: str, dst: str, weight: float = 0.5) -> None:
        a = self._ensure(src).key
        b = self._ensure(dst).key
        self._edges[(a, b)] = max(0.0, min(1.0, float(weight)))

    def update_from_evidence(self, tool: str, output: str, success: bool, quality: float = 0.5) -> dict[str, Any]:
        tool_key = f"tool:{str(tool or 'unknown').lower()}"
        tool_node = self._ensure(tool_key)
        tool_node.evidence_count += 1

        score = max(0.0, min(1.0, float(quality)))
        signal = bool(_SIGNAL_RE.search(str(output or "")))
        delta = (0.10 * score) + (0.08 if signal else 0.0)
        if success:
            tool_node.confidence = min(0.99, tool_node.confidence + delta)
        else:
            tool_node.confidence = max(0.01, tool_node.confidence - max(0.08, delta))
            tool_node.contradictions += 1

        propagated = 0
        for (src, dst), w in list(self._edges.items()):
            if src != tool_node.key:
                continue
            nd = self._ensure(dst)
            if success:
                nd.confidence = min(0.99, nd.confidence + (delta * w * 0.7))
            else:
                nd.confidence = max(0.01, nd.confidence - (max(0.06, delta) * w * 0.8))
                nd.contradictions += 1
            propagated += 1

        return {
            "tool_node": tool_node.key,
            "tool_confidence": round(tool_node.confidence, 4),
            "signal": signal,
            "propagated": propagated,
            "global_uncertainty": round(self.global_uncertainty(), 4),
        }

    def global_uncertainty(self) -> float:
        if not self._nodes:
            return 1.0
        vals = [abs(0.5 - n.confidence) for n in self._nodes.values()]
        certainty = sum(vals) / max(1, len(vals)) * 2.0
        return max(0.0, min(1.0, 1.0 - certainty))

    def contradiction_ratio(self) -> float:
        if not self._nodes:
            return 0.0
        contradictions = sum(int(n.contradictions) for n in self._nodes.values())
        evidence = max(1, sum(int(n.evidence_count) for n in self._nodes.values()))
        return max(0.0, min(1.0, contradictions / evidence))

    def top_hypotheses(self, n: int = 5) -> list[dict[str, Any]]:
        items = [x for x in self._nodes.values() if not x.key.startswith("tool:")]
        items.sort(key=lambda x: x.confidence, reverse=True)
        out = []
        for i in items[: max(1, int(n))]:
            out.append(
                {
                    "key": i.key,
                    "confidence": round(i.confidence, 4),
                    "evidence_count": int(i.evidence_count),
                    "contradictions": int(i.contradictions),
                    "tags": sorted(list(i.tags))[:8],
                }
            )
        return out

    def propose_disambiguation_tests(self, max_items: int = 3) -> list[str]:
        weak = sorted(self._nodes.values(), key=lambda n: (abs(0.5 - n.confidence), -n.contradictions))
        tests: list[str] = []
        for node in weak[: max(1, int(max_items) * 2)]:
            if node.key.startswith("tool:"):
                continue
            tests.append(f"disambiguate:{node.key}:run-min-cost-check")
            if len(tests) >= max_items:
                break
        return tests

    def snapshot(self) -> dict[str, Any]:
        return {
            "nodes": {k: {
                "confidence": round(v.confidence, 4),
                "evidence_count": int(v.evidence_count),
                "contradictions": int(v.contradictions),
                "tags": sorted(list(v.tags))[:12],
            } for k, v in self._nodes.items()},
            "edges": [{"src": s, "dst": d, "weight": round(w, 4)} for (s, d), w in self._edges.items()][:200],
            "uncertainty": round(self.global_uncertainty(), 4),
            "contradiction_ratio": round(self.contradiction_ratio(), 4),
        }
