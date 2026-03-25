"""Dynamic thinking token budget manager."""
from __future__ import annotations

from collections import deque
from typing import Any


class ThinkingBudgetTracker:
    MIN_TOKENS = 2048
    MAX_TOKENS = 16_000
    DEFAULT_TOKENS = 8_000

    HIGH_EFFICIENCY = 0.25
    LOW_EFFICIENCY = 0.08

    def __init__(self, window: int = 4) -> None:
        self._window = max(2, int(window))
        self._history: deque[dict[str, Any]] = deque(maxlen=self._window)
        self._current_budget: int = self.DEFAULT_TOKENS

    def record_call(self, thinking_tokens_used: int, evidence_gained: float, model: str = "", iteration: int = 0) -> None:
        self._history.append(
            {
                "tokens": max(0, int(thinking_tokens_used)),
                "evidence": max(0.0, min(1.0, float(evidence_gained))),
                "model": model,
                "iteration": iteration,
            }
        )
        self._recompute()

    def _recompute(self) -> None:
        if len(self._history) < 2:
            return

        total_tokens = sum(h["tokens"] for h in self._history)
        total_evidence = sum(h["evidence"] for h in self._history)
        if total_tokens <= 0:
            return

        efficiency = total_evidence / (total_tokens / 1000.0)
        current = self._current_budget

        if efficiency >= self.HIGH_EFFICIENCY:
            new_budget = min(self.MAX_TOKENS, int(current * 1.25))
        elif efficiency <= self.LOW_EFFICIENCY:
            new_budget = max(self.MIN_TOKENS, int(current * 0.70))
        else:
            midpoint = (current + self.DEFAULT_TOKENS) // 2
            new_budget = max(self.MIN_TOKENS, min(self.MAX_TOKENS, midpoint))

        self._current_budget = (new_budget // 512) * 512

    def next_budget(self, difficulty: str = "medium", route_score: int = 50) -> int:
        base = self._current_budget

        floors = {"easy": 1024, "medium": 2048, "hard": 4096, "insane": 6000}
        ceilings = {"easy": 6000, "medium": 10000, "hard": 14000, "insane": self.MAX_TOKENS}
        diff_key = str(difficulty).lower()
        floor = floors.get(diff_key, 2048)
        ceiling = ceilings.get(diff_key, self.MAX_TOKENS)

        if route_score >= 80:
            ceiling = self.MAX_TOKENS

        result = max(floor, min(ceiling, base))
        return (result // 512) * 512 or self.MIN_TOKENS

    def efficiency_summary(self) -> dict[str, Any]:
        if not self._history:
            return {"efficiency": 0.0, "budget": self._current_budget, "calls": 0}

        total_tokens = sum(h["tokens"] for h in self._history)
        total_evidence = sum(h["evidence"] for h in self._history)
        efficiency = (total_evidence / (total_tokens / 1000.0)) if total_tokens > 0 else 0.0

        return {
            "efficiency": round(efficiency, 4),
            "budget": self._current_budget,
            "calls": len(self._history),
            "total_tokens_used": total_tokens,
            "total_evidence_gained": round(total_evidence, 4),
        }

    def reset(self) -> None:
        self._history.clear()
        self._current_budget = self.DEFAULT_TOKENS


_DEFAULT_TRACKER: ThinkingBudgetTracker | None = None


def get_tracker() -> ThinkingBudgetTracker:
    global _DEFAULT_TRACKER
    if _DEFAULT_TRACKER is None:
        _DEFAULT_TRACKER = ThinkingBudgetTracker()
    return _DEFAULT_TRACKER
