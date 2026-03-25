"""Dynamic thinking token budget manager.

Enhancement 3: Tracks evidence_gained_per_thinking_token across the last
N Opus calls and adjusts the thinking budget up/down based on efficiency.

Prevents the failure mode where Opus burns 12k tokens on the same dead-end
hypothesis 3 iterations in a row.
"""
from __future__ import annotations

from collections import deque
from typing import Any


class ThinkingBudgetTracker:
    """
    Adaptive thinking token allocator.

    Each Opus call registers its thinking tokens used and whether it produced
    new evidence (made_progress). The tracker computes efficiency and adjusts
    the budget for the next call.

    Budget bounds:
      min_tokens   : 2048  (always think a little)
      max_tokens   : 16000 (never exceed this)
      default      : 8000
    """

    MIN_TOKENS = 2048
    MAX_TOKENS = 16_000
    DEFAULT_TOKENS = 8_000

    # Efficiency thresholds (evidence_per_ktoken).
    HIGH_EFFICIENCY = 0.25   # boost budget
    LOW_EFFICIENCY  = 0.08   # cut budget

    def __init__(self, window: int = 4) -> None:
        """window: how many recent calls to use for efficiency calculation."""
        self._window = max(2, int(window))
        self._history: deque[dict[str, Any]] = deque(maxlen=self._window)
        self._current_budget: int = self.DEFAULT_TOKENS

    def record_call(
        self,
        thinking_tokens_used: int,
        evidence_gained: float,
        model: str = "",
        iteration: int = 0,
    ) -> None:
        """
        Register a completed Opus thinking call.

        evidence_gained: 0.0–1.0, e.g. belief.evidence_score delta or
                         (made_progress * 0.15).
        """
        self._history.append({
            "tokens": max(0, int(thinking_tokens_used)),
            "evidence": max(0.0, min(1.0, float(evidence_gained))),
            "model": model,
            "iteration": iteration,
        })
        self._recompute()

    def _recompute(self) -> None:
        """Recompute budget from rolling window efficiency."""
        if len(self._history) < 2:
            return

        total_tokens = sum(h["tokens"] for h in self._history)
        total_evidence = sum(h["evidence"] for h in self._history)
        if total_tokens <= 0:
            return

        efficiency = total_evidence / (total_tokens / 1000.0)  # evidence per ktoken

        current = self._current_budget

        if efficiency >= self.HIGH_EFFICIENCY:
            # High ROI — give more room.
            new_budget = min(self.MAX_TOKENS, int(current * 1.25))
        elif efficiency <= self.LOW_EFFICIENCY:
            # Spinning — cut back.
            new_budget = max(self.MIN_TOKENS, int(current * 0.70))
        else:
            # Moderate — small nudge toward default.
            midpoint = (current + self.DEFAULT_TOKENS) // 2
            new_budget = max(self.MIN_TOKENS, min(self.MAX_TOKENS, midpoint))

        # Round to nearest 512 for clean values.
        self._current_budget = (new_budget // 512) * 512

    def next_budget(self, difficulty: str = "medium", route_score: int = 50) -> int:
        """
        Return the recommended thinking token budget for the next Opus call.

        difficulty and route_score are used to clamp the result into a
        difficulty-appropriate range.
        """
        base = self._current_budget

        # Hard floor/ceiling per difficulty tier.
        floors = {"easy": 1024, "medium": 2048, "hard": 4096, "insane": 6000}
        ceilings = {"easy": 6000, "medium": 10000, "hard": 14000, "insane": self.MAX_TOKENS}
        diff_key = str(difficulty).lower()
        floor = floors.get(diff_key, 2048)
        ceiling = ceilings.get(diff_key, self.MAX_TOKENS)

        # route_score bonus: high complexity → allow ceiling to stretch.
        if route_score >= 80:
            ceiling = self.MAX_TOKENS

        result = max(floor, min(ceiling, base))
        return (result // 512) * 512 or self.MIN_TOKENS

    def efficiency_summary(self) -> dict[str, Any]:
        """Return current efficiency metrics for logging/telemetry."""
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
        """Reset history (e.g. after a successful pivot)."""
        self._history.clear()
        self._current_budget = self.DEFAULT_TOKENS


# ── Module-level default instance ────────────────────────────────────────────
_DEFAULT_TRACKER: ThinkingBudgetTracker | None = None


def get_tracker() -> ThinkingBudgetTracker:
    global _DEFAULT_TRACKER
    if _DEFAULT_TRACKER is None:
        _DEFAULT_TRACKER = ThinkingBudgetTracker()
    return _DEFAULT_TRACKER
