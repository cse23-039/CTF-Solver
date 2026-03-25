"""Dynamic difficulty re-estimation.

Enhancement 6: After iteration total_iters // 3, compares evidence_gain_rate
against the initial difficulty prediction and re-classifies if necessary.
Prevents under-spending on surprisingly hard challenges and wasting Opus
calls on surprisingly easy ones.
"""
from __future__ import annotations

from typing import Any

_DIFFICULTY_LADDER = ["easy", "medium", "hard", "insane"]


def _difficulty_index(d: str) -> int:
    return _DIFFICULTY_LADDER.index(d) if d in _DIFFICULTY_LADDER else 1


def _difficulty_from_index(i: int) -> str:
    return _DIFFICULTY_LADDER[max(0, min(len(_DIFFICULTY_LADDER) - 1, i))]


class DifficultyEstimator:
    """
    Tracks solve progress metrics and emits a re-classified difficulty label
    when evidence gain is inconsistent with the declared difficulty.

    The estimator fires once (at the re-estimate checkpoint) and remembers
    its verdict for the rest of the solve.
    """

    # Fraction of max_iterations at which re-estimation fires.
    CHECKPOINT_RATIO = 1 / 3

    # Evidence-per-iteration thresholds for each declared difficulty.
    # If observed rate diverges enough, we up- or down-classify.
    EXPECTED_RATE = {
        "easy":   0.18,
        "medium": 0.12,
        "hard":   0.07,
        "insane": 0.04,
    }

    # How far the observed rate must diverge to trigger reclassification.
    UP_CLASSIFY_THRESHOLD   = 0.4   # observed << expected → harder than thought
    DOWN_CLASSIFY_THRESHOLD = 2.0   # observed >> expected → easier than thought

    def __init__(self, initial_difficulty: str, max_iterations: int) -> None:
        self.initial_difficulty = str(initial_difficulty or "medium").lower()
        self.max_iterations = max(1, int(max_iterations))
        self.current_difficulty = self.initial_difficulty
        self._fired = False
        self._verdict: dict[str, Any] | None = None

    def should_reestimate(self, iteration: int) -> bool:
        """True once, at the checkpoint iteration."""
        if self._fired:
            return False
        checkpoint = max(3, int(self.max_iterations * self.CHECKPOINT_RATIO))
        return iteration >= checkpoint

    def reestimate(
        self,
        iteration: int,
        fruitless: int,
        tool_failures: int,
        evidence_log: list[dict],
        route_score: int = 50,
    ) -> dict[str, Any]:
        """
        Re-classify difficulty based on observed evidence gain rate.

        Returns dict with: new_difficulty, changed, reason, old_difficulty.
        Side-effect: updates self.current_difficulty.
        """
        self._fired = True

        successful_evidence = [
            e for e in (evidence_log or [])
            if e.get("success") or e.get("progress")
        ]
        evidence_rate = len(successful_evidence) / max(1, iteration)

        expected = self.EXPECTED_RATE.get(self.initial_difficulty, 0.10)
        ratio = evidence_rate / expected if expected > 0 else 1.0

        old_idx = _difficulty_index(self.initial_difficulty)
        new_idx = old_idx

        reason = "no change"
        changed = False

        if ratio <= self.UP_CLASSIFY_THRESHOLD:
            # Much harder than expected.
            steps_up = 1 if ratio > 0.2 else 2
            new_idx = min(len(_DIFFICULTY_LADDER) - 1, old_idx + steps_up)
            reason = (
                f"evidence_rate={evidence_rate:.3f} << expected={expected:.3f} "
                f"(ratio={ratio:.2f}) — up-classifying by {new_idx - old_idx}"
            )
            changed = new_idx != old_idx

        elif ratio >= self.DOWN_CLASSIFY_THRESHOLD:
            # Much easier than expected.
            new_idx = max(0, old_idx - 1)
            reason = (
                f"evidence_rate={evidence_rate:.3f} >> expected={expected:.3f} "
                f"(ratio={ratio:.2f}) — down-classifying"
            )
            changed = new_idx != old_idx

        # Fruitless iterations as a secondary hard-mode signal.
        if fruitless >= max(4, int(self.max_iterations * 0.25)) and new_idx < 3:
            new_idx = min(3, new_idx + 1)
            reason += f" | fruitless={fruitless} forcing up"
            changed = True

        new_diff = _difficulty_from_index(new_idx)
        self.current_difficulty = new_diff

        verdict = {
            "old_difficulty": self.initial_difficulty,
            "new_difficulty": new_diff,
            "changed": changed,
            "reason": reason,
            "evidence_rate": round(evidence_rate, 4),
            "expected_rate": round(expected, 4),
            "ratio": round(ratio, 3),
            "iteration": iteration,
            "fruitless": fruitless,
        }
        self._verdict = verdict
        return verdict

    def current(self) -> str:
        return self.current_difficulty

    def verdict(self) -> dict[str, Any] | None:
        return self._verdict
