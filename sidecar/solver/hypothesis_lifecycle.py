"""Lifecycle tracking for hypotheses with explicit kill criteria."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Hypothesis:
    text: str
    status: str = "active"
    evidence: float = 0.0
    failures: int = 0
    updates: list[str] = field(default_factory=list)


class HypothesisManager:
    def __init__(self) -> None:
        self._items: dict[str, Hypothesis] = {}

    def seed(self, hypotheses: list[str]) -> None:
        for h in hypotheses:
            if h and h not in self._items:
                self._items[h] = Hypothesis(text=h)

    def update(self, text: str, *, success: bool, evidence_gain: float, note: str = "") -> None:
        if text not in self._items:
            self._items[text] = Hypothesis(text=text)
        hyp = self._items[text]
        hyp.evidence = max(0.0, min(1.0, hyp.evidence + float(evidence_gain)))
        if success:
            hyp.status = "validated" if hyp.evidence >= 0.7 else "pending_evidence"
            hyp.failures = max(0, hyp.failures - 1)
        else:
            hyp.failures += 1
            if hyp.failures >= 3 and hyp.evidence < 0.35:
                hyp.status = "disproven"
            else:
                hyp.status = "pending_evidence"
        if note:
            hyp.updates.append(note[:220])

    def mark_kill_criteria(self, fruitless: int, iteration: int, total_iters: int) -> list[str]:
        killed = []
        late = iteration > max(4, int(total_iters * 0.65))
        for h in self._items.values():
            if h.status in ("validated", "disproven"):
                continue
            if (h.failures >= 4 and h.evidence <= 0.3) or (late and fruitless >= 4 and h.evidence < 0.45):
                h.status = "disproven"
                h.updates.append("kill_criteria")
                killed.append(h.text)
        return killed

    def summary(self) -> list[dict[str, Any]]:
        return [
            {
                "hypothesis": h.text,
                "status": h.status,
                "evidence": round(h.evidence, 4),
                "failures": h.failures,
            }
            for h in self._items.values()
        ]

    def active_hypotheses(self) -> list[str]:
        return [h.text for h in self._items.values() if h.status not in ("disproven", "validated")]

    def select_active(self, iteration: int, hint: str = "") -> str | None:
        active = self.active_hypotheses()
        if not active:
            return None
        if hint:
            hint_l = hint.lower()
            for h in active:
                if any(tok in h.lower() for tok in hint_l.split()[:3]):
                    return h
        idx = max(0, int(iteration)) % len(active)
        return active[idx]
