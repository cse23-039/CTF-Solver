"""Feedback model tracking per-tool reliability and confidence calibration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BetaPosterior:
    alpha: float = 1.0
    beta: float = 1.0

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)


@dataclass
class ToolFeedbackModel:
    posteriors: dict[str, BetaPosterior] = field(default_factory=dict)

    def update(self, tool: str, success: bool) -> float:
        p = self.posteriors.setdefault(tool, BetaPosterior())
        if success:
            p.alpha += 1.0
        else:
            p.beta += 1.0
        return p.mean

    def confidence(self, tool: str) -> float:
        return self.posteriors.get(tool, BetaPosterior()).mean


_MODEL = ToolFeedbackModel()


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    tool = str(kwargs.get("tool", "unknown"))
    success = bool(kwargs.get("success", False))
    updated = _MODEL.update(tool, success)
    return {"tool": tool, "success": success, "posterior_mean": round(updated, 6)}
