"""Unified scoring engine for branch ranking and expected flag yield."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass
class ScoreWeights:
    evidence: float = 0.32
    novelty: float = 0.18
    exploitability: float = 0.24
    success_prior: float = 0.18
    confidence: float = 0.08


def _clip01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def expected_flag_yield(
    evidence: float,
    novelty: float,
    exploitability: float,
    success_prior: float,
    confidence: float,
    estimated_cost: float,
    weights: ScoreWeights | None = None,
) -> float:
    """Compute a calibrated expected-value score for a branch/tool action."""
    w = weights or ScoreWeights()
    linear = (
        w.evidence * _clip01(evidence)
        + w.novelty * _clip01(novelty)
        + w.exploitability * _clip01(exploitability)
        + w.success_prior * _clip01(success_prior)
        + w.confidence * _clip01(confidence)
    )
    # Cost-aware damping prevents expensive low-confidence branches from dominating.
    penalty = 1.0 / (1.0 + max(0.0, float(estimated_cost)))
    # Mild logistic calibration to avoid extreme raw values.
    calibrated = 1.0 / (1.0 + math.exp(-6.0 * (linear - 0.5)))
    return calibrated * penalty


def rank_branches(branches: list[dict[str, Any]], weights: ScoreWeights | None = None) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for b in branches:
        score = expected_flag_yield(
            evidence=float(b.get("evidence", 0.0)),
            novelty=float(b.get("novelty", 0.0)),
            exploitability=float(b.get("exploitability", 0.0)),
            success_prior=float(b.get("success_prior", 0.0)),
            confidence=float(b.get("confidence", 0.0)),
            estimated_cost=float(b.get("estimated_cost", 0.0)),
            weights=weights,
        )
        enriched = dict(b)
        enriched["expected_flag_yield"] = round(score, 6)
        ranked.append(enriched)
    ranked.sort(key=lambda x: x.get("expected_flag_yield", 0.0), reverse=True)
    return ranked
