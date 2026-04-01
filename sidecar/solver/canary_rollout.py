"""Canary rollout helper for cohort-scoped policy updates."""
from __future__ import annotations

import hashlib


def canary_accept(*, cohort: str, challenge_name: str, percent: float = 0.25) -> bool:
    p = max(0.01, min(1.0, float(percent)))
    key = f"{cohort}:{challenge_name}".encode("utf-8", errors="ignore")
    h = int(hashlib.sha256(key).hexdigest()[:8], 16)
    bucket = (h % 10000) / 10000.0
    return bucket <= p
