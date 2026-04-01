"""Chaos harness for reliability fault-injection rehearsal."""
from __future__ import annotations

import random
import time
from typing import Any


def run_chaos_harness(seed: int = 42, rounds: int = 25) -> dict[str, Any]:
    rng = random.Random(int(seed))
    rounds = max(1, int(rounds))

    scenarios = [
        "api_429_storm",
        "tool_timeout_burst",
        "queue_contention",
        "stale_lock_recovery",
        "malformed_challenge_metadata",
        "platform_partial_outage",
    ]
    failures = 0
    events = []
    for _ in range(rounds):
        sc = rng.choice(scenarios)
        sev = rng.random()
        recovered = sev < 0.86
        if not recovered:
            failures += 1
        events.append({"scenario": sc, "severity": round(sev, 4), "recovered": recovered})

    pass_rate = 1.0 - (failures / max(1, rounds))
    verdict = "pass" if pass_rate >= 0.97 else "fail"
    return {
        "ts": int(time.time()),
        "rounds": rounds,
        "failures": failures,
        "pass_rate": round(pass_rate, 4),
        "verdict": verdict,
        "events": events[:50],
    }
