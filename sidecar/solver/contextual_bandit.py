"""Contextual Thompson-sampling tool policy with on-disk persistence."""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class BetaArm:
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0
    wins: int = 0
    last_ts: int = 0

    def prior(self) -> float:
        d = self.alpha + self.beta
        return self.alpha / d if d > 0 else 0.5


class ContextualBandit:
    def __init__(self, path: str, decay: float = 0.995) -> None:
        self.path = path
        self.decay = max(0.90, min(1.0, float(decay)))
        self.table: dict[str, dict[str, BetaArm]] = {}
        self._load()

    @staticmethod
    def context_key(state: dict[str, Any]) -> str:
        cat = str(state.get("category", "unknown"))
        phase = str(state.get("phase", "recon"))
        remote = "r" if bool(state.get("is_remote", False)) else "l"
        hb = "b" if bool(state.get("has_binary", False)) else "n"
        pressure = int(round(float(state.get("difficulty_pressure", 0.0)) * 10.0))
        maturity = int(round(float(state.get("exploit_maturity", 0.0)) * 10.0))
        return f"{cat}|{phase}|{remote}|{hb}|p{pressure}|m{maturity}"

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for ctx, tools in (raw.get("table", {}) or {}).items():
                self.table[ctx] = {}
                for t, rec in (tools or {}).items():
                    self.table[ctx][t] = BetaArm(
                        alpha=float(rec.get("alpha", 1.0)),
                        beta=float(rec.get("beta", 1.0)),
                        pulls=int(rec.get("pulls", 0)),
                        wins=int(rec.get("wins", 0)),
                        last_ts=int(rec.get("last_ts", 0)),
                    )
        except Exception:
            self.table = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        data: dict[str, Any] = {"table": {}}
        for ctx, tools in self.table.items():
            data["table"][ctx] = {}
            for t, arm in tools.items():
                data["table"][ctx][t] = {
                    "alpha": round(arm.alpha, 6),
                    "beta": round(arm.beta, 6),
                    "pulls": arm.pulls,
                    "wins": arm.wins,
                    "last_ts": arm.last_ts,
                }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def rank(self, state: dict[str, Any], tool_names: list[str]) -> list[dict[str, Any]]:
        ctx = self.context_key(state)
        ctx_table = self.table.setdefault(ctx, {})
        ranked = []
        for t in tool_names:
            arm = ctx_table.setdefault(t, BetaArm())
            # Thompson sampling draw: encourages exploration under uncertainty.
            sample = random.betavariate(max(1e-6, arm.alpha), max(1e-6, arm.beta))
            ranked.append({"tool": t, "score": sample, "mean": arm.prior(), "pulls": arm.pulls})
        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked

    def update(self, state: dict[str, Any], tool_name: str, success: bool) -> None:
        self.update_weighted(state, tool_name, 1.0 if success else 0.0)

    def update_weighted(self, state: dict[str, Any], tool_name: str, quality: float) -> None:
        ctx = self.context_key(state)
        arm = self.table.setdefault(ctx, {}).setdefault(tool_name, BetaArm())
        arm.alpha *= self.decay
        arm.beta *= self.decay
        q = max(0.0, min(1.0, float(quality)))
        if q > 0.0:
            arm.alpha += q
        if q < 1.0:
            arm.beta += (1.0 - q)
        if q >= 0.5:
            arm.wins += 1
        arm.pulls += 1
        arm.last_ts = int(time.time())
