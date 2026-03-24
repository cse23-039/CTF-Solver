from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BeliefState:
    hypothesis: str
    uncertainty: float = 0.5
    evidence_score: float = 0.0
    evidence_count: int = 0
    last_tool: str = ""


@dataclass
class SolveState:
    iteration: int = 0
    max_iterations: int = 0
    fruitless: int = 0
    last_progress_iter: int = 0
    tool_failures: int = 0
    last_flag_check_iter: int = 0
    opus_budget_remaining: int = 0
    autonomous_phase: str = "recon"
    autonomous_cycles: int = 0
    found_flag: str | None = None
    final_workspace: str = ""
    solve_log: list[str] = field(default_factory=list)
    route_history: list[dict[str, Any]] = field(default_factory=list)
    strategy_history: list[dict[str, Any]] = field(default_factory=list)
    pivot_events: list[str] = field(default_factory=list)
    tool_call_history: list[str] = field(default_factory=list)
    evidence_log: list[dict[str, Any]] = field(default_factory=list)
    beliefs: dict[str, BeliefState] = field(default_factory=dict)

    def touch_progress(self) -> None:
        self.fruitless = 0
        self.last_progress_iter = self.iteration
        if self.tool_failures > 0:
            self.tool_failures -= 1

    def touch_no_progress(self) -> None:
        self.fruitless += 1

    def set_phase(self, phase: str, tool_used: bool = False) -> None:
        self.autonomous_phase = phase
        if tool_used:
            self.autonomous_cycles += 1
