from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolReliability:
    success: int = 0
    failure: int = 0
    circuit_open_until: float = 0.0
    last_ts: float = 0.0

    def prior(self) -> float:
        return (self.success + 1.0) / (self.success + self.failure + 2.0)


@dataclass
class ToolRuntime:
    timeout_s: int = 45
    failure_threshold: int = 3
    cooldown_s: int = 45
    _stats: dict[str, ToolReliability] = field(default_factory=dict)
    _ctx_stats: dict[str, ToolReliability] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def reliability_snapshot(self) -> dict[str, float]:
        with self._lock:
            return {name: rec.prior() for name, rec in self._stats.items()}

    def contextual_reliability_snapshot(self, context_key: str) -> dict[str, float]:
        prefix = f"{context_key}|"
        with self._lock:
            out = {}
            for k, rec in self._ctx_stats.items():
                if k.startswith(prefix):
                    out[k[len(prefix):]] = rec.prior()
            return out

    def context_key(self, context: dict[str, Any] | None) -> str:
        return self._context_key(context)

    def _get(self, tool_name: str) -> ToolReliability:
        with self._lock:
            if tool_name not in self._stats:
                self._stats[tool_name] = ToolReliability()
            return self._stats[tool_name]

    def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_map: dict[str, Callable[[dict[str, Any]], Any]],
        context: dict[str, Any] | None = None,
    ) -> tuple[str, bool, str]:
        rec = self._get(tool_name)
        now = time.time()
        if rec.circuit_open_until > now:
            return "", False, "circuit_open"
        if tool_name not in tool_map:
            self._record(tool_name, success=False)
            return f"Unknown tool: {tool_name}", False, "unknown_tool"

        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(tool_map[tool_name], tool_input)
                out = fut.result(timeout=max(5, int(self.timeout_s)))
            txt = str(out)
            ok = self._output_success(txt)
            self._record(tool_name, success=ok)
            self._record_context(tool_name, context=context, success=ok)
            return txt, ok, "ok" if ok else "tool_failed"
        except TimeoutError:
            self._record(tool_name, success=False)
            self._record_context(tool_name, context=context, success=False)
            return f"Tool timeout after {self.timeout_s}s", False, "timeout"
        except Exception as e:
            self._record(tool_name, success=False)
            self._record_context(tool_name, context=context, success=False)
            return f"Tool error: {type(e).__name__}: {e}", False, "exception"

    def _record(self, tool_name: str, success: bool) -> None:
        rec = self._get(tool_name)
        # Gentle decay keeps priors adaptive to changing challenge distributions.
        rec.success = int(rec.success * 0.995)
        rec.failure = int(rec.failure * 0.995)
        if success:
            rec.success += 1
            rec.failure = max(0, rec.failure - 1)
            rec.circuit_open_until = 0.0
        else:
            rec.failure += 1
            if rec.failure >= self.failure_threshold:
                rec.circuit_open_until = time.time() + self.cooldown_s
        rec.last_ts = time.time()

    @staticmethod
    def _context_key(context: dict[str, Any] | None) -> str:
        c = context or {}
        tgt = "remote" if bool(c.get("is_remote", False)) else "local"
        bty = str(c.get("binary_type", "none") or "none")
        phase = str(c.get("phase", "recon") or "recon")
        lat_bucket = str(c.get("latency_bucket", "unknown") or "unknown")
        return f"{tgt}|{bty}|{phase}|{lat_bucket}"

    def _record_context(self, tool_name: str, context: dict[str, Any] | None, success: bool) -> None:
        k = f"{self._context_key(context)}|{tool_name}"
        with self._lock:
            if k not in self._ctx_stats:
                self._ctx_stats[k] = ToolReliability()
            rec = self._ctx_stats[k]
            rec.success = int(rec.success * 0.99)
            rec.failure = int(rec.failure * 0.99)
            if success:
                rec.success += 1
            else:
                rec.failure += 1
            rec.last_ts = time.time()

    @staticmethod
    def _output_success(out: str) -> bool:
        txt = str(out or "").lower()
        bad_markers = ["tool error", "unknown tool", "traceback", "timed out", "failed"]
        return not any(m in txt for m in bad_markers)
