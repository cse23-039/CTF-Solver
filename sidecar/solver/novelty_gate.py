"""Haiku novelty gate for tool call deduplication and diversification."""
from __future__ import annotations

import json
import os
from typing import Any

_MODEL_HAIKU = "claude-haiku-4-5-20251001"

_SYSTEM = """You are a CTF tool-call novelty estimator.
Given a proposed tool call and the last few outputs, score expected information gain.
Respond ONLY JSON:
{
  "information_gain": 0.0,
  "block": false,
  "reason": "...",
  "diversify_tool": "tool_name",
  "diversify_args": {"k":"v"}
}
Set block=true when call is repetitive/low signal and information_gain < 0.2.
"""


def _heuristic_gain(tool_name: str, tool_args: dict[str, Any], recent_outputs: list[str]) -> dict[str, Any]:
    args_repr = json.dumps(tool_args, ensure_ascii=False, sort_keys=True)
    repeated = 0
    for out in (recent_outputs or [])[-5:]:
        low = str(out).lower()
        if tool_name.lower() in low or args_repr[:80].lower() in low:
            repeated += 1
    gain = max(0.05, 0.75 - (0.18 * repeated))
    block = gain < 0.2
    diversify = "pre_solve_recon" if tool_name not in ("pre_solve_recon", "rank_hypotheses") else "rank_hypotheses"
    return {
        "information_gain": round(gain, 3),
        "block": block,
        "reason": "heuristic_repeat_check",
        "diversify_tool": diversify,
        "diversify_args": {},
        "source": "heuristic",
    }


def score_tool_novelty(tool_name: str, tool_args: dict[str, Any], recent_outputs: list[str], api_key: str = "") -> dict[str, Any]:
    heuristic = _heuristic_gain(tool_name, tool_args, recent_outputs)
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return heuristic

    try:
        import anthropic  # type: ignore

        cli = anthropic.Anthropic(api_key=api_key)
        user_msg = (
            f"Proposed tool: {tool_name}\n"
            f"Args: {json.dumps(tool_args, ensure_ascii=False)[:800]}\n\n"
            f"Recent outputs:\n" + "\n---\n".join([str(x)[:600] for x in (recent_outputs or [])[-5:]])
        )
        resp = cli.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=220,
            system=_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = (resp.content[0].text if resp.content else "{}").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        return {
            "information_gain": float(parsed.get("information_gain", heuristic["information_gain"])),
            "block": bool(parsed.get("block", False)),
            "reason": str(parsed.get("reason", ""))[:140],
            "diversify_tool": str(parsed.get("diversify_tool", heuristic["diversify_tool"]))[:80],
            "diversify_args": parsed.get("diversify_args", {}) if isinstance(parsed.get("diversify_args", {}), dict) else {},
            "source": "haiku",
        }
    except Exception:
        return heuristic
