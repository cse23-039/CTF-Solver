"""Haiku-powered critic loop and tool result confidence grader.

Enhancement 2: Haiku critic fires after every Sonnet/Opus reasoning step
               and returns structured JSON with hallucination flags,
               ignored evidence, and recommended_pivot.

Enhancement 7: LLM-graded tool result quality — replaces binary 0/1
               bandit updates with a continuous quality score [0,1].
"""
from __future__ import annotations

import json
import os
from typing import Any

_MODEL_HAIKU = "claude-haiku-4-5-20251001"


def _haiku_client(api_key: str = ""):
    import anthropic
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    return anthropic.Anthropic(api_key=key)


# ── Enhancement 2: Haiku Critic ───────────────────────────────────────────────

_CRITIC_SYSTEM = """You are a ruthless CTF reasoning critic. You receive:
- The model's latest reasoning/tool call
- Recent tool results
- Current hypothesis being tested

Respond ONLY with a JSON object, no prose, no markdown fences:
{
  "flag_hallucination": bool,
  "ignored_evidence": ["..."],
  "contradicts_memory": bool,
  "wasted_tool_calls": ["tool_name"],
  "recommended_pivot": bool,
  "pivot_reason": "...",
  "confidence_adjustment": float,
  "critic_note": "..."
}

confidence_adjustment: -0.3 to +0.2 relative change.
flag_hallucination: true if the model assumed a flag/key without tool evidence.
recommended_pivot: true if the current approach has < 20% chance of success.
critic_note: one sentence max."""


def run_haiku_critic(
    model_reasoning: str,
    tool_results: list[dict],
    current_hypothesis: str,
    iteration: int,
    api_key: str = "",
) -> dict[str, Any]:
    """
    Run a Haiku critic pass on the latest reasoning step.

    Returns structured verdict dict. On any error returns safe defaults.
    """
    default = {
        "flag_hallucination": False,
        "ignored_evidence": [],
        "contradicts_memory": False,
        "wasted_tool_calls": [],
        "recommended_pivot": False,
        "pivot_reason": "",
        "confidence_adjustment": 0.0,
        "critic_note": "",
        "error": None,
    }

    try:
        client = _haiku_client(api_key)

        recent_results = ""
        for tr in (tool_results or [])[-4:]:
            tname = tr.get("tool", tr.get("name", "?"))
            tout = str(tr.get("output", tr.get("content", "")))[:600]
            recent_results += f"\n[{tname}]: {tout}"

        user_msg = (
            f"Iteration: {iteration}\n"
            f"Current hypothesis: {str(current_hypothesis)[:400]}\n\n"
            f"Model reasoning (latest):\n{str(model_reasoning)[:1200]}\n\n"
            f"Recent tool results:{recent_results or ' (none yet)'}"
        )

        resp = client.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=512,
            system=_CRITIC_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )

        raw = (resp.content[0].text if resp.content else "{}").strip()
        # Strip accidental markdown fences.
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        return {**default, **{k: v for k, v in parsed.items() if k in default}}

    except Exception as e:
        default["error"] = str(e)[:120]
        return default


# ── Enhancement 7: Tool Result Confidence Grader ─────────────────────────────

_GRADER_SYSTEM = """You are a CTF tool output quality assessor.
Respond ONLY with JSON, no prose, no markdown fences:
{
  "quality": float,
  "extractable_facts": ["..."],
  "noise_ratio": float,
  "is_error": bool,
  "contains_flag_signal": bool,
  "grader_note": "..."
}

quality: 0.0 (useless/error) to 1.0 (rich, actionable output).
noise_ratio: fraction of output that is irrelevant (0.0–1.0).
extractable_facts: list of concrete facts the solver can use (max 4 items).
contains_flag_signal: true if output plausibly contains a flag or key material.
grader_note: one sentence max."""


def grade_tool_result(
    tool_name: str,
    result_text: str,
    category: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """
    Grade a tool result on quality [0,1] for weighted bandit updates.

    Falls back to heuristic scoring if Haiku call fails.
    """
    default = {
        "quality": 0.5,
        "extractable_facts": [],
        "noise_ratio": 0.3,
        "is_error": False,
        "contains_flag_signal": False,
        "grader_note": "",
        "source": "haiku",
    }

    # Fast heuristic pre-check — avoids a Haiku call for obvious errors.
    result_lower = str(result_text or "").lower()
    obvious_error = any(tok in result_lower for tok in [
        "command not found", "no such file", "permission denied",
        "error:", "traceback (most recent", "exception:", "errno",
    ])
    flag_signal = any(tok in result_lower for tok in [
        "flag{", "ctf{", "picoctf{", "htb{", "thm{", "key:", "secret:",
        "password:", "token:", "-----begin",
    ])

    if obvious_error and not flag_signal:
        default.update({"quality": 0.05, "is_error": True, "noise_ratio": 0.9, "source": "heuristic"})
        return default

    try:
        client = _haiku_client(api_key)
        user_msg = (
            f"Tool: {tool_name} | Category: {category}\n"
            f"Output (first 1200 chars):\n{str(result_text)[:1200]}"
        )
        resp = client.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=256,
            system=_GRADER_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = (resp.content[0].text if resp.content else "{}").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        result = {**default, **{k: v for k, v in parsed.items() if k in default}}
        result["quality"] = max(0.0, min(1.0, float(result.get("quality", 0.5))))
        result["noise_ratio"] = max(0.0, min(1.0, float(result.get("noise_ratio", 0.3))))
        return result

    except Exception as e:
        # Heuristic fallback.
        quality = 0.5
        if obvious_error:
            quality = 0.1
        elif flag_signal:
            quality = 0.9
        elif len(result_text or "") > 200:
            quality = 0.6
        default.update({
            "quality": quality,
            "is_error": obvious_error,
            "contains_flag_signal": flag_signal,
            "source": "heuristic",
            "grader_note": str(e)[:60],
        })
        return default


def quality_to_bandit_update(grade: dict[str, Any]) -> tuple[float, float]:
    """
    Convert a grade dict into (alpha_increment, beta_increment) for the bandit arm.

    Returns (alpha_inc, beta_inc) where alpha represents success weight
    and beta represents failure weight. Values sum to 1.0.
    """
    q = float(grade.get("quality", 0.5))
    alpha_inc = q
    beta_inc = 1.0 - q
    return round(alpha_inc, 4), round(beta_inc, 4)
