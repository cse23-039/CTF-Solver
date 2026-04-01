"""Branch synthesis and voting for parallel hypothesis rounds."""
from __future__ import annotations

import json
import os
from typing import Any

_MODEL_HAIKU = "claude-haiku-4-5-20251001"

_SYSTEM = """You rank parallel CTF branches by expected progress.
Respond ONLY JSON array of objects: [{"branch":"...","score":0.0,"reason":"..."}].
Use evidence quality and novelty, not just whether a flag was found.
"""


def synthesize_branch_progress(branch_summaries: list[dict[str, Any]], api_key: str = "") -> list[dict[str, Any]]:
    if not branch_summaries:
        return []

    # Heuristic baseline ranking.
    scored = []
    for b in branch_summaries:
        wins = float(b.get("wins", 0))
        pulls = max(1.0, float(b.get("pulls", 1)))
        quality = float(b.get("quality", 0.5))
        novelty = float(b.get("novelty", 0.5))
        score = (0.45 * (wins / pulls)) + (0.35 * quality) + (0.20 * novelty)
        scored.append({"branch": str(b.get("branch", "?")), "score": round(score, 4), "reason": "heuristic"})
    scored.sort(key=lambda x: x["score"], reverse=True)

    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return scored

    try:
        import anthropic  # type: ignore

        cli = anthropic.Anthropic(api_key=api_key)
        resp = cli.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=260,
            system=_SYSTEM,
            messages=[{"role": "user", "content": json.dumps(branch_summaries, ensure_ascii=False)[:3500]}],
        )
        raw = (resp.content[0].text if resp.content else "[]").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        if isinstance(parsed, list) and parsed:
            out = []
            for p in parsed[: len(branch_summaries)]:
                if isinstance(p, dict) and p.get("branch"):
                    out.append({
                        "branch": str(p.get("branch")),
                        "score": round(max(0.0, min(1.0, float(p.get("score", 0.5)))), 4),
                        "reason": str(p.get("reason", "haiku"))[:120],
                    })
            out.sort(key=lambda x: x["score"], reverse=True)
            return out if out else scored
    except Exception:
        pass
    return scored
