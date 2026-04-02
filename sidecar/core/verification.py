from __future__ import annotations

import json
import os
import re
from typing import Any, Callable


def _looks_like_flag(candidate_flag: str) -> bool:
    flag = str(candidate_flag or "").strip()
    if len(flag) < 6 or len(flag) > 260:
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[^{}\n]{3,220}\}", flag))


def validator_agent_secondary(candidate_flag: str, evidence_excerpt: str, model_haiku: str, api_key: str = "") -> dict[str, Any]:
    fallback = {
        "verdict": "pass" if _looks_like_flag(candidate_flag) else "fail",
        "confidence": 0.55,
        "reason": "secondary-fallback"
    }
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return fallback
    try:
        import anthropic as _ant

        cli = _ant.Anthropic(api_key=api_key)
        prompt = (
            "Return ONLY JSON with verdict, confidence, reason.\n"
            f"Candidate flag: {candidate_flag}\n"
            f"Evidence:\n{evidence_excerpt[:2800]}\n"
            "If chain-of-custody is weak, fail."
        )
        resp = cli.messages.create(
            model=model_haiku,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.content[0].text if resp.content else ""
        j = re.search(r"\{[\s\S]*\}", raw)
        if not j:
            return fallback
        out = json.loads(j.group(0))
        verdict = str(out.get("verdict", "fail")).strip().lower()
        return {
            "verdict": "pass" if verdict == "pass" else "fail",
            "confidence": max(0.0, min(1.0, float(out.get("confidence", 0.5) or 0.5))),
            "reason": str(out.get("reason", "secondary-agent"))[:220],
        }
    except Exception:
        return fallback


def reproducibility_check(candidate_flag: str, evidence_log: list[dict], solve_log: list[str]) -> dict[str, Any]:
    text_window = "\n".join(solve_log[-12:])
    in_reasoning = candidate_flag in text_window if candidate_flag else False
    evidence_hits = 0
    proof_steps: list[str] = []
    for rec in (evidence_log or [])[-120:]:
        out = str(rec.get("output", ""))
        if candidate_flag and candidate_flag in out:
            evidence_hits += 1
            tool_name = str(rec.get("tool", "unknown"))
            proof_steps.append(f"tool={tool_name} produced flag substring")

    pass_ok = in_reasoning or evidence_hits > 0
    conf = 0.72 if evidence_hits >= 2 else (0.62 if pass_ok else 0.20)
    return {
        "verdict": "pass" if pass_ok else "fail",
        "confidence": conf,
        "reason": f"reasoning_hit={in_reasoning} evidence_hits={evidence_hits}",
        "evidence_hits": evidence_hits,
        "proof_steps": proof_steps[:20],
    }


def replayable_proof_gate(repro: dict[str, Any], min_steps: int = 1) -> dict[str, Any]:
    steps = repro.get("proof_steps", []) if isinstance(repro.get("proof_steps"), list) else []
    ok = len(steps) >= min_steps and repro.get("verdict") == "pass"
    return {
        "verdict": "pass" if ok else "fail",
        "confidence": 0.75 if ok else 0.25,
        "reason": f"proof_steps={len(steps)} min_steps={min_steps}",
        "proof_steps": steps,
    }


def run_self_verification(
    candidate_flag: str,
    conversation_summary: str,
    ctf_name: str,
    category: str,
    evidence_log: list[dict],
    solve_log: list[str],
    validate_candidate_flag: Callable[..., dict[str, Any]],
    model_haiku: str,
    api_key: str = "",
) -> dict[str, Any]:
    primary = validate_candidate_flag(
        conversation_summary=conversation_summary,
        candidate_flag=candidate_flag,
        ctf_name=ctf_name,
        category=category,
        api_key=api_key,
    )
    repro = reproducibility_check(candidate_flag, evidence_log, solve_log)
    replay = replayable_proof_gate(repro, min_steps=1)
    secondary = validator_agent_secondary(candidate_flag, "\n".join(solve_log[-10:]), model_haiku=model_haiku, api_key=api_key)

    votes = [
        primary.get("verdict") == "pass",
        repro.get("verdict") == "pass",
        secondary.get("verdict") == "pass",
        replay.get("verdict") == "pass",
    ]
    score = (
        float(primary.get("confidence", 0.0)) * 0.40 +
        float(repro.get("confidence", 0.0)) * 0.25 +
        float(secondary.get("confidence", 0.0)) * 0.20 +
        float(replay.get("confidence", 0.0)) * 0.15
    )
    verdict = "pass" if (sum(1 for v in votes if v) >= 3 and score >= 0.60) else "fail"
    return {
        "verdict": verdict,
        "confidence": round(score, 3),
        "reason": f"votes={sum(1 for v in votes if v)}/4",
        "agents": {"primary": primary, "secondary": secondary, "repro": repro, "replay": replay},
        "proof_steps": replay.get("proof_steps", []),
    }
