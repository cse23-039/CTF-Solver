"""Adversarial self-play debate for high-complexity challenges.

Enhancement 8: When route_score >= 80 (high complexity + high uncertainty),
runs two parallel Sonnet calls with opposing stances:
  - Attacker: proposes exploit approaches
  - Defender: identifies why each approach will fail
Then Haiku adjudicates and produces a refined attack plan.

Replaces the self_play_red_team.md stub in apt_artifacts/.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

_MODEL_SONNET = "claude-sonnet-4-6"
_MODEL_HAIKU  = "claude-haiku-4-5-20251001"

_ATTACKER_SYSTEM = """You are a CTF attacker. Your job is to propose SPECIFIC, CONCRETE exploit approaches.
For each approach list:
1. The exact vulnerability class
2. The tool and command to exploit it
3. Why you believe this will work

Be aggressive. Propose 3 distinct attack vectors. Do not hedge.
Format each as:
ATTACK [N]: [technique name]
TOOL: tool_name(exact_args)
CONFIDENCE: X/10
WHY: one sentence"""

_DEFENDER_SYSTEM = """You are a CTF security analyst playing devil's advocate.
You receive proposed attack approaches and must identify WHY EACH ONE WILL FAIL.
Be harsh and specific. Look for:
- Wrong assumptions about the vulnerability
- Protections that block the approach (ASLR, WAF, rate limiting, etc)
- Missing prerequisites the attacker ignored
- Edge cases that break the exploit

For each attack, respond:
ATTACK [N] FLAW: [specific reason it fails]
COUNTERMEASURE: [what protection blocks it]
ALTERNATIVE HINT: [what to try instead]"""

_ADJUDICATOR_SYSTEM = """You are a CTF expert adjudicating a debate between an attacker and a defender.
Read both positions and produce a REFINED ATTACK PLAN that:
1. Takes the attacker's best approach
2. Accounts for the defender's valid objections
3. Proposes a concrete path that avoids the identified pitfalls

Respond with:
WINNING_APPROACH: [technique]
REFINED_PLAN: [step-by-step, max 5 steps]
FIRST_TOOL: tool_name(args)
CONFIDENCE: X/10
KEY_ASSUMPTION: [the one thing that must be true for this to work]"""


def _call_model(client, model: str, system: str, user_msg: str, max_tokens: int = 800) -> str:
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )
        return resp.content[0].text if resp.content else ""
    except Exception as e:
        return f"[ERROR: {e}]"


def run_self_play_debate(
    challenge_description: str,
    category: str,
    difficulty: str,
    recon_summary: str = "",
    route_score: int = 80,
    api_key: str = "",
) -> dict[str, Any]:
    """
    Run attacker vs defender debate and return adjudicated attack plan.

    Returns dict with: attacker_output, defender_output, adjudicator_output,
    winning_approach, first_tool, confidence, key_assumption, error.
    """
    default = {
        "attacker_output": "",
        "defender_output": "",
        "adjudicator_output": "",
        "winning_approach": "",
        "first_tool": "",
        "confidence": 0,
        "key_assumption": "",
        "error": None,
        "skipped": False,
    }

    # Only run for genuinely hard challenges.
    if route_score < 78:
        default["skipped"] = True
        default["error"] = f"route_score={route_score} < 78 threshold"
        return default

    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        default["error"] = "No API key"
        return default

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        context = (
            f"Category: {category} | Difficulty: {difficulty} | Route score: {route_score}\n\n"
            f"Challenge:\n{str(challenge_description)[:1500]}\n\n"
            f"Recon so far:\n{str(recon_summary)[:1000]}"
        )

        # Run attacker and defender in parallel.
        with ThreadPoolExecutor(max_workers=2) as ex:
            attacker_fut = ex.submit(
                _call_model, client, _MODEL_SONNET, _ATTACKER_SYSTEM, context, 600
            )
            defender_context = context  # defender receives same challenge info
            # Defender gets the challenge context; after attacker resolves, we'll pass attacks too.
            # For speed we run both in parallel — defender responds to challenge, not to attacker output.
            # Adjudicator synthesizes both.
            defender_fut = ex.submit(
                _call_model, client, _MODEL_SONNET, _DEFENDER_SYSTEM,
                f"{context}\n\n[Evaluate likely attacker approaches for this type of challenge]", 600
            )
            attacker_out = attacker_fut.result(timeout=40)
            defender_out = defender_fut.result(timeout=40)

        # Adjudicator sees both sides.
        adjudicator_msg = (
            f"{context}\n\n"
            f"=== ATTACKER PROPOSALS ===\n{attacker_out}\n\n"
            f"=== DEFENDER OBJECTIONS ===\n{defender_out}"
        )
        adjudicator_out = _call_model(
            client, _MODEL_HAIKU, _ADJUDICATOR_SYSTEM, adjudicator_msg, 512
        )

        # Parse adjudicator output.
        winning = ""
        first_tool = ""
        confidence = 0
        key_assumption = ""
        for line in adjudicator_out.splitlines():
            line = line.strip()
            if line.startswith("WINNING_APPROACH:"):
                winning = line.split(":", 1)[1].strip()
            elif line.startswith("FIRST_TOOL:"):
                first_tool = line.split(":", 1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = int(line.split(":", 1)[1].strip().split("/")[0])
                except Exception:
                    pass
            elif line.startswith("KEY_ASSUMPTION:"):
                key_assumption = line.split(":", 1)[1].strip()

        return {
            "attacker_output": attacker_out[:1200],
            "defender_output": defender_out[:1200],
            "adjudicator_output": adjudicator_out[:800],
            "winning_approach": winning,
            "first_tool": first_tool,
            "confidence": confidence,
            "key_assumption": key_assumption,
            "error": None,
            "skipped": False,
        }

    except Exception as e:
        default["error"] = str(e)[:200]
        return default


def render_debate_for_prompt(debate: dict[str, Any]) -> str:
    """Render debate results as a system prompt injection."""
    if debate.get("skipped") or debate.get("error") or not debate.get("winning_approach"):
        return ""
    lines = [
        "## Adversarial self-play debate results:",
        f"Winning approach: {debate['winning_approach']}",
    ]
    if debate.get("first_tool"):
        lines.append(f"Recommended first tool: {debate['first_tool']}")
    if debate.get("key_assumption"):
        lines.append(f"Key assumption to verify: {debate['key_assumption']}")
    if debate.get("confidence"):
        lines.append(f"Adjudicator confidence: {debate['confidence']}/10")
    lines.append("\nFull adjudicator plan:")
    lines.append(debate.get("adjudicator_output", "")[:600])
    return "\n".join(lines)
