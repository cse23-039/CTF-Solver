from __future__ import annotations

from routing.category_weights import get_profile
from routing.tool_priority import get_priority


def compute_expected_value_score(challenge: dict) -> float:
    diff = str(challenge.get("difficulty", "medium")).lower()
    pts = float(challenge.get("points", 100) or 100)
    diff_mult = {"easy": 1.2, "medium": 1.0, "hard": 0.82, "insane": 0.62}.get(diff, 1.0)
    return round((pts * diff_mult) / 100.0, 4)


def decide_strategy_mode(category: str, phase: str, fruitless: int, tool_failures: int,
                         iteration: int, total_iters: int, memory_diag: dict,
                         learned_overrides: dict | None = None) -> dict:
    cat = (category or "").lower()
    profile = get_profile(category, learned_overrides=learned_overrides)
    category_key = profile.get("category_key", "web")
    base_mode = "general-evidence"
    rec_tools = ["pre_solve_recon", "rank_hypotheses"]

    if "crypto" in cat:
        base_mode = "symbolic-crypto"
        rec_tools = ["crypto_attack", "sage_math", "z3_solve", "statistical_analysis"]
    elif "web" in cat:
        base_mode = "dynamic-web"
        rec_tools = ["http_request", "js_analyze", "source_audit", "sql_injection"]
    elif "reverse" in cat:
        base_mode = "rev-static-dynamic"
        rec_tools = ["disassemble", "binary_analysis", "execute_python", "decompile"]
    elif "binary" in cat or "pwn" in cat:
        base_mode = "binary-exploit"
        rec_tools = ["checksec", "binary_analysis", "rop_chain", "execute_python"]
    elif "forensic" in cat:
        base_mode = "artifact-forensics"
        rec_tools = ["forensics", "extract_strings", "pcap_analyze", "steg_analyze"]

    pivot = False
    reason = ""
    mode = base_mode

    contradictions = len((memory_diag or {}).get("contradictions", []))
    if contradictions > 0 and phase in ("recon", "exploit"):
        mode = "memory-guarded-verification"
        pivot = True
        reason = "memory-contradiction"
    if fruitless >= int(profile.get("pivot_fruitless", 3)):
        mode = "diversify-attack-surface"
        pivot = True
        reason = reason or "fruitless-iterations"
    if tool_failures >= int(profile.get("pivot_tool_failures", 2)):
        mode = "self-heal-fallbacks"
        pivot = True
        reason = reason or "tool-failures"
    if phase == "validate":
        mode = "validator-evidence-gate"
        rec_tools = ["formal_verify", "detect_flag_format", "submit_flag"]

    decay_f = float(profile.get("confidence_decay_fruitless", 0.08))
    decay_t = float(profile.get("confidence_decay_tool_failures", 0.12))
    confidence = max(0.05, min(0.99, 1.0 - ((fruitless * decay_f) + (tool_failures * decay_t))))
    # Apply category baseline priorities if strategy did not force specific tools.
    if mode not in ("validator-evidence-gate",):
        rec_tools = get_priority(category_key)
    progress_ratio = round(iteration / max(1, total_iters), 3)
    return {
        "mode": mode,
        "base_mode": base_mode,
        "category_key": category_key,
        "pivot": pivot,
        "reason": reason,
        "recommended_tools": rec_tools,
        "confidence": round(confidence, 3),
        "progress_ratio": progress_ratio,
    }


def route_model_v2(category: str, difficulty: str, iteration: int, total_iters: int,
                   user_model: str, fruitless: int, tool_failures: int,
                   progress_gap: int, opus_budget_remaining: int,
                   model_sonnet: str, model_opus: str, model_haiku: str,
                   memory_hits_count: int = 0,
                   learned_overrides: dict | None = None) -> dict:
    profile = get_profile(category, learned_overrides=learned_overrides)
    hard_categories = {"Cryptography", "Reverse Engineering"}
    diff_score_map = {"easy": 20, "medium": 45, "hard": 70, "insane": 90}
    complexity = diff_score_map.get((difficulty or "medium").lower(), 45)
    if category in hard_categories:
        complexity = min(100, complexity + 12)

    uncertainty = min(100, (fruitless * 10) + (progress_gap * 7) + (12 if memory_hits_count == 0 else 0))
    failure = min(100, (tool_failures * 18) + (20 if fruitless >= 4 else 0))
    route_score = int((0.45 * complexity) + (0.30 * uncertainty) + (0.25 * failure))

    reasons = []
    if complexity >= 80:
        reasons.append("high-complexity")
    if uncertainty >= 60:
        reasons.append("high-uncertainty")
    if failure >= 50:
        reasons.append("tool-failures")
    if memory_hits_count > 0:
        reasons.append("memory-available")

    if user_model not in (model_sonnet, model_opus, model_haiku, ""):
        return {
            "model": user_model,
            "use_thinking": False,
            "thinking_tokens": 0,
            "route_score": route_score,
            "complexity": complexity,
            "uncertainty": uncertainty,
            "failure": failure,
            "reasons": reasons + ["user-custom-model"],
        }

    if user_model == model_opus:
        return {
            "model": model_opus,
            "use_thinking": True,
            "thinking_tokens": 10000 if difficulty == "insane" else 8000,
            "route_score": route_score,
            "complexity": complexity,
            "uncertainty": uncertainty,
            "failure": failure,
            "reasons": reasons + ["user-forced-opus"],
        }

    use_opus = False
    use_thinking = False
    thinking_tokens = 0

    hard_threshold = int(profile.get("route_escalate_score", 70))
    soft_threshold = int(profile.get("route_soft_escalate_score", 58))
    if opus_budget_remaining > 0 and route_score >= hard_threshold:
        use_opus = True
        use_thinking = True
        thinking_tokens = 12000 if difficulty == "insane" else 8000
        reasons.append("route-score-threshold")
    elif opus_budget_remaining > 0 and route_score >= soft_threshold and (iteration <= max(2, total_iters // 2)):
        use_opus = True
        use_thinking = difficulty in ("hard", "insane")
        thinking_tokens = 6000 if use_thinking else 0
        reasons.append("early-iteration-escalation")

    model = model_opus if use_opus else model_sonnet
    if not reasons:
        reasons.append("default-sonnet")

    return {
        "model": model,
        "use_thinking": use_thinking,
        "thinking_tokens": thinking_tokens,
        "route_score": route_score,
        "complexity": complexity,
        "uncertainty": uncertainty,
        "failure": failure,
        "reasons": reasons,
    }


def schedule_tools_by_voi(tool_uses: list[dict], strategy: dict, reliability: dict[str, float], beliefs: dict[str, float]) -> list[dict]:
    preferred = set(strategy.get("recommended_tools", []))

    def _score(block: dict) -> float:
        name = str(block.get("name", ""))
        base = 0.4
        if name in preferred:
            base += 0.35
        rel = reliability.get(name, 0.5)
        unc = beliefs.get(name, 0.5)
        return (base * 0.6) + (rel * 0.25) + ((1.0 - unc) * 0.15)

    return sorted(tool_uses, key=_score, reverse=True)
