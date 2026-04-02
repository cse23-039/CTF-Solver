from __future__ import annotations

import threading
from typing import Any, Callable


def init_credit_guard(extra: dict[str, Any], challenge: dict[str, Any], max_iterations: int) -> dict[str, Any]:
    raw_budget = extra.get("creditBudgetUsd", extra.get("apiBudgetUsd", extra.get("budgetUsd", 5.0)))
    try:
        cap_usd = float(raw_budget)
    except Exception:
        cap_usd = 5.0
    cap_usd = max(0.25, cap_usd)

    conservative = bool(extra.get("conservativeCredits", True))
    hard_stop_ratio = float(extra.get("budgetHardStopRatio", 0.98 if conservative else 0.995))
    reserve_usd = float(extra.get("budgetReserveUsd", 0.75 if conservative else 0.30))
    low_threshold_usd = float(extra.get("lowCreditThresholdUsd", 0.75 if conservative else 0.50))

    difficulty = str(challenge.get("difficulty", "medium")).lower()
    per_iter = {
        "easy": 0.006,
        "medium": 0.012,
        "hard": 0.020,
        "insane": 0.032,
    }.get(difficulty, 0.012)
    conservative_cap_iters = max(6, int(cap_usd / max(0.002, per_iter)))

    return {
        "enabled": bool(extra.get("enforceCreditBudget", True)),
        "conservative": conservative,
        "cap_usd": round(cap_usd, 4),
        "spent_usd": 0.0,
        "hard_stop_ratio": max(0.85, min(0.999, hard_stop_ratio)),
        "reserve_usd": max(0.0, reserve_usd),
        "low_threshold_usd": max(0.05, low_threshold_usd),
        "max_output_tokens": int(extra.get("maxOutputTokensConservative", 4096 if conservative else 8192)),
        "max_reasoning_tokens": int(extra.get("maxReasoningTokensConservative", 10000 if conservative else 20000)),
        "min_remaining_for_opus": float(extra.get("minRemainingUsdForOpus", 1.50 if conservative else 0.50)),
        "conservative_cap_iters": conservative_cap_iters,
        "requested_max_iters": max_iterations,
        "calls": 0,
        "low_alert_emitted": False,
        "lock": threading.Lock(),
    }


def credit_remaining_usd(guard: dict[str, Any]) -> float:
    lock = guard.get("lock")
    if lock:
        with lock:
            return max(0.0, float(guard.get("cap_usd", 0.0)) - float(guard.get("spent_usd", 0.0)))
    return max(0.0, float(guard.get("cap_usd", 0.0)) - float(guard.get("spent_usd", 0.0)))


def credit_is_low(guard: dict[str, Any]) -> bool:
    return credit_remaining_usd(guard) <= float(guard.get("low_threshold_usd", 0.5))


def mark_low_credit_alert_once(guard: dict[str, Any]) -> bool:
    lock = guard.get("lock")
    if lock:
        with lock:
            if guard.get("low_alert_emitted", False):
                return False
            guard["low_alert_emitted"] = True
            return True
    if guard.get("low_alert_emitted", False):
        return False
    guard["low_alert_emitted"] = True
    return True


def plan_budgeted_call(
    guard: dict[str, Any],
    model: str,
    requested_max_tokens: int,
    messages: list[dict[str, Any]],
    system: str,
    use_thinking: bool,
    thinking_tokens: int,
    estimate_input_tokens: Callable[[list[dict[str, Any]], str], int],
    estimate_call_cost: Callable[[str, int, int], float],
    model_opus: str,
    model_sonnet: str,
    model_haiku: str,
) -> dict[str, Any]:
    if not guard.get("enabled", False):
        return {
            "allowed": True,
            "model": model,
            "max_tokens": requested_max_tokens,
            "use_thinking": use_thinking,
            "thinking_tokens": thinking_tokens,
            "estimated_cost": 0.0,
            "input_tokens": 0,
            "reason": "budget-disabled",
        }

    remaining = credit_remaining_usd(guard)
    reserve = float(guard.get("reserve_usd", 0.0))
    soft_remaining = max(0.0, remaining - reserve)
    chosen_model = model
    chosen_max_tokens = max(256, int(requested_max_tokens))
    chosen_max_tokens = min(chosen_max_tokens, int(guard.get("max_output_tokens", chosen_max_tokens)))

    if use_thinking:
        thinking_tokens = min(int(thinking_tokens), int(guard.get("max_reasoning_tokens", thinking_tokens)))
    chosen_use_thinking = bool(use_thinking)
    chosen_thinking_tokens = int(thinking_tokens)

    if chosen_model == model_opus and remaining < float(guard.get("min_remaining_for_opus", 1.5)):
        chosen_model = model_sonnet
        chosen_use_thinking = False
        chosen_thinking_tokens = 0

    input_tokens = estimate_input_tokens(messages, system)
    est_cost = estimate_call_cost(chosen_model, input_tokens, chosen_max_tokens + chosen_thinking_tokens)

    if soft_remaining > 0 and est_cost > soft_remaining:
        shrink_ratio = max(0.20, min(1.0, soft_remaining / max(est_cost, 1e-6)))
        chosen_max_tokens = max(256, int(chosen_max_tokens * shrink_ratio))
        est_cost = estimate_call_cost(chosen_model, input_tokens, chosen_max_tokens + chosen_thinking_tokens)

    if est_cost > soft_remaining and chosen_model == model_opus:
        chosen_model = model_sonnet
        chosen_use_thinking = False
        chosen_thinking_tokens = 0
        est_cost = estimate_call_cost(chosen_model, input_tokens, chosen_max_tokens)

    if est_cost > soft_remaining and chosen_model == model_sonnet and guard.get("conservative", False):
        chosen_model = model_haiku
        chosen_use_thinking = False
        chosen_thinking_tokens = 0
        chosen_max_tokens = max(256, min(chosen_max_tokens, 1200))
        est_cost = estimate_call_cost(chosen_model, input_tokens, chosen_max_tokens)

    if (remaining <= 0.0) or (soft_remaining <= 0.0 and guard.get("conservative", False)):
        return {
            "allowed": False,
            "reason": "no_remaining_budget",
            "model": chosen_model,
            "max_tokens": chosen_max_tokens,
            "use_thinking": chosen_use_thinking,
            "thinking_tokens": chosen_thinking_tokens,
            "estimated_cost": est_cost,
            "input_tokens": input_tokens,
        }

    hard_cap = max(0.0, remaining * 0.95)
    if est_cost > hard_cap:
        return {
            "allowed": False,
            "reason": "estimated_call_exceeds_budget",
            "model": chosen_model,
            "max_tokens": chosen_max_tokens,
            "use_thinking": chosen_use_thinking,
            "thinking_tokens": chosen_thinking_tokens,
            "estimated_cost": est_cost,
            "input_tokens": input_tokens,
        }

    return {
        "allowed": True,
        "reason": "ok",
        "model": chosen_model,
        "max_tokens": chosen_max_tokens,
        "use_thinking": chosen_use_thinking,
        "thinking_tokens": chosen_thinking_tokens,
        "estimated_cost": est_cost,
        "input_tokens": input_tokens,
    }


def record_credit_usage(
    guard: dict[str, Any],
    model: str,
    usage: Any,
    estimate_call_cost: Callable[[str, int, int], float],
    fallback_estimated_cost: float = 0.0,
) -> float:
    if not guard.get("enabled", False):
        return 0.0
    actual_cost = 0.0
    try:
        in_tok = int(getattr(usage, "input_tokens", 0) or 0)
        out_tok = int(getattr(usage, "output_tokens", 0) or 0)
        if in_tok > 0 or out_tok > 0:
            actual_cost = estimate_call_cost(model, in_tok, out_tok)
        else:
            actual_cost = max(0.0, float(fallback_estimated_cost))
    except Exception:
        actual_cost = max(0.0, float(fallback_estimated_cost))

    lock = guard.get("lock")
    if lock:
        with lock:
            guard["spent_usd"] = round(float(guard.get("spent_usd", 0.0)) + actual_cost, 6)
            guard["calls"] = int(guard.get("calls", 0)) + 1
    else:
        guard["spent_usd"] = round(float(guard.get("spent_usd", 0.0)) + actual_cost, 6)
        guard["calls"] = int(guard.get("calls", 0)) + 1
    return actual_cost
