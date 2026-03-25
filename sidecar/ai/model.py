"""Model selection and routing."""
from __future__ import annotations


def _extract_text_for_token_estimation(value, max_chars: int = 24_000, depth: int = 0) -> str:
    if value is None or max_chars <= 0 or depth > 8:
        return ""

    if isinstance(value, str):
        return value[:max_chars]
    if isinstance(value, (int, float, bool)):
        return str(value)[:max_chars]

    if isinstance(value, dict):
        parts = []
        used = 0
        # Prioritize likely high-signal keys for faster/cheaper estimates.
        priority_keys = ("role", "content", "text", "thinking", "output", "tool", "name")
        seen = set()
        ordered_items = []
        for key in priority_keys:
            if key in value:
                ordered_items.append((key, value.get(key)))
                seen.add(key)
        for key, val in value.items():
            if key not in seen:
                ordered_items.append((key, val))

        for _, item in ordered_items:
            remaining = max_chars - used
            if remaining <= 0:
                break
            chunk = _extract_text_for_token_estimation(item, max_chars=remaining, depth=depth + 1)
            if chunk:
                parts.append(chunk)
                used += len(chunk) + 1
        return "\n".join(parts)[:max_chars]

    if isinstance(value, list):
        parts = []
        used = 0
        # Favor the most recent content for iterative loop calls.
        items = value[-24:] if len(value) > 24 else value
        for item in items:
            remaining = max_chars - used
            if remaining <= 0:
                break
            chunk = _extract_text_for_token_estimation(item, max_chars=remaining, depth=depth + 1)
            if chunk:
                parts.append(chunk)
                used += len(chunk) + 1
        return "\n".join(parts)[:max_chars]

    try:
        return json.dumps(value, ensure_ascii=False)[:max_chars]
    except Exception:
        return str(value)[:max_chars]


def _estimate_tokens_from_text(text: str) -> int:
    if not text:
        return 0
    # Conservative estimate: ~3.5 chars/token + fixed request overhead
    return int(max(1, math.ceil(len(text) / 3.5)))


def _estimate_input_tokens(messages, system: str = "") -> int:
    msg_tail = messages[-18:] if isinstance(messages, list) and len(messages) > 18 else messages
    total_text = _extract_text_for_token_estimation(msg_tail, max_chars=20_000)
    if system:
        total_text += "\n" + str(system)[-4_000:]
    return _estimate_tokens_from_text(total_text) + 120


def _estimate_call_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    pricing = _MODEL_PRICING_USD_PER_MTOK.get(model, _MODEL_PRICING_USD_PER_MTOK[_MODEL_SONNET])
    in_cost = (max(0, int(input_tokens)) / 1_000_000.0) * float(pricing["input"])
    out_cost = (max(0, int(output_tokens)) / 1_000_000.0) * float(pricing["output"])
    return round(in_cost + out_cost, 6)


def _init_credit_guard(extra: dict, challenge: dict, max_iterations: int) -> dict:
    return core_budget.init_credit_guard(extra, challenge, max_iterations)


def _credit_remaining_usd(guard: dict) -> float:
    return core_budget.credit_remaining_usd(guard)


def _credit_is_low(guard: dict) -> bool:
    return core_budget.credit_is_low(guard)


def _mark_low_credit_alert_once(guard: dict) -> bool:
    return core_budget.mark_low_credit_alert_once(guard)


def _plan_budgeted_call(guard: dict, model: str, requested_max_tokens: int,
                        messages, system: str, use_thinking: bool,
                        thinking_tokens: int) -> dict:
    return core_budget.plan_budgeted_call(
        guard=guard,
        model=model,
        requested_max_tokens=requested_max_tokens,
        messages=messages,
        system=system,
        use_thinking=use_thinking,
        thinking_tokens=thinking_tokens,
        estimate_input_tokens=lambda m, s: _TOKEN_CACHE.estimate(m, s, _estimate_input_tokens),
        estimate_call_cost=_estimate_call_cost_usd,
        model_opus=_MODEL_OPUS,
        model_sonnet=_MODEL_SONNET,
        model_haiku=_MODEL_HAIKU,
    )


def _record_credit_usage(guard: dict, model: str, usage, fallback_estimated_cost: float = 0.0) -> float:
    return core_budget.record_credit_usage(
        guard=guard,
        model=model,
        usage=usage,
        estimate_call_cost=_estimate_call_cost_usd,
        fallback_estimated_cost=fallback_estimated_cost,
    )


def _select_model(category: str, difficulty: str, iteration: int,
                  total_iters: int, user_model: str) -> tuple[str, bool, int]:
    """
    Multi-model routing:
    - Returns (model_id, use_extended_thinking, thinking_tokens)
    - Uses Opus + extended thinking for hard crypto/rev on fresh iterations
    - Falls back to Sonnet for most solving
    - Uses Haiku for triage/critic (called separately, not here)
    """
    hard_categories = {"Cryptography", "Reverse Engineering"}
    use_thinking = False
    thinking_tokens = 0

    # Honor explicit user model choice
    if user_model not in (_MODEL_SONNET, _MODEL_OPUS, _MODEL_HAIKU, ""):
        return user_model, False, 0

    # Opus + extended thinking for hard math/crypto/rev challenges
    if (category in hard_categories and
        difficulty in ("hard", "insane") and
        iteration <= total_iters // 2):
        model = _MODEL_OPUS
        use_thinking = True
        thinking_tokens = 8000 if difficulty == "hard" else 12000
        return model, use_thinking, thinking_tokens

    # Opus for insane challenges in any category (first half)
    if difficulty == "insane" and iteration <= total_iters // 3:
        model = _MODEL_OPUS
        use_thinking = True
        thinking_tokens = 10000
        return model, use_thinking, thinking_tokens

    # Default: Sonnet for everything else
    return _MODEL_SONNET, False, 0


def _route_model_v2(category: str, difficulty: str, iteration: int, total_iters: int,
                    user_model: str, fruitless: int, tool_failures: int,
                    progress_gap: int, opus_budget_remaining: int,
                    memory_hits_count: int = 0,
                    learned_overrides: dict | None = None,
                    state_vector: dict | None = None) -> dict:
    return core_routing.route_model_v2(
        category=category,
        difficulty=difficulty,
        iteration=iteration,
        total_iters=total_iters,
        user_model=user_model,
        fruitless=fruitless,
        tool_failures=tool_failures,
        progress_gap=progress_gap,
        opus_budget_remaining=opus_budget_remaining,
        model_sonnet=_MODEL_SONNET,
        model_opus=_MODEL_OPUS,
        model_haiku=_MODEL_HAIKU,
        memory_hits_count=memory_hits_count,
        learned_overrides=learned_overrides,
        state_vector=state_vector,
    )

