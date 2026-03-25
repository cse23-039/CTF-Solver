"""Enhanced failure analyzer with Haiku LLM classification fallback.

Enhancement 10: When regex classification returns 'unknown', sends the output
to Haiku for classification. Dramatically expands the failure taxonomy beyond
the 6 hard-coded regex patterns.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

_MODEL_HAIKU = "claude-haiku-4-5-20251001"

_FAILURE_CLASS_LIBRARY = {
    "crash_sigsegv":        {"transforms": ["stack_align", "offset_recompute", "gadget_swap"],                      "priority": 0.95},
    "stack_canary":         {"transforms": ["canary_leak_phase", "partial_overwrite", "io_sync_before_overwrite"],  "priority": 0.90},
    "io_desync":            {"transforms": ["recvuntil_sync", "line_discipline", "stateful_prompt_map"],            "priority": 0.82},
    "timeout":              {"transforms": ["reduce_waits", "incremental_probe", "retry_with_backoff"],             "priority": 0.78},
    "exploit_runtime_error":{"transforms": ["guard_none_unpack", "type_assertions", "fallback_parse"],             "priority": 0.74},
    "null_dereference":     {"transforms": ["guard_null_ptr", "validate_address", "add_precondition_check"],       "priority": 0.80},
    "integer_overflow":     {"transforms": ["check_arithmetic_bounds", "use_safe_add", "mask_result"],             "priority": 0.75},
    "format_string_crash":  {"transforms": ["sanitize_format_arg", "trace_printf_args", "align_arg_count"],        "priority": 0.78},
    "heap_corruption":      {"transforms": ["fix_chunk_alignment", "add_heap_trace", "use_safe_free"],             "priority": 0.88},
    "authentication_failure":{"transforms": ["rotate_credentials", "try_default_creds", "inspect_auth_flow"],     "priority": 0.65},
    "network_refused":      {"transforms": ["check_port", "retry_with_backoff", "verify_host"],                    "priority": 0.60},
    "import_error":         {"transforms": ["install_missing_dep", "use_stdlib_alternative", "mock_import"],       "priority": 0.55},
    "decode_error":         {"transforms": ["try_alternate_encoding", "strip_bom", "handle_partial_data"],         "priority": 0.65},
    "unknown":              {"transforms": ["increase_logging", "trace_io", "minimal_repro_case"],                 "priority": 0.50},
}

_HAIKU_CLASSIFY_SYSTEM = """You are a CTF exploit failure classifier.
Respond ONLY with JSON, no prose, no markdown fences:
{
  "signature": "crash_sigsegv|stack_canary|io_desync|timeout|exploit_runtime_error|null_dereference|integer_overflow|format_string_crash|heap_corruption|authentication_failure|network_refused|import_error|decode_error|unknown",
  "hints": ["hint1", "hint2"],
  "recommended_transforms": ["transform1"],
  "root_cause": "one sentence",
  "confidence": 0.0
}"""


def _regex_classify(output: str) -> str:
    low = (output or "").lower()
    if "segmentation fault" in low or "sigsegv" in low:      return "crash_sigsegv"
    if "stack smashing" in low or "canary" in low:           return "stack_canary"
    if "timeout" in low or "timed out" in low:               return "timeout"
    if "connection reset" in low or "broken pipe" in low:    return "io_desync"
    if "traceback" in low or "syntaxerror" in low:           return "exploit_runtime_error"
    if "null pointer" in low or "nullpointer" in low:        return "null_dereference"
    if "heap" in low and ("corrupted" in low or "double free" in low): return "heap_corruption"
    if "modulenotfounderror" in low or "importerror" in low: return "import_error"
    if "unicodedecode" in low or "invalid byte" in low:      return "decode_error"
    if "connection refused" in low:                          return "network_refused"
    if "401" in output or "unauthorized" in low:             return "authentication_failure"
    return "unknown"


def _llm_classify(output: str, return_code: int, api_key: str = "") -> dict[str, Any]:
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        user_msg = f"Return code: {return_code}\n\nOutput:\n{str(output)[-1000:]}"
        resp = client.messages.create(
            model=_MODEL_HAIKU, max_tokens=300, system=_HAIKU_CLASSIFY_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = (resp.content[0].text if resp.content else "{}").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        return json.loads(raw)
    except Exception:
        return {}


def _extract_memory_snapshot(output: str) -> dict[str, str]:
    mem = {}
    for m in re.finditer(r"\b(mem|memory)\[(0x[0-9a-fA-F]+)\]\s*[:=]\s*(0x[0-9a-fA-F]+)", output or ""):
        mem[m.group(2)] = m.group(3)
    for m in re.finditer(r"\b(0x[0-9a-fA-F]+)\s*:\s*(0x[0-9a-fA-F]+)", output or ""):
        if len(mem) >= 64: break
        mem[m.group(1)] = m.group(2)
    return mem


def _compute_reg_deltas(register_snapshot: dict[str, str], previous_snapshot: dict[str, str] | None = None) -> dict[str, str]:
    if not previous_snapshot: return {}
    return {reg: f"{previous_snapshot[reg]}->{cur}" for reg, cur in register_snapshot.items()
            if reg in previous_snapshot and previous_snapshot[reg] != cur}


def analyze(output: str, return_code: int = 0,
            previous_register_snapshot: dict[str, str] | None = None,
            previous_memory_snapshot: dict[str, str] | None = None,
            api_key: str = "") -> dict[str, Any]:
    signature = _regex_classify(output)
    hints: list[str] = []
    llm_result: dict[str, Any] = {}

    if signature == "crash_sigsegv":    hints += ["likely bad pointer or offset", "re-check cyclic offset and stack alignment"]
    elif signature == "stack_canary":   hints += ["leak canary first", "avoid clobbering canary on overflow path"]
    elif signature == "timeout":        hints += ["add shorter I/O waits", "verify prompt synchronization"]
    elif signature == "io_desync":      hints += ["protocol framing mismatch", "re-check newline/null terminators"]
    elif signature == "exploit_runtime_error": hints += ["patch script syntax/runtime errors", "guard missing values before unpack"]
    elif signature == "unknown":
        llm_result = _llm_classify(output, return_code, api_key=api_key)
        if llm_result.get("signature") and llm_result["signature"] != "unknown":
            signature = llm_result["signature"]
            hints = llm_result.get("hints", [])

    reg_delta: dict[str, str] = {}
    for reg in ["rip", "eip", "rsp", "rbp", "rax", "rcx", "rdx"]:
        m = re.search(rf"\b{reg}\s*[:=]\s*(0x[0-9a-fA-F]+)", output or "")
        if m: reg_delta[reg] = m.group(1)

    mem_snapshot = _extract_memory_snapshot(output)
    reg_deltas = _compute_reg_deltas(reg_delta, previous_register_snapshot)
    mem_deltas = {}
    if previous_memory_snapshot:
        for addr, cur in mem_snapshot.items():
            prev = previous_memory_snapshot.get(addr)
            if prev and prev != cur: mem_deltas[addr] = f"{prev}->{cur}"

    failure_class = _FAILURE_CLASS_LIBRARY.get(signature, _FAILURE_CLASS_LIBRARY["unknown"])
    recommended_transforms = (llm_result.get("recommended_transforms") or failure_class.get("transforms", []))

    return {
        "signature": signature,
        "return_code": int(return_code),
        "hints": hints,
        "register_snapshot": reg_delta,
        "memory_snapshot": mem_snapshot,
        "register_deltas": reg_deltas,
        "memory_deltas": mem_deltas,
        "failure_class": signature,
        "recommended_transforms": recommended_transforms,
        "llm_root_cause": llm_result.get("root_cause", ""),
        "llm_confidence": float(llm_result.get("confidence", 0.0)),
    }


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    if isinstance(input_data, dict):
        out = str(input_data.get("output", ""))
        rc = int(input_data.get("return_code", 0))
    else:
        out = str(kwargs.get("output", ""))
        rc = int(kwargs.get("return_code", 0))
    return analyze(out, rc,
                   previous_register_snapshot=kwargs.get("previous_register_snapshot"),
                   previous_memory_snapshot=kwargs.get("previous_memory_snapshot"),
                   api_key=kwargs.get("api_key", ""))
