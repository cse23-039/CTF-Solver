"""Failure analysis for exploit telemetry and refinement hints."""
from __future__ import annotations

import re
from typing import Any


_FAILURE_CLASS_LIBRARY = {
    "crash_sigsegv": {
        "transforms": ["stack_align", "offset_recompute", "gadget_swap"],
        "priority": 0.95,
    },
    "stack_canary": {
        "transforms": ["canary_leak_phase", "partial_overwrite", "io_sync_before_overwrite"],
        "priority": 0.9,
    },
    "io_desync": {
        "transforms": ["recvuntil_sync", "line_discipline", "stateful_prompt_map"],
        "priority": 0.82,
    },
    "timeout": {
        "transforms": ["reduce_waits", "incremental_probe", "retry_with_backoff"],
        "priority": 0.78,
    },
    "exploit_runtime_error": {
        "transforms": ["guard_none_unpack", "type_assertions", "fallback_parse"],
        "priority": 0.74,
    },
    "unknown": {
        "transforms": ["increase_logging", "trace_io", "minimal_repro_case"],
        "priority": 0.5,
    },
}


def _extract_memory_snapshot(output: str) -> dict[str, str]:
    mem = {}
    # Common debugger-style patterns.
    for m in re.finditer(r"\b(mem|memory)\[(0x[0-9a-fA-F]+)\]\s*[:=]\s*(0x[0-9a-fA-F]+)", output or ""):
        mem[m.group(2)] = m.group(3)
    for m in re.finditer(r"\b(0x[0-9a-fA-F]+)\s*:\s*(0x[0-9a-fA-F]+)", output or ""):
        if len(mem) >= 64:
            break
        mem[m.group(1)] = m.group(2)
    return mem


def _compute_reg_deltas(register_snapshot: dict[str, str], previous_snapshot: dict[str, str] | None = None) -> dict[str, str]:
    if not previous_snapshot:
        return {}
    deltas = {}
    for reg, cur in register_snapshot.items():
        prev = previous_snapshot.get(reg)
        if prev and prev != cur:
            deltas[reg] = f"{prev}->{cur}"
    return deltas


def analyze(output: str, return_code: int = 0,
            previous_register_snapshot: dict[str, str] | None = None,
            previous_memory_snapshot: dict[str, str] | None = None) -> dict[str, Any]:
    low = (output or "").lower()
    signature = "unknown"
    hints: list[str] = []

    if "segmentation fault" in low or "sigsegv" in low:
        signature = "crash_sigsegv"
        hints += ["likely bad pointer or offset", "re-check cyclic offset and stack alignment"]
    elif "stack smashing" in low or "canary" in low:
        signature = "stack_canary"
        hints += ["leak canary first", "avoid clobbering canary on overflow path"]
    elif "timeout" in low or "timed out" in low:
        signature = "timeout"
        hints += ["add shorter I/O waits", "verify prompt synchronization"]
    elif "connection reset" in low or "broken pipe" in low:
        signature = "io_desync"
        hints += ["protocol framing mismatch", "re-check newline/null terminators"]
    elif "traceback" in low:
        signature = "exploit_runtime_error"
        hints += ["patch script syntax/runtime errors", "guard missing values before unpack"]

    reg_delta = {}
    for reg in ["rip", "eip", "rsp", "rbp", "rax", "rcx", "rdx"]:
        m = re.search(rf"\b{reg}\s*[:=]\s*(0x[0-9a-fA-F]+)", output or "")
        if m:
            reg_delta[reg] = m.group(1)

    mem_snapshot = _extract_memory_snapshot(output)
    reg_deltas = _compute_reg_deltas(reg_delta, previous_register_snapshot)
    mem_deltas = {}
    if previous_memory_snapshot:
        for addr, cur in mem_snapshot.items():
            prev = previous_memory_snapshot.get(addr)
            if prev and prev != cur:
                mem_deltas[addr] = f"{prev}->{cur}"

    failure_class = _FAILURE_CLASS_LIBRARY.get(signature, _FAILURE_CLASS_LIBRARY["unknown"])

    return {
        "signature": signature,
        "return_code": int(return_code),
        "hints": hints,
        "register_snapshot": reg_delta,
        "memory_snapshot": mem_snapshot,
        "register_deltas": reg_deltas,
        "memory_deltas": mem_deltas,
        "failure_class": signature,
        "recommended_transforms": failure_class.get("transforms", []),
    }


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    if isinstance(input_data, dict):
        out = str(input_data.get("output", ""))
        rc = int(input_data.get("return_code", 0))
    else:
        out = str(kwargs.get("output", ""))
        rc = int(kwargs.get("return_code", 0))
    return analyze(
        out,
        rc,
        previous_register_snapshot=kwargs.get("previous_register_snapshot"),
        previous_memory_snapshot=kwargs.get("previous_memory_snapshot"),
    )
