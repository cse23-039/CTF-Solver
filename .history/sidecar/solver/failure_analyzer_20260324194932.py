"""Failure analysis for exploit telemetry and refinement hints."""
from __future__ import annotations

import re
from typing import Any


def analyze(output: str, return_code: int = 0) -> dict[str, Any]:
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

    return {
        "signature": signature,
        "return_code": int(return_code),
        "hints": hints,
        "register_snapshot": reg_delta,
    }


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    if isinstance(input_data, dict):
        out = str(input_data.get("output", ""))
        rc = int(input_data.get("return_code", 0))
    else:
        out = str(kwargs.get("output", ""))
        rc = int(kwargs.get("return_code", 0))
    return analyze(out, rc)
