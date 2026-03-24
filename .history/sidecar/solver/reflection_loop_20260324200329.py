"""Closed-loop exploit reflection: execute -> analyze -> refine -> retry."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any

from .failure_analyzer import analyze as analyze_failure
from .tool_feedback_model import _MODEL


def _execute_python(script: str, timeout_s: int = 12) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(script)
        path = f.name
    try:
        proc = subprocess.run(
            ["python", path],
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_s)),
            encoding="utf-8",
            errors="replace",
        )
        out = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if (proc.stderr or "").strip() else "")
        return int(proc.returncode), out
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n[stderr]\nTimed out"
        return 124, out
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def refine_script(script: str, failure_signature: str) -> str:
    patch = ""
    if failure_signature == "io_desync":
        patch = "\n# refinement: stronger prompt sync\nio.recvuntil(b':', timeout=2)\n"
    elif failure_signature == "timeout":
        patch = "\n# refinement: reduce blocking waits\ncontext.timeout = 2\n"
    elif failure_signature == "crash_sigsegv":
        patch = "\n# refinement: align stack before final call\n# payload += p64(ret_gadget)\n"
    elif failure_signature == "stack_canary":
        patch = "\n# refinement: add canary leak phase before overwrite\n"
    else:
        patch = "\n# refinement: add guard checks and verbose diagnostics\n"
    return script + patch


def refine_script_with_transforms(script: str, transforms: list[str]) -> str:
    patched = script
    for t in transforms:
        if t == "stack_align":
            patched += "\n# transform: stack_align\n# payload += p64(ret_gadget)\n"
        elif t == "offset_recompute":
            patched += "\n# transform: offset_recompute\n# use cyclic_find() with fresh crash value\n"
        elif t == "gadget_swap":
            patched += "\n# transform: gadget_swap\n# try alternative pop gadget sequence\n"
        elif t == "canary_leak_phase":
            patched += "\n# transform: canary_leak_phase\n# stage 1 leak then stage 2 overwrite\n"
        elif t == "recvuntil_sync":
            patched += "\n# transform: recvuntil_sync\nio.recvuntil(b':', timeout=2)\n"
        elif t == "line_discipline":
            patched += "\n# transform: line_discipline\nio.sendline(payload)\n"
        elif t == "reduce_waits":
            patched += "\n# transform: reduce_waits\ncontext.timeout = 2\n"
        elif t == "trace_io":
            patched += "\n# transform: trace_io\ncontext.log_level = 'debug'\n"
        elif t == "guard_none_unpack":
            patched += "\n# transform: guard_none_unpack\nassert leaked is not None\n"
        else:
            patched += f"\n# transform: {t}\n"
    return patched


def autonomous_exploit_loop(initial_script: str, rounds: int = 5, timeout_s: int = 12) -> dict[str, Any]:
    script = initial_script
    history = []
    prev_regs = None
    prev_mem = None
    for idx in range(1, max(1, int(rounds)) + 1):
        rc, out = _execute_python(script, timeout_s=timeout_s)
        analysis = analyze_failure(
            out,
            rc,
            previous_register_snapshot=prev_regs,
            previous_memory_snapshot=prev_mem,
        )
        prev_regs = analysis.get("register_snapshot") or prev_regs
        prev_mem = analysis.get("memory_snapshot") or prev_mem
        success = (rc == 0) and ("flag{" in out.lower() or "ctf{" in out.lower() or "picoctf{" in out.lower())
        conf = _MODEL.update("auto_exploit_loop", success)
        step = {
            "round": idx,
            "return_code": rc,
            "signature": analysis.get("signature"),
            "hints": analysis.get("hints", []),
            "register_deltas": analysis.get("register_deltas", {}),
            "memory_deltas": analysis.get("memory_deltas", {}),
            "transforms": analysis.get("recommended_transforms", []),
            "posterior_confidence": round(conf, 6),
        }
        history.append(step)
        if success:
            return {"status": "solved", "history": history, "final_script": script, "output_excerpt": out[:2000]}
        transforms = analysis.get("recommended_transforms", [])
        if transforms:
            script = refine_script_with_transforms(script, transforms)
        else:
            script = refine_script(script, analysis.get("signature", "unknown"))
    return {"status": "exhausted", "history": history, "final_script": script}


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    script = str(kwargs.get("script", input_data if isinstance(input_data, str) else ""))
    return autonomous_exploit_loop(script, rounds=int(kwargs.get("rounds", 5)), timeout_s=int(kwargs.get("timeout_s", 12)))
