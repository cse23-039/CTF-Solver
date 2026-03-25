"""Closed-loop exploit reflection: execute -> analyze -> refine -> retry."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import tempfile
from typing import Any

from .failure_analyzer import analyze as analyze_failure
from .tool_feedback_model import _MODEL


_FLAG_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9_]{1,12}\{[A-Za-z0-9_!@#$%^&*()\-+=.<>?/\\, ]{4,120}\}",
    re.IGNORECASE,
)


def _contains_flag(output: str) -> bool:
    quick_prefixes = (
        "flag{", "ctf{", "picoctf{", "htb{", "ductf{", "thm{",
        "wgmy{", "lactf{", "crew{", "grey{", "uoftctf{",
    )
    low = str(output or "").lower()
    for prefix in quick_prefixes:
        if prefix in low:
            return True
    return bool(_FLAG_RE.search(str(output or "")))


def _patch_memory_path() -> str:
    return os.path.expanduser("~/.ctf-solver/patch_memory.json")


def _load_patch_memory() -> dict[str, list[str]]:
    path = _patch_memory_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): list(v) for k, v in data.items() if isinstance(v, list)}
        except Exception:
            return {}
    return {}


def _save_patch_memory(mem: dict[str, list[str]]) -> None:
    path = _patch_memory_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)


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
        patched = _ast_patch(patched, t)
    return patched


def _ast_patch(script: str, transform: str) -> str:
    try:
        tree = ast.parse(script)
    except Exception:
        return script

    lines = script.splitlines()
    line_count = len(lines)
    insertions: list[tuple[int, str]] = []

    # Build executable patches tied to common exploit variable names.
    if transform == "trace_io":
        insertions.append((0, "context.log_level = 'debug'"))
    elif transform == "reduce_waits":
        insertions.append((0, "context.timeout = 2"))
    elif transform == "guard_none_unpack":
        for i, line in enumerate(lines):
            if "=" in line and "leak" in line.lower() and "recv" in line.lower():
                indent = line[: len(line) - len(line.lstrip())]
                insertions.append((i + 1, indent + "if leaked is None:") )
                insertions.append((i + 2, indent + "    raise RuntimeError('leak returned None')"))
                break
    elif transform == "recvuntil_sync":
        for i, line in enumerate(lines):
            if ".send(" in line or ".sendline(" in line:
                indent = line[: len(line) - len(line.lstrip())]
                if "recvuntil" not in line:
                    insertions.append((i, indent + "io.recvuntil(b':', timeout=2)"))
                break
    elif transform == "line_discipline":
        for i, line in enumerate(lines):
            if ".send(" in line and ".sendline(" not in line:
                lines[i] = line.replace(".send(", ".sendline(")
    elif transform == "stack_align":
        insertions.append((line_count, "if 'payload' in locals() and 'p64' in globals() and 'ret_gadget' in locals():"))
        insertions.append((line_count + 1, "    payload += p64(ret_gadget)"))
    elif transform == "offset_recompute":
        insertions.append((line_count, "if 'cyclic_find' in globals() and 'crash_value' in locals():"))
        insertions.append((line_count + 1, "    offset = cyclic_find(crash_value)"))
    elif transform == "gadget_swap":
        insertions.append((line_count, "if 'alt_pop_rdi' in locals() and 'pop_rdi' in locals():"))
        insertions.append((line_count + 1, "    pop_rdi = alt_pop_rdi"))
    elif transform == "canary_leak_phase":
        insertions.append((line_count, "if 'canary' not in locals() and 'leak_canary' in globals():"))
        insertions.append((line_count + 1, "    canary = leak_canary()"))
    else:
        return script

    for idx, text in sorted(insertions, key=lambda x: x[0], reverse=True):
        safe_idx = max(0, min(len(lines), idx))
        lines.insert(safe_idx, text)

    patched = "\n".join(lines)
    try:
        ast.parse(patched)
        return patched
    except Exception:
        # Never emit a broken exploit script into the loop.
        try:
            ast.parse(script)
        except Exception:
            return script
        return script


def autonomous_exploit_loop(initial_script: str, rounds: int = 5, timeout_s: int = 12) -> dict[str, Any]:
    script = initial_script
    history = []
    patch_mem = _load_patch_memory()
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
        success = (rc == 0) and _contains_flag(out)
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
            sig = str(analysis.get("signature", "unknown"))
            transforms = analysis.get("recommended_transforms", [])
            if sig:
                existing = patch_mem.get(sig, [])
                if transforms:
                    patch_mem[sig] = list(dict.fromkeys((existing + transforms)[-12:]))
                    _save_patch_memory(patch_mem)
            return {"status": "solved", "history": history, "final_script": script, "output_excerpt": out[:2000]}
        transforms = analysis.get("recommended_transforms", [])
        sig = str(analysis.get("signature", "unknown"))
        if not transforms and sig in patch_mem:
            transforms = patch_mem.get(sig, [])
        if transforms:
            prior_script = script
            script = refine_script_with_transforms(script, transforms)
            # Re-run immediately so transforms have real effect in the same reflection round.
            if script != prior_script:
                rc2, out2 = _execute_python(script, timeout_s=timeout_s)
                step["post_patch_return_code"] = int(rc2)
                step["post_patch_output_excerpt"] = str(out2)[:1200]
                if (rc2 == 0) and _contains_flag(out2):
                    return {"status": "solved", "history": history, "final_script": script, "output_excerpt": out2[:2000]}
        else:
            script = refine_script(script, analysis.get("signature", "unknown"))
    return {"status": "exhausted", "history": history, "final_script": script}


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    script = str(kwargs.get("script", input_data if isinstance(input_data, str) else ""))
    return autonomous_exploit_loop(script, rounds=int(kwargs.get("rounds", 5)), timeout_s=int(kwargs.get("timeout_s", 12)))
