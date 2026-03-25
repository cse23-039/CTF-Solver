"""Shell execution and basic I/O helpers (WSL-aware)."""
from __future__ import annotations
import sys, json, subprocess, io, contextlib, traceback, platform as _platform, shutil

IS_WINDOWS = _platform.system() == "Windows"
USE_WSL: bool  # set after _wsl_ok() call below



def _wsl_ok():
    if not IS_WINDOWS or not shutil.which("wsl"): return False
    try:
        r = subprocess.run(["wsl","--list","--quiet"], capture_output=True,
                           text=True, encoding="utf-16-le", timeout=5)
        return r.returncode == 0 and bool(r.stdout.strip())
    except: return False


def _w2l(p):
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:].replace(chr(92),'/')}"
    return p.replace("\\","/")


def emit(t, **kw): kw["type"]=t; print(json.dumps(kw,ensure_ascii=False),flush=True)


def log(tag,msg,cls=""): emit("log",tag=tag,msg=str(msg),cls=cls)


def result(status,flag=None,workspace=None):
    emit("result",status=status,flag=flag,workspace=workspace)


def _shell(cmd, timeout=60, env=None):
    if IS_WINDOWS and USE_WSL:
        safe = cmd.replace("'","'\\''")
        args = ["wsl","bash","-c",safe]
    elif IS_WINDOWS:
        args = cmd; cmd = None
    else:
        args = ["bash", "-c", cmd]

    try:
        p = subprocess.run(
            args, shell=(cmd is not None), capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env
        )
        out = p.stdout + ("\n[stderr]\n"+p.stderr if p.stderr.strip() else "")
        out = out.strip() or f"(exit {p.returncode}, no output)"
        return out[:8000] if len(out)<=8000 else out[:4000]+"\n...[truncated]...\n"+out[-3000:]
    except subprocess.TimeoutExpired: return f"Timed out after {timeout}s"
    except Exception as e: return f"Shell error: {e}"


def tool_execute_shell(command, timeout=60, working_dir=None):
    prefix = "[WSL] " if IS_WINDOWS and USE_WSL else "[cmd] " if IS_WINDOWS else ""
    log("sys", f"{prefix}$ {command}", "dim")
    if working_dir:
        command = f"cd '{working_dir}' && {command}"
    return _shell(command, timeout=timeout)


def tool_execute_python(code, timeout=60):
    log("sys", "Running Python snippet...", "dim")
    buf_o, buf_e = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_o), contextlib.redirect_stderr(buf_e):
            exec(compile(code,"<solver>","exec"), {"__builtins__":__builtins__}, {})
        out = buf_o.getvalue()
        err = buf_e.getvalue()
        full = (out + ("\n[stderr]\n"+err if err.strip() else "")).strip()
        return full or "(executed — no output)"
    except Exception as ex:
        return f"{type(ex).__name__}: {ex}\n{traceback.format_exc()}\n{buf_e.getvalue()}".strip()


USE_WSL = _wsl_ok()

