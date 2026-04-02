"""Shell execution and basic I/O helpers (WSL-aware)."""
from __future__ import annotations
import sys, os, json, subprocess, platform as _platform, shutil

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

IS_WINDOWS = _platform.system() == "Windows"
USE_WSL = False



def _wsl_ok():
    if not IS_WINDOWS or not shutil.which("wsl"): return False
    encodings = ["utf-8", "utf-16-le", None]
    for enc in encodings:
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "errors": "replace",
                "timeout": 5,
            }
            if enc is not None:
                kwargs["encoding"] = enc
            r = subprocess.run(["wsl", "--list", "--quiet"], **kwargs)
            if r.returncode == 0:
                return bool((r.stdout or "").strip())
        except Exception:
            continue
    return False


def _w2l(p):
    raw = str(p or "")
    if raw.startswith("\\\\"):
        unc = raw.lstrip("\\").replace("\\", "/")
        return f"/mnt/unc/{unc}"
    if len(raw) >= 2 and raw[1] == ":":
        drive = raw[0].lower()
        tail = raw[2:].replace("\\", "/")
        if not tail:
            tail = "/"
        elif not tail.startswith("/"):
            tail = "/" + tail
        return f"/mnt/{drive}{tail}"
    return raw.replace("\\", "/")


def emit(t, **kw):
    kw["type"] = t
    try:
        print(json.dumps(kw, ensure_ascii=False), flush=True)
    except UnicodeEncodeError:
        print(json.dumps(kw, ensure_ascii=True), flush=True)


def log(tag,msg,cls=""): emit("log",tag=tag,msg=str(msg),cls=cls)


def result(status,flag=None,workspace=None):
    emit("result",status=status,flag=flag,workspace=workspace)


def _shell(cmd, timeout=60, env=None):
    if IS_WINDOWS and USE_WSL:
        safe = cmd.replace("'","'\\''")
        args = ["wsl","bash","-c",safe]
        use_shell = False
    elif IS_WINDOWS:
        args = cmd
        use_shell = True
    else:
        args = ["bash", "-c", cmd]
        use_shell = False

    try:
        p = subprocess.run(
            args, shell=use_shell, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env
        )
        stdout = p.stdout or ""
        stderr = p.stderr or ""
        out = stdout + ("\n[stderr]\n" + stderr if stderr.strip() else "")
        out = out.strip() or f"(exit {p.returncode}, no output)"
        if len(out) <= 8000:
            return out
        if stderr.strip():
            stderr_tail = stderr[-2500:]
            stdout_budget = max(600, 8000 - len(stderr_tail) - len("\n...[truncated]...\n\n[stderr]\n"))
            return (stdout[:stdout_budget] + "\n...[truncated]...\n\n[stderr]\n" + stderr_tail).strip()
        return (out[:4200] + "\n...[truncated]...\n" + out[-3400:]).strip()
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
    # Full-access execution: CTF solvers need pwntools, z3, pycryptodome, sympy, etc.
    # The old sandboxed approach broke all imports, defeating the solver's purpose.
    wrapper = r'''
import sys, io, contextlib, traceback

code = sys.stdin.read()
buf_o, buf_e = io.StringIO(), io.StringIO()
try:
    with contextlib.redirect_stdout(buf_o), contextlib.redirect_stderr(buf_e):
        exec(compile(code, "<solver>", "exec"), {"__name__": "__main__"})
    out = buf_o.getvalue()
    err = buf_e.getvalue()
    full = (out + ("\n[stderr]\n" + err if err.strip() else "")).strip()
    print(full or "(executed \u2014 no output)")
except BaseException as ex:
    print(f"{type(ex).__name__}: {ex}\n{traceback.format_exc()}\n{buf_e.getvalue()}".strip())
'''

    try:
        p = subprocess.run(
            [sys.executable, "-c", wrapper],
            input=str(code or ""),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout or 60)),
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"},
        )
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if err:
            out = (out + "\n[stderr]\n" + err).strip()
        return out or "(executed \u2014 no output)"
    except subprocess.TimeoutExpired:
        return f"Timed out after {timeout}s"
    except Exception as ex:
        return f"Python execution error: {type(ex).__name__}: {ex}"


USE_WSL = _wsl_ok()

