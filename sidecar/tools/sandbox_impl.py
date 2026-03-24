"""Language sandboxes and jail-escape tools."""
from __future__ import annotations
import re, subprocess, os, shutil, tempfile


def tool_docker_sandbox(operation: str, binary_path: str = "", exploit_code: str = "",
                          libc_path: str = "", timeout: int = 30) -> str:
    """Docker-isolated exploit testing: setup, run_exploit, local_test."""
    if operation == "setup":
        return _shell("docker pull ubuntu:22.04 2>&1 | tail -3", timeout=60)
    if operation == "run_exploit":
        if not exploit_code: return "Provide exploit_code (pwntools Python string)"
        ef = f"/tmp/exploit_{int(time.time())}.py"
        with open(ef,"w") as f: f.write(exploit_code)
        bn = os.path.basename(binary_path)
        _shell(f"cp '{binary_path}' /tmp/{bn} 2>/dev/null")
        vols = f"-v /tmp/{bn}:/pwn/{bn}:ro -v {ef}:/pwn/exploit.py:ro"
        if libc_path:
            ln = os.path.basename(libc_path); _shell(f"cp '{libc_path}' /tmp/{ln}")
            vols += f" -v /tmp/{ln}:/pwn/{ln}:ro"
        out = _shell(f"docker run --rm --network=none --memory=256m {vols} --entrypoint python3 ubuntu:22.04 /pwn/exploit.py 2>&1", timeout=timeout+10)
        flag = extract_flag(out)
        return f"{out}\n{'FLAG: '+flag if flag else 'No flag in output'}"
    if operation == "local_test":
        ef = f"/tmp/exploit_{int(time.time())}.py"
        with open(ef,"w") as f: f.write(exploit_code)
        out = _shell(f"timeout {timeout} python3 {ef} 2>&1")
        return out
    return "Available: setup, run_exploit, local_test"


def tool_java_sandbox(source_code: str = "", source_path: str = "",
                       operation: str = "run", class_name: str = "",
                       stdin_input: str = "", timeout: int = 15) -> str:
    """Compile and run Java source code, or reverse-engineer Java check logic.
    Ops: run (javac+java), reverse (extract flag from checkPassword logic),
    decompile (javap -c bytecode), analyze (find flag patterns in source),
    solve (auto-extract flag from char/byte comparison methods)."""

    if operation == "analyze" or (not source_code and not source_path and operation != "decompile"):
        src = source_code or (open(_w2l(source_path) if (IS_WINDOWS and USE_WSL) else source_path).read()
                              if source_path else "")
        if not src:
            return "Provide source_code or source_path"
        code = f"""
import re, ast as pyast

src = {repr(src)}

# Find checkPassword-style method and extract flag chars
results = []

# Pattern 1: password.charAt(N) == 'X'
chars = re.findall(r'charAt\\s*\\(\\s*(\\d+)\\s*\\)\\s*==\\s*[\'\"](.)[\'\"]', src)
if chars:
    max_idx = max(int(i) for i,_ in chars)
    flag = ['?'] * (max_idx + 1)
    for idx, ch in chars:
        flag[int(idx)] = ch
    results.append(f"charAt extraction: {{''.join(flag)}}")

# Pattern 2: byte[] XOR with constant
xor_match = re.search(r'(0x[0-9a-fA-F]+).*byte.*\\[\\].*myBytes|myBytes.*byte.*\\[\\]', src, re.DOTALL)
if xor_match:
    xor_key_m = re.search(r'\\^\\s*(0x[0-9a-fA-F]+|\\d+)', src)
    bytes_m = re.findall(r'(0x[0-9a-fA-F]{{1,2}})', src)
    if xor_key_m and bytes_m:
        key = int(xor_key_m.group(1), 16 if xor_key_m.group(1).startswith('0x') else 10)
        flag = ''.join(chr(int(b, 16) ^ key) for b in bytes_m[:50] if 32 <= (int(b,16)^key) <= 126)
        if len(flag) > 5:
            results.append(f"XOR extraction (key=0x{{key:02x}}): {{flag}}")

# Pattern 3: int[] bit-packed (vault door 7 style)
int_arr = re.findall(r'(\\d{{8,}})\\s*[,}}]', src)
for n in int_arr[:8]:
    val = int(n)
    chars_out = []
    for shift in [24,16,8,0]:
        byte = (val >> shift) & 0xFF
        if 32 <= byte <= 126:
            chars_out.append(chr(byte))
    if len(chars_out) == 4:
        results.append(f"int-packed chars from {{n}}: {{''.join(chars_out)}}")

# Pattern 4: base64/url encoded string at end
b64_m = re.findall(r'["\']([A-Za-z0-9+/]{{20,}}={0,2})["\']', src)
for b64 in b64_m[:3]:
    try:
        import base64, urllib.parse
        dec = base64.b64decode(b64).decode()
        results.append(f"base64 decoded: {{dec}}")
        results.append(f"url+b64 decoded: {{urllib.parse.unquote(dec)}}")
    except: pass

# Pattern 5: scrambled char array with loops (vault door 3 style)
arr_m = re.search(r'String\\s+\\w+\\s*=\\s*"([^"{{}}]{{20,}})"', src)
if arr_m:
    results.append(f"String literal (may be scrambled): {{arr_m.group(1)}}")

print("\\n".join(results) if results else "No obvious flag pattern found — try operation='run' to execute the logic")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "run":
        src = source_code or ""
        sp = (_w2l(source_path) if (IS_WINDOWS and USE_WSL) else source_path) if source_path else ""
        if not src and not sp:
            return "Provide source_code or source_path"
        code = f"""
import subprocess, tempfile, os, sys

src = {repr(src)}
sp = {repr(sp)}
cls = {repr(class_name)}
inp = {repr(stdin_input)}

with tempfile.TemporaryDirectory() as td:
    if sp:
        import shutil
        fname = os.path.basename(sp)
        dst = os.path.join(td, fname)
        shutil.copy(sp, dst)
    else:
        # Guess class name from source
        import re
        cls_m = re.search(r'public\\s+class\\s+(\\w+)', src)
        if not cls_m: cls_m = re.search(r'class\\s+(\\w+)', src)
        cls = cls or (cls_m.group(1) if cls_m else 'Main')
        fname = cls + '.java'
        dst = os.path.join(td, fname)
        with open(dst, 'w') as f: f.write(src)

    # Compile
    r = subprocess.run(['javac', dst], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        print(f"Compile error: {{r.stderr[:500]}}")
        sys.exit(1)
    print(f"Compiled OK")

    # Run
    cls_m2 = re.search(r'public\\s+class\\s+(\\w+)', open(dst).read()) if not cls else None
    run_cls = cls or (cls_m2.group(1) if cls_m2 else 'Main')
    r2 = subprocess.run(['java', '-cp', td, run_cls],
                        input=inp, capture_output=True, text=True, timeout={timeout})
    print(r2.stdout[:2000])
    if r2.stderr: print("STDERR:", r2.stderr[:500])
"""
        return tool_execute_python(code, timeout=timeout+10)

    if operation == "decompile":
        sp = (_w2l(source_path) if (IS_WINDOWS and USE_WSL) else source_path) if source_path else ""
        if not sp:
            return "Provide source_path to .class or .jar file"
        return _shell(f"javap -c -p '{sp}' 2>/dev/null | head -100 || "
                     f"javap -verbose '{sp}' 2>/dev/null | head -80", timeout=15)

    if operation == "solve":
        # Auto-solve: run the Java check logic inverted via Python
        src = source_code or (open(source_path).read() if source_path else "")
        if not src:
            return "Provide source_code"
        # Try to extract and invert automatically
        code = f"""
import re, base64, urllib.parse

src = {repr(src)}

# Try multiple extraction strategies and combine
flag_chars = {{}}
flag_bytes_xor = []
xor_key = None

# charAt comparisons
for m in re.finditer(r'charAt\\s*\\(\\s*(\\d+)\\s*\\)\\s*==\\s*[\'\"](.)[\'\"]', src):
    flag_chars[int(m.group(1))] = m.group(2)

# Byte XOR
xor_m = re.search(r'\\^\\s*(0x[0-9a-fA-F]+)', src)
if xor_m:
    xor_key = int(xor_m.group(1), 16)
    bytes_m = re.findall(r'(0x[0-9a-fA-F]{{2}})', src)
    flag_bytes_xor = [chr(int(b,16) ^ xor_key) for b in bytes_m if 32 <= (int(b,16)^xor_key) <= 126]

# Print best guess
if flag_chars:
    out = ''.join(flag_chars.get(i,'?') for i in range(max(flag_chars)+1))
    print(f"Flag (charAt): {{out}}")
if flag_bytes_xor:
    print(f"Flag (XOR 0x{{xor_key:02x}}): {{''.join(flag_bytes_xor)}}")
if not flag_chars and not flag_bytes_xor:
    print("Could not auto-solve — use operation='run' with modified source that prints flag")
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: run, analyze, solve, decompile"


def tool_node_exec(code: str = "", file_path: str = "",
                   operation: str = "run", pattern: str = "picoCTF{",
                   timeout: int = 30) -> str:
    """Execute JavaScript/Node.js code, eval obfuscated snippets, and grep
    .heapsnapshot JSON files for flag patterns.
    Ops: run (write + execute JS file), eval_snippet (node -e inline),
    heapsnapshot_grep (extract strings matching pattern from .heapsnapshot),
    deobfuscate_run (run and capture all console.log output)."""

    fp = (_w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path) if file_path else ""

    # Verify node is available
    node_check = _shell("node --version 2>&1", timeout=5)
    if "not found" in node_check or "command not found" in node_check:
        return f"node.js not found ({node_check}). Install with: apt-get install nodejs"

    if operation == "run":
        src = code
        if not src and fp:
            try:
                with open(fp) as f: src = f.read()
            except Exception as ex:
                return f"Cannot read {fp}: {ex}"
        if not src:
            return "Provide code= or file_path="
        tmp = f"/tmp/node_{int(time.time())}.js"
        with open(tmp, "w") as f: f.write(src)
        out = _shell(f"node '{tmp}' 2>&1", timeout=timeout)
        try: os.remove(tmp)
        except: pass
        return out

    if operation == "eval_snippet":
        src = code or ""
        if not src:
            return "Provide code= for eval_snippet"
        # Wrap in safe eval with output capture
        wrapped = f"try {{ {src} }} catch(e) {{ console.error('Error:', e.message); }}"
        tmp = f"/tmp/node_eval_{int(time.time())}.js"
        with open(tmp, "w") as f: f.write(wrapped)
        out = _shell(f"node '{tmp}' 2>&1", timeout=timeout)
        try: os.remove(tmp)
        except: pass
        return out

    if operation == "heapsnapshot_grep":
        if not fp:
            return "Provide file_path= pointing to .heapsnapshot file"
        # Stream-parse the massive JSON with node to avoid loading it all into Python
        pat = pattern.replace("'", "\\'")
        js = f"""
const fs = require('fs');
const path = {repr(fp)};
const pat = {repr(pattern)};
let buf = '';
const stream = fs.createReadStream(path, {{encoding:'utf8', highWaterMark: 1024*1024}});
const found = new Set();
stream.on('data', chunk => {{
  buf += chunk;
  // Scan for flag patterns in the rolling buffer
  let idx;
  const search = pat;
  let pos = 0;
  while ((idx = buf.indexOf(search, pos)) !== -1) {{
    const start = Math.max(0, idx - 10);
    const end   = Math.min(buf.length, idx + 120);
    const snippet = buf.slice(start, end).replace(/[\\n\\r]/g, ' ');
    found.add(snippet);
    pos = idx + 1;
  }}
  // Keep last 500 chars in buffer for cross-chunk matches
  if (buf.length > 2000) buf = buf.slice(-500);
}});
stream.on('end', () => {{
  if (found.size === 0) {{
    console.log('[heapsnapshot_grep] No matches for: ' + pat);
  }} else {{
    console.log('[heapsnapshot_grep] Found ' + found.size + ' match(es):');
    [...found].forEach(s => console.log('  ' + s));
  }}
}});
stream.on('error', err => console.error('Error:', err.message));
"""
        tmp = f"/tmp/hs_grep_{int(time.time())}.js"
        with open(tmp, "w") as f: f.write(js)
        out = _shell(f"node '{tmp}' 2>&1", timeout=60)
        try: os.remove(tmp)
        except: pass
        return out

    if operation == "deobfuscate_run":
        src = code or ""
        if not src and fp:
            try:
                with open(fp) as f: src = f.read()
            except Exception as ex:
                return f"Cannot read {fp}: {ex}"
        if not src:
            return "Provide code= or file_path="
        # Patch console to capture everything
        wrapper = f"""
const _logs = [];
const _orig = console.log.bind(console);
console.log = (...a) => {{ _logs.push(a.join(' ')); _orig(...a); }};
console.error = (...a) => {{ _logs.push('[ERR] '+a.join(' ')); }};
try {{
{src}
}} catch(e) {{
  console.error('Deobfuscation error:', e.message);
}}
// Print summary
process.stderr.write('\\n[deobfuscate] total outputs: ' + _logs.length + '\\n');
"""
        tmp = f"/tmp/deobf_{int(time.time())}.js"
        with open(tmp, "w") as f: f.write(wrapper)
        out = _shell(f"node --max-old-space-size=512 '{tmp}' 2>&1", timeout=timeout)
        try: os.remove(tmp)
        except: pass
        return out

    return "Operations: run, eval_snippet, heapsnapshot_grep, deobfuscate_run"


def tool_pyjail_escape(operation: str = "detect", jail_code: str = "",
                        available: str = "", blocked: str = "") -> str:
    """Python sandbox escape. Ops: detect (analyze restrictions), escape_chains
    (20+ techniques ordered by likelihood), builtins_restore, subclass_walk,
    code_object, audit_hooks_bypass, wasm_escape, fstring."""

    # ESCAPE_CHAINS removed - Claude generates these

    if operation == "detect":
        if not jail_code:
            return ("Python jail analysis guide:\n\n"
                    "1. Determine what's blocked:\n"
                "   Try: import os; __import__; exec; eval; open; breakpoint\n"
                    "   Try: __builtins__; globals(); locals(); dir()\n\n"
                    "2. Check which built-ins remain:\n"
                    "   [x for x in dir(__builtins__) if x not in ('__name__',)]\n"
                    "   OR: print(__builtins__) if accessible\n\n"
                    "3. Check allowed modules:\n"
                    "   import sys; sys.modules.keys()\n\n"
                    "4. Check string literal filter:\n"
                    "   'os' vs chr(111)+chr(115) vs b'os'.decode()\n\n"
                    "5. What attributes are accessible:\n"
                    "   ().__class__ vs type(()) etc.\n\n"
                    "Use operation='escape_chains' for ordered list of techniques")

        code = f"""
jail = {repr(jail_code)}
import ast, re
print("=== Jail analysis ===")
blocked = []
try:
    tree = ast.parse(jail)
except: pass
# Check for common restrictions
for kw in ['__import__', 'exec', 'eval', 'compile', 'open', 'breakpoint',
           '__builtins__', 'globals', 'locals', 'getattr', 'setattr',
           '__class__', '__mro__', '__subclasses__']:
    if kw in jail:
        blocked.append(kw)
        print(f"  Blocked/checked: {{kw}}")
# Check for whitelisting
if 'if ' in jail and ('not in' in jail or 'in ALLOWED' in jail or 'whitelist' in jail.lower()):
    print("  [!] Whitelist-based filter detected (harder to bypass)")
if 'ast' in jail and 'parse' in jail:
    print("  [!] AST-based filter (blocks syntax-level, not runtime)")
if 'audit' in jail.lower() or 'addaudithook' in jail:
    print("  [!] sys.addaudithook detected (persistent, cannot be removed)")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "escape_chains":
        lines = [f"=== Python jail escape chains (ordered by success rate) ===\n"]
        for i, (name, payload, note) in enumerate(ESCAPE_CHAINS, 1):
            lines.append(f"[{i:02d}] {name}")
            lines.append(f"     {payload}")
            lines.append(f"     Note: {note}\n")
        return "\n".join(lines)

    if operation == "subclass_walk":
        code = f"""
# Find useful subclasses for escape
try:
    subs = object.__subclasses__()
    targets = ['Popen', 'os', 'system', 'BuiltinImporter', 'FileLoader',
               'catch_warnings', 'timeit', 'code', 'InteractiveConsole']
    for i, cls in enumerate(subs):
        name = str(cls)
        if any(t in name for t in targets):
            print(f"  [{i}] {{cls}}")
    # Also find index for generic exec capability
    for i, cls in enumerate(subs):
        try:
            if hasattr(cls, '__init__') and hasattr(cls.__init__, '__globals__'):
                if 'builtins' in str(cls.__init__.__globals__.get('__builtins__','')):
                    print(f"  [{i}] Has builtins: {{cls}}")
                    break
        except: pass
except Exception as e:
    print(f"subclass walk error: {{e}}")
    print("May need: ''.__class__.__mro__[-1].__subclasses__()")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "builtins_restore":
        return f"[builtins_restore] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "audit_hooks_bypass":
        return f"[audit_hooks_bypass] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("Python jail escape operations:\n"
            "  detect          — analyze jail code for restrictions\n"
            "  escape_chains   — 20 ordered escape techniques\n"
            "  subclass_walk   — find useful classes via object.__subclasses__()\n"
            "  builtins_restore— recover __builtins__ via multiple paths\n"
            "  audit_hooks_bypass — bypass sys.addaudithook (Python 3.8+)\n"
            "  fstring         — f-string execution tricks\n"
            "  code_object     — code.co_code manipulation")


def tool_rust_sandbox(source_code: str = "", source_path: str = "",
                      operation: str = "run", patch: str = "",
                      timeout: int = 30) -> str:
    """Compile and run Rust source code (rustc). Like tool_java_sandbox but for Rust.
    Ops: run (compile + execute), fix_and_run (apply patch then run),
    analyze (AST/HIR dump via rustc), decompile (strings + nm on compiled binary)."""

    import tempfile

    sp = (_w2l(source_path) if (IS_WINDOWS and USE_WSL) else source_path) if source_path else ""
    work = f"/tmp/rust_{int(time.time())}"
    _shell(f"mkdir -p '{work}'")

    # Load source
    src = source_code
    if not src and sp:
        try:
            with open(sp) as f: src = f.read()
        except Exception as ex:
            return f"Cannot read {sp}: {ex}"
    if not src:
        return "Provide source_code or source_path"

    # Apply patch if given
    if patch and operation == "fix_and_run":
        # Try unified diff first
        patch_file = f"{work}/fix.patch"
        src_file   = f"{work}/main.rs"
        with open(src_file, "w") as f: f.write(src)
        with open(patch_file, "w") as f: f.write(patch)
        patched = _shell(f"patch '{src_file}' '{patch_file}' 2>&1 && cat '{src_file}'", timeout=10)
        if "succeeded" in patched or "patching" in patched:
            try:
                with open(src_file) as f: src = f.read()
            except: pass
        else:
            # Plain string replacement: patch = "OLD|||NEW"
            if "|||" in patch:
                old, new = patch.split("|||", 1)
                src = src.replace(old, new)

    src_file = f"{work}/main.rs"
    bin_file = f"{work}/main_bin"
    with open(src_file, "w") as f: f.write(src)

    if operation in ("run", "fix_and_run"):
        compile_out = _shell(f"rustc '{src_file}' -o '{bin_file}' 2>&1", timeout=30)
        if not os.path.exists(bin_file):
            return f"Compile error:\n{compile_out}"
        run_out = _shell(f"'{bin_file}'", timeout=timeout)
        return f"[Compiled OK]\n{run_out}"

    if operation == "analyze":
        return _shell(f"rustc '{src_file}' --edition 2021 -Z unpretty=hir 2>&1 | head -120", timeout=20)

    if operation == "decompile":
        compile_out = _shell(f"rustc '{src_file}' -o '{bin_file}' 2>&1", timeout=30)
        if not os.path.exists(bin_file):
            return f"Compile error:\n{compile_out}"
        return (_shell(f"strings '{bin_file}' | grep -vE '^[.\\x00-\\x1f]' | head -60", timeout=10) +
                "\n" + _shell(f"nm '{bin_file}' 2>/dev/null | grep -v 'std\\|core\\|alloc' | head -40", timeout=10))

    return "Operations: run, fix_and_run, analyze, decompile"

