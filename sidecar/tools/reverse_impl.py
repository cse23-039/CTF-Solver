"""Reverse engineering and decompilation tools."""
from __future__ import annotations
import re, subprocess, os, shutil
import time
from tools.shell import _shell, _w2l, IS_WINDOWS, USE_WSL, tool_execute_python, log


def tool_ghidra_decompile(binary_path: str, function_name: str = "main",
                           all_functions: bool = False, project_dir: str = "/tmp/ghidra_proj") -> str:
    """
    Ghidra headless decompilation. Returns semantically rich C pseudocode.
    Set all_functions=True to decompile every function (for small binaries).
    Falls back to radare2/objdump if Ghidra not installed.
    """
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    os.makedirs(project_dir, exist_ok=True)

    # Try Ghidra headless
    ghidra_paths = [
        shutil.which("analyzeHeadless"),
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/local/ghidra/support/analyzeHeadless",
        os.path.expanduser("~/ghidra/support/analyzeHeadless"),
    ]
    ghidra = next((p for p in ghidra_paths if p and os.path.exists(p)), None)

    if ghidra:
        # Write inline decompile script
        script_content = f"""
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
DecompInterface di = new DecompInterface();
di.openProgram(currentProgram);
FunctionManager fm = currentProgram.getFunctionManager();
{"for (Function f : fm.getFunctions(true)) {" if all_functions else f'Function f = fm.getFunctions(true).iterator().next();  // fallback'}
    DecompileResults dr = di.decompileFunction(f, 60, monitor);
    if (dr.decompileCompleted()) {{
        println("\\n=== " + f.getName() + " ===");
        println(dr.getDecompiledFunction().getC());
    }}
{"}" if all_functions else ""}
"""
        script_path = "/tmp/ghidra_decompile.java"
        with open(script_path, "w") as sf: sf.write(script_content)
        proj_name = f"ctf_{int(time.time())}"
        cmd = (f"'{ghidra}' '{project_dir}' '{proj_name}' -import '{sp}' "
               f"-postScript '{script_path}' -deleteProject 2>&1")
        out = _shell(cmd, timeout=120)
        if "=== " in out or "void " in out or "int " in out:
            return out[:8000]
        return f"Ghidra ran but no output matched. Raw:\n{out[:2000]}"
    else:
        # Fallback chain: r2 → objdump → strings
        log("warn", "Ghidra not found — falling back to radare2", "")
        r2 = _shell(f"r2 -q -c 'aaa;s sym.{function_name};pdf' '{sp}' 2>/dev/null", timeout=45)
        if r2 and "invalid" not in r2.lower() and len(r2) > 50:
            return f"[r2 fallback]\n{r2[:6000]}"
        return _shell(f"objdump -d -M intel '{sp}' | head -300", timeout=30)


def tool_ai_rename_functions(decompiled_output: str, api_key: str = "",
                              binary_path: str = "") -> str:
    """
    Use Claude to semantically rename sub_XXXX functions in decompiled code.
    Returns annotated version with meaningful names and inline comments explaining purpose.
    This dramatically reduces the cognitive load of hard rev challenges.
    """
    if not api_key:
        # Try to read from environment
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "ai_rename_functions requires ANTHROPIC_API_KEY in environment."

    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        prompt = f"""You are a reverse engineering expert. Below is decompiled C pseudocode with generic names like sub_401234, var_8, etc.

Rewrite it with:
1. Meaningful function names based on what the code does
2. Meaningful variable names  
3. Short inline comments on non-obvious logic
4. Identify: input validation, crypto operations, flag checks, network code, encoding/decoding

Output ONLY the renamed code, no preamble.

DECOMPILED CODE:
{decompiled_output[:6000]}"""

        resp = c.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        renamed = resp.content[0].text if resp.content else ""
        log("ok", "[AI-RENAME] Functions renamed semantically", "white")
        return renamed
    except Exception as e:
        return f"AI rename error: {e}"


def tool_go_rev(binary_path: str, operation: str = "analyze",
                 output_dir: str = "") -> str:
    """Go binary reversing: analyze (version, build info, goroutines), symbols (recover stripped symbols via GoReSym),
    functions (list all Go functions), strings (Go string table), types (recover type info),
    pcln (parse pclntab for function names even when stripped)."""

    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    od = output_dir or f"/tmp/go_rev_{int(time.time())}"

    if operation == "analyze":
        return _shell(f"strings '{sp}' | grep -E 'go[0-9]+\\.[0-9]+|/usr/local/go|GOOS|GOARCH' | head -10 && "
                     f"echo '--- Build info ---' && "
                     f"go version '{sp}' 2>/dev/null || strings '{sp}' | grep 'go1\\.' | head -5 && "
                     f"echo '--- Suspicious strings ---' && "
                     f"strings '{sp}' | grep -iE 'flag|ctf|secret|key|password|check|verify' | head -20 && "
                     f"echo '--- ELF info ---' && "
                     f"readelf -h '{sp}' 2>/dev/null | grep -E 'Type|Machine|Entry' | head -5",
                     timeout=20)

    if operation == "symbols":
        code = f"""
import subprocess, os
sp = {repr(sp)}
od = {repr(od)}
os.makedirs(od, exist_ok=True)

# Try GoReSym first (best Go symbol recovery)
r = subprocess.run(['GoReSym', '-t', '-d', '-m', sp],
                   capture_output=True, text=True, timeout=60)
if r.returncode == 0:
    out_file = f'{{od}}/goresym.json'
    with open(out_file, 'w') as f: f.write(r.stdout)
    print(f"GoReSym output: {{out_file}}")
    # Print function names
    import json
    try:
        data = json.loads(r.stdout)
        fns = data.get('UserFunctions', []) + data.get('StdFunctions', [])
        print(f"Recovered {{len(fns)}} functions:")
        for fn in fns[:30]:
            print(f"  0x{{fn.get('Start','?'):x}}: {{fn.get('FullName','?')}}")
    except: print(r.stdout[:2000])
else:
    print("GoReSym not found. Install: go install github.com/mandiant/GoReSym@latest")
    print("Trying pclntab parse...")
    # Parse pclntab manually
    r2 = subprocess.run(['strings', '-n', '8', sp], capture_output=True, text=True, timeout=15)
    go_fns = [s for s in r2.stdout.split('\\n')
              if s.startswith('main.') or s.startswith('github.com/') or s.startswith('golang.org/')]
    print(f"pclntab strings ({{len(go_fns)}}):")
    for fn in go_fns[:40]: print(f"  {{fn}}")
"""
        return tool_execute_python(code, timeout=70)

    if operation == "functions":
        code = f"""
import subprocess, re
sp = {repr(sp)}

# Method 1: nm
r = subprocess.run(['nm', '-n', sp], capture_output=True, text=True, timeout=15)
go_fns = [l for l in r.stdout.split('\\n') if ' T ' in l or ' t ' in l]
if go_fns:
    print(f"Functions (nm): {{len(go_fns)}}")
    for fn in go_fns[:40]: print(f"  {{fn.strip()}}")
else:
    # Method 2: Parse pclntab via radare2
    r2 = subprocess.run(['r2', '-q', '-c', 'aaa; afll', sp],
                        capture_output=True, text=True, timeout=60)
    print(f"r2 function list:")
    for l in r2.stdout.split('\\n')[:40]: print(l)
"""
        return tool_execute_python(code, timeout=70)

    if operation == "pcln":
        code = f"""
import subprocess, struct, re
sp = {repr(sp)}

# Parse pclntab to recover function names even in stripped binary
with open(sp, 'rb') as f:
    data = f.read()

# Find pclntab magic
MAGIC_1_20 = b'\\xf1\\xff\\xff\\xff\\x00\\x00'
MAGIC_1_18 = b'\\xf0\\xff\\xff\\xff\\x00\\x00'
MAGIC_1_16 = b'\\xfb\\xff\\xff\\xff\\x00\\x00'
MAGIC_OLD  = b'\\xfb\\xff\\xff\\xff'

names = []
for magic in [MAGIC_1_20, MAGIC_1_18, MAGIC_1_16, MAGIC_OLD]:
    pos = data.find(magic)
    if pos != -1:
        print(f"Found pclntab at offset 0x{{pos:x}} (magic: {{magic.hex()}})")
        # Extract function names from pclntab
        # This is simplified — proper parsing needs architecture awareness
        chunk = data[pos:pos+1024*1024]
        # Find null-terminated strings that look like Go function names
        for m in re.finditer(b'[\\x20-\\x7e]{{10,200}}\\x00', chunk):
            s = m.group().rstrip(b'\\x00').decode(errors='replace')
            if '.' in s and any(c.isupper() for c in s) and '/' in s or s.startswith('main.'):
                names.append(s)
        break

print(f"Recovered {{len(names)}} function names from pclntab:")
for n in sorted(set(names))[:50]: print(f"  {{n}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "strings":
        return _shell(f"strings -n 6 '{sp}' | grep -E '^[a-z]{{2,}}/|^main\\.|^github\\.com|^golang\\.org' | head -50 && "
                     f"echo '--- All strings (filtered) ---' && "
                     f"strings '{sp}' | grep -vE '^\\s*$|^\\.' | head -80",
                     timeout=15)

    return "Operations: analyze, symbols, functions, pcln, strings, types"


def tool_powershell_deobf(script_path: str = "", script_content: str = "",
                           operation: str = "deobfuscate") -> str:
    """PowerShell deobfuscation and analysis.
    Ops: deobfuscate (layer-by-layer decode), amsi_detect (find AMSI bypass attempts),
    iex_extract (extract Invoke-Expression payloads), strings (extract all cleartext strings),
    run_safe (execute in constrained language mode), decode_chain (base64 + gzip + xor chains)."""

    src = script_content or ""
    if script_path:
        sp = _w2l(script_path) if (IS_WINDOWS and USE_WSL) else script_path
        try:
            src = open(sp).read()
        except:
            src = _shell(f"cat '{sp}' 2>/dev/null", timeout=5)

    if operation == "deobfuscate":
        code = f"""
import re, base64, zlib, binascii

script = {repr(src[:50000])}
layers = [("Original", script)]
current = script

# Layer 1: base64 decode
def try_b64(s):
    # Find all base64 blobs
    results = []
    for m in re.finditer(r'[A-Za-z0-9+/]{{40,}}={{0,2}}', s):
        try:
            decoded = base64.b64decode(m.group())
            # Check if UTF-16LE (common in PS)
            try:
                text = decoded.decode('utf-16-le')
                if len(text) > 10 and text.isprintable():
                    results.append(('b64+utf16le', text[:500]))
                    continue
            except: pass
            # Try UTF-8
            try:
                text = decoded.decode('utf-8')
                if len(text) > 10 and any(c.isalpha() for c in text):
                    results.append(('b64+utf8', text[:500]))
            except: pass
        except: pass
    return results

b64_results = try_b64(current)
if b64_results:
    print(f"=== Base64 decoded layers ({{len(b64_results)}}) ===")
    for kind, text in b64_results[:3]:
        print(f"[{{kind}}]: {{text[:300]}}")
        current = text

# Layer 2: gzip decompress
for m in re.finditer(r'[A-Za-z0-9+/]{{40,}}={{0,2}}', current):
    try:
        compressed = base64.b64decode(m.group())
        decompressed = zlib.decompress(compressed, -15)  # raw deflate
        print(f"\\n=== Gzip/deflate layer ===")
        print(decompressed.decode(errors='replace')[:500])
        current = decompressed.decode(errors='replace')
    except: pass

# Layer 3: string replacement / char code
if 'char' in current.lower() or '[char]' in current.lower():
    char_vals = re.findall(r'\\[char\\]\\s*(\\d+)', current, re.IGNORECASE)
    if char_vals:
        decoded = ''.join(chr(int(v)) for v in char_vals if int(v) < 128)
        print(f"\\n=== [char] decode: {{decoded[:300]}}")

# Layer 4: string join / concatenation
join_m = re.search(r"-join\\s*['\"]([^'\"]+)['\"]", current, re.IGNORECASE)
if join_m:
    print(f"\\n=== -join content: {{join_m.group(1)[:200]}}")

# Extract final IEX payload
iex = re.findall(r'(?:Invoke-Expression|iex)\\s*[\\(\\$].*', current, re.IGNORECASE)
for ix in iex[:3]:
    print(f"\\n=== IEX call: {{ix[:200]}}")

# Extract interesting strings
strings_found = re.findall(r"['\"]([^'\"{{}}]{{8,200}})['\"]", current)
interesting = [s for s in strings_found if any(kw in s.lower()
               for kw in ['http','flag','key','secret','pass','cmd','exec','download'])]
if interesting:
    print(f"\\n=== Interesting strings: {{interesting[:10]}}")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "amsi_detect":
        code = f"""
import re
script = {repr(src[:50000])}
amsi_patterns = [
    r'amsi', r'AmsiScanBuffer', r'AmsiInitialize',
    r'[Rr]ef.*AmsiUtils', r'\\$a.*\\[ref\\].*amsi',
    r'Win32.*Amsi', r'amsiContext', r'amsiSession',
    r'Reflection.*Assembly.*Load.*amsi',
    r'\\[Byte\\[\\]\\]\\s*\\(\\s*0x',  # byte array patches
    r'VirtualProtect', r'WriteProcessMemory',
    r'SetWindowsHookEx.*amsi',
]
found = []
for p in amsi_patterns:
    if re.search(p, script, re.IGNORECASE):
        found.append(p)
        for m in re.finditer(p, script, re.IGNORECASE):
            start = max(0, m.start()-50)
            print(f"[{{p}}]: {{script[start:m.end()+50]}}")
            break
if not found:
    print("No obvious AMSI bypass detected")
else:
    print(f"\\nAMSI bypass patterns found: {{found}}")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "strings":
        code = f"""
import re
script = {repr(src[:50000])}
# Extract all string literals
strings = re.findall(r"['\"]([^'\"\\n]{{4,200}})['\"]", script)
# Deduplicate and filter
seen = set()
for s in strings:
    if s not in seen and not s.startswith('http://schemas') and not s.startswith('xmlns'):
        seen.add(s)
        print(s)
"""
        return tool_execute_python(code, timeout=10)

    if operation == "run_safe":
        if not src:
            return "Provide script_content or script_path"
        return _shell(f"pwsh -NonInteractive -NoProfile -ExecutionPolicy Bypass "
                     f"-Command \"$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; "
                     f"{src[:2000].replace(chr(34), chr(39))}\" 2>&1 | head -30 || "
                     f"powershell -NonInteractive -NoProfile -ExecutionPolicy Bypass "
                     f"-EncodedCommand {__import__('base64').b64encode(src[:2000].encode('utf-16-le')).decode()} "
                     f"2>&1 | head -30",
                     timeout=20)

    return "Operations: deobfuscate, amsi_detect, iex_extract, strings, run_safe, decode_chain"


def tool_swift_decompile(binary_path: str = "", ipa_path: str = "",
                          operation: str = "analyze") -> str:
    """iOS Swift binary analysis.
    Ops: analyze (file info + encryption check), demangle (Swift symbol demangling),
    class_hierarchy (reconstruct class structure), strings (Swift string literals),
    protocols (list implemented protocols), frida_hooks (generate Swift-aware Frida hooks)."""

    sp = ""
    if ipa_path:
        ip = _w2l(ipa_path) if (IS_WINDOWS and USE_WSL) else ipa_path
        # Extract binary from IPA
        out = f"/tmp/swift_ipa_{int(time.time())}"
        _shell(f"mkdir -p '{out}' && unzip -q '{ip}' -d '{out}' 2>/dev/null", timeout=20)
        sp_list = _shell(f"find '{out}' -name '*.app' -type d | head -1", timeout=5).strip()
        if sp_list:
            bin_name = _shell(f"ls '{sp_list}' | grep -v '\\.' | head -1", timeout=5).strip()
            sp = f"{sp_list}/{bin_name}"
    elif binary_path:
        sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path

    if not sp:
        return "Provide binary_path or ipa_path"

    if operation == "analyze":
        return _shell(f"file '{sp}' 2>/dev/null && "
                     f"echo '--- Encryption check ---' && "
                     f"otool -l '{sp}' 2>/dev/null | grep -A3 'LC_ENCRYPTION_INFO' && "
                     f"echo '--- Swift version ---' && "
                     f"strings '{sp}' | grep -E 'Swift [0-9]|swiftlang' | head -5 && "
                     f"echo '--- Security ---' && "
                     f"checksec --file='{sp}' 2>/dev/null || "
                     f"otool -l '{sp}' 2>/dev/null | grep -E 'PIE|STACK' | head -5",
                     timeout=20)

    if operation == "demangle":
        return _shell(f"nm '{sp}' 2>/dev/null | grep '_\\$s' | "
                     f"awk '{{print $3}}' | swift-demangle 2>/dev/null | head -50 || "
                     f"nm '{sp}' 2>/dev/null | grep '_\\$s' | head -30 | "
                     f"while read addr type sym; do "
                     f"  echo \"$addr $type $(echo $sym | xcrun swift-demangle 2>/dev/null || echo $sym)\"; "
                     f"done | head -30",
                     timeout=30)

    if operation == "class_hierarchy":
        return _shell(f"class-dump --arch arm64 '{sp}' 2>/dev/null | head -100 || "
                     f"nm '{sp}' 2>/dev/null | grep -E 'metaclass|OBJC_CLASS' | "
                     f"awk '{{print $3}}' | sed 's/_OBJC_CLASS_\\$_//' | head -40",
                     timeout=20)

    if operation == "strings":
        return _shell(f"strings '{sp}' | grep -vE '^[^[:print:]]|^\\.' | "
                     f"grep -iE 'flag|ctf|key|secret|password|token|auth' | head -30 && "
                     f"echo '--- All non-trivial strings ---' && "
                     f"strings -n 8 '{sp}' | grep -v '^[_@$.]' | head -60",
                     timeout=15)

    if operation == "frida_hooks":
        return (f"Swift-aware Frida hooks:\n\n"
                f"// Hook all Swift methods on a class\n"
                f"var ClassName = ObjC.classes['ClassName'];\n"
                f"if (ClassName) {{\n"
                f"  ObjC.choose(ClassName, {{\n"
                f"    onMatch: function(obj) {{\n"
                f"      console.log('Found instance:', obj);\n"
                f"    }},\n"
                f"    onComplete: function() {{}}\n"
                f"  }});\n"
                f"}}\n\n"
                f"// Swift function hooking (by mangled name)\n"
                f"// First demangle: nm binary | grep _\\$s | head -20\n"
                f"var swiftFunc = Module.findExportByName(null, '_\\$s<mangled_name>');\n"
                f"if (swiftFunc) {{\n"
                f"  Interceptor.attach(swiftFunc, {{\n"
                f"    onEnter: function(args) {{ console.log('Swift func called', args[0]); }},\n"
                f"    onLeave: function(retval) {{ retval.replace(1); }}\n"
                f"  }});\n"
                f"}}")

    return "Operations: analyze, demangle, class_hierarchy, strings, protocols, frida_hooks"


def tool_license_check(binary_path: str = "", operation: str = "hook_comparisons",
                        username: str = "user", input_value: str = "",
                        timeout: int = 30) -> str:
    """License/serial check extractor using angr symbolic execution + frida hooks.
    Ops: hook_comparisons (frida-intercept strcmp/memcmp/strncmp, print comparisons),
    angr_keygen (angr symbolic execution to find valid input/serial),
    patch_check (NOP out validation with binary_patch — makes any input valid),
    frida_hook (custom frida script to dump function args at interesting calls)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    if not sp: return "Provide binary_path="

    if operation == "hook_comparisons":
        # Frida intercept script
        frida_script = """
Interceptor.attach(Module.getExportByName(null, 'strcmp'), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();
        console.log('[strcmp] ' + JSON.stringify(s1) + ' vs ' + JSON.stringify(s2));
    }
});
Interceptor.attach(Module.getExportByName(null, 'strncmp'), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();
        console.log('[strncmp] ' + JSON.stringify(s1) + ' vs ' + JSON.stringify(s2));
    }
});
Interceptor.attach(Module.getExportByName(null, 'memcmp'), {
    onEnter(args) {
        const n = args[2].toInt32();
        const b1 = args[0].readByteArray(n);
        const b2 = args[1].readByteArray(n);
        console.log('[memcmp] ' + Array.from(new Uint8Array(b1)).map(x=>x.toString(16).padStart(2,'0')).join('') +
                    ' vs '     + Array.from(new Uint8Array(b2)).map(x=>x.toString(16).padStart(2,'0')).join(''));
    }
});
"""
        tmp_script = f"/tmp/frida_hook_{int(time.time())}.js"
        with open(tmp_script, "w") as f: f.write(frida_script)
        cmd = (f"echo {repr(input_value)} | frida -l '{tmp_script}' "
               f"--no-pause -f '{sp}' 2>&1 | grep -E 'strcmp|strncmp|memcmp' | head -30")
        result = _shell(cmd, timeout=timeout)
        try: os.remove(tmp_script)
        except: pass
        if "not found" in result or "Unable to find" in result:
            # Fallback: GDB hooks
            gdb_script = f"""set pagination off
set confirm off
break strcmp
commands 1
  printf "strcmp: %s vs %s\\n", (char*)$rdi, (char*)$rsi
  continue
end
break strncmp
commands 2
  printf "strncmp: %s vs %s\\n", (char*)$rdi, (char*)$rsi
  continue
end
run <<< {repr(input_value)}
quit"""
            tmp_gdb = f"/tmp/gdb_hook_{int(time.time())}.gdb"
            with open(tmp_gdb, "w") as f: f.write(gdb_script)
            result = _shell(f"timeout {timeout} gdb -batch -x '{tmp_gdb}' '{sp}' 2>&1 | grep -E 'strcmp|strncmp' | head -20", timeout=timeout+5)
            try: os.remove(tmp_gdb)
            except: pass
        return result

    if operation == "angr_keygen":
        code = f"""
import angr, claripy, sys
proj = angr.Project({repr(sp)}, load_options={{'auto_load_libs': False}})
state = proj.factory.entry_state(stdin=angr.SimFileStream(name='stdin', size=64))
simgr = proj.factory.simulation_manager(state)

# Look for success/failure strings
simgr.explore(
    find=lambda s: b'Correct' in s.posix.dumps(1) or b'Valid' in s.posix.dumps(1) or b'picoCTF' in s.posix.dumps(1),
    avoid=lambda s: b'Wrong' in s.posix.dumps(1) or b'Invalid' in s.posix.dumps(1) or b'Incorrect' in s.posix.dumps(1),
)
if simgr.found:
    s = simgr.found[0]
    stdin_val = s.posix.dumps(0)
    stdout_val = s.posix.dumps(1)
    print(f'[+] Found valid input: {{repr(stdin_val)}}')
    print(f'    stdout: {{repr(stdout_val[:200])}}')
else:
    print('[-] No path found — try adjusting find/avoid conditions')
    print(f'    deadended: {{len(simgr.deadended)}}, active: {{len(simgr.active)}}')
"""
        return tool_execute_python(code, timeout=120)

    if operation == "patch_check":
        # Find the comparison and NOP it — delegate to binary_patch
        result = tool_binary_analysis(sp, "disassemble_func", "main")
        return (f"Analysis of {sp}:\n{result[:2000]}\n\n"
                f"Use tool_binary_patch('{sp}', 'flip_jump', ...) to NOP out the check\n"
                f"or tool_binary_patch('{sp}', 'patch_ret', ...) to make function always return 1")

    if operation == "frida_hook":
        frida_script = f"""
// Generic hook — modify target address as needed
const target = Process.enumerateModulesSync()[0];
console.log('[*] Target module:', target.name, target.base);
Process.enumerateExportsSync().filter(e => e.type === 'function').slice(0,5).forEach(e => {{
    console.log('[export]', e.name, e.address);
}});
"""
        tmp_script = f"/tmp/frida_generic_{int(time.time())}.js"
        with open(tmp_script, "w") as f: f.write(frida_script)
        result = _shell(f"frida -l '{tmp_script}' --no-pause -f '{sp}' 2>&1 | head -30", timeout=15)
        try: os.remove(tmp_script)
        except: pass
        return result

    return "Operations: hook_comparisons, angr_keygen, patch_check, frida_hook"


def tool_proto_decode(operation: str = "decode", data: str = "",
                       binary_path: str = "", output_format: str = "json") -> str:
    """Protobuf decoder using blackboxprotobuf + protoc --decode_raw.
    Ops: decode (decode raw protobuf hex/bytes without .proto schema),
    schema_guess (guess field types and output an approximate .proto schema),
    encode (encode a dict back to protobuf bytes),
    from_file (decode a binary file as protobuf),
    decode_raw (shell to protoc --decode_raw for quick inspection)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""

    if operation == "decode_raw":
        target = f"cat '{sp}'" if sp else f"echo -n '{data}' | xxd -r -p"
        result = _shell(f"{target} | protoc --decode_raw 2>&1", timeout=10)
        if "not found" in result:
            return "protoc not installed. Install: apt install protobuf-compiler"
        return result

    if operation in ("decode", "schema_guess", "encode"):
        code = f"""
try:
    import blackboxprotobuf as bbpb
    import json, binascii

    data_str = {repr(data)}
    binary_path = {repr(sp)}

    if binary_path:
        with open(binary_path, 'rb') as f:
            raw = f.read()
    elif data_str:
        # Try hex decode first, then base64, then raw
        try:
            raw = binascii.unhexlify(data_str.replace(' ','').replace(':',''))
        except:
            import base64
            try: raw = base64.b64decode(data_str)
            except: raw = data_str.encode()
    else:
        print('Provide data= (hex/base64) or binary_path=')
        exit()

    if '{operation}' == 'encode':
        # Treat data_str as JSON dict to encode
        d = json.loads(data_str)
        encoded = bbpb.encode_message(d)
        print(f'Encoded hex: {{encoded.hex()}}')
        print(f'Encoded b64: {{__import__("base64").b64encode(encoded).decode()}}')
    else:
        message, typedef = bbpb.decode_message(raw)
        print(f'Decoded message:')
        print(json.dumps(message, indent=2, default=str))
        if '{operation}' == 'schema_guess':
            print(f'\\nInferred typedef (approximate .proto):')
            print(json.dumps(typedef, indent=2, default=str))

except ImportError:
    print('blackboxprotobuf not installed. Install: pip install blackboxprotobuf')
    # Fallback: protoc --decode_raw
    import subprocess
    r = subprocess.run(['protoc','--decode_raw'], input={repr(data)}.encode() if {repr(data)} else open({repr(sp or '/dev/null')},'rb').read(),
                       capture_output=True, timeout=10)
    print(r.stdout.decode(errors='replace') or r.stderr.decode(errors='replace'))
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "from_file":
        return tool_proto_decode("decode", binary_path=sp)

    return "Operations: decode, schema_guess, encode, from_file, decode_raw"

