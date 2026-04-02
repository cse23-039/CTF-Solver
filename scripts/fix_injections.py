"""Fix path-injection sites in tool files.

All sites use the pattern  \'  {variable}  \'  inside tool_execute_python()
code f-strings. The fix replaces  \'{var}\'  with  {repr(var)}  so that
single-quotes (and other special characters) in paths cannot break the
generated Python code.
"""

import pathlib

BASE = pathlib.Path(__file__).parent.parent / "sidecar" / "tools"


def patch(filepath: str, replacements: list[tuple[str, str]]) -> None:
    p = BASE / filepath
    text = p.read_text(encoding="utf-8")
    changed = 0
    for old, new in replacements:
        count = text.count(old)
        if count == 0:
            print(f"  [WARN] Not found in {filepath}: {old[:60]!r}")
        else:
            text = text.replace(old, new)
            changed += count
            print(f"  [OK]   {filepath}: replaced {count}x  {old[:55]!r}")
    p.write_text(text, encoding="utf-8")
    print(f"  -> {filepath}: {changed} replacement(s) applied")


# ── steg_impl.py ──────────────────────────────────────────────────────────────
patch("steg_impl.py", [
    (
        r"with wave.open(\'{audio_path}\',\'rb\')",
        "with wave.open({repr(audio_path)},'rb')",
    ),
])

# ── forensics_impl.py ─────────────────────────────────────────────────────────
patch("forensics_impl.py", [
    (
        r"data=open(\'{input_path}\',\'rb\').read()",
        "data=open({repr(input_path)},'rb').read()",
    ),
    (
        r"with wave.open(\'{audio_path}\',\'rb\')",
        "with wave.open({repr(audio_path)},'rb')",
    ),
])

# ── pwn_impl.py ───────────────────────────────────────────────────────────────
patch("pwn_impl.py", [
    # ELF calls
    (
        r"ELF(\'{binary_path}\',checksec=False)",
        "ELF({repr(binary_path)},checksec=False)",
    ),
    # safe_link_decode — enc used twice
    (
        r"enc=int(\'{enc}\',16) if \'{enc}\'.startswith(\'0x\')",
        "enc=int({repr(enc)},16) if {repr(enc)}.startswith('0x')",
    ),
    # ret2dlresolve — target_func, arg, binary_path
    (
        r"elf=ELF(\'{binary_path}\',checksec=False); context.binary=elf",
        "elf=ELF({repr(binary_path)},checksec=False); context.binary=elf",
    ),
    (
        r"dl=Ret2dlresolvePayload(elf,symbol=\'{target_func}\',args=[b\'{arg}\'])",
        "dl=Ret2dlresolvePayload(elf,symbol={repr(target_func)},args=[{repr(arg).encode() if isinstance(arg,str) else repr(arg)}])",
    ),
    # srop arch
    (
        r"context.arch=\'{arch}\'",
        "context.arch={repr(arch)}",
    ),
    # miasm Container
    (
        r"cont=Container.from_stream(open(\'{binary_path}\',\'rb\'))",
        "cont=Container.from_stream(open({repr(binary_path)},'rb'))",
    ),
    # miasm func addr — two occurrences
    (
        r"addr=int(\'{func}\',16) if \'{func}\' else cont.entry_point",
        "addr=int({repr(func)},16) if {repr(func)} else cont.entry_point",
    ),
])

# ── crypto_impl.py ────────────────────────────────────────────────────────────
patch("crypto_impl.py", [
    # ecdsa_lattice leak_type
    (
        r"leak_type=\'{leak_type}\'",
        "leak_type={repr(leak_type)}",
    ),
    # aes_gcm_attack nonce_reuse c1/c2/t1/t2
    (
        r"c1,c2=bytes.fromhex(\'{c1}\'),bytes.fromhex(\'{c2}\')",
        "c1,c2=bytes.fromhex({repr(c1)}),bytes.fromhex({repr(c2)})",
    ),
    (
        r"t1,t2=bytes.fromhex(\'{t1}\'),bytes.fromhex(\'{t2}\')",
        "t1,t2=bytes.fromhex({repr(t1)}),bytes.fromhex({repr(t2)})",
    ),
    # bleichenbacher host
    (
        r"host,port=\'{host}\',{port}",
        "host,port={repr(host)},{port}",
    ),
])

# ── web_impl.py ───────────────────────────────────────────────────────────────
patch("web_impl.py", [
    # http_smuggle host
    (
        r"host,port=\'{host}\',{port}",
        "host,port={repr(host)},{port}",
    ),
    # websocket_fuzz connect url
    (
        r"ws=websocket.WebSocketApp(\'{url}\',on_message=on_msg)",
        "ws=websocket.WebSocketApp({repr(url)},on_message=on_msg)",
    ),
    # websocket_fuzz fuzz url
    (
        r"ws=websocket.create_connection(\'{url}\',timeout=5,sslopt={'cert_reqs':0})",
        "ws=websocket.create_connection({repr(url)},timeout=5,sslopt={'cert_reqs':0})",
    ),
    # websocket_fuzz origin_bypass url
    (
        r"ws=websocket.create_connection(\'{url}\',timeout=5,header=[f'Origin: {{origin}}'],sslopt={'cert_reqs':0})",
        "ws=websocket.create_connection({repr(url)},timeout=5,header=[f'Origin: {origin}'],sslopt={'cert_reqs':0})",
    ),
    # websocket_fuzz inject url
    (
        r"ws=websocket.create_connection(\'{url}\',timeout=15,sslopt={'cert_reqs':0})",
        "ws=websocket.create_connection({repr(url)},timeout=15,sslopt={'cert_reqs':0})",
    ),
    # deserialize node command
    (
        r".exec(\'{command}\', function(e,s,_){{console.log(s)}})",
        ".exec(' + repr(command) + ', function(e,s,_){console.log(s)})",
    ),
])

print("\nDone.")
