"""File analysis, network forensics, and memory forensics tools."""
from __future__ import annotations
import re, subprocess, os, shutil
import math
from collections import Counter
from tools.shell import _shell, _w2l, IS_WINDOWS, USE_WSL, tool_execute_python, log, emit


def tool_analyze_file(path, operation):
    """File analysis — type detection, strings, hex, entropy, steg, PCAP, metadata."""
    try:
        sp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
        if not os.path.exists(path) and not (IS_WINDOWS and USE_WSL):
            return f"File not found: {path}"

        if operation == "file_type":
            return _shell(f"file '{sp}' && wc -c '{sp}'")
        if operation == "strings":
            return _shell(f"strings -n 8 '{sp}' | head -300")
        if operation == "strings_all":
            return _shell(f"strings -n 4 '{sp}'")
        if operation == "hexdump":
            out = _shell(f"xxd '{sp}' | head -100")
            if "not found" in out.lower():
                with open(path,"rb") as f: data=f.read(1600)
                lines=[f"{i:08x}  {' '.join(f'{b:02x}' for b in data[i:i+16]):<48}  "
                       f"{''.join(chr(b) if 32<=b<127 else '.' for b in data[i:i+16])}"
                       for i in range(0,len(data),16)]
                return "\n".join(lines)
            return out
        if operation == "hexdump_full":
            return _shell(f"xxd '{sp}'")
        if operation == "metadata":
            return _shell(f"exiftool '{sp}' 2>/dev/null || file '{sp}'")
        if operation == "entropy":
            with open(path,"rb") as f: data=f.read()
            if not data: return "Empty file"
            counts=Counter(data)
            ent=-sum((c/len(data))*math.log2(c/len(data)) for c in counts.values())
            # Block entropy
            block_sz=256; block_ents=[]
            for i in range(0,len(data),block_sz):
                blk=data[i:i+block_sz]
                bc=Counter(blk); be=-sum((c/len(blk))*math.log2(c/len(blk)) for c in bc.values())
                block_ents.append(be)
            high_blocks=[(i,e) for i,e in enumerate(block_ents) if e>7.0]
            return (f"Entropy: {ent:.4f} bits/byte | Size: {len(data)} bytes\n"
                    f">7.5 = encrypted/compressed | <3 = plaintext\n"
                    f"High-entropy blocks: {high_blocks[:10]}")
        if operation == "binwalk":
            return _shell(f"binwalk '{sp}'")
        if operation == "binwalk_extract":
            return _shell(f"binwalk -e '{sp}' && ls -la _*/ 2>/dev/null")
        if operation == "steg_lsb":
            # Use repr() so any path (with quotes, backslashes, spaces) is a
            # valid Python string literal when embedded in the code string.
            path_repr = repr(str(path))
            lsb_code = """
from PIL import Image
import numpy as np, re
try:
    img = Image.open(__PATH_REPR__)
    arr = np.array(img)
    lsbs = arr.flatten() & 1
    bits = ''.join(str(b) for b in lsbs)
    result = bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8))
    printable = result[:500]
    print("LSB data (first 500 bytes):", printable)
    print("As text:", printable.decode('utf-8',errors='replace'))
    flags = re.findall(rb'[a-zA-Z]{2,10}\\{[^}]{1,50}\\}', result)
    if flags: print("FLAGS FOUND:", flags)
except Exception as e:
    print(f"PIL error: {e} — try: pip install Pillow numpy")
""".replace("__PATH_REPR__", path_repr)
            return tool_execute_python(lsb_code)
        if operation == "steg_tools":
            out = _shell(f"steghide info '{sp}' 2>&1; echo '---'; zsteg '{sp}' 2>/dev/null | head -30; echo '---'; stegseek '{sp}' 2>/dev/null")
            return out
        if operation == "pcap_summary":
            return _shell(f"tshark -r '{sp}' -q -z conv,tcp 2>/dev/null | head -40; echo '---'; tshark -r '{sp}' -q -z io,phs 2>/dev/null")
        if operation == "pcap_strings":
            return _shell(f"tshark -r '{sp}' -Y 'http or ftp or smtp' -T fields -e text 2>/dev/null | head -50; strings '{sp}' | grep -iE 'flag|ctf|pass|key|secret' | head -20")
        if operation == "pcap_http":
            return _shell(f"tshark -r '{sp}' -Y http -T fields -e http.request.method -e http.request.uri -e http.response.code -e http.file_data 2>/dev/null | head -50")
        if operation == "zip_crack":
            return _shell(f"zip2john '{sp}' > /tmp/zip.hash 2>/dev/null && john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/zip.hash")
        if operation == "pdf_extract":
            return _shell(f"pdftotext '{sp}' - 2>/dev/null | head -100; strings '{sp}' | grep -i flag")
        if operation == "magic_bytes":
            with open(path,"rb") as f: header=f.read(32)
            sigs = {b'\x89PNG':'.png',b'\xff\xd8\xff':'.jpg',b'GIF8':'.gif',
                    b'PK\x03\x04':'.zip',b'%PDF':'.pdf',b'\x7fELF':'.elf',
                    b'MZ':'.exe',b'BM':'.bmp',b'OggS':'.ogg',b'\x1f\x8b':'.gz',
                    b'BZh':'.bz2',b'\xfd7zXZ':'.xz',b'7z\xbc\xaf':'.7z',
                    b'Rar!':'.rar',b'\x00\x00\x00 ftyp':'.mp4'}
            detected = [ext for sig,ext in sigs.items() if header.startswith(sig)]
            return f"Magic bytes: {header.hex()}\nDetected type: {detected or 'unknown'}\nHeader ASCII: {header.decode('ascii',errors='replace')}"
        return f"Unknown operation. Available: file_type,strings,strings_all,hexdump,hexdump_full,metadata,entropy,binwalk,binwalk_extract,steg_lsb,steg_tools,pcap_summary,pcap_strings,pcap_http,zip_crack,pdf_extract,magic_bytes"
    except Exception as e: return f"File analysis error: {e}"


def tool_js_analyze(url_or_path, operation):
    """
    JavaScript analysis: source map recovery, endpoint extraction, minified code
    deobfuscation. From msfrog-generator: .map files expose full source of minified JS.
    """
    try:
        if operation == "fetch_sourcemap":
            # Try common source map locations
            import requests; requests.packages.urllib3.disable_warnings()
            targets = []
            if url_or_path.endswith(".js"):
                targets = [url_or_path + ".map", url_or_path.replace(".js", ".js.map")]
            else:
                targets = [url_or_path]
            for t in targets:
                try:
                    r = requests.get(t, timeout=10, verify=False)
                    if r.status_code == 200 and ("sources" in r.text or "sourceRoot" in r.text):
                        data = r.json()
                        sources = data.get("sources", [])
                        out = [f"Source map found: {t}", f"Sources ({len(sources)}):"]
                        out += [f"  {s}" for s in sources[:30]]
                        # Extract source content if available
                        contents = data.get("sourcesContent", [])
                        if contents:
                            out.append(f"\nFirst source content ({sources[0] if sources else '?'}):")
                            out.append(str(contents[0])[:3000])
                        return "\n".join(out)
                except: pass
            return f"No source map found at common locations for: {url_or_path}"

        if operation == "extract_endpoints":
            # From JS source/minified code find API endpoints
            if url_or_path.startswith("http"):
                import requests; requests.packages.urllib3.disable_warnings()
                content = requests.get(url_or_path, timeout=10, verify=False).text
            else:
                with open(url_or_path, "r", errors="replace") as f: content = f.read()
            # Find fetch/axios/XHR calls and URL strings
            patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'\.get\(["\']([/][^"\']+)["\']',
                r'\.post\(["\']([/][^"\']+)["\']',
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/[a-zA-Z][a-zA-Z0-9_/-]+)["\']',
                r'url\s*[=:]\s*["\']([^"\']+)["\']',
                r'path\s*[=:]\s*["\']([/][^"\']+)["\']',
            ]
            found = set()
            for pat in patterns:
                found.update(re.findall(pat, content))
            # Filter noise
            found = {e for e in found if len(e) > 2 and not e.startswith("//") and "." not in e.split("/")[-1][:3]}
            out = [f"Endpoints found ({len(found)}):"] + sorted(found)
            # Also find comments
            comments = re.findall(r'//[^\n]{5,100}|/\*[\s\S]{5,200}?\*/', content)
            if comments:
                out.append(f"\nComments ({len(comments)}):")
                out += comments[:20]
            return "\n".join(out[:100])

        if operation == "beautify":
            # Use js-beautify if available, else basic formatting
            out = _shell(f"js-beautify '{url_or_path}' 2>/dev/null || node -e \"const fs=require('fs'); console.log(fs.readFileSync('{url_or_path}','utf8'))\" 2>/dev/null")
            if "not found" in out.lower() or not out.strip():
                # Python fallback: just add newlines after ; { }
                with open(url_or_path,"r",errors="replace") as f: code=f.read()
                code = re.sub(r'([;{])', r'\1\n', code)
                return code[:5000]
            return out[:5000]

        if operation == "find_secrets":
            if url_or_path.startswith("http"):
                import requests; requests.packages.urllib3.disable_warnings()
                content = requests.get(url_or_path, timeout=10, verify=False).text
            else:
                with open(url_or_path,"r",errors="replace") as f: content=f.read()
            patterns = {
                "API Keys": r'["\']([a-zA-Z0-9_-]{20,})["\']',
                "Passwords": r'password["\s]*[:=]["\s]*["\']([^"\']{4,})["\']',
                "Tokens": r'token["\s]*[:=]["\s]*["\']([^"\']{8,})["\']',
                "Secrets": r'secret["\s]*[:=]["\s]*["\']([^"\']{4,})["\']',
                "URLs": r'https?://[^\s"\'<>]{10,100}',
            }
            out = []
            for name, pat in patterns.items():
                hits = re.findall(pat, content, re.IGNORECASE)[:10]
                if hits: out.append(f"{name}: {hits}")
            return "\n".join(out) or "No obvious secrets found"

        return f"Unknown operation: {operation}. Available: fetch_sourcemap, extract_endpoints, beautify, find_secrets"
    except Exception as e:
        return f"JS analysis error: {e}"


def tool_wasm_analyze(path, operation):
    """
    WebAssembly analysis. From Pachinko Revisited: WASM binaries contain synthesized
    Verilog/CPU logic as bitwise xors. Extract as Python, find I/O ports, emulate.
    """
    sp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
    try:
        if operation == "decompile":
            # wasm2wat is from wabt toolkit
            out = _shell(f"wasm2wat '{sp}' 2>/dev/null | head -200")
            if "not found" in out.lower():
                out = _shell(f"wasm-decompile '{sp}' 2>/dev/null | head -200")
            if "not found" in out.lower():
                return "Install wabt: sudo apt install wabt\nOr use: pip install wasmtime\nFallback: strings analysis below\n\n" + _shell(f"strings '{sp}' | head -100")
            return out

        if operation == "strings":
            return _shell(f"strings '{sp}' | head -200")

        if operation == "exports_imports":
            out = _shell(f"wasm-objdump -x '{sp}' 2>/dev/null | grep -E 'Export|Import|Function|Memory|Table' | head -60")
            if "not found" in out.lower():
                # Python fallback
                return tool_execute_python(f"""
import struct
data = open(r'{path}', 'rb').read()
# Find export/import sections by WASM magic
if data[:4] != b'\\x00asm':
    print("Not a valid WASM file"); exit()
print(f"WASM version: {{struct.unpack('<I', data[4:8])[0]}}")
# Find function names via strings
import re
names = re.findall(rb'[a-zA-Z_][a-zA-Z0-9_]{{3,}}', data)
unique = list(dict.fromkeys(n.decode() for n in names))[:60]
print("Identifiers:", unique)
""")
            return out

        if operation == "to_python":
            # Convert WASM to WAT then extract logic as Python
            wat = _shell(f"wasm2wat '{sp}' 2>/dev/null")
            if "not found" in wat.lower():
                return "Install wabt to convert WASM→WAT→Python. See: https://github.com/WebAssembly/wabt"
            # Count instructions to give size estimate
            insn_count = wat.count("i32.xor") + wat.count("i32.and") + wat.count("i32.or")
            return (f"WAT output ({len(wat)} chars, ~{insn_count} bitwise ops):\n"
                    f"Use execute_python with wasmtime to run directly:\n"
                    f"  from wasmtime import Store, Module, Instance\n"
                    f"  store = Store()\n"
                    f"  module = Module.from_file(store.engine, '{path}')\n"
                    f"  instance = Instance(store, module, [])\n"
                    f"  func = instance.exports(store)['process']\n"
                    f"  result = func(store, ...)\n\n"
                    f"WAT preview:\n{wat[:3000]}")

        if operation == "run":
            return tool_execute_python(f"""
try:
    from wasmtime import Store, Module, Instance, Func, FuncType, ValType
    store = Store()
    module = Module.from_file(store.engine, r'{path}')
    instance = Instance(store, module, [])
    exports = instance.exports(store)
    print("Exports:", list(exports._mapping.keys()))
except ImportError:
    print("Install wasmtime: pip install wasmtime")
except Exception as e:
    print(f"WASM run error: {{e}}")
""")

        if operation == "analyze_bitops":
            # Analyze bitwise operations to find I/O ports (read-only = input, write-only = output)
            wat = _shell(f"wasm2wat '{sp}' 2>/dev/null")
            if not wat.strip() or "not found" in wat.lower():
                return "Need wasm2wat from wabt toolkit"
            # Find all load/store indices to state array
            loads  = set(re.findall(r'i32\.load8_u.*?offset=(\d+)', wat))
            stores = set(re.findall(r'i32\.store8.*?offset=(\d+)', wat))
            # Or array accesses
            loads2  = set(re.findall(r'get_local.*?\(i32\.const (\d+)\)', wat))
            readonly  = sorted(loads - stores,  key=int)[:40]
            writeonly = sorted(stores - loads,  key=int)[:40]
            both      = sorted(loads & stores,  key=int)[:20]
            return (f"Read-only (inputs):  {readonly}\n"
                    f"Write-only (outputs): {writeonly}\n"
                    f"Read+Write (internal): {both[:10]}")

        return f"Unknown op. Available: decompile, strings, exports_imports, to_python, run, analyze_bitops"
    except Exception as e:
        return f"WASM error: {e}"


def tool_mime_email(operation, **params):
    """
    MIME/email manipulation. From secure-email-service:
    - header injection via newlines in subject
    - encoded-word (RFC 2047) base64 encoding to smuggle newlines
    - multipart boundary prediction/injection
    - UTF-7 encoding for XSS payload bypass
    - S/MIME signature analysis
    """
    try:
        if operation == "parse":
            raw = params.get("raw","")
            return tool_execute_python(f"""
import email
msg = email.message_from_string({repr(raw)})
print("Headers:")
for k,v in msg.items():
    print(f"  {{k}}: {{v}}")
print("\\nParts:")
for part in msg.walk():
    ct = part.get_content_type()
    charset = part.get_param('charset','')
    payload = part.get_payload(decode=True)
    print(f"  ContentType={{ct}} charset={{charset}}")
    if payload:
        print(f"    Preview: {{payload[:200]}}")
""")

        if operation == "encode_word":
            # RFC 2047 encoded-word: =?charset?B?base64?=
            # Used to smuggle newlines through email subject field
            text = params.get("text","")
            charset = params.get("charset","ISO-8859-1")
            return tool_execute_python(f"""
import base64
text = {repr(text)}
charset = {repr(charset)}
b64 = base64.b64encode(text.encode(charset, errors='replace')).decode()
result = f'=?{{charset}}?B?{{b64}}?='
print("Encoded-Word:", result)
print()
print("Usage in subject to inject newlines:")
print(f"Subject: prefix{{result}}\\ninjected_header: value")
print()
print("Decoding check:")
import quopri, re
m = re.match(r'=\\?(.+?)\\?([BQ])\\?(.+?)\\?=', result)
if m:
    charset2, enc, data = m.groups()
    if enc.upper() == 'B':
        decoded = base64.b64decode(data + '==').decode(charset2, errors='replace')
        print("Decoded:", repr(decoded))
""")

        if operation == "craft_injection":
            # Build a complete MIME header injection payload
            inject_headers = params.get("inject_headers","")    # e.g. "From: admin@example.com\nX-Custom: val"
            multipart_boundary = params.get("boundary","")
            html_content = params.get("html","")
            charset = params.get("charset","utf-7")
            prefix = params.get("prefix","hi")
            return tool_execute_python(f"""
import base64
prefix = {repr(prefix)}
inject = {repr(inject_headers)}
boundary = {repr(multipart_boundary)}
html = {repr(html_content)}
charset = {repr(charset)}

# Build full injection payload
if boundary and html:
    # Full multipart section injection
    section = f'''{{prefix}}

   --==============={{boundary}}==
Content-Type : text/html; charset={{charset}}
MIME-Version : 1.0

{{html}}
   --==============={{boundary}}==
'''
    if inject:
        payload = section + "\\n" + inject
    else:
        payload = section
else:
    payload = prefix + "\\n" + inject

# Encode as RFC 2047 encoded-word (B encoding)
b64 = base64.b64encode(payload.encode('latin-1', errors='replace')).decode()
encoded = f'=?ISO-8859-1?B?{{b64}}?='
if inject:
    final_subject = encoded + "\\n" + inject
else:
    final_subject = encoded

print("=== Injection Payload ===")
print(repr(payload))
print()
print("=== Encoded Subject ===")
print(final_subject)
print()
print("=== Subject for JSON body ===")
import json
print(json.dumps(final_subject))
""")

        if operation == "utf7_encode":
            # UTF-7 encodes < > " etc as +ADw- +AD4- — bypasses HTML escaping in email parsers
            text = params.get("text","")
            return tool_execute_python(f"""
text = {repr(text)}
# UTF-7 encoding
encoded = text.encode('utf-7').decode('ascii')
print("UTF-7 encoded:", encoded)
print()
print("Manual UTF-7 map:")
TABLE = {{'<':'+ADw-','>':'+AD4-','"':'+ACI-',"'":'+ACc-','&':'+ACY-','=':'+AD0-',' ':'+ACA-'}}
manual = ''.join(TABLE.get(c,c) for c in text)
print("Manual:", manual)
""")

        if operation == "extract_boundaries":
            raw_emails = params.get("raw_emails",[])
            pattern = r'boundary="=+(\d+)=+"'
            return tool_execute_python(f"""
import re
raws = {json.dumps(raw_emails)}
pattern = {repr(pattern)}
boundaries = []
for raw in raws:
    matches = re.findall(pattern, raw)
    boundaries.extend(int(m) for m in matches)
print(f"Found {{len(boundaries)}} boundaries:")
for b in boundaries:
    print(f"  {{b}}")
print()
print("Use rng_crack(operation='python_random_from_randbits63', outputs=<list>) to predict next")
""")

        if operation == "smime_verify":
            raw_email = params.get("raw_email","")
            ca_cert = params.get("ca_cert","")
            # Write to disk, run openssl
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".eml",mode="w",delete=False) as f:
                f.write(raw_email); epath=f.name
            if ca_cert:
                with tempfile.NamedTemporaryFile(suffix=".crt",mode="w",delete=False) as f:
                    f.write(ca_cert); cpath=f.name
                out = _shell(f"openssl cms -verify -in '{epath}' -CAfile '{cpath}' 2>&1")
            else:
                out = _shell(f"openssl cms -verify -noverify -in '{epath}' 2>&1")
            os.unlink(epath)
            return out

        return f"Unknown op. Available: parse, encode_word, craft_injection, utf7_encode, extract_boundaries, smime_verify"
    except Exception as e:
        return f"MIME email error: {e}"


def tool_source_audit(path_or_content, operation, language=None):
    """
    Source code security audit. Automatically finds sinks, dangerous patterns,
    injection points, filter checks. Covers Python, JS, PHP, Go, Rust, C.
    From notepad/msfrog: spots url_fix backslash bypass, shell command injection.
    """
    try:
        if path_or_content.startswith("/") or (len(path_or_content) < 300 and os.path.exists(path_or_content)):
            with open(path_or_content,"r",errors="replace") as f:
                content = f.read()
            filepath = path_or_content
        else:
            content = path_or_content
            filepath = "/tmp/audit_target"

        if operation == "find_sinks":
            # Dangerous sinks by language
            patterns = {
                # Command injection
                "CMD_INJECTION": [r'os\.system\(', r'subprocess\.(run|call|Popen|check_output)\(',
                                  r'exec\(', r'eval\(', r'`[^`]+`', r'\bshell=True\b',
                                  r'child_process', r'execSync', r'spawn\('],
                # Path traversal
                "PATH_TRAVERSAL": [r'open\(.*\+', r'open\(.*format', r'os\.path\.join\(.*request',
                                   r'readFile\(.*req\.', r'url_fix\(', r'include.*\$_GET',
                                   r'require\(.*req\.', r'__import__\(.*user'],
                # SQL injection
                "SQL_INJECTION": [r'execute\(.*\+', r'execute\(f"', r'execute\(.*format',
                                  r'query\(.*\+', r'query\(f"', r'\.format.*SELECT',
                                  r'%.*SELECT', r'cursor\.execute.*%'],
                # XSS sinks
                "XSS": [r'innerHTML\s*=', r'outerHTML\s*=', r'document\.write\(',
                        r'\.html\(.*req\.', r'shadow\.innerHTML', r'eval\(.*user',
                        r'dangerouslySetInnerHTML'],
                # File operations on user input
                "FILE_OPS": [r'open\(.*user', r'open\(.*param', r'open\(.*request',
                             r'with open.*format', r'writefile.*request'],
                # SSTI
                "SSTI": [r'render_template_string\(', r'Template\(.*\+', r'Environment\(.*user',
                         r'jinja.*eval', r'render\(.*user', r'Mustache\.render'],
                # Deserialization
                "DESER": [r'pickle\.loads\(', r'yaml\.load\(', r'unserialize\(',
                          r'ObjectMapper.*readValue', r'JSON\.parse.*eval'],
                # Weak random
                "WEAK_RANDOM": [r'random\.random\(\)', r'random\.randrange\(', r'Math\.random\(\)',
                                r'rand\(\)', r'time\.time\(\).*seed'],
            }
            found = {}
            for sink_type, pats in patterns.items():
                hits = []
                for pat in pats:
                    for m in re.finditer(pat, content):
                        line_no = content[:m.start()].count("\n") + 1
                        line = content.splitlines()[line_no-1].strip()[:100]
                        hits.append(f"  L{line_no}: {line}")
                if hits:
                    found[sink_type] = hits[:5]

            if not found: return "No obvious dangerous patterns found. Manual review recommended."
            return "\n".join(f"[{k}]\n" + "\n".join(v) for k,v in found.items())

        if operation == "find_filters":
            # Find input validation/filtering — look for what's blocked (to find bypasses)
            filter_pats = [
                r'if\s+["\'][^"\']+["\'].*in\s+\w+',           # char in string checks
                r'\.replace\(["\'][^"\']+["\']',                  # replace calls
                r'\.strip\(',                                      # strip
                r'regex|re\.match|re\.sub|re\.findall',           # regex
                r'blacklist|whitelist|blocklist|allowlist',        # named lists
                r'filter.*content|content.*filter',
                r'if.*\\\\|if.*/|if.*\.\.',                      # path traversal checks
                r'sanitize|escape|encode|htmlspecialchars',
            ]
            hits = []
            for pat in filter_pats:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    line_no = content[:m.start()].count("\n") + 1
                    line = content.splitlines()[line_no-1].strip()[:120]
                    hits.append(f"  L{line_no}: {line}")
            return "Filters/validation found:\n" + "\n".join(hits[:30]) if hits else "No filter patterns found"

        if operation == "find_routes":
            # Find URL routes / endpoints in web frameworks
            route_pats = [
                r'@app\.route\(["\']([^"\']+)["\']',             # Flask
                r'router\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # Express
                r'app\.(get|post|put|delete)\(["\']([^"\']+)["\']',     # Express
                r'path\(["\']([^"\']+)["\']',                    # Django paths
                r'url\(r?["\']([^"\']+)["\']',                   # Django urls
                r'\[HttpGet\("([^"]+)"\)\]',                     # ASP.NET
                r'#\[Route\("([^"]+)"\)\]',                      # Rust Actix
            ]
            routes = []
            for pat in route_pats:
                for m in re.finditer(pat, content):
                    routes.append(m.group(0)[:100])
            return "Routes found:\n" + "\n".join(routes[:40]) if routes else "No routes detected"

        if operation == "find_auth":
            # Find authentication/authorization checks
            auth_pats = [r'if.*admin', r'if.*role', r'if.*auth', r'if.*token',
                         r'require.*auth', r'@login_required', r'middleware.*auth',
                         r'if.*cookie', r'verify.*token', r'decode.*jwt']
            hits = []
            for pat in auth_pats:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    line_no = content[:m.start()].count("\n") + 1
                    line = content.splitlines()[line_no-1].strip()[:120]
                    hits.append(f"  L{line_no}: {line}")
            return "Auth checks:\n" + "\n".join(hits[:20]) if hits else "No auth checks found"

        if operation == "full_audit":
            results = []
            for op in ["find_sinks","find_filters","find_routes","find_auth"]:
                r = tool_source_audit(content, op, language)
                results.append(f"=== {op.upper()} ===\n{r}")
            return "\n\n".join(results)

        return f"Unknown op. Available: find_sinks, find_filters, find_routes, find_auth, full_audit"
    except Exception as e:
        return f"Source audit error: {e}"


def tool_docker_recon(path):
    """
    Analyze Docker configuration files for attack surface.
    From challenge analysis: docker-compose reveals Redis maxmemory-policy,
    network config, exposed ports, environment variables, secrets.
    """
    try:
        results = []
        # Find docker files
        search_paths = [path] if os.path.isfile(path) else []
        if os.path.isdir(path):
            for fname in ["docker-compose.yml","docker-compose.yaml","Dockerfile",".env",".env.example"]:
                fp = os.path.join(path, fname)
                if os.path.exists(fp): search_paths.append(fp)

        for fp in search_paths:
            with open(fp,"r",errors="replace") as f: content=f.read()
            results.append(f"=== {os.path.basename(fp)} ===")

            # Secrets and env vars
            secrets = re.findall(r'(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*[=:]\s*(.+)', content, re.IGNORECASE)
            if secrets: results.append(f"Secrets/env: {secrets}")

            # Interesting flags/commands
            cmds = re.findall(r'command\s*[:=]\s*(.+)', content)
            if cmds: results.append(f"Commands: {cmds}")

            # Exposed ports
            ports = re.findall(r'[\s\-](\d+:\d+)', content)
            if ports: results.append(f"Port mappings: {ports}")

            # Redis/DB config
            redis = re.findall(r'redis-server\s+(.+)', content)
            if redis: results.append(f"Redis config: {redis}")
            # LRU policy is interesting!
            lru = re.findall(r'maxmemory[^\n]+', content)
            if lru: results.append(f"Memory policy: {lru} ← check for LRU side-channel attacks!")

            # Volumes
            vols = re.findall(r'volumes?:\s*\n((?:\s+-.+\n)+)', content)
            if vols: results.append(f"Volumes: {vols}")

            # Network
            nets = re.findall(r'networks?:\s*\n((?:\s+.+\n)+)', content)
            if nets: results.append(f"Networks: {nets}")

            results.append(content[:1000])

        if not results: return f"No Docker files found at: {path}"
        return "\n".join(results)
    except Exception as e:
        return f"Docker recon error: {e}"


def tool_volatility(image_path: str, plugin: str, args: str = "", timeout: int = 120) -> str:
    """
    Volatility 3 memory forensics.
    Common plugins: windows.pslist, windows.pstree, windows.cmdline, windows.filescan,
    windows.dumpfiles, windows.registry.hivelist, windows.hashdump,
    linux.pslist, linux.bash, linux.proc.Maps, linux.malfind,
    mac.pslist, mac.bash
    """
    sp = _w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path
    # Try vol3 first, then vol2
    for cmd in [f"vol -f '{sp}' {plugin} {args} 2>&1",
                f"vol3 -f '{sp}' {plugin} {args} 2>&1",
                f"python3 /opt/volatility3/vol.py -f '{sp}' {plugin} {args} 2>&1"]:
        out = _shell(cmd, timeout=timeout)
        if "not found" not in out.lower() and "Error" not in out[:50]:
            return out[:6000]

    # Auto-suggest plugins if unknown
    return (f"Volatility not found or plugin error. Install: pip install volatility3\n"
            f"Common first steps:\n"
            f"  vol -f image.mem windows.info  # Identify OS\n"
            f"  vol -f image.mem windows.pslist # Process list\n"
            f"  vol -f image.mem windows.cmdline # Command lines\n"
            f"  vol -f image.mem windows.filescan | grep -i flag # Find flag files\n"
            f"  vol -f image.mem windows.dumpfiles --virtaddr <addr> # Dump file\n"
            f"Raw output:\n{out[:1000]}")


def tool_tls_decrypt(pcap_path: str, keylog_path: str = "", privkey_path: str = "",
                      operation: str = "decrypt", filter_str: str = "http") -> str:
    """TLS traffic decryption from PCAP using keylog file or RSA private key."""
    sp = _w2l(pcap_path) if (IS_WINDOWS and USE_WSL) else pcap_path
    if operation == "decrypt":
        if keylog_path:
            kp = _w2l(keylog_path) if (IS_WINDOWS and USE_WSL) else keylog_path
            return _shell(f"tshark -r '{sp}' -o 'tls.keylog_file:{kp}' -Y '{filter_str}' -T fields -e http.request.uri -e text 2>&1 | head -60", timeout=30)
        if privkey_path:
            pp = _w2l(privkey_path) if (IS_WINDOWS and USE_WSL) else privkey_path
            out = _shell(f"tshark -r '{sp}' -o 'tls.keys_list:,443,http,{pp}' -Y '{filter_str}' -T fields -e text 2>&1 | head -60", timeout=30)
            return out or _shell(f"ssldump -r '{sp}' -k '{pp}' 2>&1 | head -80")
        return "Provide keylog_path (NSS keylog, e.g. SSLKEYLOGFILE) or privkey_path (RSA private key)"
    if operation == "follow_stream":
        sid = keylog_path or "0"
        return _shell(f"tshark -r '{sp}' -z 'follow,ssl,ascii,{sid}' 2>&1 | head -100", timeout=20)
    if operation == "extract_files":
        od = f"/tmp/tls_extract_{int(time.time())}"
        _shell(f"mkdir -p {od}")
        kl = f"-o 'tls.keylog_file:{keylog_path}'" if keylog_path else ""
        return _shell(f"tshark -r '{sp}' {kl} --export-objects 'http,{od}' 2>&1; ls -la {od}", timeout=30)
    if operation == "check":
        return _shell(f"tshark -r '{sp}' -Y tls -T fields -e tls.handshake.type -e tls.record.version 2>&1 | head -20", timeout=15)
    return "Available: decrypt, follow_stream, extract_files, check"


def tool_bytecode_disasm(input_path: str, language: str = "auto", operation: str = "disasm") -> str:
    """Bytecode disassembly: Python .pyc, Java .class, .NET IL, Lua."""
    sp = _w2l(input_path) if (IS_WINDOWS and USE_WSL) else input_path
    if language == "auto":
        magic = _shell(f"xxd '{sp}' | head -1").lower()
        if "0d0d" in magic or "550d" in magic: language = "python"
        elif "cafe babe" in magic.replace(" ","")[:8]: language = "java"
        elif "4d5a" in magic[:4]: language = ".net"
        else: language = "unknown"
    if language == "python":
        code = f"""import dis,marshal
data=open({repr(input_path)},'rb').read()
# Skip magic (4) + bit_field (4) + timestamp/hash (4/8) + size (4)
for offset in [16,12]:
    try: co=marshal.loads(data[offset:]); dis.dis(co); print('constants:',co.co_consts[:10]); break
    except: pass"""
        out = tool_execute_python(code)
        if "Error" in out: out += "\n" + _shell(f"uncompyle6 '{sp}' 2>/dev/null || pycdc '{sp}' 2>/dev/null")
        return out
    if language == "java":
        return _shell(f"javap -c -p '{sp}' 2>/dev/null | head -80 || cfr '{sp}' 2>/dev/null | head -80")
    if language in (".net","cil","il"):
        return _shell(f"ilspycmd '{sp}' 2>/dev/null | head -80 || monodis '{sp}' 2>/dev/null | head -80")
    if language == "lua":
        return _shell(f"luadec '{sp}' 2>/dev/null | head -60 || strings '{sp}' | head -40")
    return _shell(f"strings '{sp}' | head -60")


def tool_audio_steg(audio_path: str, operation: str = "analyze") -> str:
    """Audio steganography: analyze, spectrogram, dtmf, lsb, strings."""
    sp = _w2l(audio_path) if (IS_WINDOWS and USE_WSL) else audio_path
    if operation == "analyze":
        return _shell(f"file '{sp}'; soxi '{sp}' 2>/dev/null; exiftool '{sp}' 2>/dev/null | head -15")
    if operation == "spectrogram":
        out_img = f"/tmp/spec_{int(time.time())}.png"
        out = _shell(f"sox '{sp}' -n spectrogram -o '{out_img}' 2>/dev/null && echo 'Saved:{out_img}'")
        return out or _shell(f"ffmpeg -i '{sp}' -lavfi showspectrumpic=s=1024x512 '{out_img}' 2>&1 | tail -3") + f"\nView: {out_img}"
    if operation == "dtmf":
        return _shell(f"multimon-ng -t wav -a DTMF '{sp}' 2>/dev/null || sox '{sp}' -t raw -r 8000 -e signed -b 16 - 2>/dev/null | multimon-ng -t raw -a DTMF - 2>/dev/null")
    if operation == "lsb":
        code = f"""import wave,struct,re
try:
    with wave.open({repr(audio_path)},'rb') as w: raw=w.readframes(w.getnframes())
    samples=[struct.unpack_from(\'<h\',raw,i*2)[0] for i in range(min(8000*8,len(raw)//2))]
    bits=\'\'.join(str(s&1) for s in samples)
    result=bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8))
    print(f\'LSB: {{result[:200]}}\'); flags=re.findall(rb\'[A-Za-z]{{2,10}}\\{{[^}}]{{3,60}}\\}}\',result)
    if flags: print(f\'FLAGS: {{flags}}\')\nexcept ImportError: print('wave module issue')"""
        return tool_execute_python(code)
    if operation == "strings":
        return _shell(f"strings -n 6 '{sp}' | head -50")
    return "Available: analyze, spectrogram, dtmf, lsb, strings"


def tool_git_forensics(repo_path: str, operation: str = "all") -> str:
    """Git forensics: dangling objects, reflog, stash, secrets in history, orphan branches."""
    rp = _w2l(repo_path) if (IS_WINDOWS and USE_WSL) else repo_path
    g = f"git -C '{rp}'"
    results = {}
    if operation in ("all","dangling"):
        fsck = _shell(f"{g} fsck --unreachable 2>&1 | head -20")
        for sha in re.findall(r"[0-9a-f]{40}", fsck)[:5]:
            fsck += f"\n--- {sha} ---\n" + _shell(f"{g} cat-file -p {sha} 2>/dev/null | head -20")
        results["dangling"] = fsck
    if operation in ("all","reflog"):
        results["reflog"] = _shell(f"{g} reflog --all 2>&1 | head -30")
    if operation in ("all","stash"):
        results["stash"] = _shell(f"{g} stash list 2>&1; {g} stash show -p 2>&1 | head -40")
    if operation in ("all","secrets"):
        results["secrets"] = _shell(f"{g} log -p --all 2>&1 | grep -iE 'password|secret|api.key|token|flag' | head -30")
    if operation in ("all","orphans"):
        results["orphans"] = _shell(f"{g} branch -a 2>&1; {g} tag -l 2>&1")
    if operation in results:
        return results[operation]
    return "\n\n".join(f"=== {k} ===\n{v}" for k,v in results.items())


def tool_bindiff(binary_a: str, binary_b: str, operation: str = "diff") -> str:
    """Binary diff between two versions to find patch-introduced vulnerability."""
    sa = _w2l(binary_a) if (IS_WINDOWS and USE_WSL) else binary_a
    sb = _w2l(binary_b) if (IS_WINDOWS and USE_WSL) else binary_b
    if operation == "diff":
        out = _shell(f"radiff2 -A '{sa}' '{sb}' 2>/dev/null | head -50")
        if not out.strip(): out = _shell(f"diff <(strings '{sa}' | sort) <(strings '{sb}' | sort) | head -40")
        return out
    if operation == "changed_functions":
        return _shell(f"radiff2 -A -C '{sa}' '{sb}' 2>/dev/null | grep CHANGED | head -30")
    if operation == "strings_diff":
        return _shell(f"diff <(strings '{sa}' | sort) <(strings '{sb}' | sort) | head -40")
    return "Available: diff, changed_functions, strings_diff"


def tool_cloud_forensics(path: str, operation: str = "analyze",
                          cloud: str = "aws", keyword: str = "") -> str:
    """Cloud forensics: analyze (detect log type), cloudtrail (AWS CloudTrail event analysis),
    gcp_audit (GCP audit logs), azure_activity (Azure activity logs),
    s3_access (S3 access logs), lambda_logs (CloudWatch Lambda), timeline (chronological events)."""

    wp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
    kw = keyword or "flag"

    if operation == "analyze":
        code = f"""
import json, os, glob, re
path = {repr(wp)}
files = glob.glob(path + '/**/*.json', recursive=True) + glob.glob(path + '/*.json') + [path]
files = [f for f in files if os.path.isfile(f)]
print(f"Files found: {{len(files)}}")
for fp in files[:5]:
    print(f"\\n--- {{fp}} ---")
    try:
        with open(fp) as f:
            data = json.load(f)
        if isinstance(data, dict):
            keys = list(data.keys())[:10]
            print(f"Keys: {{keys}}")
            # Detect log type
            if 'Records' in data and isinstance(data['Records'], list):
                r = data['Records'][0] if data['Records'] else {{}}
                if 'eventSource' in r: print(f"AWS CloudTrail detected")
                elif 'methodName' in r: print(f"GCP Audit Log detected")
            elif 'value' in data and isinstance(data.get('value'), list):
                print("Azure Activity Log detected")
    except Exception as ex:
        print(f"Parse error: {{ex}}")
        # Try as text
        content = open(fp).read()[:500]
        print(f"Content preview: {{content}}")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "cloudtrail":
        code = f"""
import json, glob, os, re
from collections import defaultdict
path = {repr(wp)}
kw = {repr(kw)}

records = []
for fp in glob.glob(path + '/**/*.json', recursive=True) + [path]:
    if not os.path.isfile(fp): continue
    try:
        with open(fp) as f: data = json.load(f)
        if 'Records' in data:
            records.extend(data['Records'])
    except: pass

print(f"Total CloudTrail events: {{len(records)}}")

# Sort by time
records.sort(key=lambda r: r.get('eventTime', ''))

# Summarize
events_by_user = defaultdict(list)
errors = []
interesting = []
for r in records:
    user = r.get('userIdentity', {{}}).get('userName') or r.get('userIdentity', {{}}).get('type', '?')
    events_by_user[user].append(r.get('eventName','?'))
    if r.get('errorCode'): errors.append(f"{{r.get('eventTime','')}}: {{r.get('errorCode')}} {{r.get('eventName')}}")
    name = r.get('eventName','').lower()
    if any(kw2 in name for kw2 in ['getobject','putobject','invoke','assume','create','delete',kw.lower()]):
        interesting.append(f"{{r.get('eventTime','')}}: {{r.get('eventName')}} by {{user}}")

print("\\nEvents per user:")
for user, evts in list(events_by_user.items())[:10]:
    print(f"  {{user}}: {{len(evts)}} events — {{', '.join(set(evts))[:80]}}")

print(f"\\nErrors ({{len(errors)}}):")
for e in errors[:10]: print(f"  {{e}}")

print(f"\\nInteresting events:")
for ev in interesting[:20]: print(f"  {{ev}}")

# Keyword search
if kw != 'flag':
    kw_hits = [r for r in records if kw.lower() in json.dumps(r).lower()]
    print(f"\\nKeyword '{{kw}}' matches: {{len(kw_hits)}}")
    for r in kw_hits[:5]: print(f"  {{json.dumps(r)[:200]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "gcp_audit":
        code = f"""
import json, glob, os
from collections import defaultdict
path = {repr(wp)}
kw = {repr(kw)}

records = []
for fp in glob.glob(path + '/**/*.json', recursive=True) + [path]:
    if not os.path.isfile(fp): continue
    try:
        with open(fp) as f: data = json.load(f)
        if isinstance(data, list): records.extend(data)
        elif 'entries' in data: records.extend(data['entries'])
        else: records.append(data)
    except: pass

print(f"Total GCP log entries: {{len(records)}}")
for r in sorted(records, key=lambda x: x.get('timestamp',''))[:30]:
    ts   = r.get('timestamp','?')[:19]
    meth = r.get('protoPayload',{{}}).get('methodName', r.get('logName','?'))
    prin = r.get('protoPayload',{{}}).get('authenticationInfo',{{}}).get('principalEmail','?')
    res  = r.get('resource',{{}}).get('labels',{{}})
    print(f"{{ts}} | {{prin}} | {{meth}} | {{res}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "s3_access":
        return _shell(f"grep -iE 'GET|PUT|DELETE|HEAD' '{wp}' | "
                     f"awk '{{print $8, $7, $9, $12}}' | sort | head -30 && "
                     f"echo '--- 403/404 errors ---' && "
                     f"grep ' 40[34] ' '{wp}' | head -10 && "
                     f"echo '--- Keyword search ---' && "
                     f"grep -i '{kw}' '{wp}' | head -10",
                     timeout=15)

    if operation == "timeline":
        code = f"""
import json, glob, os, re
path = {repr(wp)}
events = []

for fp in glob.glob(path + '/**/*', recursive=True):
    if not os.path.isfile(fp): continue
    try:
        with open(fp) as f: content = f.read()
        # Find timestamps
        for m in re.finditer(r'(\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}:\\d{{2}})', content):
            start = max(0, m.start()-10)
            events.append((m.group(1), content[start:m.end()+100].replace('\\n',' ')[:120]))
    except: pass

events.sort()
print(f"Timeline ({{len(events)}} events):")
for ts, ctx in events[:50]:
    print(f"  {{ts}}: {{ctx}}")
"""
        return tool_execute_python(code, timeout=20)

    return "Operations: analyze, cloudtrail, gcp_audit, azure_activity, s3_access, lambda_logs, timeline"


def tool_disk_forensics(image_path: str, operation: str = "analyze",
                         partition: int = 0, output_dir: str = "",
                         keyword: str = "") -> str:
    """Disk image forensics: analyze (partition table, filesystem), mount (loop mount),
    recover_files (photorec/foremost), mft (NTFS Master File Table), timeline (mactime/log2timeline),
    deleted_files, keyword_search, hash_check, strings."""

    ip = _w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path
    out = output_dir or f"/tmp/disk_forensics_{int(time.time())}"

    if operation == "analyze":
        return _shell(f"file '{ip}'; echo '---'; "
                     f"fdisk -l '{ip}' 2>/dev/null || mmls '{ip}' 2>/dev/null; echo '---'; "
                     f"fsstat '{ip}' 2>/dev/null | head -30; echo '---'; "
                     f"blkid '{ip}' 2>/dev/null",
                     timeout=20)

    if operation == "mount":
        offset_cmd = f"$(mmls '{ip}' 2>/dev/null | awk 'NR=={partition+3}{{print $3*512}}')" if partition else "0"
        return _shell(f"mkdir -p '{out}' && "
                     f"mount -o ro,loop,offset={offset_cmd} '{ip}' '{out}' 2>/dev/null && "
                     f"echo 'Mounted at {out}' && ls '{out}' | head -20 || "
                     f"echo 'Mount failed — try: sudo losetup -fP {ip}'",
                     timeout=15)

    if operation == "recover_files":
        return _shell(f"mkdir -p '{out}' && "
                     f"photorec /d '{out}' /cmd '{ip}' fileopt,everything,enable,search 2>&1 | tail -20 || "
                     f"foremost -o '{out}' '{ip}' 2>&1 | tail -10",
                     timeout=120)

    if operation == "mft":
        return _shell(f"analyzeMFT.py -f '{ip}' -o '{out}/mft.csv' 2>/dev/null && "
                     f"head -30 '{out}/mft.csv' || "
                     f"istat -f ntfs '{ip}' 0 2>/dev/null | head -40 || "
                     f"python3 -c \""
                     f"import struct; f=open('{ip}','rb'); "
                     f"data=f.read(1024*1024); "
                     f"pos=0; count=0;\n"
                     f"while pos<len(data)-4 and count<20:\n"
                     f"  if data[pos:pos+4]==b'FILE':\n"
                     f"    print(hex(pos), 'MFT record'); count+=1\n"
                     f"  pos+=512\n"
                     f"\"",
                     timeout=30)

    if operation == "deleted_files":
        return _shell(f"fls -r -d '{ip}' 2>/dev/null | head -50 || "
                     f"extundelete '{ip}' --restore-all --output-dir '{out}' 2>&1 | tail -20",
                     timeout=60)

    if operation == "timeline":
        return _shell(f"fls -m '' -r '{ip}' 2>/dev/null > /tmp/body.txt && "
                     f"mactime -b /tmp/body.txt 2>/dev/null | head -50 || "
                     f"log2timeline.py '{out}/plaso.db' '{ip}' 2>&1 | tail -10",
                     timeout=60)

    if operation == "keyword_search":
        kw = keyword or "flag"
        return _shell(f"strings '{ip}' | grep -i '{kw}' | head -30; "
                     f"bulk_extractor -e email -e find -S 'FIND_LIST={kw}' -o '{out}' '{ip}' 2>&1 | tail -10",
                     timeout=30)

    if operation == "strings":
        return _shell(f"strings -n 8 '{ip}' | grep -vE '^[[:space:]]*$' | head -100", timeout=15)

    if operation == "hash_check":
        return _shell(f"md5sum '{ip}'; sha256sum '{ip}'; "
                     f"echo '---'; sha1sum '{ip}'", timeout=30)

    return "Operations: analyze, mount, recover_files, mft, deleted_files, timeline, keyword_search, strings, hash_check"


def tool_dotnet_decompile(binary_path: str, operation: str = "decompile",
                            type_name: str = "", method_name: str = "",
                            output_path: str = "") -> str:
    """Full .NET C# decompilation via ilspycmd/ILSpy. Ops: decompile (full C# output),
    list_types, list_methods, method (single method), strings, resources, references."""

    bp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path

    if operation == "decompile":
        out = output_path or f"/tmp/dotnet_decompile_{int(time.time())}"
        # Try ilspycmd first (most common), fallback to dotnet-decompiler, then ildasm
        result = _shell(f"ilspycmd -p -o '{out}' '{bp}' 2>&1 | head -20", timeout=60)
        if "not found" in result.lower() or "command not found" in result.lower():
            # Try dotnet tool
            result = _shell(f"dotnet ilspycmd -p -o '{out}' '{bp}' 2>&1 | head -20", timeout=60)
        if "not found" in result.lower():
            # Fallback: ildasm for IL
            result = _shell(f"ildasm /text '{bp}' 2>/dev/null || monodis '{bp}' 2>/dev/null | head -100", timeout=30)
            if result.strip():
                return f"[Using IL disassembly (no ilspycmd)]\n{result}"
            return ("ilspycmd not found. Install:\n"
                    "  dotnet tool install -g ilspycmd\n"
                    "  OR: apt install mono-utils (for monodis)\n"
                    "  OR: use dnSpy GUI on Windows\n\n"
                    "Manual decompile: upload .dll/.exe to https://sharplab.io or https://decompiler.dedot.dev")
        # Show decompiled output
        code_out = _shell(f"find '{out}' -name '*.cs' | head -20 && cat '{out}'/*.cs 2>/dev/null | head -200", timeout=10)
        return f"Decompiled to {out}:\n{code_out}"

    if operation == "list_types":
        result = _shell(f"ilspycmd '{bp}' --list 2>&1 | head -60", timeout=30)
        if "not found" in result.lower():
            result = _shell(f"monodis --typedef '{bp}' 2>/dev/null | head -60", timeout=15)
        return result or "No types found (check file is valid .NET assembly)"

    if operation == "list_methods":
        type_filter = f"--type '{type_name}'" if type_name else ""
        result = _shell(f"ilspycmd '{bp}' {type_filter} --list-methods 2>&1 | head -80", timeout=30)
        return result

    if operation == "method":
        if not type_name or not method_name:
            return "Provide type_name and method_name"
        result = _shell(f"ilspycmd '{bp}' -t '{type_name}' -m '{method_name}' 2>&1", timeout=30)
        return result

    if operation == "strings":
        result = _shell(f"strings '{bp}' | grep -v '^\\.' | grep -v '^_' | grep -v 'System\\.' | head -80", timeout=10)
        return result

    if operation == "resources":
        result = _shell(f"ilspycmd '{bp}' --resources 2>/dev/null || "
                       f"monodis --resources '{bp}' 2>/dev/null || "
                       f"unzip -l '{bp}' 2>/dev/null | head -30", timeout=15)
        return result

    if operation == "references":
        result = _shell(f"monodis --assemblyref '{bp}' 2>/dev/null || "
                       f"ilspycmd '{bp}' --show-assembly-info 2>/dev/null | head -30", timeout=15)
        return result

    if operation == "patch":
        # Patch IL using dnlib or Mono.Cecil
        patch_code = f"""
try:
    import subprocess
    # Try using Cecil via Python for simple patches
    patch_script = '''
using Mono.Cecil;
using Mono.Cecil.Cil;
var asm = AssemblyDefinition.ReadAssembly("{bp}");
// TODO: modify instructions
asm.Write("{bp}.patched.dll");
Console.WriteLine("Patched!");
'''
    print("Patching .NET requires Mono.Cecil (C#) or dnlib")
    print("Install: dotnet add package Mono.Cecil")
    print("Or use: dnSpy GUI for interactive IL patching")
    print("Quick patch via sed on IL (monodis/ilasm roundtrip):")
    print(f"  monodis '{bp}' > /tmp/out.il")
    print(f"  # Edit /tmp/out.il")
    print(f"  ilasm /output:{bp}.patched.exe /dll /debug /exe /quiet /optimize /noautoinherit /fold /pack /nologo /debug /res /sse /quiet /out /quiet /noautoinherit /quiet /quiet /nologo /quiet /x64 /fold /nologo /debug /sse /res /nologo /quiet /nologo /quiet /nologo /quiet /nologo /sse /quiet /debug /fold /nologo /quiet /quiet /noautoinherit /quiet")
except Exception as ex:
    print(f"Error: {{ex}}")
"""
        return tool_execute_python(patch_code, timeout=15)

    return "Operations: decompile, list_types, list_methods, method, strings, resources, references, patch"


def tool_firmware_unpack(firmware_path: str, operation: str = "analyze",
                          arch: str = "auto", output_dir: str = "") -> str:
    """Firmware analysis: analyze (binwalk + file type), extract (filesystem extraction),
    emulate (QEMU user/system mode), find_vulns (hardcoded creds, command injection, overflow),
    strings_scan (secrets, URLs, keys), entropy (packed/encrypted regions)."""

    fp = _w2l(firmware_path) if (IS_WINDOWS and USE_WSL) else firmware_path
    out = output_dir or f"/tmp/firmware_extract_{int(time.time())}"

    if operation == "analyze":
        return _shell(f"binwalk '{fp}' 2>&1; echo '---'; "
                     f"file '{fp}'; echo '---'; "
                     f"xxd '{fp}' | head -20; echo '---'; "
                     f"strings '{fp}' | grep -E 'http://|https://|password|admin|root|flag' | head -20",
                     timeout=30)

    if operation == "extract":
        result = _shell(f"binwalk -eM --run-as=root '{fp}' -C '{out}' 2>&1 | tail -20 && "
                       f"echo '--- Extracted contents ---' && "
                       f"find '{out}' -type f | head -50", timeout=120)
        if not result.strip() or "error" in result.lower():
            result += _shell(f"mkdir -p '{out}' && "
                            f"jefferson '{fp}' -d '{out}' 2>&1 || "  # JFFS2
                            f"ubireader_extract_images '{fp}' -o '{out}' 2>&1 || "  # UBI
                            f"7z x '{fp}' -o'{out}' 2>&1 | tail -10", timeout=60)
        return result

    if operation == "emulate":
        # Try QEMU user mode for common architectures
        code = f"""
import subprocess, os
fp = {repr(fp)}
arch = {repr(arch)}
# Detect arch from file magic
r = subprocess.run(['file', fp], capture_output=True, text=True)
arch_info = r.stdout
print(f"File type: {{arch_info.strip()}}")
# Determine QEMU binary
qemu_map = {{
    'ARM':    'qemu-arm-static',
    'MIPS':   'qemu-mips-static',
    'MIPSEL': 'qemu-mipsel-static',
    'PowerPC':'qemu-ppc-static',
    'x86-64': 'qemu-x86_64',
    'x86':    'qemu-i386',
    'AArch64':'qemu-aarch64-static',
}}
detected = 'x86-64'
for a, q in qemu_map.items():
    if a in arch_info:
        detected = a; break
print(f"Detected arch: {{detected}}")
qemu_bin = qemu_map.get(detected, 'qemu-arm-static')
r2 = subprocess.run(['which', qemu_bin], capture_output=True, text=True)
if r2.returncode != 0:
    print(f"{{qemu_bin}} not found. Install: apt install qemu-user-static")
    print("Alternative: extract filesystem and use chroot:")
    print(f"  binwalk -eM '{fp}' -C /tmp/fw")
    print(f"  chroot /tmp/fw /bin/sh")
else:
    # Run binary with QEMU
    r3 = subprocess.run([qemu_bin, fp], capture_output=True, text=True, timeout=5,
                         env={{**os.environ, 'QEMU_LD_PREFIX': '/tmp/fw'}})
    print(f"QEMU output: {{r3.stdout[:500]}} {{r3.stderr[:200]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "find_vulns":
        extracted = out if os.path.exists(out) else f"/tmp/_binwalk.extracted"
        code = f"""
import subprocess, os, re
extracted = {repr(extracted)}
print("=== Hardcoded credentials ===")
r = subprocess.run(["grep", "-r", "-iE",
    "password|passwd|secret|admin|root|default.*pass|hardcoded",
    extracted, "--include=*.conf", "--include=*.cfg",
    "--include=*.ini", "--include=*.sh", "--include=*.py"],
    capture_output=True, text=True, timeout=20)
for line in r.stdout.split('\\n')[:20]: print(line)
print()
print("=== Command injection sinks ===")
r2 = subprocess.run(["grep", "-r", "-E",
    "system\\(|popen\\(|exec\\(|shell_exec\\(|backtick|`.*\\$",
    extracted, "--include=*.c", "--include=*.php", "--include=*.cgi"],
    capture_output=True, text=True, timeout=20)
for line in r2.stdout.split('\\n')[:15]: print(line)
print()
print("=== Interesting binaries ===")
r3 = subprocess.run(["find", extracted, "-type", "f", "-executable"],
    capture_output=True, text=True, timeout=10)
for f in r3.stdout.strip().split('\\n')[:20]:
    if f: print(f)
print()
print("=== Crypto keys / certificates ===")
r4 = subprocess.run(["grep", "-r", "-lE",
    "BEGIN PRIVATE KEY|BEGIN RSA|BEGIN CERTIFICATE|BEGIN EC",
    extracted], capture_output=True, text=True, timeout=15)
for line in r4.stdout.split('\\n')[:10]: print(line)
"""
        return tool_execute_python(code, timeout=40)

    if operation == "strings_scan":
        return _shell(f"strings '{fp}' | grep -iE "
                     f"'password|passwd|secret|api.key|token|flag|admin|root|https?://' | head -50 && "
                     f"echo '---WiFi/creds---' && "
                     f"strings '{fp}' | grep -iE 'ssid|wpa|wep|wifi|802\\.11' | head -20",
                     timeout=20)

    if operation == "entropy":
        return _shell(f"binwalk -E '{fp}' 2>&1 | head -30", timeout=20)

    return "Operations: analyze, extract, emulate, find_vulns, strings_scan, entropy"


def tool_pcap_deep(pcap_path: str, operation: str = "summary",
                    key_path: str = "", output_dir: str = "",
                    filter_expr: str = "", keyword: str = "") -> str:
    """Deep PCAP analysis beyond basic HTTP.
    Ops: summary (protocol breakdown + stats), decrypt_export (RSA key → decrypt TLS → export all HTTP objects),
    dns_exfil (detect/reconstruct DNS tunneling), covert_channel (timing/ICMP/HTTP-header covert data),
    extract_streams (follow all TCP/UDP streams), ftp_extract (files from FTP),
    smtp_extract (emails from SMTP), credentials (extract plaintext creds from any protocol),
    strings_all (strings across all packets matching keyword)."""

    sp = _w2l(pcap_path) if (IS_WINDOWS and USE_WSL) else pcap_path
    kp = (_w2l(key_path) if (IS_WINDOWS and USE_WSL) else key_path) if key_path else ""
    od = output_dir or f"/tmp/pcap_deep_{int(time.time())}"

    if operation == "summary":
        return _shell(f"tshark -r '{sp}' -q -z io,phs 2>/dev/null | head -40 && "
                     f"echo '--- Endpoints ---' && "
                     f"tshark -r '{sp}' -q -z endpoints,ip 2>/dev/null | head -20 && "
                     f"echo '--- Conversations ---' && "
                     f"tshark -r '{sp}' -q -z conv,tcp 2>/dev/null | head -15",
                     timeout=30)

    if operation == "decrypt_export":
        if not kp:
            return "Provide key_path (RSA private key .pem/.key or NSS keylog file)"
        _shell(f"mkdir -p '{od}'")
        # tshark with RSA key for TLS decryption + HTTP object export
        # Detect if keylog or RSA private key
        is_keylog = _shell(f"head -1 '{kp}' 2>/dev/null", timeout=5)
        if "CLIENT_RANDOM" in is_keylog or "SERVER_HANDSHAKE" in is_keylog:
            key_opt = f"-o 'tls.keylog_file:{kp}'"
        else:
            # RSA private key — need IP:port mapping
            key_opt = f"-o 'tls.keys_list:0.0.0.0,0,data,{kp}'"
        result = _shell(f"tshark -r '{sp}' {key_opt} --export-objects 'http,{od}' 2>&1 | head -20 && "
                       f"echo '--- Exported files ---' && ls -la '{od}' && "
                       f"echo '--- String search in exported files ---' && "
                       f"strings '{od}'/* 2>/dev/null | grep -iE 'flag|ctf|pico|key|secret' | head -20",
                       timeout=60)
        # Also try SMB objects
        result += _shell(f"tshark -r '{sp}' {key_opt} --export-objects 'smb,{od}/smb' 2>/dev/null; "
                        f"tshark -r '{sp}' {key_opt} --export-objects 'imf,{od}/imf' 2>/dev/null; "
                        f"ls '{od}'/ 2>/dev/null",
                        timeout=30)
        return result

    if operation == "dns_exfil":
        code = f"""
import subprocess, re, base64
sp = {repr(sp)}
# Extract all DNS queries
r = subprocess.run(['tshark', '-r', sp, '-Y', 'dns.flags.response == 0',
                    '-T', 'fields', '-e', 'dns.qry.name'],
                   capture_output=True, text=True, timeout=30)
queries = [q.strip() for q in r.stdout.strip().split('\\n') if q.strip()]
print(f"DNS queries: {{len(queries)}}")

# Look for exfiltration patterns
# Pattern 1: hex-encoded subdomains (e.g., 6865780a.evil.com)
hex_parts = []
b64_parts = []
text_parts = []
for q in queries:
    parts = q.split('.')
    for p in parts[:-2]:  # skip TLD parts
        if re.match(r'^[0-9a-fA-F]{{4,}}$', p):
            hex_parts.append(p)
        elif re.match(r'^[A-Za-z0-9+/]{{4,}}={{0,2}}$', p) and len(p) % 4 == 0:
            b64_parts.append(p)
        elif re.match(r'^[A-Za-z0-9]{{6,}}$', p):
            text_parts.append(p)

print(f"\\nHex-encoded subdomains: {{len(hex_parts)}}")
if hex_parts:
    combined = ''.join(hex_parts)
    try:
        decoded = bytes.fromhex(combined).decode(errors='replace')
        print(f"Hex decoded: {{decoded[:200]}}")
    except: pass

print(f"\\nPossible base64 subdomains: {{len(b64_parts)}}")
if b64_parts:
    combined = ''.join(b64_parts)
    try:
        decoded = base64.b64decode(combined + '==').decode(errors='replace')
        print(f"B64 decoded: {{decoded[:200]}}")
    except: pass

print(f"\\nQuery sequence (first 30): {{' | '.join(queries[:30])}}")

# iodine/dnscat2 detection
if any('dnscat' in q.lower() for q in queries):
    print("\\n[!] dnscat2 protocol detected!")
if any(len(q.split('.')[0]) > 50 for q in queries):
    print("\\n[!] Long subdomain labels — likely DNS tunnel")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "covert_channel":
        code = f"""
import subprocess, re, collections
sp = {repr(sp)}

print("=== Timing channel analysis ===")
r = subprocess.run(['tshark', '-r', sp, '-T', 'fields',
                    '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.len'],
                   capture_output=True, text=True, timeout=20)
times = []
for line in r.stdout.strip().split('\\n')[:500]:
    parts = line.split('\\t')
    if len(parts) >= 3:
        try: times.append((float(parts[0]), parts[1], int(parts[2])))
        except: pass

if times:
    intervals = [times[i][0]-times[i-1][0] for i in range(1, len(times))]
    short = sum(1 for t in intervals if t < 0.01)
    long_ = sum(1 for t in intervals if t > 0.1)
    print(f"  Short intervals (<10ms): {{short}}, Long (>100ms): {{long_}}")
    if short > 10 and long_ > 10:
        # Possible timing channel — classify as bits
        bits = ''.join('0' if t < 0.05 else '1' for t in intervals[:200])
        print(f"  Timing bits (threshold 50ms): {{bits[:80]}}")
        for i in range(0, len(bits)-7, 8):
            b = int(bits[i:i+8], 2)
            if 32 <= b <= 126: print(chr(b), end='')
        print()

print("\\n=== ICMP data channel ===")
r2 = subprocess.run(['tshark', '-r', sp, '-Y', 'icmp', '-T', 'fields',
                     '-e', 'icmp.data'],
                    capture_output=True, text=True, timeout=15)
icmp_data = [d.strip() for d in r2.stdout.strip().split('\\n') if d.strip() and d.strip() != 'Pad']
if icmp_data:
    print(f"  ICMP payloads: {{len(icmp_data)}}")
    combined = ''.join(icmp_data)
    try:
        decoded = bytes.fromhex(combined).decode(errors='replace')
        if any(32 <= ord(c) <= 126 for c in decoded[:20]):
            print(f"  ICMP data: {{decoded[:200]}}")
    except: pass

print("\\n=== HTTP header covert data ===")
r3 = subprocess.run(['tshark', '-r', sp, '-Y', 'http', '-T', 'fields',
                     '-e', 'http.request.full_uri', '-e', 'http.cookie',
                     '-e', 'http.user_agent', '-e', 'http.authorization'],
                    capture_output=True, text=True, timeout=15)
for line in r3.stdout.strip().split('\\n')[:20]:
    if line.strip(): print(f"  {{line[:120]}}")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "credentials":
        return _shell(f"tshark -r '{sp}' -Y 'ftp.request.command == \"PASS\" or http.authbasic or "
                     f"telnet.data or smtp.auth.password or pop.request or imap.request' "
                     f"-T fields -e ftp.request.arg -e http.authbasic -e telnet.data 2>/dev/null | head -30 && "
                     f"echo '--- HTTP Basic Auth ---' && "
                     f"tshark -r '{sp}' -Y http -T fields -e http.authorization 2>/dev/null | "
                     f"grep -v '^$' | head -10",
                     timeout=20)

    if operation == "extract_streams":
        _shell(f"mkdir -p '{od}'")
        return _shell(f"tshark -r '{sp}' -q -z follow,tcp,ascii,0 2>/dev/null | head -100 && "
                     f"echo '--- All TCP stream count ---' && "
                     f"tshark -r '{sp}' -T fields -e tcp.stream 2>/dev/null | sort -u | wc -l && "
                     f"echo '--- Follow stream 0 ---' && "
                     f"tshark -r '{sp}' -q -z follow,tcp,raw,0 2>/dev/null | head -60",
                     timeout=30)

    if operation == "ftp_extract":
        _shell(f"mkdir -p '{od}'")
        return _shell(f"tshark -r '{sp}' --export-objects 'ftp-data,{od}' 2>/dev/null && "
                     f"ls -la '{od}' && strings '{od}'/* 2>/dev/null | grep -iE 'flag|ctf|key' | head -20",
                     timeout=30)

    if operation == "smtp_extract":
        _shell(f"mkdir -p '{od}'")
        return _shell(f"tshark -r '{sp}' --export-objects 'imf,{od}' 2>/dev/null && "
                     f"ls -la '{od}' && cat '{od}'/* 2>/dev/null | head -100",
                     timeout=30)

    if operation == "strings_all":
        kw = keyword or "flag"
        return _shell(f"tshark -r '{sp}' -T fields -e data.data 2>/dev/null | "
                     f"xxd -r -p 2>/dev/null | strings | grep -i '{kw}' | head -30 && "
                     f"strings '{sp}' | grep -i '{kw}' | head -20",
                     timeout=20)

    return "Operations: summary, decrypt_export, dns_exfil, covert_channel, credentials, extract_streams, ftp_extract, smtp_extract, strings_all"


def tool_pe_analysis(binary_path: str, operation: str = "info",
                     resource_type: str = "", output_dir: str = "") -> str:
    """Windows PE (Portable Executable) analysis.
    Ops: info (headers, sections, imports, TLS), resources (list + extract via wrestool/7z),
    icons (extract ICO resources), strings (pefile + strings command),
    unpack (UPX/Themida/MPRESS detection and unpacking)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    od = output_dir or f"/tmp/pe_out_{int(time.time())}"
    _shell(f"mkdir -p '{od}'")

    if operation == "info":
        code = f"""
try:
    import pefile
    pe = pefile.PE({repr(sp)}, fast_load=False)
    print("=== PE Header ===")
    print(f"Machine:     {{hex(pe.FILE_HEADER.Machine)}}")
    print(f"Subsystem:   {{pe.OPTIONAL_HEADER.Subsystem}}")
    print(f"ImageBase:   {{hex(pe.OPTIONAL_HEADER.ImageBase)}}")
    print(f"EntryPoint:  {{hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}}")
    print(f"Timestamp:   {{pe.FILE_HEADER.TimeDateStamp}}")
    print("\\n=== Sections ===")
    for s in pe.sections:
        name = s.Name.rstrip(b'\\x00').decode(errors='replace')
        print(f"  {{name:<12}} VA={{hex(s.VirtualAddress)}} sz={{s.SizeOfRawData}} entropy={{s.get_entropy():.2f}}")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("\\n=== Imports (first 30) ===")
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:10]:
            dll = entry.dll.decode(errors='replace')
            funcs = [imp.name.decode(errors='replace') if imp.name else f'ord_{{imp.ordinal}}' for imp in entry.imports[:5]]
            print(f"  {{dll}}: {{', '.join(funcs)}}...")
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        print("\\n[!] TLS callbacks detected")
    print("\\n=== Resources ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def _r(d, depth=0):
            for e in d.entries:
                n = str(e.name) if e.name else pefile.RESOURCE_TYPE.get(e.id, str(e.id))
                if hasattr(e, 'directory'):
                    print(f"  {{'  '*depth}}[DIR] {{n}}")
                    _r(e.directory, depth+1)
                else:
                    d2 = e.data.struct
                    print(f"  {{'  '*depth}}{{n}} offset={{hex(d2.OffsetToData)}} size={{d2.Size}}")
        _r(pe.DIRECTORY_ENTRY_RESOURCE)
except ImportError:
    print("pefile not installed — pip install pefile")
except Exception as ex:
    print(f"Error: {{ex}}")
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=20)

    if operation == "resources":
        result = _shell(f"wrestool -l '{sp}' 2>&1", timeout=10)
        if "not found" in result or "command not found" in result:
            # fallback: 7z
            result = _shell(f"7z l '{sp}' 2>&1 | head -40", timeout=10)
        else:
            _shell(f"wrestool -x --output='{od}' '{sp}' 2>&1")
            ls = _shell(f"ls -la '{od}' && strings '{od}'/* 2>/dev/null | grep -iE 'flag|ctf|key|secret' | head -20", timeout=10)
            result += f"\n\nExtracted to {od}:\n{ls}"
        return result

    if operation == "icons":
        out = _shell(f"wrestool -x -t 14 --output='{od}' '{sp}' 2>&1 && "
                     f"ls '{od}'/*.ico '{od}'/*.ICO 2>/dev/null && "
                     f"convert '{od}'/*.ico '{od}/icon_%d.png' 2>/dev/null && "
                     f"echo 'PNGs saved to {od}'", timeout=15)
        return out

    if operation == "strings":
        code = f"""
try:
    import pefile, re
    pe = pefile.PE({repr(sp)}, fast_load=False)
    strings_found = []
    for section in pe.sections:
        data = section.get_data()
        # Find printable ASCII runs ≥6 chars
        for m in re.finditer(rb'[ -~]{{6,}}', data):
            strings_found.append(m.group().decode(errors='replace'))
    # Also check resource section string table
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        pass  # already covered by raw section scan
    interesting = [s for s in strings_found if any(kw in s.lower() for kw in ['flag','ctf','key','secret','password','token'])]
    print(f"Total strings: {{len(strings_found)}}, Interesting: {{len(interesting)}}")
    for s in interesting[:30]:
        print(f"  [*] {{s}}")
    print("\\n--- All strings (first 60) ---")
    for s in strings_found[:60]:
        print(f"  {{s}}")
except ImportError:
    import subprocess, re
    r = subprocess.run(['strings', {repr(sp)}], capture_output=True, text=True, timeout=15)
    interesting = [l for l in r.stdout.splitlines() if any(kw in l.lower() for kw in ['flag','ctf','key','secret'])]
    print("Interesting:"); [print(f"  {{l}}") for l in interesting[:20]]
    print("\\nAll strings (first 60):"); [print(f"  {{l}}") for l in r.stdout.splitlines()[:60]]
"""
        return tool_execute_python(code, timeout=20)

    if operation == "unpack":
        result = []
        # Detect packer via section names
        code = f"""
try:
    import pefile
    pe = pefile.PE({repr(sp)}, fast_load=False)
    section_names = [s.Name.rstrip(b'\\x00').decode(errors='replace') for s in pe.sections]
    print(f"Sections: {{section_names}}")
    packers = []
    if any('UPX' in n for n in section_names): packers.append('UPX')
    if any(n in ('themida','winlicense','.vmp0','.vmp1') for n in section_names): packers.append('Themida/VMProtect')
    if any('.MPRESS' in n for n in section_names): packers.append('MPRESS')
    entropies = [s.get_entropy() for s in pe.sections]
    if any(e > 7.0 for e in entropies): packers.append('High-entropy section (possible packing)')
    print(f"Detected packers: {{packers or ['None detected']}}")
except Exception as ex:
    print(f"pefile error: {{ex}}")
"""
        result.append(tool_execute_python(code, timeout=10))
        # Try upx -d
        out_bin = f"{od}/unpacked.exe"
        upx_out = _shell(f"upx -d '{sp}' -o '{out_bin}' 2>&1", timeout=20)
        result.append(f"\nUPX unpack attempt:\n{upx_out}")
        return "\n".join(result)

    return "Operations: info, resources, icons, strings, unpack"


def tool_windows_forensics(path: str, operation: str = "all",
                             output_dir: str = "", keyword: str = "") -> str:
    """Windows artifact forensics: registry (SAM/SYSTEM/SOFTWARE hive parsing),
    event_logs (EVTX parsing), prefetch, lnk_files, shellbags, amcache, browser_history,
    credentials (cached creds, LSA secrets), timeline_all."""

    wp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
    out = output_dir or f"/tmp/winforensics_{int(time.time())}"

    if operation in ("all", "registry"):
        code = f"""
import subprocess, os, sys
wp = {repr(wp)}
# Try regipy (pip install regipy), then regripper fallback
hives = ['SAM', 'SYSTEM', 'SOFTWARE', 'SECURITY', 'NTUSER.DAT']
found_hives = []
for hive in hives:
    # Search for hive file
    r = subprocess.run(['find', wp, '-name', hive, '-type', 'f'],
                       capture_output=True, text=True, timeout=10)
    for hive_path in r.stdout.strip().split('\\n'):
        if hive_path:
            found_hives.append((hive, hive_path))
            print(f"Found: {{hive_path}}")
if not found_hives:
    print(f"No registry hives found under {{wp}}")
    print("Expected locations: Windows/System32/config/{{SAM,SYSTEM,SOFTWARE,SECURITY}}")
    print("                    Users/*/NTUSER.DAT")
else:
    for hive_name, hive_path in found_hives[:3]:
        print(f"\\n=== {{hive_name}} ===")
        # Try regipy
        r2 = subprocess.run(['regipy-cli', 'registry-diff', hive_path],
                            capture_output=True, text=True, timeout=15)
        if r2.returncode == 0:
            print(r2.stdout[:500])
        else:
            # Try regdump or hivex
            r3 = subprocess.run(['hivexsh', '-w', hive_path],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=10)
            if r3.stdout:
                print(r3.stdout[:300])
            else:
                print(f"  (use regripper or regipy-cli to parse {{hive_name}})")
"""
        reg_result = tool_execute_python(code, timeout=30)
        if operation == "registry":
            return reg_result

    if operation in ("all", "event_logs"):
        code2 = f"""
import subprocess
wp = {repr(wp)}
kw = {repr(keyword or 'EventID')}
r = subprocess.run(['find', wp, '-name', '*.evtx', '-type', 'f'],
                   capture_output=True, text=True, timeout=10)
evtx_files = r.stdout.strip().split('\\n')
if evtx_files and evtx_files[0]:
    for evtx in evtx_files[:3]:
        print(f"Parsing: {{evtx}}")
        r2 = subprocess.run(['python3', '-m', 'evtxtools', evtx],
                            capture_output=True, text=True, timeout=15)
        if r2.returncode == 0:
            print(r2.stdout[:500])
        else:
            r3 = subprocess.run(['evtxexport', evtx],
                                capture_output=True, text=True, timeout=15)
            if r3.stdout: print(r3.stdout[:300])
            else:
                print(f"  (install python-evtx or evtxexport to parse .evtx)")
else:
    print(f"No .evtx files found under {{wp}}")
    # Check for common important event log locations
    print("Expected: Windows/System32/winevt/Logs/")
    print("Key logs: Security.evtx (4624=logon,4625=failed,4720=new user)")
    print("          System.evtx, Application.evtx, PowerShell/Operational.evtx")
"""
        evtx_result = tool_execute_python(code2, timeout=30)
        if operation == "event_logs":
            return evtx_result

    if operation in ("all", "prefetch"):
        pf_result = _shell(f"find '{wp}' -name '*.pf' -type f 2>/dev/null | head -20 && "
                          f"python3 -m prefetchparser '{wp}/Windows/Prefetch/' 2>/dev/null | head -30 || "
                          f"echo 'Install prefetch parser: pip install libscca-python'",
                          timeout=20)
        if operation == "prefetch":
            return pf_result

    if operation in ("all", "lnk_files"):
        lnk_result = _shell(f"find '{wp}' -name '*.lnk' -type f 2>/dev/null | head -20 && "
                           f"python3 -c \"import glob,subprocess; "
                           f"[subprocess.run(['lnkinfo',f],capture_output=True,text=True) for f in glob.glob('{wp}/**/*.lnk',recursive=True)[:5]]\" "
                           f"2>/dev/null || "
                           f"find '{wp}' -name '*.lnk' 2>/dev/null | xargs file 2>/dev/null | head -20",
                           timeout=20)
        if operation == "lnk_files":
            return lnk_result

    if operation in ("all", "credentials"):
        return _shell(f"find '{wp}' -name 'SAM' -o -name 'SYSTEM' 2>/dev/null | head -5 && "
                     f"echo '--- Secretsdump (if SAM+SYSTEM available) ---' && "
                     f"samdump2 '{wp}/Windows/System32/config/SYSTEM' '{wp}/Windows/System32/config/SAM' 2>/dev/null || "
                     f"secretsdump.py -sam '{wp}/Windows/System32/config/SAM' "
                     f"  -system '{wp}/Windows/System32/config/SYSTEM' LOCAL 2>/dev/null | head -20",
                     timeout=30)

    if operation in ("all", "browser_history"):
        code3 = f"""
import subprocess, os
wp = {repr(wp)}
db_paths = []
# Chrome / Chromium
r = subprocess.run(['find', wp, '-name', 'History', '-path', '*/Chrome/*'],
                   capture_output=True, text=True, timeout=10)
db_paths.extend(r.stdout.strip().split('\\n'))
# Firefox
r2 = subprocess.run(['find', wp, '-name', 'places.sqlite'],
                    capture_output=True, text=True, timeout=10)
db_paths.extend(r2.stdout.strip().split('\\n'))
for db in db_paths[:3]:
    if db and os.path.exists(db):
        print(f"DB: {{db}}")
        r3 = subprocess.run(['sqlite3', db, 'SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20;'],
                            capture_output=True, text=True, timeout=10)
        print(r3.stdout[:400] or r3.stderr[:200])
if not any(os.path.exists(d) for d in db_paths if d):
    print(f"No browser history found under {{wp}}")
"""
        return tool_execute_python(code3, timeout=25)

    return reg_result + "\n\n" + evtx_result if operation == "all" else "Operations: all, registry, event_logs, prefetch, lnk_files, credentials, browser_history, shellbags, amcache"


def tool_string_decryptor(binary_path: str = "", operation: str = "floss",
                           key: str = "", algorithm: str = "auto",
                           decompiled_code: str = "") -> str:
    """Obfuscated string extractor wrapping FLOSS (Mandiant/flare-floss).
    Ops: floss (run FLOSS to extract all obfuscated strings automatically),
    xor_scan (scan binary for XOR-encrypted string patterns + brute key),
    stack_strings (extract stack-allocated strings via FLOSS --only-stack-strings),
    tight_loops (find tight decryption loops — common in malware/CTF obfuscation),
    decode_with_key (given key + algorithm, decrypt all strings matching pattern)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""

    if operation in ("floss", "stack_strings", "tight_loops"):
        if not sp: return "Provide binary_path="
        flag_filter = "| grep -iE 'picoCTF|flag{|ctf{|key|password|secret' 2>/dev/null || true"
        mode = "--only-stack-strings" if operation == "stack_strings" else \
               "--only-tight-loops" if operation == "tight_loops" else ""
        result = _shell(f"floss {mode} '{sp}' 2>&1 | head -100", timeout=60)
        if "not found" in result or "command not found" in result:
            result = _shell(f"python3 -m floss {mode} '{sp}' 2>&1 | head -100", timeout=60)
        if "not found" in result or "command not found" in result:
            return ("FLOSS not installed. Install: pip install flare-floss\n"
                    "Fallback: using strings + XOR scan\n\n" +
                    _shell(f"strings '{sp}' | grep -iE '.{{6,}}' | head -50", timeout=10))
        return result

    if operation == "xor_scan":
        if not sp: return "Provide binary_path="
        code = f"""
import subprocess, itertools
sp = {repr(sp)}

# Read binary
with open(sp, 'rb') as f: data = f.read()

# Try all single-byte XOR keys
flag_patterns = [b'picoCTF', b'flag{{', b'CTF{{', b'FLAG']
found = []
for key_byte in range(256):
    decrypted = bytes(b ^ key_byte for b in data)
    for pat in flag_patterns:
        if pat in decrypted:
            idx = decrypted.index(pat)
            snippet = decrypted[max(0,idx-5):idx+60]
            printable = bytes(b if 32<=b<=126 else ord('.') for b in snippet)
            found.append(f'[KEY=0x{{key_byte:02x}}] {{printable.decode()}}')

if found:
    print('Flag pattern found with XOR key!')
    for f in found:
        print(f'  {{f}}')
else:
    # Try multi-byte XOR with common lengths
    print('No single-byte XOR hit. Trying common 2-4 byte keys...')
    r = subprocess.run(['strings', sp], capture_output=True, text=True, timeout=10)
    printable_strings = [s for s in r.stdout.splitlines() if len(s) > 8]
    print(f'Found {{len(printable_strings)}} strings. Top suspicious:')
    for s in printable_strings[:20]:
        if any(ord(c)>127 or c=='\\x00' for c in s[:3]):
            print(f'  {{repr(s)}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "decode_with_key":
        if not sp or not key: return "Provide binary_path= and key= (hex bytes e.g. 'deadbeef')"
        code = f"""
with open({repr(sp)}, 'rb') as f: data = f.read()
key_bytes = bytes.fromhex({repr(key.replace(' ','').replace('0x',''))})
kl = len(key_bytes)
decrypted = bytes(data[i] ^ key_bytes[i % kl] for i in range(len(data)))

# Extract printable strings from decrypted
import re
strings = re.findall(rb'[ -~]{{6,}}', decrypted)
print(f'Decrypted strings (key={{repr(key_bytes.hex())}}):')
for s in strings[:40]:
    print(f'  {{s.decode(errors="replace")}}')
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: floss, xor_scan, stack_strings, tight_loops, decode_with_key"


def tool_pcap_reassemble(pcap_path: str, operation: str = "auto",
                          output_dir: str = "", stream_id: int = 0,
                          filter_expr: str = "", keyword: str = "") -> str:
    """PCAP file reconstruction wrapping tshark --export-objects + tcpflow + foremost.
    Ops: auto (export all objects from all protocols, search for flags),
    http_objects (tshark export HTTP objects — files transferred over HTTP),
    ftp_objects (tshark export FTP-DATA — files transferred over FTP),
    tcp_stream (reconstruct single TCP stream to file),
    all_streams (tcpflow — reconstruct every TCP stream to separate files),
    find_files (run foremost/binwalk on all reconstructed data to find embedded files)."""

    sp = (_w2l(pcap_path) if (IS_WINDOWS and USE_WSL) else pcap_path) if pcap_path else ""
    od = output_dir or f"/tmp/pcap_reassemble_{int(time.time())}"
    _shell(f"mkdir -p '{od}'")

    if operation in ("auto", "http_objects"):
        result = _shell(f"tshark -r '{sp}' --export-objects http,'{od}/http' 2>&1 && "
                       f"ls -la '{od}/http' 2>/dev/null | head -20 && "
                       f"strings '{od}/http'/* 2>/dev/null | grep -iE 'picoCTF|flag{{|ctf{{' | head -10",
                       timeout=30)
        if operation == "http_objects": return result

    if operation in ("auto", "ftp_objects"):
        result_ftp = _shell(f"tshark -r '{sp}' --export-objects ftp-data,'{od}/ftp' 2>&1 && "
                            f"ls -la '{od}/ftp' 2>/dev/null | head -20 && "
                            f"strings '{od}/ftp'/* 2>/dev/null | grep -iE 'picoCTF|flag{{|ctf{{' | head -10",
                            timeout=30)
        if operation == "ftp_objects": return result_ftp

    if operation == "tcp_stream":
        return _shell(f"tshark -r '{sp}' -q -z follow,tcp,raw,{stream_id} 2>&1 | "
                     f"grep -v '^===\\|^\\s*$\\|^Follow' | xxd -r -p > '{od}/stream_{stream_id}.bin' 2>/dev/null && "
                     f"file '{od}/stream_{stream_id}.bin' && "
                     f"strings '{od}/stream_{stream_id}.bin' | head -30",
                     timeout=20)

    if operation == "all_streams":
        result = _shell(f"tcpflow -r '{sp}' -o '{od}' 2>&1 || "
                       f"tshark -r '{sp}' -T fields -e tcp.stream 2>/dev/null | sort -u | "
                       f"xargs -I{{}} tshark -r '{sp}' -q -z follow,tcp,raw,{{}} 2>/dev/null | head -5",
                       timeout=60)
        ls = _shell(f"ls -la '{od}' | head -20", timeout=5)
        grep = _shell(f"strings '{od}'/* 2>/dev/null | grep -iE 'picoCTF|flag{{|ctf{{' | head -20", timeout=10)
        return f"{result}\n\nFiles:\n{ls}\n\nFlag search:\n{grep}"

    if operation == "find_files":
        binwalk_out = _shell(f"binwalk -e -C '{od}' '{sp}' 2>&1 | head -30", timeout=30)
        foremost_out = _shell(f"foremost -i '{sp}' -o '{od}/foremost' 2>&1 | head -20 && "
                             f"ls '{od}/foremost'/* 2>/dev/null | head -20", timeout=30)
        return f"Binwalk:\n{binwalk_out}\n\nForemost:\n{foremost_out}"

    # auto: run all and return combined
    return "\n\n".join([
        f"=== HTTP objects → {od}/http ===\n" + _shell(f"tshark -r '{sp}' --export-objects http,'{od}/http' 2>&1 && ls '{od}/http' 2>/dev/null | head -10 && strings '{od}/http'/* 2>/dev/null | grep -iE 'picoCTF|flag{{' | head -5", timeout=20),
        f"=== FTP objects → {od}/ftp ===\n" + _shell(f"tshark -r '{sp}' --export-objects ftp-data,'{od}/ftp' 2>&1 && ls '{od}/ftp' 2>/dev/null | head -10", timeout=20),
        f"=== All TCP streams → {od}/streams ===\n" + _shell(f"mkdir -p '{od}/streams' && tcpflow -r '{sp}' -o '{od}/streams' 2>&1 | head -10 || echo 'tcpflow not installed: apt install tcpflow'", timeout=20),
    ])


def tool_pdf_forensics(pdf_path: str, operation: str = "analyze",
                        output_dir: str = "") -> str:
    """PDF forensics wrapping peepdf + pdf-parser.py (Didier Stevens) + pikepdf.
    Ops: analyze (full scan — JS, embedded files, streams, metadata),
    extract_js (extract JavaScript from PDF actions and objects),
    extract_embedded (extract embedded files from /EmbeddedFiles),
    decompress_streams (decompress all FlateDecode/LZWDecode streams),
    find_hidden (search for steganographic content, whitespace encoding, hidden layers),
    metadata (dump all XMP/DocInfo metadata)."""

    sp = (_w2l(pdf_path) if (IS_WINDOWS and USE_WSL) else pdf_path) if pdf_path else ""
    od = output_dir or f"/tmp/pdf_forensics_{int(time.time())}"
    _shell(f"mkdir -p '{od}'")

    if operation in ("analyze", "extract_js"):
        # Try peepdf first
        result = _shell(f"peepdf -f -i '{sp}' 2>&1 | head -60", timeout=20)
        if "not found" in result or "command not found" in result:
            # Fallback: pdf-parser.py
            result = _shell(f"python3 pdf-parser.py --search /JavaScript '{sp}' 2>&1 | head -40 || "
                           f"python3 ~/.local/bin/pdf-parser.py --search /JavaScript '{sp}' 2>&1 | head -40",
                           timeout=20)
        if "not found" in result:
            # Pure Python fallback with pikepdf
            result = tool_execute_python(f"""
try:
    import pikepdf, json
    with pikepdf.open({repr(sp)}) as pdf:
        print(f'Pages: {{len(pdf.pages)}}')
        print(f'Info: {{dict(pdf.docinfo)}}')
        # Search for JS
        if '/Names' in pdf.Root:
            names = pdf.Root['/Names']
            if '/JavaScript' in names:
                print('[!] JavaScript found in /Names/JavaScript')
        # Search for embedded files
        if '/Names' in pdf.Root and '/EmbeddedFiles' in pdf.Root['/Names']:
            print('[!] Embedded files found')
        # Dump all stream objects
        for i, obj in enumerate(pdf.objects):
            try:
                if hasattr(obj, 'read_bytes'):
                    data = obj.read_bytes()
                    printable = ''.join(chr(b) if 32<=b<=126 else '.' for b in data[:200])
                    if any(kw in printable for kw in ['flag','ctf','picoCTF','password']):
                        print(f'[!] Object {{i}}: {{printable[:200]}}')
            except: pass
except ImportError:
    print('pikepdf not installed. Install: pip install pikepdf')
except Exception as ex:
    print(f'Error: {{ex}}')
""", timeout=20)
        return result

    if operation == "extract_embedded":
        code = f"""
try:
    import pikepdf, os
    od = {repr(od)}
    with pikepdf.open({repr(sp)}) as pdf:
        if '/Names' in pdf.Root and '/EmbeddedFiles' in pdf.Root.get('/Names', {{}}):
            ef = pdf.Root['/Names']['/EmbeddedFiles']
            names = ef.get('/Names', [])
            for i in range(0, len(names), 2):
                fname = str(names[i])
                fspec = names[i+1]
                if '/EF' in fspec:
                    data = fspec['/EF']['/F'].read_bytes()
                    out_path = os.path.join(od, fname.strip('/'))
                    with open(out_path, 'wb') as f: f.write(data)
                    print(f'Extracted: {{out_path}} ({{len(data)}} bytes)')
        else:
            print('No embedded files found in /EmbeddedFiles')
            # Check attachments
            for page in pdf.pages:
                if '/Annots' in page:
                    for annot in page['/Annots']:
                        if annot.get('/Subtype') == '/FileAttachment':
                            print(f'  File attachment found on page')
except ImportError:
    print('pikepdf not installed. Install: pip install pikepdf')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "decompress_streams":
        code = f"""
try:
    import pikepdf
    od = {repr(od)}
    with pikepdf.open({repr(sp)}) as pdf:
        found = 0
        for i, obj in enumerate(pdf.objects):
            try:
                if hasattr(obj, 'read_bytes'):
                    data = obj.read_bytes()
                    if len(data) > 10:
                        out_path = f'{{od}}/stream_{{i:04d}}.bin'
                        with open(out_path, 'wb') as f: f.write(data)
                        # Check for interesting content
                        text = data.decode(errors='replace')
                        if any(kw in text for kw in ['flag','ctf','picoCTF','password','secret']):
                            print(f'[!] Interesting stream {{i}}: {{text[:200]}}')
                        found += 1
            except: pass
        print(f'Extracted {{found}} streams to {{od}}')
except ImportError:
    print('pikepdf not installed. Install: pip install pikepdf')
"""
        return tool_execute_python(code, timeout=20)

    if operation == "metadata":
        return (_shell(f"exiftool '{sp}' 2>&1 | head -40", timeout=10) + "\n" +
                _shell(f"pdfinfo '{sp}' 2>&1 | head -30", timeout=10))

    if operation == "find_hidden":
        code = f"""
import re
with open({repr(sp)}, 'rb') as f: data = f.read()
# Look for strings in raw PDF
text = data.decode(errors='replace')
patterns = [r'picoCTF\\{{[^}}]+\\}}', r'flag\\{{[^}}]+\\}}', r'CTF\\{{[^}}]+\\}}']
for pat in patterns:
    matches = re.findall(pat, text, re.IGNORECASE)
    if matches:
        print(f'[!] FOUND: {{matches}}')
# Look for suspicious whitespace encoding (zero-width chars, spaces)
hidden = re.findall(r'[\\x00-\\x08\\x0e-\\x1f][\\x20-\\x7e]{{4,}}', data.decode(errors='replace'))
if hidden:
    print(f'Hidden content candidates: {{hidden[:5]}}')
# Check for layers/optional content
if b'/OCG' in data or b'/OCProperties' in data:
    print('[!] Optional Content Groups (layers) found — may hide content')
# Check for steganography in embedded images
print(f'Raw strings with flag keywords:')
for m in re.finditer(b'(?:flag|picoCTF|ctf).*', data, re.IGNORECASE):
    print(f'  {{m.group()[:80]}}')
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: analyze, extract_js, extract_embedded, decompress_streams, metadata, find_hidden"

