"""Encoding/decoding transforms and number base conversions."""
from __future__ import annotations
import base64, re, urllib.parse


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

