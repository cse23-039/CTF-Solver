"""Flag extraction and format detection."""
from __future__ import annotations
import json
import re


def _emit_fallback(event_type: str, **kwargs):
    try:
        print(json.dumps({"type": event_type, **kwargs}, ensure_ascii=False), flush=True)
    except Exception:
        pass


def _log_fallback(tag: str, msg: str, cls: str = ""):
    _emit_fallback("log", tag=str(tag), msg=str(msg), cls=str(cls))


emit = globals().get("emit") if callable(globals().get("emit")) else _emit_fallback
log = globals().get("log") if callable(globals().get("log")) else _log_fallback


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


def _normalize_hint_values(raw_hints) -> list[str]:
    out = []
    if raw_hints is None:
        return out
    if isinstance(raw_hints, str):
        txt = raw_hints.strip()
        if txt:
            out.append(txt)
        return out
    if isinstance(raw_hints, (list, tuple, set)):
        for item in raw_hints:
            if item is None:
                continue
            if isinstance(item, str):
                txt = item.strip()
                if txt:
                    out.append(txt)
            elif isinstance(item, dict):
                txt = str(item.get("text") or item.get("hint") or item.get("value") or "").strip()
                if txt:
                    out.append(txt)
            else:
                txt = str(item).strip()
                if txt:
                    out.append(txt)
        return out
    if isinstance(raw_hints, dict):
        for key in ("hint", "hints", "text", "value"):
            if key in raw_hints:
                out.extend(_normalize_hint_values(raw_hints.get(key)))
        return out
    txt = str(raw_hints).strip()
    if txt:
        out.append(txt)
    return out


def _extract_name_hints(challenge_name: str) -> list[str]:
    name = (challenge_name or "").strip()
    if not name:
        return []
    hints = [f"Challenge name may be a clue: '{name}'"]
    low = name.lower()
    keyword_map = {
        "xor": "Potential XOR/bitwise encoding challenge",
        "rsa": "Potential RSA cryptography challenge",
        "heap": "Potential heap exploitation path",
        "rop": "Potential ROP exploitation path",
        "format": "Potential format-string vulnerability",
        "jwt": "Potential JWT/web token attack",
        "steg": "Potential steganography investigation",
        "pcap": "Potential network capture/forensics task",
        "wasm": "Potential WebAssembly reverse engineering",
        "pickle": "Potential insecure deserialization",
        "cache": "Potential cache/timing side-channel",
        "oracle": "Potential oracle-based cryptanalysis",
        "padding": "Potential padding oracle attack",
    }
    for k, v in keyword_map.items():
        if k in low:
            hints.append(v)

    tokens = [t for t in re.split(r"[^A-Za-z0-9_]+", name) if t]
    if len(tokens) > 1:
        hints.append("Name tokens: " + ", ".join(tokens[:10]))
    return hints


def _build_challenge_signal_pack(challenge: dict, extra_config: dict) -> dict:
    name = challenge.get("name", "")
    desc = challenge.get("description", "")

    raw_hint_candidates = [
        challenge.get("hint"),
        challenge.get("hints"),
        challenge.get("challenge_hint"),
        challenge.get("challenge_hints"),
        challenge.get("tips"),
        challenge.get("clues"),
        extra_config.get("hint"),
        extra_config.get("hints"),
    ]

    explicit_hints = []
    for cand in raw_hint_candidates:
        explicit_hints.extend(_normalize_hint_values(cand))

    # de-dup, preserve order
    seen = set()
    deduped_hints = []
    for h in explicit_hints:
        key = h.lower().strip()
        if key and key not in seen:
            seen.add(key)
            deduped_hints.append(h)

    name_hints = _extract_name_hints(name)

    combined_lines = []
    if name_hints:
        combined_lines.append("Name-derived hints:")
        combined_lines.extend([f"- {h}" for h in name_hints])
    if deduped_hints:
        combined_lines.append("Explicit hints:")
        combined_lines.extend([f"- {h}" for h in deduped_hints])

    summary = "\n".join(combined_lines).strip()
    augmented_description = desc
    if summary:
        augmented_description = f"{desc}\n\n[Challenge Signals]\n{summary}"

    return {
        "name": name,
        "description": desc,
        "explicit_hints": deduped_hints,
        "name_hints": name_hints,
        "signal_summary": summary,
        "augmented_description": augmented_description,
    }


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

    code = """
import re, base64, binascii, urllib.parse

text = __TEXT__  # cap at 100KB
ctf = __CTF__
op = __OP__
extra_patterns = __PATTERNS__

# Build flag regex patterns
flag_re = [
    re.escape(ctf) + '\\{[^\\}]+\\}',
    'flag\\{[^\\}]+\\}',
    'CTF\\{[^\\}]+\\}',
    '[A-Z]{{3,8}}_?\\{[^\\}]{{5,50}}\\}',
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
    code = code.replace("__TEXT__", repr(text[:100000]))
    code = code.replace("__CTF__", repr(ctf_name))
    code = code.replace("__OP__", repr(operation))
    code = code.replace("__PATTERNS__", repr(patterns or []))
    return tool_execute_python(code, timeout=20)
