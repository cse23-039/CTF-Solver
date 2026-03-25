"""Speculative Haiku hypothesis fan-out."""
from __future__ import annotations

import json
import os
from typing import Any

_MODEL_HAIKU = "claude-haiku-4-5-20251001"

_FANOUT_SYSTEM = """You are a CTF expert pre-analyst. Given a challenge description and category,
generate exactly 5 distinct attack hypotheses ranked by likelihood.

Respond ONLY with a JSON array, no prose, no markdown fences:
[
  {
    "rank": 1,
    "hypothesis": "specific attack technique description",
    "confidence": 0.0-1.0,
    "first_tool": "tool_name",
    "first_args": "key arguments to try",
    "rationale": "one sentence"
  },
  ...
]

Rules:
- rank 1 = most likely. Each hypothesis must be DISTINCT (different technique class).
- confidence is your estimate that this exact technique will find the flag.
- first_tool should be a real CTF tool (checksec, strings, gobuster, z3, etc).
- No generic answers like "analyze the binary". Be specific.
- Total confidence across all 5 should roughly sum to ≤ 2.0 (there are unknowns)."""


def speculative_hypothesis_fanout(challenge_description: str, category: str, difficulty: str = "medium", rag_context: str = "", cross_ctf_context: str = "", api_key: str = "") -> list[dict[str, Any]]:
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return _generic_fallback(category, difficulty)

    try:
        import anthropic  # type: ignore

        client = anthropic.Anthropic(api_key=api_key)

        context_block = ""
        if rag_context:
            context_block += f"\n\n{rag_context[:1200]}"
        if cross_ctf_context:
            context_block += f"\n\n{cross_ctf_context[:600]}"

        user_msg = f"Category: {category} | Difficulty: {difficulty}\n\nChallenge description:\n{str(challenge_description)[:2000]}{context_block}"

        resp = client.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=1024,
            system=_FANOUT_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )

        raw = (resp.content[0].text if resp.content else "[]").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ValueError("Expected list")

        result = []
        for item in parsed[:5]:
            if isinstance(item, dict) and item.get("hypothesis"):
                result.append(
                    {
                        "rank": int(item.get("rank", len(result) + 1)),
                        "hypothesis": str(item["hypothesis"])[:400],
                        "confidence": max(0.0, min(1.0, float(item.get("confidence", 0.5)))),
                        "first_tool": str(item.get("first_tool", "pre_solve_recon")),
                        "first_args": str(item.get("first_args", ""))[:200],
                        "rationale": str(item.get("rationale", ""))[:200],
                        "source": "haiku_fanout",
                    }
                )
        result.sort(key=lambda x: x["confidence"], reverse=True)
        return result if result else _generic_fallback(category, difficulty)

    except Exception:
        return _generic_fallback(category, difficulty)


def _generic_fallback(category: str, difficulty: str) -> list[dict[str, Any]]:
    cat = str(category or "").lower()

    templates: dict[str, list[dict]] = {
        "cryptography": [
            {"hypothesis": "RSA with small/weak parameters (small e, Wiener, fermat)", "confidence": 0.4, "first_tool": "crypto_attack", "first_args": "rsa_wiener"},
            {"hypothesis": "Classical cipher (Caesar/Vigenere/substitution)", "confidence": 0.3, "first_tool": "crypto_attack", "first_args": "classical_cipher"},
            {"hypothesis": "AES in ECB mode with oracle padding attack", "confidence": 0.25, "first_tool": "crypto_attack", "first_args": "padding_oracle"},
            {"hypothesis": "PRNG seed recovery (Mersenne Twister/LCG)", "confidence": 0.2, "first_tool": "statistical_analysis", "first_args": ""},
            {"hypothesis": "Hash length extension or collision attack", "confidence": 0.15, "first_tool": "crypto_attack", "first_args": "hash_extender"},
        ],
        "binary exploitation": [
            {"hypothesis": "Stack buffer overflow with ROP chain", "confidence": 0.45, "first_tool": "checksec", "first_args": ""},
            {"hypothesis": "Format string vulnerability → arbitrary write", "confidence": 0.35, "first_tool": "binary_analysis", "first_args": "format_string"},
            {"hypothesis": "Heap exploitation (tcache/fastbin dup)", "confidence": 0.25, "first_tool": "binary_analysis", "first_args": "heap"},
            {"hypothesis": "ret2win / ret2libc no PIE", "confidence": 0.3, "first_tool": "disassemble", "first_args": "main"},
            {"hypothesis": "Shellcode injection via mmap or rwx region", "confidence": 0.2, "first_tool": "checksec", "first_args": ""},
        ],
        "web": [
            {"hypothesis": "SQL injection in login or search parameter", "confidence": 0.4, "first_tool": "sql_injection", "first_args": ""},
            {"hypothesis": "SSTI via template engine (Jinja2/Twig/Freemarker)", "confidence": 0.35, "first_tool": "http_request", "first_args": "{{7*7}}"},
            {"hypothesis": "JWT algorithm confusion or weak secret", "confidence": 0.3, "first_tool": "js_analyze", "first_args": "jwt"},
            {"hypothesis": "SSRF to internal metadata / cloud IMDS", "confidence": 0.25, "first_tool": "http_request", "first_args": "SSRF probe"},
            {"hypothesis": "Path traversal or local file inclusion", "confidence": 0.2, "first_tool": "http_request", "first_args": "../../../etc/passwd"},
        ],
        "reverse engineering": [
            {"hypothesis": "Anti-debug stripped binary → decompile main logic", "confidence": 0.4, "first_tool": "decompile", "first_args": "main"},
            {"hypothesis": "Custom string transform / XOR obfuscation", "confidence": 0.35, "first_tool": "extract_strings", "first_args": ""},
            {"hypothesis": "VM-based interpreter → trace bytecode", "confidence": 0.25, "first_tool": "disassemble", "first_args": ""},
            {"hypothesis": "Packed binary (UPX/custom) → unpack first", "confidence": 0.3, "first_tool": "binary_analysis", "first_args": "entropy"},
            {"hypothesis": "License / serial check → patch or keygen", "confidence": 0.2, "first_tool": "disassemble", "first_args": "check_serial"},
        ],
        "forensics": [
            {"hypothesis": "Steganography in image (LSB / DCT)", "confidence": 0.4, "first_tool": "steg_analyze", "first_args": ""},
            {"hypothesis": "Hidden data in PCAP (protocol extraction)", "confidence": 0.35, "first_tool": "pcap_analyze", "first_args": ""},
            {"hypothesis": "File carved from binary / memory dump", "confidence": 0.3, "first_tool": "forensics", "first_args": "binwalk"},
            {"hypothesis": "Metadata artifact in document/image", "confidence": 0.25, "first_tool": "forensics", "first_args": "exiftool"},
            {"hypothesis": "Deleted file recovery from disk image", "confidence": 0.2, "first_tool": "forensics", "first_args": "recover"},
        ],
    }

    for key, hyps in templates.items():
        if key in cat:
            result = []
            for i, h in enumerate(hyps, 1):
                result.append({**h, "rank": i, "rationale": "Category default", "source": "generic_fallback"})
            return result

    return [
        {"rank": 1, "hypothesis": "Static analysis to understand program logic", "confidence": 0.4, "first_tool": "pre_solve_recon", "first_args": "", "rationale": "Default recon", "source": "generic_fallback"},
        {"rank": 2, "hypothesis": "String extraction for embedded secrets", "confidence": 0.3, "first_tool": "extract_strings", "first_args": "", "rationale": "Default strings", "source": "generic_fallback"},
        {"rank": 3, "hypothesis": "Entropy analysis for encryption/compression", "confidence": 0.2, "first_tool": "analyze_file", "first_args": "entropy", "rationale": "Default entropy", "source": "generic_fallback"},
        {"rank": 4, "hypothesis": "Network traffic analysis", "confidence": 0.15, "first_tool": "pcap_analyze", "first_args": "", "rationale": "Default network", "source": "generic_fallback"},
        {"rank": 5, "hypothesis": "Web endpoint enumeration", "confidence": 0.1, "first_tool": "http_request", "first_args": "", "rationale": "Default web", "source": "generic_fallback"},
    ]


def render_fanout_for_prompt(hypotheses: list[dict[str, Any]]) -> str:
    if not hypotheses:
        return ""
    lines = ["## Pre-solve hypothesis fan-out (Haiku pre-analysis — ranked by confidence):"]
    for h in hypotheses:
        lines.append(f"  #{h.get('rank', '?')} [{h.get('confidence', 0):.0%}] {h.get('hypothesis', '')}")
        if h.get("first_tool"):
            lines.append(f"     → Start with: {h['first_tool']}({h.get('first_args', '')})")
        if h.get("rationale"):
            lines.append(f"     Rationale: {h['rationale']}")
    return "\n".join(lines)
