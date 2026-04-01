"""Cross-challenge transfer utilities for family inference and tactic preload."""
from __future__ import annotations

import re
from typing import Any


def infer_challenge_family(name: str, description: str, category: str) -> str:
    text = f"{name} {description} {category}".lower()
    if re.search(r"rsa|ecdsa|nonce|oracle|lattice|mod|cipher", text):
        return "crypto-structured"
    if re.search(r"heap|rop|canary|ret2|libc|format", text):
        return "pwn-memory-corruption"
    if re.search(r"xss|sqli|ssti|jwt|csrf|xxe|idor|upload", text):
        return "web-appsec"
    if re.search(r"pcap|forensic|steg|exif|disk|memory dump", text):
        return "forensics-artifacts"
    if re.search(r"vm|bytecode|decompile|symbol|obfusc", text):
        return "reverse-devirtualization"
    return "general"


def preload_tactics(family: str, memory_hits: list[dict[str, Any]]) -> list[str]:
    tactics = []
    for rec in memory_hits[:8]:
        seq = rec.get("tool_sequence")
        if isinstance(seq, list) and seq:
            tactics.append(" -> ".join([str(x) for x in seq[:4]]))
    if not tactics:
        defaults = {
            "crypto-structured": ["pre_solve_recon -> crypto_attack -> z3_solve"],
            "pwn-memory-corruption": ["pre_solve_recon -> binary_analysis -> rop_chain"],
            "web-appsec": ["http_request -> source_audit -> web_attack"],
            "forensics-artifacts": ["analyze_file -> extract_strings -> forensics"],
            "reverse-devirtualization": ["disassemble -> decompile -> execute_python"],
            "general": ["pre_solve_recon -> rank_hypotheses"],
        }
        return defaults.get(family, defaults["general"])
    return list(dict.fromkeys(tactics))[:6]
