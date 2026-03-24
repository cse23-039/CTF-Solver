from __future__ import annotations


STRATEGY_PLAYBOOKS = {
    "binary exploitation": {
        "entry": "recon -> mitigations -> crash primitive -> control primitive -> exploit chain",
        "decision_tree": [
            "If NX off and direct RIP control: prioritize shellcode path.",
            "If PIE+Canary present: pivot to infoleak, then ret2libc/ROP.",
            "If heap indicators found: run heap grooming + allocator fingerprinting.",
        ],
        "tools": ["checksec", "binary_analysis", "execute_python", "rop_chain", "libc_lookup"],
    },
    "cryptography": {
        "entry": "classify primitive -> detect weakness -> verify with small tests -> recover secret",
        "decision_tree": [
            "If RSA with weak params/leaks: attempt factorization/CRT faults/small-exponent paths.",
            "If substitution/stream hints: run frequency/known-plaintext and keystream recovery.",
            "If oracle behavior detected: prioritize adaptive chosen-ciphertext flow.",
        ],
        "tools": ["crypto_attack", "decode_transform", "execute_python", "factordb", "rsa_toolkit"],
    },
    "web": {
        "entry": "surface mapping -> auth/session review -> injection matrix -> exploit + verify",
        "decision_tree": [
            "If user input reflected: test XSS + template injection + output encoding bypasses.",
            "If DB-backed forms: probe SQL/NoSQL then automate extraction path.",
            "If upload endpoints exist: run polyglot/MIME bypass with retrieval validation.",
        ],
        "tools": ["http_request", "web_crawl", "sqlmap", "nosql_inject", "file_upload", "template_inject"],
    },
    "reverse engineering": {
        "entry": "identify packer/obfuscation -> recover semantics -> derive key/check logic",
        "decision_tree": [
            "If symbols stripped: prioritize decompile + AI rename + execution traces.",
            "If anti-debug checks: bypass checks and re-run dynamic analysis.",
            "If crypto-like loops found: extract constants and test reduced models in Python.",
        ],
        "tools": ["disassemble", "ghidra_decompile", "ai_rename_functions", "execute_python", "frida_trace"],
    },
    "forensics": {
        "entry": "triage artifacts -> recover hidden data -> correlate timestamps/channels",
        "decision_tree": [
            "If image anomalies: inspect metadata, channels, LSB, broken headers.",
            "If pcap provided: reconstruct streams and extract credentials/tokens/files.",
            "If memory dump clues: process tree, strings, suspicious handles/modules.",
        ],
        "tools": ["analyze_file", "steg_brute", "pcap_reassemble", "volatility", "pdf_forensics"],
    },
}


def normalize_category_key(category: str) -> str:
    cat = str(category or "").strip().lower()
    if "pwn" in cat or "binary" in cat:
        return "binary exploitation"
    if "crypto" in cat:
        return "cryptography"
    if "web" in cat:
        return "web"
    if "reverse" in cat or "rev" in cat:
        return "reverse engineering"
    if "forensic" in cat:
        return "forensics"
    return cat


def build_attack_playbook(category: str, difficulty: str, phase: str, multimodal: dict | None = None) -> dict:
    key = normalize_category_key(category)
    pb = STRATEGY_PLAYBOOKS.get(key, {
        "entry": "recon -> hypothesis -> evidence -> exploit -> verify",
        "decision_tree": ["Use evidence-driven pivots and avoid repeating failed paths."],
        "tools": ["pre_solve_recon", "rank_hypotheses", "execute_python"],
    })
    diff = str(difficulty or "medium").lower()
    intensity = {"easy": "lean", "medium": "balanced", "hard": "deep", "insane": "max"}.get(diff, "balanced")
    mm_modalities = (multimodal or {}).get("modalities", [])
    return {
        "category": key,
        "phase": phase,
        "difficulty": diff,
        "intensity": intensity,
        "entry": pb.get("entry", ""),
        "decision_tree": pb.get("decision_tree", [])[:6],
        "tools": pb.get("tools", [])[:8],
        "modalities": mm_modalities,
    }


def render_playbook_for_prompt(playbook: dict) -> str:
    if not playbook:
        return ""
    lines = [
        "## Attack Strategy Library (Playbook)",
        f"Category profile: {playbook.get('category','general')} | intensity={playbook.get('intensity','balanced')} | phase={playbook.get('phase','recon')}",
        f"Entry flow: {playbook.get('entry','recon -> exploit -> verify')}",
        "Decision tree:",
    ]
    for idx, node in enumerate(playbook.get("decision_tree", [])[:6], 1):
        lines.append(f"{idx}. {node}")
    tools = playbook.get("tools", [])
    if tools:
        lines.append(f"Preferred tool chain: {', '.join(tools)}")
    if playbook.get("modalities"):
        lines.append(f"Multimodal priors: {', '.join(playbook.get('modalities', []))}")
    return "\n".join(lines)
