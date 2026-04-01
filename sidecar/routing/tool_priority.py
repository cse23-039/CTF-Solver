"""Category-aware tool priority baselines for fast scheduling."""
from __future__ import annotations

from typing import Any


PRIORITIES = {
    "pwn": ["binary_analysis", "afl_fuzz", "angr_solve", "rop_chain", "format_string_exploit"],
    "web": ["web_crawl", "source_audit", "http_request", "sqlmap", "template_inject"],
    "crypto": ["crypto_attack", "rsa_toolkit", "dlog", "sage_math", "z3_solve"],
    "rev": ["ghidra_decompile", "binary_analysis", "deobfuscate", "unicorn_emulate", "symbolic_pipeline"],
    "forensics": ["analyze_file", "pcap_deep", "pdf_forensics", "disk_forensics", "windows_forensics"],
}


def get_priority(category_key: str) -> list[str]:
    return list(PRIORITIES.get(category_key, PRIORITIES["web"]))


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    key = str(kwargs.get("category_key", input_data if isinstance(input_data, str) else "web"))
    return {"category_key": key, "priority": get_priority(key)}
