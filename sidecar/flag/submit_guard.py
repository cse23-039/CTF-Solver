"""Hard flag submission guard combining prefix/context/entropy checks."""
from __future__ import annotations

import math
import re
from typing import Any


def _prefix_score(flag: str, ctf_name: str = "") -> float:
    f = str(flag or "")
    known = ["flag{", "ctf{", "picoctf{", "htb{", "thm{"]
    low = f.lower()
    if any(low.startswith(k) for k in known):
        return 1.0
    if re.match(r"^[A-Za-z0-9_]{2,20}\{.+\}$", f):
        return 0.75
    return 0.2


def _context_score(flag: str, evidence_log: list[dict], solve_log: list[str]) -> float:
    score = 0.0
    if flag and any(flag in str(e.get("output", "")) for e in (evidence_log or [])[-80:]):
        score += 0.65
    if flag and flag in "\n".join((solve_log or [])[-20:]):
        score += 0.25
    return min(1.0, score)


def _entropy_score(flag: str) -> float:
    inner = re.sub(r"^[^{]*\{|\}$", "", str(flag or ""))
    if not inner:
        return 0.0
    counts = {}
    for ch in inner:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(inner)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    # Typical CTF flags are mixed and moderately high entropy but not fully random.
    if 2.5 <= ent <= 5.5:
        return 1.0
    if 1.8 <= ent <= 6.0:
        return 0.7
    return 0.3


def score_flag_candidate(flag: str, ctf_name: str, evidence_log: list[dict], solve_log: list[str]) -> dict[str, Any]:
    regex_ok = bool(re.match(r"^[^\s]{2,40}\{[^\n\r]{3,300}\}$", str(flag or "")))
    prefix = _prefix_score(flag, ctf_name)
    context = _context_score(flag, evidence_log, solve_log)
    entropy = _entropy_score(flag)
    combined = (0.35 * prefix) + (0.40 * context) + (0.25 * entropy)
    hard_pass = regex_ok and prefix >= 0.5 and context >= 0.5 and combined >= 0.62
    return {
        "regex_ok": regex_ok,
        "prefix_score": round(prefix, 3),
        "context_score": round(context, 3),
        "entropy_score": round(entropy, 3),
        "combined_score": round(combined, 3),
        "pass": hard_pass,
    }
