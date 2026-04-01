"""GitHub writeup search utilities for live solve hinting."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def find_similar_writeups(challenge_name: str, challenge_description: str, limit: int = 3) -> list[str]:
    """Best-effort GitHub code search for challenge writeup snippets."""
    query = (challenge_name or challenge_description or "ctf writeup").strip()
    query = re.sub(r"\s+", "+", query)[:140]
    out: list[str] = []
    try:
        import requests

        # Public HTML search fallback, no token required.
        url = f"https://github.com/search?q={query}+writeup&type=code"
        r = requests.get(url, timeout=8, headers={"User-Agent": "ctf-solver/1.0"})
        txt = r.text[:250000]
        for m in re.finditer(r"href=\"(/[^\"]+/blob/[^\"]+)\"", txt):
            p = m.group(1)
            if "/blob/" not in p:
                continue
            link = f"https://github.com{p}"
            if link not in out:
                out.append(link)
            if len(out) >= max(1, int(limit)):
                break
    except Exception:
        pass
    return out


@dataclass
class github_scraperState:
    metadata: dict[str, Any] = field(default_factory=dict)


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    name = str(kwargs.get("challenge_name", ""))
    desc = str(kwargs.get("challenge_description", ""))
    limit = int(kwargs.get("limit", 3))
    hits = find_similar_writeups(name, desc, limit=limit)
    return {
        "module": "github_scraper",
        "status": "ok",
        "input_summary": str(type(input_data).__name__),
        "kwargs_keys": sorted(kwargs.keys()),
        "hits": hits,
    }

