"""CTFtime scraper utilities for live writeup hint retrieval."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


def find_similar_writeups(challenge_name: str, challenge_description: str, limit: int = 3) -> list[str]:
    """Best-effort retrieval of CTFtime writeup references by challenge keyword."""
    q = re.sub(r"\s+", "+", (challenge_name or challenge_description or "ctf").strip())[:120]
    out: list[str] = []
    try:
        import requests

        # CTFtime supports simple event listing API; challenge-level metadata is sparse.
        # We use lightweight site search page snippets as a hint source.
        url = f"https://ctftime.org/search?q={q}"
        r = requests.get(url, timeout=8)
        txt = r.text[:200000]
        for m in re.finditer(r"<a[^>]+href=\"(/writeup/\d+)\"[^>]*>([^<]+)</a>", txt, re.IGNORECASE):
            path = m.group(1)
            title = re.sub(r"\s+", " ", m.group(2)).strip()
            out.append(f"{title} | https://ctftime.org{path}")
            if len(out) >= max(1, int(limit)):
                break
    except Exception:
        pass
    return out


@dataclass
class ctftime_scraperState:
    metadata: dict[str, Any] = field(default_factory=dict)


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    name = str(kwargs.get("challenge_name", ""))
    desc = str(kwargs.get("challenge_description", ""))
    limit = int(kwargs.get("limit", 3))
    hits = find_similar_writeups(name, desc, limit=limit)
    return {
        "module": "ctftime_scraper",
        "status": "ok",
        "input_summary": str(type(input_data).__name__),
        "kwargs_keys": sorted(kwargs.keys()),
        "hits": hits,
    }

