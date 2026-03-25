"""Live intel hint retrieval after fruitless iterations."""
from __future__ import annotations

from typing import Any


def fetch_live_writeup_hint(challenge_name: str, challenge_description: str, category: str, ctf_name: str = "") -> str:
    hints: list[str] = []
    try:
        from intel.ctftime_scraper import find_similar_writeups

        ctftime_hits = find_similar_writeups(challenge_name, challenge_description, limit=2)
        for h in ctftime_hits:
            hints.append(f"[CTFtime] {h}")
    except Exception:
        pass

    try:
        from intel.github_scraper import find_similar_writeups

        gh_hits = find_similar_writeups(challenge_name, challenge_description, limit=2)
        for h in gh_hits:
            hints.append(f"[GitHub] {h}")
    except Exception:
        pass

    if not hints:
        try:
            from solver.rag_store import retrieve_similar_challenges

            sims = retrieve_similar_challenges(challenge_description, category=category, top_k=2)
            for s in sims:
                hints.append(
                    f"[Local-RAG] {s.get('challenge_name','?')}: {s.get('attack_technique','')} | {str(s.get('solve_summary',''))[:220]}"
                )
        except Exception:
            pass

    if not hints:
        return ""
    return "## Live external writeup hints (fruitless loop recovery):\n" + "\n".join([f"- {x}" for x in hints[:4]])
