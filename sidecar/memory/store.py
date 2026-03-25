from __future__ import annotations

import hashlib
import json
import os
import re
import time

from solver.storage_retention import prune_jsonl


def memory_v2_path() -> str:
    return os.path.expanduser("~/.ctf-solver/challenge_memory_v2.jsonl")


def tokenize_simple(text: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z0-9_]{3,}", (text or "").lower()))


def challenge_fingerprint(challenge: dict, ctf_name: str = "") -> str:
    raw = "|".join([
        (ctf_name or "").strip().lower(),
        str(challenge.get("category", "")).strip().lower(),
        str(challenge.get("name", "")).strip().lower(),
        str(challenge.get("description", ""))[:2000].strip().lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]


def load_memory_v2(limit: int = 800) -> list[dict]:
    path = memory_v2_path()
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return rows[-limit:]


def store_memory_v2(record: dict) -> None:
    path = memory_v2_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if "memory_type" not in record:
        rtype = str(record.get("type", "")).lower()
        if rtype == "failure_map":
            record["memory_type"] = "anti_pattern"
        elif record.get("winning_path"):
            record["memory_type"] = "episodic"
        else:
            record["memory_type"] = "semantic"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    prune_jsonl(path, max_lines=180000, max_bytes=256 * 1024 * 1024)


def memory_trust_score(rec: dict, ctf_name: str = "", category: str = "", query_fingerprint: str = "") -> float:
    score = 0.45
    source_strength = float(rec.get("source_strength", 0.5) or 0.5)
    reproducibility = float(rec.get("reproducibility_count", 0.0) or 0.0)
    validator = rec.get("validator") if isinstance(rec.get("validator"), dict) else {}
    val_conf = float(validator.get("confidence", 0.0) or 0.0)
    if validator.get("verdict") == "pass":
        score += 0.18
    score += min(0.20, max(0.0, val_conf * 0.20))

    if rec.get("winning_path"):
        score += 0.08
    if rec.get("tool_sequence"):
        score += 0.06
    if rec.get("dead_ends"):
        score -= 0.05

    score += max(0.0, min(0.16, source_strength * 0.16))
    score += max(0.0, min(0.12, reproducibility * 0.03))

    if ctf_name and str(rec.get("ctf_name", "")).strip().lower() == ctf_name.strip().lower():
        score += 0.08
    if category and str(rec.get("category", "")).strip().lower() == category.strip().lower():
        score += 0.05
    if query_fingerprint and str(rec.get("fingerprint", "")) == query_fingerprint:
        score += 0.10

    ts = int(rec.get("timestamp", 0) or 0)
    if ts > 0:
        age_days = max(0.0, (time.time() - ts) / 86400.0)
        # Keep stale memory usable but never equally trusted as fresh evidence.
        score *= max(0.5, 1.0 - (age_days / 730.0))

    return max(0.0, min(1.0, score))


def analyze_memory_consistency(memory_hits: list[dict]) -> dict:
    if not memory_hits:
        return {
            "trusted_hits": [],
            "contradictions": [],
            "average_trust": 0.0,
            "summary": "No memory hits available",
            "guidance": "Proceed evidence-first with fresh recon.",
        }

    trusts = [float(h.get("_memory_trust", 0.0)) for h in memory_hits]
    average_trust = sum(trusts) / max(1, len(trusts))
    trusted_hits = [h for h in memory_hits if float(h.get("_memory_trust", 0.0)) >= 0.55]

    contradictions = []
    prefixes = {str(h.get("flag_prefix", "")).strip() for h in memory_hits if str(h.get("flag_prefix", "")).strip()}
    if len(prefixes) > 1:
        contradictions.append("multiple_flag_prefixes")

    top_tools = set()
    first_tools = set()
    for rec in memory_hits[:4]:
        seq = rec.get("tool_sequence")
        if isinstance(seq, list) and seq:
            top_tools.add(str(seq[0]))
            first_tools.add(str(seq[0]).strip().lower())
    if len(top_tools) >= 3 and len(memory_hits) <= 4:
        contradictions.append("divergent_opening_toolchains")
    if len(first_tools) >= 3 and len(memory_hits) >= 3:
        contradictions.append("conflicting_first_tool_signal")

    episodic = [h for h in memory_hits if str(h.get("memory_type", "")).lower() == "episodic"]
    anti_pattern = [h for h in memory_hits if str(h.get("memory_type", "")).lower() == "anti_pattern"]
    if anti_pattern and episodic and len(anti_pattern) >= len(episodic):
        contradictions.append("anti_pattern_dominance")

    summary = (
        f"memory_hits={len(memory_hits)} trusted={len(trusted_hits)} avg_trust={average_trust:.2f} "
        f"contradictions={len(contradictions)}"
    )
    guidance = (
        "Prefer top trusted memory paths as priors."
        if not contradictions else
        "Memory contains contradictory priors — use only high-trust records and re-verify every claim with tool output."
    )
    return {
        "trusted_hits": trusted_hits,
        "contradictions": contradictions,
        "average_trust": average_trust,
        "summary": summary,
        "guidance": guidance,
    }


def retrieve_memory_v2(challenge: dict, ctf_name: str = "", top_k: int = 3) -> list[dict]:
    query = " ".join([
        str(challenge.get("name", "")),
        str(challenge.get("category", "")),
        str(challenge.get("description", ""))[:2500],
    ])
    qtok = tokenize_simple(query)
    if not qtok:
        return []

    rows = load_memory_v2()
    scored = []
    category = str(challenge.get("category", "")).strip()
    query_fp = challenge_fingerprint(challenge, ctf_name)
    high_cost_mode = bool(challenge.get("high_cost_mode", False))
    min_trust = 0.62 if high_cost_mode else 0.45

    for rec in rows:
        doc = " ".join([
            str(rec.get("challenge_name", "")),
            str(rec.get("category", "")),
            str(rec.get("ctf_name", "")),
            str(rec.get("summary", "")),
            str(rec.get("winning_path", "")),
        ])
        rtok = tokenize_simple(doc)
        if not rtok:
            continue
        overlap = len(qtok & rtok)
        if overlap == 0:
            continue
        ctf_bonus = 3 if ctf_name and rec.get("ctf_name", "").strip().lower() == ctf_name.strip().lower() else 0
        similarity = overlap / max(1, len(qtok))
        trust = memory_trust_score(rec, ctf_name=ctf_name, category=category, query_fingerprint=query_fp)
        mtype = str(rec.get("memory_type", "semantic")).lower()
        type_mult = {"episodic": 1.18, "semantic": 1.0, "anti_pattern": 0.88}.get(mtype, 1.0)
        score = ((overlap + ctf_bonus) + (trust * 6.0)) * type_mult
        rec2 = dict(rec)
        rec2["_memory_similarity"] = round(similarity, 4)
        rec2["_memory_trust"] = round(trust, 4)
        rec2["_memory_score"] = round(score, 4)
        if trust < min_trust:
            continue
        scored.append((score, rec2))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [x[1] for x in scored[:max(1, top_k)]]


def build_memory_injection(memory_hits: list[dict]) -> str:
    if not memory_hits:
        return ""
    lines = ["## Retrieved prior challenge memory (high similarity):"]
    for i, rec in enumerate(memory_hits[:3], 1):
        trust = float(rec.get("_memory_trust", 0.0))
        sim = float(rec.get("_memory_similarity", 0.0))
        lines.append(
            f"{i}. [{rec.get('ctf_name','?')}] {rec.get('challenge_name','?')} "
            f"({rec.get('category','?')}) | trust={trust:.2f} sim={sim:.2f}"
        )
        if rec.get("winning_path"):
            lines.append(f"   Winning path: {str(rec.get('winning_path'))[:220]}")
        if rec.get("dead_ends"):
            dead = rec.get("dead_ends")
            dead_text = ", ".join(dead[:3]) if isinstance(dead, list) else str(dead)
            lines.append(f"   Dead ends to avoid: {dead_text[:220]}")
        if rec.get("tool_sequence"):
            seq = rec.get("tool_sequence")
            seq_text = " -> ".join(seq[:8]) if isinstance(seq, list) else str(seq)
            lines.append(f"   Tool chain: {seq_text[:220]}")
    lines.append("Use this as prior evidence, but verify with fresh tool outputs.")
    return "\n".join(lines)


def store_failure_path(
    challenge: dict,
    ctf_name: str,
    failed_approaches: list[str],
    category: str,
    difficulty: str,
) -> None:
    if not failed_approaches:
        return
    record = {
        "type": "failure_map",
        "fingerprint": challenge_fingerprint(challenge, ctf_name),
        "ctf_name": ctf_name,
        "category": category,
        "difficulty": difficulty,
        "failed_approaches": failed_approaches[:20],
        "source_strength": 0.55,
        "reproducibility_count": 1,
        "timestamp": int(time.time()),
    }
    store_memory_v2(record)


def retrieve_failure_paths(challenge: dict, ctf_name: str = "", top_k: int = 3) -> list[str]:
    fp = challenge_fingerprint(challenge, ctf_name)
    cat = str(challenge.get("category", "")).lower()
    rows = load_memory_v2(limit=400)
    scored_matches = []
    for row in rows:
        if row.get("type") != "failure_map":
            continue
        row_cat = str(row.get("category", "")).lower()
        row_ctf = str(row.get("ctf_name", "")).strip().lower()
        row_fp = str(row.get("fingerprint", ""))

        # Candidate scope: exact fingerprint OR same CTF/category neighborhood.
        if not (row_fp == fp or (ctf_name and row_ctf == ctf_name.strip().lower()) or row_cat == cat):
            continue

        score = 0.0
        if row_fp == fp:
            score += 0.65
        if ctf_name and row_ctf == ctf_name.strip().lower():
            score += 0.20
        if row_cat == cat:
            score += 0.15
        score += max(0.0, min(0.20, float(row.get("source_strength", 0.5) or 0.5) * 0.20))
        score += max(0.0, min(0.10, float(row.get("reproducibility_count", 0.0) or 0.0) * 0.05))

        ts = int(row.get("timestamp", 0) or 0)
        if ts > 0:
            age_days = max(0.0, (time.time() - ts) / 86400.0)
            # Faster decay for failures; stale dead-ends should not dominate.
            score *= max(0.4, 1.0 - (age_days / 90.0))

        if score >= 0.35:
            scored_matches.append((score, row))

    scored_matches.sort(key=lambda x: x[0], reverse=True)

    dead_ends = []
    for _, rec in scored_matches[:max(1, int(top_k))]:
        dead_ends.extend(rec.get("failed_approaches", []))
    return list(dict.fromkeys([str(d) for d in dead_ends if str(d).strip()]))
