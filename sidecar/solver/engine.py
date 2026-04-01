"""Core solve loop."""
from __future__ import annotations

import importlib
import hashlib
import json
import os
import re
import shutil
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from core import orchestrator as core_orchestrator
except Exception:
    core_orchestrator = None


_MODEL_OPUS = "claude-opus-4-1-20250805"
_MODEL_SONNET = "claude-sonnet-4-6"
_MODEL_HAIKU = "claude-haiku-4-5-20251001"

_RUNTIME_BOOTSTRAPPED = False


def _safe_fail(payload: dict | None, message: str) -> None:
    msg = str(message or "Unknown solver runtime error")
    try:
        logger = globals().get("log")
        if callable(logger):
            logger("err", msg, "red")
        else:
            print(json.dumps({"type": "error", "message": msg}, ensure_ascii=False), flush=True)
    except Exception:
        try:
            print(json.dumps({"type": "error", "message": msg}, ensure_ascii=False), flush=True)
        except Exception:
            pass

    workspace = ""
    if isinstance(payload, dict):
        workspace = str(payload.get("base_dir", "") or "")

    try:
        result_fn = globals().get("result")
        if callable(result_fn):
            result_fn("failed", workspace=workspace)
        else:
            print(
                json.dumps(
                    {"type": "result", "status": "failed", "flag": None, "reason": msg, "workspace": workspace},
                    ensure_ascii=False,
                ),
                flush=True,
            )
    except Exception:
        try:
            print(
                json.dumps(
                    {"type": "result", "status": "failed", "flag": None, "reason": msg, "workspace": workspace},
                    ensure_ascii=False,
                ),
                flush=True,
            )
        except Exception:
            pass


def _bootstrap_runtime_context() -> None:
    global _RUNTIME_BOOTSTRAPPED
    if _RUNTIME_BOOTSTRAPPED:
        return

    if globals().get("core_orchestrator") is None:
        from core import orchestrator as _core_orchestrator
        globals()["core_orchestrator"] = _core_orchestrator

    candidate_modules = []
    main_mod = sys.modules.get("__main__")
    if main_mod is not None:
        candidate_modules.append(main_mod)

    for mod_name in ("solver", "sidecar.solver"):
        try:
            candidate_modules.append(importlib.import_module(mod_name))
        except Exception:
            continue

    for entry in candidate_modules:
        try:
            for name, value in vars(entry).items():
                if name.startswith("__"):
                    continue
                globals().setdefault(name, value)
        except Exception:
            continue

    try:
        from tools.shell import emit as _emit, log as _log, result as _result, _shell as __shell, IS_WINDOWS as _isw, USE_WSL as _uwsl, _w2l as __w2l
        globals().setdefault("emit", _emit)
        globals().setdefault("log", _log)
        globals().setdefault("result", _result)
        globals().setdefault("_shell", __shell)
        globals().setdefault("IS_WINDOWS", _isw)
        globals().setdefault("USE_WSL", _uwsl)
        globals().setdefault("_w2l", __w2l)
    except Exception:
        pass

    try:
        from tools.definitions import TOOLS as _TOOLS, TOOL_MAP as _TOOL_MAP, _ctf_knowledge as __ctf_knowledge
        globals().setdefault("TOOLS", _TOOLS)
        globals().setdefault("TOOL_MAP", _TOOL_MAP)
        globals().setdefault("_ctf_knowledge", __ctf_knowledge)
    except Exception:
        pass

    try:
        from tools.registry import build_tool_registry as _build_tool_registry, enabled_tools as _enabled_tools
        globals().setdefault("build_tool_registry", _build_tool_registry)
        globals().setdefault("enabled_tools", _enabled_tools)
    except Exception:
        pass

    try:
        from tools.forensics_impl import tool_analyze_file as _tool_analyze_file, tool_js_analyze as _tool_js_analyze
        globals().setdefault("tool_analyze_file", _tool_analyze_file)
        globals().setdefault("tool_js_analyze", _tool_js_analyze)
    except Exception:
        pass

    try:
        from tools.web_impl import tool_http_request as _tool_http_request
        globals().setdefault("tool_http_request", _tool_http_request)
    except Exception:
        pass

    try:
        from ai.model import _init_credit_guard as __init_credit_guard
        globals().setdefault("_init_credit_guard", __init_credit_guard)
    except Exception:
        pass

    try:
        from ai.prompt import build_system_prompt as _build_system_prompt, _build_attack_playbook as __build_attack_playbook, _build_multimodal_feature_pack as __build_multimodal_feature_pack, _normalize_category_key as __normalize_category_key
        globals().setdefault("build_system_prompt", _build_system_prompt)
        globals().setdefault("_build_attack_playbook", __build_attack_playbook)
        globals().setdefault("_build_multimodal_feature_pack", __build_multimodal_feature_pack)
        globals().setdefault("_normalize_category_key", __normalize_category_key)
    except Exception:
        pass

    try:
        from ai.memory import _tokenize_simple as __tokenize_simple, _store_failure_path as __store_failure_path, _retrieve_memory_v2 as __retrieve_memory_v2, _store_memory_v2 as __store_memory_v2
        globals().setdefault("_tokenize_simple", __tokenize_simple)
        globals().setdefault("_store_failure_path", __store_failure_path)
        globals().setdefault("_retrieve_memory_v2", __retrieve_memory_v2)
        globals().setdefault("_store_memory_v2", __store_memory_v2)
    except Exception:
        pass

    try:
        from flag.extractor import _build_challenge_signal_pack as __build_challenge_signal_pack, extract_flag as _extract_flag
        globals().setdefault("_build_challenge_signal_pack", __build_challenge_signal_pack)
        globals().setdefault("extract_flag", _extract_flag)
    except Exception:
        pass

    try:
        from memory.knowledge_graph import KnowledgeGraphStore as _KnowledgeGraphStore
        if globals().get("_KG_STORE") is None:
            globals()["_KG_STORE"] = _KnowledgeGraphStore()
    except Exception:
        pass

    globals().setdefault("_ctf_knowledge", defaultdict(dict))

    if globals().get("_KG_STORE") is None:
        class _NoopKnowledgeStore:
            db_path = ""

            def get_facts(self, _ctf_name):
                return {}

            def upsert_fact(self, _ctf_name, _key, _value):
                return None

            def query_context(self, _ctf_name, _query_terms, max_items=8):
                return []

            def render_cross_ctf_context(self, category="", technique_hint=""):
                return ""

            def ingest_solve_record(self, _record):
                return None

        globals()["_KG_STORE"] = _NoopKnowledgeStore()

    if globals().get("emit") is None:
        def _emit_fallback(t, **kw):
            print(json.dumps({"type": str(t), **kw}, ensure_ascii=False), flush=True)
        globals()["emit"] = _emit_fallback

    if globals().get("log") is None:
        def _log_fallback(tag, msg, cls=""):
            print(json.dumps({"type": "log", "tag": str(tag), "msg": str(msg), "cls": str(cls)}, ensure_ascii=False), flush=True)
        globals()["log"] = _log_fallback

    if globals().get("result") is None:
        def _result_fallback(status, flag=None, workspace=None):
            print(json.dumps({"type": "result", "status": str(status), "flag": flag, "workspace": workspace}, ensure_ascii=False), flush=True)
        globals()["result"] = _result_fallback

    try:
        from core import routing as _core_routing
        globals().setdefault("core_routing", _core_routing)
    except Exception:
        pass

    try:
        from core import verification as _core_verification
        globals().setdefault("core_verification", _core_verification)
    except Exception:
        pass

    globals().setdefault("_NETWORK_TOOLS", set())

    _RUNTIME_BOOTSTRAPPED = True


def _kgkey(ctf_name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', ctf_name.lower())


def tool_knowledge_store(ctf_name: str, key: str, value: str) -> str:
    """Store a discovered fact in the cross-challenge CTF knowledge graph."""
    k = _kgkey(ctf_name)
    _ctf_knowledge[k][key] = value
    try:
        _kg_upsert_fact(ctf_name, key, value)
    except Exception:
        pass
    emit("knowledge", ctf=ctf_name, key=key, value=value[:200])
    log("sys", f"[KG] Stored: {key} = {value[:80]}", "dim")
    return f"Stored: {key} → {value[:80]}"


def tool_knowledge_get(ctf_name: str) -> str:
    """Retrieve all known facts about a CTF (shared infrastructure, creds, patterns)."""
    k = _kgkey(ctf_name)
    facts = _ctf_knowledge.get(k, {})
    try:
        corpus = _KG_STORE.get_facts(ctf_name)
        if isinstance(corpus, dict):
            facts = {**corpus, **facts}
    except Exception:
        pass
    if not facts:
        return "No cross-challenge knowledge stored yet for this CTF."
    lines = [f"## Cross-challenge knowledge for '{ctf_name}':"]
    for key, val in facts.items():
        lines.append(f"  {key}: {val}")
    return "\n".join(lines)


def _get_knowledge_injection(ctf_name: str) -> str:
    """Build knowledge context string for system prompt injection."""
    k = _kgkey(ctf_name)
    facts = _ctf_knowledge.get(k, {})
    try:
        corpus = _KG_STORE.get_facts(ctf_name)
        if isinstance(corpus, dict):
            facts = {**corpus, **facts}
    except Exception:
        pass
    if not facts: return ""
    lines = ["## Known CTF context (from previous challenges):"]
    for key, val in facts.items():
        lines.append(f"  - {key}: {val}")
    return "\n".join(lines)


def _query_live_challenge_status(platform_config: dict, challenge_id: str) -> dict:
    """Best-effort live challenge status lookup from platform connector."""
    if not platform_config or platform_config.get("type") == "manual" or not challenge_id:
        return {"enabled": False, "found": False, "solved": False, "solve_count": 0}
    try:
        try:
            from platforms import get_challenge_status
        except Exception:
            import importlib
            sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if sidecar_root not in sys.path:
                sys.path.insert(0, sidecar_root)
            get_challenge_status = importlib.import_module("platforms").get_challenge_status

        data = get_challenge_status(platform_config, str(challenge_id))
        if isinstance(data, dict):
            data["enabled"] = True
            return data
    except Exception as e:
        return {"enabled": True, "error": str(e), "found": False, "solved": False, "solve_count": 0}
    return {"enabled": True, "found": False, "solved": False, "solve_count": 0}


def tool_rank_hypotheses(challenge_description: str, category: str,
                          recon_results: str, api_key: str = "") -> str:
    """
    Use Claude Haiku to rapidly score attack hypotheses by evidence strength.
    Returns ranked list of attack vectors with confidence scores and reasoning.
    This prevents wasting iterations on low-probability approaches.
    """
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "rank_hypotheses requires ANTHROPIC_API_KEY."

    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        resp = c.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"""CTF challenge analysis. Category: {category}

DESCRIPTION:
{challenge_description[:2000]}

RECON RESULTS:
{recon_results[:3000]}

List the top 5 attack vectors in order of likelihood. For each, give:
1. Attack name (specific technique)
2. Confidence 1-10
3. Key evidence supporting it
4. First tool to try

Format as:
#1 [confidence=X/10] ATTACK NAME
Evidence: ...
First step: tool_name(specific_args)

Be precise. No padding."""}]
        )
        return resp.content[0].text if resp.content else "No hypotheses generated."
    except Exception as e:
        return f"Hypothesis ranking error: {e}"


def tool_critic(conversation_summary: str, iterations_used: int,
                category: str, api_key: str = "") -> str:
    """
    Adversarial critic agent that reads the current approach and diagnoses failures.
    Triggers automatically every N fruitless iterations. Uses claude-sonnet-4-6.
    Returns concrete pivot recommendations.
    """
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "critic requires ANTHROPIC_API_KEY."

    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        resp = c.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"""You are a ruthless CTF expert reviewing a failed solve attempt.

CATEGORY: {category}
ITERATIONS USED: {iterations_used}

CONVERSATION SUMMARY (what has been tried):
{conversation_summary[:4000]}

Diagnose what is wrong with this approach. Be harsh and specific.
Then give 3 concrete next actions that are DIFFERENT from what was tried.

Format:
DIAGNOSIS: [one paragraph on what's wrong]
PIVOT 1: [specific tool + exact arguments]
PIVOT 2: [specific tool + exact arguments]
PIVOT 3: [specific tool + exact arguments]
KEY INSIGHT: [the one thing the solver is missing]"""}]
        )
        result_text = resp.content[0].text if resp.content else "Critic failed."
        log("warn", f"[CRITIC] {result_text[:200]}", "")
        return result_text
    except Exception as e:
        return f"Critic error: {e}"


def tool_pre_solve_recon(binary_path: str = "", url: str = "",
                          category: str = "Unknown") -> str:
    """
    Run parallel pre-solve reconnaissance appropriate for the challenge category.
    For pwn: checksec + file + strings + one_gadget
    For web: headers + robots.txt + source map check + JS endpoint scan
    For rev: file + strings + entropy + export/import table
    For forensics: file + exiftool + binwalk + entropy blocks
    Returns combined report to inform hypothesis generation.
    """
    results = {}
    tasks = []

    if binary_path and os.path.exists(binary_path):
        sp = _w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path
        if category in ("Binary Exploitation", "Reverse Engineering", "Unknown"):
            tasks = [
                ("file_type",  lambda: _shell(f"file '{sp}' && wc -c '{sp}'")),
                ("checksec",   lambda: _shell(f"checksec --file='{sp}' 2>/dev/null || python3 -c \"from pwn import ELF; print(ELF('{sp}').checksec())\" 2>/dev/null")),
                ("strings",    lambda: _shell(f"strings -n 8 '{sp}' | head -200")),
                ("functions",  lambda: _shell(f"nm '{sp}' 2>/dev/null | head -60; objdump -t '{sp}' 2>/dev/null | grep -i 'F' | head -30")),
                ("entropy",    lambda: tool_analyze_file(binary_path, "entropy")),
            ]
            if category == "Binary Exploitation":
                tasks.append(("one_gadget", lambda: _shell(f"one_gadget '{sp}' 2>/dev/null | head -30 || echo 'one_gadget not installed'")))
                tasks.append(("rop_gadgets", lambda: _shell(f"ROPgadget --binary '{sp}' --rop 2>/dev/null | head -40 || echo 'ROPgadget not installed'")))
        elif category == "Forensics":
            tasks = [
                ("file_type",  lambda: _shell(f"file '{sp}' && wc -c '{sp}'")),
                ("metadata",   lambda: _shell(f"exiftool '{sp}' 2>/dev/null | head -40")),
                ("binwalk",    lambda: _shell(f"binwalk '{sp}' 2>/dev/null")),
                ("entropy",    lambda: tool_analyze_file(binary_path, "entropy")),
                ("strings",    lambda: _shell(f"strings -n 6 '{sp}' | grep -iE 'flag|ctf|key|secret|pass' | head -30")),
            ]

    elif url:
        tasks = [
            ("http_headers", lambda: tool_http_request(url, headers={"User-Agent": "Mozilla/5.0"})),
            ("robots",       lambda: tool_http_request(url.rstrip("/")+"/robots.txt")),
            ("source_map",   lambda: tool_js_analyze(url, "fetch_sourcemap") if url.endswith(".js") else "N/A"),
            ("tech_detect",  lambda: _shell(f"whatweb '{url}' 2>/dev/null || curl -sI '{url}' | head -20")),
        ]

    lines = ["## Pre-solve recon results:"]
    with ThreadPoolExecutor(max_workers=min(len(tasks), 6)) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks}
        for fut in as_completed(futures, timeout=60):
            name = futures[fut]
            try:
                out = str(fut.result())[:1500]
                results[name] = out
                lines.append(f"\n### {name}\n{out}")
            except Exception as e:
                lines.append(f"\n### {name}\nError: {e}")

    return "\n".join(lines)


def _validator_agent_secondary(candidate_flag: str, evidence_excerpt: str, api_key: str = "") -> dict:
    fallback = {
        "verdict": "pass" if candidate_flag and "{" in candidate_flag and "}" in candidate_flag else "fail",
        "confidence": 0.55,
        "reason": "secondary-fallback"
    }
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return fallback
    try:
        import anthropic as _ant
        cli = _ant.Anthropic(api_key=api_key)
        prompt = f"""Return ONLY JSON with verdict, confidence, reason.\nCandidate flag: {candidate_flag}\nEvidence:\n{evidence_excerpt[:2800]}\nIf chain-of-custody is weak, fail."""
        resp = cli.messages.create(
            model=_MODEL_HAIKU,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.content[0].text if resp.content else ""
        j = re.search(r"\{[\s\S]*\}", raw)
        if not j:
            return fallback
        out = json.loads(j.group(0))
        verdict = str(out.get("verdict", "fail")).strip().lower()
        return {
            "verdict": "pass" if verdict == "pass" else "fail",
            "confidence": max(0.0, min(1.0, float(out.get("confidence", 0.5) or 0.5))),
            "reason": str(out.get("reason", "secondary-agent"))[:220],
        }
    except Exception:
        return fallback


def _reproducibility_check(candidate_flag: str, evidence_log: list[dict], solve_log: list[str]) -> dict:
    text_window = "\n".join(solve_log[-12:])
    in_reasoning = candidate_flag in text_window if candidate_flag else False
    evidence_hits = 0
    for rec in (evidence_log or [])[-80:]:
        out = str(rec.get("output", ""))
        if candidate_flag and candidate_flag in out:
            evidence_hits += 1
    pass_ok = in_reasoning or evidence_hits > 0
    conf = 0.72 if evidence_hits >= 2 else (0.62 if pass_ok else 0.20)
    return {
        "verdict": "pass" if pass_ok else "fail",
        "confidence": conf,
        "reason": f"reasoning_hit={in_reasoning} evidence_hits={evidence_hits}",
        "evidence_hits": evidence_hits,
    }


def _run_self_verification(candidate_flag: str, conversation_summary: str, ctf_name: str, category: str,
                           evidence_log: list[dict], solve_log: list[str], api_key: str = "") -> dict:
    return core_verification.run_self_verification(
        candidate_flag=candidate_flag,
        conversation_summary=conversation_summary,
        ctf_name=ctf_name,
        category=category,
        evidence_log=evidence_log,
        solve_log=solve_log,
        validate_candidate_flag=_validate_candidate_flag,
        model_haiku=_MODEL_HAIKU,
        api_key=api_key,
    )


def _kg_corpus_path() -> str:
    return _KG_STORE.db_path


def _kg_upsert_fact(ctf_name: str, key: str, value: str) -> None:
    _KG_STORE.upsert_fact(ctf_name, key, value)


def _kg_query_context(ctf_name: str, query_terms: set[str], max_items: int = 8) -> list[str]:
    return _KG_STORE.query_context(ctf_name, query_terms, max_items=max_items)


def _compute_expected_value_score(challenge: dict) -> float:
    return core_routing.compute_expected_value_score(challenge)


def _run_exploit_dev_automation(category: str, challenge_ctx: dict, workspace: str, extra: dict) -> dict:
    cat = _normalize_category_key(category)
    artifacts = []
    loops = []
    if cat in ("binary exploitation", "reverse engineering"):
        loops.append({
            "name": "exploit_script_variants",
            "variants": ["ret2win", "ret2libc", "rop-chain", "format-string"],
            "validation": ["local_replay", "remote_probe", "stability_check"],
        })
    if cat == "web":
        loops.append({
            "name": "web_attack_variants",
            "variants": ["sqli_boolean", "sqli_time", "ssti_probe", "upload_polyglot"],
            "validation": ["response_diff", "timing_delta", "auth_state_change"],
        })
    if cat == "cryptography":
        loops.append({
            "name": "crypto_hypothesis_variants",
            "variants": ["parameter_edge_case", "modulus_fault", "oracle_adaptive"],
            "validation": ["known_plaintext", "consistency_check"],
        })

    if loops:
        payload = {
            "ts": int(time.time()),
            "category": cat,
            "challenge": challenge_ctx.get("name", ""),
            "loops": loops,
            "fuzzing": {
                "enabled": True,
                "seed_strategy": "evidence_guided",
                "max_cases": int(extra.get("fuzzMaxCases", 128)),
            },
        }
        if workspace:
            try:
                out_dir = os.path.join(workspace, ".solver")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, "exploit_dev_automation.json")
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                artifacts.append(out_path)
            except Exception:
                pass
        return {"enabled": True, "loops": loops, "artifacts": artifacts}
    return {"enabled": False, "loops": [], "artifacts": []}


def run_benchmark(payload: dict):
    _bootstrap_runtime_context()
    rows = payload.get("results", []) if isinstance(payload.get("results"), list) else []
    total = len(rows)
    if total == 0:
        emit("benchmark_summary", error="no_results")
        print(json.dumps({"type": "benchmark_result", "status": "failed", "error": "no_results"}, ensure_ascii=False), flush=True)
        return

    solved = 0
    total_time = 0.0
    total_cost = 0.0
    false_flags = 0
    for rec in rows:
        status = str(rec.get("status", "")).lower()
        solved += 1 if status == "solved" else 0
        total_time += float(rec.get("elapsed", 0.0) or 0.0)
        total_cost += float(rec.get("spent_usd", 0.0) or 0.0)
        false_flags += 1 if bool(rec.get("false_flag", False)) else 0

    solve_rate = solved / max(1, total)
    time_to_flag = (total_time / max(1, solved)) if solved else 0.0
    cost_per_flag = (total_cost / max(1, solved)) if solved else total_cost
    false_flag_rate = false_flags / max(1, total)

    gates = payload.get("gates", {}) if isinstance(payload.get("gates"), dict) else {}
    min_solve = float(gates.get("min_solve_rate", 0.0) or 0.0)
    max_cost = float(gates.get("max_cost_per_flag", 99999.0) or 99999.0)
    max_false = float(gates.get("max_false_flag_rate", 1.0) or 1.0)

    gate_ok = (solve_rate >= min_solve) and (cost_per_flag <= max_cost) and (false_flag_rate <= max_false)
    summary = {
        "type": "benchmark_result",
        "status": "passed" if gate_ok else "failed",
        "total": total,
        "solved": solved,
        "solve_rate": round(solve_rate, 4),
        "time_to_flag": round(time_to_flag, 3),
        "cost_per_flag": round(cost_per_flag, 6),
        "false_flag_rate": round(false_flag_rate, 4),
        "gates": {"min_solve_rate": min_solve, "max_cost_per_flag": max_cost, "max_false_flag_rate": max_false},
    }
    emit("benchmark_summary", **summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)


def _evidence_log_path(workspace: str = "") -> str:
    if workspace:
        return os.path.join(workspace, ".solver", "evidence_log.jsonl")
    return os.path.expanduser("~/.ctf-solver/runtime_evidence.jsonl")


def _persist_evidence_record(workspace: str, record: dict) -> str:
    path = _evidence_log_path(workspace)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    clean = dict(record)
    clean["ts"] = int(time.time())
    clean["input_hash"] = hashlib.sha256(
        json.dumps(clean.get("input", {}), ensure_ascii=False, sort_keys=True).encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    clean["output_hash"] = hashlib.sha256(
        str(clean.get("output", "")).encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(clean, ensure_ascii=False) + "\n")
    try:
        from solver.storage_retention import prune_jsonl as _prune_jsonl
        _prune_jsonl(path, max_lines=120000, max_bytes=128 * 1024 * 1024)
    except Exception:
        pass
    return path


def _run_self_healing_preflight(category: str) -> dict:
    cat = (category or "").lower()
    required = ["python", "strings"]
    if "web" in cat:
        required.extend(["curl"])
    if "binary" in cat or "pwn" in cat or "reverse" in cat:
        required.extend(["file", "objdump", "gdb"])
    if "crypto" in cat:
        required.extend(["openssl"])

    available = []
    missing = []
    for cmd in sorted(set(required)):
        ok = bool(shutil.which(cmd))
        if (not ok) and IS_WINDOWS and USE_WSL:
            check = _shell(f"command -v {cmd} >/dev/null 2>&1 && echo ok || echo missing", timeout=8)
            ok = "ok" in (check or "")
        (available if ok else missing).append(cmd)

    fallbacks = {
        "gdb": "Fallback to pre_solve_recon + disassemble + binary_analysis",
        "objdump": "Fallback to disassemble + execute_python(pwntools)",
        "curl": "Fallback to http_request tool",
        "openssl": "Fallback to crypto_attack and decode_transform",
        "file": "Fallback to file_type tool",
    }
    fallback_plan = [fallbacks[m] for m in missing if m in fallbacks]
    summary = f"preflight available={len(available)} missing={len(missing)}"
    return {
        "ok": len(missing) == 0,
        "available": available,
        "missing": missing,
        "fallback_plan": fallback_plan,
        "summary": summary,
    }


def _decide_strategy_mode(category: str, phase: str, fruitless: int, tool_failures: int,
                          iteration: int, total_iters: int, memory_diag: dict,
                          learned_overrides: dict | None = None,
                          state_vector: dict | None = None) -> dict:
    return core_routing.decide_strategy_mode(
        category=category,
        phase=phase,
        fruitless=fruitless,
        tool_failures=tool_failures,
        iteration=iteration,
        total_iters=total_iters,
        memory_diag=memory_diag,
        learned_overrides=learned_overrides,
        state_vector=state_vector,
    )


def _validate_candidate_flag(conversation_summary: str, candidate_flag: str,
                             ctf_name: str, category: str, api_key: str = "") -> dict:
    local_fmt_ok = bool(extract_flag(candidate_flag, ctf_name) == candidate_flag)
    fallback = {
        "verdict": "pass" if local_fmt_ok else "fail",
        "confidence": 0.65 if local_fmt_ok else 0.25,
        "reason": "local_format_check",
        "required_checks": ["verify_with_source_artifact", "replay_command_once"],
        "evidence": [f"candidate={candidate_flag}", f"local_format_ok={local_fmt_ok}"],
    }

    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return fallback

    try:
        import anthropic as _ant
        client = _ant.Anthropic(api_key=api_key)
        prompt = f"""You are a strict CTF solution validator.
Return ONLY JSON with keys: verdict, confidence, reason, required_checks, evidence.

CTF: {ctf_name}
Category: {category}
Candidate flag: {candidate_flag}

Recent solver transcript:
{conversation_summary[:5000]}

Rules:
- verdict must be pass or fail.
- confidence must be 0.0-1.0.
- If evidence chain is weak, return fail.
- required_checks must be concrete replay/verification steps.
"""
        resp = client.messages.create(
            model=_MODEL_SONNET,
            max_tokens=900,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.content[0].text if resp.content else ""
        jmatch = re.search(r"\{[\s\S]*\}", raw)
        if not jmatch:
            return fallback
        data = json.loads(jmatch.group(0))
        verdict = str(data.get("verdict", "")).strip().lower()
        confidence = float(data.get("confidence", fallback["confidence"]))
        if verdict not in ("pass", "fail"):
            verdict = fallback["verdict"]
        data["verdict"] = verdict
        data["confidence"] = max(0.0, min(1.0, confidence))
        if "required_checks" not in data or not isinstance(data.get("required_checks"), list):
            data["required_checks"] = fallback["required_checks"]
        if "evidence" not in data or not isinstance(data.get("evidence"), list):
            data["evidence"] = fallback["evidence"]
        if not data.get("reason"):
            data["reason"] = "validator_output"
        return data
    except Exception:
        return fallback


def _specialists_for_category(category: str) -> list[str]:
    base = ["planner", "critic"]
    cat = (category or "").lower()
    if "binary" in cat or "pwn" in cat:
        return base + ["pwn", "rev", "crypto", "forensics", "web"]
    if "reverse" in cat:
        return base + ["rev", "pwn", "crypto", "forensics", "web"]
    if "crypto" in cat:
        return base + ["crypto", "rev", "web", "forensics", "pwn"]
    if "forensic" in cat:
        return base + ["forensics", "rev", "crypto", "web", "pwn"]
    if "web" in cat:
        return base + ["web", "crypto", "forensics", "rev", "pwn"]
    return base + ["web", "crypto", "rev", "forensics", "pwn"]


def _parse_json_block(text: str):
    if not text:
        return None
    m = re.search(r"\{[\s\S]*\}|\[[\s\S]*\]", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _default_tool_graph(category: str, binary_path: str = "", url: str = "") -> list[dict]:
    cat = (category or "").lower()
    graph = []
    if "web" in cat and url:
        graph = [
            {"id": "n1", "tool": "http_request", "input": {"url": url, "method": "GET"}, "retry": 2},
            {"id": "n2", "tool": "execute_shell", "depends_on": ["n1"],
             "input": {"command": f"curl -skI '{url}' | head -40"}, "retry": 1},
        ]
    elif binary_path:
        graph = [
            {"id": "n1", "tool": "pre_solve_recon", "input": {"binary_path": binary_path, "category": category}, "retry": 1},
            {"id": "n2", "tool": "rank_hypotheses", "depends_on": ["n1"],
             "input": {"challenge_description": "auto", "category": category, "recon_results": "auto"}, "retry": 1},
        ]
    else:
        graph = [
            {"id": "n1", "tool": "detect_flag_format", "input": {"ctf_name": "auto", "description": "auto"}, "retry": 1}
        ]
    return graph


def _run_specialist_agent(spec: str, challenge_ctx: dict, api_key: str,
                          model: str = _MODEL_SONNET) -> list[dict]:
    if not api_key:
        return []
    try:
        import anthropic as _ant
        c = _ant.Anthropic(api_key=api_key)
        prompt = f"""You are the {spec} specialist in a CTF multi-agent team.
Return ONLY JSON list of 1-3 objects with keys:
- hypothesis
- score (0-100)
- evidence_gain (0-100)
- first_tool
- first_input (object)

Challenge:
Category: {challenge_ctx.get('category','')}
Name: {challenge_ctx.get('name','')}
Description:
{challenge_ctx.get('description','')[:2500]}
Files summary:
{str(challenge_ctx.get('files',''))[:1200]}
"""
        resp = c.messages.create(model=model, max_tokens=900, messages=[{"role": "user", "content": prompt}])
        raw = resp.content[0].text if resp.content else ""
        data = _parse_json_block(raw)
        if isinstance(data, list):
            cleaned = []
            for item in data[:3]:
                if not isinstance(item, dict):
                    continue
                hyp = str(item.get("hypothesis", "")).strip()
                if not hyp:
                    continue
                cleaned.append({
                    "specialist": spec,
                    "hypothesis": hyp,
                    "score": int(item.get("score", 50)),
                    "evidence_gain": int(item.get("evidence_gain", 50)),
                    "first_tool": str(item.get("first_tool", "")),
                    "first_input": item.get("first_input", {}) if isinstance(item.get("first_input", {}), dict) else {},
                })
            if cleaned:
                return cleaned
    except Exception:
        pass

    return [{
        "specialist": spec,
        "hypothesis": f"{spec} baseline analysis path",
        "score": 48,
        "evidence_gain": 45,
        "first_tool": "pre_solve_recon",
        "first_input": {"category": challenge_ctx.get("category", "Unknown")},
    }]


def _build_hypothesis_tree(spec_outputs: list[dict]) -> list[dict]:
    tree = []
    for i, node in enumerate(spec_outputs, 1):
        score = int(node.get("score", 50))
        gain = int(node.get("evidence_gain", 50))
        combined = round((score * 0.65) + (gain * 0.35), 2)
        tree.append({
            "id": f"h{i}",
            "parent": "root",
            "specialist": node.get("specialist", "unknown"),
            "hypothesis": node.get("hypothesis", ""),
            "first_tool": node.get("first_tool", ""),
            "first_input": node.get("first_input", {}),
            "score": score,
            "evidence_gain": gain,
            "combined": combined,
        })
    tree.sort(key=lambda x: x["combined"], reverse=True)
    return tree


def _prune_hypothesis_tree(tree: list[dict], keep: int = 5) -> list[dict]:
    pruned = tree[:max(1, keep)]
    for n in pruned:
        n["pruned"] = False
    for n in tree[max(1, keep):]:
        n["pruned"] = True
    return pruned


def _resolve_auto_input(data: dict, challenge_ctx: dict, prior_outputs: dict) -> dict:
    out = {}
    for k, v in (data or {}).items():
        if isinstance(v, str) and v == "auto":
            if k == "challenge_description":
                out[k] = challenge_ctx.get("description", "")
            elif k == "category":
                out[k] = challenge_ctx.get("category", "Unknown")
            elif k == "recon_results":
                out[k] = "\n\n".join([str(x)[:1200] for x in prior_outputs.values()])
            elif k == "ctf_name":
                out[k] = challenge_ctx.get("ctf_name", "")
            elif k == "description":
                out[k] = challenge_ctx.get("description", "")
            else:
                out[k] = ""
        else:
            out[k] = v
    return out


def _tool_output_success(out: str) -> bool:
    txt = str(out or "").lower()
    bad_markers = ["tool error", "unknown tool", "traceback", "timed out", "failed"]
    return not any(m in txt for m in bad_markers)


def _execute_tool_plan_graph(plan_graph: list[dict], challenge_ctx: dict,
                             max_workers: int = 3) -> tuple[str, list[dict], dict]:
    if not plan_graph:
        return "No planner graph provided.", [], {}

    nodes = {n.get("id", f"n{idx}"): n for idx, n in enumerate(plan_graph, 1)}
    completed = {}
    evidence = []
    pending = set(nodes.keys())
    failed_nodes = set()

    def run_node(node_id: str):
        n = nodes[node_id]
        tool = n.get("tool", "")
        inp = _resolve_auto_input(n.get("input", {}), challenge_ctx, completed)
        retry = int(n.get("retry", 1))
        fallback_tool = n.get("fallback_tool", "")
        fallback_input = _resolve_auto_input(n.get("fallback_input", {}), challenge_ctx, completed)

        attempt = 0
        last_out = ""
        success = False
        used_tool = tool
        while attempt < max(1, retry):
            attempt += 1
            if tool in TOOL_MAP:
                try:
                    last_out = str(TOOL_MAP[tool](inp))
                except Exception as e:
                    last_out = f"Tool error: {type(e).__name__}: {e}"
            else:
                last_out = f"Unknown tool: {tool}"
            success = _tool_output_success(last_out)
            if success:
                break

        if (not success) and fallback_tool:
            used_tool = fallback_tool
            if fallback_tool in TOOL_MAP:
                try:
                    last_out = str(TOOL_MAP[fallback_tool](fallback_input))
                except Exception as e:
                    last_out = f"Tool error: {type(e).__name__}: {e}"
            else:
                last_out = f"Unknown fallback tool: {fallback_tool}"
            success = _tool_output_success(last_out)

        return {
            "node_id": node_id,
            "tool": used_tool,
            "input": inp,
            "success": success,
            "output": last_out,
            "depends_on": n.get("depends_on", []),
        }

    while pending:
        ready = []
        for nid in list(pending):
            deps = nodes[nid].get("depends_on", []) or []
            if all(d in completed for d in deps):
                ready.append(nid)

        if not ready:
            # deadlock / cyclic deps
            break

        batch = ready[:max(1, max_workers)]
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
            futs = {ex.submit(run_node, nid): nid for nid in batch}
            for fut in as_completed(futs):
                rec = fut.result()
                nid = rec["node_id"]
                pending.discard(nid)
                completed[nid] = rec["output"]
                evidence.append(rec)
                emit("planner_node", node=nid, tool=rec["tool"], success=rec["success"])
                if not rec["success"]:
                    failed_nodes.add(nid)

    summary_lines = [
        f"Planner graph executed: {len(evidence)} node(s)",
        f"Failed nodes: {len(failed_nodes)}",
    ]
    for rec in evidence[:10]:
        summary_lines.append(
            f"- {rec['node_id']} [{rec['tool']}] success={rec['success']}"
        )
    return "\n".join(summary_lines), evidence, completed


def _run_hierarchical_planner(challenge_ctx: dict, api_key: str,
                              extra: dict) -> dict:
    specialists = _specialists_for_category(challenge_ctx.get("category", "Unknown"))
    specialist_outputs = []
    # skip planner/critic pseudo-roles for actual hypothesis generation
    for spec in [s for s in specialists if s not in ("planner", "critic")][:5]:
        specialist_outputs.extend(_run_specialist_agent(spec, challenge_ctx, api_key))

    tree = _build_hypothesis_tree(specialist_outputs)
    keep = int(extra.get("hypothesisKeep", 5))
    pruned = _prune_hypothesis_tree(tree, keep=keep)
    hypotheses = [n.get("hypothesis", "") for n in pruned if n.get("hypothesis")]

    default_graph = _default_tool_graph(
        category=challenge_ctx.get("category", "Unknown"),
        binary_path=challenge_ctx.get("binary_path", ""),
        url=challenge_ctx.get("instance", ""),
    )

    # Build planner graph from top hypotheses first-tool hints
    graph = []
    for idx, n in enumerate(pruned[:3], 1):
        tool = n.get("first_tool", "")
        if tool and tool in TOOL_MAP:
            graph.append({
                "id": f"h{idx}",
                "tool": tool,
                "input": n.get("first_input", {}),
                "retry": 2,
                "fallback_tool": "pre_solve_recon",
                "fallback_input": {"category": challenge_ctx.get("category", "Unknown")},
            })
    if not graph:
        graph = default_graph

    return {
        "specialists": specialists,
        "tree": tree,
        "pruned": pruned,
        "hypotheses": hypotheses,
        "plan_graph": graph,
    }


def _update_autonomous_phase(state: dict, iteration: int, tool_used: bool,
                             found_signal: bool, fruitless: int) -> dict:
    phase = state.get("phase", "recon")
    if phase == "recon" and (iteration >= 3 or found_signal):
        phase = "exploit"
    if phase == "exploit" and fruitless >= 3:
        phase = "refine"
    if phase == "refine" and found_signal:
        phase = "validate"
    state["phase"] = phase
    state["cycles"] = int(state.get("cycles", 0)) + (1 if tool_used else 0)
    return state


def _run_branch(branch_id: int, hypothesis: str, challenge_ctx: dict,
                api_key: str, active_tools: list, system: str,
                max_iters: int, extra: dict,
                result_queue: list, stop_event: threading.Event,
                credit_guard: dict | None = None) -> None:
    """
    Run a single hypothesis branch. Adds flag to result_queue if found.
    Stops early if stop_event is set (another branch won).
    """
    try:
        import anthropic as _ant
        client = _ant.Anthropic(api_key=api_key)
        ctf_name = challenge_ctx.get("ctf_name", "")
        cat = challenge_ctx.get("category", "")
        name = challenge_ctx.get("name", "")

        branch_system = system + f"\n\n## Branch {branch_id} hypothesis:\n{hypothesis}\nPursue ONLY this approach. If you find strong counter-evidence after 3 tool calls, say HYPOTHESIS_FAILED."

        msgs = [{"role": "user", "content":
                 f"[Branch {branch_id}] {challenge_ctx.get('user_msg','')}"}]

        for i in range(max_iters):
            if stop_event.is_set(): return
            if i % 2 == 0:
                try:
                    live_status = _query_live_challenge_status(_PLATFORM_CONFIG, str(challenge_ctx.get("platform_id", "") or ""))
                    if bool(live_status.get("solved", False)):
                        emit("solve_cancelled", reason="teammate_solved_parallel", branch=branch_id)
                        stop_event.set()
                        return
                except Exception:
                    pass
            try:
                planned = _plan_budgeted_call(
                    credit_guard or {"enabled": False},
                    model=_MODEL_SONNET,
                    requested_max_tokens=1800,
                    messages=msgs,
                    system=branch_system,
                    use_thinking=False,
                    thinking_tokens=0,
                )
                if not planned.get("allowed", True):
                    return
                resp = client.messages.create(
                    model=planned.get("model", _MODEL_SONNET),
                    max_tokens=int(planned.get("max_tokens", 1800)),
                    system=branch_system, tools=active_tools, messages=msgs
                )
                _record_credit_usage(
                    credit_guard or {"enabled": False},
                    model=planned.get("model", _MODEL_SONNET),
                    usage=getattr(resp, "usage", None),
                    fallback_estimated_cost=float(planned.get("estimated_cost", 0.0)),
                )
            except Exception: return

            tool_results = []
            for block in resp.content:
                btype = getattr(block, "type", None)
                if btype == "text":
                    if "HYPOTHESIS_FAILED" in block.text: return
                    flag = extract_flag(block.text, ctf_name)
                    if flag:
                        result_queue.append((branch_id, hypothesis, flag))
                        stop_event.set()
                        return
                elif btype == "tool_use":
                    if block.name in TOOL_MAP:
                        try:
                            tout = TOOL_MAP[block.name](block.input)
                        except Exception as e:
                            tout = str(e)
                    else:
                        tout = f"Unknown tool: {block.name}"
                    flag = extract_flag(str(tout), ctf_name)
                    if flag:
                        result_queue.append((branch_id, hypothesis, flag))
                        stop_event.set()
                        return
                    tool_results.append({"type":"tool_result","tool_use_id":block.id,"content":str(tout)})

            msgs.append({"role":"assistant","content":resp.content})
            stop = getattr(resp,"stop_reason",None)
            if tool_results:
                msgs.append({"role":"user","content":tool_results})
            elif stop == "end_turn":
                return
    except Exception:
        return


def run_parallel_branches(hypotheses: list, challenge_ctx: dict, api_key: str,
                          active_tools: list, system: str, branch_iters: int,
                          extra: dict,
                          credit_guard: dict | None = None) -> tuple[str, str] | None:
    """
    Launch 2-3 parallel hypothesis branches. Return (winning_hypothesis, flag) or None.
    """
    if not hypotheses: return None
    branches = hypotheses[:3]  # max 3 concurrent branches
    result_queue = []
    stop_event = threading.Event()

    log("sys", f"[PARALLEL] Launching {len(branches)} hypothesis branches simultaneously", "bright")
    for i, hyp in enumerate(branches):
        log("sys", f"  Branch {i+1}: {hyp[:80]}", "dim")

    threads = []
    for i, hyp in enumerate(branches):
        t = threading.Thread(
            target=_run_branch,
            args=(i+1, hyp, challenge_ctx, api_key, active_tools, system,
                  branch_iters, extra, result_queue, stop_event, credit_guard),
            daemon=True
        )
        threads.append(t)
        t.start()

    # Wait for first result or all threads to finish
    deadline = time.time() + branch_iters * 45  # rough timeout
    while not stop_event.is_set() and time.time() < deadline:
        if all(not t.is_alive() for t in threads): break
        time.sleep(2)

    stop_event.set()
    for t in threads: t.join(timeout=5)

    if result_queue:
        branch_id, hyp, flag = result_queue[0]
        log("ok", f"[PARALLEL] Branch {branch_id} won: {flag}", "white")
        return hyp, flag
    return None


def run_import(payload):
    _bootstrap_runtime_context()
    pc=payload.get("platform",{}); base_dir=payload.get("base_dir",""); ctf_name=payload.get("ctf_name","CTF")
    watch = bool(payload.get("watchNewChallenges", False))
    watch_interval = max(5, int(payload.get("watchIntervalSeconds", 30) or 30))
    watch_cycles = int(payload.get("watchCycles", 0) or 0)
    auto_queue = bool(payload.get("autoQueuePolicy", True))
    auto_start = bool(payload.get("autoStartSolveOnNew", False))
    max_auto_starts = max(1, int(payload.get("maxAutoStartsPerCycle", 1) or 1))
    solve_api_key = str(payload.get("api_key", "") or "")
    solve_model = str(payload.get("model", "claude-sonnet-4-6") or "claude-sonnet-4-6")
    solve_extra = payload.get("extraConfig", {}) if isinstance(payload.get("extraConfig", {}), dict) else {}
    single_active_lock = bool(payload.get("singleActiveSolveLock", True))
    lock_ttl_s = max(60, int(payload.get("singleActiveSolveLockTtlSeconds", 6 * 3600) or 6 * 3600))
    queue_maxsize = max(1, int(payload.get("autoSolveQueueSize", 16) or 16))
    queue_heartbeat_seconds = max(3.0, float(payload.get("autoSolveQueueHeartbeatSeconds", 15.0) or 15.0))
    from solver.import_scheduler import (
        try_acquire_active_solve_lock as _try_acquire_active_solve_lock_raw,
        release_active_solve_lock as _release_active_solve_lock_raw,
        build_queue as _build_queue_raw,
        persist_queue as _persist_queue_raw,
    )
    from solver.solve_executor import execute_solve_payload as _execute_solve_payload
    from solver.auto_solve_queue import AutoSolveQueue as _AutoSolveQueue

    def _try_acquire_active_solve_lock() -> tuple[bool, str]:
        return _try_acquire_active_solve_lock_raw(
            base_dir=base_dir,
            ctf_name=ctf_name,
            ttl_s=lock_ttl_s,
            enabled=single_active_lock,
            emit_cb=emit,
        )

    def _release_active_solve_lock(lock_path: str) -> None:
        _release_active_solve_lock_raw(lock_path, enabled=single_active_lock, emit_cb=emit)

    def _build_queue(rows: list[dict]) -> list[dict]:
        return _build_queue_raw(rows, expected_value_fn=_compute_expected_value_score)

    def _persist_queue(queue_rows: list[dict], cycle_no: int) -> str:
        return _persist_queue_raw(base_dir=base_dir, ctf_name=ctf_name, queue_rows=queue_rows, cycle_no=cycle_no)

    queue_persist_dir = os.path.join(base_dir, re.sub(r'[<>:"/\\|?*]', "_", str(ctf_name)).strip()[:80], ".solver")

    def _run_queued_job(job: dict) -> None:
        lock_path = str(job.get("lock_path", "") or "")
        challenge_name = str(job.get("challenge_name", "") or "")
        rank = int(job.get("rank", 0) or 0)
        cycle_no = int(job.get("cycle", 0) or 0)
        try:
            _execute_solve_payload(_run_solve_impl, job.get("payload", {}))
        finally:
            _release_active_solve_lock(lock_path)
            emit(
                "auto_solve_finished",
                ctf_name=ctf_name,
                challenge=challenge_name,
                rank=rank,
                cycle=cycle_no,
            )

    auto_queue_worker = _AutoSolveQueue(
        maxsize=queue_maxsize,
        emit_cb=emit,
        run_cb=_run_queued_job,
        heartbeat_seconds=queue_heartbeat_seconds,
        persist_dir=queue_persist_dir,
        max_retries=max(0, int(payload.get("autoSolveMaxRetries", 2) or 2)),
    )
    auto_queue_worker.start()

    def _launch_auto_solve(item: dict, cycle_no: int = 0) -> bool:
        lock_ok, lock_path = _try_acquire_active_solve_lock()
        if not lock_ok:
            emit(
                "auto_solve_skipped",
                ctf_name=ctf_name,
                challenge=item.get("name", ""),
                reason="active_solve_in_progress",
                lock_path=lock_path,
                cycle=cycle_no,
            )
            return False

        solve_payload = {
            "challenge": item,
            "api_key": solve_api_key,
            "model": solve_model,
            "platform": pc,
            "base_dir": base_dir,
            "ctf_name": ctf_name,
            "extraConfig": {**solve_extra, "adaptiveAllocator": True, "queueExpectedValue": float(item.get("queue_expected_value", 0.0))},
        }

        enqueued = auto_queue_worker.enqueue(
            {
                "challenge_name": item.get("name", ""),
                "payload": solve_payload,
                "lock_path": lock_path,
                "rank": item.get("queue_rank", 0),
                "cycle": cycle_no,
                "lease_id": f"{ctf_name}:{item.get('platform_id', item.get('id', item.get('name', 'unknown')))}:{cycle_no}",
            }
        )
        if not enqueued:
            _release_active_solve_lock(lock_path)
            emit(
                "auto_solve_skipped",
                ctf_name=ctf_name,
                challenge=item.get("name", ""),
                reason="queue_full",
                cycle=cycle_no,
            )
            return False

        emit(
            "auto_solve_enqueued",
            ctf_name=ctf_name,
            challenge=item.get("name", ""),
            rank=item.get("queue_rank", 0),
            cycle=cycle_no,
        )
        return True

    if not base_dir:
        log("err","No base directory set","red"); emit("import_result",error="No base directory"); return
    log("sys",f"Connecting to {pc.get('type','?')}...","bright")
    try:
        sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
        from platforms import import_challenges
        if not watch:
            res=import_challenges(pc,base_dir,ctf_name,incremental=True)
            if res.get("error"): log("err",res["error"],"red"); emit("import_result",error=res["error"]); return
            log("ok",res.get("login_message","Connected"),"white")
            n=len(res.get("challenges",[])); log("sys",f"Fetched {n} challenges (new={res.get('new_count',0)} updated={res.get('updated_count',0)})","bright")
            for err in res.get("errors",[]): log("warn",err,"")
            queue_rows = []
            queue_path = ""
            if auto_queue:
                queue_rows = _build_queue(res.get("new_challenges", []) + res.get("updated_challenges", []))
                try:
                    queue_path = _persist_queue(queue_rows, cycle_no=1)
                except Exception:
                    queue_path = ""
                emit("import_queue", ctf_name=ctf_name, cycle=1, queue=queue_rows[:25], queue_count=len(queue_rows), queue_path=queue_path)
            emit("import_result",challenges=res.get("challenges",[]),
                 platform_token=res.get("platform_token"),ctf_name=ctf_name,
                 new_count=res.get("new_count",0),updated_count=res.get("updated_count",0))

            if auto_start and solve_api_key and queue_rows:
                starts = 0
                for item in queue_rows[:max_auto_starts]:
                    if not _launch_auto_solve(item, cycle_no=1):
                        break
                    starts += 1
                    emit("auto_solve_start", ctf_name=ctf_name, challenge=item.get("name", ""), rank=item.get("queue_rank", 0), expected_value=item.get("queue_expected_value", 0.0))
                emit("auto_solve_batch", ctf_name=ctf_name, started=starts, requested=max_auto_starts)
            return

        cycle = 0
        while True:
            cycle += 1
            res = import_challenges(pc, base_dir, ctf_name, incremental=True)
            if res.get("error"):
                log("warn", f"Import watch cycle {cycle} failed: {res.get('error')}", "")
                emit("import_watch", cycle=cycle, status="error", error=res.get("error"))
            else:
                new_rows = res.get("new_challenges", []) or []
                updated_rows = res.get("updated_challenges", []) or []
                if new_rows or updated_rows:
                    log("sys", f"[IMPORT WATCH] cycle={cycle} new={len(new_rows)} updated={len(updated_rows)}", "bright")
                queue_rows = []
                queue_path = ""
                if auto_queue and (new_rows or updated_rows):
                    queue_rows = _build_queue((new_rows or []) + (updated_rows or []))
                    try:
                        queue_path = _persist_queue(queue_rows, cycle_no=cycle)
                    except Exception:
                        queue_path = ""
                emit(
                    "import_watch",
                    cycle=cycle,
                    status="ok",
                    new_count=len(new_rows),
                    updated_count=len(updated_rows),
                    new_challenges=new_rows,
                    updated_challenges=updated_rows,
                    queue_count=len(queue_rows),
                    queue=queue_rows[:25],
                    queue_path=queue_path,
                    platform_token=res.get("platform_token"),
                    ctf_name=ctf_name,
                )

                if auto_start and solve_api_key and queue_rows:
                    starts = 0
                    for item in queue_rows[:max_auto_starts]:
                        if not _launch_auto_solve(item, cycle_no=cycle):
                            break
                        starts += 1
                        emit("auto_solve_start", ctf_name=ctf_name, challenge=item.get("name", ""), rank=item.get("queue_rank", 0), expected_value=item.get("queue_expected_value", 0.0), cycle=cycle)
                    emit("auto_solve_batch", ctf_name=ctf_name, cycle=cycle, started=starts, requested=max_auto_starts)

            if watch_cycles > 0 and cycle >= watch_cycles:
                break
            time.sleep(watch_interval)

        emit("import_result", status="watch_completed", cycles=cycle, ctf_name=ctf_name)
    except Exception as e:
        log("err",f"Import failed: {e}","red"); emit("import_result",error=str(e))
    finally:
        try:
            auto_queue_worker.stop()
        except Exception:
            pass


def _run_solve_impl(payload):
    _bootstrap_runtime_context()
    global _PLATFORM_CONFIG, _solve_start_time, _current_model_display
    _solve_start_time = time.time()

    challenge      = payload.get("challenge",{})
    api_key        = payload.get("api_key","")
    user_model     = payload.get("model","claude-sonnet-4-6")
    pc             = payload.get("platform",{})
    base_dir       = payload.get("base_dir","")
    ctf_name       = payload.get("ctf_name","")
    extra          = payload.get("extraConfig",{})
    human_loop = {
        "approve_pivot": bool(extra.get("humanApprovePivot", False)),
        "lock_strategy": bool(extra.get("lockStrategy", False)),
        "locked_mode": str(extra.get("lockedStrategyMode", "")).strip(),
        "force_local_only": bool(extra.get("forceLocalOnly", False)),
    }
    allocator_cfg = {
        "enabled": bool(extra.get("adaptiveAllocator", True)),
        "queue_expected_value": float(extra.get("queueExpectedValue", 0.0) or 0.0),
    }

    _PLATFORM_CONFIG = {**pc,"challenge_id":challenge.get("platform_id","")}
    os.environ["ANTHROPIC_API_KEY"] = api_key  # make available to sub-agents

    if not api_key: log("err","No API key","red"); result("failed"); return
    try: import anthropic
    except ImportError: log("err","pip install anthropic","red"); result("failed"); return

    client = anthropic.Anthropic(api_key=api_key)

    name    = challenge.get("name","Unknown")
    challenge_id = challenge.get("id", "")
    platform_challenge_id = str(challenge.get("platform_id", "") or "")
    cat     = challenge.get("category","Unknown")
    diff    = challenge.get("difficulty","medium")
    pts     = challenge.get("points",0)
    desc    = challenge.get("description","(no description)")
    files   = challenge.get("files","")
    inst    = challenge.get("instance","")
    ffmt    = challenge.get("flagFormat") or challenge.get("flag_format","")
    ws      = challenge.get("workspace","")
    signal_pack = _build_challenge_signal_pack(challenge, extra)
    explicit_hints = signal_pack.get("explicit_hints", [])
    name_hints = signal_pack.get("name_hints", [])
    signal_summary = signal_pack.get("signal_summary", "")
    augmented_desc = signal_pack.get("augmented_description", desc)
    emit(
        "challenge_signals",
        hint_count=len(explicit_hints),
        name_hint_count=len(name_hints),
        has_signals=bool(signal_summary)
    )

    live_sync_enabled = bool(extra.get("liveTeamSync", True))
    live_sync_poll_seconds = float(extra.get("liveTeamSyncPollSeconds", 12.0) or 12.0)
    live_sync_poll_iter = int(extra.get("liveTeamSyncPollIters", 1) or 1)
    last_live_sync_ts = 0.0
    baseline_solve_count = int(challenge.get("solve_count", challenge.get("solves", 0)) or 0)

    # ── Score-guided iteration budget ────────────────────────────────────────
    budget_override = int(payload.get("max_iterations",0))
    if budget_override > 0:
        max_iterations = budget_override
    else:
        max_iterations = ITERATION_BUDGET.get(diff.lower(), 25)
    if allocator_cfg.get("enabled", True):
        ev = allocator_cfg.get("queue_expected_value", 0.0)
        if ev > 1.2:
            max_iterations = int(max_iterations * 1.15)
        elif ev < 0.6:
            max_iterations = max(8, int(max_iterations * 0.75))
        try:
            from solver.branch_budgeting import allocate_mpc_budget as _allocate_mpc_budget
            mpc = _allocate_mpc_budget(
                base_iterations=max_iterations,
                expected_value=float(ev),
                difficulty=diff,
                reliability_pressure=float(extra.get("reliabilityPressure", 0.2) or 0.2),
            )
            max_iterations = int(mpc.get("total", max_iterations))
            extra["verificationReserveIterations"] = int(mpc.get("verify", 2))
            extra["exploreIterations"] = int(mpc.get("explore", max_iterations))
            emit("mpc_budget", **mpc)
        except Exception:
            pass
    credit_guard = _init_credit_guard(extra, challenge, max_iterations)
    if credit_guard.get("enabled", False) and credit_guard.get("conservative", False):
        max_iterations = min(max_iterations, int(credit_guard.get("conservative_cap_iters", max_iterations)))
    max_tokens_default = 1800 if credit_guard.get("conservative", False) else 4096
    max_tokens = int(extra.get("maxTokens", max_tokens_default))

    # Enabled tools filter via registry
    registry = build_tool_registry(TOOLS, TOOL_MAP)
    enabled = set(extra.get("enabledTools", list(TOOL_MAP.keys())))
    active_tools = enabled_tools(registry, enabled)
    if human_loop.get("force_local_only", False):
        active_tools = [t for t in active_tools if t.get("name") not in _NETWORK_TOOLS]
        emit("human_loop", action="force_local_only", active_tools=len(active_tools))

    # ── Cross-challenge knowledge injection ──────────────────────────────────
    knowledge_ctx = _get_knowledge_injection(ctf_name)
    kg_query_terms = _tokenize_simple(" ".join([str(challenge.get("name", "")), str(challenge.get("description", ""))[:1200]]))
    kg_hits = _kg_query_context(ctf_name, kg_query_terms, max_items=8)
    if kg_hits:
        knowledge_ctx += "\n\n## Queried knowledge graph matches:\n" + "\n".join([f"  - {h}" for h in kg_hits])
    cross_ctf_ctx = ""
    try:
        cross_ctf_ctx = _KG_STORE.render_cross_ctf_context(category=cat, technique_hint=" ".join(list(kg_query_terms)[:6]))
    except Exception:
        cross_ctf_ctx = ""
    rag_ctx = ""
    pre_fanout_hypotheses = []
    try:
        from solver.rag_store import render_rag_context as _render_rag_context
        rag_ctx = _render_rag_context(description=augmented_desc, category=cat, top_k=int(extra.get("ragTopK", 3)))
    except Exception:
        rag_ctx = ""
    try:
        from solver.hypothesis_fanout import speculative_hypothesis_fanout as _speculative_fanout
        from solver.hypothesis_fanout import render_fanout_for_prompt as _render_fanout_for_prompt_boot
        pre_fanout_hypotheses = _speculative_fanout(
            challenge_description=(signal_pack.get("augmented_description", augmented_desc) or augmented_desc),
            category=cat,
            difficulty=diff,
            rag_context=rag_ctx,
            cross_ctf_context=cross_ctf_ctx,
            api_key=api_key,
        )
        fanout_block = _render_fanout_for_prompt_boot(pre_fanout_hypotheses)
        if fanout_block:
            knowledge_ctx += "\n\n" + fanout_block
    except Exception:
        pre_fanout_hypotheses = []
    memory_hits = _retrieve_memory_v2(
        {
            **challenge,
            "high_cost_mode": bool(extra.get("highCostMode", True)),
        },
        ctf_name=ctf_name,
        top_k=int(extra.get("memoryTopK", 3))
    )
    try:
        from memory.trust_controls import filter_for_high_cost as _filter_for_high_cost
        if bool(extra.get("highCostMode", True)):
            memory_hits = _filter_for_high_cost(memory_hits, min_trust=float(extra.get("memoryHighCostTrust", 0.62)))
    except Exception:
        pass
    memory_diag = _analyze_memory_consistency(memory_hits)
    trusted_memory_hits = memory_diag.get("trusted_hits", [])
    memory_ctx = _build_memory_injection(trusted_memory_hits or memory_hits)
    challenge_family = "general"
    transfer_tactics = []
    try:
        from solver.transfer_learning import infer_challenge_family as _infer_challenge_family, preload_tactics as _preload_tactics
        challenge_family = _infer_challenge_family(name=name, description=augmented_desc, category=cat)
        transfer_tactics = _preload_tactics(challenge_family, trusted_memory_hits or memory_hits)
        emit("transfer_learning", family=challenge_family, tactic_count=len(transfer_tactics))
    except Exception:
        challenge_family = "general"
        transfer_tactics = []
    emit(
        "memory_retrieval",
        hits=len(memory_hits),
        challenges=[h.get("challenge_name", "") for h in memory_hits[:3]]
    )
    emit(
        "memory_consistency",
        average_trust=round(float(memory_diag.get("average_trust", 0.0)), 3),
        contradictions=memory_diag.get("contradictions", []),
        trusted_hits=len(trusted_memory_hits),
        guidance=memory_diag.get("guidance", ""),
    )

    multimodal_pack = _build_multimodal_feature_pack(challenge, files, extra)
    playbook = _build_attack_playbook(cat, diff, phase="recon", multimodal=multimodal_pack)
    emit(
        "multimodal_ingest",
        modalities=multimodal_pack.get("modalities", []),
        attachment_count=multimodal_pack.get("attachment_count", 0),
        ingest_mode=multimodal_pack.get("ingest_mode", "native_structured"),
    )
    emit(
        "strategy_playbook",
        category=playbook.get("category", "general"),
        intensity=playbook.get("intensity", "balanced"),
        phase=playbook.get("phase", "recon"),
        tools=playbook.get("tools", []),
    )

    # ── Auto-detect flag format ───────────────────────────────────────────────
    auto_fmt = tool_detect_flag_format(ctf_name=ctf_name, description=desc,
                                        platform_type=pc.get("type",""), hint=ffmt or "")
    fmt_match = re.search(r"Prefix:\s+(.+)\n.*Example:\s+(.+)\n.*Confidence:\s+(\S+)", auto_fmt)
    fmt_inject = ""
    if fmt_match:
        fmt_inject = (f"\n## Auto-Detected Flag Format\n"
                      f"Prefix: {fmt_match.group(1).strip()} | "
                      f"Example: {fmt_match.group(2).strip()} | "
                      f"Confidence: {fmt_match.group(3).strip()}\n")

    # ── System prompt ─────────────────────────────────────────────────────────
    dead_ends = []
    try:
        dead_ends = _retrieve_failure_paths(challenge, ctf_name=ctf_name, top_k=int(extra.get("failureMemoryTopK", 3)))
    except Exception:
        dead_ends = []

    system = build_system_prompt(pc.get("type","manual"), ctf_name, base_dir, extra, category=cat, dead_ends=dead_ends)
    if memory_ctx:
        system = memory_ctx + "\n\n" + system
    if knowledge_ctx:
        system = knowledge_ctx + "\n\n" + system
    if cross_ctf_ctx:
        system = cross_ctf_ctx + "\n\n" + system
    if rag_ctx:
        system = rag_ctx + "\n\n" + system

    remaining_budget = _credit_remaining_usd(credit_guard)
    log("sys",f"{'WSL2' if IS_WINDOWS and USE_WSL else 'Win' if IS_WINDOWS else 'Linux'} | budget={max_iterations}iters | tools={len(active_tools)} | api_budget=${remaining_budget:.2f}","")
    log("sys",f"━━━ [{cat}] {name} ({diff}, {pts}pts) ━━━","bright")
    emit("solve_start", name=name, category=cat, difficulty=diff, points=pts,
         budget=max_iterations, tools=len(active_tools))
    emit(
        "credit_status",
        challenge_id=challenge_id,
        challenge_name=name,
        enabled=credit_guard.get("enabled", False),
        conservative=credit_guard.get("conservative", False),
        cap_usd=credit_guard.get("cap_usd", 0.0),
        spent_usd=credit_guard.get("spent_usd", 0.0),
        remaining_usd=remaining_budget,
        reserve_usd=credit_guard.get("reserve_usd", 0.0),
        low_threshold_usd=credit_guard.get("low_threshold_usd", 0.0),
        low=_credit_is_low(credit_guard),
    )

    # ── Build base user message ───────────────────────────────────────────────
    pb = PromptBuildBuffer()
    pb.add("Solve this CTF challenge completely.\n\n")
    pb.add(f"Challenge: {name}\n")
    pb.add(f"Category:  {cat}\n")
    pb.add(f"Difficulty:{diff}\n")
    pb.add(f"Points:    {pts}\n")
    pb.add(f"CTF:       {ctf_name or 'Unknown'}\n")
    if ffmt:
        pb.add(f"Flag format: {ffmt}\n")
    if inst:
        pb.add(f"Instance:   {inst}\n")
    if base_dir:
        pb.add(f"Base dir:   {base_dir}\n")
    if ws:
        pb.add(f"Workspace:  {ws} (already created)\n")
    elif base_dir and ctf_name:
        pb.add(f"\nCall create_workspace(base_dir='{base_dir}', ctf_name='{ctf_name}', category='{cat}', challenge_name='{name}')\n")

    pb.add(f"\n## Description\n{desc}\n")
    if signal_summary:
        pb.add(f"\n## Parsed Challenge Signals\n{signal_summary}\n")
    mm_prompt = _render_multimodal_for_prompt(multimodal_pack)
    if mm_prompt:
        pb.add(f"\n{mm_prompt}\n")
    playbook_prompt = _render_playbook_for_prompt(playbook)
    if playbook_prompt:
        pb.add(f"\n{playbook_prompt}\n")
    if memory_diag.get("summary"):
        pb.add(f"\n## Memory Trust/Consistency\n{memory_diag.get('summary')}\n")
        pb.add(f"Guidance: {memory_diag.get('guidance','')}\n")
    if explicit_hints:
        pb.add("\n## Platform/Provided Hints\n")
        for idx, hint_text in enumerate(explicit_hints[:12], 1):
            pb.add(f"{idx}. {hint_text}\n")
    if name_hints:
        pb.add("\n## Name-Derived Clues\n")
        for idx, hint_text in enumerate(name_hints[:12], 1):
            pb.add(f"{idx}. {hint_text}\n")
    if dead_ends:
        pb.add("\n## Known Dead Ends (from similar prior challenges)\n")
        for idx, dead_end in enumerate(dead_ends[:10], 1):
            pb.add(f"{idx}. {dead_end}\n")
    if files:
        pb.add(f"\n## Challenge Files / Source / Data\n```\n{files[:8000]}\n```\n")
    if fmt_inject:
        pb.add(fmt_inject)
    if memory_ctx:
        pb.add(f"\n{memory_ctx}\n")
    if knowledge_ctx:
        pb.add(f"\n{knowledge_ctx}\n")
    if cross_ctf_ctx:
        pb.add(f"\n{cross_ctf_ctx}\n")
    if rag_ctx:
        pb.add(f"\n{rag_ctx}\n")
    if transfer_tactics:
        pb.add("\n## Cross-Challenge Transfer Tactics\n")
        pb.add(f"Family: {challenge_family}\n")
        for t in transfer_tactics[:8]:
            pb.add(f"- {t}\n")
    pb.add("\n**METHODOLOGY**: planner+specialists → hypothesis tree + pruning → tool graph execution → parallel branches → autonomous recon→exploit→refine loop → validator gate → submit_flag → evidence-backed WRITEUP.md")
    pb.add("\n\n**CREDIT GUARD (MANDATORY)**: be frugal with API usage; prefer tool-driven/local reasoning first, minimize repeated long outputs, and avoid expensive model escalation unless evidence shows clear expected gain.")
    user_msg = pb.build()

    challenge_ctx = {
        "ctf_name": ctf_name,
        "category": cat,
        "name": name,
        "description": augmented_desc,
        "files": files,
        "instance": inst,
        "hints": explicit_hints,
        "name_hints": name_hints,
        "binary_path": challenge.get("binary_path", "") or challenge.get("file_path", ""),
        "multimodal": multimodal_pack,
        "playbook": playbook,
    }

    if bool(extra.get("replayMode", False)):
        try:
            from solver.replay import replay as _replay_rows
            replay_path = os.path.join((ws or base_dir or os.getcwd()), ".solver", "decision_replay.jsonl")
            rows = _replay_rows(replay_path, limit=int(extra.get("replayLimit", 250)))
            action_counts = {}
            for r in rows:
                a = str((r.get("action") or {}).get("type", "unknown"))
                action_counts[a] = int(action_counts.get(a, 0)) + 1
            emit("replay_audit", rows=len(rows), actions=action_counts)
            print(json.dumps({"type": "replay_audit", "rows": len(rows), "actions": action_counts}, ensure_ascii=False), flush=True)
        except Exception as e:
            emit("replay_audit", error=str(e))
            print(json.dumps({"type": "replay_audit", "error": str(e)}, ensure_ascii=False), flush=True)
        result("failed", workspace=ws)
        return

    if bool(extra.get("regressionAuditMode", False)):
        try:
            from solver.regression_audit import run_regression_audit as _run_regression_audit
            audit_workspace = ws or base_dir or os.getcwd()
            audit = _run_regression_audit(
                workspace=audit_workspace,
                min_solve_rate=float(extra.get("regressionMinSolveRate", 0.6) or 0.6),
                max_false_flag_rate=float(extra.get("regressionMaxFalseFlagRate", 0.15) or 0.15),
            )
            emit("regression_audit", **audit)
            print(json.dumps({"type": "regression_audit", **audit}, ensure_ascii=False), flush=True)
        except Exception as e:
            emit("regression_audit", error=str(e))
            print(json.dumps({"type": "regression_audit", "error": str(e)}, ensure_ascii=False), flush=True)
        result("failed", workspace=ws)
        return

    if bool(extra.get("offlineEvalMode", False)):
        try:
            from solver.offline_eval import run_offline_eval as _run_offline_eval
            dataset_path = str(extra.get("offlineEvalDataset", "") or "")
            if not dataset_path:
                raise RuntimeError("offlineEvalDataset is required")
            audit = _run_offline_eval(
                dataset_path=dataset_path,
                benchmark_path=os.path.join((ws or base_dir or os.getcwd()), ".solver", "benchmark_history.json"),
                gates=extra.get("benchmarkGates", {}) if isinstance(extra.get("benchmarkGates", {}), dict) else {},
            )
            emit("offline_eval", **audit)
            print(json.dumps({"type": "offline_eval", **audit}, ensure_ascii=False), flush=True)
        except Exception as e:
            emit("offline_eval", error=str(e))
            print(json.dumps({"type": "offline_eval", "error": str(e)}, ensure_ascii=False), flush=True)
        result("failed", workspace=ws)
        return

    if bool(extra.get("chaosHarnessMode", False)):
        try:
            from solver.chaos_harness import run_chaos_harness as _run_chaos_harness
            audit = _run_chaos_harness(
                seed=int(extra.get("chaosSeed", 42) or 42),
                rounds=int(extra.get("chaosRounds", 40) or 40),
            )
            emit("chaos_harness", **audit)
            print(json.dumps({"type": "chaos_harness", **audit}, ensure_ascii=False), flush=True)
        except Exception as e:
            emit("chaos_harness", error=str(e))
            print(json.dumps({"type": "chaos_harness", "error": str(e)}, ensure_ascii=False), flush=True)
        result("failed", workspace=ws)
        return

    # ── Phase-3 adaptive engines (lazy imports to avoid hard startup dependency) ──
    _rank_branches_live = None
    _symbolic_orchestrate_live = None
    _fuse_branch_results_live = None
    _autonomous_exploit_loop_live = None
    _benchmark_evaluate = None
    _append_iteration_telemetry = None
    _should_retrain_weekly = None
    _retrain_priors = None
    _get_learned_overrides = None
    _a_star_attack_path = None
    _update_edge_success = None
    _build_state_vector = None
    _ContextualBandit = None
    _HypothesisManager = None
    _allocate_budget = None
    _should_early_stop_branch = None
    _append_replay = None
    _run_haiku_critic = None
    _grade_tool_result = None
    _quality_to_bandit_update = None
    _run_self_play_debate = None
    _render_debate_for_prompt = None
    _thinking_tracker = None
    _DifficultyEstimator = None
    _rag_ingest_solved = None
    _score_tool_novelty = None
    _ToolDeduplicator = None
    _synthesize_branch_progress = None
    _record_chain_edge = None
    _fetch_live_writeup_hint = None
    _score_flag_candidate = None
    _maybe_compress_messages = None
    _BeliefGraph = None
    _run_council = None
    _compute_slo_pressure = None
    _decide_slo_controls = None
    _ToolChainPolicy = None
    _detect_hint_deception = None
    try:
        from solver.unified_scorer import rank_branches as _rank_branches_live
    except Exception:
        _rank_branches_live = None
    try:
        from solver.symbolic_manager import orchestrate as _symbolic_orchestrate_live
    except Exception:
        _symbolic_orchestrate_live = None
    try:
        from cluster.result_merger import fuse as _fuse_branch_results_live
    except Exception:
        _fuse_branch_results_live = None
    try:
        from solver.reflection_loop import autonomous_exploit_loop as _autonomous_exploit_loop_live
    except Exception:
        _autonomous_exploit_loop_live = None
    try:
        from solver.benchmark_gate import evaluate as _benchmark_evaluate
    except Exception:
        _benchmark_evaluate = None
    try:
        from solver.policy_learning import (
            append_iteration_telemetry as _append_iteration_telemetry,
            should_retrain_weekly as _should_retrain_weekly,
            retrain_priors as _retrain_priors,
            get_learned_overrides as _get_learned_overrides,
        )
    except Exception:
        _append_iteration_telemetry = None
        _should_retrain_weekly = None
        _retrain_priors = None
        _get_learned_overrides = None
    try:
        from routing.heuristics import a_star_attack_path as _a_star_attack_path, update_edge_success as _update_edge_success
    except Exception:
        _a_star_attack_path = None
        _update_edge_success = None
    try:
        from solver.state_vector import build_state_vector as _build_state_vector
    except Exception:
        _build_state_vector = None
    try:
        from solver.contextual_bandit import ContextualBandit as _ContextualBandit
    except Exception:
        _ContextualBandit = None
    try:
        from solver.hypothesis_lifecycle import HypothesisManager as _HypothesisManager
    except Exception:
        _HypothesisManager = None
    try:
        from solver.branch_budgeting import allocate_budget as _allocate_budget, should_early_stop_branch as _should_early_stop_branch
    except Exception:
        _allocate_budget = None
        _should_early_stop_branch = None
    try:
        from solver.replay import append_replay as _append_replay
    except Exception:
        _append_replay = None
    try:
        from solver.haiku_critic import run_haiku_critic as _run_haiku_critic, grade_tool_result as _grade_tool_result, quality_to_bandit_update as _quality_to_bandit_update
    except Exception:
        _run_haiku_critic = None
        _grade_tool_result = None
        _quality_to_bandit_update = None
    try:
        from solver.self_play_debate import run_self_play_debate as _run_self_play_debate, render_debate_for_prompt as _render_debate_for_prompt
    except Exception:
        _run_self_play_debate = None
        _render_debate_for_prompt = None
    try:
        from solver.thinking_budget import get_tracker as _thinking_tracker
    except Exception:
        _thinking_tracker = None
    try:
        from solver.difficulty_estimator import DifficultyEstimator as _DifficultyEstimator
    except Exception:
        _DifficultyEstimator = None
    try:
        from solver.rag_store import ingest_solved_challenge as _rag_ingest_solved
    except Exception:
        _rag_ingest_solved = None
    try:
        from solver.novelty_gate import score_tool_novelty as _score_tool_novelty
    except Exception:
        _score_tool_novelty = None
    try:
        from solver.tool_deduplicator import ToolDeduplicator as _ToolDeduplicator
    except Exception:
        _ToolDeduplicator = None
    try:
        from solver.branch_synthesis import synthesize_branch_progress as _synthesize_branch_progress
    except Exception:
        _synthesize_branch_progress = None
    try:
        from solver.exploit_chain import record_chain_edge as _record_chain_edge
    except Exception:
        _record_chain_edge = None
    try:
        from solver.live_intel import fetch_live_writeup_hint as _fetch_live_writeup_hint
    except Exception:
        _fetch_live_writeup_hint = None
    try:
        from flag.submit_guard import score_flag_candidate as _score_flag_candidate
    except Exception:
        _score_flag_candidate = None
    try:
        from core.context_compressor import maybe_compress_messages as _maybe_compress_messages
    except Exception:
        _maybe_compress_messages = None
    try:
        from solver.belief_graph import BeliefGraph as _BeliefGraph
    except Exception:
        _BeliefGraph = None
    try:
        from solver.council import run_council as _run_council
    except Exception:
        _run_council = None
    try:
        from solver.slo_controller import compute_pressure as _compute_slo_pressure, decide_controls as _decide_slo_controls
    except Exception:
        _compute_slo_pressure = None
        _decide_slo_controls = None
    try:
        from solver.tool_chain_policy import ToolChainPolicy as _ToolChainPolicy
    except Exception:
        _ToolChainPolicy = None
    try:
        from solver.deception_guard import detect_hint_deception as _detect_hint_deception
    except Exception:
        _detect_hint_deception = None

    preflight = _run_self_healing_preflight(cat)
    emit(
        "self_heal_preflight",
        ok=preflight.get("ok", False),
        missing=preflight.get("missing", []),
        fallback_plan=preflight.get("fallback_plan", []),
        summary=preflight.get("summary", ""),
    )
    if not preflight.get("ok", False):
        log("warn", f"[SELF-HEAL] {preflight.get('summary','')} | missing={preflight.get('missing', [])}", "")
        user_msg += "\n## Self-Healing Preflight\n"
        user_msg += f"{preflight.get('summary','')}\n"
        for item in preflight.get("fallback_plan", [])[:10]:
            user_msg += f"- {item}\n"

    deception_risk = 0.0
    if _detect_hint_deception:
        try:
            dec = _detect_hint_deception(description=augmented_desc, hints=explicit_hints)
            deception_risk = float(dec.get("risk", 0.0) or 0.0)
            emit("deception_guard", risk=deception_risk, suspicious=bool(dec.get("suspicious", False)), flags=dec.get("flags", []))
            if bool(dec.get("suspicious", False)):
                user_msg += "\n## Deception Guard\nPotentially conflicting/poisoned hints detected. Require disconfirming checks before trusting challenge hints.\n"
        except Exception:
            deception_risk = 0.0

    planner_summary = ""
    planner_evidence = []
    planner_outputs = {}
    planner_hypotheses = [h.get("hypothesis", "") for h in pre_fanout_hypotheses if h.get("hypothesis")][:5]
    planner_pruned = []
    bootstrap_artifacts = []
    strategy_history = []
    tool_quality_log = []
    bandit_updates = []
    difficulty_events = []
    debate_context = ""
    planner_enabled = bool(extra.get("hierarchicalPlanner", True))
    if credit_guard.get("conservative", False) and _credit_remaining_usd(credit_guard) <= 3.0:
        planner_enabled = False
        emit("credit_guard", action="planner_disabled", reason="low_budget")

    try:
        if planner_enabled:
            planner = _run_hierarchical_planner(challenge_ctx, api_key, extra)
            planner_hypotheses = list(dict.fromkeys((planner_hypotheses + planner.get("hypotheses", []))))[:8]
            planner_pruned = planner.get("pruned", [])
            emit("planner", specialists=planner.get("specialists", []), hypothesis_count=len(planner_hypotheses))

            graph = planner.get("plan_graph", [])
            planner_summary, planner_evidence, planner_outputs = _execute_tool_plan_graph(
                graph,
                challenge_ctx,
                max_workers=int(extra.get("plannerMaxWorkers", 3))
            )
            if planner_summary:
                log("sys", f"[PLANNER] {planner_summary}", "dim")
                user_msg += f"\n\n## Planner Execution Summary\n{planner_summary}\n"
                if planner_outputs:
                    planner_join = "\n\n".join([f"{k}: {str(v)[:1200]}" for k, v in planner_outputs.items()])
                    user_msg += f"\n## Planner Tool Outputs\n{planner_join}\n"
                if _rank_branches_live and planner_pruned:
                    try:
                        ranked_pruned = _rank_branches_live([
                            {
                                "hypothesis": n.get("hypothesis", ""),
                                "evidence": float(n.get("evidence_gain", 50)) / 100.0,
                                "novelty": 0.55,
                                "exploitability": float(n.get("score", 50)) / 100.0,
                                "success_prior": 0.5,
                                "confidence": 0.6,
                                "estimated_cost": 0.35,
                            }
                            for n in planner_pruned
                        ])
                        emit("planner_ev", top=ranked_pruned[:3], count=len(ranked_pruned))
                        top_h = [str(x.get("hypothesis", ""))[:120] for x in ranked_pruned[:3]]
                        if top_h:
                            user_msg += "\n## EV-Ranked Hypotheses\n" + "\n".join([f"- {h}" for h in top_h]) + "\n"
                    except Exception:
                        pass
    except Exception as e:
        log("warn", f"Planner stage failed: {e}", "")

    if hyp_manager and planner_hypotheses:
        hyp_manager.seed(planner_hypotheses)
        for h in planner_hypotheses:
            branch_stats[h] = {"name": h, "pulls": 1, "wins": 0}
        emit("hypothesis_lifecycle", summary=hyp_manager.summary()[:8])
    if belief_graph and planner_hypotheses:
        try:
            for h in planner_hypotheses[:10]:
                belief_graph.upsert_hypothesis(h, confidence=0.55, tags=[cat, diff])
                for tool_name in (playbook.get("tools", []) or [])[:6]:
                    belief_graph.connect(f"tool:{tool_name}", h, weight=0.6)
            emit("belief_graph", event="seeded", hypotheses=len(planner_hypotheses[:10]))
        except Exception:
            pass

    exploit_automation = _run_exploit_dev_automation(cat, challenge_ctx, ws or base_dir, extra)
    if exploit_automation.get("enabled", False):
        emit("exploit_dev", loops=len(exploit_automation.get("loops", [])), artifacts=exploit_automation.get("artifacts", []))
        user_msg += "\n## Exploit/Dev Automation\n"
        for loop in exploit_automation.get("loops", [])[:5]:
            user_msg += f"- {loop.get('name')}: variants={', '.join(loop.get('variants', [])[:6])}\n"

    if extra.get("autoBootstrapLab", True) and diff in ("hard", "insane"):
        try:
            lab_workspace = ws or base_dir or os.getcwd()
            det_out = tool_apt_orchestrator(
                operation="deterministic_lab",
                workspace=lab_workspace,
                challenge_type=cat,
                profile=diff,
            )
            bootstrap_artifacts.append({"operation": "deterministic_lab", "result": str(det_out)[:500]})
            bench_out = tool_apt_orchestrator(
                operation="benchmark_eval",
                workspace=lab_workspace,
                category=cat,
                suite=["unit", "integration", "regression"],
            )
            bootstrap_artifacts.append({"operation": "benchmark_eval", "result": str(bench_out)[:500]})
            emit("lab_bootstrap", workspace=lab_workspace, artifacts=bootstrap_artifacts)
            user_msg += "\n## Deterministic Lab Bootstrap\n"
            for rec in bootstrap_artifacts:
                user_msg += f"- {rec['operation']}: {rec['result']}\n"
        except Exception as e:
            log("warn", f"Lab bootstrap skipped: {e}", "")

    # ── Parallel branch solve for hard/insane ────────────────────────────────
    parallel_enabled = bool(extra.get("parallelBranches", True))
    if credit_guard.get("conservative", False) and _credit_remaining_usd(credit_guard) <= 4.0:
        parallel_enabled = False
        emit("credit_guard", action="parallel_disabled", reason="low_budget")

    allow_parallel_any = bool(extra.get("parallelBranchesAllDifficulties", True))
    if parallel_enabled and (diff in ("hard", "insane") or allow_parallel_any):
        log("sys","[PARALLEL] Attempting branch-budgeted parallel solve","bright")
        hypotheses = planner_hypotheses[:3] if planner_hypotheses else []
        if hypotheses and _should_early_stop_branch:
            kept = []
            for h in hypotheses:
                st = branch_stats.get(h, {"pulls": 1, "wins": 0})
                if not _should_early_stop_branch(pulls=int(st.get("pulls", 1)), wins=int(st.get("wins", 0)), min_pulls=3, fail_ratio=0.8):
                    kept.append(h)
            hypotheses = kept or hypotheses
        if hypotheses and _allocate_budget:
            try:
                alloc = _allocate_budget([branch_stats.get(h, {"name": h, "pulls": 1, "wins": 0}) for h in hypotheses], total_budget=max(3, len(hypotheses) * 2))
                hypotheses = [str(x.get("name", "")) for x in alloc if str(x.get("name", ""))][:3]
                emit("branch_budget", allocated=alloc[:3])
            except Exception:
                pass
        if not hypotheses:
            hypotheses = [h.get("hypothesis", "") for h in pre_fanout_hypotheses if h.get("hypothesis")][:3]
        if not hypotheses:
            # Fast hypothesis generation via Haiku fallback
            try:
                hyp_plan = _plan_budgeted_call(
                    credit_guard,
                    model=_MODEL_HAIKU,
                    requested_max_tokens=512,
                    messages=[{"role":"user","content": f"CTF challenge: [{cat}] {name}\n{desc[:1200]}"}],
                    system="",
                    use_thinking=False,
                    thinking_tokens=0,
                )
                if not hyp_plan.get("allowed", True):
                    raise RuntimeError("budget guard blocked hypothesis generation")
                h_resp = client.messages.create(
                    model=hyp_plan.get("model", _MODEL_HAIKU),
                    max_tokens=int(hyp_plan.get("max_tokens", 512)),
                    messages=[{"role":"user","content":
                        f"CTF challenge: [{cat}] {name}\n{desc[:1500]}\n\n"
                        f"Files: {files[:500]}\nInstance: {inst}\n\n"
                        f"List exactly 3 attack hypotheses as numbered lines. Be specific. No padding."}]
                )
                _record_credit_usage(
                    credit_guard,
                    model=hyp_plan.get("model", _MODEL_HAIKU),
                    usage=getattr(h_resp, "usage", None),
                    fallback_estimated_cost=float(hyp_plan.get("estimated_cost", 0.0)),
                )
                hyp_text = h_resp.content[0].text if h_resp.content else ""
                hypotheses = [l.strip().lstrip("123456789.-) ") for l in hyp_text.splitlines() if l.strip() and len(l.strip()) > 10][:3]
            except Exception as e:
                log("warn",f"[PARALLEL] Hypothesis generation failed: {e}","")
                hypotheses = []

        if len(hypotheses) >= 2:
            for h in hypotheses:
                if h in branch_stats:
                    branch_stats[h]["pulls"] = int(branch_stats[h].get("pulls", 1)) + 1
            challenge_ctx = {
                "ctf_name": ctf_name,
                "category": cat,
                "name": name,
                "user_msg": user_msg,
                "platform_id": platform_challenge_id,
            }
            branch_iters  = min(8, max_iterations // 4)
            branch_result = run_parallel_branches(hypotheses, challenge_ctx, api_key,
                                                   active_tools, system, branch_iters, extra,
                                                   credit_guard=credit_guard)
            if branch_result:
                winning_hyp, found_flag = branch_result
                if winning_hyp in branch_stats:
                    branch_stats[winning_hyp]["wins"] = int(branch_stats[winning_hyp].get("wins", 0)) + 1
                validator_api_key = api_key if _credit_remaining_usd(credit_guard) >= 0.12 else ""
                validation = _run_self_verification(
                    candidate_flag=found_flag,
                    conversation_summary=winning_hyp,
                    ctf_name=ctf_name,
                    category=cat,
                    evidence_log=[],
                    solve_log=[winning_hyp],
                    api_key=validator_api_key,
                )
                emit(
                    "validation",
                    verdict=validation.get("verdict", "fail"),
                    confidence=validation.get("confidence", 0.0),
                    reason=validation.get("reason", "")
                )
                if validation.get("verdict") != "pass":
                    log("warn", "[PARALLEL] Candidate flag failed validator gate — continuing sequential solve", "")
                    found_flag = None
                    branch_result = None
                else:
                    log("ok",f"🚩 FLAG (parallel): {found_flag}","white")
                    prefix = _infer_prefix_from_flag(found_flag)
                    if prefix and ctf_name: confirm_flag_format(ctf_name, prefix, found_flag)
                    elapsed = time.time() - _solve_start_time
                    emit("solve_stats", elapsed=round(elapsed,1), iterations=f"parallel/{branch_iters}",
                         model="parallel-sonnet", method=winning_hyp[:60], validation_confidence=validation.get("confidence", 0.0))
                    if _credit_remaining_usd(credit_guard) >= 0.35:
                        generate_writeup(client, user_model, {**challenge,"ctf_name":ctf_name},
                                         found_flag, f"Parallel solve via: {winning_hyp}", ws, extra,
                                         evidence_bundle={
                                             "planner_summary": planner_summary,
                                             "tool_evidence": planner_evidence,
                                             "failed_attempts": [],
                                             "route_history": [],
                                             "strategy_history": strategy_history[-20:],
                                             "hypothesis_trace": planner_hypotheses[:12],
                                             "tool_quality_log": tool_quality_log[-40:],
                                             "bandit_updates": bandit_updates[-60:],
                                             "difficulty_events": difficulty_events[-8:],
                                             "debate_context": debate_context,
                                         })
                    else:
                        log("warn", "Skipping LLM writeup to conserve remaining API credits.", "")
                    try:
                        _store_memory_v2({
                            "timestamp": int(time.time()),
                            "ctf_name": ctf_name,
                            "challenge_name": name,
                            "category": cat,
                            "difficulty": diff,
                            "fingerprint": _challenge_fingerprint(challenge, ctf_name),
                            "tool_sequence": ["parallel_branches"],
                            "winning_path": winning_hyp,
                            "dead_ends": [],
                            "summary": f"Parallel branch winner. Flag={found_flag}",
                            "validator": validation,
                            "memory_type": "proof_artifact" if validation.get("verdict") == "pass" else "episodic",
                            "why_it_worked": "parallel branch won and validator accepted",
                            "source_strength": 0.75,
                            "reproducibility_count": 1,
                            "workspace": ws,
                        })
                        if _rag_ingest_solved:
                            _rag_ingest_solved({
                                "ctf_name": ctf_name,
                                "challenge_name": name,
                                "category": cat,
                                "difficulty": diff,
                                "description_text": augmented_desc,
                                "attack_technique": winning_hyp,
                                "winning_tool_sequence": ["parallel_branches"],
                                "solve_summary": f"Parallel branch winner. Flag={found_flag}",
                            })
                        try:
                            _kg_upsert_fact(ctf_name or "default", f"{cat}_winning_writeup", f"Parallel solve via: {winning_hyp}")
                        except Exception:
                            pass
                        try:
                            _KG_STORE.ingest_solve_record({
                                "ctf_name": ctf_name,
                                "challenge_name": name,
                                "category": cat,
                                "attack_technique": winning_hyp,
                                "winning_tool_sequence": ["parallel_branches"],
                                "flag_prefix": _infer_prefix_from_flag(found_flag) or "",
                            })
                        except Exception:
                            pass
                    except Exception as e:
                        log("warn", f"Memory store skipped: {e}", "")
                    try:
                        from solver.benchmark_gate import evaluate as _bg_eval
                        policy_dir = os.path.join((ws or base_dir or os.getcwd()), ".solver")
                        benchmark_path = os.path.join(policy_dir, "benchmark_history.json")
                        spent = float(credit_guard.get("spent_usd", 0.0)) if isinstance(credit_guard, dict) else 0.0
                        elapsed_total = max(0.0, time.time() - _solve_start_time)
                        bench = _bg_eval({
                            "category": cat,
                            "challenge": name,
                            "solve_rate": 1.0,
                            "false_flag_rate": 0.0,
                            "cost_per_flag": float(spent),
                            "time_to_first_signal": elapsed_total,
                            "time_to_flag": elapsed_total,
                        }, benchmark_path, gates=extra.get("benchmarkGates", {}))
                        emit("benchmark_gate", **bench)
                    except Exception:
                        pass
                    result("solved", found_flag, workspace=ws)
                    return
            if _synthesize_branch_progress and hypotheses:
                try:
                    synth = _synthesize_branch_progress(
                        [
                            {
                                "branch": h,
                                "wins": float(branch_stats.get(h, {}).get("wins", 0)),
                                "pulls": float(branch_stats.get(h, {}).get("pulls", 1)),
                                "quality": 0.5,
                                "novelty": 0.5,
                            }
                            for h in hypotheses
                        ],
                        api_key=api_key,
                    )
                    if synth:
                        rank_map = {str(x.get("branch", "")): float(x.get("score", 0.5)) for x in synth}
                        planner_hypotheses.sort(key=lambda h: rank_map.get(str(h), 0.0), reverse=True)
                        emit("branch_synthesis", ranked=synth[:4])
                except Exception:
                    pass
            log("sys","[PARALLEL] No branch found flag — continuing with full sequential solve","dim")

    # ── Sequential solve loop ────────────────────────────────────────────────
    messages   = [{"role":"user","content":user_msg}]
    solve_state = SolveState(
        iteration=0,
        max_iterations=max_iterations,
        fruitless=0,
        last_progress_iter=0,
        tool_failures=0,
        last_flag_check_iter=0,
        opus_budget_remaining=0,
        final_workspace=ws,
    )
    found_flag = solve_state.found_flag
    final_ws = solve_state.final_workspace
    solve_log = solve_state.solve_log
    iteration = solve_state.iteration
    fruitless = solve_state.fruitless
    last_flag_check_iter = solve_state.last_flag_check_iter
    last_progress_iter = solve_state.last_progress_iter
    tool_failures = solve_state.tool_failures
    route_history = []
    tool_call_history = []
    pivot_events = []
    strategy_history = []
    opus_budget_remaining = int(extra.get("opusBudget", max(3, max_iterations // 3)))
    solve_state.opus_budget_remaining = opus_budget_remaining
    if allocator_cfg.get("enabled", True):
        ev = allocator_cfg.get("queue_expected_value", 0.0)
        if ev < 0.6:
            opus_budget_remaining = max(0, min(opus_budget_remaining, 1))
        elif ev > 1.2 and diff in ("hard", "insane"):
            opus_budget_remaining = max(opus_budget_remaining, max(3, max_iterations // 2))
    autonomous_state = {"phase": "recon", "cycles": 0}
    evidence_log = []
    evidence_ledger_path = ""
    last_strategy_pivot_iter = 0
    first_signal_time_s = None
    false_flag_candidates = 0
    contradiction_penalty = len(memory_diag.get("contradictions", []))
    trusted_memory_hits_count = len(trusted_memory_hits)
    thinking_tracker = _thinking_tracker() if _thinking_tracker else None
    difficulty_estimator = _DifficultyEstimator(diff, max_iterations) if _DifficultyEstimator else None
    difficulty_events = []
    tool_quality_log = []
    bandit_updates = []
    debate_used = False
    debate_context = ""
    novelty_min_score = float(extra.get("noveltyGateMinScore", 0.2))
    novelty_gate_enabled = bool(extra.get("haikuNoveltyGate", True))
    dedup_enabled = bool(extra.get("toolDedupEnabled", True))
    dedup_similarity = float(extra.get("toolDedupSimilarity", 0.70))
    tool_deduplicator = _ToolDeduplicator(similarity_threshold=dedup_similarity) if (_ToolDeduplicator and dedup_enabled) else None
    last_chain_tool = ""
    last_chain_output = ""
    last_iter_tool_set = set()
    no_novel_thinking_streak = 0
    critic_hard_block_until_iter = 0
    live_hint_last_iter = 0
    live_hint_cooldown = int(extra.get("liveHintCooldownIters", 3))

    policy_dir = os.path.join((final_ws or ws or base_dir or os.getcwd()), ".solver")
    telemetry_path = os.path.join(policy_dir, "iteration_telemetry.json")
    priors_path = os.path.join(policy_dir, "learned_policy.json")
    benchmark_path = os.path.join(policy_dir, "benchmark_history.json")
    bandit_path = os.path.join(policy_dir, "tool_bandit.json")
    replay_path = os.path.join(policy_dir, "decision_replay.jsonl")
    chain_policy_path = os.path.join(policy_dir, "tool_chain_policy.json")
    learned_overrides = {}
    bandit = None
    if _ContextualBandit:
        try:
            bandit = _ContextualBandit(bandit_path)
        except Exception:
            bandit = None
    hyp_manager = _HypothesisManager() if _HypothesisManager else None
    belief_graph = _BeliefGraph() if _BeliefGraph else None
    chain_policy = _ToolChainPolicy(chain_policy_path) if _ToolChainPolicy else None
    council_submit_blocked = False
    council_action = "continue"
    council_throttle = False
    branch_stats: dict[str, dict] = {}
    if _get_learned_overrides:
        try:
            if _should_retrain_weekly and _retrain_priors and _should_retrain_weekly(priors_path):
                _retrain_priors(telemetry_path, priors_path)
                emit("policy_retrain", status="completed", reason="weekly")
            learned_overrides = _get_learned_overrides(priors_path, cat)
        except Exception:
            learned_overrides = {}
    bench_hist = []
    try:
        if os.path.exists(benchmark_path):
            with open(benchmark_path, "r", encoding="utf-8") as f:
                bench_hist = json.load(f)
            if isinstance(bench_hist, list) and bench_hist:
                last_bench = bench_hist[-1]
                if last_bench.get("verdict") == "fail" and bool(last_bench.get("regressed", False)):
                    learned_overrides = {}
                    emit("policy_reject", reason="previous_regression")
    except Exception:
        pass

    try:
        from solver.control_plane import tune_runtime_knobs as _tune_runtime_knobs
        from solver.canary_rollout import canary_accept as _canary_accept
        tuned = _tune_runtime_knobs(cat, learned_overrides, bench_hist[-25:] if isinstance(bench_hist, list) else [])
        cohort = f"{str(cat).lower()}|{str(diff).lower()}"
        canary_ok = _canary_accept(cohort=cohort, challenge_name=name, percent=float(extra.get("policyCanaryPercent", 0.35) or 0.35))
        if canary_ok and isinstance(learned_overrides, dict):
            learned_overrides = {**learned_overrides, **tuned}
            if "enableSelfPlayDebate" in tuned and "enableSelfPlayDebate" not in extra:
                extra["enableSelfPlayDebate"] = bool(tuned.get("enableSelfPlayDebate", True))
        emit("control_plane", tuned=tuned, cohort=cohort, canary_applied=canary_ok)
    except Exception:
        pass

    try:
        d_corr = float(learned_overrides.get("difficulty_correction", 0.0)) if isinstance(learned_overrides, dict) else 0.0
        d_order = ["easy", "medium", "hard", "insane"]
        if diff in d_order and abs(d_corr) >= 0.35:
            cur_idx = d_order.index(diff)
            new_idx = max(0, min(3, int(round(cur_idx + d_corr))))
            if new_idx != cur_idx:
                prev_diff = diff
                diff = d_order[new_idx]
                emit("difficulty_recalibration", previous=prev_diff, corrected=diff, correction=round(d_corr, 3), category=cat)
    except Exception:
        pass

    attack_graph = None
    if _a_star_attack_path and _update_edge_success:
        attack_graph = {
            "edges": [
                {"from": "start", "to": "recon", "cost": 1.0, "success_prob": 0.55},
                {"from": "start", "to": "exploit", "cost": 1.2, "success_prob": 0.50},
                {"from": "start", "to": "refine", "cost": 1.4, "success_prob": 0.45},
                {"from": "start", "to": "validate", "cost": 1.0, "success_prob": 0.70},
                {"from": "recon", "to": "goal", "cost": 1.1, "success_prob": 0.55},
                {"from": "exploit", "to": "goal", "cost": 0.9, "success_prob": 0.60},
                {"from": "refine", "to": "goal", "cost": 1.0, "success_prob": 0.58},
                {"from": "validate", "to": "goal", "cost": 0.7, "success_prob": 0.82},
            ]
        }

    def _finalize_policy_and_benchmark(status: str, solved_flag: str = "") -> None:
        bench = None
        benchmark_pass = False
        if bandit:
            try:
                bandit.save()
            except Exception:
                pass
        if chain_policy:
            try:
                chain_policy.save()
            except Exception:
                pass
        if _append_iteration_telemetry:
            try:
                _append_iteration_telemetry(telemetry_path, {
                    "category": cat,
                    "iteration": iteration,
                    "route_score": route_history[-1].get("route_score", 50) if route_history else 50,
                    "fruitless": fruitless,
                    "tool_failures": tool_failures,
                    "strategy_mode": strategy_history[-1].get("mode", "") if strategy_history else "",
                    "solved": status == "solved",
                    "failed": status != "solved",
                    "has_flag": bool(solved_flag),
                    "predicted_difficulty": challenge.get("difficulty", "medium"),
                    "actual_iterations": iteration,
                    "max_iterations": max_iterations,
                    "tool_sequence": tool_call_history[-60:],
                })
            except Exception:
                pass
        if _benchmark_evaluate:
            try:
                elapsed_total = max(0.0, time.time() - _solve_start_time)
                t_first = float(first_signal_time_s if first_signal_time_s is not None else elapsed_total)
                solved = 1 if status == "solved" else 0
                spent = float(credit_guard.get("spent_usd", 0.0)) if isinstance(credit_guard, dict) else 0.0
                metrics = {
                    "category": cat,
                    "difficulty": diff,
                    "challenge": name,
                    "solve_rate": float(solved),
                    "false_flag_rate": float(false_flag_candidates / max(1, false_flag_candidates + solved)),
                    "cost_per_flag": float(spent / max(1, solved)),
                    "time_to_first_signal": t_first,
                    "time_to_flag": elapsed_total if solved else float(9999.0),
                }
                bench = _benchmark_evaluate(metrics, benchmark_path, gates=extra.get("benchmarkGates", {}))
                benchmark_pass = bool(bench.get("verdict") == "pass")
                emit("benchmark_gate", **bench)
                if bench.get("verdict") != "pass":
                    emit("policy_reject", reason="benchmark_gate_failed", details=bench.get("reasons", []))
            except Exception:
                pass
        try:
            from solver.policy_guard import snapshot_policy as _snapshot_policy
            from solver.policy_guard import latest_good_snapshot as _latest_good_snapshot
            from solver.policy_guard import latest_good_snapshot_for_cohort as _latest_good_snapshot_for_cohort
            from solver.policy_guard import rollback_to_snapshot as _rollback_to_snapshot
            meta = {
                "status": status,
                "benchmark_pass": benchmark_pass,
                "category": cat,
                "difficulty": diff,
                "challenge": name,
            }
            _snapshot_policy(policy_dir, priors_path, benchmark_path, metadata=meta)
            if (bench is not None) and not benchmark_pass and bool(bench.get("regressed", False)):
                snap = _latest_good_snapshot_for_cohort(policy_dir, cat, diff) or _latest_good_snapshot(policy_dir)
                if snap and _rollback_to_snapshot(policy_dir, priors_path, snap):
                    emit("policy_rollback", restored=snap.get("version_id", ""), reason="benchmark_regressed")
        except Exception:
            pass
        if status != "solved":
            try:
                from solver.counterfactual_learning import derive_counterfactual_deltas as _derive_counterfactual_deltas
                deltas = _derive_counterfactual_deltas(
                    replay_path=replay_path,
                    output_path=os.path.join(policy_dir, "counterfactual_deltas.json"),
                    limit=4000,
                )
                emit("counterfactual_learning", **deltas)
            except Exception:
                pass
            try:
                from solver.curriculum_learning import append_curriculum_item as _append_curriculum_item, build_failure_curriculum_item as _build_failure_curriculum_item
                item = _build_failure_curriculum_item(
                    category=cat,
                    difficulty=diff,
                    challenge=name,
                    failed_tools=tool_call_history[-20:],
                    reason="solve_failed_or_budget_exhausted",
                )
                _append_curriculum_item(os.path.join(policy_dir, "curriculum_queue.json"), item)
                emit("curriculum", event="queued", challenge=name, category=cat, difficulty=diff)
            except Exception:
                pass

    if bool(extra.get("resumeCheckpoint", True)):
        resume_state = core_checkpoint.load_checkpoint(final_ws or ws or base_dir or os.getcwd(), name)
        if resume_state:
            messages = resume_state.get("messages", messages)
            iteration = int(resume_state.get("iteration", iteration))
            fruitless = int(resume_state.get("fruitless", fruitless))
            tool_failures = int(resume_state.get("tool_failures", tool_failures))
            solve_log = resume_state.get("solve_log", solve_log)
            evidence_log = resume_state.get("evidence_log", evidence_log)
            route_history = resume_state.get("route_history", route_history)
            strategy_history = resume_state.get("strategy_history", strategy_history)
            emit("checkpoint", action="resumed", iteration=iteration, challenge=name)

    while iteration < max_iterations:
        iteration += 1
        solve_state.iteration = iteration

        if live_sync_enabled and platform_challenge_id and _PLATFORM_CONFIG and _PLATFORM_CONFIG.get("type") != "manual":
            should_poll_iter = (iteration % max(1, live_sync_poll_iter) == 0)
            should_poll_time = (time.time() - float(last_live_sync_ts)) >= max(2.0, live_sync_poll_seconds)
            if should_poll_iter or should_poll_time:
                last_live_sync_ts = time.time()
                live_status = _query_live_challenge_status(_PLATFORM_CONFIG, platform_challenge_id)
                solve_count = int(live_status.get("solve_count", 0) or 0)
                solved_remote = bool(live_status.get("solved", False))
                solved_by_team = solved_remote or (solve_count > baseline_solve_count)
                emit(
                    "live_sync",
                    iteration=iteration,
                    challenge_id=platform_challenge_id,
                    found=bool(live_status.get("found", False)),
                    solved=solved_by_team,
                    solve_count=solve_count,
                    baseline_solve_count=baseline_solve_count,
                    error=live_status.get("error", ""),
                )
                if solved_by_team and not found_flag:
                    log("warn", "Teammate solve detected in real time — canceling this run to save tokens.", "")
                    emit(
                        "solve_cancelled",
                        reason="teammate_solved",
                        iteration=iteration,
                        challenge_id=platform_challenge_id,
                        solve_count=solve_count,
                    )
                    try:
                        failed_approaches = list(dict.fromkeys((pivot_events + [f"tool:{t}" for t in tool_call_history[-30:]])))
                        _store_failure_path(challenge, ctf_name, failed_approaches, cat, diff)
                    except Exception:
                        pass
                    result("cancelled", workspace=final_ws)
                    return
                baseline_solve_count = max(baseline_solve_count, solve_count)

        # Pre-route state vector snapshot for model routing and replay logging.
        state_vector = {
            "category": cat.lower(),
            "phase": autonomous_state.get("phase", "recon"),
            "signal_quality": max(0.0, min(1.0, len(evidence_log) / max(3.0, float(iteration * 2)))),
            "reliability_trend": 0.0,
            "contradiction_score": max(0.0, min(1.0, len(memory_diag.get("contradictions", [])) / 4.0)),
            "exploit_maturity": max(0.0, min(1.0, len([x for x in solve_log[-20:] if "exploit" in str(x).lower()]) / 6.0)),
            "fruitless": fruitless,
            "tool_failures": tool_failures,
            "progress": iteration / max(1, max_iterations),
            "is_remote": bool(inst),
            "has_binary": bool(challenge.get("binary_path", "") or challenge.get("file_path", "")),
            "difficulty_pressure": max(0.0, min(1.0, (fruitless + tool_failures) / 8.0)),
        }

        dynamic_max_tool_calls = int(extra.get("maxToolCallsPerIteration", 3) or 3)
        dynamic_force_local_only = bool(human_loop.get("force_local_only", False))
        if _compute_slo_pressure and _decide_slo_controls:
            try:
                elapsed_so_far = max(1.0, time.time() - _solve_start_time)
                p95_proxy = elapsed_so_far / max(1.0, float(iteration))
                burn_velocity = float(credit_guard.get("spent_usd", 0.0) or 0.0) / elapsed_so_far
                error_rate = float(tool_failures) / max(1.0, float(iteration))
                pressure = _compute_slo_pressure(
                    p95_latency_s=float(p95_proxy),
                    queue_depth=0,
                    error_rate=error_rate,
                    burn_velocity=burn_velocity,
                )
                controls = _decide_slo_controls(pressure)
                dynamic_max_tool_calls = min(dynamic_max_tool_calls, int(controls.get("max_tool_calls", dynamic_max_tool_calls)))
                dynamic_force_local_only = bool(dynamic_force_local_only or controls.get("force_local_only", False))
                if bool(controls.get("throttle", False)):
                    emit("slo_controller", iteration=iteration, **controls)
            except Exception:
                pass

        # ── Multi-model routing ──────────────────────────────────────────────
        progress_gap = (iteration - last_progress_iter if last_progress_iter else iteration) + contradiction_penalty
        from solver.routing_controller import build_route_decision as _build_route_decision
        route_decision = _build_route_decision(
            _route_model_v2,
            category=cat,
            difficulty=diff,
            iteration=iteration,
            total_iters=max_iterations,
            user_model=user_model,
            fruitless=fruitless,
            tool_failures=tool_failures,
            progress_gap=progress_gap,
            opus_budget_remaining=opus_budget_remaining,
            memory_hits_count=trusted_memory_hits_count,
            learned_overrides=learned_overrides,
            state_vector=state_vector,
        )
        if difficulty_estimator and difficulty_estimator.should_reestimate(iteration):
            try:
                diff_evt = difficulty_estimator.reestimate(
                    iteration=iteration,
                    fruitless=fruitless,
                    tool_failures=tool_failures,
                    evidence_log=evidence_log,
                    route_score=int(route_decision.get("route_score", 50)),
                )
                difficulty_events.append(diff_evt)
                if diff_evt.get("changed"):
                    diff = diff_evt.get("new_difficulty", diff)
                    emit("difficulty_reestimate", **diff_evt)
                    messages.append({"role": "user", "content":
                        "[DYNAMIC DIFFICULTY RE-ESTIMATE]\n"
                        f"{diff_evt.get('old_difficulty')} -> {diff_evt.get('new_difficulty')}\n"
                        f"Reason: {diff_evt.get('reason')}\n"
                        "Update strategy and model routing immediately."
                    })
            except Exception:
                pass
        model = route_decision["model"]
        use_thinking = route_decision["use_thinking"]
        thinking_tokens = route_decision["thinking_tokens"]
        if thinking_tracker and use_thinking:
            try:
                adaptive_budget = thinking_tracker.next_budget(difficulty=diff, route_score=int(route_decision.get("route_score", 0)))
                thinking_tokens = max(2048, min(int(thinking_tokens or adaptive_budget), int(adaptive_budget)))
                emit("thinking_budget", iteration=iteration, route_score=route_decision.get("route_score", 0), tokens=thinking_tokens)
            except Exception:
                pass
        if model == _MODEL_OPUS and opus_budget_remaining > 0 and user_model != _MODEL_OPUS:
            opus_budget_remaining -= 1
        route_history.append({
            "iteration": iteration,
            **route_decision,
            "opus_budget_remaining": opus_budget_remaining,
        })
        emit(
            "route_decision",
            iteration=iteration,
            model=model,
            route_score=route_decision.get("route_score", 0),
            complexity=route_decision.get("complexity", 0),
            uncertainty=route_decision.get("uncertainty", 0),
            failure=route_decision.get("failure", 0),
            reasons=route_decision.get("reasons", []),
            opus_budget_remaining=opus_budget_remaining,
        )
        if _run_council:
            try:
                council = _run_council({
                    "fruitless": fruitless,
                    "tool_failures": tool_failures,
                    "route_score": route_decision.get("route_score", 0),
                    "evidence_count": len(evidence_log),
                    "min_evidence": int(extra.get("minEvidenceBeforeFlag", 2) or 2),
                    "remaining_usd": _credit_remaining_usd(credit_guard),
                    "reserve_usd": float(credit_guard.get("reserve_usd", 0.0) or 0.0),
                    "token_burn_velocity": float((credit_guard.get("spent_usd", 0.0) or 0.0) / max(1.0, (time.time() - _solve_start_time))),
                    "belief_uncertainty": float(belief_graph.global_uncertainty()) if belief_graph else 1.0,
                    "belief_contradiction": float(belief_graph.contradiction_ratio()) if belief_graph else 0.0,
                    "hallucination_risk": float(min(1.0, deception_risk + (0.2 if bool(critic_hard_block_until_iter >= iteration) else 0.0))),
                })
                council_action = str(council.get("action", "continue"))
                council_submit_blocked = bool(council.get("submit_blocked", False))
                council_throttle = bool(council.get("throttle", False))
                emit("council", iteration=iteration, action=council_action, veto=bool(council.get("veto", False)), throttle=council_throttle, submit_blocked=council_submit_blocked)
                if council_action in ("pivot", "disambiguate") and iteration > 1:
                    tests = []
                    if belief_graph and council_action == "disambiguate":
                        try:
                            tests = belief_graph.propose_disambiguation_tests(max_items=3)
                        except Exception:
                            tests = []
                    hint = f"Suggested tests: {tests}" if tests else "Run a low-cost disambiguation step before continuing."
                    messages.append({"role": "user", "content": f"[COUNCIL] action={council_action}. {hint}"})
            except Exception:
                council_submit_blocked = False
                council_throttle = False
        from solver.routing_controller import should_trigger_debate as _should_trigger_debate
        if _run_self_play_debate and _render_debate_for_prompt and _should_trigger_debate(
            route_score=int(route_decision.get("route_score", 0)),
            difficulty=diff,
            debate_used=debate_used,
            debate_enabled=bool(extra.get("enableSelfPlayDebate", True)),
        ):
            try:
                debate = _run_self_play_debate(
                    challenge_description=augmented_desc,
                    category=cat,
                    difficulty=diff,
                    recon_summary="\n".join(solve_log[-6:]),
                    route_score=int(route_decision.get("route_score", 0)),
                    api_key=api_key,
                )
                debate_context = _render_debate_for_prompt(debate)
                if debate_context:
                    debate_used = True
                    messages.append({"role": "user", "content": "[SELF-PLAY DEBATE]\n" + debate_context})
                    emit("self_play_debate", iteration=iteration, used=True, confidence=debate.get("confidence", 0), winning=debate.get("winning_approach", ""))
            except Exception:
                pass
        if _append_replay:
            try:
                _append_replay(
                    replay_path,
                    state=state_vector,
                    action={"type": "route", "model": model, "use_thinking": use_thinking, "route_score": route_decision.get("route_score", 0)},
                    outcome={"accepted": True, "reasons": route_decision.get("reasons", [])},
                )
            except Exception:
                pass
        _current_model_display = model.split("-")[1] if "-" in model else model
        emit("model_switch", model=model, iteration=iteration,
             thinking=use_thinking, thinking_tokens=thinking_tokens)

        elapsed = time.time() - _solve_start_time
        log("sys",
            f"─── iter {iteration}/{max_iterations} | "
            f"{'opus+think' if use_thinking else model.split('-')[1] if '-' in model else model} | "
            f"{elapsed:.0f}s ──────────────","dim")
        autonomous_state = _update_autonomous_phase(
            autonomous_state,
            iteration=iteration,
            tool_used=False,
            found_signal=False,
            fruitless=fruitless,
        )
        emit("autoloop", phase=autonomous_state.get("phase"), iteration=iteration, cycles=autonomous_state.get("cycles", 0))

        state_vector = {
            "category": cat.lower(),
            "phase": autonomous_state.get("phase", "recon"),
            "signal_quality": max(0.0, min(1.0, len(evidence_log) / max(3.0, float(iteration * 2)))) ,
            "reliability_trend": 0.0,
            "contradiction_score": max(0.0, min(1.0, len(memory_diag.get("contradictions", [])) / 4.0)),
            "exploit_maturity": max(0.0, min(1.0, len([x for x in solve_log[-20:] if "exploit" in str(x).lower()]) / 6.0)),
            "fruitless": fruitless,
            "tool_failures": tool_failures,
            "progress": iteration / max(1, max_iterations),
            "is_remote": bool(inst),
            "has_binary": bool(challenge.get("binary_path", "") or challenge.get("file_path", "")),
            "difficulty_pressure": max(0.0, min(1.0, (fruitless + tool_failures) / 8.0)),
        }
        if _build_state_vector:
            try:
                rel_vals = list((_TOOL_RUNTIME.reliability_snapshot() or {}).values())
                rel_avg = (sum(rel_vals) / len(rel_vals)) if rel_vals else 0.5
                state_vector = _build_state_vector(
                    category=cat,
                    phase=autonomous_state.get("phase", "recon"),
                    signal_quality=state_vector["signal_quality"],
                    reliability_trend=(rel_avg - 0.5) * 2.0,
                    contradiction_score=state_vector["contradiction_score"],
                    exploit_maturity=state_vector["exploit_maturity"],
                    fruitless=fruitless,
                    tool_failures=tool_failures,
                    iteration=iteration,
                    total_iters=max_iterations,
                    is_remote=bool(inst),
                    has_binary=bool(challenge.get("binary_path", "") or challenge.get("file_path", "")),
                )
            except Exception:
                pass
        emit("state_vector", iteration=iteration, vector=state_vector)

        strategy = _decide_strategy_mode(
            category=cat,
            phase=autonomous_state.get("phase", "recon"),
            fruitless=fruitless,
            tool_failures=tool_failures,
            iteration=iteration,
            total_iters=max_iterations,
            memory_diag=memory_diag,
            learned_overrides=learned_overrides,
            state_vector=state_vector,
        )
        if attack_graph and _a_star_attack_path:
            try:
                gp = _a_star_attack_path(attack_graph, start="start", goal="goal", capabilities=set(), beam_width=12)
                path = gp.get("path", []) if isinstance(gp, dict) else []
                if len(path) >= 2:
                    primary = path[1]
                    mode_map = {
                        "recon": "general-evidence",
                        "exploit": "binary-exploit" if any(k in cat.lower() for k in ["binary", "pwn"]) else "dynamic-web",
                        "refine": "diversify-attack-surface",
                        "validate": "validator-evidence-gate",
                    }
                    strategy["mode"] = mode_map.get(primary, strategy.get("mode", "general-evidence"))
                    strategy["graph_policy_primary"] = primary
                    emit("graph_policy", iteration=iteration, primary=primary, path=path)
            except Exception:
                pass
        if human_loop.get("lock_strategy", False):
            locked_mode = human_loop.get("locked_mode") or strategy.get("base_mode", "general-evidence")
            strategy["mode"] = locked_mode
            strategy["pivot"] = False
            strategy["reason"] = "human-locked-strategy"
        strategy_history.append({"iteration": iteration, **strategy})
        emit(
            "strategy",
            iteration=iteration,
            mode=strategy.get("mode", ""),
            base_mode=strategy.get("base_mode", ""),
            pivot=strategy.get("pivot", False),
            reason=strategy.get("reason", ""),
            recommended_tools=strategy.get("recommended_tools", []),
            confidence=strategy.get("confidence", 0.0),
        )

        # ── Live EV ranking over strategy options each cycle ───────────────────
        if _rank_branches_live:
            try:
                ev_rank = _rank_branches_live([
                    {
                        "name": strategy.get("mode", "current"),
                        "evidence": min(1.0, max(0.0, (1.0 - (fruitless / max(1, max_iterations))) + 0.15)),
                        "novelty": 0.6 if strategy.get("pivot") else 0.35,
                        "exploitability": 0.65 if "exploit" in str(strategy.get("mode", "")).lower() else 0.5,
                        "success_prior": max(0.05, 1.0 - (tool_failures / max(1, iteration + 1))),
                        "confidence": float(strategy.get("confidence", 0.5) or 0.5),
                        "estimated_cost": max(0.1, iteration / max(1, max_iterations)),
                    }
                ])
                emit("adaptive_ev", iteration=iteration, ranked=ev_rank[:1])
            except Exception:
                pass

        # ── Live symbolic orchestration tick ──────────────────────────────────
        if _symbolic_orchestrate_live and (fruitless >= 2 or "symbolic" in str(strategy.get("mode", "")).lower()):
            try:
                if any(k in cat.lower() for k in ["binary", "pwn", "reverse", "crypto"]):
                    tail = "\n".join(solve_log[-14:])
                    raw_constraints = []
                    for ln in tail.splitlines():
                        low_ln = ln.lower()
                        if any(m in low_ln for m in ["==", "<=", ">=", " xor ", "mod", "hash", "crc", "nonce"]):
                            raw_constraints.append(ln.strip()[:220])
                    if raw_constraints:
                        symbolic_tick = _symbolic_orchestrate_live(
                            challenge_type=cat,
                            constraints=raw_constraints[:20],
                            candidate_paths=[],
                            path_budget=int(extra.get("symbolicPathBudget", 12)),
                            mode="auto",
                            timeout_s=5,
                        )
                        emit(
                            "symbolic_tick",
                            iteration=iteration,
                            backend=symbolic_tick.get("backend", ""),
                            status=symbolic_tick.get("solve", {}).get("status", ""),
                            constraints=len(raw_constraints[:20]),
                        )
                        messages.append({"role": "user", "content":
                            "[LIVE SYMBOLIC ORCHESTRATOR]\n"
                            f"Backend: {symbolic_tick.get('backend','auto')}\n"
                            f"Solver status: {symbolic_tick.get('solve',{}).get('status','unknown')}\n"
                            f"Unsat core: {symbolic_tick.get('solve',{}).get('unsat_core', [])}\n"
                            "Use this to prune impossible hypotheses now."
                        })
            except Exception:
                pass
        emit(
            "explainability",
            event="iteration_state",
            iteration=iteration,
            phase=autonomous_state.get("phase", "recon"),
            strategy_mode=strategy.get("mode", ""),
            route_score=route_decision.get("route_score", 0),
            evidence_count=len(evidence_log),
            contradictions=memory_diag.get("contradictions", []),
        )
        if _fetch_live_writeup_hint and fruitless >= 3 and (iteration - live_hint_last_iter) >= max(1, live_hint_cooldown):
            try:
                hint_block = _fetch_live_writeup_hint(
                    challenge_name=name,
                    challenge_description=augmented_desc,
                    category=cat,
                    ctf_name=ctf_name,
                )
                if hint_block:
                    live_hint_last_iter = iteration
                    messages.append({"role": "user", "content": "[LIVE WRITEUP INTEL]\n" + hint_block})
                    emit("live_writeup_hint", iteration=iteration, fruitless=fruitless, injected=True)
            except Exception:
                pass
        if strategy.get("pivot") and (iteration - last_strategy_pivot_iter >= 2):
            pivot_reason = strategy.get("reason") or "adaptive-pivot"
            if human_loop.get("approve_pivot", False):
                emit(
                    "pivot_request",
                    iteration=iteration,
                    mode=strategy.get("mode"),
                    reason=pivot_reason,
                    recommended_tools=strategy.get("recommended_tools", []),
                )
                messages.append({"role": "user", "content":
                    "[HUMAN-IN-THE-LOOP]\n"
                    "Pivot approval required and not granted in this run. Continue current strategy but collect evidence for next pivot request."
                })
                continue
            pivot_events.append(f"iter={iteration}: strategy pivot due to {pivot_reason} -> {strategy.get('mode')}")
            messages.append({"role": "user", "content":
                "[ADAPTIVE STRATEGY ENGINE]\n"
                f"Mode: {strategy.get('mode')}\n"
                f"Reason: {pivot_reason}\n"
                f"Recommended tools: {', '.join(strategy.get('recommended_tools', [])[:8])}\n"
                "Pivot now. Gather fresh evidence and avoid repeating previously failed paths."
            })
            last_strategy_pivot_iter = iteration

        # ── Live branch-memory fusion tick ─────────────────────────────────────
        if _fuse_branch_results_live and len(strategy_history) >= 3 and iteration % 3 == 0:
            try:
                tail_hist = strategy_history[-3:]
                branch_payload = []
                for idx, rec in enumerate(tail_hist, 1):
                    branch_payload.append({
                        "branch": f"iter-{rec.get('iteration', idx)}",
                        "timestamp": time.time(),
                        "facts": [
                            {"key": "strategy_mode", "value": rec.get("mode", ""), "confidence": float(rec.get("confidence", 0.5) or 0.5), "provenance": "live-strategy"},
                            {"key": "pivot", "value": bool(rec.get("pivot", False)), "confidence": 0.6, "provenance": "live-strategy"},
                        ],
                    })
                fusion_tick = _fuse_branch_results_live(branch_payload, half_life_min=90.0)
                emit(
                    "branch_fusion",
                    iteration=iteration,
                    fact_count=fusion_tick.get("fact_count", 0),
                    conflicts=list((fusion_tick.get("conflicts") or {}).keys())[:5],
                )
            except Exception:
                pass

        # ── Trigger critic every N fruitless iterations ──────────────────────
        planned_critic_every = int(extra.get("criticPlannedCheckpointEvery", 5))
        if planned_critic_every > 0 and (iteration % planned_critic_every == 0):
            try:
                recent_evidence = "\n\n".join([
                    f"Tool: {e.get('tool')}\nInput: {str(e.get('input',''))[:200]}\nOutput: {str(e.get('output',''))[:500]}"
                    for e in evidence_log[-5:]
                ]) or "\n".join(solve_log[-10:])
                critic_out = tool_critic(recent_evidence, iteration, cat, api_key)
                if "PIVOT" in critic_out.upper():
                    messages.append({"role": "user", "content":
                        "[PLANNED CRITIC CHECKPOINT]\n"
                        f"{critic_out}\n\n"
                        "Before pivoting, run at least one DISCONFIRMING TEST against your current best hypothesis."
                    })
                emit("critic_checkpoint", iteration=iteration, planned=True)
            except Exception:
                pass

        if fruitless >= _critic_threshold and fruitless % _critic_threshold == 0:
            log("warn",f"[CRITIC] {fruitless} fruitless iters — triggering critic analysis","")
            recent_evidence = "\n\n".join([
                f"Tool: {e.get('tool')}\nInput: {str(e.get('input',''))[:200]}\nOutput: {str(e.get('output',''))[:500]}"
                for e in evidence_log[-5:]
            ]) or "\n".join(solve_log[-8:])
            critic_out = tool_critic(recent_evidence, iteration, cat, api_key)
            pivot_events.append(f"iter={iteration}: {critic_out[:160]}")
            # Inject critic feedback as a new user message
            messages.append({"role":"user","content":
                f"[CRITIC ANALYSIS after {fruitless} fruitless iterations]\n{critic_out}\n\n"
                "Act on the PIVOT recommendations above. Do NOT continue your previous approach."})
            fruitless = 0  # reset after critic fires

        # ── Live exploit reflection tick (local closed-loop) ─────────────────
        if _autonomous_exploit_loop_live and any(k in cat.lower() for k in ["binary", "pwn", "reverse"]) and fruitless >= 4:
            try:
                recent = "\n".join(solve_log[-12:])
                code_blocks = re.findall(r"```python\n([\s\S]*?)```", recent)
                if code_blocks:
                    candidate_script = code_blocks[-1][:12000]
                    reflect_tick = _autonomous_exploit_loop_live(
                        initial_script=candidate_script,
                        rounds=int(extra.get("reflectionRounds", 2)),
                        timeout_s=int(extra.get("reflectionTimeout", 10)),
                    )
                    emit(
                        "exploit_reflection",
                        iteration=iteration,
                        status=reflect_tick.get("status", ""),
                        rounds=len(reflect_tick.get("history", [])),
                    )
                    messages.append({"role": "user", "content":
                        "[LIVE EXPLOIT REFLECTION]\n"
                        f"Status: {reflect_tick.get('status','unknown')}\n"
                        f"History: {reflect_tick.get('history', [])[:2]}\n"
                        "Use failure signatures/hints to refine exploit logic, not random retries."
                    })
            except Exception:
                pass

        # ── Build API call kwargs ────────────────────────────────────────────
        if iteration <= 2 and diff in ("hard", "insane") and len(pre_fanout_hypotheses) >= 2:
            try:
                hyp_a = pre_fanout_hypotheses[0]
                hyp_b = pre_fanout_hypotheses[1]
                messages.append({"role": "user", "content":
                    f"[PARALLEL HYPOTHESIS EVALUATION — ITERATION {iteration}]\n"
                    "Evaluate BOTH of these simultaneously and report findings for each:\n"
                    f"HYP-A: {hyp_a.get('hypothesis','')} (confidence={float(hyp_a.get('confidence', 0.0)):.2f})\n"
                    f"  First tool: {hyp_a.get('first_tool','')}({hyp_a.get('first_args','')})\n"
                    f"HYP-B: {hyp_b.get('hypothesis','')} (confidence={float(hyp_b.get('confidence', 0.0)):.2f})\n"
                    f"  First tool: {hyp_b.get('first_tool','')}({hyp_b.get('first_args','')})\n"
                    "Run both. Report which has stronger evidence. Then pursue the winner."
                })
            except Exception:
                pass

        if _maybe_compress_messages:
            try:
                messages = _maybe_compress_messages(messages)
            except Exception:
                pass

        adaptive_efficiency = bool(extra.get("adaptiveEfficiency", True))
        efficiency_scale = 1.0
        if adaptive_efficiency:
            if fruitless >= 5:
                efficiency_scale *= 0.60
            elif fruitless >= 3:
                efficiency_scale *= 0.75
            elif fruitless >= 2:
                efficiency_scale *= 0.85
            if _credit_is_low(credit_guard):
                efficiency_scale *= 0.85

        requested_tokens = max(max_tokens, thinking_tokens + 2048) if use_thinking else max_tokens
        if efficiency_scale < 0.999:
            reduced_tokens = max(512, int(requested_tokens * efficiency_scale))
            if reduced_tokens < requested_tokens:
                emit(
                    "efficiency_mode",
                    iteration=iteration,
                    fruitless=fruitless,
                    tool_failures=tool_failures,
                    from_tokens=requested_tokens,
                    to_tokens=reduced_tokens,
                    scale=round(efficiency_scale, 3),
                )
                requested_tokens = reduced_tokens

        budget_plan = _plan_budgeted_call(
            credit_guard,
            model=model,
            requested_max_tokens=requested_tokens,
            messages=messages,
            system=system,
            use_thinking=use_thinking,
            thinking_tokens=thinking_tokens,
        )
        if not budget_plan.get("allowed", True):
            emit(
                "credit_guard",
                challenge_id=challenge_id,
                challenge_name=name,
                action="stop",
                iteration=iteration,
                reason=budget_plan.get("reason", "budget_guard"),
                spent_usd=credit_guard.get("spent_usd", 0.0),
                cap_usd=credit_guard.get("cap_usd", 0.0),
                remaining_usd=_credit_remaining_usd(credit_guard),
            )
            log("warn", f"Budget guard stopped solve: {budget_plan.get('reason','budget_guard')}", "")
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed", workspace=final_ws)
            return

        planned_model = budget_plan.get("model", model)
        planned_use_thinking = bool(budget_plan.get("use_thinking", use_thinking))
        planned_thinking_tokens = int(budget_plan.get("thinking_tokens", thinking_tokens))
        planned_max_tokens = int(budget_plan.get("max_tokens", requested_tokens))

        if adaptive_efficiency and fruitless >= 4 and planned_model == _MODEL_OPUS and int(route_decision.get("route_score", 0)) < 72:
            planned_model = _MODEL_SONNET
            planned_use_thinking = bool(int(route_decision.get("route_score", 0)) >= 60 and diff in ("hard", "insane"))
            if not planned_use_thinking:
                planned_thinking_tokens = 0
            planned_max_tokens = max(768, min(planned_max_tokens, int(max_tokens * 0.7)))
            emit(
                "efficiency_mode",
                iteration=iteration,
                action="downgrade_model",
                reason="fruitless_streak",
                route_score=route_decision.get("route_score", 0),
                model=planned_model,
                thinking=planned_use_thinking,
                max_tokens=planned_max_tokens,
            )

        if planned_model != model or planned_max_tokens != requested_tokens or planned_use_thinking != use_thinking:
            emit(
                "credit_guard",
                challenge_id=challenge_id,
                challenge_name=name,
                action="throttle",
                iteration=iteration,
                from_model=model,
                to_model=planned_model,
                from_tokens=requested_tokens,
                to_tokens=planned_max_tokens,
                from_thinking=use_thinking,
                to_thinking=planned_use_thinking,
                reason=budget_plan.get("reason", "budget_guard"),
                estimated_cost=budget_plan.get("estimated_cost", 0.0),
            )

        cached_tools = active_tools
        if active_tools:
            try:
                cached_tools = list(active_tools)
                cached_tools[-1] = {**cached_tools[-1], "cache_control": {"type": "ephemeral"}}
            except Exception:
                cached_tools = active_tools

        call_kwargs = dict(
            model=planned_model,
            max_tokens=planned_max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=cached_tools,
            messages=messages
        )
        if planned_use_thinking:
            call_kwargs["thinking"] = {"type":"enabled","budget_tokens":planned_thinking_tokens}
            call_kwargs["betas"] = ["interleaved-thinking-2025-05-14"]

        # ── Call Claude ──────────────────────────────────────────────────────
        try:
            resp = client.messages.create(**call_kwargs)
        except anthropic.AuthenticationError:
            log("err","Auth failed — check API key","red"); result("failed"); return
        except anthropic.RateLimitError as e:
            random = __import__("random")
            resp = None
            for attempt in range(3):
                wait = min(120, (2 ** attempt) * 15 + random.uniform(0, 5))
                log("warn", f"Rate limit — retry {attempt + 1}/3 in {wait:.1f}s: {e}", "")
                time.sleep(wait)
                try:
                    resp = client.messages.create(**call_kwargs)
                    break
                except anthropic.RateLimitError:
                    continue
                except Exception:
                    resp = None
                    break
            if resp is None:
                result("failed",workspace=final_ws); return
        except Exception as e:
            log("err",f"API error: {e}","red"); result("failed"); return

        spent_this_call = _record_credit_usage(
            credit_guard,
            model=planned_model,
            usage=getattr(resp, "usage", None),
            fallback_estimated_cost=float(budget_plan.get("estimated_cost", 0.0)),
        )
        emit(
            "credit_status",
            challenge_id=challenge_id,
            challenge_name=name,
            iteration=iteration,
            call_spend_usd=round(spent_this_call, 6),
            spent_usd=round(float(credit_guard.get("spent_usd", 0.0)), 6),
            cap_usd=credit_guard.get("cap_usd", 0.0),
            remaining_usd=round(_credit_remaining_usd(credit_guard), 6),
            low_threshold_usd=credit_guard.get("low_threshold_usd", 0.0),
            low=_credit_is_low(credit_guard),
            calls=credit_guard.get("calls", 0),
            model=planned_model,
        )
        if _credit_is_low(credit_guard) and _mark_low_credit_alert_once(credit_guard):
            emit(
                "credit_guard",
                challenge_id=challenge_id,
                challenge_name=name,
                action="low_credit",
                iteration=iteration,
                spent_usd=round(float(credit_guard.get("spent_usd", 0.0)), 6),
                cap_usd=credit_guard.get("cap_usd", 0.0),
                remaining_usd=round(_credit_remaining_usd(credit_guard), 6),
                low_threshold_usd=credit_guard.get("low_threshold_usd", 0.0),
            )
        if float(credit_guard.get("spent_usd", 0.0)) >= float(credit_guard.get("cap_usd", 0.0)) * float(credit_guard.get("hard_stop_ratio", 0.98)):
            log("warn", "Credit hard-stop reached; ending solve to protect API budget.", "")
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed", workspace=final_ws)
            return

        has_tool = False
        tool_results = []
        made_progress = False

        ordered_content = list(resp.content)
        tool_candidates = []
        for block in ordered_content:
            if getattr(block, "type", None) == "tool_use":
                if dynamic_force_local_only and getattr(block, "name", "") in _NETWORK_TOOLS:
                    continue
                tool_candidates.append({
                    "name": getattr(block, "name", ""),
                    "block": block,
                })
        if tool_candidates:
            reliability = _TOOL_RUNTIME.reliability_snapshot()
            ctx_rel = {}
            try:
                ctx_key = _TOOL_RUNTIME.context_key({
                    "is_remote": bool(inst),
                    "binary_type": "elf" if bool(challenge.get("binary_path", "") or challenge.get("file_path", "")) else "none",
                    "phase": autonomous_state.get("phase", "recon"),
                    "latency_bucket": "high" if (bool(inst) and iteration > 2) else "low",
                })
                ctx_rel = _TOOL_RUNTIME.contextual_reliability_snapshot(ctx_key)
            except Exception:
                ctx_rel = {}
            belief_uncertainty = {k: v.uncertainty for k, v in solve_state.beliefs.items()}
            merged_rel = {**reliability, **{k: ((0.4 * reliability.get(k, 0.5)) + (0.6 * v)) for k, v in ctx_rel.items()}}
            ranked = core_routing.schedule_tools_by_voi(tool_candidates, strategy, merged_rel, belief_uncertainty)
            if bandit:
                try:
                    b_rank = bandit.rank(state_vector, [str(r.get("name", "")) for r in ranked])
                    b_score = {str(x.get("tool", "")): float(x.get("score", 0.5)) for x in b_rank}
                    ranked.sort(key=lambda r: (0.65 * b_score.get(str(r.get("name", "")), 0.5)) + (0.35 * merged_rel.get(str(r.get("name", "")), 0.5)), reverse=True)
                except Exception:
                    pass
            if chain_policy and last_chain_tool:
                try:
                    chain_rank = chain_policy.rerank([str(r.get("name", "")) for r in ranked], prev_tool=last_chain_tool)
                    rank_pos = {n: i for i, n in enumerate(chain_rank)}
                    ranked.sort(key=lambda r: rank_pos.get(str(r.get("name", "")), 9999))
                except Exception:
                    pass
            if council_throttle:
                dynamic_max_tool_calls = min(dynamic_max_tool_calls, 1)
            ranked = ranked[: max(1, int(dynamic_max_tool_calls))]
            ranked_blocks = [r["block"] for r in ranked]
            non_tools = [b for b in ordered_content if getattr(b, "type", None) != "tool_use"]
            ordered_content = non_tools + ranked_blocks

        cur_iter_tool_set = set([str(getattr(b, "name", "")) for b in ordered_content if getattr(b, "type", None) == "tool_use"])
        novel_tool_actions = len([t for t in cur_iter_tool_set if t and t not in last_iter_tool_set])
        if planned_model == _MODEL_OPUS and planned_use_thinking:
            try:
                if novel_tool_actions <= 0:
                    no_novel_thinking_streak += 1
                else:
                    no_novel_thinking_streak = 0
                usage_obj = getattr(resp, "usage", None)
                out_toks = float(getattr(usage_obj, "output_tokens", 0) or 0) if usage_obj is not None else 0.0
                consumed_ceiling = out_toks >= (0.95 * float(max(1, planned_max_tokens)))
                if no_novel_thinking_streak >= 2:
                    reduced = max(2048, int(planned_thinking_tokens * 0.5))
                    emit("thinking_calibration", iteration=iteration, action="halve", from_tokens=planned_thinking_tokens, to_tokens=reduced, reason="no_novel_actions")
                    planned_thinking_tokens = reduced
                    no_novel_thinking_streak = 0
                elif consumed_ceiling:
                    boosted = min(32000, int(planned_thinking_tokens * 1.25))
                    emit("thinking_calibration", iteration=iteration, action="boost", from_tokens=planned_thinking_tokens, to_tokens=boosted, reason="budget_ceiling_hit")
                    planned_thinking_tokens = boosted
            except Exception:
                pass
        last_iter_tool_set = cur_iter_tool_set

        for block in ordered_content:
            btype = getattr(block,"type",None)

            if btype == "thinking":
                # Log thinking blocks compactly
                think_text = getattr(block,"thinking","")
                if think_text:
                    log("sys",f"[THINKING] {think_text[:200]}...","dim")

            elif btype == "text":
                solve_log.append(block.text)
                for line in block.text.splitlines():
                    if line.strip(): log("ai",line.strip(),"")
                flag = extract_flag(block.text, ctf_name)
                if flag and not found_flag: found_flag = flag; made_progress = True

            elif btype == "tool_use":
                has_tool    = True
                tname,tinput,tid = block.name,block.input,block.id
                if int(critic_hard_block_until_iter) >= int(iteration) and tname not in ("pre_solve_recon", "rank_hypotheses", "fetch_live_writeup_hint"):
                    emit("critic_hard_block", iteration=iteration, blocked_tool=tname, until_iter=critic_hard_block_until_iter)
                    tool_results.append({"type": "tool_result", "tool_use_id": tid, "content": "Tool blocked by critic hard-stop. Pivot required before further exploit actions."})
                    continue

                if tool_deduplicator and tname not in ("submit_flag", "detect_flag_format"):
                    try:
                        dedup = tool_deduplicator.register_or_block(
                            tool_name=tname,
                            tool_args=tinput if isinstance(tinput, dict) else {},
                            recommended_tools=list(strategy.get("recommended_tools", [])),
                        )
                        emit("tool_dedup", iteration=iteration, tool=tname, blocked=bool(dedup.get("blocked", False)), similarity=dedup.get("similarity", 0.0), hash=dedup.get("hash", ""))
                        if bool(dedup.get("blocked", False)):
                            alt_tool = str(dedup.get("diversify_tool", "")).strip() or str((strategy.get("recommended_tools") or ["pre_solve_recon"])[0])
                            alt_input = dedup.get("diversify_args", {}) if isinstance(dedup.get("diversify_args", {}), dict) else {}
                            if alt_tool in TOOL_MAP and alt_tool != tname:
                                emit("tool_dedup_substitute", iteration=iteration, blocked_tool=tname, substitute_tool=alt_tool, similarity=dedup.get("similarity", 0.0))
                                tname = alt_tool
                                tinput = alt_input
                            else:
                                tool_results.append({"type": "tool_result", "tool_use_id": tid, "content": f"Blocked redundant tool call: {tname}"})
                                continue
                    except Exception:
                        pass

                tool_call_history.append(tname)
                preview = json.dumps(tinput)
                log("sys",f"→ {tname}({preview[:160]+'...' if len(preview)>160 else preview})","dim")
                emit("tool_call", tool=tname, iteration=iteration)

                if novelty_gate_enabled and _score_tool_novelty and tname not in ("submit_flag", "detect_flag_format"):
                    try:
                        novelty = _score_tool_novelty(
                            tool_name=tname,
                            tool_args=tinput if isinstance(tinput, dict) else {},
                            recent_outputs=[str(e.get("output", "")) for e in evidence_log[-5:]],
                            api_key=api_key,
                        )
                        emit("novelty_gate", iteration=iteration, tool=tname, score=novelty.get("information_gain", 0.0), blocked=bool(novelty.get("block", False)))
                        if float(novelty.get("information_gain", 0.0)) < novelty_min_score or bool(novelty.get("block", False)):
                            alt_tool = str(novelty.get("diversify_tool", "")).strip() or str((strategy.get("recommended_tools") or ["pre_solve_recon"])[0])
                            alt_input = novelty.get("diversify_args", {}) if isinstance(novelty.get("diversify_args", {}), dict) else {}
                            if alt_tool in TOOL_MAP and alt_tool != tname:
                                emit("novelty_substitute", iteration=iteration, blocked_tool=tname, substitute_tool=alt_tool)
                                tname = alt_tool
                                tinput = alt_input
                    except Exception:
                        pass

                made_progress = True

                tool_ctx = {
                    "is_remote": bool(inst),
                    "binary_type": "elf" if bool(challenge.get("binary_path", "") or challenge.get("file_path", "")) else "none",
                    "phase": autonomous_state.get("phase", "recon"),
                    "latency_bucket": "high" if (bool(inst) and iteration > 2) else "low",
                }
                tout, tool_ok, tool_reason = _TOOL_RUNTIME.execute(tname, tinput, TOOL_MAP, context=tool_ctx)
                if not tool_ok:
                    log("err", f"{tout} ({tool_reason})", "red")
                    tool_failures += 1
                tool_grade = {
                    "quality": 1.0 if tool_ok else 0.0,
                    "extractable_facts": [],
                    "noise_ratio": 0.5,
                    "source": "binary_fallback",
                }
                if _grade_tool_result:
                    try:
                        tool_grade = _grade_tool_result(tool_name=tname, result_text=str(tout), category=cat, api_key=api_key)
                    except Exception:
                        pass
                if bandit:
                    try:
                        q_score = float(tool_grade.get("quality", 1.0 if tool_ok else 0.0))
                        if hasattr(bandit, "update_weighted"):
                            bandit.update_weighted(state_vector, tname, q_score)
                        else:
                            bandit.update(state_vector, tname, bool(q_score >= 0.5))
                        bandit_updates.append({"iteration": iteration, "tool": tname, "quality": round(q_score, 4)})
                    except Exception:
                        pass
                if chain_policy and last_chain_tool:
                    try:
                        chain_policy.update(f"{last_chain_tool}->{tname}", success=bool(tool_ok))
                    except Exception:
                        pass
                if _append_replay:
                    try:
                        _append_replay(
                            replay_path,
                            state=state_vector,
                            action={"type": "tool_call", "tool": tname, "input": tinput},
                            outcome={"success": bool(tool_ok), "reason": tool_reason, "preview": str(tout)[:240]},
                        )
                    except Exception:
                        pass

                if tname not in solve_state.beliefs:
                    solve_state.beliefs[tname] = BeliefState(hypothesis=f"tool:{tname}", uncertainty=0.5)
                belief = solve_state.beliefs[tname]
                belief.last_tool = tname
                belief.evidence_count += 1
                belief.evidence_score = max(0.0, min(1.0, belief.evidence_score + (0.10 if tool_ok else -0.08)))
                belief.uncertainty = max(0.05, min(0.95, belief.uncertainty + (-0.10 if tool_ok else 0.12)))
                emit(
                    "belief_state",
                    iteration=iteration,
                    tool=tname,
                    uncertainty=round(belief.uncertainty, 3),
                    evidence_score=round(belief.evidence_score, 3),
                    evidence_count=belief.evidence_count,
                    reliability=round(_TOOL_RUNTIME.reliability_snapshot().get(tname, 0.5), 3),
                )
                if attack_graph and _update_edge_success:
                    try:
                        phase_node = "recon"
                        sm = str(strategy.get("mode", "")).lower()
                        if "validator" in sm:
                            phase_node = "validate"
                        elif "diversify" in sm or "refine" in sm:
                            phase_node = "refine"
                        elif "exploit" in sm or "binary" in sm:
                            phase_node = "exploit"
                        attack_graph = _update_edge_success(attack_graph, [{"from": phase_node, "to": "goal", "success": bool(tool_ok)}])
                    except Exception:
                        pass
                if hyp_manager and planner_hypotheses:
                    try:
                        active_h = hyp_manager.select_active(iteration=iteration, hint=f"{tname} {strategy.get('mode', '')}")
                        if not active_h:
                            active_h = planner_hypotheses[min(len(planner_hypotheses) - 1, iteration % max(1, len(planner_hypotheses))) ]
                        ev_gain = 0.12 if tool_ok else -0.08
                        hyp_manager.update(active_h, success=bool(tool_ok), evidence_gain=ev_gain, note=f"tool={tname}")
                        killed = hyp_manager.mark_kill_criteria(fruitless=fruitless, iteration=iteration, total_iters=max_iterations)
                        if killed:
                            emit("hypothesis_kill", iteration=iteration, killed=killed[:4])
                        emit("hypothesis_lifecycle", iteration=iteration, summary=hyp_manager.summary()[:8])
                    except Exception:
                        pass

                # Capture workspace path
                if tname=="create_workspace" and "Workspace created:" in str(tout):
                    m=re.search(r"Workspace created: (.+)",str(tout))
                    if m: final_ws=m.group(1).strip()
                    emit("workspace",path=final_ws)

                # Log preview
                pout=str(tout); preview_len=int(extra.get("logPreview",400))
                if len(pout)>preview_len: pout=pout[:preview_len//2]+"\n...\n"+pout[-preview_len//2:]
                for line in pout.splitlines():
                    if line.strip(): log("info",f"  {line.strip()}","")

                flag = extract_flag(str(tout), ctf_name)
                if flag and not found_flag: found_flag = flag; made_progress = True
                tool_results.append({"type":"tool_result","tool_use_id":tid,"content":str(tout)})
                evidence_log.append({
                    "iteration": iteration,
                    "phase": autonomous_state.get("phase"),
                    "strategy": strategy.get("mode", ""),
                    "tool": tname,
                    "input": tinput,
                    "output": str(tout)[:2000],
                    "success": _tool_output_success(str(tout)),
                    "quality": float(tool_grade.get("quality", 0.5)),
                    "extractable_facts": tool_grade.get("extractable_facts", []),
                    "noise_ratio": float(tool_grade.get("noise_ratio", 0.0)),
                })
                if belief_graph:
                    try:
                        bup = belief_graph.update_from_evidence(
                            tool=tname,
                            output=str(tout),
                            success=bool(tool_ok),
                            quality=float(tool_grade.get("quality", 0.5) or 0.5),
                        )
                        emit("belief_graph", iteration=iteration, event="evidence_update", **bup)
                    except Exception:
                        pass
                if _record_chain_edge and last_chain_tool:
                    try:
                        chain_edge = _record_chain_edge(
                            _KG_STORE,
                            ctf_name or "default",
                            from_tool=last_chain_tool,
                            from_output=last_chain_output,
                            to_tool=tname,
                            to_output=str(tout),
                        )
                        emit("exploit_chain", iteration=iteration, edge=chain_edge)
                    except Exception:
                        pass
                last_chain_tool = tname
                last_chain_output = str(tout)
                tool_quality_log.append({
                    "iteration": iteration,
                    "tool": tname,
                    "quality": float(tool_grade.get("quality", 0.5)),
                    "noise_ratio": float(tool_grade.get("noise_ratio", 0.0)),
                    "contains_flag_signal": bool(tool_grade.get("contains_flag_signal", False)),
                })
                if bool(extra.get("haikuCommentary", True)) and _run_haiku_critic:
                    try:
                        cmt = _run_haiku_critic(
                            model_reasoning=(solve_log[-1] if solve_log else ""),
                            tool_results=[{"tool": tname, "output": str(tout)[:900]}],
                            current_hypothesis=strategy.get("mode", ""),
                            iteration=iteration,
                            api_key=api_key,
                        )
                        note = str(cmt.get("critic_note", "")).strip()
                        if note:
                            emit("haiku_commentary", iteration=iteration, note=note)
                    except Exception:
                        pass
                try:
                    evidence_ledger_path = _persist_evidence_record(final_ws or ws, {
                        "iteration": iteration,
                        "phase": autonomous_state.get("phase"),
                        "strategy": strategy.get("mode", ""),
                        "tool": tname,
                        "input": tinput,
                        "output": str(tout)[:4000],
                        "success": _tool_output_success(str(tout)),
                        "quality": float(tool_grade.get("quality", 0.5)),
                        "route_score": route_decision.get("route_score", 0),
                    })
                except Exception as e:
                    log("warn", f"Evidence ledger write failed: {e}", "")
                emit(
                    "explainability",
                    event="tool_result",
                    iteration=iteration,
                    phase=autonomous_state.get("phase"),
                    strategy_mode=strategy.get("mode", ""),
                    tool=tname,
                    success=_tool_output_success(str(tout)),
                    evidence_ledger=evidence_ledger_path,
                )
                autonomous_state = _update_autonomous_phase(
                    autonomous_state,
                    iteration=iteration,
                    tool_used=True,
                    found_signal=bool(flag),
                    fruitless=fruitless,
                )
                if flag and first_signal_time_s is None:
                    first_signal_time_s = max(0.0, time.time() - _solve_start_time)

        messages.append({"role":"assistant","content":resp.content})

        # ── Progress tracking ────────────────────────────────────────────────
        if made_progress and not found_flag:
            solve_state.iteration = iteration
            solve_state.fruitless = fruitless
            solve_state.tool_failures = tool_failures
            solve_state.touch_progress()
            fruitless = solve_state.fruitless
            last_progress_iter = solve_state.last_progress_iter
            tool_failures = solve_state.tool_failures
        elif not found_flag:
            solve_state.iteration = iteration
            solve_state.fruitless = fruitless
            solve_state.touch_no_progress()
            fruitless = solve_state.fruitless

        if thinking_tracker and planned_model == _MODEL_OPUS and planned_use_thinking:
            try:
                thinking_tracker.record_call(
                    thinking_tokens_used=int(planned_thinking_tokens),
                    evidence_gained=(0.35 if made_progress else 0.0),
                    model=planned_model,
                    iteration=iteration,
                )
                emit("thinking_efficiency", iteration=iteration, **thinking_tracker.efficiency_summary())
            except Exception:
                pass

        if _run_haiku_critic:
            try:
                critic_verdict = _run_haiku_critic(
                    model_reasoning=(solve_log[-1] if solve_log else ""),
                    tool_results=[{"tool": rec.get("tool", ""), "output": rec.get("output", "")} for rec in evidence_log[-4:]],
                    current_hypothesis=(planner_hypotheses[0] if planner_hypotheses else strategy.get("mode", "")),
                    iteration=iteration,
                    api_key=api_key,
                )
                emit("critic_step", iteration=iteration, verdict=critic_verdict)
                if bool(critic_verdict.get("recommended_pivot", False)):
                    fruitless += 1
                    messages.append({"role": "user", "content":
                        "[HAIKU CRITIC VERDICT]\n"
                        f"Pivot recommended: {critic_verdict.get('pivot_reason', '')}\n"
                        f"Ignored evidence: {critic_verdict.get('ignored_evidence', [])}\n"
                        "Change approach now and run a disconfirming test."
                    })
                if bool(critic_verdict.get("flag_hallucination", False)) and bool(critic_verdict.get("recommended_pivot", False)):
                    critic_hard_block_until_iter = max(int(critic_hard_block_until_iter), int(iteration + 1))
                    emit("critic_hard_block", iteration=iteration, until_iter=critic_hard_block_until_iter, reason="flag_hallucination_and_pivot")
                    messages.append({"role": "user", "content":
                        "[CRITIC HARD BLOCK]\n"
                        "Flag hallucination risk detected with mandatory pivot.\n"
                        "Do not run another exploit submission path until a fresh recon/disconfirming step succeeds."
                    })
            except Exception:
                pass

        # ── Flag found ───────────────────────────────────────────────────────
        if found_flag:
            if council_submit_blocked:
                false_flag_candidates += 1
                emit("zero_trust_gate", iteration=iteration, blocked=True, reason="council_submit_blocked")
                messages.append({"role": "user", "content": "[ZERO-TRUST GATE] Council blocked submission. Gather more reproducible evidence and reduce contradictions first."})
                found_flag = None
                fruitless += 1
                continue
            min_evidence = int(extra.get("minEvidenceBeforeFlag", 2))
            if len(evidence_log) < min_evidence:
                false_flag_candidates += 1
                emit(
                    "explainability",
                    event="flag_candidate_rejected",
                    iteration=iteration,
                    reason="insufficient_evidence",
                    evidence_count=len(evidence_log),
                    required=min_evidence,
                )
                messages.append({"role": "user", "content":
                    "[EVIDENCE-FIRST GATE]\n"
                    f"Candidate flag detected but evidence_count={len(evidence_log)} < required={min_evidence}.\n"
                    "Collect additional reproducible tool evidence before validating/submitting."
                })
                found_flag = None
                fruitless += 1
                continue
            repro = _reproducibility_check(found_flag, evidence_log, solve_log)
            emit("zero_trust_gate", iteration=iteration, reproducibility=repro)
            if repro.get("verdict") != "pass":
                false_flag_candidates += 1
                messages.append({"role": "user", "content": "[ZERO-TRUST GATE] Reproducibility check failed. Re-run extraction path and gather corroborating tool output."})
                found_flag = None
                fruitless += 1
                continue
            if belief_graph and float(belief_graph.contradiction_ratio()) > float(extra.get("maxBeliefContradictionForSubmit", 0.4) or 0.4):
                false_flag_candidates += 1
                emit("zero_trust_gate", iteration=iteration, blocked=True, reason="belief_contradiction_high", contradiction_ratio=belief_graph.contradiction_ratio())
                found_flag = None
                fruitless += 1
                continue
            if _score_flag_candidate:
                try:
                    guard = _score_flag_candidate(found_flag, ctf_name, evidence_log, solve_log)
                    emit("flag_submit_guard", iteration=iteration, **guard)
                    if not bool(guard.get("pass", False)):
                        false_flag_candidates += 1
                        messages.append({"role": "user", "content":
                            "[FLAG SUBMIT GUARD]\n"
                            f"Blocked candidate flag. Scores: prefix={guard.get('prefix_score')} context={guard.get('context_score')} entropy={guard.get('entropy_score')} combined={guard.get('combined_score')}\n"
                            "Collect stronger chain-of-custody evidence before trying to validate/submit."
                        })
                        found_flag = None
                        fruitless += 1
                        continue
                except Exception:
                    pass
            validation = _run_self_verification(
                candidate_flag=found_flag,
                conversation_summary="\n\n".join(solve_log[-10:]),
                ctf_name=ctf_name,
                category=cat,
                evidence_log=evidence_log,
                solve_log=solve_log,
                api_key=(api_key if _credit_remaining_usd(credit_guard) >= 0.12 else ""),
            )
            emit(
                "validation",
                verdict=validation.get("verdict", "fail"),
                confidence=validation.get("confidence", 0.0),
                reason=validation.get("reason", "")
            )
            if validation.get("verdict") != "pass":
                false_flag_candidates += 1
                log("warn", f"Validator rejected candidate flag (confidence={validation.get('confidence', 0.0):.2f})", "")
                messages.append({"role": "user", "content":
                    "[VALIDATOR RESULT]\n"
                    f"Verdict: {validation.get('verdict')}\n"
                    f"Reason: {validation.get('reason')}\n"
                    f"Required checks: {validation.get('required_checks')}\n"
                    "Continue solving and gather stronger evidence before finalizing."})
                found_flag = None
                fruitless += 1
                continue

            elapsed = time.time() - _solve_start_time
            log("ok",f"🚩 FLAG: {found_flag}","white")
            prefix = _infer_prefix_from_flag(found_flag)
            if prefix and ctf_name: confirm_flag_format(ctf_name, prefix, found_flag)
            emit("solve_stats", elapsed=round(elapsed,1), iterations=iteration,
                 model=model, thinking=use_thinking, validation_confidence=validation.get("confidence", 0.0))
            emit(
                "explainability",
                event="solve_complete",
                iteration=iteration,
                phase=autonomous_state.get("phase"),
                strategy_mode=strategy.get("mode", ""),
                evidence_count=len(evidence_log),
                evidence_ledger=evidence_ledger_path,
            )
            summary="\n\n".join(solve_log[-6:])
            if _credit_remaining_usd(credit_guard) >= 0.35:
                generate_writeup(client,user_model,{**challenge,"ctf_name":ctf_name},
                                 found_flag,summary,final_ws,extra,
                                 evidence_bundle={
                                     "planner_summary": planner_summary,
                                     "tool_evidence": (planner_evidence + evidence_log)[-60:],
                                     "failed_attempts": pivot_events[-20:],
                                     "route_history": route_history[-20:],
                                     "strategy_history": strategy_history[-20:],
                                     "hypothesis_trace": planner_hypotheses[:16],
                                     "tool_quality_log": tool_quality_log[-80:],
                                     "bandit_updates": bandit_updates[-120:],
                                     "difficulty_events": difficulty_events[-8:],
                                     "debate_context": debate_context,
                                 })
            else:
                log("warn", "Skipping LLM writeup to preserve API credit budget.", "")
            try:
                _store_memory_v2({
                    "timestamp": int(time.time()),
                    "ctf_name": ctf_name,
                    "challenge_name": name,
                    "category": cat,
                    "difficulty": diff,
                    "fingerprint": _challenge_fingerprint(challenge, ctf_name),
                    "tool_sequence": tool_call_history[-80:],
                    "winning_path": summary[:1200],
                    "dead_ends": pivot_events[-8:],
                    "summary": summary[:2000],
                    "validator": validation,
                    "memory_type": "proof_artifact" if (validation.get("verdict") == "pass" and len(evidence_log) >= 3) else "episodic",
                    "why_it_worked": strategy.get("mode", ""),
                    "why_failed_before": pivot_events[-6:],
                    "source_strength": 0.85 if len(evidence_log) >= 3 else 0.7,
                    "reproducibility_count": max(1, len([e for e in evidence_log[-20:] if bool(e.get("success", False))])),
                    "model_route": route_history[-12:],
                    "strategy_history": strategy_history[-12:],
                    "workspace": final_ws,
                    "flag_prefix": _infer_prefix_from_flag(found_flag) or "",
                })
                _kg_upsert_fact(ctf_name or "default", f"{cat}_last_flag_prefix", _infer_prefix_from_flag(found_flag) or "")
                _kg_upsert_fact(ctf_name or "default", f"{cat}_last_strategy", strategy.get("mode", ""))
                _kg_upsert_fact(ctf_name or "default", f"{cat}_winning_writeup", summary[:2000])
                if _rag_ingest_solved:
                    _rag_ingest_solved({
                        "ctf_name": ctf_name,
                        "challenge_name": name,
                        "category": cat,
                        "difficulty": diff,
                        "description_text": augmented_desc,
                        "attack_technique": strategy.get("mode", ""),
                        "winning_tool_sequence": tool_call_history[-40:],
                        "solve_summary": summary,
                    })
                try:
                    _KG_STORE.ingest_solve_record({
                        "ctf_name": ctf_name,
                        "challenge_name": name,
                        "category": cat,
                        "attack_technique": strategy.get("mode", ""),
                        "winning_tool_sequence": tool_call_history[-40:],
                        "flag_prefix": _infer_prefix_from_flag(found_flag) or "",
                    })
                except Exception:
                    pass
            except Exception as e:
                log("warn", f"Memory store skipped: {e}", "")
            _finalize_policy_and_benchmark("solved", solved_flag=found_flag)
            result("solved",found_flag,workspace=final_ws)
            return

        try:
            cp_path = core_checkpoint.save_checkpoint(final_ws or ws or base_dir or os.getcwd(), name, {
                "iteration": iteration,
                "fruitless": fruitless,
                "tool_failures": tool_failures,
                "messages": messages[-30:],
                "solve_log": solve_log[-40:],
                "evidence_log": evidence_log[-80:],
                "route_history": route_history[-40:],
                "strategy_history": strategy_history[-40:],
            })
            emit("checkpoint", action="saved", path=cp_path, iteration=iteration)
        except Exception as e:
            log("warn", f"Checkpoint save failed: {e}", "")

        if _append_iteration_telemetry:
            try:
                _append_iteration_telemetry(telemetry_path, {
                    "category": cat,
                    "iteration": iteration,
                    "route_score": route_decision.get("route_score", 50),
                    "fruitless": fruitless,
                    "tool_failures": tool_failures,
                    "strategy_mode": strategy.get("mode", ""),
                    "solved": False,
                    "failed": True,
                    "has_flag": False,
                    "tool_sequence": tool_call_history[-30:],
                })
            except Exception:
                pass

        # ── Continue or stop ─────────────────────────────────────────────────
        stop=getattr(resp,"stop_reason",None)
        if has_tool and tool_results:
            messages.append({"role":"user","content":tool_results})
        elif stop=="end_turn":
            log("warn","Stopped without flag — add more context or increase iterations","")
            try:
                failed_approaches = list(dict.fromkeys((pivot_events + [f"tool:{t}" for t in tool_call_history[-30:]])))
                _store_failure_path(challenge, ctf_name, failed_approaches, cat, diff)
            except Exception:
                pass
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed",workspace=final_ws); return
        else:
            log("warn",f"Unexpected stop: {stop}","")
            try:
                failed_approaches = list(dict.fromkeys((pivot_events + [f"tool:{t}" for t in tool_call_history[-30:]])))
                _store_failure_path(challenge, ctf_name, failed_approaches, cat, diff)
            except Exception:
                pass
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed",workspace=final_ws); return

    elapsed = time.time() - _solve_start_time
    log("warn",f"Budget exhausted ({max_iterations} iters, {elapsed:.0f}s)","")
    try:
        failed_approaches = list(dict.fromkeys((pivot_events + [f"tool:{t}" for t in tool_call_history[-30:]])))
        _store_failure_path(challenge, ctf_name, failed_approaches, cat, diff)
    except Exception:
        pass
    _finalize_policy_and_benchmark("failed", solved_flag="")
    result("failed",workspace=final_ws)
    return


def run_solve(payload):
    _bootstrap_runtime_context()

    critical_symbols = [
        "emit",
        "log",
        "result",
        "IS_WINDOWS",
        "USE_WSL",
        "_w2l",
        "_shell",
        "_ctf_knowledge",
        "_build_challenge_signal_pack",
        "_init_credit_guard",
        "build_tool_registry",
        "enabled_tools",
        "TOOLS",
        "TOOL_MAP",
        "build_system_prompt",
        "_build_attack_playbook",
        "_build_multimodal_feature_pack",
        "_tokenize_simple",
        "extract_flag",
        "_store_failure_path",
        "_retrieve_memory_v2",
        "_store_memory_v2",
        "_KG_STORE",
        "core_routing",
        "core_verification",
        "_normalize_category_key",
        "_NETWORK_TOOLS",
        "tool_analyze_file",
        "tool_js_analyze",
        "tool_http_request",
    ]
    missing = [name for name in critical_symbols if name not in globals()]
    if missing:
        _safe_fail(
            payload,
            "Runtime dependency preflight failed. Missing symbols: " + ", ".join(missing),
        )
        return

    orchestrator = globals().get("core_orchestrator")
    if orchestrator is None:
        try:
            from core import orchestrator as orchestrator  # type: ignore
            globals()["core_orchestrator"] = orchestrator
        except Exception as e:
            _safe_fail(payload, f"Runtime init failed: cannot load core orchestrator ({e})")
            return

    try:
        return orchestrator.run_solve(payload, _run_solve_impl)
    except Exception as e:
        _safe_fail(payload, f"Solve pipeline crashed: {e}")
        return

