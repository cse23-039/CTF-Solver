"""Core solve loop."""
from __future__ import annotations


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
                          learned_overrides: dict | None = None) -> dict:
    return core_routing.decide_strategy_mode(
        category=category,
        phase=phase,
        fruitless=fruitless,
        tool_failures=tool_failures,
        iteration=iteration,
        total_iters=total_iters,
        memory_diag=memory_diag,
        learned_overrides=learned_overrides,
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
    pc=payload.get("platform",{}); base_dir=payload.get("base_dir",""); ctf_name=payload.get("ctf_name","CTF")
    if not base_dir:
        log("err","No base directory set","red"); emit("import_result",error="No base directory"); return
    log("sys",f"Connecting to {pc.get('type','?')}...","bright")
    try:
        sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
        from platforms import import_challenges
        res=import_challenges(pc,base_dir,ctf_name)
        if res.get("error"): log("err",res["error"],"red"); emit("import_result",error=res["error"]); return
        log("ok",res.get("login_message","Connected"),"white")
        n=len(res.get("challenges",[])); log("sys",f"Fetched {n} challenges","bright")
        for err in res.get("errors",[]): log("warn",err,"")
        emit("import_result",challenges=res.get("challenges",[]),
             platform_token=res.get("platform_token"),ctf_name=ctf_name)
    except Exception as e:
        log("err",f"Import failed: {e}","red"); emit("import_result",error=str(e))


def _run_solve_impl(payload):
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
    memory_hits = _retrieve_memory_v2(
        challenge,
        ctf_name=ctf_name,
        top_k=int(extra.get("memoryTopK", 3))
    )
    memory_diag = _analyze_memory_consistency(memory_hits)
    trusted_memory_hits = memory_diag.get("trusted_hits", [])
    memory_ctx = _build_memory_injection(trusted_memory_hits or memory_hits)
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
    system = build_system_prompt(pc.get("type","manual"), ctf_name, base_dir, extra)
    if memory_ctx:
        system = memory_ctx + "\n\n" + system
    if knowledge_ctx:
        system = knowledge_ctx + "\n\n" + system

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
    if files:
        pb.add(f"\n## Challenge Files / Source / Data\n```\n{files[:8000]}\n```\n")
    if fmt_inject:
        pb.add(fmt_inject)
    if memory_ctx:
        pb.add(f"\n{memory_ctx}\n")
    if knowledge_ctx:
        pb.add(f"\n{knowledge_ctx}\n")
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

    planner_summary = ""
    planner_evidence = []
    planner_outputs = {}
    planner_hypotheses = []
    planner_pruned = []
    bootstrap_artifacts = []
    planner_enabled = bool(extra.get("hierarchicalPlanner", True))
    if credit_guard.get("conservative", False) and _credit_remaining_usd(credit_guard) <= 3.0:
        planner_enabled = False
        emit("credit_guard", action="planner_disabled", reason="low_budget")

    try:
        if planner_enabled:
            planner = _run_hierarchical_planner(challenge_ctx, api_key, extra)
            planner_hypotheses = planner.get("hypotheses", [])
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

    if diff in ("hard","insane") and parallel_enabled:
        log("sys","[PARALLEL] Hard challenge — attempting parallel branch solve first","bright")
        hypotheses = planner_hypotheses[:3] if planner_hypotheses else []
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
            challenge_ctx = {"ctf_name":ctf_name,"category":cat,"name":name,"user_msg":user_msg}
            branch_iters  = min(8, max_iterations // 4)
            branch_result = run_parallel_branches(hypotheses, challenge_ctx, api_key,
                                                   active_tools, system, branch_iters, extra,
                                                   credit_guard=credit_guard)
            if branch_result:
                winning_hyp, found_flag = branch_result
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
                            "workspace": ws,
                        })
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

    policy_dir = os.path.join((final_ws or ws or base_dir or os.getcwd()), ".solver")
    telemetry_path = os.path.join(policy_dir, "iteration_telemetry.json")
    priors_path = os.path.join(policy_dir, "learned_policy.json")
    benchmark_path = os.path.join(policy_dir, "benchmark_history.json")
    learned_overrides = {}
    if _get_learned_overrides:
        try:
            if _should_retrain_weekly and _retrain_priors and _should_retrain_weekly(priors_path):
                _retrain_priors(telemetry_path, priors_path)
                emit("policy_retrain", status="completed", reason="weekly")
            learned_overrides = _get_learned_overrides(priors_path, cat)
        except Exception:
            learned_overrides = {}
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
                    "has_flag": bool(solved_flag),
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
                    "challenge": name,
                    "solve_rate": float(solved),
                    "false_flag_rate": float(false_flag_candidates / max(1, false_flag_candidates + solved)),
                    "cost_per_flag": float(spent / max(1, solved)),
                    "time_to_first_signal": t_first,
                    "time_to_flag": elapsed_total if solved else float(9999.0),
                }
                bench = _benchmark_evaluate(metrics, benchmark_path, gates=extra.get("benchmarkGates", {}))
                emit("benchmark_gate", **bench)
                if bench.get("verdict") != "pass":
                    emit("policy_reject", reason="benchmark_gate_failed", details=bench.get("reasons", []))
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

        # ── Multi-model routing ──────────────────────────────────────────────
        progress_gap = (iteration - last_progress_iter if last_progress_iter else iteration) + contradiction_penalty
        route_decision = _route_model_v2(
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
        )
        model = route_decision["model"]
        use_thinking = route_decision["use_thinking"]
        thinking_tokens = route_decision["thinking_tokens"]
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

        strategy = _decide_strategy_mode(
            category=cat,
            phase=autonomous_state.get("phase", "recon"),
            fruitless=fruitless,
            tool_failures=tool_failures,
            iteration=iteration,
            total_iters=max_iterations,
            memory_diag=memory_diag,
            learned_overrides=learned_overrides,
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
        if fruitless >= _critic_threshold and fruitless % _critic_threshold == 0:
            log("warn",f"[CRITIC] {fruitless} fruitless iters — triggering critic analysis","")
            summary = "\n".join(solve_log[-8:])
            critic_out = tool_critic(summary, iteration, cat, api_key)
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
        requested_tokens = max(max_tokens, thinking_tokens + 2048) if use_thinking else max_tokens
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

        call_kwargs = dict(
            model=planned_model,
            max_tokens=planned_max_tokens,
            system=system,
            tools=active_tools,
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
            log("warn",f"Rate limit — waiting 30s: {e}","")
            time.sleep(30)
            try: resp = client.messages.create(**call_kwargs)
            except: result("failed",workspace=final_ws); return
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
                tool_candidates.append({
                    "name": getattr(block, "name", ""),
                    "block": block,
                })
        if tool_candidates:
            reliability = _TOOL_RUNTIME.reliability_snapshot()
            belief_uncertainty = {k: v.uncertainty for k, v in solve_state.beliefs.items()}
            ranked = core_routing.schedule_tools_by_voi(tool_candidates, strategy, reliability, belief_uncertainty)
            ranked_blocks = [r["block"] for r in ranked]
            non_tools = [b for b in ordered_content if getattr(b, "type", None) != "tool_use"]
            ordered_content = non_tools + ranked_blocks

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
                made_progress = True
                tname,tinput,tid = block.name,block.input,block.id
                tool_call_history.append(tname)
                preview = json.dumps(tinput)
                log("sys",f"→ {tname}({preview[:160]+'...' if len(preview)>160 else preview})","dim")
                emit("tool_call", tool=tname, iteration=iteration)

                tout, tool_ok, tool_reason = _TOOL_RUNTIME.execute(tname, tinput, TOOL_MAP)
                if not tool_ok:
                    log("err", f"{tout} ({tool_reason})", "red")
                    tool_failures += 1

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
                })
                try:
                    evidence_ledger_path = _persist_evidence_record(final_ws or ws, {
                        "iteration": iteration,
                        "phase": autonomous_state.get("phase"),
                        "strategy": strategy.get("mode", ""),
                        "tool": tname,
                        "input": tinput,
                        "output": str(tout)[:4000],
                        "success": _tool_output_success(str(tout)),
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

        # ── Flag found ───────────────────────────────────────────────────────
        if found_flag:
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
                    "model_route": route_history[-12:],
                    "strategy_history": strategy_history[-12:],
                    "workspace": final_ws,
                    "flag_prefix": _infer_prefix_from_flag(found_flag) or "",
                })
                _kg_upsert_fact(ctf_name or "default", f"{cat}_last_flag_prefix", _infer_prefix_from_flag(found_flag) or "")
                _kg_upsert_fact(ctf_name or "default", f"{cat}_last_strategy", strategy.get("mode", ""))
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
                    "has_flag": False,
                })
            except Exception:
                pass

        # ── Continue or stop ─────────────────────────────────────────────────
        stop=getattr(resp,"stop_reason",None)
        if has_tool and tool_results:
            messages.append({"role":"user","content":tool_results})
        elif stop=="end_turn":
            log("warn","Stopped without flag — add more context or increase iterations","")
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed",workspace=final_ws); return
        else:
            log("warn",f"Unexpected stop: {stop}","")
            _finalize_policy_and_benchmark("failed", solved_flag="")
            result("failed",workspace=final_ws); return

    elapsed = time.time() - _solve_start_time
    log("warn",f"Budget exhausted ({max_iterations} iters, {elapsed:.0f}s)","")
    _finalize_policy_and_benchmark("failed", solved_flag="")
    result("failed",workspace=final_ws)
    return


def run_solve(payload):
    return core_orchestrator.run_solve(payload, _run_solve_impl)

