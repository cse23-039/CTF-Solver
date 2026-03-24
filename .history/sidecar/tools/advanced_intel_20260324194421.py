"""Advanced intelligence tooling layer (MVP implementations).

These tools provide orchestration-grade building blocks for:
- AI-guided fuzzing
- constraint fusion across domains
- program synthesis helpers
- protocol/state recovery
- attack-graph reasoning
- autonomous exploit loop control
"""
from __future__ import annotations

import json
import math
import random
import re
import statistics
import time
from collections import Counter, defaultdict, deque
from typing import Any


def _to_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


def _tokenize(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-zA-Z0-9_]+", (text or "").lower()) if t]


def tool_ai_fuzzer(target: str = "", seeds: list[str] | None = None, rounds: int = 200,
                   mutation_rate: float = 0.15, max_len: int = 256) -> str:
    seeds = _to_list(seeds) or ["A", "AAAA", "0", "{}", "[]", "\x00", "../../etc/passwd"]
    corpus = set(seeds)
    crashes = []
    coverage_proxy = set()

    def mutate(s: str) -> str:
        if not s:
            s = "A"
        chars = list(s)
        for i in range(len(chars)):
            if random.random() < mutation_rate:
                chars[i] = chr(random.randint(1, 126))
        if random.random() < mutation_rate:
            chars.append(chr(random.randint(1, 126)))
        out = "".join(chars)[:max_len]
        if random.random() < mutation_rate:
            out += random.choice(["\n", "\r\n", "%x%x%x", "' OR 1=1--", "\x00\x00"])
        return out[:max_len]

    for _ in range(max(1, int(rounds))):
        base = random.choice(tuple(corpus))
        candidate = mutate(base)
        corpus.add(candidate)

        # Coverage proxy: token + length + byte histogram signatures.
        sig = (
            len(candidate) // 8,
            sum(ord(c) for c in candidate) % 97,
            len(set(candidate))
        )
        coverage_proxy.add(sig)

        # Crash heuristics to triage likely interesting payloads.
        low = candidate.lower()
        if any(x in low for x in ["%n", "\x00\x00\x00", "../../", "\r\n\r\n", "${", "{{"]):
            crashes.append(candidate)

    report = {
        "target": target,
        "seed_count": len(seeds),
        "corpus_size": len(corpus),
        "coverage_proxy_buckets": len(coverage_proxy),
        "triaged_candidates": crashes[:20],
        "next": [
            "Run interesting candidates against instrumented target (AFL/QEMU/ASAN)",
            "Feed crashes to tool_auto_exploit_loop",
            "Promote candidates into grammar/stateful fuzzers"
        ],
    }
    return _safe_json(report)


def tool_grammar_infer(samples: list[str] | None = None, max_rules: int = 24) -> str:
    samples = [str(x) for x in _to_list(samples) if str(x)]
    if not samples:
        return "Provide non-empty sample inputs."

    token_patterns = Counter()
    delimiters = Counter()
    for s in samples:
        for d in [",", ":", "=", "&", "|", ";", " ", "\t"]:
            if d in s:
                delimiters[d] += s.count(d)
        for tok in re.split(r"([,:=&|;\s])", s):
            if not tok or tok.isspace() or tok in ",:=&|;":
                continue
            if re.fullmatch(r"[0-9]+", tok):
                token_patterns["INT"] += 1
            elif re.fullmatch(r"[0-9a-fA-F]+", tok):
                token_patterns["HEX"] += 1
            elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
                token_patterns["IDENT"] += 1
            elif re.fullmatch(r"[A-Za-z0-9+/=]+", tok):
                token_patterns["B64LIKE"] += 1
            else:
                token_patterns["TEXT"] += 1

    rules = []
    for kind, _ in token_patterns.most_common(max_rules):
        if kind == "INT":
            rules.append("<INT> ::= /[0-9]+/")
        elif kind == "HEX":
            rules.append("<HEX> ::= /[0-9a-fA-F]+/")
        elif kind == "IDENT":
            rules.append("<IDENT> ::= /[A-Za-z_][A-Za-z0-9_]*/")
        elif kind == "B64LIKE":
            rules.append("<B64LIKE> ::= /[A-Za-z0-9+/=]+/")
        else:
            rules.append("<TEXT> ::= /.{1,64}/")

    top_delim = delimiters.most_common(1)[0][0] if delimiters else ","
    grammar = ["<START> ::= <FIELD> (DELIM <FIELD>)*", f"DELIM ::= '{top_delim}'"] + rules

    return _safe_json({
        "sample_count": len(samples),
        "dominant_delimiter": top_delim,
        "token_profile": token_patterns,
        "grammar": grammar,
    })


def tool_protocol_learn(messages: list[str] | None = None, transport: str = "tcp") -> str:
    messages = [str(x) for x in _to_list(messages) if str(x)]
    if not messages:
        return "Provide protocol messages to learn from."

    lengths = [len(m) for m in messages]
    prefixes = Counter(m[:4] for m in messages if len(m) >= 4)
    suffixes = Counter(m[-2:] for m in messages if len(m) >= 2)

    field_hints = []
    for m in messages[:64]:
        if re.search(r"^[A-Z]+\s+/.+HTTP/", m):
            field_hints.append("http_request_line")
        if "{" in m and "}" in m:
            field_hints.append("json_like_payload")
        if re.search(r"\b[A-Z0-9_]{3,}\b", m):
            field_hints.append("enum_or_opcode_tokens")

    return _safe_json({
        "transport": transport,
        "message_count": len(messages),
        "length_stats": {
            "min": min(lengths),
            "max": max(lengths),
            "avg": round(sum(lengths) / len(lengths), 2),
        },
        "top_prefixes": prefixes.most_common(10),
        "top_suffixes": suffixes.most_common(10),
        "field_hints": Counter(field_hints),
        "next": "Use tool_state_machine_recovery on ordered traces.",
    })


def tool_stateful_fuzz(state_model: dict | None = None, seeds: list[str] | None = None,
                       rounds: int = 100) -> str:
    state_model = state_model or {"start": ["auth", "ping"], "auth": ["query", "quit"], "query": ["query", "quit"]}
    seeds = _to_list(seeds) or ["PING", "AUTH user pass", "QUERY key", "QUIT"]

    generated = []
    current = "start"
    for _ in range(max(1, int(rounds))):
        options = state_model.get(current) or ["quit"]
        nxt = random.choice(options)
        payload = random.choice(seeds)
        if random.random() < 0.25:
            payload += random.choice(["\r\n", "\n", "\x00", " |../../etc/passwd"])
        generated.append({"state": current, "transition": nxt, "payload": payload})
        current = nxt

    return _safe_json({
        "generated_cases": len(generated),
        "sample": generated[:30],
        "note": "Replay sequence against live target and score responses for divergence."
    })


def tool_constraint_fusion(constraints: dict | None = None, mode: str = "z3") -> str:
    constraints = constraints or {}
    crypto = _to_list(constraints.get("crypto"))
    rev = _to_list(constraints.get("reversing"))
    net = _to_list(constraints.get("network"))

    fused = []
    fused.extend(str(x) for x in crypto)
    fused.extend(str(x) for x in rev)
    fused.extend(str(x) for x in net)

    if mode.lower() == "z3":
        lines = ["from z3 import *", "s = Solver()", "# Add fused constraints below"]
        for c in fused:
            lines.append(f"# {c}")
        lines += ["# Example: x = Int('x'); s.add(x > 0)", "print(s.check())", "print(s.model())"]
        return "\n".join(lines)

    return _safe_json({"mode": mode, "constraints": fused})


def tool_symbolic_pipeline(binary_path: str = "", crypto_equations: list[str] | None = None,
                           protocol_states: list[str] | None = None) -> str:
    return _safe_json({
        "binary": binary_path,
        "pipeline": [
            "angr: discover path constraints from success block",
            "normalize crypto equations into SMT form",
            "convert protocol states into boolean transition constraints",
            "merge with tool_constraint_fusion",
            "solve and emit concrete candidate inputs"
        ],
        "crypto_equations": _to_list(crypto_equations),
        "protocol_states": _to_list(protocol_states),
    })


def tool_generate_exploit_script(target: str = "", vuln_type: str = "auto",
                                 host: str = "", port: int = 0) -> str:
    template = f'''#!/usr/bin/env python3
from pwn import *

context.binary = ELF("{target or './chall'}", checksec=False)
context.log_level = "info"

HOST = "{host or '127.0.0.1'}"
PORT = {int(port) if port else 1337}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(context.binary.path)

io = start()
# TODO: leak libc / build ROP / send payload
io.interactive()
'''
    return template


def tool_generate_decoder(format_hint: str = "auto", sample: str = "") -> str:
    return f'''#!/usr/bin/env python3
import base64, binascii, urllib.parse, codecs

s = {sample!r}
# format_hint={format_hint}

candidates = []
for fn in [
    lambda x: base64.b64decode(x + '=' * ((4-len(x)%4)%4)).decode('utf-8','replace'),
    lambda x: bytes.fromhex(''.join(ch for ch in x if ch in '0123456789abcdefABCDEF')).decode('utf-8','replace'),
    lambda x: urllib.parse.unquote(x),
    lambda x: codecs.decode(x, 'rot_13'),
]:
    try:
        candidates.append(fn(s))
    except Exception:
        pass

for i, c in enumerate(candidates, 1):
    print(f"[{i}]", c)
'''


def tool_generate_emulator(isa_name: str = "custom_vm", opcodes: dict | None = None) -> str:
    opcodes = opcodes or {"0x01": "PUSH", "0x02": "ADD", "0xFF": "HALT"}
    return _safe_json({
        "isa": isa_name,
        "skeleton": {
            "state": ["pc", "stack", "regs", "memory"],
            "loop": "fetch -> decode -> execute -> pc++",
            "opcodes": opcodes,
        }
    })


def tool_generate_patch(target: str = "", patch_type: str = "nop", offset: int = 0,
                        size: int = 1, replacement_hex: str = "") -> str:
    if patch_type == "nop":
        replacement_hex = replacement_hex or ("90" * max(1, size))
    return _safe_json({
        "target": target,
        "offset": offset,
        "patch_type": patch_type,
        "replacement_hex": replacement_hex,
        "steps": ["backup binary", "apply bytes", "verify checksum", "re-run challenge"]
    })


def tool_lift_to_ir(code: str = "", ir: str = "vex") -> str:
    normalized = re.sub(r"\s+", " ", code or "").strip()
    return _safe_json({
        "ir": ir,
        "input_size": len(code or ""),
        "lifted": [
            f"block0: {normalized[:120]}",
            "tmp0 = LOAD(mem, rsp)",
            "tmp1 = ADD(tmp0, 0x10)",
            "STORE(mem, rsp, tmp1)",
        ]
    })


def tool_ir_symbolic_exec(ir_text: str = "", goal: str = "") -> str:
    vars_found = sorted(set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", ir_text or "")))[:32]
    return _safe_json({
        "goal": goal,
        "variables": vars_found,
        "constraints": [f"{v} unconstrained" for v in vars_found[:10]],
        "next": "Export constraints to tool_constraint_fusion(mode='z3')."
    })


def tool_ir_diff(ir_a: str = "", ir_b: str = "") -> str:
    a = set((ir_a or "").splitlines())
    b = set((ir_b or "").splitlines())
    return _safe_json({
        "added": sorted(b - a)[:100],
        "removed": sorted(a - b)[:100],
        "unchanged_count": len(a & b),
    })


def tool_protocol_reverse(messages: list[str] | None = None) -> str:
    return tool_protocol_learn(messages=messages or [], transport="auto")


def tool_message_fuzzer(message: str = "", format_type: str = "auto", rounds: int = 50) -> str:
    base = message or '{"op":"ping","id":1}'
    out = []
    for _ in range(max(1, rounds)):
        s = list(base)
        for i in range(len(s)):
            if random.random() < 0.07:
                s[i] = chr(random.randint(32, 126))
        if random.random() < 0.2:
            s.append(random.choice(["\n", "\r", "\x00", "}", "{"]))
        out.append("".join(s))
    return _safe_json({"format": format_type, "cases": out[:100]})


def tool_state_machine_recovery(trace: list[dict] | None = None) -> str:
    trace = _to_list(trace)
    edges = Counter()
    prev = None
    for step in trace:
        state = str(step.get("state", step.get("to", "unknown"))) if isinstance(step, dict) else str(step)
        if prev is not None:
            edges[(prev, state)] += 1
        prev = state
    nodes = sorted({n for e in edges for n in e})
    return _safe_json({
        "nodes": nodes,
        "edges": [{"from": a, "to": b, "count": c} for (a, b), c in edges.items()],
    })


def tool_function_classifier(function_text: str = "", function_name: str = "") -> str:
    text = (function_name + "\n" + function_text).lower()
    labels = []
    if any(k in text for k in ["encrypt", "decrypt", "xor", "aes", "rsa"]):
        labels.append("crypto")
    if any(k in text for k in ["malloc", "free", "strcpy", "memcpy", "gets"]):
        labels.append("memory_unsafe")
    if any(k in text for k in ["socket", "send", "recv", "http", "request"]):
        labels.append("network")
    if any(k in text for k in ["auth", "token", "password", "login"]):
        labels.append("auth")
    return _safe_json({"labels": labels or ["generic"], "name": function_name})


def tool_crypto_detector(code: str = "") -> str:
    hits = []
    patterns = {
        "aes": r"\baes\b|gcm|cbc|ctr|sbox",
        "rsa": r"\brsa\b|modulus|exponent|crt|pkcs",
        "ecc": r"elliptic|ecdsa|ecdh|curve25519|secp",
        "hash": r"sha1|sha256|sha512|md5|blake|hmac",
    }
    low = (code or "").lower()
    for name, pat in patterns.items():
        if re.search(pat, low):
            hits.append(name)
    return _safe_json({"detected": hits})


def tool_obfuscation_classifier(code: str = "") -> str:
    low = (code or "").lower()
    scores = {
        "string_array_obfuscation": sum(x in low for x in ["_0x", "fromcharcode", "atob("]),
        "control_flow_flattening": sum(x in low for x in ["switch", "while(true)", "dispatcher"]),
        "packing": sum(x in low for x in ["eval(function(p,a,c,k,e,d)", "upx", "themida"]),
    }
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    return _safe_json({"scores": ranked, "likely": ranked[0][0] if ranked else "none"})


def tool_fault_injection_sim(model: str = "bitflip", trials: int = 1000,
                             bit_error_rate: float = 0.01) -> str:
    faults = 0
    for _ in range(max(1, int(trials))):
        if random.random() < bit_error_rate:
            faults += 1
    return _safe_json({"model": model, "trials": trials, "faults": faults, "rate": faults / max(1, trials)})


def tool_timing_attack_sim(secret: str = "deadbeef", samples_per_guess: int = 8,
                           noise_sigma: float = 0.005) -> str:
    charset = "0123456789abcdef"
    recovered = ""
    for i in range(len(secret)):
        best = None
        for ch in charset:
            baseline = 0.01 + (0.003 * (ch == secret[i]))
            vals = [random.gauss(baseline, noise_sigma) for _ in range(max(1, samples_per_guess))]
            m = sum(vals) / len(vals)
            if best is None or m > best[0]:
                best = (m, ch)
        recovered += best[1]
    return _safe_json({"secret_len": len(secret), "recovered": recovered, "match": recovered == secret})


def tool_power_trace_analyzer(traces: list[list[float]] | None = None,
                              labels: list[int] | None = None) -> str:
    traces = _to_list(traces)
    labels = _to_list(labels)
    if not traces:
        return "Provide power traces."

    means = [statistics.mean(t) if t else 0.0 for t in traces]
    out = {"trace_count": len(traces), "global_mean": statistics.mean(means), "global_std": statistics.pstdev(means)}
    if labels and len(labels) == len(traces):
        by_label = defaultdict(list)
        for m, lb in zip(means, labels):
            by_label[int(lb)].append(m)
        out["label_means"] = {str(k): statistics.mean(v) for k, v in by_label.items()}
    return _safe_json(out)


def tool_pattern_mine_writeups(texts: list[str] | None = None, min_support: int = 2) -> str:
    texts = [str(t) for t in _to_list(texts) if str(t)]
    if not texts:
        return "Provide writeup texts."

    techniques = [
        "ret2libc", "rop", "sqli", "xss", "ssti", "ssrf", "padding oracle", "mt19937",
        "vigenere", "steg", "format string", "uaf", "heap", "angr", "z3"
    ]
    counts = Counter()
    for t in texts:
        low = t.lower()
        for tech in techniques:
            if tech in low:
                counts[tech] += 1
    return _safe_json({
        "patterns": [{"technique": k, "support": v} for k, v in counts.items() if v >= min_support],
        "total_docs": len(texts),
    })


def tool_attack_graph_builder(assets: list[str] | None = None, vulnerabilities: list[dict] | None = None,
                              capabilities: list[str] | None = None) -> str:
    assets = _to_list(assets)
    vulnerabilities = _to_list(vulnerabilities)
    capabilities = _to_list(capabilities)

    nodes = []
    edges = []
    for a in assets:
        nodes.append({"id": f"asset:{a}", "type": "asset"})
    for c in capabilities:
        nodes.append({"id": f"cap:{c}", "type": "capability"})
    for v in vulnerabilities:
        name = str(v.get("name", "vuln")) if isinstance(v, dict) else str(v)
        target = str(v.get("target", "unknown")) if isinstance(v, dict) else "unknown"
        nid = f"vuln:{name}"
        nodes.append({"id": nid, "type": "vulnerability", "target": target})
        edges.append({"from": nid, "to": f"asset:{target}", "label": "exploit"})

    return _safe_json({"nodes": nodes, "edges": edges})


def tool_chain_builder(steps: list[str] | None = None) -> str:
    steps = _to_list(steps)
    if not steps:
        return "Provide exploit steps."
    chain = []
    for i, s in enumerate(steps, 1):
        chain.append({"order": i, "step": s, "requires": chain[-1]["step"] if chain else "initial access"})
    return _safe_json({"chain": chain})


def tool_attack_path_finder(graph: dict | None = None, start: str = "", goal: str = "") -> str:
    graph = graph or {}
    nodes = {n.get("id") for n in _to_list(graph.get("nodes")) if isinstance(n, dict)}
    edges = _to_list(graph.get("edges"))
    adj = defaultdict(list)
    for e in edges:
        if isinstance(e, dict):
            adj[e.get("from")].append(e.get("to"))

    if start not in nodes or goal not in nodes:
        return _safe_json({"error": "start/goal not found", "start": start, "goal": goal})

    q = deque([(start, [start])])
    seen = {start}
    while q:
        cur, path = q.popleft()
        if cur == goal:
            return _safe_json({"path": path, "length": len(path)})
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return _safe_json({"path": [], "reason": "unreachable"})


def tool_ctf_heuristics(description: str = "", files: list[str] | None = None,
                        hint: str = "") -> str:
    text = " ".join([description, hint] + [str(f) for f in _to_list(files)]).lower()
    guesses = []
    if any(x in text for x in ["png", "jpg", "image", "pixel"]):
        guesses.append("steg + decompression")
    if any(x in text for x in ["socket", "ws", "tcp", "protocol"]):
        guesses.append("protocol reverse + stateful fuzz")
    if any(x in text for x in ["rsa", "cipher", "modulus", "nonce"]):
        guesses.append("crypto equations + constraint fusion")
    if any(x in text for x in ["binary", "elf", "checksec", "segfault"]):
        guesses.append("pwn pipeline + symbolic")
    return _safe_json({"heuristics": guesses or ["generic recon"], "input_tokens": _tokenize(text)[:40]})


def tool_category_strategy(category: str = "unknown", time_budget_min: int = 60) -> str:
    c = (category or "unknown").lower()
    phases = [
        {"window": "0-10m", "goal": "recon + classification"},
        {"window": "10-30m", "goal": "broad exploit attempts"},
    ]
    if time_budget_min >= 45:
        phases.append({"window": "30-60m", "goal": "heavy symbolic/fuzzing"})
    if time_budget_min >= 60:
        phases.append({"window": "60m+", "goal": "writeup mining + branch search"})

    focus = {
        "pwn": ["afl_fuzz", "angr_solve", "rop_chain"],
        "crypto": ["rsa_toolkit", "dlog", "constraint_fusion"],
        "web": ["web_crawl", "sqlmap", "template_inject"],
        "rev": ["ghidra_decompile", "lift_to_ir", "symbolic_pipeline"],
    }.get(c, ["pre_solve_recon", "rank_hypotheses"])

    return _safe_json({"category": category, "time_budget_min": time_budget_min, "phases": phases, "focus_tools": focus})


def tool_strategy_optimizer(elapsed_min: float = 0.0, iterations: int = 0,
                            success_rate: float = 0.0, failures: int = 0) -> str:
    mode = "balanced"
    if elapsed_min < 10:
        mode = "recon"
    elif success_rate < 0.1 and failures > 5:
        mode = "symbolic-heavy"
    elif success_rate > 0.4:
        mode = "exploit-polish"
    elif elapsed_min > 45:
        mode = "writeup+search"

    return _safe_json({
        "mode": mode,
        "recommendations": [
            "increase branch diversity" if mode in ("symbolic-heavy", "writeup+search") else "continue current plan",
            "cache successful constraints",
            "promote top candidates to auto exploit loop",
        ]
    })


def tool_branch_knowledge_share(branch_results: list[dict] | None = None) -> str:
    branch_results = _to_list(branch_results)
    facts = []
    for br in branch_results:
        if isinstance(br, dict):
            for k in ["leak", "offset", "key", "endpoint", "primitive"]:
                if k in br:
                    facts.append({"fact": k, "value": br[k]})
    return _safe_json({"shared_facts": facts})


def tool_solution_merger(candidates: list[dict] | None = None, key: str = "score") -> str:
    candidates = [c for c in _to_list(candidates) if isinstance(c, dict)]
    if not candidates:
        return "No candidates to merge."
    best = max(candidates, key=lambda c: float(c.get(key, 0.0)))
    merged = {
        "best": best,
        "all_count": len(candidates),
        "union_signals": sorted({k for c in candidates for k in c.keys()})
    }
    return _safe_json(merged)


def tool_ctf_pattern_classifier(text: str = "", source: str = "") -> str:
    corpus = (text + " " + source).lower()
    patterns = []
    checks = {
        "lcg_rng": ["lcg", "a*x+b", "mod", "rand"],
        "padding_oracle": ["padding", "oracle", "cbc", "pkcs"],
        "ret2dlresolve": ["plt", "got", "dlresolve", "reloc"],
        "format_string": ["%n", "%p", "printf"],
    }
    for name, keys in checks.items():
        if sum(k in corpus for k in keys) >= 2:
            patterns.append(name)
    return _safe_json({"patterns": patterns})


def tool_exploit_simulation(exploit_code: str = "", target: str = "", timeout_s: int = 15) -> str:
    # Safe-by-default static simulation; does not execute network payloads here.
    warnings = []
    low = (exploit_code or "").lower()
    if "remote(" in low:
        warnings.append("remote connection present")
    if "shell" in low or "system(" in low:
        warnings.append("shell execution primitives present")
    if not exploit_code.strip():
        return "Provide exploit code to simulate."
    return _safe_json({
        "target": target,
        "timeout_s": timeout_s,
        "static_checks": {
            "length": len(exploit_code),
            "warnings": warnings,
            "has_pwntools": "from pwn import" in exploit_code,
            "has_payload": "payload" in low,
        },
        "result": "static-pass"
    })


def tool_exploit_safety_check(exploit_code: str = "") -> str:
    dangerous = []
    checks = {
        "destructive_shell": ["rm -rf", "mkfs", "dd if=", "shutdown"],
        "credential_exfil": ["/etc/shadow", "aws_access_key", "private_key"],
        "network_spread": ["for ip in", "masscan", "nmap -p-"],
    }
    low = (exploit_code or "").lower()
    for category, keys in checks.items():
        if any(k in low for k in keys):
            dangerous.append(category)
    return _safe_json({"danger": dangerous, "safe": not dangerous})


def tool_paper_search(query: str = "", top_k: int = 5) -> str:
    # Offline-friendly search stub: returns curated seed topics from query tokens.
    toks = _tokenize(query)
    seeds = []
    if any(t in toks for t in ["lattice", "lll", "hnp", "ecdsa"]):
        seeds.append("Howgrave-Graham and lattice attacks on weak signatures")
    if any(t in toks for t in ["side", "timing", "power"]):
        seeds.append("Kocher timing attacks and differential power analysis")
    if any(t in toks for t in ["protocol", "state", "fuzz"]):
        seeds.append("State machine inference with active automata learning")
    if any(t in toks for t in ["symbolic", "angr", "smt"]):
        seeds.append("Hybrid fuzzing + symbolic execution research")
    return _safe_json({"query": query, "suggested_papers": seeds[:top_k]})


def tool_attack_research(query: str = "", context: str = "") -> str:
    papers = json.loads(tool_paper_search(query or context, top_k=6))
    hypotheses = []
    for p in papers.get("suggested_papers", []):
        hypotheses.append(f"Apply technique from: {p}")
    return _safe_json({"query": query, "context_size": len(context or ""), "hypotheses": hypotheses})


def tool_protocol_auto_decode(packets: list[str] | None = None) -> str:
    packets = [str(p) for p in _to_list(packets)]
    out = []
    for p in packets[:100]:
        s = p.strip()
        if s.startswith("GET ") or s.startswith("POST "):
            out.append({"kind": "http", "value": s[:120]})
        elif s.startswith("{") and s.endswith("}"):
            out.append({"kind": "json", "value": s[:120]})
        elif re.fullmatch(r"[0-9a-fA-F]+", s):
            out.append({"kind": "hex", "value": s[:120]})
        elif re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            out.append({"kind": "base64_like", "value": s[:120]})
        else:
            out.append({"kind": "raw", "value": s[:120]})
    return _safe_json({"decoded": out})


def tool_dns_exfil_detect(domains: list[str] | None = None) -> str:
    domains = [str(d).strip() for d in _to_list(domains) if str(d).strip()]
    suspicious = []
    for d in domains:
        label = d.split(".")[0] if "." in d else d
        entropy = 0.0
        if label:
            freq = Counter(label)
            n = len(label)
            entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
        if len(label) > 24 or entropy > 3.5:
            suspicious.append({"domain": d, "label_entropy": round(entropy, 3), "reason": "possible data chunk"})
    return _safe_json({"checked": len(domains), "suspicious": suspicious})


def tool_covert_channel_detect(timings: list[float] | None = None,
                               sizes: list[int] | None = None) -> str:
    timings = [float(x) for x in _to_list(timings)]
    sizes = [int(x) for x in _to_list(sizes)]
    result = {}
    if timings:
        mean_t = statistics.mean(timings)
        std_t = statistics.pstdev(timings) if len(timings) > 1 else 0.0
        result["timing_cv"] = (std_t / mean_t) if mean_t else 0.0
    if sizes:
        mean_s = statistics.mean(sizes)
        std_s = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
        result["size_cv"] = (std_s / mean_s) if mean_s else 0.0
    result["covert_signal_likely"] = (result.get("timing_cv", 0) > 0.5) or (result.get("size_cv", 0) > 0.5)
    return _safe_json(result)


def tool_neural_steg_detector(image_path: str = "", metadata: dict | None = None) -> str:
    # Lightweight heuristic stand-in for a neural detector.
    metadata = metadata or {}
    score = 0.0
    score += 0.3 if metadata.get("high_entropy") else 0.0
    score += 0.2 if metadata.get("palette_anomaly") else 0.0
    score += 0.2 if metadata.get("alpha_noise") else 0.0
    score += 0.2 if metadata.get("fft_spikes") else 0.0
    score += 0.1 if metadata.get("size_mismatch") else 0.0
    return _safe_json({"image_path": image_path, "steg_probability": round(min(score, 1.0), 3)})


def tool_image_layer_decompose(image_path: str = "", mode: str = "rgb") -> str:
    code = f'''
from PIL import Image
import statistics
p = {image_path!r}
img = Image.open(p).convert("RGBA")
r,g,b,a = img.split()
stats = {{
    "size": img.size,
    "r_mean": statistics.mean(r.getdata()),
    "g_mean": statistics.mean(g.getdata()),
    "b_mean": statistics.mean(b.getdata()),
    "a_mean": statistics.mean(a.getdata()),
}}
print(stats)
'''
    return code


def tool_frequency_steg(image_path: str = "", method: str = "fft") -> str:
    return _safe_json({
        "image_path": image_path,
        "method": method,
        "next": "Use numpy FFT over each channel; inspect high-frequency energy asymmetry."
    })


def tool_vm_unpacker(binary_path: str = "", operation: str = "detect") -> str:
    low = (binary_path or "").lower()
    hints = []
    if any(x in low for x in ["vmp", "themida", "upx", "packed"]):
        hints.append("possible packed/protected binary")
    if operation == "detect":
        return _safe_json({"binary": binary_path, "hints": hints})
    return _safe_json({"binary": binary_path, "operation": operation, "status": "planned"})


def tool_custom_vm_solver(bytecode: list[int] | None = None, opcode_map: dict | None = None,
                          max_steps: int = 1000) -> str:
    bytecode = [int(x) for x in _to_list(bytecode)]
    opcode_map = opcode_map or {1: "PUSH", 2: "ADD", 3: "SUB", 255: "HALT"}
    stack = []
    pc = 0
    steps = 0
    while pc < len(bytecode) and steps < max_steps:
        op = bytecode[pc]
        name = opcode_map.get(op, "UNK")
        if name == "PUSH" and pc + 1 < len(bytecode):
            stack.append(bytecode[pc + 1])
            pc += 2
            steps += 1
            continue
        if name == "ADD" and len(stack) >= 2:
            b = stack.pop(); a = stack.pop(); stack.append(a + b)
        elif name == "SUB" and len(stack) >= 2:
            b = stack.pop(); a = stack.pop(); stack.append(a - b)
        elif name == "HALT":
            break
        pc += 1
        steps += 1
    return _safe_json({"steps": steps, "pc": pc, "stack": stack[-16:]})


def tool_control_flow_recovery(disassembly: str = "") -> str:
    lines = (disassembly or "").splitlines()
    edges = []
    labels = set()
    for ln in lines:
        m = re.match(r"\s*([A-Za-z0-9_.$]+):", ln)
        if m:
            labels.add(m.group(1))
    for ln in lines:
        jm = re.search(r"\b(jmp|je|jne|jg|jl|ja|jb|call)\s+([A-Za-z0-9_.$]+)", ln)
        if jm:
            edges.append({"op": jm.group(1), "to": jm.group(2)})
    return _safe_json({"labels": sorted(labels), "edges": edges[:500]})


def tool_auto_exploit_loop(target: str = "", vuln_type: str = "auto", host: str = "",
                           port: int = 0, max_rounds: int = 5) -> str:
    rounds = []
    candidate = tool_generate_exploit_script(target=target, vuln_type=vuln_type, host=host, port=port)
    for i in range(1, max(1, int(max_rounds)) + 1):
        sim = json.loads(tool_exploit_simulation(exploit_code=candidate, target=target))
        safety = json.loads(tool_exploit_safety_check(candidate))
        status = "refine"
        if sim.get("result") == "static-pass" and safety.get("safe", False):
            status = "ready-for-live-test"
        rounds.append({"round": i, "status": status, "warnings": sim.get("static_checks", {}).get("warnings", [])})
        if status == "ready-for-live-test":
            break
        candidate += "\n# refinement: add leak parsing and retry logic\n"
    return _safe_json({"target": target, "rounds": rounds, "final_script": candidate[:6000]})
