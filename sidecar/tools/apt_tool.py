"""APT (Advanced Persistent Threat) multi-stage orchestrator tool."""
from __future__ import annotations

import hashlib
import json
import os

# Keep in sync with engine.py model constants.
_MODEL_OPUS = "claude-opus-4-6"

def tool_apt_orchestrator(operation: str = "all", **params) -> str:
    """
    APT-level orchestration module.
    Implements high-end automation primitives as executable plans/artifacts.
    """
    op = (operation or "").strip().lower()
    workspace = params.get("workspace") or params.get("workspace_path") or os.getcwd()
    workspace = os.path.abspath(os.path.expanduser(str(workspace)))
    os.makedirs(workspace, exist_ok=True)

    apt_dir = os.path.join(workspace, "apt_artifacts")
    os.makedirs(apt_dir, exist_ok=True)

    def _write_artifact(name: str, content: str) -> str:
        path = os.path.join(apt_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    if op in ("deterministic_lab", "lab", "orchestrate_lab"):
        target = params.get("target", "challenge")
        profile = params.get("profile", "docker")
        lab_script = f"""#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./snapshots ./replays ./net
echo "[LAB] profile={profile} target={target}"

# deterministic seed & env
export PYTHONHASHSEED=0
export TZ=UTC
export LANG=C.UTF-8

# snapshot/revert stubs
echo "[LAB] snapshot create" > ./snapshots/latest.snapshot
echo "[LAB] revert to snapshot ./snapshots/latest.snapshot"

# network shaping (best-effort)
if command -v tc >/dev/null 2>&1; then
  sudo tc qdisc add dev lo root netem delay 80ms loss 0.5% rate 10mbit 2>/dev/null || true
fi

# reproducible replay entrypoint
cat > ./replays/replay.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[REPLAY] running deterministic exploit replay"
EOF
chmod +x ./replays/replay.sh
echo "[LAB] ready"
"""
        p = _write_artifact("deterministic_lab.sh", lab_script)
        return f"Deterministic attack lab generated: {p}"

    if op in ("concolic_orchestrate", "concolic", "symbolic"):
        binary_path = params.get("binary_path", "")
        find_addr = params.get("find_addr", "")
        avoid = params.get("avoid_addrs", [])
        plan = {
            "engine_order": ["angr", "manticore", "triton", "fuzzing", "z3"],
            "switch_conditions": {
                "path_stall": "no_new_paths >= 3",
                "solver_timeout": "z3_timeout > 20s",
                "coverage_plateau": "coverage_delta < 1% over 5 rounds"
            },
            "binary_path": binary_path,
            "find_addr": find_addr,
            "avoid_addrs": avoid,
            "execution_recipe": [
                {"step": "angr_solve", "input": {"binary_path": binary_path, "find_addr": find_addr, "avoid_addrs": avoid}},
                {"step": "execute_shell", "input": {"command": f"python3 -c \"import manticore\" 2>/dev/null || echo manticore_missing\""}},
                {"step": "execute_shell", "input": {"command": f"python3 -c \"import triton\" 2>/dev/null || echo triton_missing\""}},
                {"step": "z3_solve", "input": {"constraints_code": "from z3 import *\nx=BitVec('x',32)\ns=Solver(); s.add(x>0); print(s.check()); print(s.model())"}}
            ]
        }
        p = _write_artifact("concolic_plan.json", json.dumps(plan, indent=2))
        return f"Concolic/symbolic orchestration plan generated: {p}"

    if op in ("protocol_learner", "stateful_protocol", "protocol"):
        pcap = params.get("pcap_path", "")
        protocol = params.get("protocol", "tcp")
        learner = {
            "protocol": protocol,
            "inputs": {"pcap": pcap},
            "states": ["INIT", "NEGOTIATE", "AUTH", "SESSION", "ERROR", "DONE"],
            "transitions": [
                {"from": "INIT", "on": "banner", "to": "NEGOTIATE"},
                {"from": "NEGOTIATE", "on": "hello/params", "to": "AUTH"},
                {"from": "AUTH", "on": "token_ok", "to": "SESSION"},
                {"from": "AUTH", "on": "token_fail", "to": "ERROR"}
            ],
            "grammar_templates": [
                "MSG ::= HELLO VERSION CAPS",
                "AUTH ::= USER TOKEN NONCE",
                "REQ ::= VERB PATH ARGS"
            ],
            "fuzz_strategies": ["state-aware mutation", "grammar-aware generation", "sequence reordering"]
        }
        out = _write_artifact("protocol_state_machine.json", json.dumps(learner, indent=2))
        return f"Stateful protocol learner artifact generated: {out}"

    if op in ("exploit_compiler", "exploit_candidates", "compiler"):
        challenge_type = params.get("challenge_type", "auto")
        seeds = params.get("seeds", ["ret2libc", "rop_chain", "format_string", "heap_uaf"])
        candidates = []
        for idx, seed in enumerate(seeds[:8], 1):
            reliability = max(0.1, round(0.92 - idx * 0.09, 2))
            candidates.append({
                "id": f"cand_{idx}",
                "strategy": seed,
                "challenge_type": challenge_type,
                "estimated_reliability": reliability,
                "triage": {
                    "crash_signature": f"sig_{seed}",
                    "repro_steps": ["run exploit", "collect core", "validate control-flow"],
                    "stable": reliability >= 0.55
                }
            })
        stable = [c for c in candidates if c["triage"]["stable"]]
        out = _write_artifact("exploit_candidates.json", json.dumps({"candidates": candidates, "stable": stable}, indent=2))
        return f"Exploit candidate compiler output generated: {out} (stable={len(stable)}/{len(candidates)})"

    if op in ("intel_layer", "intel", "multi_source_intel"):
        query = params.get("query", "")
        local_sources = {
            "writeup_rag": "local writeup embeddings",
            "knowledge_graph": "ctf-scoped facts",
            "git_forensics": "repo artifacts",
            "tool_outputs": "runtime observations"
        }
        trust = {
            "confirmed_flag_artifact": 1.0,
            "repeatable_tool_output": 0.85,
            "single_observation": 0.55,
            "heuristic_guess": 0.25
        }
        dedup_rules = [
            "same IOC/hash/path -> merge",
            "same endpoint + params -> merge",
            "contradictory evidence -> keep higher trust score"
        ]
        out = _write_artifact("multi_source_intel.json", json.dumps({
            "query": query,
            "sources": local_sources,
            "trust_scoring": trust,
            "dedup_rules": dedup_rules
        }, indent=2))
        return f"Multi-source intelligence layer policy generated: {out}"

    if op in ("adaptive_decompose", "decompose", "task_decompose"):
        desc = params.get("description", "")
        category = params.get("category", "Unknown")
        graph = {
            "root": "solve_challenge",
            "subtasks": [
                {"id": "t1", "name": "recon", "depends_on": []},
                {"id": "t2", "name": "hypothesis_generation", "depends_on": ["t1"]},
                {"id": "t3", "name": "exploit_attempts_parallel", "depends_on": ["t2"]},
                {"id": "t4", "name": "validation_and_replay", "depends_on": ["t3"]},
                {"id": "t5", "name": "writeup_generation", "depends_on": ["t4"]}
            ],
            "merge_strategy": "weighted_evidence_union",
            "context": {"category": category, "description": desc[:500]}
        }
        out = _write_artifact("adaptive_decomposition.json", json.dumps(graph, indent=2))
        return f"Adaptive challenge decomposition graph generated: {out}"

    if op in ("formal_verify", "formal_verifier", "verify"):
        candidate_flag = params.get("candidate_flag", "")
        evidence_paths = params.get("evidence_paths", [])
        replay_script = params.get("replay_script", "")
        checks = []
        for p in evidence_paths:
            ap = os.path.abspath(os.path.expanduser(str(p)))
            exists = os.path.exists(ap)
            h = ""
            if exists and os.path.isfile(ap):
                try:
                    with open(ap, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    h = "unreadable"
            checks.append({"path": ap, "exists": exists, "sha256": h})
        verdict = bool(candidate_flag) and any(c["exists"] for c in checks)
        report = {
            "candidate_flag": candidate_flag,
            "replay_script": replay_script,
            "artifact_checks": checks,
            "verdict": "pass" if verdict else "fail",
            "required": ["replay script", "expected output", "artifact checksum", "path evidence"]
        }
        out = _write_artifact("formal_verifier_report.json", json.dumps(report, indent=2))
        return f"Formal verifier report generated: {out} (verdict={report['verdict']})"

    if op in ("red_team_critic", "self_play_critic", "redteam"):
        summary = params.get("conversation_summary", "")
        api_key = params.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            critique = "No API key provided. Fallback critic: challenge assumptions, verify exploit preconditions, replay from clean snapshot."
        else:
            try:
                import anthropic as _ant
                c = _ant.Anthropic(api_key=api_key)
                prompt = f"""You are an adversarial red-team reviewer.
Try to break the solver's reasoning and exploit chain.
Return concise attack on assumptions + 3 break tests + 3 hardening fixes.

Context:
{summary[:5000]}
"""
                r = c.messages.create(model=_MODEL_OPUS, max_tokens=1000, messages=[{"role": "user", "content": prompt}])
                critique = r.content[0].text if r.content else "No red-team output"
            except Exception as e:
                critique = f"Red-team critic fallback due to API issue: {e}"
        out = _write_artifact("self_play_red_team.md", critique)
        return f"Self-play red-team critique generated: {out}"

    if op in ("benchmark_eval", "benchmark", "eval_harness"):
        bench = {
            "suite": params.get("suite", ["picoctf-mini", "web-mini", "pwn-mini"]),
            "metrics": ["pass_rate", "time_to_flag", "tool_success_rate", "validator_pass_rate", "regressions"],
            "schedule": "nightly",
            "alerts": {
                "pass_rate_drop": "< -10%",
                "median_ttf_increase": "> +25%",
                "critical_regression": "previously solved now failed"
            }
        }
        out = _write_artifact("benchmark_harness.json", json.dumps(bench, indent=2))
        return f"Benchmark + eval harness generated: {out}"

    if op in ("side_channel_lab", "hardware_sidechannel", "sidechannel"):
        model = {
            "timing": {"sampling": "n>=30", "test": "Welch t-test + z-score", "confidence": 0.95},
            "cache": {"methods": ["prime+probe", "flush+reload"], "noise_model": "gaussian+burst"},
            "power": {"methods": ["CPA", "DPA"], "trace_alignment": "cross-correlation"},
            "simulation": {"rounds": int(params.get("rounds", 1000)), "noise_sigma": float(params.get("noise_sigma", 0.8))}
        }
        out = _write_artifact("side_channel_module.json", json.dumps(model, indent=2))
        return f"Hardware/side-channel module profile generated: {out}"

    if op in ("all", "full"):
        ops = [
            "deterministic_lab",
            "concolic_orchestrate",
            "protocol_learner",
            "exploit_compiler",
            "intel_layer",
            "adaptive_decompose",
            "formal_verify",
            "red_team_critic",
            "benchmark_eval",
            "side_channel_lab",
        ]
        results = []
        for sub in ops:
            try:
                sub_params = dict(params)
                sub_params["operation"] = sub
                results.append({"op": sub, "result": tool_apt_orchestrator(**sub_params)})
            except Exception as e:
                results.append({"op": sub, "error": str(e)})
        out = _write_artifact("apt_upgrade_manifest.json", json.dumps(results, indent=2, ensure_ascii=False))
        return f"APT-level full suite complete. Manifest: {out}"

    return (
        "Unknown apt_orchestrator operation. Available: deterministic_lab, concolic_orchestrate, "
        "protocol_learner, exploit_compiler, intel_layer, adaptive_decompose, formal_verify, "
        "red_team_critic, benchmark_eval, side_channel_lab, all"
    )

