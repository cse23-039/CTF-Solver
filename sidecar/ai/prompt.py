"""System prompt construction and playbook rendering."""
from __future__ import annotations

import json
import os

from flag.extractor import _extract_name_hints, _normalize_hint_values
from intelligence import ingest as intel_ingest
from intelligence import playbooks as intel_playbooks
from tools.shell import IS_WINDOWS, USE_WSL, log


def _write_text_file(path: str, content: str) -> None:
    target = str(path or "").strip()
    if not target:
        return
    parent = os.path.dirname(os.path.abspath(target))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(str(content or ""))


def _normalize_category_key(category: str) -> str:
    cat = str(category or "").strip().lower()
    if "pwn" in cat or "binary" in cat:
        return "binary exploitation"
    if "crypto" in cat:
        return "cryptography"
    if "web" in cat:
        return "web"
    if "reverse" in cat or "rev" in cat:
        return "reverse engineering"
    if "forensic" in cat:
        return "forensics"
    if "osint" in cat:
        return "osint"
    return cat


def _build_attack_playbook(category: str, difficulty: str, phase: str, multimodal: dict | None = None) -> dict:
    return intel_playbooks.build_attack_playbook(category, difficulty, phase, multimodal)


def _render_playbook_for_prompt(playbook: dict) -> str:
    return intel_playbooks.render_playbook_for_prompt(playbook)


def _build_multimodal_feature_pack(challenge: dict, files_blob: str, extra: dict) -> dict:
    return intel_ingest.build_multimodal_feature_pack(challenge, files_blob, extra)


def _render_multimodal_for_prompt(pack: dict) -> str:
    return intel_ingest.render_multimodal_for_prompt(pack)


def _build_challenge_signal_pack(challenge: dict, extra_config: dict) -> dict:
    name = challenge.get("name", "")
    desc = challenge.get("description", "")

    raw_hint_candidates = [
        challenge.get("hint"),
        challenge.get("hints"),
        challenge.get("challenge_hint"),
        challenge.get("challenge_hints"),
        challenge.get("tips"),
        challenge.get("clues"),
        extra_config.get("hint"),
        extra_config.get("hints"),
    ]

    explicit_hints = []
    for cand in raw_hint_candidates:
        explicit_hints.extend(_normalize_hint_values(cand))

    seen = set()
    deduped_hints = []
    for h in explicit_hints:
        key = h.lower().strip()
        if key and key not in seen:
            seen.add(key)
            deduped_hints.append(h)

    name_hints = _extract_name_hints(name)

    combined_lines = []
    if name_hints:
        combined_lines.append("Name-derived hints:")
        combined_lines.extend([f"- {h}" for h in name_hints])
    if deduped_hints:
        combined_lines.append("Explicit hints:")
        combined_lines.extend([f"- {h}" for h in deduped_hints])

    summary = "\n".join(combined_lines).strip()
    augmented_description = desc
    if summary:
        augmented_description = f"{desc}\n\n[Challenge Signals]\n{summary}"

    return {
        "name": name,
        "description": desc,
        "explicit_hints": deduped_hints,
        "name_hints": name_hints,
        "signal_summary": summary,
        "augmented_description": augmented_description,
    }


_PWN_SECTION = """### Binary Exploitation (pwn)
- Start: checksec -> file_type -> functions -> disassemble main
- Stack path: cyclic offset, canary status, PIE/ASLR bypass plan
- ROP/ret2libc path: leak -> base calc -> controlled chain
- Heap path: identify allocator behavior, then targeted poisoning/dup strategy"""

_CRYPTO_SECTION = """### Cryptography
- Start: identify primitive and mode first (RSA/symmetric/hash/PRNG/ECC)
- RSA path: small-e, Wiener, shared factors/modulus, oracle behavior
- Symmetric path: ECB/CBC/GCM behavior, oracle and malleability checks
- PRNG/ECC path: state recovery, nonce misuse, invalid-curve or subgroup issues"""

_WEB_SECTION = """### Web Exploitation
- Start: source_audit(full_audit), then docker_recon if Docker artifacts exist
- Core attack set: SQLi, SSTI, SSRF, upload bypass, traversal/LFI, deserialization
- JS/source maps: js_analyze(fetch_sourcemap) then endpoint extraction
- Race/timing: concurrent_requests with differential evidence collection"""

_REV_SECTION = """### Reverse Engineering & Custom Architectures
- Start: file_type -> strings -> checksec -> functions -> disassemble main
- WASM path: wasm_analyze(decompile/exports_imports/to_python/analyze_bitops)
- VM/custom CPU path: opcode map -> emulator/disassembler -> trace to flag logic
- Constraint path: convert predicates to z3/angr and solve for accepted input"""

_FORENSICS_SECTION = """### Forensics
- Start: magic bytes + entropy + format-specific metadata parsing
- Media path: EXIF/chunks/spectrogram/steg extraction workflows
- PCAP path: stream reassembly, object extraction, protocol anomaly pivots
- Memory/disk path: volatility/filesystem timeline with carve-and-verify"""

_OSINT_SECTION = """### OSINT
- Identity pivoting: username/alias reuse across platforms
- Image/domain pivoting: reverse image, EXIF, whois, CT logs, historical DNS
- Build verifiable chain-of-custody for each inferred fact"""

_MISC_CHAIN_SECTION = """### Misc / Pyjail / Sandbox
- Python jail: inspect __builtins__, class hierarchy, and object graph escape paths
- Restricted eval: mro/subclasses indirection, encoded payload reconstruction
- Sandbox escape: importlib/os/subprocess pivots when primitives are exposed

### Blockchain / Smart Contracts
- Source-first review: auth gates, privilege flow, reentrancy/order-of-operations
- Check tx.origin misuse, state-update ordering, and invariant violations
- Validate exploitability with execute_python + web3.py style scripting"""


def _build_category_section(category: str, hints: dict) -> str:
    key = _normalize_category_key(category)
    sections = {
        "binary exploitation": _PWN_SECTION,
        "cryptography": _CRYPTO_SECTION,
        "web": _WEB_SECTION,
        "reverse engineering": _REV_SECTION,
        "forensics": _FORENSICS_SECTION,
        "osint": _OSINT_SECTION,
    }
    primary = sections.get(key, "")
    if not primary:
        primary = "\n\n".join([_WEB_SECTION, _REV_SECTION])

    custom_hint = ""
    if isinstance(hints, dict):
        custom_hint = str(hints.get(category, "") or "").strip()
    if custom_hint:
        primary += f"\n- Custom hint: {custom_hint}"

    return primary + "\n\n" + _MISC_CHAIN_SECTION


def build_system_prompt(platform_type, ctf_name, base_dir, extra_config, category: str = "", dead_ends: list[str] | None = None):
    env = ("Windows+WSL2" if IS_WINDOWS and USE_WSL
           else "Windows(no WSL—use Python tools)" if IS_WINDOWS else "Linux/Mac")
    hints = extra_config.get("hints", {})
    extra = extra_config.get("extraInstructions", "")
    depth = extra_config.get("analysisDepth", "thorough")
    plat = f"\nPlatform: {platform_type} — submit_flag when found." if platform_type and platform_type != "manual" else ""
    category_content = _build_category_section(category, hints)

    dead_ends = dead_ends or []
    dead_end_block = ""
    if dead_ends:
        dead_end_block = "\n## ⚠️ DEAD ENDS — DO NOT ATTEMPT\n" + "\n".join([f"- {d}" for d in dead_ends[:8]])

    return f"""You are an elite CTF solver capable of solving insane-difficulty challenges across all categories. You approach challenges with the methodical depth of a top CTF competitor.

## Environment
OS: {env} | CTF: {ctf_name or "?"} | Base dir: {base_dir or "?"}{plat}

## Solving Philosophy
Depth: {depth}. Never guess. Never give up early. If one approach fails, pivot with reasoning.
Use tools aggressively, but only when each call adds measurable evidence.

## Methodology (follow this every time)
1. **knowledge_get** — check cross-challenge CTF context FIRST
2. **detect_flag_format** — identify expected flag shape
3. **create_workspace** — always early
4. **Recon** — understand challenge behavior before exploit chain
5. **Hypothesis** — state vulnerability theory and disconfirming test
6. **Execute/Iterate** — gather evidence, adapt quickly, avoid repeated dead paths
7. **Verify** — confirm chain-of-custody before submission
8. **submit_flag** then **write_file**(WRITEUP.md)

## Category Playbooks
{category_content}

## Side-Channel / Advanced Techniques
- Timing/cache/padding oracles: gather statistically valid measurements before claims
- Differential analysis: compare baseline vs manipulated responses for high-signal pivots
- Constraint-first reduction: model unknowns and prune impossible branches early

## Tool Selection Guide
- Need ROP/gadgets -> binary_analysis + execute_python(pwntools)
- Need symbolic constraints -> z3_solve / sage_math
- Need recon breadth -> pre_solve_recon + rank_hypotheses
- Need performance under uncertainty -> concurrent_requests + statistical_analysis

{dead_end_block}

## Rules
- Never submit unverified flags
- Prefer evidence over intuition
- If stuck after 3 attempts, pivot attack class
- Continue until flag or exhaustive, justified failure
{f"\n## Extra Instructions\n{extra}" if extra else ""}
"""


def generate_writeup(client, model, challenge, flag, solve_summary, workspace, extra_config,
                    evidence_bundle: dict | None = None):
    if not workspace: return
    try:
        log("sys","Generating writeup...","")
        detail = extra_config.get("writeupDetail","normal")
        style  = extra_config.get("writeupStyle","technical")
        wname  = extra_config.get("writeupName","WRITEUP.md")

        evidence_text = ""
        if evidence_bundle:
            evidence_text = f"""

    Evidence bundle (must cite directly):
    - Planner summary:
    {str(evidence_bundle.get('planner_summary',''))[:1600]}

    - Tool evidence samples:
    {json.dumps(evidence_bundle.get('tool_evidence', [])[:20], ensure_ascii=False)[:5000]}

    - Failed attempts:
    {json.dumps(evidence_bundle.get('failed_attempts', [])[:20], ensure_ascii=False)[:3000]}

    - Model routing decisions:
    {json.dumps(evidence_bundle.get('route_history', [])[-12:], ensure_ascii=False)[:3000]}

    - Strategy decisions:
    {json.dumps(evidence_bundle.get('strategy_history', [])[-16:], ensure_ascii=False)[:3500]}

    - Hypothesis trace (active/disproven/validated):
    {json.dumps(evidence_bundle.get('hypothesis_trace', [])[:20], ensure_ascii=False)[:3500]}

    - Tool quality grades:
    {json.dumps(evidence_bundle.get('tool_quality_log', [])[-40:], ensure_ascii=False)[:3500]}

    - Bandit updates:
    {json.dumps(evidence_bundle.get('bandit_updates', [])[-60:], ensure_ascii=False)[:3500]}

    - Difficulty re-estimation events:
    {json.dumps(evidence_bundle.get('difficulty_events', [])[-8:], ensure_ascii=False)[:2000]}

    - Self-play debate context:
    {str(evidence_bundle.get('debate_context', ''))[:1600]}
    """

        prompt = f"""Write a {"comprehensive, detailed" if detail=="detailed" else "concise"} CTF writeup in Markdown.
Style: {style}

Challenge: {challenge.get('name')} | CTF: {challenge.get('ctf_name','')}
Category: {challenge.get('category')} | Points: {challenge.get('points')} | Difficulty: {challenge.get('difficulty')}
Flag: {flag}

Description:
{challenge.get('description','')}

Solve process:
{solve_summary}
{evidence_text}

Include: challenge overview, vulnerability identification, exploitation steps with exact commands/output snippets, failed attempts and why they failed, validation checks, final flag.
Format as clean Markdown. Be technical and precise."""

        resp = client.messages.create(model=model,max_tokens=3000,
                                      messages=[{"role":"user","content":prompt}])
        writeup = resp.content[0].text if resp.content else ""
        if writeup:
            path = os.path.join(workspace, wname)
            _write_text_file(path, writeup)
            log("ok",f"Writeup: {path}","white")
    except Exception as e: log("warn",f"Writeup failed: {e}","")
