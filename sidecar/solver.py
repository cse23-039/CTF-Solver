#!/usr/bin/env python3
"""
CTF::SOLVER — Autonomous Sidecar (slim entry point)
Full-spectrum solver capable of insane-difficulty challenges across all categories.
Reads JSON payload from stdin, streams events to stdout.

All heavy implementations live in the sub-packages:
  tools/shell.py          — shell execution, emit/log helpers
  tools/transform.py      — encoding/decoding transforms
  tools/crypto_impl.py    — crypto attack implementations
  tools/web_impl.py       — HTTP / web exploitation
  tools/pwn_impl.py       — binary exploitation / pwn
  tools/forensics_impl.py — file & network forensics
  tools/reverse_impl.py   — reverse engineering & decompilation
  tools/mobile_impl.py    — Android / iOS analysis
  tools/steg_impl.py      — steganography & image forensics
  tools/sandbox_impl.py   — language sandboxes & jail escapes
  tools/misc_impl.py      — miscellaneous utilities
  tools/apt_tool.py       — APT multi-stage orchestrator
  tools/definitions.py    — TOOLS JSON schema registry
  flag/extractor.py       — flag extraction & format intelligence
  ai/model.py             — model selection & credit guard
  ai/memory.py            — memory v2 retrieval
  ai/prompt.py            — system prompt construction
  solver/engine.py        — core solve loop
  core/                   — budget, checkpoint, routing, state, verification
  intelligence/           — ingest, playbooks
  memory/                 — store, knowledge_graph
"""

import sys, json

from core import budget as core_budget
from core import checkpoint as core_checkpoint
from core import orchestrator as core_orchestrator
from core import routing as core_routing
from core import verification as core_verification
from core.parsing import PromptBuildBuffer, TokenizationCache
from core.state import BeliefState, SolveState
from core.tool_runtime import ToolRuntime
from intelligence import ingest as intel_ingest
from intelligence import playbooks as intel_playbooks
from memory import store as memory_store
from memory.knowledge_graph import KnowledgeGraphStore
from tools.registry import build_tool_registry, enabled_tools
from tools.definitions import TOOLS, TOOL_MAP

# ── Platform / IO ────────────────────────────────────────────────────────────
from tools.shell import (
    IS_WINDOWS, USE_WSL, _wsl_ok, _w2l,
    emit, log, result, _shell,
    tool_execute_shell, tool_execute_python,
)

# ── Transforms ───────────────────────────────────────────────────────────────
from tools.transform import (
    tool_decode_transform, tool_encoding_bypass, tool_number_bases,
)

# ── Crypto ───────────────────────────────────────────────────────────────────
from tools.crypto_impl import (
    tool_crypto_attack, tool_z3_solve, tool_sage_math, tool_dlog,
    tool_factordb, tool_cbc_oracle, tool_vigenere_crack, tool_side_channel,
    tool_differential_cryptanalysis, tool_ecdsa_lattice, tool_coppersmith,
    tool_aes_gcm_attack, tool_bleichenbacher, tool_pqc_attack, tool_zkp_attack,
    tool_lll, tool_rsa_toolkit, tool_rng_crack, tool_ecc_special_attacks,
    tool_hash_crack,
)

# ── Web ───────────────────────────────────────────────────────────────────────
from tools.web_impl import (
    tool_http_request, tool_concurrent_requests, tool_tcp_connect,
    tool_web_attack, tool_browser_agent, tool_sqlmap, tool_ffuf,
    tool_web_crawl, tool_http_smuggle, tool_graphql, tool_websocket_fuzz,
    tool_oauth_attack, tool_cache_poison, tool_cors_exploit, tool_dom_xss,
    tool_ssrf_chain, tool_ssti_rce, tool_swagger_fuzz, tool_nosql_inject,
    tool_file_upload, tool_template_inject, tool_jwt_forge, tool_xs_leak,
    tool_shodan, tool_2fa_bypass, tool_deserialization_exploit,
)

# ── Pwn ───────────────────────────────────────────────────────────────────────
from tools.pwn_impl import (
    tool_binary_analysis, tool_unicorn_emulate, tool_custom_cpu_emulate,
    tool_libc_lookup, tool_angr_solve, tool_frida_trace,
    tool_heap_analysis, tool_kernel_info, tool_seccomp_analyze,
    tool_ret2dlresolve, tool_srop, tool_afl_fuzz, tool_patchelf,
    tool_triton_taint, tool_aeg_pipeline, tool_arm_rop, tool_asm_eval,
    tool_binary_patch, tool_cpp_vtable, tool_ebpf_exploit,
    tool_format_string_exploit, tool_fsop, tool_gdb_remote,
    tool_house_of_exploit, tool_kernel_lpe, tool_rop_chain, tool_vm_devirt,
    tool_deobfuscate, tool_one_gadget, tool_pwn_template,
    tool_heap_visualize, tool_libc_database,
)

# ── Forensics ─────────────────────────────────────────────────────────────────
from tools.forensics_impl import (
    tool_analyze_file, tool_js_analyze, tool_wasm_analyze, tool_mime_email,
    tool_source_audit, tool_docker_recon, tool_volatility, tool_tls_decrypt,
    tool_audio_steg, tool_git_forensics, tool_cloud_forensics,
    tool_disk_forensics, tool_dotnet_decompile, tool_firmware_unpack,
    tool_pcap_deep, tool_pe_analysis, tool_windows_forensics,
    tool_pdf_forensics, tool_pcap_reassemble, tool_string_decryptor,
    tool_bytecode_disasm, tool_bindiff,
)

# ── Reverse ───────────────────────────────────────────────────────────────────
from tools.reverse_impl import (
    tool_ghidra_decompile, tool_ai_rename_functions, tool_go_rev,
    tool_powershell_deobf, tool_swift_decompile, tool_license_check,
    tool_proto_decode,
)

# ── Mobile ────────────────────────────────────────────────────────────────────
from tools.mobile_impl import (
    tool_android_vuln, tool_apk_analyze, tool_apk_resign, tool_flutter_re,
    tool_ios_vuln, tool_ipa_analyze, tool_ssl_pinning_bypass,
)

# ── Steg ──────────────────────────────────────────────────────────────────────
from tools.steg_impl import (
    tool_image_steg_advanced, tool_polyglot_file, tool_qr_decode,
    tool_steg_brute, tool_image_repair, tool_compression,
)

# ── Sandboxes ─────────────────────────────────────────────────────────────────
from tools.sandbox_impl import (
    tool_java_sandbox, tool_rust_sandbox, tool_node_exec,
    tool_pyjail_escape, tool_docker_sandbox,
)

# ── Misc ──────────────────────────────────────────────────────────────────────
from tools.misc_impl import (
    tool_writeup_rag, tool_index_writeups, tool_statistical_analysis,
    tool_create_workspace, tool_write_file, tool_write_binary,
    tool_download_file, tool_submit_flag, tool_encrypted_store,
    tool_challenge_classifier, tool_ethereum_exploit,
    tool_sdr_analyze, tool_solve_resume, tool_ssh_exec,
)

# ── Advanced Intelligence ────────────────────────────────────────────────────
from tools.advanced_intel import (
    tool_ai_fuzzer, tool_grammar_infer, tool_protocol_learn, tool_stateful_fuzz,
    tool_constraint_fusion, tool_symbolic_pipeline,
    tool_generate_exploit_script, tool_generate_decoder, tool_generate_emulator,
    tool_generate_patch, tool_lift_to_ir, tool_ir_symbolic_exec, tool_ir_diff,
    tool_protocol_reverse, tool_message_fuzzer, tool_state_machine_recovery,
    tool_function_classifier, tool_crypto_detector, tool_obfuscation_classifier,
    tool_fault_injection_sim, tool_timing_attack_sim, tool_power_trace_analyzer,
    tool_pattern_mine_writeups, tool_attack_graph_builder,
    tool_chain_builder, tool_attack_path_finder,
    tool_ctf_heuristics, tool_category_strategy, tool_strategy_optimizer,
    tool_branch_knowledge_share, tool_solution_merger,
    tool_ctf_pattern_classifier, tool_exploit_simulation,
    tool_exploit_safety_check, tool_paper_search, tool_attack_research,
    tool_protocol_auto_decode, tool_dns_exfil_detect, tool_covert_channel_detect,
    tool_neural_steg_detector, tool_image_layer_decompose, tool_frequency_steg,
    tool_vm_unpacker, tool_custom_vm_solver, tool_control_flow_recovery,
    tool_auto_exploit_loop,
)

# ── APT orchestrator ──────────────────────────────────────────────────────────
from tools.apt_tool import tool_apt_orchestrator

# ── Flag intelligence ─────────────────────────────────────────────────────────
from flag.extractor import (
    _normalize_ctf_key, _scan_description_for_format,
    tool_detect_flag_format, confirm_flag_format,
    _infer_prefix_from_flag, _normalize_hint_values, tool_flag_extractor,
    _extract_name_hints, _build_challenge_signal_pack, extract_flag,
)

# ── AI helpers ────────────────────────────────────────────────────────────────
from ai.model import (
    _extract_text_for_token_estimation, _estimate_tokens_from_text,
    _estimate_input_tokens, _estimate_call_cost_usd,
    _init_credit_guard, _credit_remaining_usd, _credit_is_low,
    _mark_low_credit_alert_once, _plan_budgeted_call, _record_credit_usage,
    _select_model, _route_model_v2,
)
from ai.memory import (
    _memory_v2_path, _tokenize_simple, _challenge_fingerprint,
    _load_memory_v2, _build_memory_injection, _memory_trust_score,
    _analyze_memory_consistency, _retrieve_memory_v2, _store_memory_v2,
    _store_failure_path, _retrieve_failure_paths,
)
from ai.prompt import (
    _normalize_category_key, _build_attack_playbook, _render_playbook_for_prompt,
    _build_multimodal_feature_pack, _render_multimodal_for_prompt,
    build_system_prompt, generate_writeup,
)

# ── Solver engine ─────────────────────────────────────────────────────────────
from solver.engine import (
    _kgkey, tool_knowledge_store, tool_knowledge_get, _get_knowledge_injection,
    _kg_corpus_path, _kg_upsert_fact, _kg_query_context,
    tool_rank_hypotheses, tool_critic, tool_pre_solve_recon,
    _validator_agent_secondary, _reproducibility_check, _run_self_verification,
    _compute_expected_value_score, _run_exploit_dev_automation,
    run_benchmark, _evidence_log_path, _persist_evidence_record,
    _run_self_healing_preflight, _decide_strategy_mode,
    _validate_candidate_flag, _specialists_for_category, _parse_json_block,
    _default_tool_graph, _run_specialist_agent,
    _build_hypothesis_tree, _prune_hypothesis_tree,
    _resolve_auto_input, _tool_output_success,
    _execute_tool_plan_graph, _run_hierarchical_planner,
    _update_autonomous_phase, _run_branch, run_parallel_branches,
    run_import, _run_solve_impl, run_solve,
)

# ── Globals ───────────────────────────────────────────────────────────────────
_TOKEN_CACHE = TokenizationCache(max_size=384)
_TOOL_RUNTIME = ToolRuntime(timeout_s=45, failure_threshold=3, cooldown_s=50)
_KG_STORE = KnowledgeGraphStore()


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        emit("error", message="No input received")
        sys.exit(1)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        emit("error", message=f"Invalid JSON: {e}")
        sys.exit(1)

    mode = payload.get("mode", "solve")
    if mode == "solve":
        run_solve(payload)
    elif mode == "benchmark":
        run_benchmark(payload)
    elif mode == "import":
        run_import(payload)
    else:
        emit("error", message=f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
