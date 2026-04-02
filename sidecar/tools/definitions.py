"""TOOLS list and TOOL_MAP — JSON schemas for the AI tool loop."""
from __future__ import annotations
import json
import os
from collections import defaultdict

from tools.shell import *
from tools.transform import *
from tools.crypto_impl import *
from tools.web_impl import *
from tools.pwn_impl import *
from tools.forensics_impl import *
from tools.reverse_impl import *
from tools.mobile_impl import *
from tools.steg_impl import *
from tools.sandbox_impl import *
from tools.misc_impl import *
from tools.apt_tool import tool_apt_orchestrator

# ─── Tool registry ────────────────────────────────────────────────────────────
TOOLS = [
    {"name":"execute_shell",
     "description":"Execute shell commands. On Windows+WSL2 auto-routes through Linux. Use for: any CLI tool (binwalk, strings, gdb, pwndbg, radare2, tshark, john, hashcat, nc, curl, openssl, objdump, ROPgadget, steghide, zsteg, exiftool, volatility, etc). All standard CTF tools available.",
     "input_schema":{"type":"object","properties":{
         "command":{"type":"string","description":"Shell command (bash syntax)"},
         "timeout":{"type":"integer","description":"Timeout seconds (default 60, use 300+ for hashcat/john)"},
         "working_dir":{"type":"string","description":"Working directory path"}
     },"required":["command"]}},

    {"name":"execute_python",
     "description":"Execute Python 3 code. Use for: pwntools exploit scripting, RSA/crypto math, z3 solving, sympy, angr symbolic execution, custom decoders, PIL image analysis, scapy networking, any complex logic. print() for output. All installed packages available.",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"Python 3 code"},
         "timeout":{"type":"integer"}
     },"required":["code"]}},

    {"name":"decode_transform",
     "description":"Comprehensive encoding/decoding and classical ciphers: base64/32/58, hex, rot_n (all shifts), URL/HTML, binary, XOR (single/multi-byte), Caesar bruteforce (all 25), Atbash, Vigenere (encode/decode), Morse, frequency_analysis, detect_encoding, int_to_bytes, bytes_to_int, xor_hex.",
     "input_schema":{"type":"object","properties":{
         "text":{"type":"string"},
         "method":{"type":"string","enum":["base64_decode","base64_encode","base64url_decode","hex_decode","hex_encode","rot13","rot_n","url_decode","url_encode","html_decode","binary_to_text","text_to_binary","xor","xor_hex","caesar","caesar_bruteforce","atbash","vigenere_decode","vigenere_encode","morse_decode","base32_decode","base58_decode","int_to_bytes","bytes_to_int","frequency_analysis","detect_encoding"]},
         "key":{"type":"string","description":"Key for XOR/Vigenere/Caesar shift"},
         "key2":{"type":"string"}
     },"required":["text","method"]}},

    {"name":"crypto_attack",
     "description":"Dedicated cryptographic attacks: rsa_small_e (eth root/Hastad), rsa_wiener (small private exponent), rsa_factor_known_phi, rsa_common_modulus (same n different e), rsa_lsb_oracle, cbc_padding_oracle (skeleton), hash_length_extension, aes_ecb_byte_at_a_time, mt19937_crack (Mersenne Twister), ecdsa_nonce_reuse (same k), xor_key_length (IC analysis).",
     "input_schema":{"type":"object","properties":{
         "attack":{"type":"string"},
         "n":{"type":"string"},"e":{"type":"string"},"d":{"type":"string"},
         "c":{"type":"string"},"p":{"type":"string"},"q":{"type":"string"},
         "phi":{"type":"string"},"e1":{"type":"string"},"e2":{"type":"string"},
         "c1":{"type":"string"},"c2":{"type":"string"},
         "r":{"type":"string"},"s1":{"type":"string"},"s2":{"type":"string"},
         "m1":{"type":"string"},"m2":{"type":"string"},
         "algo":{"type":"string"},"secret_len":{"type":"integer"},
         "known_hash":{"type":"string"},"known_msg":{"type":"string"},"append_msg":{"type":"string"},
         "ciphertext":{"type":"string"}
     },"required":["attack"]}},

    {"name":"http_request",
     "description":"HTTP/HTTPS requests with full control: cookies, headers, JSON body, follow redirects. Use for web challenges, REST APIs, form submissions.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},
         "method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"]},
         "headers":{"type":"object"},"data":{"type":"string"},
         "json_data":{"type":"object"},"cookies":{"type":"object"},
         "follow_redirects":{"type":"boolean"},"verify_ssl":{"type":"boolean"},
         "timeout":{"type":"integer"}
     },"required":["url"]}},

    {"name":"concurrent_requests",
     "description":"Fire hundreds of HTTP requests in parallel. Essential for: timing attacks, cache side-channels (LRU probing), brute-forcing parameters, fuzzing endpoints simultaneously, checking many markers at once. Returns status code distribution and interesting results.",
     "input_schema":{"type":"object","properties":{
         "requests_list":{"type":"array","description":"List of {url, method, headers, cookies, label} objects"},
         "workers":{"type":"integer","description":"Parallel workers (default 50, max ~500)"},
         "timeout":{"type":"number","description":"Per-request timeout seconds"}
     },"required":["requests_list"]}},

    {"name":"tcp_connect",
     "description":"Raw TCP connection for nc-style challenges. For complex pwn (ROP chains, heap exploitation, format strings), use execute_python with pwntools instead. Supports interactive pwntools scripts.",
     "input_schema":{"type":"object","properties":{
         "host":{"type":"string"},"port":{"type":"integer"},
         "data":{"type":"string","description":"Data to send (text)"},
         "data_hex":{"type":"string","description":"Data to send (hex)"},
         "timeout":{"type":"integer"},
         "interactive_script":{"type":"string","description":"Pwntools Python code body (after remote() is created as io)"}
     },"required":["host","port"]}},

    {"name":"analyze_file",
     "description":"Deep file analysis: file_type, strings, strings_all, hexdump, hexdump_full, metadata (EXIF), entropy (with block analysis), binwalk, binwalk_extract, steg_lsb (PIL LSB extraction), steg_tools (steghide+zsteg+stegseek), pcap_summary, pcap_strings, pcap_http, zip_crack (john), pdf_extract, magic_bytes.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string"}
     },"required":["path","operation"]}},

    {"name":"binary_analysis",
     "description":"ELF/PE binary analysis for pwn and reverse challenges: checksec, disassemble, disassemble_func (specific function), functions (nm/objdump), plt_got, decompile_r2 (radare2), rop_gadgets, rop_find (filter by instruction), libc_version, gdb_run (with script), pwndbg_cyclic (pattern generation), format_string_offsets, heap_analysis.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string"},
         "args":{"type":"string","description":"Function name for disassemble_func, regex for rop_find, GDB script for gdb_run, length for pwndbg_cyclic"}
     },"required":["path","operation"]}},

    {"name":"web_attack",
     "description":"Web attack primitives: sql_injection_test (auto-probe with payloads), xss_test (payload list), path_traversal (auto-probe), jwt_attack (decode+alg:none+secret brute), ssti_test (all engine payloads), ssrf_test (payload list), xxe (XXE payloads), deserialization (ysoserial), prototype_pollution.",
     "input_schema":{"type":"object","properties":{
         "attack":{"type":"string"},
         "target_url":{"type":"string"},
         "param":{"type":"string","description":"Parameter name for injection"},
         "token":{"type":"string","description":"JWT token for jwt_attack"}
     },"required":["attack","target_url"]}},

    {"name":"z3_solve",
     "description":"Z3 SMT constraint solver. Use for: reverse engineering (find inputs that satisfy conditions), binary puzzle solving, cryptographic constraint solving. Write Z3 Python code directly — define variables, add constraints, call check()+model().",
     "input_schema":{"type":"object","properties":{
         "constraints_code":{"type":"string","description":"Z3 Python code using from z3 import *"}
     },"required":["constraints_code"]}},

    {"name":"sage_math",
     "description":"SageMath for advanced mathematics: LLL lattice reduction (SVP/CVP), elliptic curve operations, discrete log, integer factoring (factor(n)), polynomial arithmetic, modular arithmetic. Falls back to Python if Sage unavailable.",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"SageMath/Python code"}
     },"required":["code"]}},

    {"name":"statistical_analysis",
     "description":"Statistical tools for side-channel attacks: log_likelihood_ratio (calibrate true/false positive rates for cache oracle attacks), beam_search (reconstruct secret from scored n-gram evidence — for CSS oracle/LRU attacks), frequency_analysis (letter frequencies for classical ciphers), timing_analysis (mean/std/outliers from timing measurements), index_of_coincidence (detect cipher type).",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["log_likelihood_ratio","beam_search","frequency_analysis","timing_analysis","index_of_coincidence"]},
         "data":{"description":"Operation-specific data"},
         "params":{"type":"object"}
     },"required":["operation","data"]}},

    {"name":"create_workspace",
     "description":"CALL FIRST. Creates base_dir/CTF/Category/Challenge/{files,exploits,artifacts}/. Returns path for all subsequent file operations.",
     "input_schema":{"type":"object","properties":{
         "base_dir":{"type":"string"},"ctf_name":{"type":"string"},
         "category":{"type":"string"},"challenge_name":{"type":"string"}
     },"required":["base_dir","ctf_name","category","challenge_name"]}},

    {"name":"write_file",
     "description":"Write text to disk. Use for: exploit scripts, decoded data, WRITEUP.md (auto-detected and reported), intermediate results, shellcode as Python bytes.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"content":{"type":"string"},
         "mode":{"type":"string","enum":["w","a"]}
     },"required":["path","content"]}},

    {"name":"write_binary",
     "description":"Write binary data from hex string to a file. Use for: patched binaries, shellcode files, crafted binary inputs.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},
         "hex_content":{"type":"string","description":"Hex string (spaces ok)"}
     },"required":["path","hex_content"]}},

    {"name":"download_file",
     "description":"Download a file from URL to local path. For challenge binary/archive downloads.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},"dest_path":{"type":"string"},
         "headers":{"type":"object"},"cookies":{"type":"object"}
     },"required":["url","dest_path"]}},

    {"name":"submit_flag",
     "description":"Submit the flag to the CTF platform for verification. Call once you have the flag, then write WRITEUP.md.",
     "input_schema":{"type":"object","properties":{
         "flag":{"type":"string"},"challenge_id":{"type":"string"}
     },"required":["flag"]}},

    {"name":"health_preflight",
     "description":"Environment health and capability preflight. Checks required commands/python modules by scope so the planner can avoid unavailable tools automatically.",
     "input_schema":{"type":"object","properties":{
         "scope":{"type":"string","enum":["core","web","pwn","mobile","forensics"]}
     },"required":[]}},

    {"name":"detect_flag_format",
     "description":"""CALL THIS FIRST at the start of every solve. Auto-detects the CTF flag format using:
1. Session cache (fastest — if same CTF solved before, uses confirmed format)
2. Description scan (finds 'flag format: PREFIX{...}' or literal examples in the description)
3. Known CTF database (50+ competitions pre-mapped: picoCTF, HTB, DUCTF, corCTF, uiuctf, etc.)
4. Platform type inference
5. Generic fallback pattern

Returns the prefix (e.g. 'picoCTF'), regex pattern, example, confidence level, and source.
Use the returned pattern as your primary flag search target throughout the solve.
If you find a flag with a DIFFERENT prefix than detected, call this tool again with the found prefix
so subsequent challenges in the same CTF benefit from the correction.""",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string","description":"Name of the CTF competition (e.g. 'PicoCTF 2025', 'HTB Cyber Apocalypse 2025')"},
         "description":{"type":"string","description":"Challenge description text — scanned for format hints"},
         "platform_type":{"type":"string","description":"Platform type: picoctf, htb, ctfd, manual"},
         "hint":{"type":"string","description":"Optional known prefix e.g. 'MYCTF{' to force-cache a format"}
     },"required":[]}},

    {"name":"js_analyze",
     "description":"JavaScript analysis. CRITICAL for web challenges with minified JS: fetch_sourcemap (recover full source from .map files — like msfrog-generator where .map exposed all API endpoints), extract_endpoints (find all API routes/fetch calls in JS), beautify (format minified code), find_secrets (API keys, tokens, hardcoded credentials in JS).",
     "input_schema":{"type":"object","properties":{
         "url_or_path":{"type":"string","description":"URL of JS file or local path"},
         "operation":{"type":"string","enum":["fetch_sourcemap","extract_endpoints","beautify","find_secrets"]}
     },"required":["url_or_path","operation"]}},

    {"name":"wasm_analyze",
     "description":"WebAssembly analysis. For challenges with WASM binaries (like Pachinko Revisited — custom CPU synthesized from Verilog into WASM): decompile (wasm2wat), strings, exports_imports, to_python (convert to executable), run (execute with wasmtime), analyze_bitops (find read-only=input ports, write-only=output ports for custom CPU reverse engineering).",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string"},"operation":{"type":"string","enum":["decompile","strings","exports_imports","to_python","run","analyze_bitops"]}
     },"required":["path","operation"]}},

    {"name":"rng_crack",
     "description":"PRNG cracking. mt19937_from_outputs: crack MT19937 from 32-bit outputs (needs randcrack). python_random_from_randbits63: crack Python random.randrange(2**63) from email boundary strings — the EXACT technique from secure-email-service to predict admin's multipart boundary. lcg_crack: recover Linear Congruential Generator params. xorshift_crack: XorShift variants.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["mt19937_from_outputs","python_random_from_randbits63","lcg_crack","xorshift_crack"]},
         "outputs":{"type":"array","description":"List of observed RNG outputs (integers as strings or numbers)"},
         "bits":{"type":"integer"},"modulus":{"type":"integer"},
         "multiplier":{"type":"integer"},"increment":{"type":"integer"}
     },"required":["operation"]}},

    {"name":"mime_email",
     "description":"MIME/email manipulation for email-based web challenges. parse: decode raw email. encode_word: RFC 2047 base64-encode text including newlines for header smuggling (\\n survives through email subjects this way). craft_injection: build full multipart header injection with boundary spoofing. utf7_encode: encode XSS payload in UTF-7 (< becomes +ADw-) to bypass HTML escaping in email clients. extract_boundaries: pull boundary strings from emails for MT19937 cracking. smime_verify: check S/MIME signatures with OpenSSL.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["parse","encode_word","craft_injection","utf7_encode","extract_boundaries","smime_verify"]},
         "raw":{"type":"string"},"raw_email":{"type":"string"},
         "text":{"type":"string"},"charset":{"type":"string"},
         "inject_headers":{"type":"string"},"boundary":{"type":"string"},
         "html":{"type":"string"},"prefix":{"type":"string"},
         "raw_emails":{"type":"array"},"ca_cert":{"type":"string"}
     },"required":["operation"]}},

    {"name":"source_audit",
     "description":"Automated source code security audit. find_sinks: detect dangerous functions (exec, eval, innerHTML, pickle.loads, os.system, render_template_string, sql execute with string concat). find_filters: spot input validation/blacklists to understand what to bypass. find_routes: extract all web endpoints. find_auth: locate auth checks. full_audit: run all. Essential first step when challenge provides source code.",
     "input_schema":{"type":"object","properties":{
         "path_or_content":{"type":"string","description":"File path or raw source code content"},
         "operation":{"type":"string","enum":["find_sinks","find_filters","find_routes","find_auth","full_audit"]},
         "language":{"type":"string","description":"python, js, php, go, rust, c (optional, auto-detected)"}
     },"required":["path_or_content","operation"]}},

    {"name":"encoding_bypass",
     "description":"Generate filter-bypassing encodings of a payload. path_traversal: backslash (\\) instead of slash, URL double-encoding, null bytes (from notepad challenge: backslash bypassed slash filter). underscore: hex \\x5f, HTML entity &#95; (bypasses _ filter). xss_charset: UTF-7 encoding for XSS through HTML-escaping email parsers, base64 data URIs. command: base64-wrapped shell commands, IFS separator. sql: comment-based space bypass. header_inject: space-after-colon bypass for Python email header check, encoded-word RFC2047.",
     "input_schema":{"type":"object","properties":{
         "text":{"type":"string","description":"The payload to encode/transform"},
         "target_bypass":{"type":"string","enum":["path_traversal","underscore","xss_charset","command","sql","header_inject","all"]}
     },"required":["text","target_bypass"]}},

    {"name":"docker_recon",
     "description":"Analyze Docker configuration for attack surface. Extracts: exposed ports, environment variables/secrets, Redis/database config (maxmemory-policy=allkeys-lru reveals LRU side-channel opportunity!), volumes, network config, hardcoded credentials. Always run this when docker-compose.yml or Dockerfile is provided.",
     "input_schema":{"type":"object","properties":{
         "path":{"type":"string","description":"Path to docker-compose.yml, Dockerfile, or directory containing them"}
     },"required":["path"]}},

    {"name":"custom_cpu_emulate",
     "description":"Framework for emulating custom CPU architectures. From Pachinko Revisited: after reversing WASM→Python bitops, use this to write a CPU simulator with BitView helper class (bit-level state array access), clock stepping, port I/O, register dumping. Write your CPU simulation code in the 'code' param; BitView and helpers are auto-injected. Operations: run (execute), check (syntax only).",
     "input_schema":{"type":"object","properties":{
         "code":{"type":"string","description":"Python code implementing the CPU emulator. BitView class is pre-imported."},
         "operation":{"type":"string","enum":["run","check"]},
         "timeout":{"type":"integer","description":"Execution timeout (default 120s for complex emulation)"}
     },"required":["code","operation"]}},

    # ── Elite Intelligence Layer ─────────────────────────────────────────────
    {"name":"knowledge_store",
     "description":"Store a discovered fact in the cross-challenge CTF knowledge graph. Use for: discovered credentials, server tech stack, shared infrastructure, flag patterns, admin paths. These facts auto-inject into subsequent challenge solves in the same CTF.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"},"key":{"type":"string","description":"Fact key e.g. 'admin_password', 'server_tech', 'db_name'"},
         "value":{"type":"string","description":"Fact value"}
     },"required":["ctf_name","key","value"]}},

    {"name":"knowledge_get",
     "description":"Retrieve all known facts about a CTF from the knowledge graph. Call at solve start — previous challenges may have discovered creds, tech stack, infrastructure shared with this challenge.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"}
     },"required":["ctf_name"]}},

    {"name":"browser_agent",
     "description":"Playwright headless browser for JS-heavy web challenges. Handles SPAs, AJAX, login flows, CSRF tokens, DOM manipulation, WebSocket, cookie auth — things raw HTTP requests can't reach. Write Playwright Python in 'script' using page.click(), page.fill(), page.evaluate(), page.wait_for_selector(). Set capture_requests=True to intercept XHR/fetch. Set capture_screenshot=True to save a screenshot.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string"},"script":{"type":"string","description":"Playwright Python code (page, browser, context available)"},
         "timeout":{"type":"integer"},"capture_requests":{"type":"boolean"},"capture_screenshot":{"type":"boolean"}
     },"required":["url","script"]}},

    {"name":"ghidra_decompile",
     "description":"Ghidra headless decompilation — returns semantically rich C pseudocode far superior to objdump/r2 assembly. Essential for hard rev. Falls back to r2 if Ghidra not installed. Set all_functions=True to decompile all functions in a small binary.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"function_name":{"type":"string","description":"Function to decompile (default: main)"},
         "all_functions":{"type":"boolean","description":"Decompile all functions (slow for large binaries)"},
         "project_dir":{"type":"string"}
     },"required":["binary_path"]}},

    {"name":"ai_rename_functions",
     "description":"Use Claude to semantically rename sub_XXXX, var_8, etc. in decompiled code. Returns annotated code with meaningful names and inline comments. Feed it ghidra_decompile output. Dramatically reduces cognitive load on hard rev challenges.",
     "input_schema":{"type":"object","properties":{
         "decompiled_output":{"type":"string","description":"Raw decompiled C pseudocode with generic names"},
         "binary_path":{"type":"string","description":"Optional path for context"}
     },"required":["decompiled_output"]}},

    {"name":"libc_lookup",
     "description":"Look up the exact libc version from a leaked function address via libc.rip. Returns matching libc versions, download links, and key offsets (system, execve, /bin/sh, hooks). Essential after a GOT/PLT leak for ret2libc. Provide the raw hex leaked address.",
     "input_schema":{"type":"object","properties":{
         "leak_address":{"type":"string","description":"Leaked function address as hex e.g. '0x7f4a1b2c3d40'"},
         "symbol":{"type":"string","description":"Which function was leaked (default: puts)"},
         "extra_symbols":{"type":"object","description":"Additional leaked symbol:address pairs for disambiguation"}
     },"required":["leak_address"]}},

    {"name":"factordb",
     "description":"Look up RSA modulus factorization on factordb.com. ALWAYS try this first before any other RSA attack — the community may have already factored it. Returns p, q, and a ready-to-use decrypt snippet if successful.",
     "input_schema":{"type":"object","properties":{
         "n":{"type":"string","description":"RSA modulus as integer string"}
     },"required":["n"]}},

    {"name":"angr_solve",
     "description":"angr symbolic execution for automatic input synthesis in rev/pwn challenges. Finds inputs that reach a target address while avoiding bad addresses. Set find_addr to the address of the 'Correct!'/'You win!' block. Use custom_code for complex setups.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"find_addr":{"type":"string","description":"Hex address of success state e.g. '0x401234'"},
         "avoid_addrs":{"type":"array","items":{"type":"string"},"description":"Hex addresses to avoid"},
         "stdin_len":{"type":"integer","description":"Length of symbolic stdin buffer (default 64)"},
         "custom_code":{"type":"string","description":"Extra angr Python code"},
         "timeout":{"type":"integer"}
     },"required":["binary_path"]}},

    {"name":"sqlmap",
     "description":"SQLMap for automatic SQL injection exploitation. Auto-discovers injectable params, database type, dumps tables and data. level=1-5, risk=1-3. Use data= for POST, cookie= for session auth.",
     "input_schema":{"type":"object","properties":{
         "target_url":{"type":"string"},"param":{"type":"string"},
         "data":{"type":"string"},"cookie":{"type":"string"},
         "level":{"type":"integer"},"risk":{"type":"integer"},
         "dbms":{"type":"string"},"extra_args":{"type":"string"}
     },"required":["target_url"]}},

    {"name":"ffuf",
     "description":"FFUF directory/file/parameter fuzzer. Replaces FUZZ in URL/headers/body. For: hidden endpoints, admin panels, backup files, param discovery. Falls back to gobuster.",
     "input_schema":{"type":"object","properties":{
         "url":{"type":"string","description":"URL with FUZZ placeholder e.g. 'https://ctf.io/FUZZ'"},
         "wordlist":{"type":"string"},"extensions":{"type":"string"},
         "method":{"type":"string"},"headers":{"type":"object"},
         "filter_codes":{"type":"string"},"match_codes":{"type":"string"},"data":{"type":"string"}
     },"required":["url"]}},

    {"name":"web_crawl",
     "description":"Burp-style web spider. Maps all routes, forms, input params, JS API endpoints. Flags interesting patterns (admin, flag, secret, token). Essential first step for black-box web.",
     "input_schema":{"type":"object","properties":{
         "base_url":{"type":"string"},"max_depth":{"type":"integer"},"max_pages":{"type":"integer"},
         "headers":{"type":"object"},"cookies":{"type":"object"},
         "find_patterns":{"type":"array","items":{"type":"string"}}
     },"required":["base_url"]}},

    {"name":"volatility",
     "description":"Volatility 3 memory forensics. Common plugins: windows.pslist, windows.cmdline, windows.filescan, windows.dumpfiles, windows.hashdump, linux.pslist, linux.bash, linux.malfind, mac.bash",
     "input_schema":{"type":"object","properties":{
         "image_path":{"type":"string"},"plugin":{"type":"string"},
         "args":{"type":"string"},"timeout":{"type":"integer"}
     },"required":["image_path","plugin"]}},

    {"name":"frida_trace",
     "description":"Frida dynamic instrumentation. Hooks functions, intercepts args/retvals, bypasses anti-debug/anti-tamper. Provide function_hooks for auto-hooking or write Frida JS in script.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"pid":{"type":"integer"},
         "script":{"type":"string"},"function_hooks":{"type":"array","items":{"type":"string"}},
         "timeout":{"type":"integer"}
     },"required":[]}},

    {"name":"rank_hypotheses",
     "description":"Claude Haiku scores attack hypotheses by evidence strength. Returns top 5 attack vectors ranked by confidence with first-step tool calls. Call after pre_solve_recon.",
     "input_schema":{"type":"object","properties":{
         "challenge_description":{"type":"string"},"category":{"type":"string"},
         "recon_results":{"type":"string"}
     },"required":["challenge_description","category","recon_results"]}},

    {"name":"pre_solve_recon",
     "description":"Run ALL relevant recon in parallel. For pwn: checksec+strings+one_gadget+ROP. For web: headers+robots+tech detect. For forensics: exiftool+binwalk+entropy. For rev: file+nm+objdump. Call immediately after create_workspace.",
     "input_schema":{"type":"object","properties":{
         "binary_path":{"type":"string"},"url":{"type":"string"},"category":{"type":"string"}
     },"required":[]}},

    {"name":"detect_flag_format",
     "description":"Auto-detects the CTF flag format using session cache, description scan, 50+ CTF database, platform inference. Returns prefix, regex, example, confidence. The format is also pre-injected into every solve — use this to update the cache if you find a different prefix.",
     "input_schema":{"type":"object","properties":{
         "ctf_name":{"type":"string"},"description":{"type":"string"},
         "platform_type":{"type":"string"},"hint":{"type":"string"}
     },"required":[]}},

    {"name":"dlog",
     "description":"Discrete logarithm attacks for DH/ECC/DSA. Ops: baby_giant (BSGS, fast for small groups), pohlig_hellman (smooth-order groups), ecc_dlog (elliptic curve via SageMath), index_calculus (large prime fields), auto (tries all). Params: g,h,p (prime field) or Gx,Gy,Px,Py,a,b (ECC). Provide n=group_order and factors=[(q,e)...] for Pohlig-Hellman.",
     "input_schema":{"type":"object","properties":{
         "operation":{"type":"string","enum":["baby_giant","pohlig_hellman","ecc_dlog","index_calculus","auto"]},
         "g":{"type":"integer"},"h":{"type":"integer"},"p":{"type":"integer"},
         "n":{"type":"integer","description":"Group order (default: p-1 for prime fields)"},
         "factors":{"type":"array","description":"[(prime, exponent)...] factors of group order"},
         "Gx":{"type":"integer"},"Gy":{"type":"integer"},
         "Px":{"type":"integer"},"Py":{"type":"integer"},
         "a":{"type":"integer"},"b":{"type":"integer"},
         "order":{"type":"integer","description":"ECC curve order"}
     },"required":["operation"]}},

    {"name":"unicorn_emulate",
     "description":"Unicorn CPU emulator — safely run shellcode/bytecode without executing it. Arches: x86, x86_64, arm, arm64/aarch64, mips. shellcode_hex=hex bytes to load at code_addr. code=extra Unicorn Python API calls (uc available). Logs full register dump and instruction trace after emulation. Perfect for: custom VM bytecode, obfuscated shellcode, architecture challenges.",
     "input_schema":{"type":"object","properties":{
         "arch":{"type":"string","enum":["x86","x86_64","arm","arm64","aarch64","mips"]},
         "shellcode_hex":{"type":"string","description":"Hex string of bytes to emulate"},
         "code_addr":{"type":"integer","description":"Virtual address to load code (default 0x1000)"},
         "code":{"type":"string","description":"Extra Unicorn Python API code (uc object available)"},
         "registers":{"type":"object","description":"Register values to set before emulation"},
         "timeout":{"type":"integer"}
     },"required":[]}},

    {"name":"writeup_rag",
     "description":"Retrieve similar past CTF writeups from local ChromaDB vector store. Returns top-N writeups by semantic similarity to current challenge — Claude reads them for known-good approaches. Requires pre-built DB: call tool_index_writeups first. Empty result = DB not built yet.",
     "input_schema":{"type":"object","properties":{
         "description":{"type":"string","description":"Challenge description to search against"},
         "category":{"type":"string"},"ctf_name":{"type":"string"},
         "db_path":{"type":"string","description":"DB path (default ~/.ctf-solver/writeups.db)"},
         "n_results":{"type":"integer","description":"Number of writeups to return (default 5)"}
     },"required":["description","category"]}},

    {"name":"index_writeups",
     "description":"One-time setup: index a directory of CTF writeups (.md/.txt) into ChromaDB for RAG retrieval. Run once pointing at your writeup collection. After indexing, writeup_rag queries it automatically at solve start.",
     "input_schema":{"type":"object","properties":{
         "writeups_dir":{"type":"string","description":"Directory containing writeup files (searched recursively)"},
         "db_path":{"type":"string","description":"DB path (default ~/.ctf-solver/writeups.db)"}
     },"required":["writeups_dir"]}},

    {"name":"heap_analysis","description":"Heap inspection: bins, chunks, tcache_key, safe_link_decode, arena. Returns live glibc heap state for Claude to plan heap exploits.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["bins","chunks","tcache_key","safe_link_decode","arena"]},"args":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"kernel_info","description":"Kernel recon: mitigations (SMEP/SMAP/KPTI), kallsyms, module_symbols, gadgets, seccomp_dump.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["mitigations","kallsyms","module_symbols","gadgets","seccomp_dump"]},"module_path":{"type":"string"},"args":{"type":"string"}},"required":["operation"]}},
    {"name":"seccomp_analyze","description":"Seccomp BPF filter dump and bypass paths (32-bit ABI, process_vm_writev, openat, etc).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["dump","allowed"]}},"required":["binary_path"]}},
    {"name":"ret2dlresolve","description":"ret2dlresolve structure: resolv_addr, payload bytes, pwntools skeleton.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"target_func":{"type":"string"},"arg":{"type":"string"}},"required":["binary_path"]}},
    {"name":"srop","description":"SROP/sigreturn: frame (SigreturnFrame skeleton), find_syscall, gadgets.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["frame","find_syscall","gadgets"]},"arch":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"afl_fuzz","description":"AFL++ fuzzing for N seconds, returns crash paths for aeg_pipeline or angr_solve.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"input_dir":{"type":"string"},"output_dir":{"type":"string"},"timeout_ms":{"type":"integer"},"run_seconds":{"type":"integer"},"extra_args":{"type":"string"}},"required":["binary_path"]}},
    {"name":"patchelf","description":"Patch binary to use downloaded libc/linker. After libc_lookup, download the libc then call this to match remote environment.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"libc_path":{"type":"string"},"ld_path":{"type":"string"},"operation":{"type":"string","enum":["patch","info","download_libc"]}},"required":["binary_path"]}},
    {"name":"coppersmith","description":"Coppersmith small-root attacks: small_e, partial_p, franklin_reiter, hastad, custom polynomial. All use SageMath small_roots().","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["small_e","partial_p","franklin_reiter","hastad","custom"]},"N":{"type":"integer"},"e":{"type":"integer"},"c":{"type":"integer"},"m_high":{"type":"integer"},"m_bits":{"type":"integer"},"p_high":{"type":"integer"},"p_bits":{"type":"integer"},"c1":{"type":"integer"},"c2":{"type":"integer"},"r":{"type":"integer"},"s":{"type":"integer"},"ciphertexts":{"type":"array"},"moduli":{"type":"array"},"polynomial":{"type":"string"},"X":{"type":"string"},"beta":{"type":"number"}},"required":["operation"]}},
    {"name":"ecdsa_lattice","description":"ECDSA lattice attack (HNP) for biased nonces. Provide signatures [(r,s,h)...], curve order n, leaked bits k.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["hnp","msb_leak","lsb_leak","lll_direct"]},"n":{"type":"integer"},"signatures":{"type":"array"},"k":{"type":"integer"},"leaks":{"type":"array"},"leak_type":{"type":"string"},"matrix_code":{"type":"string"}},"required":["operation"]}},
    {"name":"lll","description":"LLL lattice reduction and CVP/SVP. Claude provides matrix_rows. ops: lll, svp, cvp (needs target list).","input_schema":{"type":"object","properties":{"matrix_rows":{"type":"array"},"operation":{"type":"string","enum":["lll","svp","cvp"]},"target":{"type":"array"}},"required":["matrix_rows"]}},
    {"name":"aes_gcm_attack","description":"AES-GCM nonce_reuse (XOR ciphertexts, tag diff reveals H) and forbidden_attack (H recovery over GF(2^128)).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["nonce_reuse","forbidden_attack","key_recover"]},"c1":{"type":"string"},"c2":{"type":"string"},"t1":{"type":"string"},"t2":{"type":"string"}},"required":["operation"]}},
    {"name":"bleichenbacher","description":"RSA PKCS#1 v1.5 padding oracle: probe (detect via timing), skeleton (attack code with oracle() stub).","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["probe","skeleton"]},"n":{"type":"integer"},"e":{"type":"integer"},"c":{"type":"integer"}},"required":["host"]}},
    {"name":"http_smuggle","description":"HTTP request smuggling: detect (CL.TE/TE.CL timing probe), cl_te/te_cl/te_te (payload structure for tcp_connect).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["detect","cl_te","te_cl","te_te"]}},"required":["target_url","operation"]}},
    {"name":"graphql","description":"GraphQL: introspect (full schema), batch (IDOR bypass), alias (rate limit bypass), find_mutations, custom.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["introspect","batch","alias","find_mutations","field_suggest","custom"]},"query":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","operation"]}},
    {"name":"websocket_fuzz","description":"WebSocket: connect (dump messages), fuzz (send payloads), origin_bypass, inject (custom script with ws object).","input_schema":{"type":"object","properties":{"url":{"type":"string"},"operation":{"type":"string","enum":["connect","fuzz","origin_bypass","inject"]},"messages":{"type":"array"},"script":{"type":"string"},"timeout":{"type":"integer"}},"required":["url","operation"]}},
    {"name":"oauth_attack","description":"OAuth2/SAML: probe (endpoints), open_redirect, pkce_bypass, saml_bypass (XSW, comment injection, alg confusion).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","open_redirect","pkce_bypass","saml_bypass"]},"client_id":{"type":"string"},"redirect_uri":{"type":"string"}},"required":["target_url","operation"]}},
    {"name":"cache_poison","description":"Web cache poisoning: probe (unkeyed headers), poison (inject payload), param_cloaking (fat GET).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","poison","param_cloaking"]},"header":{"type":"string"},"value":{"type":"string"}},"required":["target_url","operation"]}},
    {"name":"shodan","description":"Shodan OSINT: search, host, ssl. Set SHODAN_API_KEY env var.","input_schema":{"type":"object","properties":{"query":{"type":"string"},"operation":{"type":"string","enum":["search","host","ssl"]},"api_key":{"type":"string"}},"required":["query"]}},
    {"name":"tls_decrypt","description":"Decrypt TLS PCAP using NSS keylog or RSA private key. Ops: decrypt, follow_stream, extract_files, check.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"keylog_path":{"type":"string"},"privkey_path":{"type":"string"},"operation":{"type":"string","enum":["decrypt","follow_stream","extract_files","check"]},"filter_str":{"type":"string"}},"required":["pcap_path"]}},
    {"name":"deobfuscate","description":"Binary deobfuscation: detect (OLLVM/CFF), mba_simplify, cff_detect, decompile_miasm.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","mba_simplify","cff_detect","decompile_miasm"]},"expression":{"type":"string"},"func_addr":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"bytecode_disasm","description":"Bytecode disassembly: Python .pyc, Java .class, .NET IL, Lua. auto-detects from magic bytes.","input_schema":{"type":"object","properties":{"input_path":{"type":"string"},"language":{"type":"string","enum":["auto","python","java",".net","lua"]},"operation":{"type":"string"}},"required":["input_path"]}},
    {"name":"audio_steg","description":"Audio steg: analyze, spectrogram (PNG), dtmf (multimon-ng), lsb (WAV sample LSBs), strings.","input_schema":{"type":"object","properties":{"audio_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","spectrogram","dtmf","lsb","strings"]}},"required":["audio_path","operation"]}},
    {"name":"git_forensics","description":"Git forensics: dangling objects, reflog, stash, secrets (grep history), orphan branches. operation=all runs all.","input_schema":{"type":"object","properties":{"repo_path":{"type":"string"},"operation":{"type":"string","enum":["all","dangling","reflog","stash","secrets","orphans"]}},"required":["repo_path"]}},
    {"name":"triton_taint","description":"Triton taint analysis for data flow tracing. Falls back to ltrace/strace if not installed.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"stdin_input":{"type":"string"},"operation":{"type":"string","enum":["trace","strace"]}},"required":["binary_path"]}},
    {"name":"aeg_pipeline","description":"Automatic Exploit Generation: AFL++ → crash triage → checksec → register state → angr_solve suggestion.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["run","triage"]},"fuzz_seconds":{"type":"integer"},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"docker_sandbox","description":"Docker-isolated exploit testing: setup, run_exploit (sandboxed, no network), local_test. Safely catches crashes.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["setup","run_exploit","local_test"]},"binary_path":{"type":"string"},"exploit_code":{"type":"string"},"libc_path":{"type":"string"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"bindiff","description":"Binary diff between two versions to find patch-introduced vulnerability. diff, changed_functions, strings_diff.","input_schema":{"type":"object","properties":{"binary_a":{"type":"string"},"binary_b":{"type":"string"},"operation":{"type":"string","enum":["diff","changed_functions","strings_diff"]}},"required":["binary_a","binary_b"]}},
    {"name":"encrypted_store","description":"Persistent AES-256-GCM keystore for API keys/creds. Set CTF_SOLVER_MASTER env var. Ops: set, get, list, delete.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["set","get","list","delete"]},"key":{"type":"string"},"value":{"type":"string"},"store_path":{"type":"string"}},"required":["operation"]}},
    {"name":"differential_cryptanalysis","description":"Differential/linear cryptanalysis for custom CTF ciphers: collect_pairs, guess_key (last-round), linear_approx (bias table).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["collect_pairs","guess_key","linear_approx"]},"pairs":{"type":"array"},"target_diff":{"type":"integer"},"sbox":{"type":"array"}},"required":["operation"]}},

    # ── 53 gap-closing tools ──────────────────────────────────────────────────
    {"name":"2fa_bypass","description":"2FA/MFA bypass execution: probe (detect OTP type), race (20 concurrent requests to beat rate limit), bruteforce (try all N-digit codes), totp_predict (given base32 secret generate valid TOTPs ±2 windows), backup_bruteforce (common backup code formats).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["probe","race","bruteforce","totp_predict","backup_bruteforce","response_manipulation"]},"target_url":{"type":"string"},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"secret":{"type":"string"},"token_length":{"type":"integer"}},"required":["operation"]}},
    {"name":"android_vuln","description":"Android vulnerability exploitation: scan (drozer attack surface), intent_hijack (exported activity/service/receiver), content_provider (SQLi + path traversal), deeplink (URL scheme injection), webview (JS bridge + file scheme XSS), backup (ADB backup extraction), adb_commands.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["scan","intent_hijack","content_provider","deeplink","broadcast","webview","backup","debug","adb_commands"]},"target":{"type":"string"},"package_name":{"type":"string"},"device":{"type":"string"},"extra":{"type":"string"}},"required":["operation"]}},
    {"name":"apk_analyze","description":"Android APK analysis: all (quick overview), decompile (jadx Java/Kotlin), manifest (permissions, exported components), dex (Dalvik bytecode), strings (hardcoded secrets/URLs/keys), find_vulns (exported activities, SQLi, WebView JS bridge, content providers), certificate.","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"operation":{"type":"string","enum":["all","manifest","decompile","strings","certificate","find_vulns","dex","smali"]},"class_filter":{"type":"string"},"output_dir":{"type":"string"}},"required":["apk_path"]}},
    {"name":"apk_resign","description":"Full APK patch→rebuild→sign→install pipeline. Ops: full_pipeline (decompile+patch_ssl+rebuild+sign+install), decompile (apktool d), patch_ssl (inject network_security_config for mitmproxy), rebuild (apktool b), sign (jarsigner+zipalign), install (adb install).","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"operation":{"type":"string","enum":["full_pipeline","decompile","patch_ssl","rebuild","sign","install"]},"patch_smali":{"type":"string"},"target_class":{"type":"string"},"output_path":{"type":"string"}},"required":["apk_path","operation"]}},
    {"name":"arm_rop","description":"ARM/AArch64/MIPS ROP chain builder via pwntools. Ops: chain (build ROP for goal: shell/ret2libc/syscall/execve), gadgets (dump useful gadgets via ROPgadget/ropper), checksec, ret2libc (find system+/bin/sh). Supports arm, arm64/aarch64, mips, mipsel.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["chain","gadgets","checksec","ret2libc","syscall"]},"libc_path":{"type":"string"},"arch":{"type":"string","enum":["arm","arm64","aarch64","mips","mipsel"]},"goal":{"type":"string"},"base_addr":{"type":"string"}},"required":["binary_path"]}},
    {"name":"asm_eval","description":"Evaluate x86/ARM/MIPS assembly snippet to compute final register state. Critical for asm1-asm4 type challenges. Ops: eval (run + dump registers), trace (step-by-step), find_ret (what does eax/rax equal). Uses Unicorn+Keystone, falls back to Python mini-evaluator.","input_schema":{"type":"object","properties":{"code_or_path":{"type":"string"},"operation":{"type":"string","enum":["eval","trace","find_ret","decompile_snippet"]},"arch":{"type":"string","enum":["x86","x86_64","arm","arm64","mips"]},"entry":{"type":"string"},"inputs":{"type":"object"},"steps":{"type":"integer"}},"required":["code_or_path"]}},
    {"name":"binary_patch","description":"Instruction-level binary patching for reversing challenges. Ops: find_checks (locate cmp+jcc license checks), nop (NOP out bytes), flip_jump (jz↔jnz, je↔jne flip), patch_bytes (write arbitrary hex), patch_ret (make function return constant), assemble (keystone asm → write bytes), info (function offsets).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["find_checks","nop","flip_jump","patch_bytes","patch_ret","assemble","info"]},"offset":{"type":"string"},"size":{"type":"integer"},"new_bytes":{"type":"string"},"output_path":{"type":"string"},"function_name":{"type":"string"}},"required":["binary_path","operation"]}},
    {"name":"challenge_classifier","description":"Predict challenge technique from description + file list using keyword scoring. Returns ranked techniques (tcache_uaf, stack_bof, rsa_basic, ecc, ssti, sqli, deserialization, etc.), attack narrative, and tool recommendations. Fast, no API needed.","input_schema":{"type":"object","properties":{"description":{"type":"string"},"files":{"type":"array"},"category_hint":{"type":"string"},"use_api":{"type":"boolean"}},"required":["description"]}},
    {"name":"cloud_forensics","description":"Cloud log forensics: analyze (detect log type), cloudtrail (AWS CloudTrail event timeline, IAM actions, errors), gcp_audit (GCP audit logs), azure_activity (Azure activity), s3_access (S3 access logs), timeline (chronological event reconstruction).","input_schema":{"type":"object","properties":{"path":{"type":"string"},"operation":{"type":"string","enum":["analyze","cloudtrail","gcp_audit","azure_activity","s3_access","lambda_logs","timeline"]},"cloud":{"type":"string"},"keyword":{"type":"string"}},"required":["path","operation"]}},
    {"name":"cors_exploit","description":"CORS misconfiguration: probe (detect origin reflection/null/subdomain), exploit (credential theft PoC), subdomain_check (find takeable subdomains for CORS bypass), preflight (complex request bypass). Essential for insane web.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","exploit","subdomain_check","preflight"]},"origin":{"type":"string"},"credentials":{"type":"boolean"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"cpp_vtable","description":"C++ vtable exploitation: detect (find vtable ptrs + RTTI in binary), type_confusion (unsafe cast patterns), vtable_overwrite (generate heap payload to hijack vptr), fake_vtable (build fake vtable struct), vptr_spray.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","type_confusion","vtable_overwrite","fake_vtable","vptr_spray"]},"target_class":{"type":"string"},"rip_target":{"type":"string"}},"required":["operation"]}},
    {"name":"deserialization_exploit","description":"Java ysoserial + PHP phpggc deserialization payload generator. Languages: java, php, python, ruby, node. Ops: list (chains), generate (payload), detect (magic bytes).","input_schema":{"type":"object","properties":{"language":{"type":"string","enum":["java","php","python","ruby","node"]},"operation":{"type":"string","enum":["list","generate","detect"]},"gadget_chain":{"type":"string"},"command":{"type":"string"},"output_format":{"type":"string","enum":["base64","hex","raw"]},"extra_args":{"type":"string"}},"required":["language"]}},
    {"name":"disk_forensics","description":"Disk image forensics: analyze (partition table, filesystem type), mount (loop mount), recover_files (photorec/foremost), mft (NTFS Master File Table), deleted_files (fls/extundelete), timeline (mactime/log2timeline), keyword_search, strings.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","mount","recover_files","mft","deleted_files","timeline","keyword_search","strings","hash_check"]},"partition":{"type":"integer"},"output_dir":{"type":"string"},"keyword":{"type":"string"}},"required":["image_path"]}},
    {"name":"dom_xss","description":"DOM XSS: analyze (find sinks + sources in JS), payloads (sink-specific bypass chains), dom_clobbering (id/name attribute clobber for XSS), mutation_xss (mXSS parser confusion, DOMPurify bypasses), csp_bypass (JSONP/base-uri/dangling markup), prototype_pollution_xss.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["analyze","payloads","dom_clobbering","mutation_xss","csp_bypass","prototype_pollution_xss"]},"url_or_path":{"type":"string"},"html_content":{"type":"string"},"sink":{"type":"string"},"extra_payloads":{"type":"string"}},"required":["operation"]}},
    {"name":"dotnet_decompile","description":"Full .NET C# decompilation via ilspycmd/ILSpy (vs bytecode_disasm which only does raw IL). Ops: decompile (full project), list_types, list_methods, method (single method), strings, resources, references, patch.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["decompile","list_types","list_methods","method","strings","resources","references","patch"]},"type_name":{"type":"string"},"method_name":{"type":"string"},"output_path":{"type":"string"}},"required":["binary_path"]}},
    {"name":"ebpf_exploit","description":"eBPF exploitation: detect (kernel version + unprivileged BPF check + vuln taxonomy), verifier_bypass (explain OOB r/w approach + CVE references), skeleton (C exploit skeleton with libbpf). For kernel eBPF CTF challenges.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","verifier_bypass","jit_spray","map_oob","priv_escalation","skeleton"]},"program_path":{"type":"string"},"vuln_type":{"type":"string"}},"required":["operation"]}},
    {"name":"ecc_special_attacks","description":"ECC special attacks: detect (Smart/MOV/Pohlig-Hellman/invalid-curve), smart (anomalous curve DLP in O(log p)), mov (supersingular Tate pairing), invalid_curve (small-order points for CRT key recovery), pohlig_hellman (smooth-order DLP). All use SageMath.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","smart","mov","invalid_curve","pohlig_hellman"]},"p":{"type":"integer"},"a":{"type":"integer"},"b":{"type":"integer"},"n":{"type":"integer"},"Gx":{"type":"integer"},"Gy":{"type":"integer"},"Px":{"type":"integer"},"Py":{"type":"integer"},"k":{"type":"integer"}},"required":["operation"]}},
    {"name":"ethereum_exploit","description":"Ethereum/Solidity CTF exploitation: analyze (detect vulns in source), reentrancy (cross-function/read-only attack), selfdestruct (force ETH send), delegatecall (storage collision), tx_origin (auth bypass), flash_loan (price manipulation), storage_collision, setup (Foundry/Hardhat env).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["analyze","reentrancy","selfdestruct","delegatecall","tx_origin","flash_loan","storage_collision","access_control","integer_overflow","setup"]},"contract_source":{"type":"string"},"contract_address":{"type":"string"},"network":{"type":"string"},"target_function":{"type":"string"},"value_eth":{"type":"string"}},"required":["operation"]}},
    {"name":"firmware_unpack","description":"Firmware analysis: analyze (binwalk + file type), extract (filesystem extraction: JFFS2/UBI/squashfs), emulate (QEMU user-mode for ARM/MIPS/PPC), find_vulns (hardcoded creds, command injection, keys), strings_scan, entropy.","input_schema":{"type":"object","properties":{"firmware_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","extract","emulate","find_vulns","strings_scan","entropy"]},"arch":{"type":"string"},"output_dir":{"type":"string"}},"required":["firmware_path"]}},
    {"name":"flutter_re","description":"Flutter/React Native/Dart reverse engineering: detect (identify framework), flutter_extract (libflutter.so + libapp.so from APK), dart_snapshot (analyze Dart AOT snapshot + reFlutter reference), rn_bundle (extract JS bundle), rn_deobfuscate (Hermes bytecode via hbcdump/hermes-dec).","input_schema":{"type":"object","properties":{"apk_path":{"type":"string"},"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","flutter_extract","dart_snapshot","rn_bundle","rn_deobfuscate","strings"]}},"required":["operation"]}},
    {"name":"format_string_exploit","description":"Pwntools format string exploit helper. Ops: find_offset (brute %p chain to locate AAAA offset), read_stack (dump stack values), write_target (generate fmtstr_payload for GOT overwrite given offset+write_addr+write_val), auto_exploit (FmtStr full automation). Covers format_string_1/2/3.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["find_offset","read_stack","write_target","auto_exploit"]},"write_addr":{"type":"string","description":"Target address (hex)"},"write_val":{"type":"string","description":"Value to write (hex)"},"offset":{"type":"integer","description":"Format string offset from find_offset"}},"required":["operation"]}},
    {"name":"fsop","description":"IO_FILE / FSOP exploitation for glibc ≥2.35 (no __free_hook/__malloc_hook). Ops: detect (check glibc version), fake_file (build _IO_FILE bytes), wide_data (_wide_data vtable attack for RIP), _io_list_all (overwrite chain), skeleton (full pwntools exploit).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","fake_file","wide_data","_io_list_all","skeleton"]},"libc_path":{"type":"string"},"target_func":{"type":"string"},"rip_control":{"type":"string"}},"required":["operation"]}},
    {"name":"gdb_remote","description":"Remote GDB debugging for challenges running gdbserver. Ops: connect (verify gdbserver alive + RSP handshake), run_script (execute GDB command script against remote target via gdb -batch), pwntools_remote (pwntools GDB remote attach), find_password (hook strcmp/strncmp/memcmp via GDB breakpoints to extract compared values), angr_remote (angr symbolic execution against local binary to find valid input). Covers pwn challenges where binary runs on a remote gdbserver rather than plain nc.","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer","description":"gdbserver port (default 1234)"},"binary_path":{"type":"string","description":"Local copy of the remote binary (for symbols)"},"operation":{"type":"string","enum":["connect","run_script","pwntools_remote","find_password","angr_remote"]},"script":{"type":"string","description":"GDB commands for run_script op (one per line)"},"find_addr":{"type":"string","description":"Target address for angr_remote"},"avoid_addrs":{"type":"array","items":{"type":"string"},"description":"Addresses to avoid for angr_remote"},"timeout":{"type":"integer"}},"required":["host"]}},
    {"name":"go_rev","description":"Go binary reverse engineering: analyze (version + suspicious strings), symbols (GoReSym symbol recovery for stripped binaries), functions (list all Go functions via nm/r2), pcln (parse pclntab to recover function names), strings (Go string table extraction).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","symbols","functions","pcln","strings","types"]},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"hash_crack","description":"Identify and crack hashes (MD5/SHA1/SHA256/SHA512/bcrypt/NTLM). Ops: auto (identify then online then hashcat), identify (detect type only), wordlist (hashcat -a 0 rockyou.txt), bruteforce (hashcat -a 3 mask), online_lookup (CrackStation + hashes.com). Essential for hashcrack challenge class and NTLM hashes in forensics.","input_schema":{"type":"object","properties":{"hash_value":{"type":"string"},"operation":{"type":"string","enum":["auto","identify","wordlist","bruteforce","online_lookup"]},"wordlist":{"type":"string"},"hash_type":{"type":"string","description":"Force type: md5/sha1/sha256/sha512/ntlm/bcrypt"}},"required":["hash_value"]}},
    {"name":"house_of_exploit","description":"House of * heap exploitation for glibc ≥2.31 (post-__free_hook era). Techniques: detect, orange (unsorted_bin→__malloc_hook), force (top chunk), spirit (free fake chunk), lore (large_bin bk_nextsize AAW), einherjar (off-by-null consolidation), poison_null_byte, off_by_one.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"technique":{"type":"string","enum":["detect","orange","force","spirit","lore","einherjar","tangerine","poison_null_byte","off_by_one"]},"libc_path":{"type":"string"},"libc_version":{"type":"string"},"target_addr":{"type":"string"},"cmd":{"type":"string"}},"required":["technique"]}},
    {"name":"image_steg_advanced","description":"Advanced image steganography beyond basic LSB/zsteg. Ops: auto (run all checks), msb (most-significant-bit extraction from R/G/B), color_planes (save each RGB/A channel as separate PNG), bit_plane_extract (extract specific bit 0-7 from each channel + check for flag), fourier (FFT magnitude spectrum for frequency-domain steg), palette_steg (hidden data in PNG indexed palette LSBs), alpha_extract (alpha channel raw + LSB), outguess (JPEG steg via outguess), stegsolve (all 64 bit/channel/order combos in one sweep), metadata_deep (exiftool -a -u -g + identify -verbose). Covers LoadSomeBits MSB, RED rgba LSB, and any non-standard steg channel.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["auto","msb","color_planes","bit_plane_extract","fourier","palette_steg","alpha_extract","outguess","stegsolve","metadata_deep"]},"channel":{"type":"string","description":"R/G/B/A or all"},"bit_plane":{"type":"integer","description":"Bit plane 0-7 for bit_plane_extract"},"output_path":{"type":"string"}},"required":[]}},
    {"name":"ios_vuln","description":"iOS vulnerability analysis: scan (objection/idb overview), keychain (dump keychain items via Frida/objection), nsuserdefaults (insecure storage), jailbreak_bypass (Frida JB detection bypass script), method_swizzling (ObjC hook template), runtime_analysis (frida-trace), url_scheme.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["scan","keychain","nsuserdefaults","url_scheme","jailbreak_bypass","method_swizzling","runtime_analysis","network_analysis"]},"target":{"type":"string"},"bundle_id":{"type":"string"},"device":{"type":"string"}},"required":["operation"]}},
    {"name":"ipa_analyze","description":"iOS IPA analysis: all (overview), extract (unzip app bundle), plist (Info.plist + all plists), class_dump (ObjC headers), strings (secrets), entitlements (code signing), find_vulns (ATS bypass, URL schemes, keychain misuse, WebView), binary_analysis (checksec + encryption).","input_schema":{"type":"object","properties":{"ipa_path":{"type":"string"},"operation":{"type":"string","enum":["all","extract","plist","class_dump","strings","entitlements","find_vulns","binary_analysis","swift_decompile"]},"output_dir":{"type":"string"},"class_filter":{"type":"string"}},"required":["ipa_path"]}},
    {"name":"java_sandbox","description":"Compile and run Java source code, or reverse Java checkPassword logic. Ops: run (javac+java), analyze (extract flag from charAt/XOR/int-packed patterns), solve (auto-extract flag), decompile (javap -c). Critical for Vault Door, crackme, and all Java source reversing challenges.","input_schema":{"type":"object","properties":{"source_code":{"type":"string"},"source_path":{"type":"string"},"operation":{"type":"string","enum":["run","analyze","solve","decompile"]},"class_name":{"type":"string"},"stdin_input":{"type":"string"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"kernel_lpe","description":"Linux kernel LPE: detect (version + mitigations: SMEP/SMAP/KPTI/kptr_restrict), dirty_pipe (CVE-2022-0847), modprobe_path (arbitrary root cmd), userfaultfd_uaf (race slowdown), ret2usr (with SMEP/SMAP/KPTI bypass), slub_overflow (SLUB heap grooming).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","dirty_pipe","modprobe_path","userfaultfd_uaf","ret2usr","slub_overflow","skeleton"]},"module_path":{"type":"string"},"vuln_type":{"type":"string"},"target_cred":{"type":"string"}},"required":["operation"]}},
    {"name":"node_exec","description":"Execute JavaScript/Node.js code. Ops: run (write .js + node execute), eval_snippet (node -e inline), heapsnapshot_grep (stream-parse .heapsnapshot JSON and grep for flag pattern — key for head-dump challenge), deobfuscate_run (run obfuscated JS, capture all console.log). Covers Bookmarklet XOR, head-dump heapsnapshot, client-side JS.","input_schema":{"type":"object","properties":{"code":{"type":"string"},"file_path":{"type":"string","description":"Path to .js or .heapsnapshot file"},"operation":{"type":"string","enum":["run","eval_snippet","heapsnapshot_grep","deobfuscate_run"]},"pattern":{"type":"string","description":"Grep pattern for heapsnapshot_grep (default: picoCTF{)"},"timeout":{"type":"integer"}},"required":["operation"]}},
    {"name":"pcap_deep","description":"Deep PCAP analysis: summary (protocol stats), decrypt_export (RSA privkey → decrypt TLS → tshark --export-objects http), dns_exfil (detect/reconstruct DNS tunnel from hex/b64 subdomains), covert_channel (timing bits/ICMP/HTTP-header), credentials (extract plaintext creds), extract_streams, ftp_extract, smtp_extract.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"operation":{"type":"string","enum":["summary","decrypt_export","dns_exfil","covert_channel","credentials","extract_streams","ftp_extract","smtp_extract","strings_all"]},"key_path":{"type":"string"},"output_dir":{"type":"string"},"filter_expr":{"type":"string"},"keyword":{"type":"string"}},"required":["pcap_path","operation"]}},
    {"name":"pe_analysis","description":"Windows PE analysis — ELF binary_analysis misses all PE structure. Ops: info (headers, sections, imports, TLS via pefile), resources (list + wrestool extract), icons (extract ICO, convert PNG), strings (pefile section scan), unpack (detect UPX/Themida/MPRESS, run upx -d). Covers Windows crackme and .exe embedded-flag challenges.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string","description":"Path to .exe/.dll/.sys"},"operation":{"type":"string","enum":["info","resources","icons","strings","unpack"]},"resource_type":{"type":"string"},"output_dir":{"type":"string"}},"required":["binary_path"]}},
    {"name":"polyglot_file","description":"Generate polyglot files valid as two formats simultaneously (GIF+PHP, JPG+PHP, SVG+XSS, PDF+HTML, ZIP+PHP) to bypass upload type checks. Ops: list (catalog), generate (create file), check (file + exiftool inspect).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["list","generate","check"]},"file_type_a":{"type":"string"},"file_type_b":{"type":"string"},"content":{"type":"string"},"input_path":{"type":"string"},"output_path":{"type":"string"}},"required":["operation"]}},
    {"name":"powershell_deobf","description":"PowerShell script deobfuscation: deobfuscate (base64+gzip+char decode chain), amsi_detect (find AMSI bypass patches), iex_extract (pull Invoke-Expression payloads), strings (all cleartext string literals), run_safe (execute in constrained language mode).","input_schema":{"type":"object","properties":{"script_path":{"type":"string"},"script_content":{"type":"string"},"operation":{"type":"string","enum":["deobfuscate","amsi_detect","iex_extract","strings","run_safe","decode_chain"]}},"required":["operation"]}},
    {"name":"pqc_attack","description":"Post-quantum crypto attacks: detect (BKZ beta estimate for LWE params), lwe_attack (primal BDD via Sage lattice embedding), ntru_attack (LLL key recovery), kyber_fault (fault injection model), zkp_attack (ZK proof soundness exploits).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","lwe_attack","ntru_attack","kyber_fault","zkp_attack"]},"n":{"type":"integer"},"q":{"type":"integer"},"samples":{"type":"array"},"N":{"type":"integer"},"h":{"type":"array"}},"required":["operation"]}},
    {"name":"pyjail_escape","description":"Python sandbox escape: detect (analyze restrictions), escape_chains (20 ordered techniques: subclass walk, builtins restore, frame inspection, breakpoint, timeit, f-string, code objects), subclass_walk (find useful __subclasses__), builtins_restore, audit_hooks_bypass (ctypes bypass for sys.addaudithook).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","escape_chains","subclass_walk","builtins_restore","audit_hooks_bypass","fstring","code_object"]},"jail_code":{"type":"string"},"available":{"type":"string"},"blocked":{"type":"string"}},"required":["operation"]}},
    {"name":"qr_decode","description":"Decode QR codes, DataMatrix, Code128, and all barcode types from image files. Ops: decode (zbarimg + pyzbar fallback), scan_all (both decoders merged), barcode (force type: qr/code128/datamatrix/ean), generate (qrencode data string to PNG). Appears in ~10% of picoCTF forensics challenges.","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["decode","scan_all","barcode","generate"]},"barcode_type":{"type":"string","description":"Force barcode type (default: any)"},"data":{"type":"string","description":"String to encode (for generate op)"}},"required":[]}},
    {"name":"rop_chain","description":"ROP chain builder wrapping pwntools ROP(). Goals: shell/ret2libc, syscall/execve, write_what_where. Auto-selects gadgets, handles x86_64 stack alignment. Also: gadgets (dump via ROPgadget), checksec, one_gadget.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["build","gadgets","checksec"]},"goal":{"type":"string","enum":["shell","ret2libc","syscall","execve","write_what_where","one_gadget"]},"libc_path":{"type":"string"},"base_addr":{"type":"string"},"extra_gadgets":{"type":"string"}},"required":["binary_path"]}},
    {"name":"rust_sandbox","description":"Compile and run Rust source code (rustc). Like java_sandbox but for Rust. Ops: run (compile + execute), fix_and_run (apply patch='OLD|||NEW' or unified diff then compile+run), analyze (HIR dump), decompile (strings+nm). Covers Rust-Fixme 1/2/3 series.","input_schema":{"type":"object","properties":{"source_code":{"type":"string"},"source_path":{"type":"string"},"operation":{"type":"string","enum":["run","fix_and_run","analyze","decompile"]},"patch":{"type":"string","description":"For fix_and_run: 'OLD|||NEW' replacement or unified diff"},"timeout":{"type":"integer"}},"required":[]}},
    {"name":"sdr_analyze","description":"SDR/RF signal analysis: analyze (file inspection), demodulate (AM/FM/FSK/OOK/BPSK/QPSK), spectrum (ASCII frequency plot), decode_ook (On-Off Keying binary extraction), replay (generate replay payload). Supports .wav/.iq/.cf32/.cs8 files.","input_schema":{"type":"object","properties":{"file_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","demodulate","spectrum","decode_ook","decode_dtmf","replay"]},"frequency":{"type":"number"},"sample_rate":{"type":"number"},"modulation":{"type":"string"}},"required":["operation"]}},
    {"name":"solve_resume","description":"Serialize/resume conversation state for multi-hour solves. Prevents losing Opus iterations on network failures. Ops: save, load, list, delete, checkpoint. Stores turns, iteration count, hypotheses, flags, workspace path.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["save","load","list","delete","checkpoint"]},"session_id":{"type":"string"},"state_path":{"type":"string"},"conversation":{"type":"array"},"metadata":{"type":"object"}},"required":["operation"]}},
    {"name":"ssh_exec","description":"SSH with password/key auth, command execution, SCP download, interactive game protocol. Ops: run_command (exec + return stdout), scp_download (pull remote_path via SCP/SFTP), interactive_game (shell with binary_search:lo:hi shorthand or custom script lines), connect (probe+banner). Covers Binary Search SSH game and hash-only-1 SCP challenge.","input_schema":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"username":{"type":"string"},"password":{"type":"string"},"key_path":{"type":"string"},"operation":{"type":"string","enum":["run_command","scp_download","interactive_game","connect"]},"command":{"type":"string"},"remote_path":{"type":"string"},"local_path":{"type":"string"},"script":{"type":"string","description":"For interactive_game: 'binary_search:1:1000' or newline-separated responses"}},"required":["host"]}},
    {"name":"ssl_pinning_bypass","description":"SSL/certificate pinning bypass: frida (universal Android+iOS Frida bypass script for OkHttp/TrustManager/NSURLSession), objection (objection ssl disable), apktool_patch (network_security_config patch + resign APK), ios_frida, custom (hook specific class).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["frida","objection","apktool_patch","ios_frida","custom"]},"target":{"type":"string"},"package_name":{"type":"string"},"method":{"type":"string"}},"required":["operation"]}},
    {"name":"ssrf_chain","description":"SSRF automated exploitation: probe (detect), cloud_metadata (AWS/GCP/Azure IMDS credentials), port_scan (internal network), redis_rce (gopher→RCE), protocol_smuggle (gopher/dict/file/ldap/tftp payloads + IP filter bypasses).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","cloud_metadata","port_scan","redis_rce","protocol_smuggle"]},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"internal_target":{"type":"string"},"custom_payload":{"type":"string"}},"required":["target_url"]}},
    {"name":"ssti_rce","description":"SSTI detection + engine-specific RCE escalation. Ops: detect (probe URL with polymath probes), escalate (sandbox escape chains), payloads (dump without requests), list_engines. Engines: jinja2, jinja2_sandbox, twig, freemarker, velocity, mako, erb, tornado, smarty, handlebars, pebble.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","escalate","payloads","list_engines"]},"engine":{"type":"string"},"target_url":{"type":"string"},"param":{"type":"string"},"method":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"custom_payload":{"type":"string"}},"required":["operation"]}},
    {"name":"swagger_fuzz","description":"Enumerate OpenAPI/Swagger specs and test endpoints for sensitive data. Ops: discover (probe /api-docs /swagger.json /openapi.json /actuator), parse_spec (list all paths+methods), test_all (call every GET endpoint, flag interesting), download_artifact (stream binary from endpoint e.g. /actuator/heapdump to output_path). Covers head-dump and Spring Boot Actuator challenges.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["discover","parse_spec","test_all","download_artifact"]},"endpoint":{"type":"string","description":"Endpoint path for download_artifact"},"output_path":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"swift_decompile","description":"iOS Swift binary analysis: analyze (file + encryption check), demangle (Swift symbol demangling via swift-demangle), class_hierarchy (class-dump + ObjC metadata), strings (Swift + ObjC string literals), frida_hooks (Swift-aware Frida hook templates).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"ipa_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","demangle","class_hierarchy","strings","protocols","frida_hooks"]}},"required":["operation"]}},
    {"name":"vm_devirt","description":"VM devirtualization for VMProtect/Themida/custom VM: detect (identify protector + dispatcher), trace (Frida/Unicorn execution trace), lift (bytecode→C from opcode_map), devirt_skeleton (analysis script template).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["detect","trace","lift","devirt_skeleton"]},"handler_addr":{"type":"string"},"opcode_map":{"type":"object"}},"required":["binary_path"]}},
    {"name":"windows_forensics","description":"Windows artifact forensics: registry (SAM/SYSTEM/SOFTWARE hive parsing, credential extraction), event_logs (EVTX: logon events 4624/4625, PowerShell), prefetch, lnk_files, shellbags, browser_history (Chrome/Firefox SQLite), credentials (secretsdump).","input_schema":{"type":"object","properties":{"path":{"type":"string"},"operation":{"type":"string","enum":["all","registry","event_logs","prefetch","lnk_files","credentials","browser_history","shellbags","amcache"]},"output_dir":{"type":"string"},"keyword":{"type":"string"}},"required":["path"]}},
    {"name":"xs_leak","description":"XS-Leak and CSS injection oracle for information leakage web challenges. Ops: css_oracle (generate CSS attribute selector payload for secret attribute probing), lru_setup (upload marker files + garbage prefill to approach Redis memory limit), lru_flood (flood Redis to trigger LRU eviction), lru_probe (probe all marker IDs: 200=survived/touched, 404=evicted), reconstruct (beam-search + LLR scoring to recover secret from survived markers), full_pipeline (orchestration guide for picoCTF 2026 Paper-2 attack), error_oracle (probe URL list by status code), frame_count (count iframes as oracle bit). Essential for Paper-2 2026 (CSS+LRU side-channel) and elements-2024 (frame counting).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["css_oracle","lru_setup","lru_flood","lru_probe","reconstruct","full_pipeline","error_oracle","frame_count"]},"secret_endpoint":{"type":"string","description":"Endpoint that renders secret in HTML attribute (default /secret)"},"secret_attr":{"type":"string","description":"HTML attribute name holding secret (default: secret)"},"charset":{"type":"string","description":"Characters in the secret (default: 0123456789abcdef)"},"secret_len":{"type":"integer","description":"Length of secret to recover (default: 32)"},"upload_endpoint":{"type":"string","description":"File upload endpoint (default: /upload)"},"visit_endpoint":{"type":"string","description":"Bot trigger endpoint (default: /visit)"},"output":{"type":"object","description":"Carry state between ops: markers dict, survived list, etc."}},"required":["target_url"]}},
    {"name":"zkp_attack","description":"ZK proof system attacks: detect (identify system + vuln patterns), null_constraint (under-constrained Circom signals), weak_fiat_shamir (replay/grinding), groth16_malleability (rerandomize proof), plonk_soundness (constraint extraction).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["detect","null_constraint","weak_fiat_shamir","groth16_malleability","plonk_soundness"]},"circuit_code":{"type":"string"}},"required":["operation"]}},

    # ── 23 new tools — external tool wrappers ─────────────────────────────────
    {"name":"rsa_toolkit","description":"RSA attack toolkit wrapping RsaCtfTool (github.com/RsaCtfTool/RsaCtfTool). Ops: auto (try all attacks), fermat (Fermat factoring for p\u2248q \u2014 most common picoCTF miss), wiener (small d), hastads (small e broadcast), common_modulus, batch_gcd (factor N from list of moduli with gcd), multiprime (3+ prime RSA), factor_only. Falls back to sympy/gmpy2 pure-Python for fermat+batch_gcd when RsaCtfTool missing.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["auto","fermat","wiener","hastads","common_modulus","batch_gcd","multiprime","factor_only"]},"n":{"type":"string"},"e":{"type":"string"},"c":{"type":"string"},"p":{"type":"string"},"q":{"type":"string"},"factors":{"type":"array","items":{"type":"string"}},"moduli":{"type":"array","items":{"type":"string"}},"output_file":{"type":"string"}},"required":[]}},
    {"name":"cbc_oracle","description":"CBC padding oracle attack wrapping padbuster / paddingoracle. Ops: decrypt (recover plaintext byte-by-byte via oracle), encrypt (encrypt arbitrary plaintext via oracle), probe (verify oracle is working \u2014 distinguishable padding error response), padbuster (shell to padbuster CLI for full automation). Provide target_url + ciphertext_hex + oracle_param.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["decrypt","encrypt","probe","padbuster"]},"target_url":{"type":"string"},"ciphertext_hex":{"type":"string"},"block_size":{"type":"integer"},"oracle_param":{"type":"string"},"method":{"type":"string"},"encoding":{"type":"string"},"known_plaintext":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","ciphertext_hex"]}},
    {"name":"vigenere_crack","description":"Automated Vigenere cipher cracking \u2014 Kasiski test + Index of Coincidence key length + per-column frequency analysis. No external deps needed. Ops: crack (auto find key + decrypt), kasiski (repeated trigram spacing), ic_key_length (IC analysis per key length), recover_key (given key length, recover key by frequency).","input_schema":{"type":"object","properties":{"ciphertext":{"type":"string"},"operation":{"type":"string","enum":["crack","kasiski","ic_key_length","recover_key"]},"key_length":{"type":"integer"},"known_key":{"type":"string"}},"required":["ciphertext"]}},
    {"name":"side_channel","description":"Statistical timing side-channel attack \u2014 measures response time per character to recover secrets byte-by-byte. Ops: timing_attack (probe target URL with each charset char, find outlier timing for each position), analyze_timings (given [(char,time)] list compute z-scores), bit_leak_extract (binary search timing oracle).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["timing_attack","analyze_timings","bit_leak_extract"]},"target_url":{"type":"string"},"param":{"type":"string"},"charset":{"type":"string"},"known_prefix":{"type":"string"},"secret_len":{"type":"integer"},"method":{"type":"string"},"samples":{"type":"integer"},"measurements":{"type":"array"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["operation"]}},
    {"name":"one_gadget","description":"Wrapper around one_gadget Ruby gem (github.com/david942j/one_gadget). Finds single-gadget RCE addresses in libc that give a shell when register constraints are met. Ops: find (list all gadgets + constraints), best (highest probability gadget), find_with_leak (compute absolute gadget addresses from a libc leak + symbol), check_constraints (verify usable gadgets given register state). Falls back to ROPgadget execve search if gem not installed.","input_schema":{"type":"object","properties":{"libc_path":{"type":"string"},"operation":{"type":"string","enum":["find","best","find_with_leak","check_constraints"]},"leak_addr":{"type":"string"},"leak_symbol":{"type":"string"},"constraints":{"type":"object"}},"required":[]}},
    {"name":"pwn_template","description":"Exploit template generator using pwninit + pwntools. Ops: generate (full exploit scaffold from binary analysis \u2014 auto-detects arch, PIE, RELRO, creates pwntools script), stack_template (ret2win/ROP scaffold), heap_template (heap exploit scaffold with menu interaction helpers), rop_template (ROP chain scaffold with libc leak pattern), pwninit (run pwninit to patch binary + create solve.py). Pass checksec output for smarter templates.","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"host":{"type":"string"},"port":{"type":"integer"},"operation":{"type":"string","enum":["generate","stack_template","heap_template","rop_template","pwninit"]},"vuln_type":{"type":"string","enum":["auto","stack","heap","format_string"]},"libc_path":{"type":"string"}},"required":[]}},
    {"name":"heap_visualize","description":"Parse and visualize pwndbg/GDB heap state. Ops: live (attach to process, run pwndbg heap/bins/vis_heap_chunks commands), parse_state (parse raw pwndbg output into structured chunk/bin data), find_overlap (detect overlapping chunks \u2014 common in heap overflow challenges), tcache_status (parse tcache bins and counts), check_double_free (scan for same address in multiple bins).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["live","parse_state","find_overlap","tcache_status","check_double_free"]},"gdb_output":{"type":"string"},"binary_path":{"type":"string"},"pid":{"type":"integer"}},"required":["operation"]}},
    {"name":"libc_database","description":"Extended libc lookup via libc.rip API + pwntools. Ops: search (find libc from leak_addr + symbol \u2014 returns build IDs + all symbol offsets), identify (narrow down with multiple leak+symbol pairs), download (download matching libc .so from libc.rip to /tmp), offsets (print all useful symbol offsets for a build), one_gadgets (get one_gadget offsets for downloaded libc).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["search","identify","download","offsets","one_gadgets"]},"leak_addr":{"type":"string"},"symbol":{"type":"string","description":"Known leaked symbol name e.g. puts, printf"},"extra_symbols":{"type":"object"},"build_id":{"type":"string"},"arch":{"type":"string"}},"required":["operation"]}},
    {"name":"string_decryptor","description":"Obfuscated string extractor wrapping FLOSS (Mandiant/flare-floss \u2014 pip install flare-floss). Extracts stack strings, tight-loop decoded strings, and XOR-obfuscated strings automatically. Ops: floss (run FLOSS for all string types), xor_scan (brute all 256 single-byte XOR keys and check for flag pattern), stack_strings (FLOSS stack strings only), tight_loops (FLOSS tight loop decoded strings only), decode_with_key (given known key + algorithm, decrypt all matching strings).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["floss","xor_scan","stack_strings","tight_loops","decode_with_key"]},"key":{"type":"string","description":"Hex key for decode_with_key"},"algorithm":{"type":"string"},"decompiled_code":{"type":"string"}},"required":[]}},
    {"name":"license_check","description":"License/serial check extractor using angr symbolic execution + frida/GDB hooks. Ops: hook_comparisons (frida intercept strcmp/strncmp/memcmp at runtime \u2014 prints both sides of every comparison), angr_keygen (angr symbolic execution to find valid input that reaches success path), patch_check (identify check location for binary_patch), frida_hook (custom frida JS script against binary).","input_schema":{"type":"object","properties":{"binary_path":{"type":"string"},"operation":{"type":"string","enum":["hook_comparisons","angr_keygen","patch_check","frida_hook"]},"username":{"type":"string"},"input_value":{"type":"string","description":"Input to feed via stdin when hooking"},"timeout":{"type":"integer"}},"required":["binary_path"]}},
    {"name":"proto_decode","description":"Protobuf decoder wrapping blackboxprotobuf (pip install blackboxprotobuf) + protoc --decode_raw. No .proto schema needed. Ops: decode (decode raw protobuf hex/base64/bytes \u2014 returns JSON), schema_guess (infer approximate .proto schema from wire format), encode (encode JSON dict back to protobuf bytes), from_file (decode a binary file as protobuf), decode_raw (shell to protoc --decode_raw for quick view).","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["decode","schema_guess","encode","from_file","decode_raw"]},"data":{"type":"string","description":"Hex or base64 protobuf bytes"},"binary_path":{"type":"string"},"output_format":{"type":"string"}},"required":["operation"]}},
    {"name":"jwt_forge","description":"JWT attack toolkit wrapping jwt_tool (github.com/ticarpi/jwt_tool \u2014 pip install jwt-tool) with PyJWT/pycryptodome fallbacks. Ops: analyze (decode all parts), alg_none (forge with no signature \u2014 alg:none), rs256_hs256 (RS256\u2192HS256 confusion attack \u2014 sign with RSA public key as HMAC secret), kid_injection (kid header path traversal to /dev/null for empty-key signing), jku_redirect (jku header pointing to attacker JWKS URL), crack (brute-force HS256 secret with wordlist), forge (sign new payload with known secret + payload overrides).","input_schema":{"type":"object","properties":{"token":{"type":"string"},"operation":{"type":"string","enum":["analyze","alg_none","rs256_hs256","kid_injection","jku_redirect","crack","forge"]},"pubkey_path":{"type":"string"},"secret":{"type":"string"},"attacker_url":{"type":"string"},"kid":{"type":"string"},"payload_overrides":{"type":"object"},"wordlist":{"type":"string"}},"required":["operation"]}},
    {"name":"nosql_inject","description":"NoSQL (MongoDB) injection tester. Ops: probe (test $ne/$gt/$regex operator injection), auth_bypass (attempt MongoDB auth bypass \u2014 $ne/$gt/$exists/$regex), extract_field (extract field value char-by-char using $regex injection), js_inject (test $where JavaScript injection), nosqlmap (shell to NoSQLMap for full automated scan \u2014 git clone github.com/codingo/NoSQLMap). Supports JSON and form-encoded request bodies.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","auth_bypass","extract_field","js_inject","nosqlmap"]},"param":{"type":"string"},"password_param":{"type":"string"},"method":{"type":"string"},"charset":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"},"field":{"type":"string"},"data_format":{"type":"string","enum":["form","json"]}},"required":["target_url"]}},
    {"name":"file_upload","description":"File upload exploitation \u2014 MIME spoofing, double extension, .htaccess, null byte, polyglot. Ops: probe (try all bypass techniques), mime_spoof (mismatched Content-Type header), double_ext (file.php.jpg), htaccess (upload .htaccess to enable PHP execution), null_byte (filename%00.jpg injection), fuxploider (shell to fuxploider \u2014 pip install fuxploider). No payload logic \u2014 just the upload mechanism.","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","mime_spoof","double_ext","htaccess","null_byte","fuxploider"]},"upload_param":{"type":"string"},"code_content":{"type":"string","description":"File content to upload (e.g. PHP shell code)"},"filename":{"type":"string"},"output_dir":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url"]}},
    {"name":"template_inject","description":"SSTI blind probe + filter bypass extending ssti_rce. Ops: probe (comprehensive SSTI detection \u2014 delegates to ssti_rce detect), blind_probe (boolean-based blind SSTI), tplmap (shell to tplmap \u2014 git clone github.com/epinna/tplmap), filter_bypass (Jinja2 payloads that avoid underscore/dot/bracket filters using |attr(), lipsum, cycler, joiner, namespace globals), polyglot (single probe that triggers Jinja2/Twig/Freemarker simultaneously).","input_schema":{"type":"object","properties":{"target_url":{"type":"string"},"operation":{"type":"string","enum":["probe","blind_probe","tplmap","filter_bypass","polyglot"]},"param":{"type":"string"},"method":{"type":"string"},"engine":{"type":"string"},"headers":{"type":"object"},"cookies":{"type":"object"}},"required":["target_url","operation"]}},
    {"name":"steg_brute","description":"Steganography password brute-force wrapping stegseek (fastest \u2014 apt install stegseek) + stegcracker (pip install stegcracker). Ops: auto (stegseek \u2192 empty password \u2192 stegcracker in order), stegseek (RickdeJager/stegseek \u2014 fastest steghide cracker, uses rockyou in seconds), stegcracker (slower, more formats), steghide_empty (quick empty password test), outguess_crack (wordlist crack for outguess), all_tools (run every tool in sequence).","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["auto","stegseek","stegcracker","steghide_empty","outguess_crack","all_tools"]},"wordlist":{"type":"string"},"output_dir":{"type":"string"}},"required":["image_path"]}},
    {"name":"pcap_reassemble","description":"PCAP file reconstruction wrapping tshark --export-objects + tcpflow + foremost/binwalk. Ops: auto (export all objects from all protocols + flag scan), http_objects (tshark export HTTP transferred files), ftp_objects (tshark export FTP-DATA files), tcp_stream (reconstruct single TCP stream by ID), all_streams (tcpflow \u2014 every stream to separate file), find_files (run binwalk+foremost on reconstructed data to find embedded files). Essential for 'file-in-pcap' forensics challenges.","input_schema":{"type":"object","properties":{"pcap_path":{"type":"string"},"operation":{"type":"string","enum":["auto","http_objects","ftp_objects","tcp_stream","all_streams","find_files"]},"output_dir":{"type":"string"},"stream_id":{"type":"integer"},"filter_expr":{"type":"string"},"keyword":{"type":"string"}},"required":["pcap_path"]}},
    {"name":"pdf_forensics","description":"PDF forensics wrapping peepdf (pip install peepdf) + pikepdf + pdf-parser.py. Ops: analyze (full scan \u2014 JS, embedded files, streams, metadata), extract_js (extract JavaScript from PDF actions), extract_embedded (extract /EmbeddedFiles and attachments), decompress_streams (decompress all FlateDecode/LZWDecode streams to separate files, flag-scan each), metadata (dump all XMP/DocInfo metadata via exiftool + pdfinfo), find_hidden (search raw bytes for flag patterns + whitespace encoding + optional content layers).","input_schema":{"type":"object","properties":{"pdf_path":{"type":"string"},"operation":{"type":"string","enum":["analyze","extract_js","extract_embedded","decompress_streams","metadata","find_hidden"]},"output_dir":{"type":"string"}},"required":["pdf_path"]}},
    {"name":"image_repair","description":"Corrupted image repair using pngcheck + PIL/struct header patching \u2014 zero external deps beyond PIL. Ops: detect (identify corruption \u2014 wrong magic bytes, zero dimensions, bad CRC, truncated data), fix_png_header (repair PNG magic + recompute IHDR CRC), fix_jpeg_markers (repair SOI/EOI markers, scan for valid JPEG structure), restore_dimensions (patch width/height in PNG IHDR \u2014 common CTF trick where dimensions are set to 0), fix_bmp_header (repair BMP DIB header), check_crc (recompute all PNG chunk CRCs and report mismatches).","input_schema":{"type":"object","properties":{"image_path":{"type":"string"},"operation":{"type":"string","enum":["detect","fix_png_header","fix_jpeg_markers","restore_dimensions","fix_bmp_header","check_crc"]},"width":{"type":"integer","description":"Correct width for restore_dimensions"},"height":{"type":"integer","description":"Correct height for restore_dimensions"},"output_path":{"type":"string"}},"required":["image_path"]}},
    {"name":"compression","description":"Multi-format decompression using 7z + unar + Python stdlib (gzip/bz2/lzma/zipfile/tarfile). Ops: detect (identify compression from magic bytes), decompress (extract with best available tool \u2014 7z first, then unar, then Python stdlib), nested_extract (recursive decompression up to max_depth \u2014 handles 'file-in-file' chains common in General Skills), try_all (attempt every format until one succeeds), list_contents (list archive contents without extracting). Supports: gzip/bzip2/xz/zip/tar/rar/7z/lzma/zstd/lz4.","input_schema":{"type":"object","properties":{"file_path":{"type":"string"},"operation":{"type":"string","enum":["detect","decompress","nested_extract","try_all","list_contents"]},"output_dir":{"type":"string"},"max_depth":{"type":"integer"},"data_hex":{"type":"string"}},"required":[]}},
    {"name":"number_bases","description":"Extended base encoding/decoding wrapping basecrack (pip install basecrack \u2014 auto-detects base16/32/36/58/62/64/85/91/92) + pure Python implementations. Ops: auto (basecrack auto-detect), base85 (ASCII85/btoa a85+b85), base91 (base91 pure Python), base36, custom_b64 (base64 with non-standard alphabet), baudot (Baudot/ITA2 telegraph code), gray_code (Gray/reflected binary code), dna (ACGT DNA encoding 4 mappings), bcd (Binary-Coded Decimal). Decode or encode with direction=encode.","input_schema":{"type":"object","properties":{"text":{"type":"string"},"operation":{"type":"string","enum":["auto","base85","base91","base36","custom_b64","baudot","gray_code","dna","bcd"]},"alphabet":{"type":"string","description":"Custom 64-char alphabet for custom_b64"},"direction":{"type":"string","enum":["decode","encode"]}},"required":["text","operation"]}},
    {"name":"flag_extractor","description":"Scan any text or file for flag patterns, encoded flags, credentials, and interesting data. Ops: scan (find all flag patterns + try base64/hex/rot13/URL-decode each chunk for hidden flags), find_encoded (exhaustive encoding scan), find_credentials (extract username:password, API keys, Bearer tokens, secrets), interesting (URLs, IPs, emails, hex hashes). Works on output from any tool \u2014 pipe large strings through this to find the flag.","input_schema":{"type":"object","properties":{"text":{"type":"string"},"file_path":{"type":"string"},"ctf_name":{"type":"string","description":"CTF flag prefix e.g. picoCTF"},"operation":{"type":"string","enum":["scan","find_encoded","find_credentials","interesting","strings_flag"]},"patterns":{"type":"array","items":{"type":"string"}}},"required":[]}},
    {"name":"apt_orchestrator","description":"APT-level orchestration suite implementing deterministic attack lab, concolic/symbolic orchestration, stateful protocol learner, exploit candidate compiler, multi-source intelligence policy, adaptive challenge decomposition DAG, formal verifier gate artifacts, self-play red-team critic, benchmark/eval harness, and hardware side-channel modeling. operation=all generates all artifacts at once under apt_artifacts/.","input_schema":{"type":"object","properties":{"operation":{"type":"string","enum":["deterministic_lab","concolic_orchestrate","protocol_learner","exploit_compiler","intel_layer","adaptive_decompose","formal_verify","red_team_critic","benchmark_eval","side_channel_lab","all"]},"workspace":{"type":"string"},"workspace_path":{"type":"string"},"target":{"type":"string"},"profile":{"type":"string"},"binary_path":{"type":"string"},"find_addr":{"type":"string"},"avoid_addrs":{"type":"array","items":{"type":"string"}},"pcap_path":{"type":"string"},"protocol":{"type":"string"},"challenge_type":{"type":"string"},"seeds":{"type":"array","items":{"type":"string"}},"query":{"type":"string"},"description":{"type":"string"},"category":{"type":"string"},"candidate_flag":{"type":"string"},"evidence_paths":{"type":"array","items":{"type":"string"}},"replay_script":{"type":"string"},"conversation_summary":{"type":"string"},"api_key":{"type":"string"},"suite":{"type":"array","items":{"type":"string"}},"rounds":{"type":"integer"},"noise_sigma":{"type":"number"}},"required":["operation"]}},
]

TOOL_MAP = {
    "execute_shell":       lambda a: tool_execute_shell(a["command"],a.get("timeout",60),a.get("working_dir")),
    "execute_python":      lambda a: tool_execute_python(a["code"],a.get("timeout",60)),
    "decode_transform":    lambda a: tool_decode_transform(a["text"],a["method"],a.get("key"),a.get("key2")),
    "crypto_attack":       lambda a: tool_crypto_attack(a["attack"],**{k:v for k,v in a.items() if k!="attack"}),
    "http_request":        lambda a: tool_http_request(a["url"],a.get("method","GET"),a.get("headers"),a.get("data"),a.get("json_data"),a.get("cookies"),a.get("follow_redirects",True),a.get("verify_ssl",False),a.get("timeout",20)),
    "concurrent_requests": lambda a: tool_concurrent_requests(a["requests_list"],a.get("workers",50),a.get("timeout",5)),
    "tcp_connect":         lambda a: tool_tcp_connect(a["host"],a["port"],a.get("data"),a.get("data_hex"),a.get("timeout",10),a.get("read_until"),a.get("interactive_script")),
    "analyze_file":        lambda a: tool_analyze_file(a["path"],a["operation"]),
    "binary_analysis":     lambda a: tool_binary_analysis(a["path"],a["operation"],a.get("args")),
    "web_attack":          lambda a: tool_web_attack(a["attack"],a["target_url"],**{k:v for k,v in a.items() if k not in ("attack","target_url")}),
    "z3_solve":            lambda a: tool_z3_solve(a["constraints_code"]),
    "sage_math":           lambda a: tool_sage_math(a["code"]),
    "statistical_analysis":lambda a: tool_statistical_analysis(a["operation"],a["data"],**a.get("params",{})),
    "create_workspace":    lambda a: tool_create_workspace(a["base_dir"],a["ctf_name"],a["category"],a["challenge_name"]),
    "write_file":          lambda a: tool_write_file(a["path"],a["content"],a.get("mode","w")),
    "write_binary":        lambda a: tool_write_binary(a["path"],a["hex_content"]),
    "download_file":       lambda a: tool_download_file(a["url"],a["dest_path"],a.get("headers"),a.get("cookies")),
    "submit_flag":         lambda a: tool_submit_flag(a["flag"],a.get("challenge_id","")),
    "health_preflight":    lambda a: tool_health_preflight(a.get("scope","core")),
    "detect_flag_format":  lambda a: tool_detect_flag_format(a.get("ctf_name",""),a.get("description",""),a.get("platform_type",""),a.get("hint","")),
    "js_analyze":          lambda a: tool_js_analyze(a["url_or_path"],a["operation"]),
    "wasm_analyze":        lambda a: tool_wasm_analyze(a["path"],a["operation"]),
    "rng_crack":           lambda a: tool_rng_crack(a["operation"],a.get("outputs",[]),a.get("bits",32),a.get("modulus"),a.get("multiplier"),a.get("increment")),
    "mime_email":          lambda a: tool_mime_email(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "source_audit":        lambda a: tool_source_audit(a["path_or_content"],a["operation"],a.get("language")),
    "encoding_bypass":     lambda a: tool_encoding_bypass(a["text"],a["target_bypass"]),
    "docker_recon":        lambda a: tool_docker_recon(a["path"]),
    "custom_cpu_emulate":  lambda a: tool_custom_cpu_emulate(a["code"],a["operation"],timeout=a.get("timeout",120)),
    # ── Elite Intelligence Layer ─────────────────────────────────────────────
    "knowledge_store":     lambda a: tool_knowledge_store(a["ctf_name"],a["key"],a["value"]),
    "knowledge_get":       lambda a: tool_knowledge_get(a["ctf_name"]),
    "browser_agent":       lambda a: tool_browser_agent(a["url"],a["script"],a.get("timeout",60),a.get("capture_requests",False),a.get("capture_screenshot",False)),
    "ghidra_decompile":    lambda a: tool_ghidra_decompile(a["binary_path"],a.get("function_name","main"),a.get("all_functions",False),a.get("project_dir","/tmp/ghidra_proj")),
    "ai_rename_functions": lambda a: tool_ai_rename_functions(a["decompiled_output"],os.environ.get("ANTHROPIC_API_KEY",""),a.get("binary_path","")),
    "libc_lookup":         lambda a: tool_libc_lookup(a["leak_address"],a.get("symbol","puts"),a.get("extra_symbols")),
    "factordb":            lambda a: tool_factordb(a["n"]),
    "angr_solve":          lambda a: tool_angr_solve(a["binary_path"],a.get("find_addr",""),a.get("avoid_addrs"),a.get("stdin_len",64),a.get("custom_code",""),a.get("timeout",120)),
    "sqlmap":              lambda a: tool_sqlmap(a["target_url"],a.get("param",""),a.get("data",""),a.get("cookie",""),a.get("level",3),a.get("risk",2),a.get("technique","BEUSTQ"),a.get("dbms",""),a.get("extra_args","")),
    "ffuf":                lambda a: tool_ffuf(a["url"],a.get("wordlist","/usr/share/wordlists/dirb/common.txt"),a.get("extensions",""),a.get("method","GET"),a.get("headers"),a.get("filter_codes","404,400"),a.get("match_codes",""),a.get("data",""),a.get("fuzz_param","FUZZ"),a.get("timeout",60)),
    "web_crawl":           lambda a: tool_web_crawl(a["base_url"],a.get("max_depth",3),a.get("max_pages",100),a.get("headers"),a.get("cookies"),a.get("find_patterns")),
    "volatility":          lambda a: tool_volatility(a["image_path"],a["plugin"],a.get("args",""),a.get("timeout",120)),
    "frida_trace":         lambda a: tool_frida_trace(a.get("binary_path",""),a.get("script",""),a.get("function_hooks"),a.get("pid",0),a.get("timeout",30)),
    "rank_hypotheses":     lambda a: tool_rank_hypotheses(a["challenge_description"],a["category"],a["recon_results"],os.environ.get("ANTHROPIC_API_KEY","")),
    "pre_solve_recon":     lambda a: tool_pre_solve_recon(a.get("binary_path",""),a.get("url",""),a.get("category","Unknown")),
    "dlog":               lambda a: tool_dlog(a.get("operation","auto"),**{k:v for k,v in a.items() if k!="operation"}),
    "unicorn_emulate":    lambda a: tool_unicorn_emulate(a.get("arch","x86_64"),a.get("shellcode_hex",""),a.get("code_addr",0x1000),a.get("code",""),a.get("registers"),a.get("timeout",60)),
    "writeup_rag":        lambda a: tool_writeup_rag(a["description"],a["category"],a.get("ctf_name",""),a.get("db_path","~/.ctf-solver/writeups.db"),a.get("n_results",5)),
    "index_writeups":     lambda a: tool_index_writeups(a["writeups_dir"],a.get("db_path","~/.ctf-solver/writeups.db")),
    # ── APT Expansion ───────────────────────────────────────────────────────
    "heap_analysis":      lambda a: tool_heap_analysis(a["binary_path"],a["operation"],a.get("args","")),
    "kernel_info":        lambda a: tool_kernel_info(a["operation"],a.get("module_path",""),a.get("args","")),
    "seccomp_analyze":    lambda a: tool_seccomp_analyze(a["binary_path"],a.get("operation","dump")),
    "ret2dlresolve":      lambda a: tool_ret2dlresolve(a["binary_path"],a.get("target_func","system"),a.get("arg","/bin/sh")),
    "srop":               lambda a: tool_srop(a["binary_path"],a.get("operation","frame"),**{k:v for k,v in a.items() if k not in("binary_path","operation")}),
    "afl_fuzz":           lambda a: tool_afl_fuzz(a["binary_path"],a.get("input_dir","/tmp/afl_in"),a.get("output_dir","/tmp/afl_out"),a.get("timeout_ms",100),a.get("run_seconds",60),a.get("extra_args","")),
    "patchelf":           lambda a: tool_patchelf(a["binary_path"],a.get("libc_path",""),a.get("ld_path",""),a.get("operation","patch")),
    "coppersmith":        lambda a: tool_coppersmith(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "ecdsa_lattice":      lambda a: tool_ecdsa_lattice(a.get("operation","hnp"),**{k:v for k,v in a.items() if k!="operation"}),
    "lll":                lambda a: tool_lll(a["matrix_rows"],a.get("operation","lll"),**{k:v for k,v in a.items() if k not in("matrix_rows","operation")}),
    "aes_gcm_attack":     lambda a: tool_aes_gcm_attack(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),
    "bleichenbacher":     lambda a: tool_bleichenbacher(a["host"],a.get("port",443),a.get("operation","probe"),**{k:v for k,v in a.items() if k not in("host","port","operation")}),
    "http_smuggle":       lambda a: tool_http_smuggle(a["target_url"],a.get("operation","detect"),**{k:v for k,v in a.items() if k not in("target_url","operation")}),
    "graphql":            lambda a: tool_graphql(a["target_url"],a.get("operation","introspect"),a.get("query",""),a.get("headers"),a.get("cookies")),
    "websocket_fuzz":     lambda a: tool_websocket_fuzz(a["url"],a.get("operation","connect"),a.get("messages"),a.get("script",""),a.get("timeout",20)),
    "oauth_attack":       lambda a: tool_oauth_attack(a["target_url"],a.get("operation","probe"),a.get("client_id",""),a.get("redirect_uri","")),
    "cache_poison":       lambda a: tool_cache_poison(a["target_url"],a.get("operation","probe"),**{k:v for k,v in a.items() if k not in("target_url","operation")}),
    "shodan":             lambda a: tool_shodan(a["query"],a.get("operation","search"),a.get("api_key","")),
    "tls_decrypt":        lambda a: tool_tls_decrypt(a["pcap_path"],a.get("keylog_path",""),a.get("privkey_path",""),a.get("operation","decrypt"),a.get("filter_str","http")),
    "deobfuscate":        lambda a: tool_deobfuscate(a["binary_path"],a.get("operation","detect"),**{k:v for k,v in a.items() if k not in("binary_path","operation")}),
    "bytecode_disasm":    lambda a: tool_bytecode_disasm(a["input_path"],a.get("language","auto"),a.get("operation","disasm")),
    "audio_steg":         lambda a: tool_audio_steg(a["audio_path"],a.get("operation","analyze")),
    "git_forensics":      lambda a: tool_git_forensics(a["repo_path"],a.get("operation","all")),
    "triton_taint":       lambda a: tool_triton_taint(a["binary_path"],a.get("stdin_input",""),a.get("operation","trace")),
    "aeg_pipeline":       lambda a: tool_aeg_pipeline(a["binary_path"],a.get("operation","run"),a.get("fuzz_seconds",30),a.get("output_dir","/tmp/afl_out")),
    "docker_sandbox":     lambda a: tool_docker_sandbox(a["operation"],a.get("binary_path",""),a.get("exploit_code",""),a.get("libc_path",""),a.get("timeout",30)),
    "bindiff":            lambda a: tool_bindiff(a["binary_a"],a["binary_b"],a.get("operation","diff")),
    "encrypted_store":    lambda a: tool_encrypted_store(a["operation"],a.get("key",""),a.get("value",""),a.get("store_path","~/.ctf-solver/keystore.json")),
    "differential_cryptanalysis": lambda a: tool_differential_cryptanalysis(a["operation"],**{k:v for k,v in a.items() if k!="operation"}),

    # ── 53 gap-closing tools ──────────────────────────────────────────────────
    "2fa_bypass":           lambda a: tool_2fa_bypass(a.get("operation","probe"),a.get("target_url",""),a.get("param",""),a.get("method","POST"),a.get("headers"),a.get("cookies"),a.get("secret",""),a.get("token_length",6)),
    "android_vuln":         lambda a: tool_android_vuln(a.get("operation","scan"),a.get("target",""),a.get("package_name",""),a.get("device","usb"),a.get("extra","")),
    "apk_analyze":          lambda a: tool_apk_analyze(a["apk_path"],a.get("operation","all"),a.get("class_filter",""),a.get("output_dir","")),
    "apk_resign":           lambda a: tool_apk_resign(a["apk_path"],a.get("operation","full_pipeline"),a.get("patch_smali",""),a.get("target_class",""),a.get("output_path","")),
    "arm_rop":              lambda a: tool_arm_rop(a["binary_path"],a.get("operation","chain"),a.get("libc_path",""),a.get("arch","arm64"),a.get("goal","shell"),a.get("base_addr","0")),
    "asm_eval":             lambda a: tool_asm_eval(a["code_or_path"],a.get("operation","eval"),a.get("arch","x86_64"),a.get("entry","_start"),a.get("inputs",{}),a.get("steps",100)),
    "binary_patch":         lambda a: tool_binary_patch(a["binary_path"],a.get("operation","nop"),a.get("offset","0"),a.get("size",1),a.get("new_bytes",""),a.get("output_path",""),a.get("function_name",""),a.get("condition","")),
    "challenge_classifier":   lambda a: tool_challenge_classifier(a.get("description",""),a.get("files",[]),a.get("category_hint",""),a.get("use_api",False)),
    "cloud_forensics":      lambda a: tool_cloud_forensics(a["path"],a.get("operation","analyze"),a.get("cloud","auto"),a.get("keyword","")),
    "cors_exploit":         lambda a: tool_cors_exploit(a["target_url"],a.get("operation","probe"),a.get("origin",""),a.get("credentials",True),a.get("headers"),a.get("cookies")),
    "cpp_vtable":           lambda a: tool_cpp_vtable(a.get("binary_path",""),a.get("operation","detect"),a.get("target_class",""),a.get("rip_target","")),
    "disk_forensics":       lambda a: tool_disk_forensics(a["image_path"],a.get("operation","analyze"),a.get("partition",0),a.get("output_dir",""),a.get("keyword","")),
    "dom_xss":              lambda a: tool_dom_xss(a.get("operation","analyze"),a.get("url_or_path",""),a.get("html_content",""),a.get("sink",""),a.get("extra_payloads","")),
    "dotnet_decompile":     lambda a: tool_dotnet_decompile(a["binary_path"],a.get("operation","decompile"),a.get("type_name",""),a.get("method_name",""),a.get("output_path","")),
    "ebpf_exploit":         lambda a: tool_ebpf_exploit(a.get("operation","detect"),a.get("program_path",""),a.get("vuln_type","")),
    "ecc_special_attacks":    lambda a: tool_ecc_special_attacks(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),
    "ethereum_exploit":     lambda a: tool_ethereum_exploit(a.get("operation","analyze"),a.get("contract_source",""),a.get("contract_address",""),a.get("network","local"),a.get("target_function",""),a.get("value_eth","0")),
    "firmware_unpack":      lambda a: tool_firmware_unpack(a["firmware_path"],a.get("operation","analyze"),a.get("arch","auto"),a.get("output_dir","")),
    "flutter_re":           lambda a: tool_flutter_re(a.get("apk_path",""),a.get("binary_path",""),a.get("operation","detect")),
    "fsop":                 lambda a: tool_fsop(a.get("binary_path",""),a.get("operation","detect"),a.get("libc_path",""),a.get("target_func","system"),a.get("rip_control","0")),
    "gdb_remote":           lambda a: tool_gdb_remote(a["host"],a.get("port",1234),a.get("binary_path",""),a.get("operation","connect"),a.get("script",""),a.get("find_addr",""),a.get("avoid_addrs",[]),a.get("timeout",30)),
    "go_rev":               lambda a: tool_go_rev(a["binary_path"],a.get("operation","analyze"),a.get("output_dir","")),
    "hash_crack":           lambda a: tool_hash_crack(a["hash_value"],a.get("operation","auto"),a.get("wordlist","rockyou"),a.get("hash_type","")),
    "house_of_exploit":     lambda a: tool_house_of_exploit(a.get("binary_path",""),a.get("technique","detect"),a.get("libc_path",""),a.get("libc_version",""),a.get("target_addr","0"),a.get("cmd","/bin/sh")),
    "image_steg_advanced":  lambda a: tool_image_steg_advanced(a.get("image_path",""),a.get("operation","auto"),a.get("channel","all"),a.get("bit_plane",0),a.get("output_path","")),
    "ios_vuln":             lambda a: tool_ios_vuln(a.get("operation","scan"),a.get("target",""),a.get("bundle_id",""),a.get("device","usb")),
    "ipa_analyze":          lambda a: tool_ipa_analyze(a["ipa_path"],a.get("operation","all"),a.get("output_dir",""),a.get("class_filter","")),
    "java_sandbox":         lambda a: tool_java_sandbox(a.get("source_code",""),a.get("source_path",""),a.get("operation","run"),a.get("class_name","Main"),a.get("stdin_input",""),a.get("timeout",30)),
    "kernel_lpe":           lambda a: tool_kernel_lpe(a.get("operation","detect"),a.get("module_path",""),a.get("vuln_type",""),a.get("target_cred","commit_creds")),
    "node_exec":            lambda a: tool_node_exec(a.get("code",""),a.get("file_path",""),a.get("operation","run"),a.get("pattern","picoCTF{"),a.get("timeout",30)),
    "pcap_deep":            lambda a: tool_pcap_deep(a["pcap_path"],a.get("operation","summary"),a.get("key_path",""),a.get("output_dir",""),a.get("filter_expr",""),a.get("keyword","")),
    "pe_analysis":          lambda a: tool_pe_analysis(a["binary_path"],a.get("operation","info"),a.get("resource_type",""),a.get("output_dir","")),
    "polyglot_file":          lambda a: tool_polyglot_file(a.get("operation","list"),a.get("file_type_a","gif"),a.get("file_type_b","php"),a.get("content","<?php system($_GET['cmd']); ?>"),a.get("input_path",""),a.get("output_path","")),
    "powershell_deobf":     lambda a: tool_powershell_deobf(a.get("script_path",""),a.get("script_content",""),a.get("operation","deobfuscate")),
    "pqc_attack":           lambda a: tool_pqc_attack(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),
    "pyjail_escape":        lambda a: tool_pyjail_escape(a.get("operation","detect"),a.get("jail_code",""),a.get("available",""),a.get("blocked","")),
    "qr_decode":            lambda a: tool_qr_decode(a.get("image_path",""),a.get("operation","decode"),a.get("barcode_type","any"),a.get("data","")),
    "rop_chain":              lambda a: tool_rop_chain(a["binary_path"],a.get("operation","build"),a.get("goal","shell"),a.get("extra_gadgets",""),a.get("libc_path",""),a.get("base_addr","0")),
    "rust_sandbox":         lambda a: tool_rust_sandbox(a.get("source_code",""),a.get("source_path",""),a.get("operation","run"),a.get("patch",""),a.get("timeout",30)),
    "sdr_analyze":          lambda a: tool_sdr_analyze(a.get("file_path",""),a.get("operation","analyze"),a.get("frequency",0),a.get("sample_rate",0),a.get("modulation","auto")),
    "solve_resume":           lambda a: tool_solve_resume(a.get("operation","save"),a.get("session_id",""),a.get("state_path","~/.ctf-solver/sessions"),a.get("conversation"),a.get("metadata")),
    "ssh_exec":             lambda a: tool_ssh_exec(a["host"],a.get("port",22),a.get("username",""),a.get("password",""),a.get("key_path",""),a.get("operation","run_command"),a.get("command",""),a.get("remote_path",""),a.get("local_path",""),a.get("script","")),
    "ssl_pinning_bypass":   lambda a: tool_ssl_pinning_bypass(a.get("operation","frida"),a.get("target",""),a.get("package_name",""),a.get("method","auto")),
    "ssrf_chain":           lambda a: tool_ssrf_chain(a["target_url"],a.get("operation","probe"),a.get("param","url"),a.get("method","GET"),a.get("headers"),a.get("cookies"),a.get("internal_target",""),a.get("custom_payload","")),
    "ssti_rce":               lambda a: tool_ssti_rce(a.get("operation","detect"),a.get("engine","auto"),a.get("target_url",""),a.get("param",""),a.get("method","GET"),a.get("headers"),a.get("cookies"),a.get("custom_payload","")),
    "swagger_fuzz":         lambda a: tool_swagger_fuzz(a["target_url"],a.get("operation","discover"),a.get("endpoint",""),a.get("method","GET"),a.get("output_path",""),a.get("headers"),a.get("cookies")),
    "swift_decompile":      lambda a: tool_swift_decompile(a.get("binary_path",""),a.get("ipa_path",""),a.get("operation","analyze")),
    "vm_devirt":            lambda a: tool_vm_devirt(a["binary_path"],a.get("operation","detect"),a.get("handler_addr",""),a.get("opcode_map",{})),
    "windows_forensics":    lambda a: tool_windows_forensics(a["path"],a.get("operation","all"),a.get("output_dir",""),a.get("keyword","")),
    "xs_leak":              lambda a: tool_xs_leak(a["target_url"],a.get("operation","css_oracle"),a.get("secret_endpoint",""),a.get("secret_attr","secret"),a.get("charset","0123456789abcdef"),a.get("secret_len",32),a.get("upload_endpoint",""),a.get("visit_endpoint",""),a.get("output",{})),
    "zkp_attack":           lambda a: tool_zkp_attack(a.get("operation","detect"),**{k:v for k,v in a.items() if k!="operation"}),

    # ── previously missing dispatch entries ─────────────────────────────────
    "statistical_analysis":lambda a: tool_statistical_analysis(a["operation"],a["data"],**a.get("params",{})),
    "format_string_exploit":lambda a: tool_format_string_exploit(a.get("binary_path",""),a.get("host",""),a.get("port",0),a.get("operation","find_offset"),a.get("write_addr",""),a.get("write_val",""),a.get("offset",0)),
    "deserialization_exploit":lambda a: tool_deserialization_exploit(a["language"],a.get("operation","list"),a.get("gadget_chain",""),a.get("command","id"),a.get("output_format","base64"),a.get("extra_args","")),

    # ── 23 new tools ───────────────────────────────────────────────────────────
    "rsa_toolkit":  lambda a: tool_rsa_toolkit(a.get("operation","auto"),a.get("n",""),a.get("e","65537"),a.get("c",""),a.get("p",""),a.get("q",""),a.get("factors"),a.get("moduli"),a.get("output_file","")),
    "cbc_oracle":  lambda a: tool_cbc_oracle(a.get("operation","decrypt"),a.get("target_url",""),a.get("ciphertext_hex",""),a.get("block_size",16),a.get("oracle_param","cipher"),a.get("method","POST"),a.get("encoding","hex"),a.get("headers"),a.get("cookies"),a.get("known_plaintext","")),
    "vigenere_crack":  lambda a: tool_vigenere_crack(a["ciphertext"],a.get("operation","crack"),a.get("key_length",0),a.get("known_key","")),
    "side_channel":  lambda a: tool_side_channel(a.get("operation","timing_attack"),a.get("target_url",""),a.get("param","password"),a.get("charset","abcdefghijklmnopqrstuvwxyz0123456789"),a.get("known_prefix",""),a.get("secret_len",32),a.get("method","POST"),a.get("samples",5),a.get("headers"),a.get("cookies"),a.get("measurements")),
    "one_gadget":  lambda a: tool_one_gadget(a.get("libc_path",""),a.get("operation","find"),a.get("leak_addr",""),a.get("leak_symbol","puts"),a.get("constraints")),
    "pwn_template":  lambda a: tool_pwn_template(a.get("binary_path",""),a.get("host",""),a.get("port",0),a.get("operation","generate"),a.get("vuln_type","auto"),a.get("libc_path","")),
    "heap_visualize":  lambda a: tool_heap_visualize(a.get("operation","parse_state"),a.get("gdb_output",""),a.get("binary_path",""),a.get("pid",0)),
    "libc_database":  lambda a: tool_libc_database(a.get("operation","search"),a.get("leak_addr",""),a.get("symbol","puts"),a.get("extra_symbols"),a.get("build_id",""),a.get("arch","amd64")),
    "string_decryptor":  lambda a: tool_string_decryptor(a.get("binary_path",""),a.get("operation","floss"),a.get("key",""),a.get("algorithm","auto"),a.get("decompiled_code","")),
    "license_check":  lambda a: tool_license_check(a.get("binary_path",""),a.get("operation","hook_comparisons"),a.get("username","user"),a.get("input_value",""),a.get("timeout",30)),
    "proto_decode":  lambda a: tool_proto_decode(a.get("operation","decode"),a.get("data",""),a.get("binary_path",""),a.get("output_format","json")),
    "jwt_forge":  lambda a: tool_jwt_forge(a.get("token",""),a.get("operation","analyze"),a.get("pubkey_path",""),a.get("secret",""),a.get("attacker_url",""),a.get("kid","/dev/null"),a.get("payload_overrides"),a.get("wordlist","/usr/share/wordlists/rockyou.txt")),
    "nosql_inject":  lambda a: tool_nosql_inject(a["target_url"],a.get("operation","probe"),a.get("param","username"),a.get("password_param","password"),a.get("method","POST"),a.get("charset","0123456789abcdefghijklmnopqrstuvwxyz"),a.get("headers"),a.get("cookies"),a.get("field","username"),a.get("data_format","form")),
    "file_upload":  lambda a: tool_file_upload(a["target_url"],a.get("operation","probe"),a.get("upload_param","file"),a.get("code_param",""),a.get("code_content",""),a.get("filename","test.php"),a.get("output_dir","/tmp/upload_test"),a.get("headers"),a.get("cookies")),
    "template_inject":  lambda a: tool_template_inject(a.get("target_url",""),a.get("operation","probe"),a.get("param","input"),a.get("method","GET"),a.get("engine","auto"),a.get("headers"),a.get("cookies"),a.get("data","")),
    "steg_brute":  lambda a: tool_steg_brute(a["image_path"],a.get("operation","auto"),a.get("wordlist","/usr/share/wordlists/rockyou.txt"),a.get("output_dir","/tmp/steg_extracted")),
    "pcap_reassemble":  lambda a: tool_pcap_reassemble(a["pcap_path"],a.get("operation","auto"),a.get("output_dir",""),a.get("stream_id",0),a.get("filter_expr",""),a.get("keyword","")),
    "pdf_forensics":  lambda a: tool_pdf_forensics(a["pdf_path"],a.get("operation","analyze"),a.get("output_dir","")),
    "image_repair":  lambda a: tool_image_repair(a["image_path"],a.get("operation","detect"),a.get("width",0),a.get("height",0),a.get("output_path","")),
    "compression":  lambda a: tool_compression(a.get("file_path",""),a.get("operation","detect"),a.get("output_dir",""),a.get("max_depth",10),a.get("data_hex","")),
    "number_bases":  lambda a: tool_number_bases(a["text"],a.get("operation","auto"),a.get("alphabet",""),a.get("direction","decode")),
    "flag_extractor":  lambda a: tool_flag_extractor(a.get("text",""),a.get("file_path",""),a.get("ctf_name","picoCTF"),a.get("operation","scan"),a.get("patterns")),
    "apt_orchestrator": lambda a: tool_apt_orchestrator(**a),
}

# ─── Advanced intelligence tool registration (phase-1 MVP) ───────────────────
_ADVANCED_TOOL_NAMES = [
    "ai_fuzzer", "grammar_infer", "protocol_learn", "stateful_fuzz",
    "constraint_fusion", "symbolic_pipeline",
    "generate_exploit_script", "generate_decoder", "generate_emulator", "generate_patch",
    "lift_to_ir", "ir_symbolic_exec", "ir_diff",
    "protocol_reverse", "message_fuzzer", "state_machine_recovery",
    "function_classifier", "crypto_detector", "obfuscation_classifier",
    "fault_injection_sim", "timing_attack_sim", "power_trace_analyzer",
    "pattern_mine_writeups", "attack_graph_builder",
    "chain_builder", "attack_path_finder",
    "ctf_heuristics", "category_strategy", "strategy_optimizer",
    "branch_knowledge_share", "solution_merger",
    "ctf_pattern_classifier", "exploit_simulation", "exploit_safety_check",
    "paper_search", "attack_research",
    "protocol_auto_decode", "dns_exfil_detect", "covert_channel_detect",
    "neural_steg_detector", "image_layer_decompose", "frequency_steg",
    "vm_unpacker", "custom_vm_solver", "control_flow_recovery",
    "auto_exploit_loop",
]

for _name in _ADVANCED_TOOL_NAMES:
    _tool_name = f"tool_{_name}"
    if not any(t.get("name") == _tool_name for t in TOOLS):
        TOOLS.append({
            "name": _tool_name,
            "description": f"Advanced intelligence capability: {_name}.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "object",
                        "description": "Tool-specific arguments."
                    }
                },
                "required": []
            }
        })

_adv = __import__("tools.advanced_intel", fromlist=["*"])

TOOL_MAP.update({
    "tool_ai_fuzzer": lambda a: _adv.tool_ai_fuzzer(**a),
    "tool_grammar_infer": lambda a: _adv.tool_grammar_infer(**a),
    "tool_protocol_learn": lambda a: _adv.tool_protocol_learn(**a),
    "tool_stateful_fuzz": lambda a: _adv.tool_stateful_fuzz(**a),
    "tool_constraint_fusion": lambda a: _adv.tool_constraint_fusion(**a),
    "tool_symbolic_pipeline": lambda a: _adv.tool_symbolic_pipeline(**a),
    "tool_generate_exploit_script": lambda a: _adv.tool_generate_exploit_script(**a),
    "tool_generate_decoder": lambda a: _adv.tool_generate_decoder(**a),
    "tool_generate_emulator": lambda a: _adv.tool_generate_emulator(**a),
    "tool_generate_patch": lambda a: _adv.tool_generate_patch(**a),
    "tool_lift_to_ir": lambda a: _adv.tool_lift_to_ir(**a),
    "tool_ir_symbolic_exec": lambda a: _adv.tool_ir_symbolic_exec(**a),
    "tool_ir_diff": lambda a: _adv.tool_ir_diff(**a),
    "tool_protocol_reverse": lambda a: _adv.tool_protocol_reverse(**a),
    "tool_message_fuzzer": lambda a: _adv.tool_message_fuzzer(**a),
    "tool_state_machine_recovery": lambda a: _adv.tool_state_machine_recovery(**a),
    "tool_function_classifier": lambda a: _adv.tool_function_classifier(**a),
    "tool_crypto_detector": lambda a: _adv.tool_crypto_detector(**a),
    "tool_obfuscation_classifier": lambda a: _adv.tool_obfuscation_classifier(**a),
    "tool_fault_injection_sim": lambda a: _adv.tool_fault_injection_sim(**a),
    "tool_timing_attack_sim": lambda a: _adv.tool_timing_attack_sim(**a),
    "tool_power_trace_analyzer": lambda a: _adv.tool_power_trace_analyzer(**a),
    "tool_pattern_mine_writeups": lambda a: _adv.tool_pattern_mine_writeups(**a),
    "tool_attack_graph_builder": lambda a: _adv.tool_attack_graph_builder(**a),
    "tool_chain_builder": lambda a: _adv.tool_chain_builder(**a),
    "tool_attack_path_finder": lambda a: _adv.tool_attack_path_finder(**a),
    "tool_ctf_heuristics": lambda a: _adv.tool_ctf_heuristics(**a),
    "tool_category_strategy": lambda a: _adv.tool_category_strategy(**a),
    "tool_strategy_optimizer": lambda a: _adv.tool_strategy_optimizer(**a),
    "tool_branch_knowledge_share": lambda a: _adv.tool_branch_knowledge_share(**a),
    "tool_solution_merger": lambda a: _adv.tool_solution_merger(**a),
    "tool_ctf_pattern_classifier": lambda a: _adv.tool_ctf_pattern_classifier(**a),
    "tool_exploit_simulation": lambda a: _adv.tool_exploit_simulation(**a),
    "tool_exploit_safety_check": lambda a: _adv.tool_exploit_safety_check(**a),
    "tool_paper_search": lambda a: _adv.tool_paper_search(**a),
    "tool_attack_research": lambda a: _adv.tool_attack_research(**a),
    "tool_protocol_auto_decode": lambda a: _adv.tool_protocol_auto_decode(**a),
    "tool_dns_exfil_detect": lambda a: _adv.tool_dns_exfil_detect(**a),
    "tool_covert_channel_detect": lambda a: _adv.tool_covert_channel_detect(**a),
    "tool_neural_steg_detector": lambda a: _adv.tool_neural_steg_detector(**a),
    "tool_image_layer_decompose": lambda a: _adv.tool_image_layer_decompose(**a),
    "tool_frequency_steg": lambda a: _adv.tool_frequency_steg(**a),
    "tool_vm_unpacker": lambda a: _adv.tool_vm_unpacker(**a),
    "tool_custom_vm_solver": lambda a: _adv.tool_custom_vm_solver(**a),
    "tool_control_flow_recovery": lambda a: _adv.tool_control_flow_recovery(**a),
    "tool_auto_exploit_loop": lambda a: _adv.tool_auto_exploit_loop(**a),
})


def _looks_structured_json(s: str) -> bool:
    try:
        obj = json.loads(s)
        return isinstance(obj, dict) and {"status", "confidence", "output"}.issubset(obj.keys())
    except Exception:
        return False


def _normalize_tool_result(tool_name: str, raw: object) -> str:
    if isinstance(raw, str) and _looks_structured_json(raw):
        return raw
    if isinstance(raw, dict) and {"status", "confidence", "output"}.issubset(raw.keys()):
        try:
            return json.dumps(raw, ensure_ascii=False)
        except Exception:
            pass
    text = str(raw)
    low = text.lower()
    bad = (
        low.startswith("tool error:")
        or low.startswith("tool timeout")
        or low.startswith("unknown tool:")
        or ("traceback" in low)
        or ('"status": "error"' in low)
    )
    payload = {
        "tool": tool_name,
        "status": "error" if bad else "ok",
        "confidence": 0.35 if bad else 0.82,
        "artifacts": [],
        "next_action": "Inspect output and proceed with recommended follow-up tool.",
        "output": text,
    }
    return json.dumps(payload, ensure_ascii=False)


def _wrap_tool_callable(name: str, fn):
    def _wrapped(args):
        try:
            raw = fn(args)
            return _normalize_tool_result(name, raw)
        except Exception as e:
            return _normalize_tool_result(name, f"Tool error: {type(e).__name__}: {e}")
    return _wrapped


for _tool_name, _tool_fn in list(TOOL_MAP.items()):
    TOOL_MAP[_tool_name] = _wrap_tool_callable(_tool_name, _tool_fn)

# ─── CTF-scoped knowledge graph ───────────────────────────────────────────────
_ctf_knowledge: dict = defaultdict(dict)  # ctf_name → {key: value}
_solve_start_time: float = 0.0
_current_model_display: str = ""
_critic_threshold: int = 6  # trigger critic after this many fruitless iterations

# Tools that require outbound network access (filtered in local-only / air-gapped mode)
_NETWORK_TOOLS: set = {
    "http_request",
    "concurrent_requests",
    "tcp_connect",
    "web_attack",
    "browser_agent",
    "sqlmap",
    "ffuf",
    "web_crawl",
    "http_smuggle",
    "graphql",
    "websocket_fuzz",
    "shodan",
    "whatweb",
    "nmap_scan",
    "dns_lookup",
}


