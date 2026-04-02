"""Miscellaneous / utility tools."""
from __future__ import annotations
import re, subprocess, os, shutil, hashlib, json, threading, time, base64, importlib
import sys
from pathlib import Path

from tools.shell import (
    IS_WINDOWS,
    USE_WSL,
    _w2l,
    _shell,
    emit,
    log,
    tool_execute_python,
)
from flag.extractor import extract_flag
from memory.knowledge_graph import KnowledgeGraphStore


_PLATFORM_CONFIG: dict = {}


def _json_result(tool: str, status: str = "ok", confidence: float = 0.8,
                 artifacts: list[str] | None = None, next_action: str = "",
                 output: object = "") -> str:
    try:
        payload = {
            "tool": tool,
            "status": status,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "artifacts": artifacts or [],
            "next_action": next_action,
            "output": output,
        }
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return str(output)


_KG_STORE = KnowledgeGraphStore()


def tool_knowledge_store(ctf_name: str, key: str, value: str) -> str:
    ctf = (ctf_name or "unknown").strip() or "unknown"
    k = (key or "").strip()
    if not k:
        return _json_result("knowledge_store", status="error", confidence=0.0,
                            next_action="Provide a non-empty key.",
                            output="missing key")
    _KG_STORE.upsert_fact(ctf, k, str(value))
    return _json_result(
        "knowledge_store",
        confidence=0.95,
        artifacts=[_KG_STORE.db_path],
        next_action="Call knowledge_get at solve start to inject prior facts.",
        output={"ctf_name": ctf, "key": k, "stored": True},
    )


def tool_knowledge_get(ctf_name: str) -> str:
    ctf = (ctf_name or "unknown").strip() or "unknown"
    flat = _KG_STORE.get_facts(ctf)
    return _json_result(
        "knowledge_get",
        confidence=0.9,
        artifacts=[_KG_STORE.db_path] if os.path.exists(_KG_STORE.db_path) else [],
        next_action="Use returned facts to prioritize likely attack vectors.",
        output={"ctf_name": ctf, "count": len(flat), "facts": flat},
    )


def tool_detect_flag_format(ctf_name: str = "", description: str = "",
                            platform_type: str = "", hint: str = "") -> str:
    text = " ".join([ctf_name or "", description or "", hint or ""]).strip()
    matches = re.findall(r"([A-Za-z0-9_]{2,24})\{", text)
    prefix = ""
    if hint and "{" in hint:
        prefix = hint.split("{", 1)[0]
    elif matches:
        prefix = matches[0]
    elif ctf_name:
        m = re.search(r"([A-Za-z0-9_]+)", ctf_name)
        prefix = m.group(1) if m else "flag"
    else:
        prefix = "flag"
    prefix = prefix.strip("_") or "flag"
    pattern = rf"{re.escape(prefix)}\{{[^\n\r\t\x00]{{4,200}}\}}"
    example = f"{prefix}{{example_payload}}"
    confidence = 0.95 if matches or (hint and "{" in hint) else 0.7
    return _json_result(
        "detect_flag_format",
        confidence=confidence,
        next_action="Use this regex in all grep/scan steps and re-run if prefix drifts.",
        output={
            "prefix": prefix,
            "pattern": pattern,
            "example": example,
            "platform_type": platform_type or "unknown",
            "source": "hint_or_description" if (matches or hint) else "heuristic",
        },
    )


def tool_flag_extractor(text: str = "", file_path: str = "", ctf_name: str = "picoCTF",
                        operation: str = "scan", patterns: list[str] | None = None) -> str:
    raw = text or ""
    if file_path:
        try:
            with open(file_path, "rb") as f:
                blob = f.read()
            raw = blob.decode("utf-8", errors="replace")
        except Exception as e:
            return _json_result("flag_extractor", status="error", confidence=0.0,
                                next_action="Provide valid text or readable file path.",
                                output=f"read failed: {e}")

    rules = patterns or []
    prefix = re.sub(r"[^A-Za-z0-9_]", "", (ctf_name or "flag").split()[0]) or "flag"
    rules.extend([
        rf"{re.escape(prefix)}\{{[^\n\r\t\x00]{{4,220}}\}}",
        r"flag\{[^\n\r\t\x00]{4,220}\}",
        r"ctf\{[^\n\r\t\x00]{4,220}\}",
    ])

    found: list[str] = []
    for rgx in rules:
        try:
            found.extend(re.findall(rgx, raw, flags=re.IGNORECASE))
        except Exception:
            pass

    if operation in ("scan", "find_encoded"):
        chunks = re.findall(r"[A-Za-z0-9+/=]{24,}|[A-Fa-f0-9]{24,}", raw)
        for chunk in chunks[:400]:
            try:
                if len(chunk) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", chunk):
                    dec = base64.b64decode(chunk + "===", validate=False).decode("utf-8", errors="ignore")
                    found.extend(re.findall(rf"{re.escape(prefix)}\{{[^\n\r\t]{{4,220}}\}}", dec, flags=re.IGNORECASE))
                if re.fullmatch(r"[A-Fa-f0-9]+", chunk) and len(chunk) % 2 == 0:
                    dec2 = bytes.fromhex(chunk).decode("utf-8", errors="ignore")
                    found.extend(re.findall(rf"{re.escape(prefix)}\{{[^\n\r\t]{{4,220}}\}}", dec2, flags=re.IGNORECASE))
            except Exception:
                pass

    uniq = sorted({f.strip() for f in found if f and "{" in f and "}" in f})
    return _json_result(
        "flag_extractor",
        confidence=0.9 if uniq else 0.5,
        artifacts=[file_path] if file_path else [],
        next_action="Validate top candidate with submit_flag.",
        output={"matches": uniq[:30], "count": len(uniq)},
    )


def tool_pre_solve_recon(binary_path: str = "", url: str = "", category: str = "Unknown") -> str:
    cat = (category or "unknown").lower()
    findings: dict[str, str] = {}
    artifacts: list[str] = []

    def _run(cmd: str, timeout_s: int = 12) -> str:
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s)
            out = (p.stdout or "") + (p.stderr or "")
            return out[:2000]
        except Exception as ex:
            return f"command failed: {ex}"

    if url:
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            r = requests.get(url, timeout=12, verify=False)
            body = (r.text or "")[:3000]
            links = sorted(set(re.findall(r'href=["\']([^"\']+)', body, flags=re.I)))[:40]
            findings["http"] = f"HTTP {r.status_code} {r.reason} len={len(r.text)}"
            findings["crawl"] = "\n".join(["links:"] + links)
        except Exception as ex:
            findings["http"] = f"request failed: {ex}"
    if binary_path:
        findings["file"] = _run(f"file '{binary_path}'")
        findings["strings"] = _run(f"strings '{binary_path}' | head -80")
        artifacts.append(binary_path)
        if cat in ("pwn", "reverse", "rev", "binary"):
            findings["checksec"] = _run(f"checksec --file='{binary_path}' 2>/dev/null || echo checksec_unavailable")
            findings["functions"] = _run(f"nm '{binary_path}' 2>/dev/null | head -120")
    if not findings:
        return _json_result("pre_solve_recon", status="error", confidence=0.0,
                            next_action="Provide binary_path and/or url.", output="no target")
    return _json_result(
        "pre_solve_recon",
        confidence=0.88,
        artifacts=artifacts,
        next_action="Feed recon output into rank_hypotheses for ordered attack plan.",
        output=findings,
    )


def tool_rank_hypotheses(challenge_description: str, category: str,
                         recon_results: str, api_key: str = "") -> str:
    text = (challenge_description or "") + "\n" + (recon_results or "")
    cat = (category or "unknown").lower()
    scored = []
    candidates = [
        ("sqli", ["sql", "union", "sqlite", "database"], ["sqlmap", "http_request"]),
        ("ssti", ["template", "jinja", "twig", "render"], ["ssti_rce", "template_inject"]),
        ("ssrf", ["fetch", "url=", "metadata", "localhost"], ["ssrf_chain", "http_request"]),
        ("ret2libc", ["puts", "plt", "got", "libc"], ["libc_lookup", "rop_chain"]),
        ("heap_uaf", ["malloc", "free", "tcache", "double free"], ["heap_analysis", "house_of_exploit"]),
        ("rsa", ["rsa", "modulus", "ciphertext", "e="], ["rsa_toolkit", "factordb"]),
        ("steg", ["image", "png", "lsb", "steg"], ["image_steg_advanced", "steg_brute"]),
    ]
    low = text.lower()
    for name, keys, tools in candidates:
        score = sum(1 for k in keys if k in low)
        if cat and name.startswith(cat[:3]):
            score += 1
        if score > 0:
            scored.append({"hypothesis": name, "score": score, "recommended_tools": tools})
    if not scored:
        scored = [{"hypothesis": "generic_recon", "score": 1,
                   "recommended_tools": ["pre_solve_recon", "challenge_classifier", "flag_extractor"]}]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return _json_result(
        "rank_hypotheses",
        confidence=0.84,
        next_action="Execute top-ranked tool chain, then rerank with new evidence.",
        output={"category": category, "ranked": scored[:5]},
    )


def tool_health_preflight(scope: str = "core") -> str:
    scope = (scope or "core").lower()
    shell_cmds = {
        "core": ["python3", "bash", "curl", "strings", "file", "objdump", "tshark"],
        "web": ["sqlmap", "ffuf", "nmap"],
        "pwn": ["gdb", "ROPgadget", "checksec", "patchelf"],
        "mobile": ["adb", "apktool", "jadx", "apksigner"],
        "forensics": ["binwalk", "exiftool", "zbarimg", "foremost"],
    }
    py_mods = {
        "core": ["requests", "z3", "sympy"],
        "web": ["playwright", "jwt", "websocket"],
        "pwn": ["pwn", "angr"],
        "mobile": ["frida", "androguard"],
        "forensics": ["PIL", "pyzbar"],
    }
    cmd_list = shell_cmds.get(scope, shell_cmds["core"])
    mod_list = py_mods.get(scope, py_mods["core"])

    cmd_status: dict[str, bool] = {}
    for cmd in cmd_list:
        cmd_status[cmd] = shutil.which(cmd) is not None

    mod_status: dict[str, bool] = {}
    for mod in mod_list:
        try:
            __import__(mod)
            mod_status[mod] = True
        except Exception:
            mod_status[mod] = False

    total = len(cmd_status) + len(mod_status)
    ok = sum(1 for v in list(cmd_status.values()) + list(mod_status.values()) if v)
    ratio = (ok / total) if total else 0.0
    confidence = min(0.95, 0.76 + (0.2 * ratio))
    unavailable = [k for k, v in {**cmd_status, **mod_status}.items() if not v]
    next_action = "Install missing dependencies and re-run preflight." if unavailable else "Environment healthy."

    return _json_result(
        "health_preflight",
        status="ok",
        confidence=confidence,
        next_action=next_action,
        output={
            "scope": scope,
            "health_state": "healthy" if ratio >= 0.75 else "degraded",
            "healthy_ratio": round(ratio, 3),
            "commands": cmd_status,
            "python_modules": mod_status,
            "unavailable": unavailable,
        },
    )


def tool_writeup_rag(description: str, category: str, ctf_name: str = "",
                      db_path: str = "~/.ctf-solver/writeups.db", n_results: int = 5) -> str:
    """
    Retrieve similar CTF writeups from local ChromaDB vector store.
    Returns top-N writeups by semantic similarity — lets Claude recall
    known-good approaches for near-identical past challenges.
    Build the DB once with: tool_index_writeups('/path/to/writeup/dir').
    """
    db_expanded = os.path.expanduser(db_path)
    code = f"""
import os
try:
    import chromadb
    client=chromadb.PersistentClient(path={repr(db_expanded)})
    try: col=client.get_collection("writeups")
    except: print("DB not found. Build with: tool_index_writeups('/path/to/writeups/')"); exit()
    q=f"{category}: {description[:800]}"
    r=col.query(query_texts=[q],n_results=min({n_results},col.count()),include=["documents","metadatas","distances"])
    for i,(doc,meta,dist) in enumerate(zip(r["documents"][0],r["metadatas"][0],r["distances"][0])):
        print(f"\\n[{{i+1}}] {{meta.get('title','?')}} | {{meta.get('ctf','?')}} | sim={{1-dist:.2f}}")
        print(doc[:2500])
except ImportError: print("pip install chromadb")
"""
    return tool_execute_python(code, timeout=20)


def tool_index_writeups(writeups_dir: str, db_path: str = "~/.ctf-solver/writeups.db") -> str:
    """
    Index a directory of CTF writeups (.md/.txt) into ChromaDB for RAG retrieval.
    Run once. Then tool_writeup_rag uses it at solve time automatically.
    """
    db_expanded = os.path.expanduser(db_path)
    code = f"""
import os, re, hashlib; from pathlib import Path
wd={repr(writeups_dir)}; db={repr(db_expanded)}
try:
    import chromadb
    os.makedirs(db,exist_ok=True)
    c=chromadb.PersistentClient(path=db)
    try: c.delete_collection("writeups")
    except: pass
    col=c.create_collection("writeups",metadata={{"hnsw:space":"cosine"}})
    files=list(Path(wd).rglob("*.md"))+list(Path(wd).rglob("*.txt"))
    print(f"Indexing {{len(files)}} files from {{wd}}")
    bd=[]; bi=[]; bm=[]; cnt=0
    for f in files:
        try:
            txt=f.read_text(encoding='utf-8',errors='replace')
            if len(txt)<80: continue
            parts=f.parts
            tm=re.search(r'^#{{1,2}}\\s+(.+)',txt,re.MULTILINE)
            title=(tm.group(1) if tm else f.stem)[:100]
            bd.append(txt[:8000]); bi.append(hashlib.md5(str(f).encode()).hexdigest())
            bm.append({{"title":title,"ctf":(parts[-3] if len(parts)>=3 else "")[:50],
                        "category":(parts[-2] if len(parts)>=2 else "")[:50],"path":str(f)[:200]}})
            if len(bd)>=100:
                col.add(documents=bd,ids=bi,metadatas=bm); cnt+=len(bd)
                print(f"  {{cnt}} indexed..."); bd.clear(); bi.clear(); bm.clear()
        except: pass
    if bd: col.add(documents=bd,ids=bi,metadatas=bm); cnt+=len(bd)
    print(f"Done! {{cnt}} writeups indexed into {{db}}")
except ImportError: print("pip install chromadb")
"""
    return tool_execute_python(code, timeout=300)


def tool_statistical_analysis(operation, data, **params):
    """Statistical tools for side-channel attacks, LRU oracle, timing analysis."""
    code = f"""
import math, json
from collections import Counter

operation = '{operation}'
data_raw = {json.dumps(data)}

if operation == 'log_likelihood_ratio':
    # data should be {{'true_hits': [k0,k1,k2,...], 'false_hits': [k0,k1,k2,...]}}
    # where each k = number of replicas that survived out of n
    true_hits  = data_raw.get('true_hits', [])
    false_hits = data_raw.get('false_hits', [])
    n_replicas = data_raw.get('n_replicas', 3)
    t_hist = [0]*(n_replicas+1)
    f_hist = [0]*(n_replicas+1)
    for k in true_hits:  t_hist[min(k,n_replicas)]+=1
    for k in false_hits: f_hist[min(k,n_replicas)]+=1
    t_total=sum(t_hist); f_total=sum(f_hist)
    eps=0.5
    llr=[]
    for k in range(n_replicas+1):
        tp=max(t_hist[k],eps)/max(t_total,1)
        fp=max(f_hist[k],eps)/max(f_total,1)
        llr.append(math.log(tp/fp))
    print("LLR table:", [round(x,3) for x in llr])
    print("Interpretation: positive=likely matched, negative=likely missed")

elif operation == 'beam_search':
    # Reconstruct a string from scored n-gram evidence
    import heapq
    alphabet   = data_raw.get('alphabet', '0123456789abcdef')
    target_len = data_raw.get('target_len', 32)
    ngram_scores= data_raw.get('ngram_scores', {{}})  # {{'abc': 2.1, 'xyz': -1.5}}
    beam_width = data_raw.get('beam_width', 1000)
    prefix_scores = data_raw.get('prefix_scores', {{}})
    suffix_scores = data_raw.get('suffix_scores', {{}})

    # Seed with all possible starting n-grams
    seed_len = min(3, target_len)
    candidates = []
    for combo in __import__('itertools').product(alphabet, repeat=seed_len):
        s = ''.join(combo)
        score = ngram_scores.get(s, 0)
        if s[:2] in prefix_scores: score += prefix_scores[s[:2]]
        candidates.append((score, s))

    candidates.sort(reverse=True)
    candidates = candidates[:beam_width]

    for pos in range(seed_len, target_len):
        new_candidates = []
        for score, s in candidates:
            for c in alphabet:
                new_s = s + c
                new_score = score
                # Score new trigram
                if pos >= 2:
                    trigram = new_s[-3:]
                    new_score += ngram_scores.get(trigram, 0)
                # Bigram
                bigram = new_s[-2:]
                new_score += ngram_scores.get(bigram, 0) * 0.5
                new_candidates.append((new_score, new_s))
        new_candidates.sort(reverse=True)
        candidates = new_candidates[:beam_width]

    # Add suffix scores
    final = []
    for score, s in candidates:
        if s[-2:] in suffix_scores: score += suffix_scores[s[-2:]]
        final.append((score, s))
    final.sort(reverse=True)
    print("Top 10 candidates:")
    for score, s in final[:10]:
        print(f"  {{s}} (score={{score:.3f}})")

elif operation == 'frequency_analysis':
    text = data_raw if isinstance(data_raw, str) else str(data_raw)
    chars = [c.upper() for c in text if c.isalpha()]
    freq = Counter(chars)
    total = len(chars)
    en_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    obs_order = ''.join(c for c,_ in freq.most_common())
    print(f"Total letters: {{total}}")
    print("Top 10 frequencies:")
    for c,n in freq.most_common(10):
        print(f"  {{c}}: {{n}} ({{100*n/total:.1f}}%) — maps to {{en_order[obs_order.index(c)] if obs_order.index(c)<len(en_order) else '?'}}")

elif operation == 'timing_analysis':
    times = data_raw if isinstance(data_raw, list) else []
    if times:
        avg=sum(times)/len(times); std=math.sqrt(sum((t-avg)**2 for t in times)/len(times))
        print(f"Count: {{len(times)}}, Mean: {{avg:.4f}}s, Std: {{std:.4f}}s")
        print(f"Min: {{min(times):.4f}}s, Max: {{max(times):.4f}}s")
        outliers=[t for t in times if abs(t-avg)>2*std]
        print(f"Outliers (>2σ): {{outliers}}")

elif operation == 'index_of_coincidence':
    text = data_raw if isinstance(data_raw, str) else ''
    text = ''.join(c.upper() for c in text if c.isalpha())
    n=len(text); freq=Counter(text)
    ic=sum(f*(f-1) for f in freq.values())/(n*(n-1)) if n>1 else 0
    print(f"IC = {{ic:.4f}} (English≈0.065, random≈0.038)")
    print("High IC = monoalphabetic cipher (Caesar, Atbash)")
    print("Low IC  = polyalphabetic cipher (Vigenere, OTP)")
"""
    return tool_execute_python(code)


def tool_create_workspace(base_dir, ctf_name, category, challenge_name):
    try:
        def safe(s):
            s=re.sub(r'[<>:"/\\|?*]',"_",s.strip())
            return re.sub(r'\s+'," ",s)[:80]
        folder=os.path.join(base_dir,safe(ctf_name),safe(category),safe(challenge_name))
        os.makedirs(os.path.join(folder,"files"),exist_ok=True)
        os.makedirs(os.path.join(folder,"exploits"),exist_ok=True)
        os.makedirs(os.path.join(folder,"artifacts"),exist_ok=True)
        log("sys",f"Workspace: {folder}","")
        emit("workspace",path=folder)
        return f"Workspace created: {folder}\nSubdirs: files/ exploits/ artifacts/"
    except Exception as e: return f"Workspace error: {e}"


def tool_write_file(path, content, mode="w"):
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path,mode,encoding="utf-8") as f: f.write(content)
        size=os.path.getsize(path)
        log("sys",f"Wrote {size}B → {path}","")
        if path.endswith(".md"): emit("writeup",path=path)
        return f"Saved: {path} ({size} bytes)"
    except Exception as e: return f"Write error: {e}"


def tool_write_binary(path, hex_content):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
        with open(path,"wb") as f: f.write(bytes.fromhex(hex_content.replace(" ","")))
        return f"Written {os.path.getsize(path)} bytes to {path}"
    except Exception as e: return f"Write binary error: {e}"


def tool_download_file(url, dest_path, headers=None, cookies=None):
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)),exist_ok=True)
        resp=requests.get(url,headers=headers or {},cookies=cookies or {},
                          stream=True,timeout=60,verify=False)
        resp.raise_for_status()
        with open(dest_path,"wb") as f:
            for chunk in resp.iter_content(8192): f.write(chunk)
        size=os.path.getsize(dest_path)
        log("sys",f"Downloaded {size}B → {dest_path}","")
        return f"Downloaded: {dest_path} ({size} bytes)"
    except Exception as e: return f"Download error: {e}"


def tool_submit_flag(flag, challenge_id=""):
    flag=flag.strip()
    runtime_cfg = dict(_PLATFORM_CONFIG) if isinstance(_PLATFORM_CONFIG, dict) else {}
    if not runtime_cfg:
        try:
            from solver import engine as _engine
            candidate = getattr(_engine, "_PLATFORM_CONFIG", {})
            if isinstance(candidate, dict):
                runtime_cfg = dict(candidate)
        except Exception:
            runtime_cfg = {}

    if not runtime_cfg or runtime_cfg.get("type")=="manual":
        return f"Manual mode — submit flag:\n{flag}"
    try:
        sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
        from platforms import submit_flag_to_platform
        res=submit_flag_to_platform(runtime_cfg,challenge_id or runtime_cfg.get("challenge_id",""),flag)
        if res.get("error"): return f"Submission error: {res['error']}"
        if res.get("correct") is True:
            log("ok","✓ Flag accepted!","white")
            return f"CORRECT! {flag}"
        elif res.get("correct") is False:
            return f"INCORRECT. {res.get('message','')}"
        return f"Response: {res}"
    except Exception as e: return f"Submit error: {e}"


def tool_docker_sandbox(operation: str, binary_path: str = "", exploit_code: str = "",
                          libc_path: str = "", timeout: int = 30) -> str:
    """Docker-isolated exploit testing: setup, run_exploit, local_test."""
    if operation == "setup":
        return _shell("docker pull ubuntu:22.04 2>&1 | tail -3", timeout=60)
    if operation == "run_exploit":
        if not exploit_code: return "Provide exploit_code (pwntools Python string)"
        ef = f"/tmp/exploit_{int(time.time())}.py"
        with open(ef,"w") as f: f.write(exploit_code)
        bn = os.path.basename(binary_path)
        _shell(f"cp '{binary_path}' /tmp/{bn} 2>/dev/null")
        vols = f"-v /tmp/{bn}:/pwn/{bn}:ro -v {ef}:/pwn/exploit.py:ro"
        if libc_path:
            ln = os.path.basename(libc_path); _shell(f"cp '{libc_path}' /tmp/{ln}")
            vols += f" -v /tmp/{ln}:/pwn/{ln}:ro"
        out = _shell(f"docker run --rm --network=none --memory=256m {vols} --entrypoint python3 ubuntu:22.04 /pwn/exploit.py 2>&1", timeout=timeout+10)
        flag = extract_flag(out)
        return f"{out}\n{'FLAG: '+flag if flag else 'No flag in output'}"
    if operation == "local_test":
        ef = f"/tmp/exploit_{int(time.time())}.py"
        with open(ef,"w") as f: f.write(exploit_code)
        out = _shell(f"timeout {timeout} python3 {ef} 2>&1")
        return out
    return "Available: setup, run_exploit, local_test"


def tool_encrypted_store(operation: str, key: str = "", value: str = "",
                           store_path: str = "~/.ctf-solver/keystore.json") -> str:
    """Persistent encrypted keystore for API keys and credentials. Set CTF_SOLVER_MASTER env for password."""
    store_path = os.path.expanduser(store_path)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    code = f"""import json,os,base64,hashlib; from pathlib import Path
op,kn,val,sp = {repr(operation)},{repr(key)},{repr(value)},{repr(store_path)}
def derive(master,salt): return hashlib.pbkdf2_hmac(\'sha256\',master,salt,100000,32)
def get_master():
    mp=os.environ.get(\'CTF_SOLVER_MASTER\',\'\')
    if not mp:
        import getpass; mp=getpass.getpass(\'Master password: \')
    return mp.encode()
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM; HAVE=True
except ImportError: HAVE=False; print(\'pip install cryptography (for encryption)\')
store=json.loads(Path(sp).read_text()) if Path(sp).exists() else {{}}
if op==\'set\':\n    if HAVE:\n        m=get_master(); s=os.urandom(16); n=os.urandom(12)\n        ct=AESGCM(derive(m,s)).encrypt(n,val.encode(),None)\n        store[kn]={{\'s\':.b64e(s),\'n\':.b64e(n),\'c\':.b64e(ct)}}\n    else: store[kn]=val\n    Path(sp).write_text(json.dumps(store,indent=2)); print(f\'Stored: {{kn}}\')
elif op==\'get\':\n    e=store.get(kn); \n    if not e: print(f\'Not found: {{kn}}\'); exit()\n    if HAVE and isinstance(e,dict):\n        m=get_master()\n        try: print(f\'{{kn}}: {{AESGCM(derive(m,b64d(e[\'s\']))).decrypt(b64d(e[\'n\']),b64d(e[\'c\']),None).decode()}}\')\n        except: print(\'Wrong password\')\n    else: print(f\'{{kn}}: {{e}}\')
elif op==\'list\': [print(f\'  {{k}}\') for k in store]
elif op==\'delete\': store.pop(kn,None); Path(sp).write_text(json.dumps(store,indent=2)); print(f\'Deleted: {{kn}}\')
""".replace(".b64e(","base64.b64encode(").replace("b64d(","base64.b64decode(")
    return tool_execute_python(code, timeout=30)


def tool_challenge_classifier(description: str = "", files: list = None,
                                category_hint: str = "",
                                use_api: bool = False) -> str:
    """Predict challenge type, likely techniques, and recommended tools from description + file list.
    Uses keyword/pattern matching (fast, no API) or Claude API (slow, accurate)."""

    # ── Keyword-based classifier (no API needed) ──────────────────────────────
    text = (description + " " + " ".join(files or []) + " " + category_hint).lower()

    SIGNATURES = {
        # PWN
        "tcache_uaf":       (["tcache","use-after-free","uaf","free","double free","chunk"], ["heap"]),
        "stack_bof":        (["overflow","bof","buffer","segfault","stack","ret2","rop"], ["pwn","binary"]),
        "ret2libc":         (["libc","plt","got","system","binsh","/bin/sh","ret2libc"], ["pwn"]),
        "format_string":    (["format string","printf","%s %p","%n","fmt"], ["pwn"]),
        "heap_grooming":    (["largebin","fastbin","unsorted","consolidate","heap spray"], ["pwn","heap"]),
        "kernel_pwn":       (["kernel","lkm","module","ioctl","/dev/","cred","commit_creds"], ["pwn"]),
        "rop_chain":        (["rop","gadget","chain","sigreturn","srop","ret2csu","ret2plt"], ["pwn"]),
        "srop":             (["sigreturn","srop","signal frame","sigframe"], ["pwn"]),
        # CRYPTO
        "rsa_basic":        (["rsa","modulus","exponent","private key","public key","crt","decrypt"], ["crypto"]),
        "ecc":              (["elliptic curve","ecc","ecdsa","secp","weierstrass","montgomery","point"], ["crypto"]),
        "aes_cbc":          (["aes","cbc","padding oracle","pkcs","iv","mode"], ["crypto"]),
        "hash_length_ext":  (["hash length","extension","sha1","sha256","md5","secret prefix"], ["crypto"]),
        "lwe_lattice":      (["lwe","sis","lattice","knapsack","shortest vector","lll","hnf"], ["crypto"]),
        "prng_crack":       (["seed","rand()","random","mersenne","mt19937","prng"], ["crypto"]),
        # WEB
        "sqli":             (["sql injection","sqli","union select","order by","' or","-- -","sleep("], ["web"]),
        "xss":              (["xss","cross-site","script","alert(","onerror","cookie theft"], ["web"]),
        "ssti":             (["template injection","ssti","jinja","twig","freemarker","{{","}}"], ["web"]),
        "ssrf":             (["ssrf","server-side request","internal","169.254","localhost","metadata"], ["web"]),
        "deserialization":  (["deseriali","pickle","unserialize","yaml.load","marshal","ysoserial"], ["web"]),
        "xxe":              (["xxe","xml external","dtd","entity","<!entity","file:///"], ["web"]),
        "jwt_attack":       (["jwt","json web token","none algorithm","hs256","rs256","alg"], ["web"]),
        "path_traversal":   (["path traversal","../","directory traversal","lfi","rfi","include"], ["web"]),
        "race_condition":   (["race condition","toctou","concurrent","limit","double-spend"], ["web","pwn"]),
        # REV
        "vm_escape":        (["vm","bytecode","interpreter","virtual machine","opcode","dispatch"], ["rev"]),
        "obfuscation":      (["obfuscat","packed","upx","ollvm","mba","cff","anti-debug"], ["rev"]),
        "custom_cipher":    (["custom crypto","xor key","encrypt","decrypt","cipher","substitution"], ["rev","crypto"]),
        # FORENSICS
        "steganography":    (["steg","hidden","lsb","wav","png","jpeg","strings","metadata"], ["forensics","misc"]),
        "memory_forensics": (["memory dump","volatility","vmem","memdump","process","memory"], ["forensics"]),
        "pcap_analysis":    (["pcap","wireshark","network","tcp","packet","tls","traffic"], ["forensics"]),
    }

    # Scoring
    scores = {}
    for tech, (keywords, categories) in SIGNATURES.items():
        score = sum(1 for kw in keywords if kw in text)
        # Boost if category matches
        if category_hint.lower() in categories:
            score += 2
        if score > 0:
            scores[tech] = score

    ranked = sorted(scores.items(), key=lambda x: -x[1])

    # Tool recommendations per technique
    TOOL_MAP_RECS = {
        "tcache_uaf":       ["heap_analysis", "binary_analysis", "ghidra_decompile", "libc_lookup"],
        "stack_bof":        ["rop_chain", "binary_analysis", "angr_solve", "ret2dlresolve"],
        "ret2libc":         ["rop_chain", "libc_lookup", "patchelf", "binary_analysis"],
        "format_string":    ["binary_analysis", "angr_solve", "execute_shell"],
        "heap_grooming":    ["heap_analysis", "binary_analysis", "ghidra_decompile"],
        "kernel_pwn":       ["kernel_info", "seccomp_analyze", "binary_analysis"],
        "rop_chain":        ["rop_chain", "binary_analysis", "srop", "ret2dlresolve"],
        "srop":             ["srop", "rop_chain", "binary_analysis"],
        "rsa_basic":        ["crypto_attack", "factordb", "sage_math", "coppersmith"],
        "ecc":              ["ecc_special_attacks", "sage_math", "ecdsa_lattice", "dlog"],
        "aes_cbc":          ["crypto_attack", "aes_gcm_attack", "execute_python"],
        "hash_length_ext":  ["crypto_attack", "execute_shell"],
        "lwe_lattice":      ["lll", "sage_math", "execute_python"],
        "prng_crack":       ["rng_crack", "execute_python"],
        "sqli":             ["sqlmap", "web_attack", "source_audit"],
        "xss":              ["web_attack", "source_audit", "browser_agent"],
        "ssti":             ["ssti_rce", "web_attack", "source_audit"],
        "ssrf":             ["web_attack", "http_request", "source_audit"],
        "deserialization":  ["deserialization_exploit", "source_audit", "web_attack"],
        "xxe":              ["web_attack", "source_audit", "http_request"],
        "jwt_attack":       ["web_attack", "crypto_attack", "source_audit"],
        "path_traversal":   ["web_attack", "ffuf", "source_audit"],
        "race_condition":   ["concurrent_requests", "web_attack", "execute_shell"],
        "vm_escape":        ["custom_cpu_emulate", "ghidra_decompile", "bytecode_disasm"],
        "obfuscation":      ["deobfuscate", "ghidra_decompile", "binary_analysis"],
        "custom_cipher":    ["decode_transform", "statistical_analysis", "z3_solve"],
        "steganography":    ["analyze_file", "execute_shell", "audio_steg"],
        "memory_forensics": ["volatility", "execute_shell"],
        "pcap_analysis":    ["tls_decrypt", "execute_shell"],
    }

    if not ranked:
        fallback = "No strong signal. Suggest: pre_solve_recon → rank_hypotheses"
        if use_api:
            fallback += "\n(API classification unavailable without strong signal)"
        return fallback

    lines = [f"=== Challenge Classifier ===\n"]
    lines.append(f"Top predictions (keyword score):")
    for tech, score in ranked[:5]:
        tools_rec = TOOL_MAP_RECS.get(tech, ["execute_shell", "execute_python"])
        lines.append(f"  [{score:2d}] {tech}")
        lines.append(f"       Recommended tools: {', '.join(tools_rec[:4])}")

    if ranked:
        best_tech = ranked[0][0]
        lines.append(f"\n=== Primary classification: {best_tech} ===")
        lines.append(f"Confidence: {'high' if ranked[0][1] >= 4 else 'medium' if ranked[0][1] >= 2 else 'low'}")

        # Attack narrative
        narratives = {
            "tcache_uaf": "Likely tcache UAF. Check glibc version (libc_lookup), find UAF primitive, forge tcache entry to get arbitrary write, overwrite __free_hook or use_after_free to hijack control flow.",
            "stack_bof": "Stack buffer overflow. Find offset with cyclic(), build ROP chain (rop_chain tool), leak libc base via puts@plt, then ret2libc or execve syscall.",
            "rsa_basic": "RSA challenge. Check n for factordb, small e (e=3 eth root), same n (GCD), Wiener (large d), Coppersmith for partial plaintext/key.",
            "ecc": "ECC challenge. Run ecc_special_attacks detect to check: anomalous (Smart's), low embedding degree (MOV), smooth order (Pohlig-Hellman), or ECDSA nonce bias (ecdsa_lattice).",
            "ssti": "SSTI detected. Use ssti_rce detect to fingerprint engine, then ssti_rce escalate to get RCE payloads with sandbox escape chains.",
            "deserialization": "Deserialization vulnerability. Use deserialization_exploit list to find available gadget chains, then generate payload for the target language/framework.",
            "sqli": "SQL injection. Run sqlmap with level=3,risk=2, try UNION, error-based, time-based blind. Check OOB if blind.",
        }
        if best_tech in narratives:
            lines.append(f"\nAttack narrative:\n  {narratives[best_tech]}")

    if use_api:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            lines.append("\n[API classification requested — use rank_hypotheses tool for API-based analysis]")
        else:
            lines.append("\n[API classification: ANTHROPIC_API_KEY not set]")

    return "\n".join(lines)


def tool_ethereum_exploit(operation: str = "analyze", contract_source: str = "",
                           contract_address: str = "", network: str = "local",
                           target_function: str = "", value_eth: str = "0") -> str:
    """Ethereum/Solidity CTF exploitation. Ops: analyze (detect vulns), reentrancy,
    integer_overflow, access_control, selfdestruct, delegatecall, flash_loan,
    storage_collision, front_run, tx_origin, setup (local hardhat/foundry env)."""

    if operation == "analyze":
        code = f"""
import re
src = {repr(contract_source)}
if not src:
    print("Provide contract_source (Solidity code)")
    print()
    print("Common Solidity vulnerability patterns to search for:")
    patterns = [
        ("Reentrancy", r'call\\.value|call{{value|transfer|send', "Use checks-effects-interactions or ReentrancyGuard"),
        ("tx.origin", r'tx\\.origin', "tx.origin auth bypass — use msg.sender"),
        ("Integer overflow", r'\\+|\\*|\\-', "SafeMath not used (Solidity < 0.8.0)"),
        ("Selfdestruct", r'selfdestruct|suicide', "Forcibly send ETH to any contract"),
        ("Delegatecall", r'delegatecall', "Storage collision, logic injection"),
        ("Uninitialized storage", r'function.*storage', "Pointer to slot 0 by default"),
        ("Weak randomness", r'block\\.number|block\\.timestamp|blockhash', "Miner-manipulable"),
        ("Access control", r'onlyOwner|require.*owner|msg\\.sender ==', "Check if properly enforced"),
        ("Flash loan", r'uniswap|flashloan|borrow', "Price manipulation via flash loans"),
    ]
    for name, pattern, desc in patterns:
        print(f"  {{name}}: {{desc}}")
else:
    print("=== Solidity Vulnerability Analysis ===")
    vulns = []
    if re.search(r'\\.call\\.value|call{{value:', src):
        # Check for reentrancy: external call before state update
        if re.search(r'call.*value.*\\n.*(?:balance|state|mapping)\\s*[-+]?=', src, re.DOTALL):
            vulns.append("REENTRANCY: external call before state update!")
        else:
            vulns.append("External ETH call found — verify checks-effects-interactions order")
    if 'tx.origin' in src:
        vulns.append("tx.origin: Authentication bypassed if user is contract")
    if re.search(r'block\\.(timestamp|number|difficulty|blockhash)', src):
        vulns.append("Weak randomness: block properties predictable by miners")
    if 'selfdestruct' in src or 'suicide(' in src:
        vulns.append("selfdestruct present — can force ETH into contract, break assumptions")
    if 'delegatecall' in src:
        vulns.append("delegatecall: storage collision possible if proxy pattern")
    # Check for SafeMath (Solidity < 0.8)
    if not re.search(r'pragma solidity \\^0\\.[89]\\.|using SafeMath', src):
        vulns.append("No SafeMath + old Solidity version: integer overflow/underflow risk")
    if 'mapping' in src and re.search(r'function.*public.*payable', src):
        if not re.search(r'require.*msg\\.sender|onlyOwner|modifier', src):
            vulns.append("Unprotected public payable function — anyone can call")
    for v in vulns:
        print(f"[!] {{v}}")
    if not vulns:
        print("No obvious vulnerabilities detected. Manual review recommended.")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "reentrancy":
        return f"[reentrancy] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "selfdestruct":
        return f"[selfdestruct] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "delegatecall":
        return f"[delegatecall] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "tx_origin":
        return f"[tx_origin] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "setup":
        return (_shell("which foundry 2>/dev/null || which forge 2>/dev/null; "
                      "which hardhat 2>/dev/null; which anvil 2>/dev/null", timeout=5) +
                "\nFoundry setup:\n"
                "  curl -L https://foundry.paradigm.xyz | bash\n"
                "  foundryup\n"
                "  forge init exploit_ctf && cd exploit_ctf\n\n"
                "Quick exploit template:\n"
                "  // test/Exploit.t.sol\n"
                "  pragma solidity ^0.8.13;\n"
                "  import 'forge-std/Test.sol';\n"
                "  import '../src/Target.sol';\n\n"
                "  contract ExploitTest is Test {\n"
                "    Target target;\n"
                "    function setUp() public { target = new Target{value: 10 ether}(); }\n"
                "    function test_exploit() public {\n"
                "      // your exploit here\n"
                "      assertEq(target.isSolved(), true);\n"
                "    }\n"
                "  }\n"
                "  forge test -vvvv")

    if operation == "flash_loan":
        return f"[flash_loan] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "storage_collision":
        return f"[storage_collision] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("Ethereum exploit operations:\n"
            "  analyze          — detect vulnerabilities in Solidity source\n"
            "  reentrancy       — cross-function/read-only reentrancy attack\n"
            "  selfdestruct     — force ETH send to break balance assumptions\n"
            "  delegatecall     — storage collision via proxy pattern\n"
            "  tx_origin        — tx.origin auth bypass\n"
            "  flash_loan       — price manipulation via flash loan\n"
            "  storage_collision— slot layout / uninitialized pointer exploit\n"
            "  setup            — Foundry/Hardhat environment setup\n"
            "  integer_overflow — SafeMath bypass (Solidity < 0.8)\n"
            "  access_control   — unprotected function exploitation")


def tool_sdr_analyze(file_path: str = "", operation: str = "analyze",
                      frequency: float = 0, sample_rate: float = 0,
                      modulation: str = "auto") -> str:
    """SDR/RF signal analysis: analyze (file inspection), demodulate (AM/FM/FSK/BPSK/QPSK),
    spectrum (frequency plot), decode_ook (On-Off Keying), decode_dtmf, morse,
    ook_to_binary, replay (generate replay payload)."""

    if operation == "analyze":
        if not file_path:
            return ("SDR analysis tools reference:\n\n"
                    "File formats: .wav, .iq, .cf32 (complex float32), .cs8, .cu8\n\n"
                    "Tools available:\n"
                    "  sox          — WAV inspection and conversion\n"
                    "  inspectrum   — visual spectrum analyzer (GUI)\n"
                    "  GNU Radio    — signal processing flowgraphs\n"
                    "  rtl_433      — common IoT protocol decoder (433MHz)\n"
                    "  multimon-ng  — POCSAG/DTMF/EAS decoder\n"
                    "  baudline      — spectrogram visualization\n"
                    "  gqrx/SDR#   — real-time SDR receiver\n\n"
                    "Quick decode commands:\n"
                    "  rtl_433 -r file.iq -f 433.92M -s 250000\n"
                    "  multimon-ng -t wav -a ALL file.wav\n"
                    "  sox file.wav -n stat  (audio statistics)\n"
                    "  python3 -c \"import numpy as np; d=np.fromfile('file.cf32',np.complex64); print(d.shape)\"")

        fp = _w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path
        return _shell(f"file '{fp}'; soxi '{fp}' 2>/dev/null; sox '{fp}' -n stat 2>&1 | head -20; "
                     f"strings '{fp}' | head -10", timeout=15)

    if operation == "demodulate":
        fp = _w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path
        mod = modulation.lower()
        if mod in ("am", "auto"):
            return _shell(f"sox '{fp}' -t wav /tmp/demod_am.wav gain -h 2>/dev/null && "
                         f"multimon-ng -t wav -a ALL /tmp/demod_am.wav 2>&1 | head -30 || "
                         f"echo 'Try: python3 -c \"import scipy.io.wavfile as w; import numpy as np; "
                         f"sr,d=w.read(\\'{fp}\\'); print(np.abs(d[:1000])[:20])\"'",
                         timeout=20)
        if mod in ("ook", "on-off keying"):
            return tool_sdr_analyze(file_path=file_path, operation="decode_ook", sample_rate=sample_rate)
        code = f"""
try:
    import numpy as np
    import scipy.signal as sig
    data = np.fromfile({repr(fp)}, dtype=np.complex64 if '.cf32' in {repr(fp)} or '.iq' in {repr(fp)} else np.int16)
    if data.dtype == np.int16:
        data = data.astype(np.float32) / 32768.0
    print(f"Samples: {{len(data)}}, dtype: {{data.dtype}}")
    sr = {sample_rate or 250000}
    mod = {repr(mod)}
    if mod == 'fm':
        # FM demodulation
        if np.iscomplexobj(data):
            demod = np.angle(data[1:] * np.conj(data[:-1]))
        else:
            demod = np.diff(np.unwrap(np.angle(data[:len(data)//2] + 1j*data[len(data)//2:])))
        print(f"FM demodulated: {{demod[:20]}}")
    elif mod in ('fsk', 'bpsk', 'qpsk'):
        print(f"{{mod.upper()}} demodulation requires GNU Radio or liquid-dsp")
        print(f"  GNU Radio: create flowgraph with GMSK/DPSK/PSK demod block")
        print(f"  liquid-dsp: modem_create({mod.upper()}) → modem_demodulate()")
    else:
        print(f"Auto-detect: checking for known IoT protocols...")
        import subprocess
        r = subprocess.run(['rtl_433', '-r', {repr(fp)},
                           '-f', str({frequency or 433920000})],
                          capture_output=True, text=True, timeout=15)
        print(r.stdout[:500] or r.stderr[:300])
except ImportError as ex:
    print(f"scipy/numpy not available: {{ex}}")
    print(f"Run: multimon-ng -t wav -a ALL {repr(fp)}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "decode_ook":
        code = f"""
try:
    import numpy as np
    fp = {repr(file_path)}
    sr = {sample_rate or 250000}
    data = np.fromfile(fp, dtype=np.float32) if '.cf32' not in fp else np.fromfile(fp, dtype=np.complex64)
    if np.iscomplexobj(data):
        data = np.abs(data)  # envelope detection
    # Simple threshold
    threshold = (data.max() + data.min()) / 2
    bits = (data > threshold).astype(int)
    # Run-length encode
    from itertools import groupby
    runs = [(k, sum(1 for _ in g)) for k, g in groupby(bits)]
    print(f"OOK runs (value, length): {{runs[:30]}}")
    # Estimate bit width
    durations = [r[1] for r in runs if r[1] > 5]
    if durations:
        bit_width = min(durations)
        print(f"Estimated bit width: {{bit_width}} samples = {{bit_width/sr*1000:.2f}}ms")
        decoded = ''.join(str(v) * (round(l/bit_width)) for v,l in runs)
        print(f"Decoded bits: {{decoded[:100]}}")
        # Try ASCII
        for i in range(0, len(decoded)-7, 8):
            byte = int(decoded[i:i+8], 2)
            if 32 <= byte <= 126:
                print(chr(byte), end='')
        print()
except Exception as ex:
    import traceback; traceback.print_exc()
"""
        return tool_execute_python(code, timeout=20)

    if operation == "spectrum":
        code = f"""
try:
    import numpy as np
    fp = {repr(file_path)}
    sr = {sample_rate or 250000}
    data = np.fromfile(fp, dtype=np.complex64 if ('.iq' in fp or '.cf32' in fp) else np.float32)
    fft = np.fft.fftshift(np.fft.fft(data[:min(len(data), 8192)]))
    freqs = np.fft.fftshift(np.fft.fftfreq(len(fft), 1/sr))
    mag = 20*np.log10(np.abs(fft)+1e-10)
    # Simple ASCII spectrum
    n_bins = 60
    bin_width = len(mag)//n_bins
    for i in range(0, len(mag)-bin_width, bin_width):
        bucket = mag[i:i+bin_width]
        level = int((bucket.max() - mag.min()) / (mag.max() - mag.min() + 1e-10) * 20)
        freq_hz = freqs[i + bin_width//2]
        bar = '█' * level
        print(f"{{freq_hz/1000:7.1f}}kHz |{{bar}}")
except Exception as ex:
    print(f"Spectrum error: {{ex}}")
    print(f"Install scipy+numpy for spectrum analysis")
"""
        return tool_execute_python(code, timeout=15)

    return "Operations: analyze, demodulate, decode_ook, spectrum, decode_dtmf, replay"


def tool_solve_resume(operation: str = "save", session_id: str = "",
                       state_path: str = "~/.ctf-solver/sessions",
                       conversation: list = None, metadata: dict = None) -> str:
    """Serialize/deserialize conversation state for long solves. Prevents losing progress
    on costly Opus runs. Save mid-solve; resume from checkpoint at any iteration."""
    import json as _json
    state_dir = os.path.expanduser(state_path)
    os.makedirs(state_dir, exist_ok=True)

    if not session_id:
        session_id = f"session_{int(time.time())}"

    sf = os.path.join(state_dir, f"{session_id}.json")

    if operation == "save":
        state = {
            "session_id": session_id,
            "saved_at": time.time(),
            "iteration": metadata.get("iteration", 0) if metadata else 0,
            "challenge": metadata.get("challenge", "") if metadata else "",
            "category": metadata.get("category", "") if metadata else "",
            "conversation_turns": len(conversation) if conversation else 0,
            "conversation": conversation or [],
            "metadata": metadata or {},
            "flags_found": metadata.get("flags_found", []) if metadata else [],
            "hypotheses": metadata.get("hypotheses", []) if metadata else [],
            "workspace": metadata.get("workspace", "") if metadata else "",
        }
        try:
            with open(sf, "w") as f:
                _json.dump(state, f, indent=2, ensure_ascii=False, default=str)
            size = os.path.getsize(sf)
            log("sys", f"[resume] Saved session {session_id} ({size} bytes, "
                f"{state['conversation_turns']} turns, iter {state['iteration']})", "green")
            return (f"Session saved: {sf}\n"
                    f"  ID: {session_id}\n"
                    f"  Turns: {state['conversation_turns']}\n"
                    f"  Iteration: {state['iteration']}\n"
                    f"  Size: {size} bytes\n"
                    f"To resume: solve_resume(operation='load', session_id='{session_id}')")
        except Exception as e:
            return f"Save failed: {e}"

    if operation == "load":
        if not os.path.exists(sf):
            # Try to find most recent session
            sessions = sorted(Path(state_dir).glob("*.json"),
                              key=lambda p: p.stat().st_mtime, reverse=True)
            if sessions:
                sf = str(sessions[0])
                log("sys", f"[resume] session_id not found, loading most recent: {sf}", "yellow")
            else:
                return f"No sessions found in {state_dir}"
        try:
            with open(sf) as f:
                state = _json.load(f)
            age_min = (time.time() - state.get("saved_at", 0)) / 60
            return (f"Session loaded: {sf}\n"
                    f"  ID: {state.get('session_id', '?')}\n"
                    f"  Challenge: {state.get('challenge', '?')}\n"
                    f"  Category: {state.get('category', '?')}\n"
                    f"  Saved: {age_min:.1f}m ago\n"
                    f"  Iteration: {state.get('iteration', 0)}\n"
                    f"  Turns: {state.get('conversation_turns', 0)}\n"
                    f"  Workspace: {state.get('workspace', '?')}\n"
                    f"  Hypotheses: {state.get('hypotheses', [])}\n"
                    f"  Flags found: {state.get('flags_found', [])}\n"
                    f"  Metadata: {_json.dumps(state.get('metadata', {}), indent=2)}")
        except Exception as e:
            return f"Load failed: {e}"

    if operation == "list":
        sessions = sorted(Path(state_dir).glob("*.json"),
                          key=lambda p: p.stat().st_mtime, reverse=True)
        if not sessions:
            return f"No sessions in {state_dir}"
        lines = [f"Sessions in {state_dir}:"]
        for sp in sessions[:20]:
            try:
                with open(sp) as f:
                    s = _json.load(f)
                age_min = (time.time() - s.get("saved_at", 0)) / 60
                lines.append(f"  {sp.stem}: {s.get('challenge','?')} "
                              f"iter={s.get('iteration',0)} "
                              f"({age_min:.0f}m ago)")
            except:
                lines.append(f"  {sp.stem}: (unreadable)")
        return "\n".join(lines)

    if operation == "delete":
        if os.path.exists(sf):
            os.remove(sf)
            return f"Deleted: {sf}"
        return f"Session not found: {sf}"

    if operation == "checkpoint":
        # Auto-name from metadata
        cname = (metadata or {}).get("challenge", "unknown")
        sid = re.sub(r"[^a-z0-9_]", "_", cname.lower()) + f"_{int(time.time())}"
        return tool_solve_resume("save", sid, state_path, conversation, metadata)

    return "Operations: save, load, list, delete, checkpoint"


def tool_ssh_exec(host: str, port: int = 22, username: str = "",
                  password: str = "", key_path: str = "",
                  operation: str = "run_command", command: str = "",
                  remote_path: str = "", local_path: str = "",
                  script: str = "") -> str:
    """SSH connection with password/key auth, command execution, SCP file download,
    and interactive protocol for game challenges (Binary Search etc.).
    Ops: run_command (exec + return stdout), scp_download (pull file to local),
    interactive_game (shell session driven by script lines), connect (probe only)."""

    kp = (_w2l(key_path) if (IS_WINDOWS and USE_WSL) else key_path) if key_path else ""

    try:
        paramiko = importlib.import_module("paramiko")
    except Exception:
        return "paramiko not installed — run: pip install paramiko"

    def _client():
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = dict(hostname=host, port=port, username=username, timeout=15)
        if kp:     kw["key_filename"] = kp
        elif password: kw["password"] = password
        else:      kw["allow_agent"] = True
        c.connect(**kw)
        return c

    if operation == "connect":
        try:
            c = _client()
            transport = c.get_transport()
            banner = str(transport.remote_version) if transport else "connected"
            c.close()
            return f"Connected to {host}:{port}\nBanner: {banner}"
        except Exception as ex:
            return f"Connection failed: {ex}"

    if operation == "run_command":
        if not command:
            return "Provide command="
        try:
            c = _client()
            stdin, stdout, stderr = c.exec_command(command, timeout=30)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            c.close()
            full = out + ("\n[stderr]\n" + err if err.strip() else "")
            return full.strip() or "(no output)"
        except Exception as ex:
            return f"SSH exec error: {ex}"

    if operation == "scp_download":
        if not remote_path:
            return "Provide remote_path="
        lp = local_path or f"/tmp/scp_{os.path.basename(remote_path)}_{int(time.time())}"
        try:
            scp_mod = importlib.import_module("scp")
            SCPClient = getattr(scp_mod, "SCPClient")
        except Exception:
            # fallback: use paramiko SFTP
            try:
                c = _client()
                sftp = c.open_sftp()
                sftp.get(remote_path, lp)
                sftp.close(); c.close()
                sz = os.path.getsize(lp)
                grep = _shell(f"strings '{lp}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -10", timeout=8)
                return f"Downloaded {sz} bytes → {lp}\nFlag scan:\n{grep}"
            except Exception as ex:
                return f"SFTP fallback error: {ex}"
        try:
            c = _client()
            with SCPClient(c.get_transport()) as scp:
                scp.get(remote_path, lp)
            c.close()
            sz = os.path.getsize(lp)
            grep = _shell(f"strings '{lp}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -10", timeout=8)
            return f"Downloaded {sz} bytes → {lp}\nFlag scan:\n{grep}"
        except Exception as ex:
            return f"SCP error: {ex}"

    if operation == "interactive_game":
        """Drive an interactive SSH game (e.g. Binary Search 1-1000).
        script = newline-separated response strategy, or 'binary_search:1:1000' shorthand."""
        try:
            c = _client()
            chan = c.invoke_shell()
            chan.settimeout(5)
            time.sleep(0.5)

            def recv_all(timeout=3):
                buf = b""
                end = time.time() + timeout
                while time.time() < end:
                    try:
                        chunk = chan.recv(4096)
                        if not chunk: break
                        buf += chunk
                    except: break
                return buf.decode(errors="replace")

            banner = recv_all(2)
            log("sys", f"[ssh_game] banner: {banner[:200]}", "dim")
            output = [banner]

            if script.startswith("binary_search:"):
                parts = script.split(":")
                lo, hi = int(parts[1]), int(parts[2])
                for _ in range(20):
                    mid = (lo + hi) // 2
                    chan.send(str(mid) + "\n")
                    resp = recv_all(3)
                    output.append(f"Sent {mid}: {resp}")
                    rl = resp.lower()
                    if "correct" in rl or "flag" in rl or "ctf" in rl:
                        break
                    elif "higher" in rl or "too low" in rl:
                        lo = mid + 1
                    elif "lower" in rl or "too high" in rl:
                        hi = mid - 1
                    else:
                        output.append(f"Unexpected response: {resp}")
                        break
            else:
                for line in (script or "").splitlines():
                    chan.send(line + "\n")
                    resp = recv_all(3)
                    output.append(f"Sent {repr(line)}: {resp}")

            chan.close(); c.close()
            return "\n".join(output)
        except Exception as ex:
            return f"Interactive SSH error: {ex}"

    return "Operations: connect, run_command, scp_download, interactive_game"


def tool_proto_decode(operation: str = "decode", data: str = "",
                       binary_path: str = "", output_format: str = "json") -> str:
    """Protobuf decoder using blackboxprotobuf + protoc --decode_raw.
    Ops: decode (decode raw protobuf hex/bytes without .proto schema),
    schema_guess (guess field types and output an approximate .proto schema),
    encode (encode a dict back to protobuf bytes),
    from_file (decode a binary file as protobuf),
    decode_raw (shell to protoc --decode_raw for quick inspection)."""

    sp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""

    if operation == "decode_raw":
        target = f"cat '{sp}'" if sp else f"echo -n '{data}' | xxd -r -p"
        result = _shell(f"{target} | protoc --decode_raw 2>&1", timeout=10)
        if "not found" in result:
            return "protoc not installed. Install: apt install protobuf-compiler"
        return result

    if operation in ("decode", "schema_guess", "encode"):
        code = f"""
try:
    import blackboxprotobuf as bbpb
    import json, binascii

    data_str = {repr(data)}
    binary_path = {repr(sp)}

    if binary_path:
        with open(binary_path, 'rb') as f:
            raw = f.read()
    elif data_str:
        # Try hex decode first, then base64, then raw
        try:
            raw = binascii.unhexlify(data_str.replace(' ','').replace(':',''))
        except:
            import base64
            try: raw = base64.b64decode(data_str)
            except: raw = data_str.encode()
    else:
        print('Provide data= (hex/base64) or binary_path=')
        exit()

    if '{operation}' == 'encode':
        # Treat data_str as JSON dict to encode
        d = json.loads(data_str)
        encoded = bbpb.encode_message(d)
        print(f'Encoded hex: {{encoded.hex()}}')
        print(f'Encoded b64: {{__import__("base64").b64encode(encoded).decode()}}')
    else:
        message, typedef = bbpb.decode_message(raw)
        print(f'Decoded message:')
        print(json.dumps(message, indent=2, default=str))
        if '{operation}' == 'schema_guess':
            print(f'\\nInferred typedef (approximate .proto):')
            print(json.dumps(typedef, indent=2, default=str))

except ImportError:
    print('blackboxprotobuf not installed. Install: pip install blackboxprotobuf')
    # Fallback: protoc --decode_raw
    import subprocess
    r = subprocess.run(['protoc','--decode_raw'], input={repr(data)}.encode() if {repr(data)} else open({repr(sp or '/dev/null')},'rb').read(),
                       capture_output=True, timeout=10)
    print(r.stdout.decode(errors='replace') or r.stderr.decode(errors='replace'))
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "from_file":
        return tool_proto_decode("decode", binary_path=sp)

    return "Operations: decode, schema_guess, encode, from_file, decode_raw"

