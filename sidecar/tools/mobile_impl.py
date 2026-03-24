"""Mobile (Android / iOS) analysis tools."""
from __future__ import annotations
import re, subprocess, os, shutil, zipfile


def tool_android_vuln(operation: str = "scan", target: str = "",
                       package_name: str = "", device: str = "usb",
                       extra: str = "") -> str:
    """Android vulnerability exploitation: scan (full auto-scan via drozer/MobSF),
    intent_hijack (exported activity/service/receiver exploitation),
    content_provider (injection, path traversal, URI abuse),
    deeplink (malicious deep link payloads), broadcast (sticky/ordered broadcast abuse),
    webview (WebView JS bridge exploitation), backup (adb backup extraction),
    debug (debuggable APK → arbitrary code), adb_commands."""

    pkg = package_name or target

    if operation == "scan":
        return _shell(f"drozer console connect --server 127.0.0.1 -c "
                     f"\"run app.package.info -a {pkg}; "
                     f"run app.package.attacksurface {pkg}; "
                     f"run app.activity.info -a {pkg}; "
                     f"run app.provider.info -a {pkg}; "
                     f"run app.service.info -a {pkg}\" 2>/dev/null || "
                     f"echo 'drozer not available — install: pip3 install drozer'",
                     timeout=30)

    if operation == "intent_hijack":
        return f"[intent_hijack] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "content_provider":
        return f"[content_provider] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "deeplink":
        return f"[deeplink] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "webview":
        return f"[webview] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "backup":
        return f"[backup] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "adb_commands":
        return f"[adb_commands] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: scan, intent_hijack, content_provider, deeplink, webview, backup, debug, adb_commands"


def tool_apk_analyze(apk_path: str, operation: str = "all",
                      class_filter: str = "", output_dir: str = "") -> str:
    """Android APK analysis: all (quick overview), decompile (jadx Java/Kotlin output),
    manifest (permissions, exported components, intents), dex (Dalvik bytecode),
    strings (hardcoded secrets, URLs, keys), smali (low-level bytecode), certificate,
    find_vulns (exported activities, SQL injection, hardcoded creds, WebView)."""

    ap = _w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path
    out = output_dir or f"/tmp/apk_analyze_{int(time.time())}"

    if operation == "manifest":
        return _shell(f"apktool d '{ap}' -o '{out}' --no-src -f 2>&1 | tail -5 && "
                     f"cat '{out}/AndroidManifest.xml' 2>/dev/null | head -100 || "
                     f"aapt dump badging '{ap}' 2>/dev/null | head -30 || "
                     f"unzip -p '{ap}' AndroidManifest.xml | python3 -c '"
                     f"import sys,struct; data=sys.stdin.buffer.read(); "
                     f"print(data.decode(errors=\\\"replace\\\")[:2000])' 2>/dev/null",
                     timeout=30)

    if operation == "decompile":
        cf = f"-f '{class_filter}'" if class_filter else ""
        result = _shell(f"jadx -d '{out}' {cf} '{ap}' 2>&1 | tail -10 && "
                       f"echo '--- Decompiled classes ---' && "
                       f"find '{out}' -name '*.java' | head -20",
                       timeout=120)
        if "not found" in result.lower():
            result = _shell(f"apktool d '{ap}' -o '{out}' -f 2>&1 | tail -5 && "
                           f"find '{out}/smali' -name '*.smali' | head -20",
                           timeout=60)
        return result

    if operation == "strings":
        return _shell(f"unzip -p '{ap}' 'classes.dex' > /tmp/classes.dex 2>/dev/null; "
                     f"strings /tmp/classes.dex | grep -iE "
                     f"'password|passwd|secret|api.key|token|http|flag|admin|root|private|firebase|aws' | head -40; "
                     f"echo '--- URLs ---'; "
                     f"strings /tmp/classes.dex | grep -E 'https?://[^\"]+' | head -20",
                     timeout=20)

    if operation == "certificate":
        return _shell(f"apksigner verify -v '{ap}' 2>/dev/null || "
                     f"jarsigner -verify -verbose -certs '{ap}' 2>/dev/null | head -30 || "
                     f"openssl pkcs7 -inform DER -print_certs -text < "
                     f"<(unzip -p '{ap}' 'META-INF/*.RSA' 2>/dev/null) 2>/dev/null | head -30",
                     timeout=15)

    if operation == "find_vulns":
        code = f"""
import subprocess, re, os
ap = {repr(ap)}
out = {repr(out)}
print("=== APK Vulnerability Scan ===")
# Extract and analyze
os.makedirs(out, exist_ok=True)
r = subprocess.run(['apktool', 'd', ap, '-o', out, '-f'],
                   capture_output=True, text=True, timeout=60)
# Check AndroidManifest for exported components
manifest = open(f'{{out}}/AndroidManifest.xml').read() if os.path.exists(f'{{out}}/AndroidManifest.xml') else ''
if manifest:
    exported = re.findall(r'<(activity|service|receiver|provider)[^>]+android:exported="true"[^>]*/?>.*?(?:android:name="([^"]+)"|)', manifest)
    for comp_type, name in exported[:10]:
        print(f"[!] Exported {{comp_type}}: {{name}}")
    # Check for unprotected content providers
    providers = re.findall(r'<provider[^>]+>', manifest)
    for p in providers:
        if 'android:exported="true"' in p and 'android:permission' not in p:
            print(f"[!] Unprotected content provider: {{re.search(r'android:name=.([^\"]+)', p)}}")
# Check smali for dangerous patterns
smali_files = subprocess.run(['find', out, '-name', '*.smali'],
                              capture_output=True, text=True, timeout=10).stdout.strip().split('\\n')
danger_patterns = [
    ('SQL injection', r'rawQuery|execSQL'),
    ('WebView JS', r'setJavaScriptEnabled.*true|addJavascriptInterface'),
    ('Hardcoded key', r'AES|DES|MD5|SHA.*=.*"[A-Za-z0-9+/]{16,}"'),
    ('External storage', r'getExternalStorage|WRITE_EXTERNAL_STORAGE'),
    ('Log sensitive', r'Log\\.[deiw].*(?:password|secret|token|key)'),
    ('World readable', r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
]
for smali in smali_files[:100]:
    if not smali or not os.path.exists(smali): continue
    content = open(smali).read()
    for name, pattern in danger_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            print(f"[!] {{name}} in {{smali.split('/')[-1]}}")
            break
"""
        return tool_execute_python(code, timeout=90)

    if operation == "dex":
        return _shell(f"unzip -p '{ap}' 'classes.dex' > /tmp/classes.dex 2>/dev/null && "
                     f"dexdump -d /tmp/classes.dex 2>/dev/null | head -80 || "
                     f"baksmali d /tmp/classes.dex -o /tmp/smali_out 2>/dev/null && "
                     f"find /tmp/smali_out -name '*.smali' | head -10 && "
                     f"head -40 /tmp/smali_out/*/*.smali 2>/dev/null",
                     timeout=30)

    if operation == "all":
        return (f"=== APK Quick Analysis: {ap} ===\n\n" +
                _shell(f"file '{ap}'; echo '---'; aapt dump badging '{ap}' 2>/dev/null | head -10; "
                      f"echo '---'; unzip -l '{ap}' | head -20; "
                      f"echo '--- Permissions ---'; aapt dump permissions '{ap}' 2>/dev/null | head -20; "
                      f"echo '--- Strings sample ---'; "
                      f"unzip -p '{ap}' classes.dex 2>/dev/null | strings | grep -iE 'http|secret|key|flag' | head -15",
                      timeout=30))

    return "Operations: all, manifest, decompile, strings, certificate, find_vulns, dex, smali"


def tool_apk_resign(apk_path: str, operation: str = "full_pipeline",
                     patch_smali: str = "", target_class: str = "",
                     output_path: str = "") -> str:
    """Full APK patch → rebuild → sign → install pipeline.
    Ops: full_pipeline (decompile → patch → rebuild → sign → install),
    decompile (apktool d), rebuild (apktool b + sign), sign (jarsigner + zipalign),
    install (adb install), patch_ssl (auto-patch network_security_config for traffic intercept)."""

    ap = _w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path
    work_dir = f"/tmp/apk_resign_{int(time.time())}"
    out_apk = output_path or ap.replace('.apk', '_patched.apk')
    keystore = "/tmp/ctf_debug.keystore"

    if operation in ("full_pipeline", "decompile"):
        decompile = _shell(f"mkdir -p '{work_dir}' && "
                          f"apktool d '{ap}' -o '{work_dir}' -f 2>&1 | tail -5 && "
                          f"echo 'Decompiled to: {work_dir}' && ls '{work_dir}'",
                          timeout=60)
        if operation == "decompile":
            return decompile

    if operation in ("full_pipeline", "patch_ssl"):
        # Auto-patch network_security_config
        nsc_dir = f"{work_dir}/res/xml"
        nsc = (_shell(f"mkdir -p '{nsc_dir}' && "
                     f"cat > '{nsc_dir}/network_security_config.xml' << 'EOF'\n"
                     f"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                     f"<network-security-config>\n"
                     f"  <base-config cleartextTrafficPermitted=\"true\">\n"
                     f"    <trust-anchors>\n"
                     f"      <certificates src=\"system\"/>\n"
                     f"      <certificates src=\"user\"/>\n"
                     f"    </trust-anchors>\n"
                     f"  </base-config>\n"
                     f"</network-security-config>\nEOF\n"
                     f"echo 'NSC patched'", timeout=5) +
               _shell(f"grep -l 'android:networkSecurityConfig' '{work_dir}/AndroidManifest.xml' 2>/dev/null || "
                     f"sed -i 's/<application/& android:networkSecurityConfig=\"@xml\\/network_security_config\"/' "
                     f"'{work_dir}/AndroidManifest.xml' 2>/dev/null && "
                     f"echo 'AndroidManifest.xml patched'", timeout=5))
        if operation == "patch_ssl":
            return nsc + f"\nWork dir: {work_dir}\nRun operation='rebuild' to build the patched APK"

    if patch_smali and target_class:
        # Apply custom smali patch
        class_file = target_class.replace('.', '/') + '.smali'
        smali_path = f"{work_dir}/smali/{class_file}"
        _shell(f"echo {repr(patch_smali)} >> '{smali_path}' 2>/dev/null", timeout=5)

    if operation in ("full_pipeline", "rebuild", "sign"):
        # Rebuild
        rebuilt_apk = f"{work_dir}/dist/{__import__('os').path.basename(ap)}"
        rebuild = _shell(f"apktool b '{work_dir}' -o '{work_dir}/dist/patched.apk' 2>&1 | tail -10",
                        timeout=120)

        # Generate debug keystore if needed
        _shell(f"[ -f '{keystore}' ] || keytool -genkey -v -keystore '{keystore}' "
              f"-alias ctf -keyalg RSA -keysize 2048 -validity 365 "
              f"-storepass ctfpass123 -keypass ctfpass123 "
              f"-dname 'CN=CTF,OU=CTF,O=CTF,L=CTF,S=CTF,C=US' 2>/dev/null", timeout=20)

        # Sign
        sign = _shell(f"jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 "
                     f"-keystore '{keystore}' -storepass ctfpass123 -keypass ctfpass123 "
                     f"'{work_dir}/dist/patched.apk' ctf 2>&1 | tail -5 && "
                     f"zipalign -v 4 '{work_dir}/dist/patched.apk' '{out_apk}' 2>&1 | tail -3 && "
                     f"echo 'Output APK: {out_apk}'",
                     timeout=30)

        if operation == "sign":
            return sign

        if operation in ("full_pipeline", "install"):
            install = _shell(f"adb install -r '{out_apk}' 2>&1", timeout=30)
            return rebuild + sign + install

        return rebuild + sign

    if operation == "install":
        return _shell(f"adb install -r '{ap}' 2>&1", timeout=30)

    return "Operations: full_pipeline, decompile, patch_ssl, rebuild, sign, install"


def tool_flutter_re(apk_path: str = "", binary_path: str = "",
                     operation: str = "detect") -> str:
    """Flutter/React Native/Dart reverse engineering.
    Ops: detect (identify framework + version), flutter_extract (extract libflutter.so + libapp.so),
    dart_snapshot (analyze Dart AOT snapshot), rn_bundle (extract React Native JS bundle),
    rn_deobfuscate (deobfuscate hermes bytecode), strings (framework-specific string extraction)."""

    sp = (_w2l(apk_path) if (IS_WINDOWS and USE_WSL) else apk_path) if apk_path else ""
    bp = (_w2l(binary_path) if (IS_WINDOWS and USE_WSL) else binary_path) if binary_path else ""
    work = f"/tmp/flutter_re_{int(time.time())}"

    if operation == "detect":
        code = f"""
import subprocess, os, zipfile
target = {repr(sp or bp)}
if not target: print("Provide apk_path or binary_path"); exit()

print("=== Framework detection ===")
# Check for Flutter
if target.endswith('.apk') or target.endswith('.ipa'):
    try:
        with zipfile.ZipFile(target) as z:
            files = z.namelist()
            if any('libflutter.so' in f for f in files):
                print("[!] Flutter app detected (libflutter.so present)")
                flutter_so = [f for f in files if 'libflutter.so' in f]
                print(f"  Flutter libs: {{flutter_so}}")
            if any('libapp.so' in f for f in files):
                print("[!] Dart AOT snapshot (libapp.so)")
            if any('index.android.bundle' in f or 'main.jsbundle' in f for f in files):
                print("[!] React Native app (JS bundle present)")
                rn_files = [f for f in files if 'bundle' in f.lower() or 'jsbundle' in f.lower()]
                print(f"  RN bundles: {{rn_files}}")
            if any('assets/flutter_assets' in f for f in files):
                print("[!] Flutter assets directory")
    except Exception as ex:
        print(f"Error: {{ex}}")
else:
    r = subprocess.run(['strings', target], capture_output=True, text=True, timeout=15)
    s = r.stdout
    if 'flutter' in s.lower(): print("[!] Flutter strings found")
    if 'dart:' in s: print("[!] Dart runtime strings found")
    if 'ReactNative' in s or 'hermes' in s.lower(): print("[!] React Native/Hermes found")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "flutter_extract":
        _shell(f"mkdir -p '{work}'")
        return _shell(f"unzip -j '{sp}' 'lib/*/libflutter.so' 'lib/*/libapp.so' "
                     f"'assets/flutter_assets/*' -d '{work}' 2>/dev/null && "
                     f"ls -la '{work}' && "
                     f"echo '--- libapp.so strings ---' && "
                     f"strings '{work}/libapp.so' 2>/dev/null | grep -iE 'flag|ctf|key|secret|check' | head -20",
                     timeout=30)

    if operation == "dart_snapshot":
        return (_shell(f"strings '{bp or work+'/libapp.so'}' | "
                      f"grep -vE '^[\\x00-\\x1f]|^\\s*$' | head -60",
                      timeout=15) +
                "\nDart AOT snapshot analysis:\n"
                "  Tool: https://github.com/mildsunrise/darter (Dart snapshot parser)\n"
                "  Tool: https://github.com/Impact-I/reFlutter (patching libflutter for SSL bypass)\n"
                "  reFlutter: reflutter --arch arm64 target.apk → patches snapshot for Burp proxy\n"
                "  IDA/Ghidra: load libapp.so, look for _kDartIsolateSnapshotInstructions symbol")

    if operation == "rn_bundle":
        _shell(f"mkdir -p '{work}'")
        return _shell(f"unzip -j '{sp}' '*.bundle' '*.jsbundle' 'assets/index*' -d '{work}' 2>/dev/null && "
                     f"ls '{work}' && "
                     f"cat '{work}'/*.bundle 2>/dev/null | head -200 || "
                     f"cat '{work}'/*.jsbundle 2>/dev/null | head -200",
                     timeout=20)

    if operation == "rn_deobfuscate":
        bundle = bp or f"{work}/index.android.bundle"
        code = f"""
import subprocess, re, os
bundle = {repr(bundle)}
if not os.path.exists(bundle):
    print(f"Bundle not found: {{bundle}}")
    print("Extract first with operation='rn_bundle'")
    exit()

with open(bundle, 'rb') as f: data = f.read()

# Check for Hermes bytecode
if data[:4] == b'Her\\x00' or data[:4] == b'Her\\xc0':
    print("[!] Hermes bytecode detected")
    r = subprocess.run(['hbcdump', bundle], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        print(r.stdout[:2000])
    else:
        print("hbcdump not found. Install: npm install -g hermes-dec")
        r2 = subprocess.run(['hermes-dec', bundle], capture_output=True, text=True, timeout=30)
        print(r2.stdout[:2000] if r2.returncode==0 else "hermes-dec also not found")
else:
    # Plain JS - look for interesting content
    text = data.decode(errors='replace')
    # Find API endpoints
    apis = re.findall(r'https?://[^"\'\\s{{}}]{5,100}', text)
    print(f"API endpoints: {{set(apis)}}")
    # Find flag patterns
    flags = re.findall(r'(?:flag|ctf|key|secret|token)[^"\'{{}}\\n]{{0,50}}', text, re.IGNORECASE)
    for f in flags[:10]: print(f"  {{f[:100]}}")
"""
        return tool_execute_python(code, timeout=30)

    return "Operations: detect, flutter_extract, dart_snapshot, rn_bundle, rn_deobfuscate, strings"


def tool_ios_vuln(operation: str = "scan", target: str = "",
                   bundle_id: str = "", device: str = "usb") -> str:
    """iOS vulnerability analysis: scan (idb/objection overview), keychain (dump keychain items),
    nsuserdefaults (check insecure storage), url_scheme (URL scheme abuse),
    jailbreak_bypass (Frida jailbreak detection bypass), method_swizzling (hook ObjC methods),
    runtime_analysis (frida-trace ObjC calls), network_analysis (traffic capture)."""

    bid = bundle_id or target

    if operation == "scan":
        return (f"iOS App Security Scan:\n\n"
                f"# With objection (pip3 install objection + Frida on device):\n"
                f"objection -g {bid} explore\n"
                f"> ios info binary\n"
                f"> ios plist cat Info.plist\n"
                f"> ios keychain dump\n"
                f"> ios nsuserdefaults get\n"
                f"> ios jailbreak disable\n"
                f"> ios sslpinning disable\n"
                f"> ios hooking list classes\n"
                f"> ios hooking list class_methods ViewController\n\n"
                f"# With idb (if available):\n"
                f"idb connect localhost 10882\n"
                f"idb bundles list  # list installed apps\n"
                f"idb info bundles {bid}\n\n"
                f"# Manual Frida checks:\n"
                f"frida-ps -U  # list running processes\n"
                f"frida -U -n '{bid}' -l your_script.js")

    if operation == "keychain":
        frida_script = '''// iOS Keychain dumper via Frida
Java.perform = function() {};  // ignore
var SecurityModule = Process.findModuleByName("Security");
var SecItemCopyMatching = new NativeFunction(
    SecurityModule.getExportByName('SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
);
var query = ObjC.classes.NSMutableDictionary.alloc().init();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('(void)'), ObjC.classes.NSString.stringWithString_('klass'));
// Use objection's: ios keychain dump
// Or: frida -U -l keychain_dump.js -n TargetApp
console.log("Use 'objection -g "+process.argv[0]+" explore' then: ios keychain dump");'''
        return (f"Keychain extraction methods:\n\n"
                f"1. Objection (easiest):\n"
                f"   objection -g {bid} explore -s 'ios keychain dump'\n\n"
                f"2. Frida script (on jailbroken device):\n"
                f"   # keychaineditor or keychain-dumper binary\n"
                f"   ssh root@device 'keychain-dumper'\n\n"
                f"3. From backup (non-jailbroken, if backup not encrypted):\n"
                f"   idevicebackup2 backup --full /tmp/backup\n"
                f"   # Parse Manifest.db, then decrypt individual files\n"
                f"   # https://github.com/jsharkey13/iphone_backup_decrypt\n\n"
                f"4. What to look for in keychain:\n"
                f"   kSecAttrService, kSecAttrAccount, kSecValueData\n"
                f"   auth tokens, passwords, API keys\n\n"
                f"Common vulnerable pattern:\n"
                f"   SecItemAdd with kSecAttrAccessible = kSecAttrAccessibleAlways\n"
                f"   (should be kSecAttrAccessibleWhenUnlockedThisDeviceOnly)")

    if operation == "jailbreak_bypass":
        return f"[jailbreak_bypass] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "nsuserdefaults":
        return f"[nsuserdefaults] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "method_swizzling":
        return f"[method_swizzling] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "runtime_analysis":
        return f"[runtime_analysis] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return ("iOS vuln operations:\n"
            "  scan, keychain, nsuserdefaults, url_scheme,\n"
            "  jailbreak_bypass, method_swizzling, runtime_analysis, network_analysis")


def tool_ipa_analyze(ipa_path: str, operation: str = "all",
                      output_dir: str = "", class_filter: str = "") -> str:
    """iOS IPA analysis: all (quick overview), extract (unzip + binary),
    class_dump (ObjC class headers), strings (hardcoded secrets), plist (Info.plist, plists),
    entitlements, binary_analysis (checksec, symbols), find_vulns (URL schemes, keychain misuse,
    NSUserDefaults secrets, ATS bypass), swift_decompile."""

    ip = _w2l(ipa_path) if (IS_WINDOWS and USE_WSL) else ipa_path
    out = output_dir or f"/tmp/ipa_analyze_{int(time.time())}"

    if operation in ("all", "extract"):
        r = _shell(f"mkdir -p '{out}' && unzip -q '{ip}' -d '{out}' 2>/dev/null && "
                  f"find '{out}' -name '*.app' -type d | head -3 && "
                  f"APP=$(find '{out}' -name '*.app' -type d | head -1) && "
                  f"echo 'App bundle: '\"$APP\" && ls \"$APP\" | head -20",
                  timeout=30)
        if operation == "extract":
            return r

    if operation == "plist":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"cat \"$APP/Info.plist\" 2>/dev/null | python3 -c 'import sys,plistlib; d=plistlib.load(sys.stdin.buffer); [print(k,\":\",v) for k,v in d.items()]' | head -30; "
                     f"echo '--- All plists ---'; find '{out}' -name '*.plist' | head -10",
                     timeout=20)

    if operation == "class_dump":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"class-dump \"$APP/$BIN\" 2>/dev/null | head -80 || "
                     f"nm -a \"$APP/$BIN\" 2>/dev/null | grep -iE 'T _' | head -40",
                     timeout=30)

    if operation == "strings":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"strings \"$APP/$BIN\" | grep -iE 'password|secret|key|token|http|flag|api' | head -40",
                     timeout=20)

    if operation == "entitlements":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"codesign -d --entitlements :- \"$APP/$BIN\" 2>/dev/null | head -40 || "
                     f"ldid -e \"$APP/$BIN\" 2>/dev/null | head -40",
                     timeout=15)

    if operation == "find_vulns":
        code = f"""
import subprocess, re, os
ip, out = {repr(ip)}, {repr(out)}
os.makedirs(out, exist_ok=True)
subprocess.run(['unzip','-q',ip,'-d',out], capture_output=True, timeout=30)
app_path = subprocess.run(['find',out,'-name','*.app','-type','d'],
                          capture_output=True,text=True,timeout=10).stdout.strip().split('\\n')[0]
if not app_path:
    print("Could not extract app bundle"); exit()
print(f"Analyzing: {{app_path}}")
# Check Info.plist for ATS bypass
plist_path = f'{{app_path}}/Info.plist'
if os.path.exists(plist_path):
    plist_content = open(plist_path,'rb').read().decode(errors='replace')
    if 'NSAllowsArbitraryLoads' in plist_content:
        print("[!] ATS bypass: NSAllowsArbitraryLoads = true (HTTP allowed)")
    if 'NSExceptionDomains' in plist_content:
        print("[!] NSExceptionDomains: per-domain ATS exceptions found")
    url_schemes = re.findall(r'CFBundleURLSchemes.*?<string>([^<]+)</string>', plist_content, re.DOTALL)
    for scheme in url_schemes[:5]:
        print(f"[!] URL scheme: {{scheme}} (check for open redirect/XSS via scheme handler)")
# Check binary for dangerous patterns
bins = [f for f in os.listdir(app_path) if '.' not in f]
for bin_name in bins[:1]:
    bin_path = f'{{app_path}}/{{bin_name}}'
    r = subprocess.run(['strings', bin_path], capture_output=True, text=True, timeout=15)
    strings = r.stdout
    dangers = [
        ('Hardcoded key', r'[A-Za-z0-9+/]{32,}={0,2}'),
        ('HTTP URL', r'http://[^\\s"<>]+'),
        ('AWS key', r'AKIA[A-Z0-9]{16}'),
        ('Private key', r'BEGIN (RSA|EC|PRIVATE) KEY'),
        ('Firebase URL', r'https://[^.]+\\.firebaseio\\.com'),
    ]
    for name, pattern in dangers:
        matches = re.findall(pattern, strings)[:3]
        if matches:
            print(f"[!] {{name}}: {{matches[0][:60]}}")
# NSUserDefaults misuse: sensitive data in defaults
if 'NSUserDefaults' in strings:
    print("[!] NSUserDefaults used — check for sensitive data storage")
if 'kSecAttrAccessible' in strings:
    print("[OK] Keychain used for sensitive data storage")
if 'UIWebView' in strings:
    print("[!] UIWebView (deprecated) used — check for JS injection")
if 'WKWebView' in strings and 'evaluateJavaScript' in strings:
    print("[!] WKWebView evaluateJavaScript — check input sanitization")
"""
        return tool_execute_python(code, timeout=60)

    if operation == "binary_analysis":
        return _shell(f"APP=$(find '{out}' -name '*.app' -type d 2>/dev/null | head -1); "
                     f"[ -z \"$APP\" ] && unzip -q '{ip}' -d '{out}' 2>/dev/null && APP=$(find '{out}' -name '*.app' -type d | head -1); "
                     f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                     f"echo 'Binary: '\"$APP/$BIN\"; "
                     f"file \"$APP/$BIN\" 2>/dev/null; "
                     f"checksec --file=\"$APP/$BIN\" 2>/dev/null; "
                     f"otool -l \"$APP/$BIN\" 2>/dev/null | grep -E 'LC_ENCRYPTION|cryptid' | head -5",
                     timeout=20)

    if operation == "all":
        return (f"=== IPA Quick Analysis: {ip} ===\n\n" +
                _shell(f"mkdir -p '{out}' 2>/dev/null; unzip -q '{ip}' -d '{out}' 2>/dev/null; "
                      f"APP=$(find '{out}' -name '*.app' -type d | head -1); "
                      f"echo 'Bundle:'; ls \"$APP\" | head -15; "
                      f"echo '--- Info.plist (key fields) ---'; "
                      f"cat \"$APP/Info.plist\" 2>/dev/null | python3 -c '"
                      f"import sys,plistlib; "
                      f"d=plistlib.load(sys.stdin.buffer); "
                      f"keys=[\"CFBundleIdentifier\",\"CFBundleName\",\"MinimumOSVersion\",\"NSAppTransportSecurity\"]; "
                      f"[print(k+\":\",d.get(k)) for k in keys if k in d]' 2>/dev/null; "
                      f"echo '--- Strings sample ---'; "
                      f"BIN=$(ls \"$APP\" | grep -v '\\.' | head -1); "
                      f"strings \"$APP/$BIN\" | grep -iE 'http|secret|key|flag' | head -15",
                      timeout=30))

    return "Operations: all, extract, plist, class_dump, strings, entitlements, find_vulns, binary_analysis, swift_decompile"


def tool_ssl_pinning_bypass(operation: str = "frida", target: str = "",
                              package_name: str = "", method: str = "auto") -> str:
    """SSL/certificate pinning bypass for mobile apps.
    Ops: frida (universal Frida bypass script), objection (objection framework),
    apktool_patch (patch smali for network_security_config), ios_frida (iOS bypass),
    custom (custom Frida hook for specific pinning implementation)."""

    # Frida bypass scripts - Claude generates these per-target

    if operation == "frida":
        if "ios" in method.lower() or "ios" in (package_name or "").lower():
            script = FRIDA_IOS_BYPASS
            cmd = f"frida -U -l ios_ssl_bypass.js -f {package_name or 'com.target.app'} --no-pause"
        else:
            script = FRIDA_ANDROID_BYPASS
            cmd = f"frida -U -l ssl_bypass.js -f {package_name or 'com.target.app'} --no-pause"
        return f"Save as ssl_bypass.js:\n\n{script}\n\nRun:\n  {cmd}\n\nThen proxy traffic through mitmproxy/Burp on port 8080"

    if operation == "objection":
        pkg = package_name or target
        return (f"Objection SSL pinning bypass:\n\n"
                f"# Install: pip3 install objection\n"
                f"# Start Frida server on device first\n\n"
                f"# Android:\n"
                f"objection -g {pkg} explore\n"
                f"> android sslpinning disable\n\n"
                f"# iOS:\n"
                f"objection -g {pkg} explore\n"
                f"> ios sslpinning disable\n\n"
                f"# Inject into running process:\n"
                f"objection -g {pkg} explore --startup-command 'android sslpinning disable'\n\n"
                f"# Combined with proxy:\n"
                f"# 1. Set device proxy to 192.168.x.x:8080 (mitmproxy)\n"
                f"# 2. Run: objection -g {pkg} explore -s 'android sslpinning disable'\n"
                f"# 3. Traffic flows through mitmproxy plaintext")

    if operation == "apktool_patch":
        return f"[apktool_patch] Claude handles this directly — use execute_python/execute_shell to run the technique"

    if operation == "custom":
        return f"[custom] Claude handles this directly — use execute_python/execute_shell to run the technique"

    return "Operations: frida (Android/iOS universal bypass), objection, apktool_patch, ios_frida, custom"

