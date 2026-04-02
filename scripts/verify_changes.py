"""Quick smoke test for all changes."""
import pathlib, re

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ── Frontend files ─────────────────────────────────────────────────────────────
for fn in ["src/index.html", "src/main.js"]:
    t = (ROOT / fn).read_text(encoding="utf-8")
    pts    = t.count("m-pts")
    bad20  = t.count("||20")
    credit = t.count("pb-credit")
    lc     = t.count("loadChallenges")
    pc     = t.count("persistChallenges")
    apikey = t.count("ctf-solver-apikey")
    print(f"\n{fn}:")
    print(f"  m-pts       : {pts}     (want 0)")
    print(f"  ||20 bug    : {bad20}   (want 0)")
    print(f"  pb-credit   : {credit}  (want >=1)")
    print(f"  loadChall   : {lc}      (want >=1)")
    print(f"  persistChall: {pc}      (want >=4)")
    print(f"  apikey store: {apikey}  (want >=2)")

# ── Tool injection audit ──────────────────────────────────────────────────────
tools_dir = ROOT / "sidecar" / "tools"
pat = re.compile(r"\\'{[a-z_]+}\\'")
total = 0
for f in sorted(tools_dir.glob("*.py")):
    t = f.read_text(encoding="utf-8")
    hits = pat.findall(t)
    if hits:
        print(f"\n  STILL INJECTED  {f.name}: {hits[:4]}")
    total += len(hits)

print(f"\nTool path injections remaining: {total}  (want 0)")
print("\nAll checks done.")
