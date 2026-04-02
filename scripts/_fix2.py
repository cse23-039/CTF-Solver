"""Fix remaining 5 injection sites."""
import pathlib

BASE = pathlib.Path(__file__).resolve().parent.parent / "sidecar" / "tools"

def fix(fn, pairs):
    p = BASE / fn
    t = p.read_text(encoding="utf-8")
    for old, new in pairs:
        n = t.count(old)
        print(f"  {fn}: {n}x  {old[:60]!r}")
        t = t.replace(old, new)
    p.write_text(t, encoding="utf-8")

# pwn_impl.py: remaining enc and binary_path
fix("pwn_impl.py", [
    (
        r" else int(\'{enc}\')",
        " else int({repr(enc)})",
    ),
    (
        r"readelf -d \'{binary_path}\' | ",
        "readelf -d {repr(binary_path)} | ",
    ),
])

# web_impl.py: create_connection url (three patterns)
# Read the file and do targeted line fixes
p = BASE / "web_impl.py"
lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
out = []
for i, line in enumerate(lines, 1):
    if r"create_connection(\'{url}\'," in line:
        fixed = line.replace(r"\'{url}\'", "{repr(url)}")
        print(f"  web_impl.py L{i}: fixed create_connection url")
        out.append(fixed)
    else:
        out.append(line)
p.write_text("".join(out), encoding="utf-8")

print("Done.")
