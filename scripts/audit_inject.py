import re, os

base = r'c:\Users\ksetwaba\Documents\CTF-Solver-main\sidecar\tools'
# In the source code, dynamically-constructed Python code strings embed paths as:
#   wave.open(\'{audio_path}\',\'rb\')
# which in the raw file is:  \'{ audio_path }\'
# If the path contains a single-quote this breaks. Fix: use repr(var) instead.
# Raw file pattern: backslash single-quote {VARNAME} backslash single-quote
pattern = re.compile(r"\\'\{([a-z_0-9]+)\}\\'")

for fn in sorted(os.listdir(base)):
    if not fn.endswith('.py'):
        continue
    path = os.path.join(base, fn)
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        m = pattern.findall(line)
        if m:
            print(f'{fn}:{i}: vars={m}  | {line.rstrip()[:120]}')
