# Windows Setup (run ONCE on Windows, not in WSL)

The CTF Solver is a Tauri desktop app. The frontend runs on Windows.
All CTF tools run inside WSL2. You need both sides set up.

---

## Step 1 — WSL2 side (Ubuntu terminal)

```bash
# In your WSL2 Ubuntu terminal:
cd ctf-solver
bash install.sh
```

This installs gdb, pwntools, tshark, steghide, angr, one_gadget,
and every other Linux CTF tool the solver uses.

---

## Step 2 — Windows side (PowerShell)

Install these once on Windows:

### Node.js
Download from https://nodejs.org/ (LTS version)
Or with winget: `winget install OpenJS.NodeJS.LTS`

### Rust (needed to build Tauri)
```powershell
winget install Rustlang.Rustup
# Then restart PowerShell and run:
rustup default stable
```

### Tauri CLI + Microsoft C++ Build Tools
```powershell
# Build tools (required by Tauri)
winget install Microsoft.VisualStudio.2022.BuildTools

# Then in the ctf-solver folder:
npm install
```

### WebView2 (usually already installed on Windows 11)
If missing: https://developer.microsoft.com/en-us/microsoft-edge/webview2/

---

## Step 3 — Set your Anthropic API key

### In WSL2 (for running solver directly):
```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE' >> ~/.bashrc
source ~/.bashrc
```

### In Windows (for the Tauri app):
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-YOUR_KEY_HERE", "User")
```

---

## Step 4 — Run

### Dev mode (hot reload):
```powershell
# In PowerShell, in the ctf-solver folder:
npm run dev
```

Use npm commands from the project root (where `package.json` is), not inside `src-tauri/`.

### Or test the solver sidecar directly (WSL2 terminal):
```bash
echo '{"mode":"solve","challenge":{"name":"test","category":"General Skills","description":"decode: aGVsbG8="}}' \
  | python3 sidecar/solver.py
```

---

## Incremental challenge drops (CTFs that release in waves)

The importer now supports incremental sync and watch mode:

- Detects newly added and updated challenges without duplicating old ones
- Can poll continuously for new drops
- Can auto-queue and optionally auto-start top new challenge(s)
- Uses a single-active-solve lock to avoid overlapping auto-start runs

Recommended payload flags:

- `watchNewChallenges: true`
- `watchIntervalSeconds: 30`
- `watchCycles: 0` (continuous)
- `autoQueuePolicy: true`
- `autoStartSolveOnNew: true`
- `maxAutoStartsPerCycle: 1`
- `singleActiveSolveLock: true`

Live solve protection also runs during solving:

- `extraConfig.liveTeamSync: true`
- `extraConfig.liveTeamSyncPollSeconds: 12`

If a teammate solves the same challenge first, the running solve is cancelled to save tokens.

---

## Troubleshooting

**"WSL not found"** — Install WSL2: `wsl --install` in PowerShell (admin), reboot.

**"Solver can't find tools"** — The app shells to WSL. Make sure you ran `install.sh` 
inside the WSL2 Ubuntu terminal, not PowerShell.

**"ANTHROPIC_API_KEY not set"** — Set it in WSL2 ~/.bashrc AND in Windows env vars.

**Tauri build fails** — Make sure Rust, Node, and VS Build Tools are all installed.
Run `rustup update` and try again.
