# CTF::SOLVER — Autonomous Desktop

A full-featured autonomous CTF challenge solver built with Tauri + Python.  
Claude analyzes challenges and executes real tools (shell, Python, decoders, HTTP) to find flags.

---

## Prerequisites

### 1. Rust (for Tauri)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Node.js (for Tauri CLI)
Download from https://nodejs.org — v18 or later

### 3. System deps (Linux only)
```bash
# Ubuntu/Debian
sudo apt install libwebkit2gtk-4.0-dev build-essential curl wget libssl-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Arch
sudo pacman -S webkit2gtk base-devel curl wget openssl gtk3
```

### 4. Python 3.8+
```bash
# macOS
brew install python3

# Ubuntu/Debian
sudo apt install python3 python3-pip

# Windows — download from python.org and check "Add to PATH"
```

### 5. Python dependencies
```bash
cd sidecar
pip3 install -r requirements.txt
```

---

## Install & Run

```bash
# 1. Clone / extract the project
cd ctf-solver

# 2. Install Node deps
npm install

# 3. Run in dev mode
npm run tauri dev

# 4. Build distributable app
npm run tauri build
```

The built app will be in `src-tauri/target/release/bundle/`

---

## First Launch

1. Open the app
2. Go to **Settings** (gear icon, top right)
3. Set your **Anthropic API key** (get one at console.anthropic.com)
4. Set **Python path** (e.g. `python3` or `/usr/bin/python3`)
5. Set **Solver script path** — absolute path to `sidecar/solver.py`
6. Click **Save Settings**

---

## Adding Challenges

**Quick add**: Type name + pick category in the bottom bar → `+ADD`  
**Full add**: Click `⚙` or press `N` → fill description, paste file contents, add instance info

The more context you give (full description, source code, ciphertext, server output),  
the better Claude solves it.

---

## CTF Tools (installed automatically via requirements.txt)

- `pwntools` — binary exploitation, network connections
- `requests` — web challenges, HTTP requests
- `cryptography` — crypto primitives
- `Pillow` — image steganography analysis
- `sympy` — math / number theory

System tools Claude can also use (install separately if needed):
- `strings`, `file`, `xxd`, `binwalk`, `steghide`, `exiftool`, `john`, `hashcat`

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `N` | New challenge |
| `S` | Solve selected |
| `A` | Solve all staged |
| `X` | Cancel solve |
| `Del` | Remove selected |
| `↑ ↓` | Navigate list |
| `Esc` | Close modal |

---

## Architecture

```
Tauri Window
├── Frontend (HTML/CSS/JS)   ← TUI interface, state management
└── Rust Backend             ← spawns Python, streams events
    └── Python Sidecar       ← Anthropic SDK + tool execution
        ├── execute_shell    ← shell commands
        ├── execute_python   ← arbitrary Python code
        ├── decode_transform ← base64/hex/rot13/xor/caesar/binary
        ├── http_request     ← web requests
        └── analyze_file     ← file type/strings/hexdump/entropy
```
