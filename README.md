# CTF::SOLVER

<p align="center">
  <strong>Autonomous CTF desktop solver powered by Claude + real tooling.</strong><br/>
  Tauri frontend • Rust bridge • Python sidecar • local + network challenge workflows
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-1f2937?style=for-the-badge&logo=tauri&logoColor=white" />
  <img alt="Tauri" src="https://img.shields.io/badge/Tauri-1.x-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Node" src="https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" />
</p>

---

## ✨ What It Does

- Solves CTF challenges from a desktop interface with autonomous tool usage.
- Streams live solve telemetry (model routing, iterations, status, tool calls).
- Uses real tools: shell, Python, file analysis, HTTP, decoding transforms.
- Supports API credit budgeting with live spend tracking and low-credit guardrails.
- Generates writeups and challenge workspaces automatically.

---

## 🧱 Architecture

```text
Tauri Desktop App
├─ Frontend (src/index.html + src/main.js + src/style.css)
│  └─ Challenge management, logs, settings, runtime dashboard
├─ Rust Backend (src-tauri/src/main.rs)
│  └─ Spawns/monitors Python sidecar, forwards event stream
└─ Python Solver (sidecar/solver.py)
   ├─ Claude orchestration + routing + budget guard
   ├─ Tool execution (shell/python/http/decode/file/...)
   └─ Workspace + writeup + validation flows
```

---

## 🚀 Quick Start

### 1) Install prerequisites

- **Rust** (Tauri backend)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js 18+** (Tauri CLI): https://nodejs.org
- **Python 3.8+**

### 2) Linux-only system packages

```bash
# Ubuntu / Debian
sudo apt install libwebkit2gtk-4.0-dev build-essential curl wget libssl-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

# Arch
sudo pacman -S webkit2gtk base-devel curl wget openssl gtk3
```

### 3) Install dependencies

```bash
cd ctf-solver
npm install
pip3 install -r sidecar/requirements.txt
```

### 4) Run

```bash
# Development
npm run dev

# Production build
npm run build
```

Bundle output: `src-tauri/target/release/bundle/`

---

## 🪟 Windows Users

Use the dedicated guide: [README_WINDOWS.md](README_WINDOWS.md)

It includes:
- WSL2 tool bootstrap (`install.sh`)
- Rust/Node/Build Tools setup
- API key and environment troubleshooting

---

## ⚙️ First Launch Setup

1. Open app → click **Settings**.
2. Add **Anthropic API key** (https://console.anthropic.com).
3. Set **Python path** (example: `python3` or full path).
4. Set **Solver script path** to absolute `sidecar/solver.py`.
5. Save and run **environment diagnostics**.

---

## 🧠 Solver Capabilities

### Core toolchain

- `execute_shell`
- `execute_python`
- `decode_transform`
- `http_request`
- `analyze_file`
- `create_workspace` / `write_file` / `download_file` / `submit_flag`

### Python packages (from `sidecar/requirements.txt`)

- `pwntools`
- `requests`
- `cryptography`
- `Pillow`
- `sympy`

### Useful external binaries (optional but recommended)

`strings`, `file`, `xxd`, `binwalk`, `steghide`, `exiftool`, `john`, `hashcat`

---

## 💸 API Credit Control

The app supports budget-aware solving:

- Per-challenge credit cap (e.g. `$5`).
- Queue-level (`Solve All`) total budget cap.
- Live credit spend + remaining balance in dashboard.
- Low-credit threshold alerts and automatic throttling.

---

## ⌨️ Shortcuts

| Key | Action |
|---|---|
| `N` | New challenge |
| `S` | Solve selected |
| `A` | Solve all staged |
| `X` | Cancel solve |
| `Del` | Remove selected |
| `↑` / `↓` | Navigate challenge list |
| `Esc` | Close active modal |

---

## 🧩 Challenge Input Tips

Best results come from rich context:

- Full prompt/description
- Attachments or file snippets
- Target host/instance info
- Observed outputs/errors
- Expected flag format (if known)

---

## 🔧 Troubleshooting

- **Tauri build fails on Windows icon resource**: ensure `src-tauri/icons/icon.ico` exists.
- **API key rejected**: verify key starts with `sk-ant-` and is active.
- **Solver path errors**: set absolute path to `sidecar/solver.py`.
- **Tools missing in WSL**: run `bash install.sh` from WSL distro.

---

## 📌 Notes

- This project is for CTF/educational workflows.
- Keep your API key private.
- Tune iteration + budget settings to control speed/cost tradeoffs.
