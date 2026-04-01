# CTF::SOLVER

<p>
  <img src="https://img.shields.io/badge/Tauri-Desktop-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" alt="Tauri"/>
  <img src="https://img.shields.io/badge/Python-Sidecar-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/UI-Customizable-8A2BE2?style=for-the-badge" alt="UI"/>
  <img src="https://img.shields.io/badge/CTF-Autonomous%20Solver-111827?style=for-the-badge" alt="CTF"/>
</p>

Modern desktop CTF workspace with autonomous solving, challenge management, and live tool execution.

## Why it stands out
- ⚡ Fast Tauri desktop app with Python solver backend
- 🧠 Autonomous solve flow with shell, Python, decoding, HTTP, and file-analysis tools
- 🎛️ UI personalization (colors, typography, layout) directly in Settings
- 🧩 Works for staged/manual CTF workflows and platform-driven imports

## Quick start
### Linux / WSL
```bash
bash install.sh
npm install
npm run tauri dev
```

### Windows
```bash
npm install
npm run tauri dev
```

Build release:
```bash
npm run tauri build
```

## First-run setup
1. Open `Settings`.
2. Set your Anthropic API key.
3. Set Python path (for example `python3`).
4. Set solver path to `sidecar/solver.py` (absolute path).
5. Save and start solving.

## UI theme customization
`Settings → UI & DISPLAY → COLOURS`

You can live-edit:
- Background
- Accent / Highlight
- Border color
- Font size, line height, and font family
- Panel width and split layout

Use `RESET COLOURS TO DEFAULT` anytime.

## Shortcuts
| Key | Action |
|---|---|
| `N` | New challenge |
| `S` | Solve selected |
| `A` | Solve all |
| `X` | Cancel |
| `Del` | Remove challenge |

## Project layout
- `src/` — frontend (HTML/CSS/JS)
- `src-tauri/` — Rust/Tauri host
- `sidecar/` — Python solver + tools
