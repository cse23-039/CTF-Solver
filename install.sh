#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CTF Solver — WSL2 Install Script
# Installs ALL Linux-side dependencies inside WSL2 (Ubuntu 22.04/24.04)
#
# USAGE:
#   1. Open WSL2 terminal (Ubuntu)
#   2. cd to the ctf-solver folder
#   3. bash install.sh
#
# The Tauri desktop app runs on Windows — see README_WINDOWS.md for
# Windows-side setup (Node, Rust, Tauri CLI).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Confirm we're in WSL ─────────────────────────────────────────────────────
if ! grep -qi microsoft /proc/version 2>/dev/null && ! grep -qi wsl /proc/version 2>/dev/null; then
    warn "Not running inside WSL2 — this script is for WSL2 Ubuntu."
    warn "If you're on Linux (not WSL), this will still work fine."
    read -rp "Continue anyway? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || exit 0
fi

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

# Ensure gem and cargo bins are in PATH
export PATH="$PATH:/usr/local/bin:$HOME/.local/bin:$HOME/.gem/bin:$HOME/.cargo/bin:$(ruby -e 'puts Gem.bindir' 2>/dev/null || true)"

apt_get()  {
    local failed=0
    for pkg in "$@"; do
        $SUDO apt-get install -y --no-install-recommends "$pkg" 2>/dev/null \
        || { warn "apt: failed: $pkg"; failed=1; }
    done
    return $failed
}
pip_get()  {
    local failed=0
    for pkg in "$@"; do
        pip3 install --quiet --break-system-packages "$pkg" 2>/dev/null \
        || pip3 install --quiet "$pkg" 2>/dev/null \
        || { warn "pip: failed: $pkg"; failed=1; }
    done
    return $failed
}
gem_get()  {
    $SUDO gem install --quiet --no-document "$@" 2>/dev/null \
    || gem install --quiet --no-document --user-install "$@" 2>/dev/null \
    || warn "gem: failed: $*"
}
cargo_get(){ cargo install --quiet "$@" 2>/dev/null || warn "cargo: failed: $*"; }

hdr "System update"
$SUDO apt-get update -qq

# ─── 1. Base build tools ─────────────────────────────────────────────────────
hdr "Base build tools"
apt_get \
    build-essential git curl wget \
    python3 python3-pip python3-dev python3-venv pipx \
    ruby ruby-dev \
    nodejs npm \
    default-jdk \
    rustc cargo \
    golang-go \
    cmake pkg-config

# ─── 2. Binary analysis / exploitation ───────────────────────────────────────
hdr "Binary analysis & exploitation"
apt_get \
    gdb \
    ltrace strace \
    radare2 \
    binutils \
    nasm \
    patchelf \
    upx-ucl \
    checksec \
    libmagic-dev \
    elfutils

# ─── 3. Network & PCAP ───────────────────────────────────────────────────────
hdr "Network & PCAP tools"
apt_get tshark tcpdump ncat netcat-openbsd openssl ssldump nmap dnsutils
# tcpflow separate — sometimes conflicts with older versions on Kali
apt_get tcpflow || {
    log "tcpflow: apt failed, building from source..."
    apt_get libpcap-dev libz-dev
    git clone --depth=1 https://github.com/simsong/tcpflow /tmp/tcpflow_src 2>/dev/null \
    && cd /tmp/tcpflow_src \
    && ./bootstrap.sh 2>/dev/null && ./configure --quiet 2>/dev/null && make -s 2>/dev/null \
    && $SUDO make install 2>/dev/null \
    && ok "tcpflow (source)" \
    || warn "tcpflow: failed"
    cd - >/dev/null; rm -rf /tmp/tcpflow_src
}

# ─── 4. Forensics ────────────────────────────────────────────────────────────
hdr "Forensics tools"
apt_get \
    foremost \
    sleuthkit \
    testdisk \
    pngcheck \
    exiftool \
    libimage-exiftool-perl \
    poppler-utils \
    icoutils
# binwalk — apt version broken on modern Kali, pip also broken, use v3 from source
if ! command -v binwalk &>/dev/null; then
    log "binwalk..."
    apt_get python3-binwalk 2>/dev/null && ok "binwalk (apt python3-binwalk)" || {
        # binwalk v3 rewrote as a proper Python package
        $SUDO apt-get install -y --no-install-recommends python3-dev 2>/dev/null || true
        rm -rf /tmp/binwalk_src
        git clone --depth=1 --branch v3.1.0 https://github.com/ReFirmLabs/binwalk /tmp/binwalk_src 2>/dev/null \
        || git clone --depth=1 https://github.com/ReFirmLabs/binwalk /tmp/binwalk_src 2>/dev/null
        cd /tmp/binwalk_src \
        && pip3 install --quiet --break-system-packages . 2>/dev/null \
        && ok "binwalk (source)" \
        || {
            # Last resort: try legacy v2 which installs cleanly
            pip3 install --quiet --break-system-packages \
                "git+https://github.com/ReFirmLabs/binwalk.git@v2.3.4" 2>/dev/null \
            && ok "binwalk (v2 legacy)" \
            || warn "binwalk: all methods failed"
        }
        cd - >/dev/null; rm -rf /tmp/binwalk_src
    }
else ok "binwalk already installed"; fi

# ─── 5. Steganography ────────────────────────────────────────────────────────
hdr "Steganography tools"
apt_get \
    steghide \
    outguess \
    zbar-tools \
    qrencode \
    imagemagick \
    ffmpeg \
    sox \
    multimon-ng

# ─── 6. Crypto & cracking ────────────────────────────────────────────────────
hdr "Crypto & password cracking"
apt_get hashcat libssl-dev libgmp-dev libmpfr-dev libmpc-dev libsodium-dev
# john — package name differs on some Kali versions
apt_get john || apt_get john-data || {
    log "john: apt failed, trying snap/source..."
    $SUDO snap install john-the-ripper 2>/dev/null && ok "john (snap)" \
    || warn "john: failed — install from https://www.openwall.com/john/"
}

# ─── 7. Compression & archives ───────────────────────────────────────────────
hdr "Compression & archive tools"
# p7zip-full is obsolete on Kali — 7zip replaces it
apt_get 7zip zip unzip bzip2 xz-utils zstd lz4
apt_get unar || apt_get dtrx || warn "unar/dtrx: not available on this system"

# ─── 8. Misc system tools ─────────────────────────────────────────────────────
hdr "Misc system tools"
apt_get \
    protobuf-compiler \
    libprotobuf-dev \
    sqlmap \
    patchutils \
    xxd \
    jq \
    bc

# ─── 9. Python packages ──────────────────────────────────────────────────────
hdr "Python packages (pip)"

# Core
pip_get anthropic requests urllib3 pyyaml

# Crypto
pip_get pycryptodome cryptography sympy "z3-solver" gmpy2 hashpumpy

# paddingoracle — install from source (abandoned on PyPI)
if ! python3 -c "import paddingoracle" 2>/dev/null; then
    log "paddingoracle..."
    pip3 install --break-system-packages \
        "git+https://github.com/mwielgoszewski/python-paddingoracle.git" 2>/dev/null \
    && ok "paddingoracle" || warn "paddingoracle: failed"
else ok "paddingoracle already installed"; fi

# Binary exploitation
pip_get pwntools ropgadget unicorn keystone-engine randcrack

# Reversing
pip_get pefile frida-tools blackboxprotobuf
# flare-floss — binary from GitHub (pip version often broken)
if ! command -v floss &>/dev/null; then
    log "flare-floss binary..."
    FLOSS_VER=$(curl -s https://api.github.com/repos/mandiant/flare-floss/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v3.1.0")
    wget -q "https://github.com/mandiant/flare-floss/releases/download/${FLOSS_VER}/floss-${FLOSS_VER}-linux.zip" \
         -O /tmp/floss.zip 2>/dev/null \
    && unzip -q /tmp/floss.zip floss -d /tmp/floss_bin 2>/dev/null \
    && $SUDO mv /tmp/floss_bin/floss /usr/local/bin/floss \
    && $SUDO chmod +x /usr/local/bin/floss \
    && ok "flare-floss" \
    || warn "flare-floss: failed — get from github.com/mandiant/flare-floss/releases"
    rm -rf /tmp/floss.zip /tmp/floss_bin
else ok "flare-floss already installed"; fi

# Web
pip_get beautifulsoup4 lxml httpx websockets websocket-client scapy
# sqlmap installed via apt; jwt-tool installed via git clone below

# Forensics / image
pip_get Pillow numpy python-magic pikepdf oletools pyzbar stegcracker yara-python

# peepdf — use maintained fork peepdf-3
pip_get peepdf-3 || pip_get peepdf || warn "peepdf: failed"

# regipy
pip_get regipy

# libscca-python — try apt first, then pip
$SUDO apt-get install -y --no-install-recommends python3-libscca 2>/dev/null \
    && ok "libscca (apt)" \
    || pip_get libscca \
    || warn "libscca: failed"

# Network / SSH
pip_get paramiko scp

# Misc
pip_get scipy wasmtime

# basecrack — install from GitHub (PyPI version outdated)
if ! python3 -c "import basecrack" 2>/dev/null; then
    log "basecrack..."
    pip3 install --quiet --break-system-packages \
        "git+https://github.com/mufeedvh/basecrack.git" 2>/dev/null \
    && ok "basecrack" || pip_get basecrack || warn "basecrack: failed"
else ok "basecrack already installed"; fi

# chromadb — heavy deps, try with verbose error
log "chromadb..."
pip3 install --quiet --break-system-packages chromadb 2>/dev/null \
    && ok "chromadb" \
    || pip3 install --quiet --break-system-packages "chromadb<0.5.0" 2>/dev/null \
    && ok "chromadb (older)" \
    || warn "chromadb: failed — not critical for CTF solving"

# angr — heavy, install last
log "angr (this may take a few minutes)..."
if ! python3 -c "import angr" 2>/dev/null; then
    pip3 install --quiet --break-system-packages angr 2>/dev/null \
    && ok "angr" \
    || warn "angr: failed — install manually: pip3 install angr"
else ok "angr already installed"; fi

# playwright
if ! python3 -c "import playwright" 2>/dev/null; then
    log "playwright..."
    pip3 install --quiet --break-system-packages "playwright" 2>/dev/null \
    && ok "playwright" || warn "playwright: pip failed"
else ok "playwright already installed"; fi

ok "pip packages done"

# ─── 10. Ruby gems ───────────────────────────────────────────────────────────
hdr "Ruby gems"
gem_get one_gadget
gem_get seccomp-tools
gem_get zsteg
ok "gems done"

# ─── 11. Node packages (global) ──────────────────────────────────────────────
hdr "Node packages"
# Ensure npm global prefix is writable
NPM_PREFIX=$($SUDO npm config get prefix 2>/dev/null || echo "/usr/local")

if $SUDO npm install -g --quiet --prefix "$NPM_PREFIX" js-beautify 2>/dev/null \
   || npm install -g --quiet js-beautify 2>/dev/null; then
    command -v js-beautify &>/dev/null && ok "npm: js-beautify" || warn "npm: js-beautify installed but not in PATH"
else
    warn "npm: failed: js-beautify"
fi

if $SUDO npm install -g --quiet --prefix "$NPM_PREFIX" hermes-dec 2>/dev/null \
   || npm install -g --quiet hermes-dec 2>/dev/null \
   || pip3 install --quiet --break-system-packages "git+https://github.com/P1sec/hermes-dec.git" 2>/dev/null; then
    if command -v hermes-dec &>/dev/null || command -v hbc-disassembler &>/dev/null || command -v hbcdump &>/dev/null; then
        ok "hermes-dec"
    else
        warn "hermes-dec installed but no CLI found (expected: hermes-dec, hbc-disassembler, or hbcdump)"
    fi
else
    warn "hermes-dec: failed"
fi

# ─── 12. Special tool installs ───────────────────────────────────────────────
hdr "Special tool installs"

# ── jwt_tool ──────────────────────────────────────────────────────────────────
if ! command -v jwt_tool &>/dev/null; then
    log "jwt_tool..."
    $SUDO git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
    && pip_get termcolor cprint pycryptodomex requests \
    && $SUDO ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && $SUDO chmod +x /opt/jwt_tool/jwt_tool.py \
    && ok "jwt_tool" || warn "jwt_tool: failed"
else ok "jwt_tool already installed"; fi

# ── stegseek ─────────────────────────────────────────────────────────────────
if ! command -v stegseek &>/dev/null; then
    log "stegseek..."
    # Try prebuilt deb first
    wget -q "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6_amd64.deb" \
         -O /tmp/stegseek.deb 2>/dev/null \
    && $SUDO dpkg -i /tmp/stegseek.deb 2>/dev/null \
    && $SUDO apt-get install -f -y 2>/dev/null \
    && ok "stegseek" || {
        warn "stegseek: deb failed — building from source..."
        apt_get libsteghide-dev libmhash-dev libmcrypt-dev libjpeg-dev
        git clone --depth=1 https://github.com/RickdeJager/stegseek /tmp/stegseek_src 2>/dev/null \
        && cd /tmp/stegseek_src \
        && mkdir build && cd build \
        && cmake .. 2>/dev/null && make -s 2>/dev/null \
        && $SUDO make install 2>/dev/null \
        && ok "stegseek (source)" \
        || warn "stegseek: build failed"
        cd - >/dev/null
        rm -rf /tmp/stegseek_src
    }
    rm -f /tmp/stegseek.deb
else ok "stegseek already installed"; fi

# ── pwndbg ───────────────────────────────────────────────────────────────────
if [[ ! -f ~/.gdbinit ]] || ! grep -q pwndbg ~/.gdbinit 2>/dev/null; then
    log "pwndbg..."
    git clone --depth=1 https://github.com/pwndbg/pwndbg ~/pwndbg 2>/dev/null \
    && cd ~/pwndbg && bash setup.sh 2>/dev/null \
    && ok "pwndbg" \
    || warn "pwndbg: failed"
    cd - >/dev/null
else ok "pwndbg already configured"; fi

# ── checksec ─────────────────────────────────────────────────────────────────
if ! command -v checksec &>/dev/null; then
    log "checksec..."
    # Try apt (Kali package)
    $SUDO apt-get install -y checksec 2>/dev/null && ok "checksec (apt)" || {
        # Fallback: pip version
        pip3 install --quiet --break-system-packages checksec 2>/dev/null && ok "checksec (pip)" || {
            # Fallback: download script directly
            wget -q "https://raw.githubusercontent.com/slimm609/checksec.sh/main/checksec" \
                 -O /tmp/checksec_dl 2>/dev/null \
            && chmod +x /tmp/checksec_dl \
            && $SUDO mv /tmp/checksec_dl /usr/local/bin/checksec \
            && ok "checksec (script)" \
            || warn "checksec: all methods failed"
        }
    }
else ok "checksec already installed"; fi

# ── jadx ─────────────────────────────────────────────────────────────────────
if ! command -v jadx &>/dev/null; then
    log "jadx..."
    JADX_VER=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest \
               | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v' 2>/dev/null || echo "1.5.0")
    wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" \
         -O /tmp/jadx.zip \
    && $SUDO unzip -q /tmp/jadx.zip -d /opt/jadx \
    && $SUDO chmod +x /opt/jadx/bin/jadx \
    && $SUDO ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ok "jadx v${JADX_VER}" \
    || warn "jadx: failed"
    rm -f /tmp/jadx.zip
else ok "jadx already installed"; fi

# ── apktool ──────────────────────────────────────────────────────────────────
if ! command -v apktool &>/dev/null; then
    log "apktool..."
    apt_get apktool 2>/dev/null && ok "apktool (apt)" || {
        APKTOOL_VER=$(curl -s https://api.github.com/repos/iBotPeaches/Apktool/releases/latest \
                     | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v' 2>/dev/null || echo "2.9.3")
        wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" \
             -O /usr/local/bin/apktool.jar \
        && printf '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"\n' \
             | $SUDO tee /usr/local/bin/apktool >/dev/null \
        && $SUDO chmod +x /usr/local/bin/apktool \
        && ok "apktool v${APKTOOL_VER}" || warn "apktool: failed"
    }
else ok "apktool already installed"; fi

# ── RsaCtfTool ───────────────────────────────────────────────────────────────
if ! command -v RsaCtfTool &>/dev/null && ! command -v rsactftool &>/dev/null && [[ ! -f /opt/RsaCtfTool/RsaCtfTool.py ]]; then
    log "RsaCtfTool..."
    TOOL_DIR="$HOME/.local/share/RsaCtfTool"
    rm -rf "$TOOL_DIR"
    git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool "$TOOL_DIR" 2>/dev/null \
    && python3 -m venv "$TOOL_DIR/venv" 2>/dev/null \
    && "$TOOL_DIR/venv/bin/pip" install --quiet -r "$TOOL_DIR/requirements.txt" 2>/dev/null \
    && chmod +x "$TOOL_DIR/RsaCtfTool.py" \
    && printf '#!/bin/bash\n"%s"/venv/bin/python "%s"/RsaCtfTool.py "$@"\n' "$TOOL_DIR" "$TOOL_DIR" > "$HOME/.local/bin/RsaCtfTool" \
    && chmod +x "$HOME/.local/bin/RsaCtfTool" \
    && { $SUDO ln -sf "$HOME/.local/bin/RsaCtfTool" /usr/local/bin/RsaCtfTool 2>/dev/null || true; } \
    && ok "RsaCtfTool" \
    || warn "RsaCtfTool: failed"
else ok "RsaCtfTool already installed"; fi

# ── tplmap ───────────────────────────────────────────────────────────────────
if [[ ! -f /opt/tplmap/tplmap.py ]]; then
    log "tplmap..."
    $SUDO git clone --depth=1 https://github.com/epinna/tplmap /opt/tplmap 2>/dev/null \
    && pip3 install --quiet --break-system-packages -r /opt/tplmap/requirements.txt 2>/dev/null \
    && ok "tplmap" || warn "tplmap: failed"
else ok "tplmap already at /opt/tplmap"; fi

# ── ysoserial ────────────────────────────────────────────────────────────────
if [[ ! -f /opt/ysoserial/ysoserial.jar ]]; then
    log "ysoserial..."
    $SUDO mkdir -p /opt/ysoserial \
    && $SUDO wget -q "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
             -O /opt/ysoserial/ysoserial.jar \
    && ok "ysoserial" || warn "ysoserial: failed"
else ok "ysoserial already present"; fi

# ── phpggc ───────────────────────────────────────────────────────────────────
if ! command -v phpggc &>/dev/null; then
    log "phpggc..."
    $SUDO git clone --depth=1 https://github.com/ambionics/phpggc /opt/phpggc 2>/dev/null \
    && $SUDO ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc \
    && ok "phpggc" || warn "phpggc: failed"
else ok "phpggc already installed"; fi

# ── hash_extender ────────────────────────────────────────────────────────────
if ! command -v hash_extender &>/dev/null; then
    log "hash_extender..."
    git clone --depth=1 https://github.com/iagox86/hash_extender /tmp/hext 2>/dev/null \
    && cd /tmp/hext && make -s 2>/dev/null \
    && $SUDO cp hash_extender /usr/local/bin/ \
    && ok "hash_extender" || warn "hash_extender: build failed (need gcc)"
    cd - >/dev/null; rm -rf /tmp/hext
else ok "hash_extender already installed"; fi

# ── pwninit ──────────────────────────────────────────────────────────────────
if ! command -v pwninit &>/dev/null; then
    log "pwninit..."
    cargo_get pwninit && ok "pwninit" || warn "pwninit: cargo install failed"
else ok "pwninit already installed"; fi

# ── volatility3 ──────────────────────────────────────────────────────────────
if ! python3 -c "import volatility3" 2>/dev/null; then
    log "volatility3..."
    pip3 install --quiet --break-system-packages volatility3 2>/dev/null && ok "volatility3 (pip)" || {
        git clone --depth=1 https://github.com/volatilityfoundation/volatility3 /opt/volatility3 2>/dev/null \
        && pip3 install --quiet --break-system-packages -r /opt/volatility3/requirements.txt 2>/dev/null \
        && $SUDO ln -sf /opt/volatility3/vol.py /usr/local/bin/vol \
        && ok "volatility3 (source)" || warn "volatility3: failed"
    }
else ok "volatility3 already installed"; fi

# ── SageMath ─────────────────────────────────────────────────────────────────
if ! command -v sage &>/dev/null; then
    log "SageMath (large package, may take several minutes)..."
    # Try apt first
    $SUDO apt-get install -y sagemath 2>/dev/null && ok "sage (apt)" || {
        # Fallback: install via conda/mamba if available
        if command -v conda &>/dev/null; then
            conda install -y -c conda-forge sage 2>/dev/null && ok "sage (conda)" \
            || warn "sage: conda failed"
        elif command -v mamba &>/dev/null; then
            mamba install -y -c conda-forge sage 2>/dev/null && ok "sage (mamba)" \
            || warn "sage: mamba failed"
        else
            # Install micromamba then use it to install sage in isolated env
            log "Installing micromamba for sage..."
            MAMBA_BIN=/usr/local/bin/micromamba
            curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest \
                | $SUDO tar -xj -C /usr/local/bin --strip-components=1 bin/micromamba 2>/dev/null
            if command -v micromamba &>/dev/null || [[ -x "$MAMBA_BIN" ]]; then
                $MAMBA_BIN create -y -n sage -c conda-forge sage python=3.11 2>/dev/null \
                && SAGE_EXEC=$($MAMBA_BIN run -n sage which sage 2>/dev/null || echo "") \
                && [[ -n "$SAGE_EXEC" ]] \
                && $SUDO ln -sf "$SAGE_EXEC" /usr/local/bin/sage \
                && ok "sage (micromamba)" \
                || warn "sage: micromamba install failed — install manually from https://www.sagemath.org/download.html"
            else
                warn "sage: micromamba not available — install manually from https://www.sagemath.org/download.html"
            fi
        fi
    }
else ok "sage already installed"; fi

# ── Playwright browsers ───────────────────────────────────────────────────────
log "Playwright browsers..."
# Install system deps first
$SUDO apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 2>/dev/null || true
python3 -m playwright install chromium 2>/dev/null \
&& ok "playwright chromium" \
|| warn "playwright: browser install failed — run manually: python3 -m playwright install chromium"

# ─── 13. Set ANTHROPIC_API_KEY ────────────────────────────────────────────────
hdr "API Key"
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    warn "ANTHROPIC_API_KEY is not set!"
    warn "Add this to your ~/.bashrc (or ~/.zshrc):"
    warn "  export ANTHROPIC_API_KEY='sk-ant-...'"
    warn "Then run: source ~/.bashrc"
else
    ok "ANTHROPIC_API_KEY is set"
fi

# ─── 14. Verification ─────────────────────────────────────────────────────────
hdr "Verification"

chk() {
    local label=$1; local test_cmd=$2
    if eval "$test_cmd" &>/dev/null 2>&1; then
        ok "$label"
    else
        warn "$label — MISSING"
    fi
}

chk "python3"           "python3 --version"
chk "pwntools"          "python3 -c 'import pwn'"
chk "pycryptodome"      "python3 -c 'from Crypto.Util.number import inverse'"
chk "z3"                "python3 -c 'import z3'"
chk "sympy"             "python3 -c 'import sympy'"
chk "gmpy2"             "python3 -c 'import gmpy2'"
chk "PIL"               "python3 -c 'from PIL import Image'"
chk "numpy"             "python3 -c 'import numpy'"
chk "angr"              "python3 -c 'import angr'"
chk "frida"             "python3 -c 'import frida'"
chk "paramiko"          "python3 -c 'import paramiko'"
chk "pefile"            "python3 -c 'import pefile'"
chk "pikepdf"           "python3 -c 'import pikepdf'"
chk "pyzbar"            "python3 -c 'from pyzbar.pyzbar import decode'"
chk "blackboxprotobuf"  "python3 -c 'import blackboxprotobuf'"
chk "basecrack"         "python3 -c 'import basecrack'"
chk "rsactftool"        "command -v RsaCtfTool || command -v rsactftool || test -f /opt/RsaCtfTool/RsaCtfTool.py || test -f $HOME/.local/share/RsaCtfTool/RsaCtfTool.py"
chk "floss"             "command -v floss"
chk "gdb"               "gdb --version"
chk "pwndbg"            "grep -q pwndbg ~/.gdbinit"
chk "radare2"           "r2 -version"
chk "binwalk"           "binwalk --version"
chk "tshark"            "tshark --version"
chk "tcpflow"           "command -v tcpflow"
chk "foremost"          "foremost -V"
chk "steghide"          "steghide --version"
chk "stegseek"          "stegseek --version"
chk "zsteg"             "command -v zsteg || ls ~/.gem/bin/zsteg 2>/dev/null || ls /usr/local/bin/zsteg 2>/dev/null"
chk "outguess"          "outguess -h"
chk "zbarimg"           "zbarimg --version"
chk "qrencode"          "qrencode --version"
chk "one_gadget"        "one_gadget --version"
chk "checksec"          "command -v checksec"
chk "patchelf"          "patchelf --version"
chk "upx"               "upx --version"
chk "7z"                "7z i"
chk "unar"              "command -v unar || command -v dtrx"
chk "hashcat"           "hashcat --version"
chk "john"              "command -v john"
chk "jadx"              "jadx --version"
chk "apktool"           "apktool --version"
chk "ysoserial"         "test -f /opt/ysoserial/ysoserial.jar"
chk "phpggc"            "phpggc --list"
chk "tplmap"            "test -f /opt/tplmap/tplmap.py"
chk "hash_extender"     "command -v hash_extender"
chk "volatility3"       "python3 -c 'import volatility3'"
chk "sage"              "command -v sage"
chk "node"              "node --version"
chk "js-beautify"       "js-beautify --version"
chk "hermes-dec"        "command -v hermes-dec || command -v hbc-disassembler || command -v hbcdump"
chk "java"              "java -version"
chk "rustc"             "rustc --version"
chk "sqlmap"            "sqlmap --version"
chk "jwt_tool"          "command -v jwt_tool"
chk "stegcracker"       "command -v stegcracker || python3 -c 'import stegcracker'"

echo ""
ok "Install complete!"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. Set your API key (if not done):"
echo "     echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc && source ~/.bashrc"
echo ""
echo "  2. Test the sidecar directly from WSL:"
echo "     echo '{\"mode\":\"solve\",\"challenge\":{\"name\":\"test\",\"category\":\"General Skills\",\"description\":\"echo hello\"}}' \\"
echo "       | python3 sidecar/solver.py"
echo ""
echo "  3. On Windows — open PowerShell and run:"
echo "     cd ctf-solver && npm install && npm run dev"