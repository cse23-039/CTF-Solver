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
set -euo pipefail

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

apt_get()  { $SUDO apt-get install -y --no-install-recommends "$@" 2>/dev/null || warn "apt: failed: $*"; }
pip_get()  { pip3 install --quiet --break-system-packages "$@" 2>/dev/null \
             || pip3 install --quiet "$@" 2>/dev/null \
             || warn "pip: failed: $*"; }
gem_get()  { gem install --quiet "$@" 2>/dev/null || warn "gem: failed: $*"; }
cargo_get(){ cargo install --quiet "$@" 2>/dev/null || warn "cargo: failed: $*"; }

hdr "System update"
$SUDO apt-get update -qq

# ─── 1. Base build tools ─────────────────────────────────────────────────────
hdr "Base build tools"
apt_get \
    build-essential git curl wget \
    python3 python3-pip python3-dev python3-venv \
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
apt_get \
    tshark \
    tcpflow \
    tcpdump \
    ncat netcat-openbsd \
    openssl \
    ssldump \
    nmap \
    dnsutils

# ─── 4. Forensics ────────────────────────────────────────────────────────────
hdr "Forensics tools"
apt_get \
    foremost \
    sleuthkit \
    testdisk \
    binwalk \
    pngcheck \
    exiftool \
    libimage-exiftool-perl \
    poppler-utils \
    pdfinfo \
    icoutils

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
apt_get \
    john \
    hashcat \
    libssl-dev \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libsodium-dev

# ─── 7. Compression & archives ───────────────────────────────────────────────
hdr "Compression & archive tools"
apt_get \
    7zip p7zip-full \
    unar \
    zip unzip \
    bzip2 \
    lzma \
    zstd \
    lz4

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
pip_get \
    pycryptodome cryptography \
    sympy "z3-solver" \
    gmpy2 hashpumpy \
    rsactftool paddingoracle

# Binary exploitation
pip_get \
    pwntools ropgadget \
    unicorn keystone-engine \
    randcrack

# Reversing
pip_get \
    pefile \
    "flare-floss" \
    frida-tools \
    blackboxprotobuf

# Web
pip_get \
    beautifulsoup4 lxml \
    httpx websockets websocket-client \
    scapy \
    "jwt-tool" \
    sqlmap

# Forensics / image
pip_get \
    Pillow numpy \
    python-magic \
    pikepdf oletools \
    pyzbar \
    peepdf \
    stegcracker \
    regipy libscca-python \
    yara-python

# Network / SSH
pip_get paramiko scp

# Misc
pip_get \
    scipy basecrack \
    playwright chromadb \
    wasmtime \
    angr

ok "pip packages done"

# ─── 10. Ruby gems ───────────────────────────────────────────────────────────
hdr "Ruby gems"
gem_get one_gadget
gem_get seccomp-tools
gem_get zsteg
ok "gems done"

# ─── 11. Node packages (global) ──────────────────────────────────────────────
hdr "Node packages"
npm install -g --quiet \
    js-beautify \
    hermes-dec \
    2>/dev/null && ok "npm global packages done" || warn "npm: some packages failed"

# ─── 12. Special tool installs ───────────────────────────────────────────────
hdr "Special tool installs"

# ── stegseek ─────────────────────────────────────────────────────────────────
if ! command -v stegseek &>/dev/null; then
    log "stegseek..."
    wget -q "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6_amd64.deb" \
         -O /tmp/stegseek.deb \
    && $SUDO dpkg -i /tmp/stegseek.deb 2>/dev/null \
    && $SUDO apt-get install -f -y 2>/dev/null \
    && ok "stegseek" \
    || warn "stegseek: failed — get from github.com/RickdeJager/stegseek/releases"
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

# ── checksec (standalone script) ─────────────────────────────────────────────
if ! command -v checksec &>/dev/null; then
    log "checksec..."
    wget -q https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec \
         -O /tmp/checksec \
    && chmod +x /tmp/checksec \
    && $SUDO mv /tmp/checksec /usr/local/bin/checksec \
    && ok "checksec" \
    || warn "checksec: failed"
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
if ! python3 -c "import rsactftool" 2>/dev/null && ! command -v RsaCtfTool &>/dev/null; then
    log "RsaCtfTool..."
    pip_get rsactftool && ok "RsaCtfTool (pip)" || {
        git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool 2>/dev/null \
        && pip_get -r /opt/RsaCtfTool/requirements.txt \
        && $SUDO ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/RsaCtfTool \
        && ok "RsaCtfTool (source)" || warn "RsaCtfTool: failed"
    }
else ok "RsaCtfTool already installed"; fi

# ── tplmap ───────────────────────────────────────────────────────────────────
if [[ ! -f /opt/tplmap/tplmap.py ]]; then
    log "tplmap..."
    $SUDO git clone --depth=1 https://github.com/epinna/tplmap /opt/tplmap 2>/dev/null \
    && pip_get -r /opt/tplmap/requirements.txt 2>/dev/null \
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
    pip_get volatility3 && ok "volatility3 (pip)" || {
        git clone --depth=1 https://github.com/volatilityfoundation/volatility3 /opt/volatility3 2>/dev/null \
        && pip_get -r /opt/volatility3/requirements.txt 2>/dev/null \
        && $SUDO ln -sf /opt/volatility3/vol.py /usr/local/bin/vol \
        && ok "volatility3 (source)" || warn "volatility3: failed"
    }
else ok "volatility3 already installed"; fi

# ── SageMath ─────────────────────────────────────────────────────────────────
if ! command -v sage &>/dev/null; then
    log "SageMath (this takes a few minutes)..."
    apt_get sagemath && ok "sage" \
    || warn "sage: apt failed — install from https://www.sagemath.org/download.html"
else ok "sage already installed"; fi

# ── Playwright browsers ───────────────────────────────────────────────────────
log "Playwright browsers..."
python3 -m playwright install chromium 2>/dev/null \
&& python3 -m playwright install-deps chromium 2>/dev/null \
&& ok "playwright chromium" || warn "playwright: browser install failed"

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
chk "rsactftool"        "python3 -c 'import rsactftool' 2>/dev/null || command -v RsaCtfTool"
chk "floss"             "command -v floss || python3 -m floss --help"
chk "gdb"               "gdb --version"
chk "pwndbg"            "grep -q pwndbg ~/.gdbinit"
chk "radare2"           "r2 -version"
chk "binwalk"           "binwalk --version"
chk "tshark"            "tshark --version"
chk "tcpflow"           "tcpflow --version"
chk "foremost"          "foremost -V"
chk "steghide"          "steghide --version"
chk "stegseek"          "stegseek --version"
chk "zsteg"             "zsteg --version"
chk "outguess"          "outguess -h"
chk "zbarimg"           "zbarimg --version"
chk "qrencode"          "qrencode --version"
chk "one_gadget"        "one_gadget --version"
chk "checksec"          "checksec --version"
chk "patchelf"          "patchelf --version"
chk "upx"               "upx --version"
chk "7z"                "7z i"
chk "unar"              "unar --version"
chk "hashcat"           "hashcat --version"
chk "john"              "john --version"
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
chk "java"              "java -version"
chk "rustc"             "rustc --version"
chk "sqlmap"            "sqlmap --version"
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
