#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CTF Solver — WSL2 Install Script  (v2)
# Installs ALL Linux-side dependencies inside WSL2 (Ubuntu 22.04 / 24.04)
#
# USAGE:
#   1. Open WSL2 terminal (Ubuntu)
#   2. cd to the ctf-solver folder
#   3. bash install.sh [--skip-heavy]   # --skip-heavy skips Ghidra / SageMath
#
# The Tauri desktop app runs on Windows — see README_WINDOWS.md for
# Windows-side setup (Node, Rust, Tauri CLI).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

# ── Flags ────────────────────────────────────────────────────────────────────
SKIP_HEAVY=0
for arg in "$@"; do [[ "$arg" == "--skip-heavy" ]] && SKIP_HEAVY=1; done

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; FAILED_TOOLS+=("$*"); }
err()  { echo -e "${RED}[-]${NC} $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

FAILED_TOOLS=()
LOGFILE="/tmp/ctf-install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1
log "Full install log → $LOGFILE"

# ── Cleanup trap ─────────────────────────────────────────────────────────────
cleanup() {
    local code=$?
    [[ $code -ne 0 ]] && err "Script exited with code $code — check $LOGFILE"
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Preflight checks"

# ── WSL check ────────────────────────────────────────────────────────────────
if ! grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    warn "Not running inside WSL2 — continuing anyway (pure Linux is fine)."
fi

# ── Root / sudo ───────────────────────────────────────────────────────────────
SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

# ── Architecture ─────────────────────────────────────────────────────────────
ARCH=$(uname -m)     # x86_64 | aarch64
ok "Architecture: $ARCH"

# ── Ubuntu version ───────────────────────────────────────────────────────────
UBUNTU_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-unknown}" || echo "unknown")
ok "Ubuntu: $UBUNTU_VER"

# ── Network connectivity ──────────────────────────────────────────────────────
if ! curl -s --max-time 10 https://archive.ubuntu.com > /dev/null 2>&1; then
    err "No internet access detected. Aborting."
    exit 1
fi
ok "Network: OK"

# ── Disk space (require ≥ 10 GB free) ─────────────────────────────────────────
FREE_KB=$(df --output=avail / 2>/dev/null | tail -1 || df -k / | awk 'NR==2{print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
if [[ $FREE_GB -lt 10 ]]; then
    warn "Only ${FREE_GB}GB free — you may run out of disk space (need ~10 GB)."
else
    ok "Disk space: ${FREE_GB}GB free"
fi

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Retry a command up to N times
retry() {
    local n=${1}; shift
    local delay=${1}; shift
    local i=1
    until "$@"; do
        [[ $i -ge $n ]] && { warn "Gave up after $n tries: $*"; return 1; }
        warn "Retry $i/$n for: $*"
        sleep "$delay"
        (( i++ ))
    done
}

# wget/curl with timeout + retry
fetch() {
    local url=$1; local dest=$2
    retry 3 5 wget -q --timeout=60 --tries=3 "$url" -O "$dest"
}

apt_get() {
    local failed=()
    for pkg in "$@"; do
        $SUDO apt-get install -y --no-install-recommends "$pkg" \
            >/dev/null 2>&1 || failed+=("$pkg")
    done
    [[ ${#failed[@]} -gt 0 ]] && warn "apt: failed to install: ${failed[*]}"
}

pip_get() {
    if [[ "${1:-}" == "-r" && -n "${2:-}" ]]; then
        python3 -m pip install --quiet --break-system-packages -r "$2" \
            >/dev/null 2>&1 \
            || python3 -m pip install --quiet -r "$2" >/dev/null 2>&1 \
            || warn "pip: failed: -r $2"
        return
    fi
    local failed=()
    for pkg in "$@"; do
        python3 -m pip install --quiet --break-system-packages "$pkg" \
            >/dev/null 2>&1 \
            || python3 -m pip install --quiet "$pkg" >/dev/null 2>&1 \
            || failed+=("$pkg")
    done
    [[ ${#failed[@]} -gt 0 ]] && warn "pip: failed to install: ${failed[*]}"
}

gem_get()   { gem install --quiet "$@" 2>/dev/null || warn "gem: failed: $*"; }
cargo_get() { cargo install --quiet "$@" 2>/dev/null || warn "cargo: failed: $*"; }

go_get() {
    local pkg=$1
    if command -v go &>/dev/null; then
        GOPATH="${GOPATH:-$HOME/go}"
        go install "$pkg" >/dev/null 2>&1 || warn "go: failed: $pkg"
    else
        warn "go: not found, skipping $pkg"
    fi
}

# Latest GitHub release tag for owner/repo
gh_latest() {
    curl -s --max-time 15 \
        "https://api.github.com/repos/$1/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v'
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. SYSTEM UPDATE
# ─────────────────────────────────────────────────────────────────────────────
hdr "System update"
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
    software-properties-common ca-certificates gnupg lsb-release \
    >/dev/null 2>&1 || true
$SUDO add-apt-repository -y universe >/dev/null 2>&1 || true
$SUDO apt-get update -qq
ok "apt repos updated"

# ─────────────────────────────────────────────────────────────────────────────
# 2. BASE BUILD TOOLS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Base build tools"
apt_get \
    build-essential git curl wget \
    python3 python3-pip python3-dev python3-venv \
    ruby ruby-dev \
    nodejs npm \
    default-jdk \
    rustc cargo \
    golang-go \
    cmake pkg-config \
    gcc-multilib g++-multilib \
    libc6-dev-i386 \
    crossbuild-essential-arm64 \
    tmux socat netcat-openbsd ncat \
    fzf ripgrep \
    file xxd strings \
    gdb gdb-multiarch \
    ltrace strace \
    adb \
    apksigner

# ─────────────────────────────────────────────────────────────────────────────
# 3. BINARY ANALYSIS & EXPLOITATION
# ─────────────────────────────────────────────────────────────────────────────
hdr "Binary analysis & exploitation"
apt_get \
    radare2 \
    binutils binutils-multiarch \
    nasm \
    patchelf \
    upx-ucl \
    checksec \
    libmagic-dev \
    elfutils \
    libc6-dbg \
    libc6-dbg:i386 \
    qemu-user-static \
    binfmt-support

# ─────────────────────────────────────────────────────────────────────────────
# 4. NETWORK & PCAP
# ─────────────────────────────────────────────────────────────────────────────
hdr "Network & PCAP tools"
apt_get \
    tshark \
    tcpflow \
    tcpdump \
    openssl \
    ssldump \
    nmap masscan \
    dnsutils \
    proxychains4 \
    stunnel4 \
    iputils-ping traceroute

# ─────────────────────────────────────────────────────────────────────────────
# 5. FORENSICS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Forensics tools"
apt_get \
    foremost \
    sleuthkit \
    testdisk \
    binwalk \
    pngcheck \
    exiftool libimage-exiftool-perl \
    exiv2 \
    poppler-utils \
    icoutils \
    bulk-extractor \
    dc3dd \
    safecopy \
    hexedit \
    bless

# ─────────────────────────────────────────────────────────────────────────────
# 6. STEGANOGRAPHY
# ─────────────────────────────────────────────────────────────────────────────
hdr "Steganography tools"
apt_get \
    steghide \
    outguess \
    zbar-tools \
    qrencode \
    imagemagick \
    ffmpeg \
    sox \
    multimon-ng \
    wavbreaker \
    libwav-dev

# ─────────────────────────────────────────────────────────────────────────────
# 7. CRYPTO & CRACKING
# ─────────────────────────────────────────────────────────────────────────────
hdr "Crypto & password cracking"
apt_get \
    john \
    hashcat \
    libssl-dev \
    libgmp-dev libmpfr-dev libmpc-dev \
    libsodium-dev \
    gpg \
    openssl

# ─────────────────────────────────────────────────────────────────────────────
# 8. COMPRESSION & ARCHIVES
# ─────────────────────────────────────────────────────────────────────────────
hdr "Compression & archive tools"
apt_get \
    p7zip-full \
    unar \
    zip unzip \
    bzip2 xz-utils zstd lz4 \
    cabextract \
    arj \
    lhasa \
    cpio \
    rpm2cpio

# ─────────────────────────────────────────────────────────────────────────────
# 9. MISC SYSTEM TOOLS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Misc system tools"
apt_get \
    protobuf-compiler libprotobuf-dev \
    sqlmap \
    patchutils \
    jq yq \
    bc \
    parallel \
    wamerican \
    seclists

# ─────────────────────────────────────────────────────────────────────────────
# 10. PYTHON PACKAGES
# ─────────────────────────────────────────────────────────────────────────────
hdr "Python packages (pip)"

# Core / AI
pip_get anthropic requests urllib3 pyyaml tqdm rich

# Crypto
pip_get \
    pycryptodome cryptography \
    sympy "z3-solver" \
    gmpy2 hashpumpy \
    RsaCtfTool paddingoracle \
    xortool \
    "name-that-hash" \
    hashid \
    pyOpenSSL \
    sagemath

# Binary exploitation
pip_get \
    pwntools ropgadget ropper \
    unicorn keystone-engine capstone \
    randcrack \
    "struct-layout"

# Reversing & decompilation
pip_get \
    pefile \
    "flare-floss" \
    frida-tools \
    androguard \
    blackboxprotobuf \
    pyinstxtractor \
    "uncompyle6" \
    decompile3 \
    "decompyle3" \
    "python-decompile3"

# Web
pip_get \
    beautifulsoup4 lxml \
    httpx websockets websocket-client \
    scapy \
    shodan \
    pyjwt \
    impacket \
    requests-toolbelt \
    "XSStrike" \
    arjun \
    "dirsearch" \
    commix \
    wfuzz \
    mitmproxy \
    ssrfmap

# Forensics / image / document analysis
pip_get \
    Pillow numpy scipy \
    python-magic \
    pikepdf oletools \
    pyzbar \
    stegcracker \
    regipy \
    yara-python \
    exifread \
    python-docx python-pptx openpyxl \
    peepdf \
    "pdf-parser" \
    "oledump" \
    "msoffcrypto-tool" \
    "xlrd" xlwt

# Network / protocol
pip_get \
    paramiko scp \
    pyftpdlib \
    ldap3 \
    dnspython \
    pysnmp \
    pysmb

# WASM / misc
pip_get \
    wasmtime \
    basecrack \
    playwright chromadb \
    angr \
    "factordb-pycli" \
    "crypto-commons" \
    crcmod \
    bitstring \
    galois

# JWT tools
if ! command -v jwt-tool &>/dev/null; then
    pip_get "git+https://github.com/ticarpi/jwt_tool.git"
fi

# PyInstaller extractor (also as standalone script)
if [[ ! -f /usr/local/bin/pyinstxtractor ]]; then
    fetch "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py" \
        /tmp/pyinstxtractor.py \
    && $SUDO install -m 755 /tmp/pyinstxtractor.py /usr/local/bin/pyinstxtractor \
    && ok "pyinstxtractor" || warn "pyinstxtractor: install failed"
fi

ok "pip packages done"

# ─────────────────────────────────────────────────────────────────────────────
# 11. RUBY GEMS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Ruby gems"
gem_get one_gadget
gem_get seccomp-tools
gem_get zsteg
ok "gems done"

# ─────────────────────────────────────────────────────────────────────────────
# 12. NODE PACKAGES (global)
# ─────────────────────────────────────────────────────────────────────────────
hdr "Node packages"
npm install -g --quiet \
    js-beautify \
    javascript-obfuscator \
    typescript \
    @solidity-parser/parser \
    2>/dev/null && ok "npm global packages done" || warn "npm: some packages failed"

# ─────────────────────────────────────────────────────────────────────────────
# 13. GO TOOLS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Go tools"
if command -v go &>/dev/null; then
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$GOPATH/bin:$PATH"

    go_get "github.com/ffuf/ffuf/v2@latest"
    go_get "github.com/OJ/gobuster/v3@latest"
    go_get "github.com/tomnomnom/waybackurls@latest"
    go_get "github.com/tomnomnom/assetfinder@latest"
    go_get "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    go_get "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    go_get "github.com/hakluke/hakrawler@latest"
    go_get "github.com/lc/gau/v2/cmd/gau@latest"

    # Add GOPATH/bin to PATH permanently
    if ! grep -q 'GOPATH/bin' ~/.bashrc 2>/dev/null; then
        echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
        echo 'export PATH="$GOPATH/bin:$PATH"' >> ~/.bashrc
    fi
    ok "Go tools done"
else
    warn "Go not found — skipping Go tools"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 14. SPECIAL TOOL INSTALLS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Special tool installs"

# ── stegseek ─────────────────────────────────────────────────────────────────
if ! command -v stegseek &>/dev/null; then
    log "stegseek..."
    fetch "https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6_amd64.deb" \
          /tmp/stegseek.deb \
    && $SUDO dpkg -i /tmp/stegseek.deb 2>/dev/null \
    && $SUDO apt-get install -f -y 2>/dev/null \
    && ok "stegseek" \
    || warn "stegseek: failed — https://github.com/RickdeJager/stegseek/releases"
    rm -f /tmp/stegseek.deb
else ok "stegseek already installed"; fi

# ── pwndbg ───────────────────────────────────────────────────────────────────
if [[ ! -f ~/.gdbinit ]] || ! grep -q pwndbg ~/.gdbinit 2>/dev/null; then
    log "pwndbg..."
    retry 2 5 git clone --depth=1 https://github.com/pwndbg/pwndbg ~/pwndbg \
    && cd ~/pwndbg && bash setup.sh 2>/dev/null \
    && ok "pwndbg" \
    || warn "pwndbg: failed"
    cd - >/dev/null
else ok "pwndbg already configured"; fi

# ── GEF (GDB Enhanced Features) ──────────────────────────────────────────────
# Installed alongside pwndbg using per-binary ~/.gdbinit_pwndbg / ~/.gdbinit_gef
# pattern so you can switch with `gdb-pwndbg` / `gdb-gef` aliases
if ! command -v gdb-gef &>/dev/null && [[ ! -f ~/.gdbinit_gef ]]; then
    log "GEF..."
    fetch "https://raw.githubusercontent.com/hugsy/gef/main/gef.py" ~/.gef.py \
    && cat > ~/.gdbinit_gef <<'EOF'
source ~/.gef.py
EOF
    # Wrapper script so `gdb-gef` loads GEF instead of pwndbg
    $SUDO tee /usr/local/bin/gdb-gef >/dev/null <<'EOF'
#!/usr/bin/env bash
exec gdb -x ~/.gdbinit_gef "$@"
EOF
    $SUDO chmod +x /usr/local/bin/gdb-gef
    ok "GEF" || warn "GEF: failed"
else ok "GEF already installed"; fi

# ── checksec (standalone) ─────────────────────────────────────────────────────
if ! command -v checksec &>/dev/null; then
    log "checksec..."
    fetch "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" \
          /tmp/checksec \
    && chmod +x /tmp/checksec \
    && $SUDO mv /tmp/checksec /usr/local/bin/checksec \
    && ok "checksec" || warn "checksec: failed"
else ok "checksec already installed"; fi

# ── jadx ─────────────────────────────────────────────────────────────────────
if ! command -v jadx &>/dev/null; then
    log "jadx..."
    JADX_VER=$(gh_latest skylot/jadx || echo "1.5.0")
    fetch "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" \
          /tmp/jadx.zip \
    && $SUDO unzip -q /tmp/jadx.zip -d /opt/jadx \
    && $SUDO chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui \
    && $SUDO ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ok "jadx v${JADX_VER}" \
    || warn "jadx: failed"
    rm -f /tmp/jadx.zip
else ok "jadx already installed"; fi

# ── dex2jar ───────────────────────────────────────────────────────────────────
if ! command -v d2j-dex2jar &>/dev/null; then
    log "dex2jar..."
    DEX2JAR_VER=$(gh_latest pxb1988/dex2jar || echo "2.4")
    fetch "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VER}/dex-tools-v${DEX2JAR_VER}.zip" \
          /tmp/dex2jar.zip \
    && $SUDO unzip -q /tmp/dex2jar.zip -d /opt \
    && $SUDO mv /opt/dex-tools-v${DEX2JAR_VER} /opt/dex2jar \
    && $SUDO chmod +x /opt/dex2jar/*.sh \
    && for sh in /opt/dex2jar/d2j-*.sh; do
           base=$(basename "$sh" .sh)
           $SUDO ln -sf "$sh" /usr/local/bin/"$base"
       done \
    && ok "dex2jar v${DEX2JAR_VER}" || warn "dex2jar: failed"
    rm -f /tmp/dex2jar.zip
else ok "dex2jar already installed"; fi

# ── CFR Java decompiler ───────────────────────────────────────────────────────
if [[ ! -f /opt/cfr/cfr.jar ]]; then
    log "CFR Java decompiler..."
    CFR_VER=$(gh_latest leibnitz27/cfr || echo "0.152")
    $SUDO mkdir -p /opt/cfr
    fetch "https://github.com/leibnitz27/cfr/releases/download/${CFR_VER}/cfr-${CFR_VER}.jar" \
          /tmp/cfr.jar \
    && $SUDO mv /tmp/cfr.jar /opt/cfr/cfr.jar \
    && $SUDO tee /usr/local/bin/cfr >/dev/null <<'EOF'
#!/bin/sh
exec java -jar /opt/cfr/cfr.jar "$@"
EOF
    $SUDO chmod +x /usr/local/bin/cfr \
    && ok "CFR v${CFR_VER}" || warn "CFR: failed"
else ok "CFR already installed"; fi

# ── Procyon Java decompiler ───────────────────────────────────────────────────
if [[ ! -f /opt/procyon/procyon.jar ]]; then
    log "Procyon Java decompiler..."
    $SUDO mkdir -p /opt/procyon
    PROC_VER=$(gh_latest mstrobel/procyon || echo "0.6.0")
    fetch "https://github.com/mstrobel/procyon/releases/download/v${PROC_VER}/procyon-decompiler-${PROC_VER}.jar" \
          /tmp/procyon.jar \
    && $SUDO mv /tmp/procyon.jar /opt/procyon/procyon.jar \
    && $SUDO tee /usr/local/bin/procyon >/dev/null <<'EOF'
#!/bin/sh
exec java -jar /opt/procyon/procyon.jar "$@"
EOF
    $SUDO chmod +x /usr/local/bin/procyon \
    && ok "Procyon v${PROC_VER}" || warn "Procyon: failed"
else ok "Procyon already installed"; fi

# ── apktool ───────────────────────────────────────────────────────────────────
if ! command -v apktool &>/dev/null; then
    log "apktool..."
    apt_get apktool 2>/dev/null && ok "apktool (apt)" || {
        APKTOOL_VER=$(gh_latest iBotPeaches/Apktool || echo "2.9.3")
        fetch "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" \
           /tmp/apktool.jar \
       && $SUDO mv /tmp/apktool.jar /usr/local/bin/apktool.jar \
        && printf '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"\n' \
             | $SUDO tee /usr/local/bin/apktool >/dev/null \
        && $SUDO chmod +x /usr/local/bin/apktool \
        && ok "apktool v${APKTOOL_VER}" || warn "apktool: failed"
    }
else ok "apktool already installed"; fi

# ── Ghidra ────────────────────────────────────────────────────────────────────
if [[ $SKIP_HEAVY -eq 0 ]]; then
    if ! command -v ghidra &>/dev/null && [[ ! -d /opt/ghidra ]]; then
        log "Ghidra (large download ~600 MB)..."
        GHIDRA_VER=$(gh_latest NationalSecurityAgency/ghidra || echo "11.1.2")
        GHIDRA_DATE=$(curl -s "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" \
            | grep '"tag_name"' | grep -oP '\d{8}' || echo "20240709")
        GHIDRA_ZIP="ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip"
        if fetch "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/${GHIDRA_ZIP}" /tmp/ghidra.zip \
        && $SUDO unzip -q /tmp/ghidra.zip -d /opt \
        && $SUDO mv "/opt/ghidra_${GHIDRA_VER}_PUBLIC" /opt/ghidra; then
            $SUDO tee /usr/local/bin/ghidra >/dev/null <<'EOF'
#!/bin/sh
exec /opt/ghidra/ghidraRun "$@"
EOF
            $SUDO chmod +x /usr/local/bin/ghidra
            # Headless analyzeHeadless wrapper
            $SUDO tee /usr/local/bin/ghidra-headless >/dev/null <<'EOF'
#!/bin/sh
exec /opt/ghidra/support/analyzeHeadless "$@"
EOF
            $SUDO chmod +x /usr/local/bin/ghidra-headless
            ok "Ghidra v${GHIDRA_VER}"
        else
            warn "Ghidra: failed — install manually from https://ghidra-sre.org/"
        fi
        rm -f /tmp/ghidra.zip
    else ok "Ghidra already installed"; fi

    # pyhidra — Python bindings for Ghidra headless
    if [[ -d /opt/ghidra ]]; then
        pip_get pyhidra && ok "pyhidra" || warn "pyhidra: failed (install Ghidra first)"
    fi
else warn "Skipping Ghidra (--skip-heavy)"; fi

# ── WABT (WebAssembly Binary Toolkit) ────────────────────────────────────────
if ! command -v wasm2wat &>/dev/null; then
    log "WABT..."
    WABT_VER=$(gh_latest WebAssembly/wabt || echo "1.0.36")
    fetch "https://github.com/WebAssembly/wabt/releases/download/${WABT_VER}/wabt-${WABT_VER}-ubuntu.tar.gz" \
          /tmp/wabt.tar.gz \
    && $SUDO tar -xzf /tmp/wabt.tar.gz -C /opt \
    && $SUDO ln -sf "/opt/wabt-${WABT_VER}/bin/wasm2wat"  /usr/local/bin/wasm2wat \
    && $SUDO ln -sf "/opt/wabt-${WABT_VER}/bin/wat2wasm"  /usr/local/bin/wat2wasm \
    && $SUDO ln -sf "/opt/wabt-${WABT_VER}/bin/wasm-objdump" /usr/local/bin/wasm-objdump \
    && $SUDO ln -sf "/opt/wabt-${WABT_VER}/bin/wasm-decompile" /usr/local/bin/wasm-decompile \
    && ok "WABT v${WABT_VER}" || warn "WABT: failed"
    rm -f /tmp/wabt.tar.gz
else ok "WABT already installed"; fi

# ── RsaCtfTool ────────────────────────────────────────────────────────────────
if ! command -v RsaCtfTool &>/dev/null; then
    log "RsaCtfTool..."
    pip_get RsaCtfTool && ok "RsaCtfTool (pip)" || {
        retry 2 5 git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool \
        && pip_get -r /opt/RsaCtfTool/requirements.txt \
        && $SUDO ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/RsaCtfTool \
        && ok "RsaCtfTool (source)" || warn "RsaCtfTool: failed"
    }
else ok "RsaCtfTool already installed"; fi

# ── xortool ───────────────────────────────────────────────────────────────────
if ! command -v xortool &>/dev/null; then
    pip_get xortool && ok "xortool" || warn "xortool: failed"
else ok "xortool already installed"; fi

# ── tplmap ────────────────────────────────────────────────────────────────────
if [[ ! -f /opt/tplmap/tplmap.py ]]; then
    log "tplmap..."
    $SUDO git clone --depth=1 https://github.com/epinna/tplmap /opt/tplmap 2>/dev/null \
    && pip_get -r /opt/tplmap/requirements.txt 2>/dev/null \
    && $SUDO tee /usr/local/bin/tplmap >/dev/null <<'EOF'
#!/bin/sh
exec python3 /opt/tplmap/tplmap.py "$@"
EOF
    $SUDO chmod +x /usr/local/bin/tplmap \
    && ok "tplmap" || warn "tplmap: failed"
else ok "tplmap already at /opt/tplmap"; fi

# ── ysoserial ─────────────────────────────────────────────────────────────────
if [[ ! -f /opt/ysoserial/ysoserial.jar ]]; then
    log "ysoserial..."
    $SUDO mkdir -p /opt/ysoserial \
    && fetch "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" \
             /tmp/ysoserial.jar \
    && $SUDO mv /tmp/ysoserial.jar /opt/ysoserial/ysoserial.jar \
    && $SUDO tee /usr/local/bin/ysoserial >/dev/null <<'EOF'
#!/bin/sh
exec java -jar /opt/ysoserial/ysoserial.jar "$@"
EOF
    $SUDO chmod +x /usr/local/bin/ysoserial \
    && ok "ysoserial" || warn "ysoserial: failed"
else ok "ysoserial already present"; fi

# ── phpggc ────────────────────────────────────────────────────────────────────
if ! command -v phpggc &>/dev/null; then
    log "phpggc..."
    $SUDO git clone --depth=1 https://github.com/ambionics/phpggc /opt/phpggc 2>/dev/null \
    && $SUDO ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc \
    && ok "phpggc" || warn "phpggc: failed"
else ok "phpggc already installed"; fi

# ── hash_extender ─────────────────────────────────────────────────────────────
if ! command -v hash_extender &>/dev/null; then
    log "hash_extender..."
    retry 2 5 git clone --depth=1 https://github.com/iagox86/hash_extender /tmp/hext 2>/dev/null \
    && cd /tmp/hext && make -s 2>/dev/null \
    && $SUDO cp hash_extender /usr/local/bin/ \
    && ok "hash_extender" || warn "hash_extender: build failed"
    cd - >/dev/null; rm -rf /tmp/hext
else ok "hash_extender already installed"; fi

# ── pwninit ───────────────────────────────────────────────────────────────────
if ! command -v pwninit &>/dev/null; then
    log "pwninit..."
    # Try cargo first, fall back to prebuilt binary
    cargo_get pwninit && ok "pwninit (cargo)" || {
        PWNINIT_VER=$(gh_latest io12/pwninit || echo "3.3.1")
        fetch "https://github.com/io12/pwninit/releases/download/${PWNINIT_VER}/pwninit" \
              /tmp/pwninit \
        && chmod +x /tmp/pwninit \
        && $SUDO mv /tmp/pwninit /usr/local/bin/pwninit \
        && ok "pwninit v${PWNINIT_VER} (prebuilt)" || warn "pwninit: all methods failed"
    }
else ok "pwninit already installed"; fi

# ── libc-database ─────────────────────────────────────────────────────────────
if [[ ! -d /opt/libc-database ]]; then
    log "libc-database..."
    $SUDO git clone --depth=1 https://github.com/niklasb/libc-database /opt/libc-database \
    && $SUDO tee /usr/local/bin/libc-find >/dev/null <<'EOF'
#!/bin/sh
exec /opt/libc-database/find "$@"
EOF
    $SUDO chmod +x /usr/local/bin/libc-find \
    && ok "libc-database" || warn "libc-database: failed"
else ok "libc-database already at /opt/libc-database"; fi

# ── pwncat-cs ─────────────────────────────────────────────────────────────────
if ! command -v pwncat-cs &>/dev/null; then
    log "pwncat-cs (advanced netcat for CTF)..."
    pip_get "pwncat-cs" && ok "pwncat-cs" || warn "pwncat-cs: failed"
else ok "pwncat-cs already installed"; fi

# ── volatility3 ───────────────────────────────────────────────────────────────
if ! python3 -c "import volatility3" 2>/dev/null; then
    log "volatility3..."
    pip_get volatility3 && ok "volatility3 (pip)" || {
        retry 2 5 git clone --depth=1 https://github.com/volatilityfoundation/volatility3 /opt/volatility3 \
        && pip_get -r /opt/volatility3/requirements.txt \
        && $SUDO ln -sf /opt/volatility3/vol.py /usr/local/bin/vol \
        && ok "volatility3 (source)" || warn "volatility3: failed"
    }
else ok "volatility3 already installed"; fi

# ── XSStrike ──────────────────────────────────────────────────────────────────
if [[ ! -d /opt/XSStrike ]]; then
    log "XSStrike..."
    $SUDO git clone --depth=1 https://github.com/s0md3v/XSStrike /opt/XSStrike \
    && pip_get -r /opt/XSStrike/requirements.txt \
    && $SUDO tee /usr/local/bin/xsstrike >/dev/null <<'EOF'
#!/bin/sh
exec python3 /opt/XSStrike/xsstrike.py "$@"
EOF
    $SUDO chmod +x /usr/local/bin/xsstrike \
    && ok "XSStrike" || warn "XSStrike: failed"
else ok "XSStrike already installed"; fi

# ── NoSQLMap ─────────────────────────────────────────────────────────────────
if ! command -v nosqlmap &>/dev/null && [[ ! -f /opt/NoSQLMap/nosqlmap.py ]]; then
    log "NoSQLMap..."
    $SUDO git clone --depth=1 https://github.com/codingo/NoSQLMap /opt/NoSQLMap \
    && pip_get -r /opt/NoSQLMap/requirements.txt \
    && $SUDO tee /usr/local/bin/nosqlmap >/dev/null <<'EOF'
#!/bin/sh
exec python3 /opt/NoSQLMap/nosqlmap.py "$@"
EOF
    $SUDO chmod +x /usr/local/bin/nosqlmap \
    && ok "NoSQLMap" || warn "NoSQLMap: failed"
else ok "NoSQLMap already installed"; fi

# ── fuxploider ────────────────────────────────────────────────────────────────
if ! command -v fuxploider &>/dev/null; then
    log "fuxploider..."
    pip_get fuxploider && ok "fuxploider" || warn "fuxploider: failed"
else ok "fuxploider already installed"; fi

# ── Docker CLI/runtime (used by sandbox helpers) ─────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Docker CLI/runtime..."
    apt_get docker.io docker-compose-v2 \
    && ok "docker" || warn "docker: failed (optional for docker_sandbox tool)"
else ok "docker already installed"; fi

# ── SageMath ──────────────────────────────────────────────────────────────────
if [[ $SKIP_HEAVY -eq 0 ]]; then
    if ! command -v sage &>/dev/null; then
        log "SageMath (may take several minutes)..."
        apt_get sagemath && ok "sage" \
        || warn "sage: apt failed — install from https://www.sagemath.org/download.html"
    else ok "sage already installed"; fi
else warn "Skipping SageMath (--skip-heavy)"; fi

# ── Playwright browsers ───────────────────────────────────────────────────────
log "Playwright browsers..."
python3 -m playwright install chromium 2>/dev/null \
&& python3 -m playwright install-deps chromium 2>/dev/null \
&& ok "playwright chromium" || warn "playwright: browser install failed"

# ── CyberChef (local copy) ────────────────────────────────────────────────────
if [[ ! -f /opt/cyberchef/index.html ]]; then
    log "CyberChef (offline)..."
    CC_VER=$(gh_latest gchq/CyberChef || echo "10.19.0")
    $SUDO mkdir -p /opt/cyberchef
    fetch "https://github.com/gchq/CyberChef/releases/download/v${CC_VER}/CyberChef_v${CC_VER}.zip" \
          /tmp/cyberchef.zip \
    && $SUDO unzip -q /tmp/cyberchef.zip -d /opt/cyberchef \
    && ok "CyberChef v${CC_VER} → /opt/cyberchef" \
    || warn "CyberChef: failed"
    rm -f /tmp/cyberchef.zip
else ok "CyberChef already at /opt/cyberchef"; fi

# ── Wordlists (rockyou) ───────────────────────────────────────────────────────
if [[ ! -f /usr/share/wordlists/rockyou.txt ]]; then
    log "rockyou.txt wordlist..."
    apt_get wordlists 2>/dev/null \
    && [[ -f /usr/share/wordlists/rockyou.txt.gz ]] \
    && $SUDO gunzip /usr/share/wordlists/rockyou.txt.gz \
    && ok "rockyou.txt" \
    || warn "rockyou.txt: apt install failed — download from danielmiessler/SecLists"
else ok "rockyou.txt already present"; fi

# ─────────────────────────────────────────────────────────────────────────────
# 15. API KEY CHECK
# ─────────────────────────────────────────────────────────────────────────────
hdr "API Key"
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    warn "ANTHROPIC_API_KEY is not set!"
    warn "Add to ~/.bashrc:"
    warn "  export ANTHROPIC_API_KEY='sk-ant-...'"
else
    ok "ANTHROPIC_API_KEY is set"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 16. VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
hdr "Verification"

chk() {
    local label=$1; local test_cmd=$2
    if eval "$test_cmd" &>/dev/null 2>&1; then
        ok "$label"
    else
        warn "$label — MISSING"
    fi
}

echo ""
echo -e "${BOLD}── Python packages ──${NC}"
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
chk "androguard"        "python3 -c 'import androguard'"
chk "paramiko"          "python3 -c 'import paramiko'"
chk "pefile"            "python3 -c 'import pefile'"
chk "pikepdf"           "python3 -c 'import pikepdf'"
chk "pyzbar"            "python3 -c 'from pyzbar.pyzbar import decode'"
chk "blackboxprotobuf"  "python3 -c 'import blackboxprotobuf'"
chk "basecrack"         "python3 -c 'import basecrack'"
chk "impacket"          "python3 -c 'import impacket'"
chk "scapy"             "python3 -c 'import scapy'"
chk "mitmproxy"         "python3 -c 'import mitmproxy'"
chk "shodan"            "command -v shodan"
chk "capstone"          "python3 -c 'import capstone'"
chk "unicorn"           "python3 -c 'import unicorn'"
chk "keystone"          "python3 -c 'import keystone'"
chk "ropper"            "python3 -c 'import ropper'"
chk "xortool"           "command -v xortool"
chk "name-that-hash"    "command -v nth || python3 -c 'import name_that_hash'"
chk "volatility3"       "python3 -c 'import volatility3'"
chk "yara"              "python3 -c 'import yara'"
chk "pwncat-cs"         "command -v pwncat-cs"
chk "factordb"          "python3 -c 'import factordb'"
chk "galois"            "python3 -c 'import galois'"

echo ""
echo -e "${BOLD}── Binary tools ──${NC}"
chk "gdb"               "gdb --version"
chk "gdb-multiarch"     "gdb-multiarch --version"
chk "pwndbg"            "grep -q pwndbg ~/.gdbinit"
chk "gef"               "test -f ~/.gef.py"
chk "radare2"           "r2 -version"
chk "checksec"          "checksec --version"
chk "patchelf"          "patchelf --version"
chk "upx"               "upx --version"
chk "binwalk"           "binwalk --version"
chk "ropper"            "command -v ropper"
chk "ropgadget"         "command -v ROPgadget"
chk "qemu-user"         "qemu-x86_64-static --version"
chk "adb"               "command -v adb"
chk "apksigner"         "command -v apksigner"
chk "pwninit"           "command -v pwninit"
chk "libc-database"     "test -d /opt/libc-database"
chk "rappel"            "command -v rappel"

echo ""
echo -e "${BOLD}── Forensics / stego ──${NC}"
chk "foremost"          "foremost -V"
chk "bulk_extractor"    "bulk_extractor --version"
chk "tshark"            "tshark --version"
chk "tcpflow"           "tcpflow --version"
chk "steghide"          "steghide --version"
chk "stegseek"          "stegseek --version"
chk "zsteg"             "zsteg --version"
chk "outguess"          "outguess -h"
chk "zbarimg"           "zbarimg --version"
chk "qrencode"          "qrencode --version"
chk "exiftool"          "exiftool -ver"
chk "ffmpeg"            "ffmpeg -version"

echo ""
echo -e "${BOLD}── Crypto ──${NC}"
chk "hashcat"           "hashcat --version"
chk "john"              "john --version"
chk "rsactftool"        "command -v RsaCtfTool"
chk "hash_extender"     "command -v hash_extender"
chk "sage"              "command -v sage"

echo ""
echo -e "${BOLD}── Web / network ──${NC}"
chk "sqlmap"            "sqlmap --version"
chk "ffuf"              "command -v ffuf"
chk "gobuster"          "command -v gobuster"
chk "nmap"              "nmap --version"
chk "tplmap"            "test -f /opt/tplmap/tplmap.py"
chk "ysoserial"         "test -f /opt/ysoserial/ysoserial.jar"
chk "phpggc"            "phpggc --list"
chk "xsstrike"          "command -v xsstrike"
chk "jwt-tool"          "command -v jwt-tool"
chk "stegcracker"       "command -v stegcracker || python3 -c 'import stegcracker'"
chk "mitmproxy"         "command -v mitmproxy"
chk "nosqlmap"          "command -v nosqlmap || test -f /opt/NoSQLMap/nosqlmap.py"
chk "fuxploider"        "command -v fuxploider"

echo ""
echo -e "${BOLD}── Reversing / JAVA / Android ──${NC}"
chk "jadx"              "jadx --version"
chk "apktool"           "apktool --version"
chk "dex2jar"           "command -v d2j-dex2jar"
chk "cfr"               "command -v cfr"
chk "procyon"           "command -v procyon"
chk "ghidra"            "test -f /opt/ghidra/ghidraRun"
chk "ghidra-headless"   "command -v ghidra-headless"
chk "floss"             "command -v floss || python3 -m floss --help"
chk "pyhidra"           "python3 -c 'import pyhidra' 2>/dev/null || true"
chk "wasm2wat"          "command -v wasm2wat"
chk "wasmtime"          "python3 -c 'import wasmtime'"
chk "pyinstxtractor"    "command -v pyinstxtractor"

echo ""
echo -e "${BOLD}── Misc ──${NC}"
chk "java"              "java -version"
chk "rustc"             "rustc --version"
chk "node"              "node --version"
chk "js-beautify"       "js-beautify --version"
chk "socat"             "socat -V"
chk "docker"            "command -v docker"
chk "tmux"              "tmux -V"
chk "fzf"               "fzf --version"
chk "7z"                "7z i"
chk "unar"              "unar --version"
chk "one_gadget"        "one_gadget --version"
chk "seccomp-tools"     "seccomp-tools --version"
chk "cyberchef"         "test -f /opt/cyberchef/index.html"
chk "rockyou.txt"       "test -f /usr/share/wordlists/rockyou.txt"

# ─────────────────────────────────────────────────────────────────────────────
# 17. FAILURE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
hdr "Summary"

if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}The following items had warnings or failures:${NC}"
    for f in "${FAILED_TOOLS[@]}"; do
        echo -e "  ${RED}✗${NC} $f"
    done
    echo ""
    echo "Full log: $LOGFILE"
else
    ok "All tools installed without warnings!"
fi

echo ""
ok "Install complete!"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. Set API key (if not done):"
echo "     echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc && source ~/.bashrc"
echo ""
echo "  2. (Optional) Download common libc versions:"
echo "     cd /opt/libc-database && ./get ubuntu  # or 'all' for everything"
echo ""
echo "  3. Test sidecar from WSL:"
printf "     echo '{\"mode\":\"solve\",\"challenge\":{\"name\":\"test\",\"category\":\"General Skills\",\"description\":\"echo hello\"}}'"
echo " \\"
echo "       | python3 sidecar/solver.py"
echo ""
echo "  4. On Windows — open PowerShell:"
echo "     cd ctf-solver && npm install && npm run dev"
echo ""
echo "  5. GDB tips:"
echo "     gdb          → pwndbg (default)"
echo "     gdb-gef      → GEF"
echo "     gdb-multiarch → cross-architecture debugging"