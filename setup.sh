#!/usr/bin/env bash
# Guardian CLI Deluxe - COMPLETE Setup (All Tools + Fixes + Enhancements)
# This version includes:
#   - ALL original tools from setup.sh
#   - Fixed dalfox (go install)
#   - Fixed commix (safe git clone)
#   - Fixed gitleaks (zricethezav path)
#   - Fixed trufflehog (binary install)
#   - Enhanced retire.js
#   - ZAP hybrid mode
#   - New recon tools (interactsh, gau, CORScanner)
#   - Smart port scanning
#   - Made idempotent
#   - Removed ancient/deprecated tools
#   - Python 3.12 compatible

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${BASE_DIR}/venv"
VENV_BIN=""
TOOLS_DIR="${BASE_DIR}/tools/vendor"
BIN_DIR="${BASE_DIR}/tools/.bin"

# Retry settings (can override via environment)
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
if [[ -f /etc/debian_version ]]; then
    OS="debian"
else
    OS="linux"
fi

log_info "Detected OS: ${OS}"

# ============================================================================
# RETRY LOGIC
# ============================================================================

retry() {
    local max_attempts="${1:-$MAX_RETRIES}"
    local delay="${2:-$RETRY_DELAY}"
    shift 2
    local cmd="$*"
    
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if eval "$cmd"; then
            return 0
        fi
        
        if [[ $attempt -lt $max_attempts ]]; then
            log_warn "Attempt ${attempt}/${max_attempts} failed. Retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done
    
    log_error "Command failed after ${max_attempts} attempts"
    return 1
}

# ============================================================================
# PYTHON VERSION CHECK
# ============================================================================

PYTHON_CHECK_BIN=""
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VENV_DIR}/bin/python" ]]; then
    PYTHON_CHECK_BIN="${VENV_DIR}/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CHECK_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CHECK_BIN="$(command -v python)"
fi

if [[ -n "${PYTHON_CHECK_BIN}" ]]; then
    if ! "${PYTHON_CHECK_BIN}" - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major, sys.version_info.minor) >= (3, 11) else 1)
PY
    then
        log_error "Python 3.11+ is required."
        exit 1
    fi
fi

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

safe_git_clone() {
    local repo_url="$1"
    local target_dir="$2"

    if [[ -d "$target_dir" ]]; then
        if [[ -d "${target_dir}/.git" ]]; then
            log_info "Updating existing repo: $(basename "$target_dir")"
            (cd "$target_dir" && git pull --ff-only 2>/dev/null) || log_warn "Failed to update"
        else
            log_warn "Removing broken directory (not a git repo): $(basename "$target_dir")"
            rm -rf "$target_dir"
            retry "$MAX_RETRIES" "$RETRY_DELAY" "git clone --depth 1 '$repo_url' '$target_dir'" || log_warn "Clone failed: $repo_url"
        fi
    else
        retry "$MAX_RETRIES" "$RETRY_DELAY" "git clone --depth 1 '$repo_url' '$target_dir'" || log_warn "Clone failed: $repo_url"
    fi
}

link_into_venv() {
    local src="$1"
    local name="$2"

    if [[ -x "${src}" ]]; then
        ln -sf "${src}" "${VENV_BIN}/${name}" 2>/dev/null || cp "${src}" "${VENV_BIN}/${name}"
        chmod +x "${VENV_BIN}/${name}" 2>/dev/null || true
        log_success "Linked ${name}"
    else
        log_warn "Source not executable: ${src}"
    fi
}

go_install_and_link() {
    local pkg="$1"
    local bin="$2"

    if [[ -x "${VENV_BIN}/${bin}" ]]; then
        log_info "${bin} already installed"
        return 0
    fi

    if command -v "$bin" >/dev/null 2>&1; then
        link_into_venv "$(command -v "$bin")" "$bin"
        return 0
    fi

    if ! command -v go >/dev/null 2>&1; then
        log_warn "go not found; skipping ${bin}"
        return 0
    fi

    log_info "Installing ${bin} via go install..."
    if retry "$MAX_RETRIES" "$RETRY_DELAY" "go install '${pkg}'"; then
        local gobin
        gobin="$(go env GOBIN 2>/dev/null || true)"
        if [[ -z "${gobin}" ]]; then
            gobin="$(go env GOPATH 2>/dev/null || true)"
            gobin="${gobin:-${GOPATH:-$HOME/go}}/bin"
        fi
        if [[ -x "${gobin}/${bin}" ]]; then
            link_into_venv "${gobin}/${bin}" "${bin}"
        fi
    else
        log_warn "Failed to install ${bin}"
    fi
}

write_python_wrapper_into_venv() {
    local script="$1"
    local name="$2"

    cat > "${VENV_BIN}/${name}" <<WRAPPER
#!/usr/bin/env bash
source "${VENV_BIN}/activate"
exec python "${script}" "\$@"
WRAPPER
    chmod +x "${VENV_BIN}/${name}"
    log_success "Created wrapper: ${name}"
}

install_system_binary() {
    local bin="$1"
    local apt_pkg="$2"

    if command -v "${bin}" >/dev/null 2>&1; then
        link_into_venv "$(command -v "${bin}")" "${bin}"
        return 0
    fi

    if [[ "${OS}" == "debian" ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            log_info "Installing ${bin} via apt..."
            sudo apt-get update -qq && sudo apt-get install -y "${apt_pkg}" 2>/dev/null || true
            command -v "${bin}" >/dev/null 2>&1 && link_into_venv "$(command -v "${bin}")" "${bin}"
        fi
    fi
}

install_github_release_and_link() {
    local repo="$1"
    local bin="$2"

    mkdir -p "${BIN_DIR}"

    if [[ -x "${BIN_DIR}/${bin}" ]]; then
        link_into_venv "${BIN_DIR}/${bin}" "${bin}"
        return 0
    fi

    if [[ -f "${BASE_DIR}/scripts/install_github_release_binary.py" ]]; then
        python "${BASE_DIR}/scripts/install_github_release_binary.py" "${repo}" "${bin}" || return 1
        [[ -x "${BIN_DIR}/${bin}" ]] && link_into_venv "${BIN_DIR}/${bin}" "${bin}"
    else
        log_warn "GitHub release installer script not found"
        return 1
    fi
}

# ============================================================================
# CORE SETUP
# ============================================================================

install_libpcap_dev() {
    if [[ "${OS}" == "debian" ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y libpcap-dev 2>/dev/null || true
        fi
    fi
}

ensure_go() {
    command -v go >/dev/null 2>&1 && return
    if [[ "${OS}" == "debian" ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y golang-go
    fi
}

ensure_node_and_npm() {
    command -v npm >/dev/null 2>&1 && return
    if [[ "${OS}" == "debian" ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y nodejs npm
    fi
}

ensure_rust() {
    # Check if cargo is already available
    if command -v cargo >/dev/null 2>&1; then
        log_success "Rust/cargo already installed ($(cargo --version 2>/dev/null || echo 'version unknown'))"
        return 0
    fi

    log_info "Installing Rust toolchain via rustup..."

    # Download and run rustup installer (non-interactive)
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal 2>/dev/null || {
            log_warn "Rust installation failed - feroxbuster will use binary download fallback"
            return 1
        }

        # Source cargo env for current shell
        if [[ -f "${HOME}/.cargo/env" ]]; then
            source "${HOME}/.cargo/env"
        fi

        if command -v cargo >/dev/null 2>&1; then
            log_success "Rust installed successfully ($(cargo --version))"
            return 0
        fi
    fi

    log_warn "Could not install Rust - feroxbuster will rely on binary downloads"
    return 1
}

# ============================================================================
# INITIAL SETUP
# ============================================================================

install_libpcap_dev

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    if [[ -f "${VENV_DIR}/bin/activate" ]]; then
        log_info "No virtualenv active; using ${VENV_DIR}"
        source "${VENV_DIR}/bin/activate"
    else
        log_error "No virtualenv active."
        echo "Create and activate one:" >&2
        echo "  python3.12 -m venv venv" >&2
        echo "  source venv/bin/activate" >&2
        exit 1
    fi
fi

VENV_BIN="${VIRTUAL_ENV}/bin"

ensure_go
ensure_node_and_npm
# Note: ensure_rust is lazy-loaded - only called by feroxbuster if binary download fails

log_info "Using virtualenv: ${VIRTUAL_ENV}"
mkdir -p "${TOOLS_DIR}" "${BIN_DIR}"

# Install project and core dependencies
log_info "Installing guardian-cli-deluxe and core dependencies..."
"${VENV_BIN}/pip" install --upgrade pip setuptools wheel --quiet
"${VENV_BIN}/pip" install -e "${BASE_DIR}" --quiet 2>/dev/null || log_warn "Editable install skipped"

# Uninstall old incompatible packages
"${VENV_BIN}/pip" uninstall -y requests urllib3 chardet charset-normalizer safeurl 2>/dev/null || true

# Install Python 3.12 compatible versions
log_info "Installing Python 3.12 compatible dependencies..."
"${VENV_BIN}/pip" install --upgrade \
    "requests>=2.32.0" \
    "urllib3>=2.0.0" \
    "charset-normalizer>=3.0.0" \
    "attrs>=22.2.0" \
    --quiet

# Install langchain ecosystem
log_info "Installing LangChain ecosystem..."
"${VENV_BIN}/pip" install --upgrade \
    "langchain>=0.2.0" \
    "langchain-core>=0.2.0" \
    "langchain-community>=0.2.0" \
    "langchain-ollama>=0.1.0" \
    "langsmith>=0.1.0" \
    --quiet

if [[ -f "${BASE_DIR}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    (cd "${BASE_DIR}" && npm install) 2>/dev/null || true
fi

# ============================================================================
# PROJECTDISCOVERY TOOLS
# ============================================================================

install_projectdiscovery_tools() {
    log_info "Installing ProjectDiscovery tools..."

    # Try GitHub releases first, fall back to go install
    install_github_release_and_link "projectdiscovery/httpx" "httpx" || \
        go_install_and_link "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"

    install_github_release_and_link "projectdiscovery/nuclei" "nuclei" || \
        go_install_and_link "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"

    install_github_release_and_link "projectdiscovery/subfinder" "subfinder" || \
        go_install_and_link "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"

    install_github_release_and_link "projectdiscovery/dnsx" "dnsx" || \
        go_install_and_link "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"

    install_github_release_and_link "projectdiscovery/katana" "katana" || \
        go_install_and_link "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"

    install_github_release_and_link "projectdiscovery/naabu" "naabu" || \
        go_install_and_link "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "naabu"

    install_github_release_and_link "projectdiscovery/shuffledns" "shuffledns" || \
        go_install_and_link "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" "shuffledns"

    install_github_release_and_link "projectdiscovery/asnmap" "asnmap" || \
        go_install_and_link "github.com/projectdiscovery/asnmap/cmd/asnmap@latest" "asnmap"

    go_install_and_link "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "interactsh-client"

    log_success "ProjectDiscovery tools installed"
}

# ============================================================================
# GO TOOLS
# ============================================================================

install_go_tools() {
    log_info "Installing Go-based tools..."

    go_install_and_link "github.com/ffuf/ffuf/v2@latest" "ffuf"
    go_install_and_link "github.com/tomnomnom/waybackurls@latest" "waybackurls"
    go_install_and_link "github.com/lc/gau/v2/cmd/gau@latest" "gau"
    go_install_and_link "github.com/hahwul/dalfox/v2@latest" "dalfox"
    go_install_and_link "github.com/zricethezav/gitleaks/v8@latest" "gitleaks"
    go_install_and_link "github.com/d3mondev/puredns/v2@latest" "puredns"
    go_install_and_link "github.com/lc/subjs@latest" "subjs"

    # REPLACED: wappalyzer (npm, deprecated) -> webanalyze
    go_install_and_link "github.com/rverton/webanalyze/cmd/webanalyze@latest" "webanalyze"

    # God-eye - comprehensive recon and security assessment
    if [[ -x "${VENV_BIN}/god-eye" ]]; then
        log_info "god-eye already installed"
    elif command -v god-eye >/dev/null 2>&1; then
        link_into_venv "$(command -v god-eye)" "god-eye"
    elif command -v go >/dev/null 2>&1; then
        safe_git_clone "https://github.com/Vyntral/god-eye.git" "${TOOLS_DIR}/god-eye"
        if [[ -d "${TOOLS_DIR}/god-eye/cmd/god-eye" ]]; then
            log_info "Building god-eye from source..."
            retry "$MAX_RETRIES" "$RETRY_DELAY" \
                "cd '${TOOLS_DIR}/god-eye' && go build -o '${TOOLS_DIR}/god-eye/god-eye' ./cmd/god-eye" || true
            [[ -x "${TOOLS_DIR}/god-eye/god-eye" ]] && link_into_venv "${TOOLS_DIR}/god-eye/god-eye" "god-eye"
        else
            log_warn "god-eye source layout unexpected; skipping build"
        fi
    else
        log_warn "go not found; skipping god-eye"
    fi

    # Kiterunner - only try GitHub release (go install path is broken upstream)
    install_github_release_and_link "assetnote/kiterunner" "kr" || \
        log_warn "kr (kiterunner) installation failed - GitHub release not available for this OS/arch"

    log_success "Go tools installed"
}

# ============================================================================
# TRUFFLEHOG (BINARY - NOT PIP)
# ============================================================================

install_trufflehog() {
    if [[ -x "${VENV_BIN}/trufflehog" ]]; then
        log_info "trufflehog already installed"
        return 0
    fi

    log_info "Installing trufflehog via official installer..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "${VENV_BIN}" 2>/dev/null; then
        log_success "Installed trufflehog"
    else
        log_warn "trufflehog installation failed"
    fi
}

# ============================================================================
# GIT-CLONED TOOLS
# ============================================================================

install_testssl() {
    safe_git_clone "https://github.com/drwetter/testssl.sh.git" "${TOOLS_DIR}/testssl.sh"
    [[ -f "${TOOLS_DIR}/testssl.sh/testssl.sh" ]] && link_into_venv "${TOOLS_DIR}/testssl.sh/testssl.sh" "testssl"
}

install_xsstrike() {
    safe_git_clone "https://github.com/s0md3v/XSStrike.git" "${TOOLS_DIR}/XSStrike"
    if [[ -f "${TOOLS_DIR}/XSStrike/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/XSStrike/requirements.txt" --quiet 2>/dev/null || true
    fi
    [[ -f "${TOOLS_DIR}/XSStrike/xsstrike.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/XSStrike/xsstrike.py" "xsstrike"
}

install_cmseek() {
    safe_git_clone "https://github.com/Tuhinshubhra/CMSeeK.git" "${TOOLS_DIR}/CMSeeK"
    if [[ -f "${TOOLS_DIR}/CMSeeK/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/CMSeeK/requirements.txt" --quiet 2>/dev/null || true
    fi
    [[ -f "${TOOLS_DIR}/CMSeeK/cmseek.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/CMSeeK/cmseek.py" "cmseek"
}

install_whatweb() {
    safe_git_clone "https://github.com/urbanadventurer/WhatWeb.git" "${TOOLS_DIR}/WhatWeb"
    [[ -f "${TOOLS_DIR}/WhatWeb/whatweb" ]] && link_into_venv "${TOOLS_DIR}/WhatWeb/whatweb" "whatweb"
}

install_commix() {
    safe_git_clone "https://github.com/commixproject/commix.git" "${TOOLS_DIR}/commix"
    [[ -f "${TOOLS_DIR}/commix/commix.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/commix/commix.py" "commix"
}

install_graphql_cop() {
    safe_git_clone "https://github.com/dolevf/graphql-cop.git" "${TOOLS_DIR}/graphql-cop"
    # Skip requirements.txt - safeurl has ancient requests pin
    # graphql-cop works without safeurl
    # Install simplejson separately (graphql-cop dependency)
    if command -v pip &>/dev/null; then
        pip install simplejson
    fi
    [[ -f "${TOOLS_DIR}/graphql-cop/graphql-cop.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/graphql-cop/graphql-cop.py" "graphql-cop"
}

# REMOVED: install_jsparser - ancient (2018), redundant with LinkFinder/xnLinkFinder

install_jwt_tool() {
    safe_git_clone "https://github.com/ticarpi/jwt_tool.git" "${TOOLS_DIR}/jwt_tool"
    if [[ -f "${TOOLS_DIR}/jwt_tool/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/jwt_tool/requirements.txt" --quiet 2>/dev/null || true
    fi
    [[ -f "${TOOLS_DIR}/jwt_tool/jwt_tool.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/jwt_tool/jwt_tool.py" "jwt_tool"
}

# REPLACED: tplmap (Python 2 deps) -> SSTImap
install_sstimap() {
    log_info "Installing SSTImap (replaces tplmap)..."
    "${VENV_BIN}/pip" install sstimap --quiet 2>/dev/null || true
    # Also clone for latest version
    safe_git_clone "https://github.com/vladko312/SSTImap.git" "${TOOLS_DIR}/SSTImap"
    [[ -f "${TOOLS_DIR}/SSTImap/sstimap.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/SSTImap/sstimap.py" "sstimap"
}

install_feroxbuster() {
    # Strategy: Binary download (fast) → Cargo compile (slow but reliable)

    # 1. Check if already installed
    if command -v feroxbuster >/dev/null 2>&1; then
        ln -sf "$(command -v feroxbuster)" "${VENV_BIN}/feroxbuster" 2>/dev/null || true
        log_success "Linked existing feroxbuster"
        return 0
    fi

    # 2. Try GitHub pre-built binary (FAST - preferred method)
    log_info "Attempting feroxbuster binary download from GitHub releases..."
    if install_github_release_and_link "epi052/feroxbuster" "feroxbuster"; then
        log_success "Feroxbuster installed via binary download"
        return 0
    fi

    # 3. Fallback: Compile from source with cargo (SLOW but works when binaries unavailable)
    log_warn "Binary download failed, attempting cargo build..."

    # Ensure Rust is available for compilation
    ensure_rust || {
        log_error "Feroxbuster installation failed - no binary available and Rust not installed"
        return 1
    }

    if command -v cargo >/dev/null 2>&1; then
        log_info "Compiling feroxbuster from source (this may take 2-5 minutes)..."
        cargo install feroxbuster 2>/dev/null || {
            log_error "Cargo build failed"
            return 1
        }

        if command -v feroxbuster >/dev/null 2>&1; then
            link_into_venv "$(command -v feroxbuster)" "feroxbuster"
            log_success "Feroxbuster compiled and installed successfully"
            return 0
        fi
    fi

    log_error "All feroxbuster installation methods failed"
    return 1
}

install_nikto() {
    install_system_binary "nikto" "nikto" "nikto"
}

install_wpscan() {
    if command -v wpscan >/dev/null 2>&1; then
        link_into_venv "$(command -v wpscan)" "wpscan"
        return 0
    fi

    if command -v gem >/dev/null 2>&1; then
        log_info "Installing wpscan via gem..."
        gem install --user-install wpscan 2>/dev/null || log_warn "wpscan failed"
    fi
}

install_corscanner() {
    safe_git_clone "https://github.com/chenjj/CORScanner.git" "${TOOLS_DIR}/CORScanner"
    if [[ -f "${TOOLS_DIR}/CORScanner/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/CORScanner/requirements.txt" --quiet 2>/dev/null || true
    fi
    [[ -f "${TOOLS_DIR}/CORScanner/cors_scan.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/CORScanner/cors_scan.py" "corscanner"
}

install_linkfinder() {
    safe_git_clone "https://github.com/GerbenJavado/LinkFinder.git" "${TOOLS_DIR}/LinkFinder"
    if [[ -f "${TOOLS_DIR}/LinkFinder/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/LinkFinder/requirements.txt" --quiet 2>/dev/null || true
    fi
    [[ -f "${TOOLS_DIR}/LinkFinder/linkfinder.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/LinkFinder/linkfinder.py" "linkfinder"
}

install_paramspider() {
    safe_git_clone "https://github.com/devanshbatham/ParamSpider.git" "${TOOLS_DIR}/ParamSpider"
    if [[ -f "${TOOLS_DIR}/ParamSpider/requirements.txt" ]]; then
        "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/ParamSpider/requirements.txt" --quiet 2>/dev/null || true
    fi
    # Install via pip from git
    "${VENV_BIN}/pip" install "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git" --quiet 2>/dev/null || true
}

install_enum4linux_ng() {
    log_info "Installing enum4linux-ng (modern Python rewrite)..."
    "${VENV_BIN}/pip" install --upgrade enum4linux-ng --quiet 2>/dev/null || {
        safe_git_clone "https://github.com/cddmp/enum4linux-ng.git" "${TOOLS_DIR}/enum4linux-ng"
        if [[ -f "${TOOLS_DIR}/enum4linux-ng/requirements.txt" ]]; then
            "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/enum4linux-ng/requirements.txt" --quiet 2>/dev/null || true
        fi
        [[ -f "${TOOLS_DIR}/enum4linux-ng/enum4linux-ng.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/enum4linux-ng/enum4linux-ng.py" "enum4linux-ng"
    }
    log_success "enum4linux-ng installed"
}

# REMOVED: install_udp_proto_scanner - ancient Perl (2017), use nmap -sU instead

# ============================================================================
# SAST TOOLS (Whitebox Analysis)
# ============================================================================

install_semgrep() {
    log_info "Installing Semgrep (SAST - code vulnerability scanner)..."

    # Check if already installed
    if command -v semgrep >/dev/null 2>&1; then
        log_success "Semgrep already installed: $(semgrep --version 2>/dev/null | head -n1)"
        return 0
    fi

    # Install via pip (recommended method)
    "${VENV_BIN}/pip" install --upgrade semgrep --quiet || {
        log_error "Failed to install Semgrep via pip"
        return 1
    }

    log_success "Semgrep installed successfully"

    # Verify installation
    if "${VENV_BIN}/semgrep" --version >/dev/null 2>&1; then
        log_success "Semgrep verified: $("${VENV_BIN}/semgrep" --version | head -n1)"
    else
        log_warn "Semgrep installed but verification failed"
    fi
}

install_trivy() {
    log_info "Installing Trivy (vulnerability/secret/config scanner)..."

    # Check if already installed
    if command -v trivy >/dev/null 2>&1; then
        log_success "Trivy already installed: $(trivy --version 2>/dev/null | head -n1)"
        return 0
    fi

    # Detect architecture
    ARCH=$(uname -m)
    case "${ARCH}" in
        x86_64) TRIVY_ARCH="64bit" ;;
        aarch64|arm64) TRIVY_ARCH="ARM64" ;;
        *) log_error "Unsupported architecture: ${ARCH}"; return 1 ;;
    esac

    # Install on Debian/Ubuntu
    if [[ "${OS}" == "debian" ]]; then
        log_info "Installing Trivy via apt..."

        # Add Trivy repository
        sudo apt-get update -qq
        sudo apt-get install -y -qq wget apt-transport-https gnupg lsb-release >/dev/null 2>&1 || true

        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null

        sudo apt-get update -qq
        sudo apt-get install -y trivy >/dev/null 2>&1 || {
            log_warn "apt installation failed, trying binary download..."
            install_trivy_binary
        }
    else
        # Fallback to binary installation
        install_trivy_binary
    fi

    # Verify installation
    if command -v trivy >/dev/null 2>&1; then
        log_success "Trivy installed successfully: $(trivy --version | head -n1)"
    else
        log_warn "Trivy installation completed but command not found in PATH"
    fi
}

install_trivy_binary() {
    log_info "Installing Trivy from binary release..."

    # Download latest release
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')

    if [[ -z "${TRIVY_VERSION}" ]]; then
        TRIVY_VERSION="0.48.3"  # Fallback version
        log_warn "Could not detect latest version, using ${TRIVY_VERSION}"
    fi

    TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"

    log_info "Downloading Trivy ${TRIVY_VERSION}..."
    curl -sL "${TRIVY_URL}" -o /tmp/trivy.tar.gz || {
        log_error "Failed to download Trivy"
        return 1
    }

    tar -xzf /tmp/trivy.tar.gz -C /tmp/
    sudo mv /tmp/trivy /usr/local/bin/trivy
    sudo chmod +x /usr/local/bin/trivy
    rm -f /tmp/trivy.tar.gz

    log_success "Trivy binary installed to /usr/local/bin/trivy"
}

# ============================================================================
# PYTHON TOOLS
# ============================================================================

install_python_tools() {
    log_info "Installing Python security tools..."

    "${VENV_BIN}/pip" install --upgrade arjun --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade dirsearch --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade schemathesis --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade wafw00f --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade sqlmap --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade sslyze --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade dnsrecon --quiet 2>/dev/null || true
    "${VENV_BIN}/pip" install --upgrade xnlinkfinder --quiet 2>/dev/null || true

    # REPLACED: py-altdns (stale, 2020) -> dnsgen (use with puredns)
    "${VENV_BIN}/pip" install --upgrade dnsgen --quiet 2>/dev/null || true

    # REMOVED: trufflehog pip - using binary v3 instead (install_trufflehog)

    log_success "Python tools installed"
}

# ============================================================================
# SYSTEM BINARIES
# ============================================================================

install_system_tools() {
    log_info "Installing system tools..."

    install_system_binary "smbclient" "smbclient" "samba"
    install_system_binary "showmount" "nfs-common" "nfs-utils"
    install_system_binary "snmpwalk" "snmp" "net-snmp"
    install_system_binary "onesixtyone" "onesixtyone" "onesixtyone"
    install_system_binary "whois" "whois" "whois"
    install_system_binary "hydra" "hydra" "hydra"
    install_system_binary "amass" "amass" "amass"
    install_system_binary "masscan" "masscan" "masscan"
    install_system_binary "nmap" "nmap" "nmap"

    # SecLists
    if [[ "${OS}" == "debian" ]]; then
        install_system_binary "seclists" "seclists" ""
    fi

    log_success "System tools installed"
}

configure_masscan_caps() {
    local masscan_bin
    masscan_bin="$(command -v masscan 2>/dev/null || true)"
    if [[ -z "${masscan_bin}" || ! -x "${masscan_bin}" ]]; then
        log_warn "masscan not found; skipping capability setup"
        return 0
    fi

    if command -v getcap >/dev/null 2>&1; then
        if getcap "${masscan_bin}" 2>/dev/null | grep -q "cap_net_raw"; then
            log_info "masscan already has network capabilities"
            return 0
        fi
    fi

    if [[ "${EUID}" -eq 0 ]]; then
        setcap cap_net_raw,cap_net_admin+eip "${masscan_bin}" 2>/dev/null || true
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo setcap cap_net_raw,cap_net_admin+eip "${masscan_bin}" 2>/dev/null || true
    else
        log_warn "masscan needs sudo or setcap for non-root use"
        return 0
    fi

    if command -v getcap >/dev/null 2>&1; then
        if getcap "${masscan_bin}" 2>/dev/null | grep -q "cap_net_raw"; then
            log_success "Configured masscan capabilities for non-root use"
        else
            log_warn "Failed to set masscan capabilities (requires sudo)"
        fi
    fi
}

# ============================================================================
# NPM TOOLS
# ============================================================================

install_npm_tools() {
    command -v npm >/dev/null 2>&1 || return

    log_info "Installing npm tools..."

    # retire.js
    local npm_prefix="${BASE_DIR}/.npm-global"
    mkdir -p "$npm_prefix"
    npm config set prefix "$npm_prefix" 2>/dev/null || true

    if npm install -g retire --prefix "$npm_prefix" 2>/dev/null; then
        [[ -f "${npm_prefix}/bin/retire" ]] && link_into_venv "${npm_prefix}/bin/retire" "retire"
        log_success "Installed retire.js"
    else
        # Try local prefix fallback
        local prefix="${HOME}/.local"
        if npm install -g --prefix "${prefix}" retire 2>/dev/null; then
            [[ -x "${prefix}/bin/retire" ]] && ln -sf "${prefix}/bin/retire" "${VENV_BIN}/retire"
            log_success "Installed retire.js (local prefix)"
        fi
    fi

    # REMOVED: wappalyzer npm - deprecated, replaced with webanalyze (Go)

    log_success "npm tools installed"
}

# ============================================================================
# WORDLISTS
# ============================================================================

install_wordlists() {
    log_info "Setting up wordlists..."

    # Kiterunner wordlists
    local kr_dest="${TOOLS_DIR}/kiterunner/routes-small.json"
    if [[ ! -f "$kr_dest" ]]; then
        mkdir -p "${TOOLS_DIR}/kiterunner"
        local url="https://wordlists-cdn.assetnote.io/rawdata/kiterunner/routes-small.json.tar.gz"
        curl -sL "$url" | tar -xz -C "${TOOLS_DIR}/kiterunner" 2>/dev/null || true
    fi

    # SecLists (optional - large download)
    local wordlist_dir="${BASE_DIR}/wordlists"
    if [[ ! -d "${wordlist_dir}/SecLists" ]]; then
        log_info "Cloning SecLists (this may take a while)..."
        mkdir -p "$wordlist_dir"
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "${wordlist_dir}/SecLists" 2>/dev/null || true
    fi

    log_success "Wordlists configured"
}

# ============================================================================
# ZAP HYBRID MODE
# ============================================================================

install_zap_hybrid() {
    log_info "Setting up ZAP hybrid mode..."

    if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
        docker pull ghcr.io/zaproxy/zaproxy:stable 2>/dev/null || true
    fi

    cat > "${VENV_BIN}/guardian-zap" << 'ZAP'
#!/usr/bin/env bash
if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
    docker images ghcr.io/zaproxy/zaproxy:stable -q | grep -q . && echo "docker" && exit 0
fi
command -v zap.sh >/dev/null 2>&1 && echo "native" && exit 0
echo "none" >&2 && exit 1
ZAP
    chmod +x "${VENV_BIN}/guardian-zap"

    # ZAP Docker wrapper
    cat > "${VENV_BIN}/zap-docker" << 'EOF'
#!/usr/bin/env bash
docker run --rm -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy:stable "$@"
EOF
    chmod +x "${VENV_BIN}/zap-docker"

    log_success "ZAP hybrid mode configured"
}

# ============================================================================
# SMART PORT SCANNER
# ============================================================================

install_smart_scanner() {
    cat > "${VENV_BIN}/guardian-portscan" << 'SCAN'
#!/usr/bin/env bash
TARGET="$1"
OUT="${2:-.}"
if command -v masscan >/dev/null 2>&1; then
    sudo masscan "$TARGET" -p1-65535 --rate=10000 -oL "$OUT/masscan.txt" 2>/dev/null
    PORTS=$(awk '/open/{print $3}' "$OUT/masscan.txt" | cut -d'/' -f1 | paste -sd, || echo "1-65535")
else
    PORTS="1-65535"
fi
nmap -sV -sC -p "$PORTS" "$TARGET" -oX "$OUT/nmap.xml" --open
SCAN
    chmod +x "${VENV_BIN}/guardian-portscan"
    log_success "Smart port scanner configured"
}

# ============================================================================
# METASPLOIT (OPTIONAL)
# ============================================================================

install_metasploit() {
    command -v msfconsole >/dev/null 2>&1 && return

    if [[ "${OS}" == "debian" ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        log_info "Installing Metasploit..."
        sudo apt-get install -y metasploit-framework 2>/dev/null || true
    fi
}

# ============================================================================
# FIX DEPENDENCY CONFLICTS
# ============================================================================

fix_dependency_conflicts() {
    log_info "Fixing dependency conflicts..."

    "${VENV_BIN}/pip" install --force-reinstall --quiet \
        "requests>=2.32.0" \
        "urllib3>=2.0.0" \
        "attrs>=22.2.0" \
        "charset-normalizer>=3.0.0" \
        2>/dev/null || true

    log_success "Dependencies fixed"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_installation() {
    log_info "Verifying installation..."

    local failed=0
    local tools=(
        "httpx"
        "nuclei"
        "subfinder"
        "ffuf"
        "dalfox"
        "katana"
        "gitleaks"
        "trufflehog"
        "feroxbuster"
        "sqlmap"
        "nmap"
        "webanalyze"
        "sstimap"
        "dnsgen"
        "god-eye"
    )

    echo ""
    echo "Checking critical tools:"
    for tool in "${tools[@]}"; do
        if [[ -x "${VENV_BIN}/${tool}" ]] || command -v "$tool" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} ${tool}"
        else
            echo -e "  ${RED}✗${NC} ${tool}"
            ((failed++)) || true
        fi
    done

    echo ""
    echo "Checking Python imports:"

    if python -c "from langchain_ollama import ChatOllama" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} langchain_ollama"
    else
        echo -e "  ${RED}✗${NC} langchain_ollama"
        ((failed++)) || true
    fi

    if python -c "import requests; assert requests.__version__ >= '2.32.0'" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} requests >= 2.32.0"
    else
        echo -e "  ${RED}✗${NC} requests >= 2.32.0"
        ((failed++)) || true
    fi

    echo ""
    if [[ $failed -eq 0 ]]; then
        log_success "All critical checks passed!"
    else
        log_warn "${failed} checks failed - some tools may not work correctly"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

echo ""
echo "==========================================="
echo " Guardian CLI Deluxe - Setup"
echo " Python 3.12 Compatible | Ancient Tools Removed"
echo " Retry: ${MAX_RETRIES} attempts, ${RETRY_DELAY}s delay"
echo "==========================================="
echo ""

# Core installations
install_projectdiscovery_tools
install_go_tools
install_trufflehog

# SAST Tools (Whitebox Analysis)
install_semgrep
install_trivy

# Git-cloned tools
install_testssl
install_xsstrike
install_cmseek
install_whatweb
install_commix
install_graphql_cop
install_jwt_tool
install_sstimap          # Replaces tplmap
install_feroxbuster
install_nikto
install_wpscan
install_corscanner
install_linkfinder
install_paramspider
install_enum4linux_ng

# Python tools
install_python_tools

# System tools
install_system_tools
configure_masscan_caps

# npm tools
install_npm_tools

# Wordlists
install_wordlists

# Enhancements
install_zap_hybrid
install_smart_scanner

# Optional
install_metasploit

# Fix conflicts from tool requirements
fix_dependency_conflicts

echo ""
echo "==========================================="
echo " Setup Complete!"
echo "==========================================="
echo ""

verify_installation

echo ""
echo "New SAST tools for whitebox analysis:"
echo "  ✓ Semgrep - Code vulnerability detection (SQLi, XSS, etc.)"
echo "  ✓ Trivy - Dependency CVE scanning + IaC misconfigurations"
echo "  ✓ Gitleaks - Secret detection (already installed)"
echo "  ✓ TruffleHog - Advanced secret scanning (already installed)"
echo ""
echo "Tools removed (ancient/deprecated):"
echo "  - tplmap (Python 2) -> sstimap"
echo "  - JSParser (2018) -> LinkFinder/xnLinkFinder"
echo "  - wappalyzer npm (deprecated) -> webanalyze"
echo "  - trufflehog pip (old) -> trufflehog binary v3"
echo "  - py-altdns (2020) -> dnsgen"
echo "  - udp-proto-scanner (2017) -> nmap -sU"
echo ""
echo "To activate the environment:"
echo "  source ${VENV_BIN}/activate"
echo ""
echo "Whitebox analysis usage:"
echo "  python -m cli.main workflow run --name web --target https://example.com --source /path/to/code"
echo ""
echo "To customize retry behavior:"
echo "  MAX_RETRIES=5 RETRY_DELAY=10 ./setup.sh"
echo ""
