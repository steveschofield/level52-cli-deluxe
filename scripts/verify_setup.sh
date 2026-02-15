#!/usr/bin/env bash
# Guardian CLI Deluxe - Setup Verification Script
# Usage: ./scripts/verify_setup.sh

set -euo pipefail

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

# Check if virtualenv is active
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    log_error "No virtualenv active. Run: source venv/bin/activate"
    exit 1
fi

log_info "Using virtualenv: ${VIRTUAL_ENV}"
echo ""

# ============================================================================
# TOOL CHECKS
# ============================================================================

check_tool() {
    local tool="$1"
    local category="$2"

    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $tool"
        return 0
    else
        echo -e "  ${RED}✗${NC} $tool"
        return 1
    fi
}

echo "========================================="
echo " ProjectDiscovery Tools"
echo "========================================="
PD_FAILED=0
for tool in httpx nuclei subfinder dnsx katana naabu shuffledns asnmap interactsh-client; do
    check_tool "$tool" "ProjectDiscovery" || ((PD_FAILED++))
done

echo ""
echo "========================================="
echo " Go Tools"
echo "========================================="
GO_FAILED=0
for tool in ffuf waybackurls gau dalfox gitleaks puredns subjs webanalyze kr; do
    check_tool "$tool" "Go" || ((GO_FAILED++))
done

echo ""
echo "========================================="
echo " Python Tools"
echo "========================================="
PY_FAILED=0
for tool in sqlmap arjun sslyze dirsearch wafw00f dnsrecon xnlinkfinder dnsgen sstimap; do
    check_tool "$tool" "Python" || ((PY_FAILED++))
done

echo ""
echo "========================================="
echo " Git-Cloned Tools"
echo "========================================="
GIT_FAILED=0
for tool in testssl commix xsstrike cmseek whatweb graphql-cop jwt_tool corscanner linkfinder feroxbuster; do
    check_tool "$tool" "Git-Cloned" || ((GIT_FAILED++))
done

echo ""
echo "========================================="
echo " System Tools (Optional)"
echo "========================================="
SYS_FAILED=0
for tool in nmap masscan nikto hydra amass; do
    check_tool "$tool" "System" || ((SYS_FAILED++))
done

echo ""
echo "========================================="
echo " Modern Replacements (vs Ancient Tools)"
echo "========================================="
MODERN_FAILED=0

# sstimap (replaced tplmap)
if command -v sstimap >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} sstimap (replaced tplmap)"
else
    echo -e "  ${RED}✗${NC} sstimap (should replace tplmap)"
    ((MODERN_FAILED++))
fi

# webanalyze (replaced wappalyzer)
if command -v webanalyze >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} webanalyze (replaced wappalyzer npm)"
else
    echo -e "  ${RED}✗${NC} webanalyze (should replace wappalyzer)"
    ((MODERN_FAILED++))
fi

# dnsgen (replaced py-altdns)
if command -v dnsgen >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} dnsgen (replaced py-altdns)"
else
    echo -e "  ${RED}✗${NC} dnsgen (should replace py-altdns)"
    ((MODERN_FAILED++))
fi

# linkfinder (replaced JSParser)
if command -v linkfinder >/dev/null 2>&1 || command -v xnlinkfinder >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} linkfinder/xnlinkfinder (replaced JSParser)"
else
    echo -e "  ${RED}✗${NC} linkfinder (should replace JSParser)"
    ((MODERN_FAILED++))
fi

# trufflehog v3 binary (not pip)
if command -v trufflehog >/dev/null 2>&1; then
    TH_VERSION=$(trufflehog --version 2>&1 | head -1)
    if [[ "$TH_VERSION" =~ "3." ]]; then
        echo -e "  ${GREEN}✓${NC} trufflehog v3 binary (not pip version)"
    else
        echo -e "  ${YELLOW}⚠${NC} trufflehog found but version unclear: $TH_VERSION"
    fi
else
    echo -e "  ${RED}✗${NC} trufflehog v3 (should replace pip version)"
    ((MODERN_FAILED++))
fi

# Verify ancient tools are NOT present
echo ""
echo "========================================="
echo " Ancient Tools Check (Should be Absent)"
echo "========================================="
ANCIENT_FOUND=0

if [[ -d "tools/vendor/tplmap" ]]; then
    echo -e "  ${RED}✗${NC} tplmap directory still exists (should be removed)"
    ((ANCIENT_FOUND++))
else
    echo -e "  ${GREEN}✓${NC} tplmap removed"
fi

if [[ -d "tools/vendor/JSParser" ]]; then
    echo -e "  ${RED}✗${NC} JSParser directory still exists (should be removed)"
    ((ANCIENT_FOUND++))
else
    echo -e "  ${GREEN}✓${NC} JSParser removed"
fi

if [[ -d "tools/vendor/udp-proto-scanner" ]]; then
    echo -e "  ${RED}✗${NC} udp-proto-scanner directory still exists (should be removed)"
    ((ANCIENT_FOUND++))
else
    echo -e "  ${GREEN}✓${NC} udp-proto-scanner removed"
fi

# ============================================================================
# PYTHON IMPORT CHECKS
# ============================================================================

echo ""
echo "========================================="
echo " Python Import Checks"
echo "========================================="

IMPORT_FAILED=0

python << 'EOF'
import sys

checks = [
    ("langchain_ollama", "ChatOllama"),
    ("langchain_google_genai", "ChatGoogleGenerativeAI"),
    ("requests", None),
    ("urllib3", None),
    ("typer", None),
    ("rich", None),
    ("pyyaml", None),
]

failed = []
for module, attr in checks:
    try:
        mod = __import__(module)
        if attr:
            getattr(mod, attr)
        print(f"\033[0;32m  ✓\033[0m {module}")
    except Exception as e:
        print(f"\033[0;31m  ✗\033[0m {module}: {e}")
        failed.append(module)

sys.exit(len(failed))
EOF

if [[ $? -ne 0 ]]; then
    ((IMPORT_FAILED++))
fi

# Check requests version
echo ""
echo -e "${BLUE}Checking critical package versions:${NC}"
REQUESTS_VERSION=$(python -c "import requests; print(requests.__version__)" 2>/dev/null || echo "ERROR")
if [[ "$REQUESTS_VERSION" == "ERROR" ]]; then
    echo -e "  ${RED}✗${NC} requests not installed"
    ((IMPORT_FAILED++))
elif python -c "import requests; assert tuple(map(int, requests.__version__.split('.'))) >= (2, 32, 0)" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} requests ${REQUESTS_VERSION} (>= 2.32.0)"
else
    echo -e "  ${RED}✗${NC} requests ${REQUESTS_VERSION} (need >= 2.32.0)"
    ((IMPORT_FAILED++))
fi

# Check urllib3 version
URLLIB3_VERSION=$(python -c "import urllib3; print(urllib3.__version__)" 2>/dev/null || echo "ERROR")
if [[ "$URLLIB3_VERSION" == "ERROR" ]]; then
    echo -e "  ${RED}✗${NC} urllib3 not installed"
    ((IMPORT_FAILED++))
elif python -c "import urllib3; assert tuple(map(int, urllib3.__version__.split('.'))) >= (2, 0, 0)" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} urllib3 ${URLLIB3_VERSION} (>= 2.0.0)"
else
    echo -e "  ${YELLOW}⚠${NC} urllib3 ${URLLIB3_VERSION} (recommend >= 2.0.0)"
fi

# ============================================================================
# VERSION CHECKS
# ============================================================================

echo ""
echo "========================================="
echo " Environment Versions"
echo "========================================="

# Python version
PY_VERSION=$(python --version 2>&1)
echo "Python: $PY_VERSION"
if python -c "import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] < (3,13) else 1)"; then
    echo -e "  ${GREEN}✓${NC} Python version compatible (3.11-3.12)"
else
    echo -e "  ${RED}✗${NC} Python version incompatible (need 3.11 or 3.12)"
    ((IMPORT_FAILED++))
fi

# Go version
if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version 2>&1)
    echo "Go: $GO_VERSION"
else
    echo -e "Go: ${YELLOW}not installed${NC} (optional but recommended)"
fi

# Node/npm version
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node --version 2>&1)
    echo "Node: $NODE_VERSION"
else
    echo -e "Node: ${YELLOW}not installed${NC} (needed for retire.js)"
fi

# ============================================================================
# GUARDIAN CLI CHECKS
# ============================================================================

echo ""
echo "========================================="
echo " Guardian CLI Checks"
echo "========================================="

CLI_FAILED=0

# Test CLI entry point
if python -m cli.main --help >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} CLI entry point working"
else
    echo -e "  ${RED}✗${NC} CLI entry point failed"
    ((CLI_FAILED++))
fi

# Test workflow listing
if python -m cli.main workflow list >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Workflow listing working"
else
    echo -e "  ${RED}✗${NC} Workflow listing failed"
    ((CLI_FAILED++))
fi

# Check config
if [[ -f "config/guardian.yaml" ]]; then
    echo -e "  ${GREEN}✓${NC} Config file exists"
else
    echo -e "  ${YELLOW}⚠${NC} Config file not found (run: python -m cli.main init)"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "========================================="
echo " Summary"
echo "========================================="

TOTAL_FAILED=$((PD_FAILED + GO_FAILED + PY_FAILED + GIT_FAILED + MODERN_FAILED + IMPORT_FAILED + CLI_FAILED + ANCIENT_FOUND))

echo ""
echo "ProjectDiscovery Tools: $((9 - PD_FAILED))/9"
echo "Go Tools: $((9 - GO_FAILED))/9"
echo "Python Tools: $((9 - PY_FAILED))/9"
echo "Git-Cloned Tools: $((10 - GIT_FAILED))/10"
echo "Modern Replacements: $((5 - MODERN_FAILED))/5"
echo "System Tools (optional): $((5 - SYS_FAILED))/5"
echo "Ancient Tools Removed: $((3 - ANCIENT_FOUND))/3"
echo "Python Imports: $(( (7 + 2) - IMPORT_FAILED ))/$((7 + 2))"
echo "Guardian CLI: $((2 - CLI_FAILED))/2"

echo ""
if [[ $TOTAL_FAILED -eq 0 ]]; then
    log_success "All critical checks passed! 🎉"
    echo ""
    echo "Your Guardian installation is ready to use."
    echo ""
    echo "Next steps:"
    echo "  1. Configure AI provider: python -m cli.main init"
    echo "  2. Run a test workflow: python -m cli.main workflow run --name recon --target example.com"
    exit 0
else
    log_warn "$TOTAL_FAILED checks failed"
    echo ""
    echo "Recommended actions:"

    if [[ $PD_FAILED -gt 0 ]] || [[ $GO_FAILED -gt 0 ]]; then
        echo "  • Install Go tools: go install [package]@latest"
    fi

    if [[ $PY_FAILED -gt 0 ]]; then
        echo "  • Install Python tools: pip install [package]"
    fi

    if [[ $MODERN_FAILED -gt 0 ]]; then
        echo "  • Re-run setup to install modern replacements: ./setup.sh"
    fi

    if [[ $ANCIENT_FOUND -gt 0 ]]; then
        echo "  • Remove ancient tool directories: rm -rf tools/vendor/{tplmap,JSParser,udp-proto-scanner}"
    fi

    if [[ $IMPORT_FAILED -gt 0 ]]; then
        echo "  • Fix Python dependencies: pip install --force-reinstall 'requests>=2.32.0' 'urllib3>=2.0.0'"
    fi

    if [[ $CLI_FAILED -gt 0 ]]; then
        echo "  • Reinstall Guardian: pip install -e ."
    fi

    echo ""
    echo "For detailed troubleshooting, see: SETUP_VERIFICATION.md"
    exit 1
fi
