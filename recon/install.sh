#!/bin/bash
# =============================================================================
# Tesla Bug Bounty Recon — Tool Installer
# =============================================================================
# Installs all required tools for the recon pipeline.
# Supports: Ubuntu/Debian, macOS (brew), and Go-based installs.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# Requirements:
#   - Go 1.21+ (for most tools)
#   - Python 3.8+
#   - curl, git, jq (base utilities)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

info "Detected OS: $OS"

# =============================================================================
# Check base requirements
# =============================================================================
check_base() {
    log "Checking base requirements..."

    # Go
    if ! command -v go &> /dev/null; then
        error "Go is not installed. Install Go 1.21+ first:"
        echo "  https://go.dev/doc/install"
        echo ""
        echo "  Quick install (Linux):"
        echo "    wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz"
        echo "    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz"
        echo "    export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
        echo ""
        exit 1
    else
        log "Go: $(go version)"
    fi

    # Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 not found. Install python3 first."
        exit 1
    else
        log "Python: $(python3 --version)"
    fi

    # Ensure Go bin is in PATH
    export PATH="$PATH:$(go env GOPATH)/bin"

    # Base utilities
    for tool in curl git jq; do
        if ! command -v "$tool" &> /dev/null; then
            warn "$tool not found. Installing..."
            if [ "$OS" == "linux" ]; then
                sudo apt-get install -y "$tool" 2>/dev/null || true
            elif [ "$OS" == "macos" ]; then
                brew install "$tool" 2>/dev/null || true
            fi
        fi
    done
}

# =============================================================================
# Go tool installer helper
# =============================================================================
install_go_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &> /dev/null; then
        log "$name already installed: $(which $name)"
    else
        info "Installing $name..."
        go install "$pkg" 2>/dev/null && log "$name installed." || warn "Failed to install $name"
    fi
}

# =============================================================================
# Install tools
# =============================================================================
install_tools() {
    log "=== Installing Recon Tools ==="
    echo ""

    # --- Subdomain Enumeration ---
    info "--- Subdomain Enumeration Tools ---"

    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "chaos" "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    install_go_tool "github-subdomains" "github.com/gwen001/github-subdomains@latest"

    # amass
    if ! command -v amass &> /dev/null; then
        info "Installing amass..."
        go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null && log "amass installed." || warn "amass install failed (try manual install)"
    else
        log "amass already installed."
    fi

    # findomain (binary release)
    if ! command -v findomain &> /dev/null; then
        info "Installing findomain..."
        if [ "$OS" == "linux" ]; then
            curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip
            unzip -o /tmp/findomain.zip -d /tmp/ 2>/dev/null || true
            chmod +x /tmp/findomain
            sudo mv /tmp/findomain /usr/local/bin/ 2>/dev/null || mv /tmp/findomain "$HOME/go/bin/"
            log "findomain installed."
        elif [ "$OS" == "macos" ]; then
            brew install findomain 2>/dev/null || warn "findomain install failed"
        fi
    else
        log "findomain already installed."
    fi

    echo ""
    # --- DNS Resolution ---
    info "--- DNS Resolution Tools ---"

    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool "puredns" "github.com/d3mondev/puredns/v2@latest"

    echo ""
    # --- HTTP Probing ---
    info "--- HTTP Probing Tools ---"

    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"

    echo ""
    # --- Crawling & URL Collection ---
    info "--- Crawling & URL Collection Tools ---"

    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "unfurl" "github.com/tomnomnom/unfurl@latest"

    echo ""
    # --- Content Discovery ---
    info "--- Content Discovery Tools ---"

    install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

    # feroxbuster (Rust-based, binary release)
    if ! command -v feroxbuster &> /dev/null; then
        info "Installing feroxbuster..."
        if [ "$OS" == "linux" ]; then
            curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null || true
            sudo mv feroxbuster /usr/local/bin/ 2>/dev/null || mv feroxbuster "$HOME/go/bin/" 2>/dev/null || true
            log "feroxbuster installed."
        elif [ "$OS" == "macos" ]; then
            brew install feroxbuster 2>/dev/null || warn "feroxbuster install failed"
        fi
    else
        log "feroxbuster already installed."
    fi

    echo ""
    # --- Fingerprinting ---
    info "--- Fingerprinting Tools ---"

    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    # webanalyze (Go-based Wappalyzer)
    install_go_tool "webanalyze" "github.com/rverton/webanalyze/cmd/webanalyze@latest"

    echo ""
    # --- Parameter Discovery ---
    info "--- Parameter Discovery Tools ---"

    # arjun (Python)
    if ! command -v arjun &> /dev/null; then
        info "Installing arjun..."
        pip3 install arjun --quiet 2>/dev/null && log "arjun installed." || warn "arjun install failed"
    else
        log "arjun already installed."
    fi

    echo ""
    # --- Nuclei templates ---
    info "--- Updating nuclei templates ---"
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates 2>/dev/null || true
        log "Nuclei templates updated."
    fi
}

# =============================================================================
# Download wordlists
# =============================================================================
download_wordlists() {
    log "=== Downloading Wordlists ==="

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WL_DIR="${SCRIPT_DIR}/wordlists"
    mkdir -p "$WL_DIR"

    # Subdomain wordlist
    if [ ! -f "${WL_DIR}/subdomains.txt" ]; then
        info "Downloading subdomain wordlist (top 110k)..."
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
            -o "${WL_DIR}/subdomains.txt" || warn "Failed to download subdomain wordlist"
        log "Subdomain wordlist: $(wc -l < "${WL_DIR}/subdomains.txt") entries"
    else
        log "Subdomain wordlist already exists."
    fi

    # Resolve wordlist validation
    if [ ! -f "${WL_DIR}/resolvers.txt" ]; then
        warn "resolvers.txt not found — using default"
    fi
}

# =============================================================================
# Verify installation
# =============================================================================
verify() {
    log "=== Verification ==="
    echo ""

    declare -A TOOLS=(
        ["subfinder"]="Subdomain enum"
        ["amass"]="Subdomain enum"
        ["assetfinder"]="Subdomain enum"
        ["findomain"]="Subdomain enum"
        ["dnsx"]="DNS resolution"
        ["puredns"]="DNS bruteforce"
        ["httpx"]="HTTP probing"
        ["katana"]="Crawling"
        ["waybackurls"]="Passive URLs"
        ["gau"]="Passive URLs"
        ["unfurl"]="URL parsing"
        ["ffuf"]="Content discovery"
        ["feroxbuster"]="Content discovery"
        ["nuclei"]="Vuln scanning"
        ["webanalyze"]="Tech fingerprint"
        ["arjun"]="Param discovery"
    )

    local installed=0
    local missing=0

    printf "%-20s %-20s %s\n" "TOOL" "PURPOSE" "STATUS"
    printf "%-20s %-20s %s\n" "----" "-------" "------"

    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            printf "%-20s %-20s ${GREEN}%s${NC}\n" "$tool" "${TOOLS[$tool]}" "INSTALLED"
            ((installed++))
        else
            printf "%-20s %-20s ${RED}%s${NC}\n" "$tool" "${TOOLS[$tool]}" "MISSING"
            ((missing++))
        fi
    done

    echo ""
    log "Installed: $installed | Missing: $missing"

    if [ "$missing" -gt 0 ]; then
        warn "Some tools are missing. The pipeline will use fallbacks where available."
        warn "For best results, install all tools manually if auto-install failed."
    else
        log "All tools installed! You're ready to run tesla_recon.sh"
    fi
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Tesla Bug Bounty — Recon Tool Installer               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

check_base
install_tools
download_wordlists
verify

echo ""
log "Setup complete! Next steps:"
echo "  1. Add Go bin to your PATH if not already:"
echo "     export PATH=\$PATH:\$(go env GOPATH)/bin"
echo ""
echo "  2. (Optional) Set API keys for better results:"
echo "     export GITHUB_TOKEN=ghp_xxxx        # for github-subdomains"
echo "     export PDCP_API_KEY=xxxx            # for chaos (ProjectDiscovery)"
echo ""
echo "  3. Run the pipeline:"
echo "     cd recon && chmod +x tesla_recon.sh && ./tesla_recon.sh"
echo ""
