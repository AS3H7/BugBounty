#!/bin/bash
# =============================================================================
# Tesla Bug Bounty — Recon Pipeline
# =============================================================================
# Subdomain Enumeration → DNS Resolution → HTTP Probing → Tech Fingerprint → Triage
#
# Usage:
#   ./tesla_recon.sh                  # Run full pipeline
#   ./tesla_recon.sh --phase enum     # Subdomain enumeration only
#   ./tesla_recon.sh --phase resolve  # DNS resolution only
#   ./tesla_recon.sh --phase probe    # HTTP probing only
#   ./tesla_recon.sh --phase finger   # Tech fingerprinting only
#   ./tesla_recon.sh --phase triage   # Categorization/triage only
#
# Prerequisites: See install.sh for required tools
# =============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output/$(date +%Y%m%d_%H%M%S)"
THREADS=50
RESOLVERS="${SCRIPT_DIR}/wordlists/resolvers.txt"
WORDLIST="${SCRIPT_DIR}/wordlists/subdomains.txt"

# In-scope root domains
DOMAINS=(
    "tesla.com"
    "teslamotors.com"
    "tesla.cn"
    "tesla.services"
    "solarcity.com"
    "teslainsuranceservices.com"
)

# Out-of-scope subdomains (will be filtered out)
OOS_PATTERNS=(
    "employeefeedback.tesla.com"
    "energysupport.tesla.com"
    "engage.tesla.com"
    "feedback.tesla.com"
    "feedback.teslamotors.com"
    "ir.tesla.com"
    "ir.teslamotors.com"
    "mkto.teslamotors.com"
    "shop.eu.teslamotors.com"
)

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Helper functions --------------------------------------------------------
banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Tesla Bug Bounty — Recon Pipeline                 ║"
    echo "║           Authorized Testing Only                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        error "Required tool not found: $1"
        error "Run ./install.sh to install dependencies"
        exit 1
    fi
}

setup_output() {
    mkdir -p "$OUTPUT_DIR"/{enum,resolved,probed,fingerprinted,triage}
    log "Output directory: $OUTPUT_DIR"
}

filter_out_of_scope() {
    local input_file="$1"
    local output_file="$2"
    
    cp "$input_file" "$output_file.tmp"
    
    for pattern in "${OOS_PATTERNS[@]}"; do
        grep -v "^${pattern}$" "$output_file.tmp" > "$output_file.tmp2" 2>/dev/null || true
        mv "$output_file.tmp2" "$output_file.tmp"
    done
    
    # Also filter any subdomain of engage.tesla.com
    grep -v "\.engage\.tesla\.com$" "$output_file.tmp" > "$output_file" 2>/dev/null || true
    rm -f "$output_file.tmp"
    
    local before=$(wc -l < "$input_file")
    local after=$(wc -l < "$output_file")
    local removed=$((before - after))
    
    if [ "$removed" -gt 0 ]; then
        warn "Filtered $removed out-of-scope subdomains"
    fi
}

# =============================================================================
# PHASE 1: Subdomain Enumeration (Passive)
# =============================================================================
phase_enum() {
    log "=== PHASE 1: Subdomain Enumeration ==="
    
    local all_subs="${OUTPUT_DIR}/enum/all_subdomains_raw.txt"
    touch "$all_subs"
    
    for domain in "${DOMAINS[@]}"; do
        info "Enumerating: $domain"
        local domain_file="${OUTPUT_DIR}/enum/${domain}_subs.txt"
        touch "$domain_file"
        
        # --- subfinder (passive multi-source) ---
        if command -v subfinder &> /dev/null; then
            log "  Running subfinder on $domain..."
            subfinder -d "$domain" -silent -all -t "$THREADS" 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- amass (passive enum) ---
        if command -v amass &> /dev/null; then
            log "  Running amass passive on $domain..."
            amass enum -passive -d "$domain" -silent 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- assetfinder ---
        if command -v assetfinder &> /dev/null; then
            log "  Running assetfinder on $domain..."
            assetfinder --subs-only "$domain" 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- findomain ---
        if command -v findomain &> /dev/null; then
            log "  Running findomain on $domain..."
            findomain -t "$domain" -q 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- crt.sh (Certificate Transparency) ---
        log "  Querying crt.sh for $domain..."
        curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | \
            sort -u >> "$domain_file" || true
        
        # --- chaos (ProjectDiscovery) ---
        if command -v chaos &> /dev/null && [ -n "${PDCP_API_KEY:-}" ]; then
            log "  Running chaos on $domain..."
            chaos -d "$domain" -silent 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- github-subdomains (if configured) ---
        if command -v github-subdomains &> /dev/null && [ -n "${GITHUB_TOKEN:-}" ]; then
            log "  Running github-subdomains on $domain..."
            github-subdomains -d "$domain" -t "$GITHUB_TOKEN" 2>/dev/null >> "$domain_file" || true
        fi
        
        # --- waybackurls for subdomain extraction ---
        if command -v waybackurls &> /dev/null; then
            log "  Extracting subdomains from Wayback Machine for $domain..."
            echo "$domain" | waybackurls 2>/dev/null | \
                unfurl --unique domains 2>/dev/null | \
                grep "\.${domain}$" >> "$domain_file" || true
        fi
        
        # Deduplicate per-domain
        sort -u "$domain_file" -o "$domain_file"
        local count=$(wc -l < "$domain_file")
        log "  Found $count unique subdomains for $domain"
        
        cat "$domain_file" >> "$all_subs"
    done
    
    # --- DNS brute force (optional, slower) ---
    if command -v puredns &> /dev/null && [ -f "$WORDLIST" ]; then
        log "Running DNS bruteforce with puredns..."
        for domain in "${DOMAINS[@]}"; do
            puredns bruteforce "$WORDLIST" "$domain" \
                --resolvers "$RESOLVERS" \
                -q 2>/dev/null >> "$all_subs" || true
        done
    fi
    
    # Deduplicate all
    sort -u "$all_subs" -o "$all_subs"
    
    # Filter out-of-scope
    filter_out_of_scope "$all_subs" "${OUTPUT_DIR}/enum/all_subdomains.txt"
    
    local total=$(wc -l < "${OUTPUT_DIR}/enum/all_subdomains.txt")
    log "Total unique in-scope subdomains: $total"
    log "Saved to: ${OUTPUT_DIR}/enum/all_subdomains.txt"
}

# =============================================================================
# PHASE 2: DNS Resolution
# =============================================================================
phase_resolve() {
    log "=== PHASE 2: DNS Resolution ==="
    
    local input="${OUTPUT_DIR}/enum/all_subdomains.txt"
    local output="${OUTPUT_DIR}/resolved/resolved_hosts.txt"
    local dns_records="${OUTPUT_DIR}/resolved/dns_records.json"
    
    if [ ! -f "$input" ]; then
        error "No subdomain list found. Run --phase enum first."
        exit 1
    fi
    
    # --- dnsx for mass resolution ---
    if command -v dnsx &> /dev/null; then
        log "Resolving with dnsx..."
        dnsx -l "$input" -silent -a -aaaa -cname -resp -json \
            -t "$THREADS" -r "$RESOLVERS" \
            -o "$dns_records" 2>/dev/null || true
        
        # Extract hosts that resolved
        dnsx -l "$input" -silent -t "$THREADS" -r "$RESOLVERS" \
            -o "$output" 2>/dev/null || true
    else
        # Fallback: simple dig-based resolution
        log "Resolving with dig (slower fallback)..."
        while IFS= read -r sub; do
            if dig +short "$sub" A 2>/dev/null | grep -qE '^[0-9]'; then
                echo "$sub" >> "$output"
            fi
        done < "$input"
    fi
    
    # --- Check for CNAME dangling (subdomain takeover candidates) ---
    log "Checking for potential subdomain takeover (dangling CNAMEs)..."
    local takeover_candidates="${OUTPUT_DIR}/resolved/takeover_candidates.txt"
    touch "$takeover_candidates"
    
    if command -v dnsx &> /dev/null; then
        dnsx -l "$input" -cname -silent -resp 2>/dev/null | \
            grep -iE "(herokuapp|herokudns|github\.io|shopify|amazonaws|azurewebsites|cloudfront|fastly|pantheon|ghost\.io|myshopify|surge\.sh|bitbucket|ghost\.org|helpjuice|helpscoutdocs|feedpress|freshdesk|statuspage|teamwork|helpjuice|zendesk|wordpress\.com|smugmug|cargo\.site|webflow)" \
            >> "$takeover_candidates" 2>/dev/null || true
    fi
    
    local resolved_count=$(wc -l < "$output" 2>/dev/null || echo "0")
    local takeover_count=$(wc -l < "$takeover_candidates" 2>/dev/null || echo "0")
    
    log "Resolved hosts: $resolved_count"
    if [ "$takeover_count" -gt 0 ]; then
        warn "Potential subdomain takeover candidates: $takeover_count"
        warn "Review: $takeover_candidates"
    fi
}

# =============================================================================
# PHASE 3: HTTP Probing
# =============================================================================
phase_probe() {
    log "=== PHASE 3: HTTP Probing ==="
    
    local input="${OUTPUT_DIR}/resolved/resolved_hosts.txt"
    local output="${OUTPUT_DIR}/probed/live_hosts.txt"
    local details="${OUTPUT_DIR}/probed/httpx_output.json"
    
    if [ ! -f "$input" ]; then
        error "No resolved hosts found. Run --phase resolve first."
        exit 1
    fi
    
    if command -v httpx &> /dev/null; then
        log "Probing with httpx..."
        httpx -l "$input" -silent \
            -status-code -title -tech-detect -content-length \
            -follow-redirects -threads "$THREADS" \
            -json -o "$details" 2>/dev/null || true
        
        # Extract live URLs
        httpx -l "$input" -silent \
            -follow-redirects -threads "$THREADS" \
            -o "$output" 2>/dev/null || true
    else
        # Fallback: curl-based probing
        log "Probing with curl (slower fallback)..."
        while IFS= read -r host; do
            for scheme in "https" "http"; do
                status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${scheme}://${host}" 2>/dev/null || echo "000")
                if [ "$status" != "000" ]; then
                    echo "${scheme}://${host} [$status]" >> "$output"
                    break
                fi
            done
        done < "$input"
    fi
    
    local live_count=$(wc -l < "$output" 2>/dev/null || echo "0")
    log "Live HTTP hosts: $live_count"
    log "Detailed output: $details"
}

# =============================================================================
# PHASE 4: Technology Fingerprinting
# =============================================================================
phase_fingerprint() {
    log "=== PHASE 4: Technology Fingerprinting ==="
    
    local input="${OUTPUT_DIR}/probed/live_hosts.txt"
    local output_dir="${OUTPUT_DIR}/fingerprinted"
    
    if [ ! -f "$input" ]; then
        error "No live hosts found. Run --phase probe first."
        exit 1
    fi
    
    # --- Wappalyzer/webanalyze ---
    if command -v webanalyze &> /dev/null; then
        log "Running webanalyze (Wappalyzer signatures)..."
        webanalyze -hosts "$input" -output json \
            > "${output_dir}/webanalyze.json" 2>/dev/null || true
    fi
    
    # --- nuclei tech-detect templates ---
    if command -v nuclei &> /dev/null; then
        log "Running nuclei tech-detect templates..."
        nuclei -l "$input" -t technologies/ -silent -json \
            -o "${output_dir}/nuclei_tech.json" \
            -c "$THREADS" 2>/dev/null || true
    fi
    
    # --- Extract interesting headers & responses ---
    log "Extracting response headers for analysis..."
    local headers_dir="${output_dir}/headers"
    mkdir -p "$headers_dir"
    
    while IFS= read -r url; do
        local filename=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
        curl -s -I --max-time 10 "$url" > "${headers_dir}/${filename}.txt" 2>/dev/null || true
    done < "$input"
    
    # --- JS file extraction (for secrets/endpoints) ---
    log "Extracting JavaScript files..."
    local js_dir="${output_dir}/js_files"
    mkdir -p "$js_dir"
    
    if command -v katana &> /dev/null; then
        katana -list "$input" -silent -jc \
            -d 2 -ef "png,jpg,gif,css,svg,woff,ttf" \
            -f qurl 2>/dev/null | \
            grep "\.js$" | sort -u > "${js_dir}/all_js_urls.txt" || true
        
        local js_count=$(wc -l < "${js_dir}/all_js_urls.txt" 2>/dev/null || echo "0")
        log "Found $js_count unique JS files"
    fi
    
    # --- Extract endpoints/secrets from JS ---
    if [ -f "${js_dir}/all_js_urls.txt" ] && [ -s "${js_dir}/all_js_urls.txt" ]; then
        log "Scanning JS files for secrets and endpoints..."
        
        # Download JS files
        mkdir -p "${js_dir}/downloaded"
        while IFS= read -r jsurl; do
            local jsfile=$(echo "$jsurl" | md5sum | cut -d' ' -f1)
            curl -s --max-time 15 "$jsurl" > "${js_dir}/downloaded/${jsfile}.js" 2>/dev/null || true
        done < "${js_dir}/all_js_urls.txt"
        
        # Grep for interesting patterns
        local secrets_file="${output_dir}/potential_secrets.txt"
        grep -rEh "(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|aws_access|AKIA[0-9A-Z]{16}|sk_live_|pk_live_|Bearer\s+[a-zA-Z0-9\-._~+/]+=*)" \
            "${js_dir}/downloaded/" 2>/dev/null | \
            sort -u > "$secrets_file" || true
        
        # Extract API endpoints
        local endpoints_file="${output_dir}/api_endpoints.txt"
        grep -rEoh "(\/api\/[a-zA-Z0-9/_\-]+|\/v[0-9]+\/[a-zA-Z0-9/_\-]+|\/graphql|\/internal\/[a-zA-Z0-9/_\-]+)" \
            "${js_dir}/downloaded/" 2>/dev/null | \
            sort -u > "$endpoints_file" || true
        
        local secrets_count=$(wc -l < "$secrets_file" 2>/dev/null || echo "0")
        local endpoints_count=$(wc -l < "$endpoints_file" 2>/dev/null || echo "0")
        
        if [ "$secrets_count" -gt 0 ]; then
            warn "Potential secrets found: $secrets_count (review: $secrets_file)"
        fi
        log "API endpoints extracted: $endpoints_count"
    fi
    
    log "Fingerprinting complete. Results in: $output_dir"
}

# =============================================================================
# PHASE 5: Triage & Categorization
# =============================================================================
phase_triage() {
    log "=== PHASE 5: Triage & Categorization ==="
    
    local httpx_json="${OUTPUT_DIR}/probed/httpx_output.json"
    local triage_dir="${OUTPUT_DIR}/triage"
    
    if [ ! -f "$httpx_json" ]; then
        error "No httpx output found. Run --phase probe first."
        exit 1
    fi
    
    # Categorize by response characteristics
    log "Categorizing hosts..."
    
    # --- Apps with login/auth (high value targets) ---
    jq -r 'select(.title != null) | select(.title | test("login|sign.in|account|dashboard|admin|portal|auth"; "i")) | .url' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/apps_with_auth.txt" || true
    
    # --- API endpoints ---
    jq -r 'select(.url | test("/api/|/v[0-9]+/|/graphql"; "i")) | .url' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/api_hosts.txt" || true
    
    # --- Static/CDN/marketing (low value) ---
    jq -r 'select(.tech != null) | select(.tech | tostring | test("WordPress|Drupal|Varnish|CDN|Cloudflare"; "i")) | select(.title != null) | select(.title | test("login|sign.in|account|dashboard|admin|portal"; "i") | not) | .url' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/static_marketing.txt" || true
    
    # --- Redirects (might hide something interesting) ---
    jq -r 'select(.status_code >= 300 and .status_code < 400) | "\(.url) -> \(.chain // "unknown")"' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/redirects.txt" || true
    
    # --- Error pages (potential info disclosure) ---
    jq -r 'select(.status_code >= 400 and .status_code < 500) | "\(.url) [\(.status_code)]"' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/client_errors.txt" || true
    
    # --- 5xx (might indicate backend issues worth investigating) ---
    jq -r 'select(.status_code >= 500) | "\(.url) [\(.status_code)]"' \
        "$httpx_json" 2>/dev/null | sort -u > "${triage_dir}/server_errors.txt" || true
    
    # --- Summary report ---
    local summary="${triage_dir}/SUMMARY.md"
    {
        echo "# Recon Triage Summary"
        echo ""
        echo "**Date:** $(date)"
        echo "**Domains Scanned:** ${DOMAINS[*]}"
        echo ""
        echo "## Results"
        echo ""
        echo "| Category | Count | File |"
        echo "|---|---|---|"
        echo "| Apps with auth (HIGH VALUE) | $(wc -l < "${triage_dir}/apps_with_auth.txt" 2>/dev/null || echo 0) | apps_with_auth.txt |"
        echo "| API endpoints | $(wc -l < "${triage_dir}/api_hosts.txt" 2>/dev/null || echo 0) | api_hosts.txt |"
        echo "| Static/Marketing | $(wc -l < "${triage_dir}/static_marketing.txt" 2>/dev/null || echo 0) | static_marketing.txt |"
        echo "| Redirects | $(wc -l < "${triage_dir}/redirects.txt" 2>/dev/null || echo 0) | redirects.txt |"
        echo "| Client errors (4xx) | $(wc -l < "${triage_dir}/client_errors.txt" 2>/dev/null || echo 0) | client_errors.txt |"
        echo "| Server errors (5xx) | $(wc -l < "${triage_dir}/server_errors.txt" 2>/dev/null || echo 0) | server_errors.txt |"
        echo ""
        echo "## Next Steps"
        echo ""
        echo "1. **Focus on \`apps_with_auth.txt\`** — these have login, accounts, dashboards = IDOR/BAC/ATO territory"
        echo "2. **Review \`api_hosts.txt\`** — API endpoints for IDOR, injection, broken authz"
        echo "3. **Check \`potential_secrets.txt\`** in fingerprinted/ — leaked keys/tokens"
        echo "4. **Check \`api_endpoints.txt\`** in fingerprinted/ — hidden endpoints to fuzz"
        echo "5. **Review takeover_candidates.txt** in resolved/ — dangling CNAMEs"
    } > "$summary"
    
    log "Triage summary written to: $summary"
    cat "$summary"
}

# =============================================================================
# Main
# =============================================================================
main() {
    banner
    
    # Parse args
    local phase="all"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --phase)
                phase="$2"
                shift 2
                ;;
            --threads)
                THREADS="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [--phase enum|resolve|probe|finger|triage] [--threads N] [--output DIR]"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    setup_output
    
    case "$phase" in
        all)
            phase_enum
            phase_resolve
            phase_probe
            phase_fingerprint
            phase_triage
            ;;
        enum)
            phase_enum
            ;;
        resolve)
            phase_resolve
            ;;
        probe)
            phase_probe
            ;;
        finger|fingerprint)
            phase_fingerprint
            ;;
        triage)
            phase_triage
            ;;
        *)
            error "Unknown phase: $phase"
            error "Valid phases: enum, resolve, probe, finger, triage"
            exit 1
            ;;
    esac
    
    echo ""
    log "Pipeline complete! Results in: $OUTPUT_DIR"
}

main "$@"
