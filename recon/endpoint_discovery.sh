#!/bin/bash
# =============================================================================
# Endpoint Discovery & Parameter Mining
# =============================================================================
# Run AFTER the main recon pipeline, against the "apps_with_auth" hosts.
# Discovers hidden endpoints, parameters, and potential IDOR/injection points.
#
# Usage:
#   ./endpoint_discovery.sh <target_url>
#   ./endpoint_discovery.sh https://owner-api.teslamotors.com
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 https://owner-api.teslamotors.com"
    exit 1
fi

TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||')
OUTPUT_DIR="./output/endpoints_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

log "Target: $TARGET"
log "Output: $OUTPUT_DIR"

# =============================================================================
# 1. Crawling (passive + active)
# =============================================================================
log "=== Crawling & URL Discovery ==="

# --- katana (active crawler) ---
if command -v katana &> /dev/null; then
    log "Running katana crawler..."
    katana -u "$TARGET" -d 3 -silent -jc \
        -f qurl -ef "png,jpg,gif,css,svg,woff,ttf,ico" \
        -o "${OUTPUT_DIR}/katana_urls.txt" 2>/dev/null || true
fi

# --- waybackurls (passive) ---
if command -v waybackurls &> /dev/null; then
    log "Fetching Wayback Machine URLs..."
    echo "$DOMAIN" | waybackurls 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/wayback_urls.txt" || true
fi

# --- gau (GetAllUrls - passive multi-source) ---
if command -v gau &> /dev/null; then
    log "Running gau (passive URL collection)..."
    echo "$DOMAIN" | gau --threads 5 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/gau_urls.txt" || true
fi

# Combine all URLs
cat "${OUTPUT_DIR}"/*_urls.txt 2>/dev/null | sort -u > "${OUTPUT_DIR}/all_urls.txt" || true
log "Total unique URLs collected: $(wc -l < "${OUTPUT_DIR}/all_urls.txt" 2>/dev/null || echo 0)"

# =============================================================================
# 2. Parameter Extraction
# =============================================================================
log "=== Parameter Extraction ==="

# Extract unique parameters
if command -v unfurl &> /dev/null; then
    log "Extracting parameters with unfurl..."
    cat "${OUTPUT_DIR}/all_urls.txt" | unfurl --unique keys 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/parameters.txt" || true
    log "Unique parameters found: $(wc -l < "${OUTPUT_DIR}/parameters.txt" 2>/dev/null || echo 0)"
fi

# Extract paths
if command -v unfurl &> /dev/null; then
    cat "${OUTPUT_DIR}/all_urls.txt" | unfurl --unique paths 2>/dev/null | \
        sort -u > "${OUTPUT_DIR}/paths.txt" || true
fi

# --- Arjun (parameter discovery) ---
if command -v arjun &> /dev/null; then
    log "Running arjun for hidden parameter discovery..."
    arjun -u "$TARGET" -oJ "${OUTPUT_DIR}/arjun_params.json" \
        -t 10 --stable 2>/dev/null || true
fi

# =============================================================================
# 3. Content Discovery (directory/file brute)
# =============================================================================
log "=== Content Discovery ==="

# --- feroxbuster ---
if command -v feroxbuster &> /dev/null; then
    log "Running feroxbuster..."
    feroxbuster -u "$TARGET" -w /usr/share/wordlists/dirb/common.txt \
        --silent -t 30 --status-codes 200 301 302 403 \
        -o "${OUTPUT_DIR}/feroxbuster.txt" 2>/dev/null || true
# --- ffuf fallback ---
elif command -v ffuf &> /dev/null; then
    log "Running ffuf..."
    ffuf -u "${TARGET}/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
        -mc 200,301,302,403 -t 30 -s \
        -o "${OUTPUT_DIR}/ffuf.json" -of json 2>/dev/null || true
# --- gobuster fallback ---
elif command -v gobuster &> /dev/null; then
    log "Running gobuster..."
    gobuster dir -u "$TARGET" -w /usr/share/wordlists/dirb/common.txt \
        -t 30 -q --no-error \
        -o "${OUTPUT_DIR}/gobuster.txt" 2>/dev/null || true
fi

# =============================================================================
# 4. Identify IDOR / Auth Patterns
# =============================================================================
log "=== IDOR & Auth Pattern Analysis ==="

# Look for numeric IDs, UUIDs, and sequential patterns in URLs
{
    echo "# Potential IDOR Candidates"
    echo "# URLs containing numeric IDs or UUIDs that might lack proper authorization"
    echo ""
    grep -E "(/[0-9]+(/|$|\?)|id=[0-9]+|user[_-]?id=|account[_-]?id=|order[_-]?id=)" \
        "${OUTPUT_DIR}/all_urls.txt" 2>/dev/null || true
    echo ""
    echo "# UUID-based references"
    grep -Ei "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" \
        "${OUTPUT_DIR}/all_urls.txt" 2>/dev/null || true
} > "${OUTPUT_DIR}/idor_candidates.txt"

# Look for API versioning patterns
{
    echo "# API Endpoints (check for broken access control)"
    echo ""
    grep -Ei "(\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/internal\/)" \
        "${OUTPUT_DIR}/all_urls.txt" 2>/dev/null | sort -u || true
} > "${OUTPUT_DIR}/api_endpoints.txt"

# =============================================================================
# 5. Summary
# =============================================================================
echo ""
log "=== Endpoint Discovery Complete ==="
echo ""
info "Key files to review:"
echo "  ${OUTPUT_DIR}/all_urls.txt          - All collected URLs"
echo "  ${OUTPUT_DIR}/parameters.txt        - Extracted parameters"
echo "  ${OUTPUT_DIR}/paths.txt             - Unique paths"
echo "  ${OUTPUT_DIR}/idor_candidates.txt   - Potential IDOR targets"
echo "  ${OUTPUT_DIR}/api_endpoints.txt     - API endpoints"
echo ""
warn "Next steps:"
echo "  1. Review idor_candidates.txt — test with two of YOUR OWN accounts"
echo "  2. Review api_endpoints.txt — check authz on each endpoint"
echo "  3. Look for GraphQL introspection on /graphql endpoints"
echo "  4. Test parameters for injection (SQLi, SSRF) with YOUR account"
