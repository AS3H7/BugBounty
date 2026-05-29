#!/bin/bash
# =============================================================================
# BookBeat — PASSIVE Recon (rules-compliant)
# =============================================================================
# IMPORTANT: BookBeat forbids automated scanners / high-traffic tools against
# their infra. This script ONLY queries THIRD-PARTY archives (Wayback Machine,
# common-crawl via gau, crt.sh). It does NOT send traffic to BookBeat servers,
# so it stays within the Rules of Engagement.
#
# It builds an endpoint/parameter map you can then test MANUALLY with
# bb-request.sh (one surgical request at a time).
#
# Usage:
#   ./passive_recon.sh
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

OUTPUT_DIR="${SCRIPT_DIR}/output/passive_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

log() { echo -e "${C_GREEN}[+]${C_NC} $1"; }
info() { echo -e "${C_BLUE}[*]${C_NC} $1"; }
warn() { echo -e "${C_YELLOW}[!]${C_NC} $1"; }

echo -e "${C_CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   BookBeat PASSIVE Recon — third-party archives only       ║"
echo "║   (no traffic sent to BookBeat infrastructure)             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${C_NC}"

ALL_URLS="${OUTPUT_DIR}/all_urls.txt"
touch "$ALL_URLS"

for host in "${BB_IN_SCOPE_HOSTS[@]}"; do
    info "Collecting archived URLs for: $host"

    # --- gau: pulls from Wayback, Common Crawl, URLScan, OTX (all third-party) ---
    if command -v gau &> /dev/null; then
        log "  gau (passive multi-source)..."
        echo "$host" | gau --threads 3 2>/dev/null >> "$ALL_URLS" || true
    fi

    # --- waybackurls: Wayback Machine only ---
    if command -v waybackurls &> /dev/null; then
        log "  waybackurls..."
        echo "$host" | waybackurls 2>/dev/null >> "$ALL_URLS" || true
    fi

    # --- Direct Wayback CDX API (no extra tooling needed) ---
    log "  Wayback CDX API..."
    curl -sS --max-time 30 \
        "https://web.archive.org/cdx/search/cdx?url=${host}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
        2>/dev/null >> "$ALL_URLS" || true
done

# Deduplicate, keep only in-scope hosts
sort -u "$ALL_URLS" | grep -E "https?://(www|api|search-api|edge)\.bookbeat\.com" > "${ALL_URLS}.tmp" 2>/dev/null || true
mv "${ALL_URLS}.tmp" "$ALL_URLS"

log "Total unique archived URLs (in-scope): $(wc -l < "$ALL_URLS")"

# --- Extract API endpoints ----------------------------------------------------
info "Extracting API endpoints..."
grep -Eoh "/api/[a-zA-Z0-9/_{}.-]+|/v[0-9]+/[a-zA-Z0-9/_{}.-]+|/search[a-zA-Z0-9/_{}.-]*|/graphql" \
    "$ALL_URLS" 2>/dev/null | sort -u > "${OUTPUT_DIR}/api_endpoints.txt" || true
log "API endpoints: $(wc -l < "${OUTPUT_DIR}/api_endpoints.txt" 2>/dev/null || echo 0)"

# --- Extract parameters -------------------------------------------------------
info "Extracting parameters..."
if command -v unfurl &> /dev/null; then
    cat "$ALL_URLS" | unfurl --unique keys 2>/dev/null | sort -u > "${OUTPUT_DIR}/parameters.txt" || true
else
    grep -oE '[?&][a-zA-Z0-9_]+=' "$ALL_URLS" 2>/dev/null | tr -d '?&=' | sort -u > "${OUTPUT_DIR}/parameters.txt" || true
fi
log "Unique parameters: $(wc -l < "${OUTPUT_DIR}/parameters.txt" 2>/dev/null || echo 0)"

# --- Flag IDOR candidates -----------------------------------------------------
info "Flagging IDOR/object-reference candidates..."
{
    echo "# IDOR / Object-Reference Candidates"
    echo "# (URLs with numeric IDs, UUIDs, or user/account/order references)"
    echo "# Test these MANUALLY with two of your own accounts via bb-request.sh"
    echo ""
    grep -E "(/[0-9]{2,}(/|\?|$)|id=[0-9]+|user(id|Id|_id)?=|account(id|Id|_id)?=|member(id|Id)?=|order(id|Id)?=|book(id|Id)?=)" \
        "$ALL_URLS" 2>/dev/null | sort -u || true
    echo ""
    echo "# UUID-based references"
    grep -Ei "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" \
        "$ALL_URLS" 2>/dev/null | sort -u || true
} > "${OUTPUT_DIR}/idor_candidates.txt"

# --- Summary ------------------------------------------------------------------
SUMMARY="${OUTPUT_DIR}/SUMMARY.md"
{
    echo "# BookBeat Passive Recon Summary"
    echo ""
    echo "**Date:** $(date)"
    echo "**Method:** Third-party archives only (no traffic to BookBeat)"
    echo ""
    echo "| Output | Count |"
    echo "|---|---|"
    echo "| All archived URLs | $(wc -l < "$ALL_URLS" 2>/dev/null || echo 0) |"
    echo "| API endpoints | $(wc -l < "${OUTPUT_DIR}/api_endpoints.txt" 2>/dev/null || echo 0) |"
    echo "| Parameters | $(wc -l < "${OUTPUT_DIR}/parameters.txt" 2>/dev/null || echo 0) |"
    echo "| IDOR candidates | $(grep -c 'bookbeat' "${OUTPUT_DIR}/idor_candidates.txt" 2>/dev/null || echo 0) |"
    echo ""
    echo "## Next Steps (ALL manual, rate-limited, with yeswehack UA)"
    echo "1. Authenticate: \`./api_login.sh\` (and a 2nd account for IDOR)"
    echo "2. Map each endpoint in \`api_endpoints.txt\` — note which need auth"
    echo "3. Test \`idor_candidates.txt\` with Account A's IDs replayed as Account B"
    echo "4. Probe \`parameters.txt\` on search-api for injection (manually)"
    echo "5. Map subscription/business-logic flows in the web app"
}> "$SUMMARY"

log "Summary: $SUMMARY"
echo ""
cat "$SUMMARY"
echo ""
warn "Reminder: from here ON, every active request must use bb-request.sh (enforces the yeswehack UA + scope guard + rate limit)."
