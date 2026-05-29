#!/bin/bash
# =============================================================================
# BookBeat — Safe Request Wrapper
# =============================================================================
# A curl wrapper that ENFORCES the program's requirements on every request:
#   - Mandatory ' yeswehack ' User-Agent
#   - In-scope host guard (refuses to hit out-of-scope hosts)
#   - Built-in delay (no high-traffic scanning)
#   - Optional auth token injection
#
# This is for MANUAL, surgical testing — one request at a time. It is NOT a
# scanner and intentionally rate-limits itself.
#
# Usage:
#   ./bb-request.sh GET  https://api.bookbeat.com/api/my/books
#   ./bb-request.sh GET  https://api.bookbeat.com/api/my/books --auth
#   ./bb-request.sh POST https://api.bookbeat.com/api/something --auth -d '{"x":1}'
#   ./bb-request.sh GET  https://search-api.bookbeat.com/search?q=test --verbose
#
# Flags:
#   --auth        Inject Bearer token from $BB_TOKEN_FILE (run api_login.sh first)
#   --verbose     Show full request/response headers
#   -d <data>     Request body (for POST/PUT/PATCH)
#   -H <header>   Add an extra header (repeatable)
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <METHOD> <URL> [--auth] [--verbose] [-d <data>] [-H <header>]"
    exit 1
fi

METHOD="$1"; shift
URL="$1"; shift

USE_AUTH=0
VERBOSE=0
BODY=""
EXTRA_HEADERS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth) USE_AUTH=1; shift ;;
        --verbose|-v) VERBOSE=1; shift ;;
        -d) BODY="$2"; shift 2 ;;
        -H) EXTRA_HEADERS+=("$2"); shift 2 ;;
        *) echo -e "${C_RED}[-]${C_NC} Unknown flag: $1"; exit 1 ;;
    esac
done

# --- SCOPE GUARD --------------------------------------------------------------
if ! bb_is_in_scope "$URL"; then
    echo -e "${C_RED}[BLOCKED]${C_NC} '$URL' is NOT in scope."
    echo -e "${C_YELLOW}[!]${C_NC} In-scope hosts only: ${BB_IN_SCOPE_HOSTS[*]}"
    exit 1
fi

# --- Build curl args ----------------------------------------------------------
CURL_ARGS=(
    -sS
    --max-time "$BB_MAX_TIME"
    -X "$METHOD"
    -A "$BB_USER_AGENT"
    -H "$BB_CLIENT_HEADER"
    -H "$BB_DEVICE_HEADER"
)

# Inject auth token if requested
if [ "$USE_AUTH" -eq 1 ]; then
    if [ -f "$BB_TOKEN_FILE" ]; then
        TOKEN=$(cat "$BB_TOKEN_FILE")
        CURL_ARGS+=(-H "Authorization: Bearer ${TOKEN}")
    else
        echo -e "${C_YELLOW}[!]${C_NC} No token found at $BB_TOKEN_FILE. Run api_login.sh first."
    fi
fi

# Extra headers
for h in "${EXTRA_HEADERS[@]}"; do
    CURL_ARGS+=(-H "$h")
done

# Body
if [ -n "$BODY" ]; then
    CURL_ARGS+=(-H "Content-Type: application/json" -d "$BODY")
fi

# Verbosity
if [ "$VERBOSE" -eq 1 ]; then
    CURL_ARGS+=(-i)
fi

# --- Confirm UA tag is present (safety) ---------------------------------------
if [[ "$BB_USER_AGENT" != *"yeswehack"* ]]; then
    echo -e "${C_RED}[-]${C_NC} FATAL: User-Agent missing 'yeswehack' tag. Aborting to avoid block."
    exit 1
fi

echo -e "${C_BLUE}[*]${C_NC} ${METHOD} ${URL}"
echo -e "${C_CYAN}    UA: ${BB_USER_AGENT}${C_NC}"

# --- Rate limit ---------------------------------------------------------------
sleep "$BB_REQUEST_DELAY"

# --- Fire ---------------------------------------------------------------------
curl "${CURL_ARGS[@]}" "$URL"
echo ""
