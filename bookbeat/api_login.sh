#!/bin/bash
# =============================================================================
# BookBeat — API Login Helper
# =============================================================================
# Authenticates to the BookBeat API using YOUR OWN account and caches the
# resulting token for use by bb-request.sh --auth.
#
# Set credentials in your shell first (never commit them):
#   export BB_USERNAME="your-ywh-alias@example.com"
#   export BB_PASSWORD="your-password"
#
# Usage:
#   ./api_login.sh
#
# For IDOR/BAC testing you need TWO accounts. Use a second token file:
#   BB_USERNAME=acctB@... BB_PASSWORD=... BB_TOKEN_FILE=/tmp/.bb_token_B ./api_login.sh
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

if [ -z "${BB_USERNAME:-}" ] || [ -z "${BB_PASSWORD:-}" ]; then
    echo -e "${C_RED}[-]${C_NC} Set BB_USERNAME and BB_PASSWORD in your environment first."
    echo "    export BB_USERNAME='your-ywh-alias@example.com'"
    echo "    export BB_PASSWORD='...'"
    exit 1
fi

echo -e "${C_BLUE}[*]${C_NC} Authenticating to ${BB_LOGIN_URL} as ${BB_USERNAME}"
echo -e "${C_CYAN}    UA: ${BB_USER_AGENT}${C_NC}"

sleep "$BB_REQUEST_DELAY"

RESPONSE=$(curl -sS --max-time "$BB_MAX_TIME" \
    -X POST "$BB_LOGIN_URL" \
    -A "$BB_USER_AGENT" \
    -H "$BB_CLIENT_HEADER" \
    -H "$BB_DEVICE_HEADER" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${BB_USERNAME}\", \"password\": \"${BB_PASSWORD}\"}")

echo -e "${C_BLUE}[*]${C_NC} Raw response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"

# Try to extract a token from common field names
TOKEN=$(echo "$RESPONSE" | jq -r '.token // .access_token // .accessToken // .jwt // empty' 2>/dev/null || echo "")

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "$TOKEN" > "$BB_TOKEN_FILE"
    echo -e "${C_GREEN}[+]${C_NC} Token cached to ${BB_TOKEN_FILE}"
    echo -e "${C_GREEN}[+]${C_NC} Use it: ./bb-request.sh GET ${BB_API}/api/... --auth"
else
    echo -e "${C_YELLOW}[!]${C_NC} Could not auto-extract a token. Inspect the response above."
    echo -e "${C_YELLOW}[!]${C_NC} The token may be in a cookie or a non-standard field — adjust as needed."
fi
