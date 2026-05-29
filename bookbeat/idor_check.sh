#!/bin/bash
# =============================================================================
# BookBeat — IDOR / BAC Test Harness (two-account, manual, safe)
# =============================================================================
# Demonstrates IDOR safely: it confirms whether Account B can access a resource
# that belongs to Account A, WITHOUT harvesting third-party data. You supply
# YOUR OWN two accounts' tokens.
#
# Workflow:
#   1. Login both accounts to separate token files:
#        export BB_USERNAME=A@... BB_PASSWORD=...; BB_TOKEN_FILE=/tmp/.bb_A ./api_login.sh
#        export BB_USERNAME=B@... BB_PASSWORD=...; BB_TOKEN_FILE=/tmp/.bb_B ./api_login.sh
#   2. As Account A, find one of YOUR OWN resource IDs (e.g., a bookmark id).
#   3. Run this harness to see if Account B's token can read A's resource.
#
# Usage:
#   ./idor_check.sh <URL_WITH_A_RESOURCE_ID>
#   ./idor_check.sh https://api.bookbeat.com/api/my/bookmarks/123456
#
# Interpretation:
#   - B gets 200 + A's data  => IDOR (report it, do NOT pull more data)
#   - B gets 401/403/404     => access control working as expected
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

TOKEN_A_FILE="${TOKEN_A_FILE:-/tmp/.bb_A}"
TOKEN_B_FILE="${TOKEN_B_FILE:-/tmp/.bb_B}"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <url_to_account_A_resource>"
    echo "First login both accounts (see header comment)."
    exit 1
fi

URL="$1"

if ! bb_is_in_scope "$URL"; then
    echo -e "${C_RED}[BLOCKED]${C_NC} Out of scope: $URL"
    exit 1
fi

for f in "$TOKEN_A_FILE" "$TOKEN_B_FILE"; do
    if [ ! -f "$f" ]; then
        echo -e "${C_RED}[-]${C_NC} Missing token file: $f"
        echo "    Login both accounts first (see header)."
        exit 1
    fi
done

TOKEN_A=$(cat "$TOKEN_A_FILE")
TOKEN_B=$(cat "$TOKEN_B_FILE")

req() {
    local token="$1"
    sleep "$BB_REQUEST_DELAY"
    curl -sS --max-time "$BB_MAX_TIME" \
        -o /dev/null -w "%{http_code}" \
        -A "$BB_USER_AGENT" \
        -H "$BB_CLIENT_HEADER" \
        -H "$BB_DEVICE_HEADER" \
        -H "Authorization: Bearer ${token}" \
        "$URL"
}

echo -e "${C_BLUE}[*]${C_NC} Testing IDOR on: $URL"
echo -e "${C_CYAN}    (using yeswehack UA, ${BB_REQUEST_DELAY}s delay between requests)${C_NC}"
echo ""

echo -e "${C_BLUE}[*]${C_NC} Account A (owner) requesting own resource..."
CODE_A=$(req "$TOKEN_A")
echo "    -> HTTP $CODE_A"

echo -e "${C_BLUE}[*]${C_NC} Account B (attacker) requesting A's resource..."
CODE_B=$(req "$TOKEN_B")
echo "    -> HTTP $CODE_B"

echo -e "${C_BLUE}[*]${C_NC} Unauthenticated request..."
sleep "$BB_REQUEST_DELAY"
CODE_NONE=$(curl -sS --max-time "$BB_MAX_TIME" -o /dev/null -w "%{http_code}" \
    -A "$BB_USER_AGENT" -H "$BB_CLIENT_HEADER" -H "$BB_DEVICE_HEADER" "$URL")
echo "    -> HTTP $CODE_NONE"

echo ""
echo "=================== RESULT ==================="
if [ "$CODE_A" == "200" ] && [ "$CODE_B" == "200" ]; then
    echo -e "${C_RED}[POTENTIAL IDOR]${C_NC} Account B accessed Account A's resource (both 200)."
    echo -e "${C_YELLOW}[!]${C_NC} STOP. Capture minimal proof (this status + one screenshot)."
    echo -e "${C_YELLOW}[!]${C_NC} Do NOT enumerate or harvest other users' data. Report it."
elif [ "$CODE_A" == "200" ] && { [ "$CODE_B" == "401" ] || [ "$CODE_B" == "403" ] || [ "$CODE_B" == "404" ]; }; then
    echo -e "${C_GREEN}[OK]${C_NC} Access control appears to be enforced (B got $CODE_B)."
else
    echo -e "${C_YELLOW}[?]${C_NC} Inconclusive. A=$CODE_A B=$CODE_B none=$CODE_NONE — investigate manually."
fi
echo "=============================================="
