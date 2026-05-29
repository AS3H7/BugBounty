#!/bin/bash
# =============================================================================
# BookBeat Bug Bounty — Central Config
# =============================================================================
# Sourced by all other scripts. Defines the mandatory headers, hosts, and
# rate-limiting defaults required by the program's Rules of Engagement.
# =============================================================================

# --- MANDATORY: YesWeHack User-Agent tag --------------------------------------
# The program requires ' yeswehack ' appended to the User-Agent so their
# security team can identify your traffic. WITHOUT THIS YOU WILL BE BLOCKED.
export YWH_TAG=" yeswehack "
export BB_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36${YWH_TAG}"

# --- Mandatory API headers ----------------------------------------------------
export BB_CLIENT_HEADER="bb-client: BookBeatApp"
export BB_DEVICE_HEADER="bb-device: api ywh"

# --- In-scope hosts (ONLY these) ----------------------------------------------
export BB_WEB="https://www.bookbeat.com"
export BB_API="https://api.bookbeat.com"
export BB_SEARCH_API="https://search-api.bookbeat.com"
export BB_EDGE="https://edge.bookbeat.com"

export BB_IN_SCOPE_HOSTS=(
    "www.bookbeat.com"
    "api.bookbeat.com"
    "search-api.bookbeat.com"
    "edge.bookbeat.com"
)

# --- API login endpoint -------------------------------------------------------
export BB_LOGIN_URL="${BB_API}/api/login"

# --- Rate limiting (be gentle — NO high-traffic scanning allowed) -------------
# Minimum delay between requests in seconds. Keep this conservative.
export BB_REQUEST_DELAY="${BB_REQUEST_DELAY:-2}"
export BB_MAX_TIME="${BB_MAX_TIME:-20}"

# --- Credentials (set via environment, never commit) --------------------------
# export BB_USERNAME="your-ywh-alias@..."   # set in your shell, not here
# export BB_PASSWORD="..."
# Token cache (populated by api_login.sh)
export BB_TOKEN_FILE="${BB_TOKEN_FILE:-/tmp/.bb_token}"

# --- Scope guard --------------------------------------------------------------
# Returns 0 if the host is in scope, 1 otherwise.
bb_is_in_scope() {
    local url="$1"
    local host
    host=$(echo "$url" | sed -E 's|https?://||; s|/.*||; s|:.*||')
    for h in "${BB_IN_SCOPE_HOSTS[@]}"; do
        if [ "$host" == "$h" ]; then
            return 0
        fi
    done
    return 1
}

# --- Colors -------------------------------------------------------------------
export C_RED='\033[0;31m'
export C_GREEN='\033[0;32m'
export C_YELLOW='\033[1;33m'
export C_BLUE='\033[0;34m'
export C_CYAN='\033[0;36m'
export C_NC='\033[0m'
