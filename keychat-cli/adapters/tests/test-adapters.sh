#!/usr/bin/env bash
#
# Test script for keychat adapter verification
#
# Usage:
#   ./test-adapters.sh              # syntax checks only
#   ./test-adapters.sh --live       # syntax + live API tests (requires running agent)
#
# Environment:
#   KC_TOKEN    API Bearer token (required for --live)
#   KC_URL      Agent daemon URL (default: http://127.0.0.1:10443)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADAPTERS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIVE=false
PASS=0
FAIL=0

[[ "${1:-}" == "--live" ]] && LIVE=true

# ─── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { ((PASS++)); echo -e "  ${GREEN}✓${NC} $*"; }
fail() { ((FAIL++)); echo -e "  ${RED}✗${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; }

echo -e "${BOLD}Keychat Adapter Tests${NC}"
echo "Adapters dir: $ADAPTERS_DIR"

# ═══════════════════════════════════════════════════════════════
section "1. File existence checks"
# ═══════════════════════════════════════════════════════════════

check_file() {
  if [[ -f "$ADAPTERS_DIR/$1" ]]; then
    pass "$1 exists"
  else
    fail "$1 missing"
  fi
}

check_file "common/keychat-client.sh"
check_file "common/keychat-client.ts"
check_file "mcp/server.ts"
check_file "mcp/package.json"
check_file "claw/bridge.sh"
check_file "claw/SKILL.md"
check_file "setup/setup-claude-code.sh"
check_file "setup/setup-codex.sh"
check_file "setup/setup-gemini.sh"
check_file "setup/setup-openclaw.sh"
check_file "setup/setup-pi.sh"
check_file "README.md"

# ═══════════════════════════════════════════════════════════════
section "2. Bash syntax checks (bash -n)"
# ═══════════════════════════════════════════════════════════════

check_syntax() {
  local file="$ADAPTERS_DIR/$1"
  if bash -n "$file" 2>/dev/null; then
    pass "$1 syntax OK"
  else
    fail "$1 syntax error"
  fi
}

check_syntax "common/keychat-client.sh"
check_syntax "claw/bridge.sh"
check_syntax "setup/setup-claude-code.sh"
check_syntax "setup/setup-codex.sh"
check_syntax "setup/setup-gemini.sh"
check_syntax "setup/setup-openclaw.sh"
check_syntax "setup/setup-pi.sh"

# ═══════════════════════════════════════════════════════════════
section "3. TypeScript checks"
# ═══════════════════════════════════════════════════════════════

if command -v npx &>/dev/null; then
  # Check if dependencies are installed
  if [[ -d "$ADAPTERS_DIR/mcp/node_modules" ]]; then
    cd "$ADAPTERS_DIR/mcp"
    if npx tsc --noEmit --skipLibCheck --esModuleInterop --module nodenext --moduleResolution nodenext server.ts 2>/dev/null; then
      pass "mcp/server.ts compiles"
    else
      fail "mcp/server.ts compile error (run 'cd adapters/mcp && npm install' first)"
    fi
  else
    echo -e "  ${YELLOW}⊘${NC} mcp/server.ts skipped (run 'cd adapters/mcp && npm install' first)"
  fi
else
  echo -e "  ${YELLOW}⊘${NC} TypeScript checks skipped (npx not found)"
fi

# ═══════════════════════════════════════════════════════════════
section "4. Shared client library checks"
# ═══════════════════════════════════════════════════════════════

# Test that keychat-client.sh can be sourced without errors
(
  export KC_TOKEN="test_token"
  source "$ADAPTERS_DIR/common/keychat-client.sh"

  # Check required functions exist
  if type kc_get &>/dev/null && type kc_post &>/dev/null && type kc_send &>/dev/null \
    && type kc_identity &>/dev/null && type kc_status &>/dev/null \
    && type kc_rooms &>/dev/null && type kc_contacts &>/dev/null \
    && type kc_pending &>/dev/null && type kc_approve &>/dev/null \
    && type kc_reject &>/dev/null && type kc_owner &>/dev/null \
    && type kc_sse_listen &>/dev/null && type kc_session_id &>/dev/null \
    && type kc_wait_ready &>/dev/null; then
    exit 0
  else
    exit 1
  fi
) && pass "keychat-client.sh sources OK, all functions defined" \
  || fail "keychat-client.sh source/function check failed"

# Test session ID routing
(
  source "$ADAPTERS_DIR/common/keychat-client.sh"
  sid_dm=$(kc_session_id "abc123" "")
  sid_sg=$(kc_session_id "abc123" "group456")
  [[ "$sid_dm" == "kcv2_dm_abc123" && "$sid_sg" == "kcv2_sg_group456" ]]
) && pass "kc_session_id routing correct" \
  || fail "kc_session_id routing incorrect"

# ═══════════════════════════════════════════════════════════════
section "5. Package.json checks"
# ═══════════════════════════════════════════════════════════════

if command -v jq &>/dev/null; then
  PKG="$ADAPTERS_DIR/mcp/package.json"
  if jq -e '.dependencies["@modelcontextprotocol/sdk"]' "$PKG" >/dev/null 2>&1; then
    pass "package.json has MCP SDK dependency"
  else
    fail "package.json missing MCP SDK dependency"
  fi

  if jq -e '.dependencies["eventsource-parser"]' "$PKG" >/dev/null 2>&1; then
    pass "package.json has eventsource-parser dependency"
  else
    fail "package.json missing eventsource-parser dependency"
  fi
else
  echo -e "  ${YELLOW}⊘${NC} package.json checks skipped (jq not found)"
fi

# ═══════════════════════════════════════════════════════════════
section "6. Script executable checks"
# ═══════════════════════════════════════════════════════════════

check_executable() {
  local file="$ADAPTERS_DIR/$1"
  if [[ -x "$file" ]]; then
    pass "$1 is executable"
  else
    fail "$1 is not executable"
  fi
}

check_executable "claw/bridge.sh"
check_executable "setup/setup-claude-code.sh"
check_executable "setup/setup-codex.sh"
check_executable "setup/setup-gemini.sh"
check_executable "setup/setup-openclaw.sh"
check_executable "setup/setup-pi.sh"

# ═══════════════════════════════════════════════════════════════
if $LIVE; then
  section "7. Live API tests (agent daemon)"

  KC_URL="${KC_URL:-http://127.0.0.1:10443}"
  KC_TOKEN="${KC_TOKEN:-}"

  if [[ -z "$KC_TOKEN" ]]; then
    fail "KC_TOKEN not set. Export it and retry."
  else
    source "$ADAPTERS_DIR/common/keychat-client.sh"

    # Test identity endpoint
    result=$(kc_identity 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      npub=$(echo "$result" | jq -r '.data.npub // empty')
      pass "GET /identity → $npub"
    else
      fail "GET /identity failed"
    fi

    # Test status endpoint
    result=$(kc_status 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      pass "GET /status → OK"
    else
      fail "GET /status failed"
    fi

    # Test rooms endpoint
    result=$(kc_rooms 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      count=$(echo "$result" | jq '.data | length')
      pass "GET /rooms → $count rooms"
    else
      fail "GET /rooms failed"
    fi

    # Test contacts endpoint
    result=$(kc_contacts 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      count=$(echo "$result" | jq '.data | length')
      pass "GET /contacts → $count contacts"
    else
      fail "GET /contacts failed"
    fi

    # Test relays endpoint
    result=$(kc_relays 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      pass "GET /relays → OK"
    else
      fail "GET /relays failed"
    fi

    # Test pending-friends endpoint
    result=$(kc_pending 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      pass "GET /pending-friends → OK"
    else
      fail "GET /pending-friends failed"
    fi

    # Test owner endpoint
    result=$(kc_owner 2>/dev/null || echo "")
    if echo "$result" | jq -e '.ok' >/dev/null 2>&1; then
      pass "GET /owner → OK"
    else
      fail "GET /owner failed"
    fi
  fi
else
  section "7. Live API tests"
  echo -e "  ${YELLOW}⊘${NC} Skipped (use --live with KC_TOKEN set)"
fi

# ═══════════════════════════════════════════════════════════════
echo ""
echo "─────────────────────────────────────────────"
echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "─────────────────────────────────────────────"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
