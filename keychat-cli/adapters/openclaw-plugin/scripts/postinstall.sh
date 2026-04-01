#!/usr/bin/env bash
#
# postinstall.sh — Download keychat-cli binary, start agent, output npub + QR code
#
set -euo pipefail

REPO="keychat-io/keychat-protocol"
BINARY_NAME="keychat"
INSTALL_DIR="${KEYCHAT_INSTALL_DIR:-$HOME/.local/bin}"
DATA_DIR="${KEYCHAT_DATA_DIR:-$HOME/.keychat}"
PORT="${KEYCHAT_PORT:-7800}"

log() { echo "[keychat] $*" >&2; }

# ─── Detect platform ────────────────────────────────────────
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)

  case "$os" in
    darwin) os="apple-darwin" ;;
    linux)  os="unknown-linux-musl" ;;
    *)      log "Unsupported OS: $os"; exit 1 ;;
  esac

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)             log "Unsupported arch: $arch"; exit 1 ;;
  esac

  echo "${arch}-${os}"
}

# ─── Download binary ────────────────────────────────────────
download_binary() {
  local platform="$1"
  local latest_tag binary_url

  # Get latest release tag
  latest_tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*: "//;s/".*//')
  if [[ -z "$latest_tag" ]]; then
    log "Failed to get latest release. Trying 'v0.2.0'..."
    latest_tag="v0.2.0"
  fi

  binary_url="https://github.com/${REPO}/releases/download/${latest_tag}/keychat-${platform}"
  log "Downloading keychat ${latest_tag} for ${platform}..."

  mkdir -p "$INSTALL_DIR"
  curl -fsSL "$binary_url" -o "${INSTALL_DIR}/${BINARY_NAME}"
  chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
  log "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# ─── Check existing installation ────────────────────────────
check_existing() {
  if command -v keychat &>/dev/null; then
    log "keychat already installed: $(command -v keychat)"
    return 0
  fi
  if [[ -x "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    log "keychat found at ${INSTALL_DIR}/${BINARY_NAME}"
    return 0
  fi
  return 1
}

# ─── Start agent daemon (launchd on macOS, systemd on Linux) ─
start_agent() {
  # Check if already running
  if curl -s "http://127.0.0.1:${PORT}/identity" >/dev/null 2>&1; then
    log "Agent already running on port ${PORT}"
    return 0
  fi

  log "Starting keychat agent on port ${PORT}..."
  mkdir -p "$DATA_DIR"

  local keychat_bin
  keychat_bin=$(command -v keychat 2>/dev/null || echo "${INSTALL_DIR}/${BINARY_NAME}")
  local real_bin
  real_bin=$(realpath "$keychat_bin" 2>/dev/null || echo "$keychat_bin")

  if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: use launchd for persistent daemon
    local plist_path="$HOME/Library/LaunchAgents/io.keychat.cli-agent.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$plist_path" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.keychat.cli-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${real_bin}</string>
        <string>agent</string>
        <string>--port</string>
        <string>${PORT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/keychat-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/keychat-agent.log</string>
    <key>WorkingDirectory</key>
    <string>$HOME</string>
</dict>
</plist>
PLIST
    launchctl unload "$plist_path" 2>/dev/null
    launchctl load "$plist_path" 2>&1
  else
    # Linux: use systemd user service
    local service_dir="$HOME/.config/systemd/user"
    mkdir -p "$service_dir"
    cat > "$service_dir/keychat-agent.service" << UNIT
[Unit]
Description=Keychat CLI Agent
After=network.target

[Service]
ExecStart=${real_bin} agent --port ${PORT}
Restart=always
RestartSec=5
StandardOutput=append:/tmp/keychat-agent.log
StandardError=append:/tmp/keychat-agent.log

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable keychat-agent
    systemctl --user start keychat-agent
  fi

  # Wait for agent to start
  for i in $(seq 1 15); do
    if curl -s "http://127.0.0.1:${PORT}/identity" >/dev/null 2>&1; then
      log "Agent started"
      return 0
    fi
    sleep 1
  done

  log "Agent failed to start. Check /tmp/keychat-agent.log"
  return 1
}

# ─── Generate QR code image ─────────────────────────────────
generate_qr() {
  local data="$1"
  local out_path="$2"

  # Try qrencode (PNG image)
  if command -v qrencode &>/dev/null; then
    qrencode -t PNG -o "$out_path" -s 10 -m 2 "$data" 2>/dev/null
    if [[ -f "$out_path" ]]; then
      echo "$out_path"
      return 0
    fi
  fi

  # Try python
  if command -v python3 &>/dev/null; then
    python3 -c "
import sys
try:
    import qrcode
    img = qrcode.make('$data', box_size=10, border=2)
    img.save('$out_path')
    print('$out_path')
except ImportError:
    try:
        import segno
        segno.make('$data').save('$out_path', scale=10, border=2)
        print('$out_path')
    except ImportError:
        pass
" 2>/dev/null && return 0
  fi

  echo ""
}

# ─── Detect OpenClaw agents from config ─────────────────────
get_openclaw_agents() {
  # Try to read agent list from openclaw config
  local config_file="$HOME/.openclaw/openclaw.json"
  if [[ -f "$config_file" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
try:
    cfg = json.load(open('$config_file'))
    agents = cfg.get('agents', {}).get('list', [])
    ids = [a.get('id', '') for a in agents if a.get('id')]
    print(' '.join(ids) if ids else 'default')
except:
    print('default')
" 2>/dev/null
    return
  fi
  echo "default"
}

# ─── Setup multi-agent directories ──────────────────────────
setup_agents() {
  local agents="$1"

  # Always create agents/{id}/ directories for consistent multi-agent mode
  for aid in $agents; do
    mkdir -p "${DATA_DIR}/agents/${aid}"
    log "Agent directory: ${DATA_DIR}/agents/${aid}"
  done
  return 0
}

# ─── Wait for multi-agent identities ────────────────────────
wait_for_agents() {
  local agents="$1"
  local base_url="http://127.0.0.1:${PORT}"

  for aid in $agents; do
    log "Ensuring identity for agent: ${aid}"
    # Check if agent exists
    local id_json
    id_json=$(curl -s "${base_url}/agents/${aid}/identity" 2>/dev/null)
    local npub
    npub=$(echo "$id_json" | grep -o '"npub":"[^"]*"' | sed 's/"npub":"//;s/"//')

    if [[ -z "$npub" ]]; then
      # Create new identity
      id_json=$(curl -s -X POST "${base_url}/agents/${aid}/identity/create" 2>/dev/null)
      npub=$(echo "$id_json" | grep -o '"npub":"[^"]*"' | sed 's/"npub":"//;s/"//')
    fi

    if [[ -n "$npub" ]]; then
      log "Agent ${aid}: ${npub}"
    else
      log "WARNING: Failed to get identity for agent ${aid}"
    fi
  done
}

# ─── Main ────────────────────────────────────────────────────

log "Setting up Keychat CLI for OpenClaw..."

# 1. Install binary if needed
if ! check_existing; then
  platform=$(detect_platform)
  download_binary "$platform"
fi

# 2. Detect OpenClaw agents
agents=$(get_openclaw_agents)
agent_count=$(echo "$agents" | wc -w | tr -d ' ')
log "Detected ${agent_count} agent(s): ${agents}"

# 3. Setup agent directories (always multi-agent mode)
setup_agents "$agents"

# 4. Start agent daemon
start_agent || exit 1

# 5. Get identities and generate QR codes
echo ""
echo "✅ Keychat installed"
echo ""

wait_for_agents "$agents"
echo ""

for aid in $agents; do
  local_npub=$(curl -s "http://127.0.0.1:${PORT}/agents/${aid}/identity" 2>/dev/null | grep -o '"npub":"[^"]*"' | sed 's/"npub":"//;s/"//')
  if [[ -n "$local_npub" ]]; then
    contact_url="https://www.keychat.io/u/?k=${local_npub}"
    qr_file="${DATA_DIR}/qr-${aid}.png"
    qr_path=$(generate_qr "$contact_url" "$qr_file")

    echo "Agent: ${aid}"
    echo "npub: ${local_npub}"
    if [[ -n "$qr_path" && -f "$qr_path" ]]; then
      echo "QR_IMAGE: ${qr_path}"
    fi
    echo ""
  fi
done

# 6. Auto-configure channel accounts in openclaw.json
log "Configuring channel accounts..."
if command -v python3 &>/dev/null; then
  python3 << PYEOF
import json, os, sys

config_path = os.path.expanduser("~/.openclaw/openclaw.json")
try:
    with open(config_path) as f:
        cfg = json.load(f)
except:
    print("[keychat] WARNING: Could not read openclaw.json", file=sys.stderr)
    sys.exit(0)

# Read agent ids
agents_list = cfg.get("agents", {}).get("list", [])
agent_ids = [a.get("id") for a in agents_list if a.get("id")]
if not agent_ids:
    agent_ids = ["default"]

# Build accounts config
accounts = {}
for aid in agent_ids:
    accounts[aid] = {"enabled": True, "dmPolicy": "open", "allowFrom": ["*"]}

# Merge into existing config
channels = cfg.setdefault("channels", {})
kc_cli = channels.setdefault("keychat-cli", {})
kc_cli["enabled"] = True
kc_cli["url"] = "http://127.0.0.1:${PORT}"

# Merge accounts (don't overwrite existing per-account settings)
existing_accounts = kc_cli.get("accounts", {})
for aid, acct in accounts.items():
    if aid not in existing_accounts:
        existing_accounts[aid] = acct
kc_cli["accounts"] = existing_accounts

# Ensure plugin is in plugins.load.paths
plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath("${BASH_SOURCE[0]}")))
# Resolve the actual plugin dir (parent of scripts/)
script_path = os.path.realpath(__file__) if '__file__' in dir() else None
# Use a known relative path from postinstall.sh location
import pathlib
# postinstall is at .../scripts/postinstall.sh, plugin root is ../..
postinstall_dir = pathlib.Path(config_path).parent  # ~/.openclaw
# Find the plugin install path from plugins.installs or plugins.load.paths
plugins = cfg.setdefault("plugins", {})
load = plugins.setdefault("load", {})
paths = load.get("paths", [])

# Also ensure plugins.entries has keychat-cli enabled
entries = plugins.setdefault("entries", {})
if "keychat-cli" not in entries:
    entries["keychat-cli"] = {"enabled": True, "config": {}}

with open(config_path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)

print(f"[keychat] Configured {len(agent_ids)} account(s): {', '.join(agent_ids)}", file=sys.stderr)
PYEOF
else
  log "WARNING: python3 not found, skipping auto-config. Manual config needed."
fi

# Note: gateway restart is handled by 'openclaw plugins install', not here

echo ""
echo "Agent listening on http://127.0.0.1:${PORT}"
echo ""
