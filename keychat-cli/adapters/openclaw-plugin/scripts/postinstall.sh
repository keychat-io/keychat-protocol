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

# ─── Start agent daemon ─────────────────────────────────────
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

  nohup "$keychat_bin" agent --port "$PORT" > /tmp/keychat-agent.log 2>&1 &
  local pid=$!

  # Wait for agent to start
  for i in $(seq 1 15); do
    if curl -s "http://127.0.0.1:${PORT}/identity" >/dev/null 2>&1; then
      log "Agent started (pid: $pid)"
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
  local out_path="${DATA_DIR}/npub-qr.png"

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

# ─── Main ────────────────────────────────────────────────────

log "Setting up Keychat CLI for OpenClaw..."

# 1. Install binary if needed
if ! check_existing; then
  platform=$(detect_platform)
  download_binary "$platform"
fi

# 2. Start agent
start_agent || exit 1

# 3. Get identity
identity=$(curl -s "http://127.0.0.1:${PORT}/identity" 2>/dev/null)
npub=$(echo "$identity" | grep -o '"npub":"[^"]*"' | sed 's/"npub":"//;s/"//')

if [[ -z "$npub" ]]; then
  log "Failed to get agent identity"
  exit 1
fi

# 4. Generate QR code image
qr_path=$(generate_qr "$npub")

# 5. Output result
echo ""
echo "✅ Keychat installed"
echo ""
echo "npub: ${npub}"
echo ""
if [[ -n "$qr_path" && -f "$qr_path" ]]; then
  echo "QR_IMAGE: ${qr_path}"
  echo ""
  echo "Scan the QR code with Keychat app to add as friend."
else
  echo "Add this npub in Keychat app to connect."
fi
echo ""
echo "Agent listening on http://127.0.0.1:${PORT}"
echo ""
